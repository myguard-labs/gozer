package gozer

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/myguard-labs/gdcc/dcc"
)

// DCC target sentinels (include/dcc_proto.h).
const (
	dccTgtsMany = 0x00fffff0 // DCC_TGTS_TOO_MANY ("many")
	dccTgtsOK   = 0x00fffff1 // DCC_TGTS_OK (whitelisted)
)

// fakeDCC answers DCC queries on UDP, echoing the transaction id and replying to
// every queried checksum with cur (silent = never reply, a black hole).
func fakeDCC(t *testing.T, silent bool, cur uint32) (port int, stop func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, ra, err := conn.ReadFromUDP(buf)
			select {
			case <-done:
				return
			default:
			}
			if err != nil || n < 28 || silent {
				continue
			}
			ncks := (n - 24 - 4 - 16) / 18
			ans := make([]byte, 24+ncks*8+16)
			binary.BigEndian.PutUint16(ans[0:2], uint16(len(ans))) // #nosec G115 -- answer length is small and bounded
			ans[2] = 12                                            // pkt_vers
			ans[3] = 4                                             // DCC_OP_ANSWER
			copy(ans[8:20], buf[8:20])
			for i := 0; i < ncks; i++ {
				binary.BigEndian.PutUint32(ans[24+i*8:], cur)
			}
			_, _ = conn.WriteToUDP(ans, ra)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port, func() { close(done); _ = conn.Close() }
}

func dccBackend(port int) *Backends {
	return &Backends{
		cfg:  &Config{BackendTimeout: 2 * time.Second},
		dcc:  &dcc.Client{Servers: []dcc.Server{{Host: "127.0.0.1", Port: port}}, Timeout: 2 * time.Second},
		logf: func(string, ...any) {},
	}
}

const dccProbe = "From: a@b.c\r\nMessage-ID: <x@y>\r\n\r\n" +
	"The quick brown fox jumps over the lazy dog while the cat watches today here.\r\n"

func TestCheckDCCMany(t *testing.T) {
	port, stop := fakeDCC(t, false, dccTgtsMany)
	defer stop()
	r, healthy := dccBackend(port).checkDCC([]byte(dccProbe))
	if !healthy {
		t.Fatal("live DCC result marked unhealthy")
	}
	if r.Action != "reject" {
		t.Errorf("many should reject, got %q", r.Action)
	}
	if r.Bulk == nil || *r.Bulk != dccTgtsMany {
		t.Errorf("bulk count: %v", r.Bulk)
	}
}

func TestCheckDCCAccept(t *testing.T) {
	port, stop := fakeDCC(t, false, dccTgtsOK)
	defer stop()
	r, healthy := dccBackend(port).checkDCC([]byte(dccProbe))
	if !healthy {
		t.Fatal("live DCC result marked unhealthy")
	}
	if r.Action != "accept" {
		t.Errorf("whitelist should accept, got %q", r.Action)
	}
	if r.Bulk != nil {
		t.Errorf("accept should have nil bulk, got %v", r.Bulk)
	}
}

func TestCheckDCCUnknownLowCount(t *testing.T) {
	port, stop := fakeDCC(t, false, 5)
	defer stop()
	r, healthy := dccBackend(port).checkDCC([]byte(dccProbe))
	if !healthy {
		t.Fatal("live DCC result marked unhealthy")
	}
	if r.Action != "unknown" || r.Bulk != nil {
		t.Errorf("low count should be unknown/nil, got %q/%v", r.Action, r.Bulk)
	}
}

func TestCheckDCCError(t *testing.T) {
	// 127.0.0.1:1 refuses; a short timeout keeps the test fast.
	b := &Backends{
		cfg:  &Config{BackendTimeout: 300 * time.Millisecond},
		dcc:  &dcc.Client{Servers: []dcc.Server{{Host: "127.0.0.1", Port: 1}}, Timeout: 300 * time.Millisecond},
		logf: func(string, ...any) {},
	}
	r, healthy := b.checkDCC([]byte(dccProbe))
	if healthy {
		t.Fatal("failed DCC result marked healthy")
	}
	if r.Action != "unknown" || r.Bulk != nil {
		t.Errorf("backend error should be unknown/nil, got %q/%v", r.Action, r.Bulk)
	}
}

func TestReportDCC(t *testing.T) {
	port, stop := fakeDCC(t, false, 0)
	defer stop()
	if v := dccBackend(port).reportDCC([]byte(dccProbe)); v == nil || !*v {
		t.Errorf("report to a live server should be true, got %v", v)
	}
}

func TestReportRazorNoIdentity(t *testing.T) {
	b := &Backends{cfg: &Config{BackendTimeout: time.Second}, logf: func(string, ...any) {}}
	if b.HasRazorIdentity() {
		t.Fatal("no identity expected")
	}
	if b.reportRazor(nil) || b.revokeRazor(nil) {
		t.Error("report/revoke without identity must be false (no network call)")
	}
}
