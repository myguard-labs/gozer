package dcc

import (
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- DCC wire protocol mandates MD5; not a security primitive here
	"encoding/binary"
	"errors"
	"fmt"
)

// DCC client-server wire protocol (include/dcc_proto.h). All multi-byte fields
// on the wire are big-endian, except op_nums which the server treats as opaque
// transaction identifiers and echoes verbatim — we use big-endian there too.

const (
	dccPktVers    = 12   // DCC_PKT_VERS (newest)
	dccSrvrPort   = 6277 // DCC_SRVR_PORT
	bulkThreshold = 10   // BULK_THRESHOLD

	dccTgtsTooMany = 0x00fffff0 // DCC_TGTS_TOO_MANY ("many")
	dccTgtsOK      = 0x00fffff1 // DCC_TGTS_OK (certified not spam)
	dccTgtsOK2     = 0x00fffff2 // DCC_TGTS_OK2 (half certified)
	dccTgtsMask    = 0x00ffffff // DCC_TGTS_MASK

	dccIDAnon = 1 // DCC_ID_ANON

	hdrLen = 24 // DCC_HDR: len2 vers1 op1 sender4 op_nums(4*4)
	ckLen  = 18 // DCC_CK: type1 len1 sum16
	sigLen = 16 // DCC_SIGNATURE
)

// opcodes (DCC_OPS)
const (
	opInvalid = 0
	opNop     = 1
	opReport  = 2
	opQuery   = 3
	opAnswer  = 4
	opError   = 7
)

// opNums identifies a transaction (DCC_OP_NUMS): host, pid, report, transmit.
type opNums struct{ h, p, r, t uint32 }

// query builds a DCC_OP_QUERY/REPORT packet for the reportable checksums.
// tgts is 0 for a query; for a report it is the recipient count (already
// OR'd with DCC_TGTS_SPAM by the caller if spam). The signature is appended:
// zero for anonymous, else MD5(passwd16 || packet-without-sig).
func buildQuery(op int, sender uint32, nums opNums, tgts uint32, cks []Checksum, passwd []byte) []byte {
	var reportable []Checksum
	for _, c := range cks {
		if c.Report {
			reportable = append(reportable, c)
		}
	}
	n := len(reportable)
	pktLen := hdrLen + 4 + n*ckLen + sigLen
	buf := make([]byte, pktLen)

	binary.BigEndian.PutUint16(buf[0:2], uint16(pktLen)) // #nosec G115 -- DCC packet length is bounded well under 2^16
	buf[2] = dccPktVers
	buf[3] = byte(op) // #nosec G115 -- op is a small opcode constant
	binary.BigEndian.PutUint32(buf[4:8], sender)
	binary.BigEndian.PutUint32(buf[8:12], nums.h)
	binary.BigEndian.PutUint32(buf[12:16], nums.p)
	binary.BigEndian.PutUint32(buf[16:20], nums.r)
	binary.BigEndian.PutUint32(buf[20:24], nums.t)

	binary.BigEndian.PutUint32(buf[24:28], tgts)

	off := 28
	for _, c := range reportable {
		buf[off] = byte(c.Type)
		buf[off+1] = ckLen
		copy(buf[off+2:off+18], c.Sum[:])
		off += ckLen
	}

	signPacket(buf, passwd)
	return buf
}

// signPacket writes the trailing 16-byte signature: zero for anon (empty
// passwd), else MD5(passwd || packet[:len-16]) — clntlib/sign.c:dcc_sign and
// the anon zeroing in clnt_send.c:clnt_xmit.
func signPacket(buf, passwd []byte) {
	sig := buf[len(buf)-sigLen:]
	if len(passwd) == 0 {
		for i := range sig {
			sig[i] = 0
		}
		return
	}
	h := md5.New() // #nosec G401 -- DCC packet signature is keyed MD5 by protocol
	h.Write(passwd)
	h.Write(buf[:len(buf)-sigLen])
	copy(sig, h.Sum(nil))
}

// verifyAnswerSig checks a server answer's trailing 16-byte signature. For an
// authenticated client the server keys the signature on the client password
// (MD5(passwd || msg[:-16]), the same construction as signPacket), and the
// reference client rejects an answer that does not verify — without this a
// spoofed UDP reply could inject arbitrary counts. Anonymous clients (empty
// passwd) get a zero signature with nothing to key on, so they pass.
func verifyAnswerSig(buf, passwd []byte) bool {
	if len(passwd) == 0 {
		return true // anonymous: nothing to verify
	}
	if len(buf) < sigLen {
		return false
	}
	h := md5.New() // #nosec G401 -- DCC packet signature is keyed MD5 by protocol
	h.Write(passwd)
	h.Write(buf[:len(buf)-sigLen])
	return hmac.Equal(h.Sum(nil), buf[len(buf)-sigLen:]) // constant-time
}

// passwd16 pads/truncates a password to the fixed 16-byte field the signature
// keys on (DCC_MAX_PASSWD). Empty → nil (anonymous, zero signature).
func passwd16(s string) []byte {
	if s == "" {
		return nil
	}
	var b [sigLen]byte
	copy(b[:], s)
	return b[:]
}

// answerCount is the server's pair for one queried checksum.
type answerCount struct {
	cur  uint32 // DCC_ANSWER_BODY_CKS.c — total including this report
	prev uint32 // .p — total before this report
}

// parseAnswer decodes a DCC_OP_ANSWER for n queried checksums and returns the
// per-checksum counts in the order they were sent. The trailing signature is
// not verified (anonymous servers send a zero signature).
func parseAnswer(buf []byte, n uint32, wantNums opNums) ([]answerCount, error) {
	if len(buf) < hdrLen {
		return nil, fmt.Errorf("dcc: short answer (%d bytes)", len(buf))
	}
	pktLen := int(binary.BigEndian.Uint16(buf[0:2]))
	op := buf[3]
	nums := opNums{
		h: binary.BigEndian.Uint32(buf[8:12]),
		p: binary.BigEndian.Uint32(buf[12:16]),
		r: binary.BigEndian.Uint32(buf[16:20]),
	}
	if nums.h != wantNums.h || nums.p != wantNums.p || nums.r != wantNums.r {
		return nil, errMismatch
	}
	if op == opError {
		msg := buf[hdrLen:]
		if len(msg) > 128 {
			msg = msg[:128]
		}
		return nil, fmt.Errorf("dcc: server error: %s", trimNul(msg))
	}
	if op != opAnswer {
		return nil, fmt.Errorf("dcc: unexpected op %d", op)
	}
	want := hdrLen + int(n)*8 + sigLen
	if pktLen != want || len(buf) < want {
		return nil, fmt.Errorf("dcc: answer length %d, expected %d", pktLen, want)
	}

	out := make([]answerCount, n)
	off := hdrLen
	for i := uint32(0); i < n; i++ {
		out[i] = answerCount{
			cur:  binary.BigEndian.Uint32(buf[off : off+4]),
			prev: binary.BigEndian.Uint32(buf[off+4 : off+8]),
		}
		off += 8
	}
	return out, nil
}

// errMismatch marks a response whose transaction id is not ours (a stray or
// late datagram); the caller keeps waiting.
var errMismatch = errors.New("dcc: response transaction id mismatch")

func trimNul(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// reportableCount returns how many checksums will be sent (Report==true).
func reportableCount(cks []Checksum) uint32 {
	var n uint32
	for _, c := range cks {
		if c.Report {
			n++
		}
	}
	return n
}
