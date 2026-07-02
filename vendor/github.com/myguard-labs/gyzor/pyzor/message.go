package pyzor

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

// header is one wire header, kept in an ordered slice because the signature is
// computed over the exact serialized byte sequence (insertion order matters,
// exactly like Python email.message).
type header struct {
	key, val string
}

// request is an outgoing pyzor message built as an ordered header list.
type request struct {
	headers []header
}

func (r *request) add(key, val string) { r.headers = append(r.headers, header{key, val}) }

// op returns the request's Op (always the first header added by newRequest).
func (r *request) op() string {
	if len(r.headers) > 0 {
		return r.headers[0].val
	}
	return ""
}

// digestSpecFlat serializes the digest spec [(20,3),(60,3)] as "20,3,60,3",
// mirroring SimpleDigestSpecBasedRequest.
const digestSpecFlat = "20,3,60,3"

// newRequest builds an op request. For digest ops pass the digest; for ping it
// is "". For report/whitelist withSpec adds the Op-Spec header.
func newRequest(op, digest string, withSpec bool) *request {
	r := &request{}
	r.add("Op", op)
	if digest != "" {
		r.add("Op-Digest", digest)
		if withSpec {
			r.add("Op-Spec", digestSpecFlat)
		}
	}
	return r
}

// Thread-id ok range: [threadOKMin, 65536); 0..threadOKMin-1 reserved for server
// error replies (pyzor ThreadId).
const threadOKMin = 1024

// generateThread returns a request correlation token. It is only used to match a
// reply to its request (pyzor itself uses random.randrange), not a security value,
// so math/rand is fine.
func generateThread() int { return threadOKMin + rand.Intn(65536-threadOKMin) } // #nosec G404 -- non-security correlation id

// serialize returns the signed wire bytes. It appends Thread, PV, User, Time
// (matching ThreadedMessage.init_for_sending + Client.send order), computes the
// Sig over the strip()'d serialization, then appends Sig and the trailing blank
// line — identical to email.message.as_string().
func (r *request) serialize(acc Account, timestamp int64, thread int) []byte {
	r.add("Thread", strconv.Itoa(thread))
	r.add("PV", protoVersion)
	r.add("User", acc.Username)
	r.add("Time", strconv.FormatInt(timestamp, 10))

	signedText := r.headerString() // == as_string().strip() before Sig
	sig := signMsg(hashKey(acc.Key, acc.Username), timestamp, signedText)
	r.add("Sig", sig)

	return []byte(r.headerString() + "\n\n")
}

// headerString joins headers as "Key: Value" with "\n" (no trailing newline),
// which equals Python's msg.as_string().strip() for a header-only message.
func (r *request) headerString() string {
	var b strings.Builder
	for i, h := range r.headers {
		if i > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "%s: %s", h.key, h.val)
	}
	return b.String()
}

// response is a parsed server reply (RFC-822-ish key:value lines).
type response struct {
	fields map[string]string
}

func parseResponse(packet []byte) *response {
	r := &response{fields: map[string]string{}}
	for _, line := range strings.Split(string(packet), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		val := strings.TrimSpace(line[i+1:])
		r.fields[key] = val
	}
	return r
}

func (r *response) code() int {
	c, _ := strconv.Atoi(r.fields["Code"])
	return c
}

func (r *response) isOK() bool { return r.code() == 200 }

// validate rejects incomplete or mismatched responses, mirroring pyzor's
// Response.ensure_complete + read_response thread check. A response must carry
// Code, Diag, PV and Thread; a Thread in the ok range (>=threadOKMin) must equal
// the request's thread (error-range threads, <threadOKMin, are accepted as server
// error replies). Stops a malformed, delayed, or spoofed datagram being treated
// as authoritative.
func (r *response) validate(expectedThread int) error {
	for _, k := range []string{"Code", "Diag", "PV", "Thread"} {
		if _, ok := r.fields[k]; !ok {
			return fmt.Errorf("incomplete response: missing %s", k)
		}
	}
	thread, err := strconv.Atoi(r.fields["Thread"])
	if err != nil {
		return fmt.Errorf("invalid Thread %q", r.fields["Thread"])
	}
	if thread >= threadOKMin && thread != expectedThread {
		return fmt.Errorf("unexpected thread %d (want %d)", thread, expectedThread)
	}
	return nil
}

func (r *response) intField(key string) int {
	v, _ := strconv.Atoi(r.fields[key])
	return v
}

// requireCounts enforces that a successful check response carries both Count and
// WL-Count as integers (pyzor reads them directly and would raise otherwise).
// Prevents a malformed reply with a missing/garbage count becoming an
// authoritative 0/0 — or, worse, a spurious hit.
func (r *response) requireCounts() error {
	for _, k := range []string{"Count", "WL-Count"} {
		v, ok := r.fields[k]
		if !ok {
			return fmt.Errorf("incomplete check response: missing %s", k)
		}
		if _, err := strconv.Atoi(v); err != nil {
			return fmt.Errorf("invalid %s %q", k, v)
		}
	}
	return nil
}
