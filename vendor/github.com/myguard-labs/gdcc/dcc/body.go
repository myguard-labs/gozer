package dcc

import "hash"
import "crypto/md5" // #nosec G501 -- DCC body checksum is MD5 by protocol

// bodyState carries the streaming state of the simple body checksum
// (clntlib/ckbody.c:ck_body0). The C code buffers accepted bytes before
// MD5Update for speed; MD5 is a stream cipher so writing byte-runs directly is
// identical. flen and total persist across chunks exactly like ctx_body.
type bodyState struct {
	md5   hash.Hash
	total int
	flen  int    // index into "\n>From" of the partial match in progress
	buf   []byte // accepted bytes batched before MD5Update (perf)
}

// fromSeq is "\n>From"; fromTail is ">From" (what gets emitted on a mismatch).
var fromSeq = []byte("\n>From")
var fromTail = []byte(">From")

const bodyBufLen = 1024 // matches ckbody.c BUF_LEN

func newBodyState() *bodyState {
	// flen = 1: cks_init sets ctx_body.flen = 1.
	return &bodyState{md5: md5.New(), flen: 1, buf: make([]byte, 0, bodyBufLen+8)} // #nosec G401 -- DCC body checksum is MD5 by protocol
}

// emit batches accepted bytes; MD5 is a stream so flushing in chunks is
// identical to per-byte updates but avoids a heap alloc per byte.
func (b *bodyState) emit(p []byte) {
	b.buf = append(b.buf, p...)
	b.total += len(p)
	if len(b.buf) >= bodyBufLen {
		b.md5.Write(b.buf)
		b.buf = b.buf[:0]
	}
}

// body0 ports clntlib/ckbody.c:ck_body0: ignore whitespace, '\r', '=' and the
// '>' (and the '\n') of a "\n>From" sequence; MD5 everything else.
func (b *bodyState) body0(bp []byte) {
	for i := 0; i < len(bp); i++ {
		c := bp[i]

		if b.flen != 0 {
			if c == fromSeq[b.flen] {
				b.flen++
				if b.flen >= 6 {
					b.emit([]byte("From"))
					b.flen = 0
				}
				continue
			}
			b.flen--
			if b.flen != 0 {
				b.emit(fromTail[:b.flen])
				b.flen = 0
			}
		}

		if c == '\n' {
			b.flen = 1
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' {
			continue
		}
		if c == '=' {
			continue
		}
		b.emit(bp[i : i+1])
	}
}

// final returns the body checksum and whether it is valid (>= 30 accepted
// bytes, per ck_body0_fin). The MD5 is always computed; validity gates emission.
func (b *bodyState) final() (Sum, bool) {
	if len(b.buf) != 0 {
		b.md5.Write(b.buf)
		b.buf = b.buf[:0]
	}
	var s Sum
	copy(s[:], b.md5.Sum(nil))
	return s, b.total >= 30
}
