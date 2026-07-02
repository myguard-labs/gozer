package dcc

import "bytes"

// MIME decoding for the body checksums — a port of clntlib/ckmime.c plus the
// ck_body / decode_sum drivers from ckbody.c.

// ckMimeHdr ports ckmime.c:ck_mime_hdr — notice a Content-Type /
// Content-Transfer-Encoding header (whole line in hdr) during the RFC-822
// headers. hdr is the full unfolded "Name: value" field.
func (c *cks) ckMimeHdr(hdr []byte) {
	c.mhdrSt = mhdrCeCt
	c.mhdrPos = 0
	c.parseMimeHdr(hdr, true)
	if c.mhdrSt != mhdrIdle {
		c.parseMimeHdr([]byte("\n"), true)
	}
	if c.mimeNest != 0 {
		c.mpSt = mpPreamble
	}
	c.flags |= cksMimeBOL
}

// match ports ckmime.c:match — case-insensitive incremental match of tgt.
func (c *cks) mhMatch(ok, fail int, tgt string, bp *[]byte) bool {
	b := *bp
	// mhdrPos is reused as a counter by other states; on malformed input it can
	// exceed len(tgt). C lets the unsigned subtraction wrap and "succeeds" via an
	// over-read; we clamp and skip the compare to the same success outcome.
	n := len(tgt) - c.mhdrPos
	if n < 0 {
		n = 0
	}
	if n > len(b) {
		n = len(b)
	}
	if n > 0 && !eqFold(tgt[c.mhdrPos:c.mhdrPos+n], b[:n]) {
		c.mhdrSt = fail
		return false
	}
	*bp = b[n:]
	c.mhdrPos += n
	if c.mhdrPos >= len(tgt) {
		c.mhdrSt = ok
		c.mhdrPos = 0
		return true
	}
	return false
}

func eqFold(s string, b []byte) bool {
	for i := 0; i < len(s); i++ {
		if toLower(s[i]) != toLower(b[i]) {
			return false
		}
	}
	return true
}

func spanWS(bp *[]byte) bool {
	b := *bp
	for len(b) > 0 {
		c := b[0]
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			*bp = b
			return true
		}
		b = b[1:]
	}
	*bp = b
	return false
}

func skipParam(bp *[]byte) bool {
	b := *bp
	for len(b) > 0 {
		c := b[0]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			*bp = b
			return true
		}
		b = b[1:]
		if c == ';' {
			*bp = b
			return true
		}
	}
	*bp = b
	return false
}

// parseMimeHdr ports ckmime.c:parse_mime_hdr. Returns true on a blank line.
func (c *cks) parseMimeHdr(bp []byte, inHdrs bool) bool {
	if c.flags&cksMimeBOL != 0 && !inHdrs {
		if len(bp) == 0 {
			return false
		}
		ch := bp[0]
		if ch == '\r' {
			bp = bp[1:]
			if len(bp) == 0 {
				return false
			}
			ch = bp[0]
		}
		if ch == '\n' {
			return true
		}
		if ch != ' ' && ch != '\t' {
			c.mhdrSt = mhdrCeCt
			c.mhdrPos = 0
		}
		c.flags &^= cksMimeBOL
	}

	for len(bp) != 0 {
		switch c.mhdrSt {
		case mhdrIdle:
			return false

		case mhdrCeCt:
			if c.mhMatch(mhdrCtWS, mhdrIdle, "Content-T", &bp) {
				if len(bp) == 0 {
					return false // wait for more input (next parse_mime_hdr call)
				}
				// the ok state from mhMatch is overwritten per the next char
				switch bp[0] {
				case 'r', 'R':
					c.mhdrSt = mhdrCe
				case 'y', 'Y':
					c.mhdrSt = mhdrCt
				default:
					c.mhdrSt = mhdrIdle
					return false
				}
			}

		case mhdrCe:
			c.mhMatch(mhdrCeWS, mhdrIdle, "ransfer-Encoding:", &bp)

		case mhdrCeWS:
			if !spanWS(&bp) {
				return false
			}
			switch bp[0] {
			case 'b', 'B':
				c.mhdrSt = mhdrB64
			case 'q', 'Q':
				c.mhdrSt = mhdrQP
			default:
				c.mhdrSt = mhdrIdle
				return false
			}

		case mhdrQP:
			if c.mhMatch(mhdrIdle, mhdrIdle, "quoted-printable", &bp) {
				c.mimeCe = ceQP
			}

		case mhdrB64:
			if c.mhMatch(mhdrIdle, mhdrIdle, "base64", &bp) {
				c.mimeCe = ceB64
			}

		case mhdrCt:
			c.mhMatch(mhdrCtWS, mhdrIdle, "ype:", &bp)

		case mhdrCtWS:
			if !spanWS(&bp) {
				return false
			}
			switch bp[0] {
			case 't', 'T':
				c.mhdrSt = mhdrText
			case 'm', 'M':
				if inHdrs || c.mimeNest < mimeBndNum {
					c.mhdrSt = mhdrMultipart
				} else {
					c.mhdrSt = mhdrIdle
				}
			default:
				c.mimeCt = ckCtBinary
				c.mhdrSt = mhdrIdle
				return false
			}

		case mhdrText:
			if c.mhMatch(mhdrHTML, mhdrIdle, "text", &bp) {
				c.mimeCt = ckCtText
			}

		case mhdrHTML:
			if c.mhMatch(mhdrCsetSkipParam, mhdrCsetSkipParam, "/html", &bp) {
				c.mimeCt = ckCtHTML
			}

		case mhdrCsetSkipParam:
			if skipParam(&bp) {
				c.mhdrSt = mhdrCsetSpanWS
			}

		case mhdrCsetSpanWS:
			if spanWS(&bp) {
				c.mhdrSt = mhdrCset
			}

		case mhdrCset:
			c.mhMatch(mhdrCsetISO8859, mhdrCsetSkipParam, "charset=", &bp)

		case mhdrCsetISO8859:
			if c.mhdrPos == 0 && len(bp) > 0 && bp[0] == '"' {
				bp = bp[1:]
			}
			c.mhMatch(mhdrCsetISOX, mhdrIdle, "iso-8859-", &bp)

		case mhdrCsetISOX:
			for {
				if len(bp) == 0 {
					return false
				}
				ch := bp[0]
				bp = bp[1:]
				if ch < '0' || ch > '9' {
					if (ch == '"' || ch == ' ' || ch == '\t' || ch == ';' ||
						ch == '\r' || ch == '\n') && c.mhdrPos == 2 {
						c.mimeCset = &cset8859_2
					} else {
						c.mimeCset = &cset8859_1
					}
					c.mhdrSt = mhdrIdle
					return false
				}
				c.mhdrPos = c.mhdrPos*10 + int(ch-'0')
				if c.mhdrPos > 99 {
					c.mhdrSt = mhdrIdle
					return false
				}
			}

		case mhdrMultipart:
			c.mhdrSt = mhdrText
			c.mhMatch(mhdrBndSkipParam, mhdrIdle, "multipart", &bp)

		case mhdrBndSkipParam:
			if skipParam(&bp) {
				c.mhdrSt = mhdrBndSpanWS
			}

		case mhdrBndSpanWS:
			if spanWS(&bp) {
				c.mhdrSt = mhdrBnd
			}

		case mhdrBnd:
			if c.mhMatch(mhdrBndValue, mhdrBndSkipParam, "boundary=", &bp) {
				if inHdrs {
					c.mimeNest = 0
					c.mimeBndMatches = 1
				}
				bnd := &c.mimeBnd[c.mimeNest]
				c.flags &^= cksMimeQuoted
				bnd.bnd[0] = '-'
				bnd.bnd[1] = '-'
				c.mhdrPos = 2
			}

		case mhdrBndValue:
			bnd := &c.mimeBnd[c.mimeNest]
			done := false
			for !done {
				if len(bp) == 0 {
					return false
				}
				ch := bp[0]
				bp = bp[1:]
				if ch == '\n' {
					break
				}
				if ch == '\r' {
					continue
				}
				if (ch == ' ' || ch == '\t' || ch == ';') && c.flags&cksMimeQuoted == 0 {
					break
				}
				if ch == '"' {
					c.flags ^= cksMimeQuoted
					continue
				}
				bnd.bnd[c.mhdrPos] = ch
				c.mhdrPos++
				if c.mhdrPos >= ckBndMax {
					c.mhdrSt = mhdrIdle
					return false
				}
			}
			bnd.bndLen = c.mhdrPos
			bnd.cmpLen = 0
			c.mimeNest++
			c.mhdrSt = mhdrIdle
		}
	}
	return false
}

// decodeSum ports ckbody.c:decode_sum — decode quoted-printable / base64 per
// the current transfer encoding and feed the body and fuzzy checksummers.
func (c *cks) decodeSum(bp []byte) {
	if c.mpSt != mpText {
		if len(bp) == 0 {
			return
		}
		c.body.body0(bp)
		c.fz1.fuz1([]byte("\n"))
		c.fz2.fuz2([]byte("\n"))
		return
	}

	var tbuf [1024]byte
	pos := 0
	for pos < len(bp) {
		var chunk []byte
		switch c.mimeCe {
		case ceQP:
			outLen, consumed := c.qpDecode(bp[pos:], tbuf[:])
			chunk = tbuf[:outLen]
			pos += consumed
		case ceB64:
			outLen, consumed := c.b64Decode(bp[pos:], tbuf[:])
			chunk = tbuf[:outLen]
			pos += consumed
		default: // ceASCII
			chunk = bp[pos:]
			pos = len(bp)
		}
		if len(chunk) != 0 {
			c.body.body0(chunk)
			c.fz1.fuz1(chunk)
			if c.mimeCt != ckCtBinary {
				c.fz2.fuz2(chunk)
			}
		}
	}
}

// qpDecode ports ckmime.c:ck_qp_decode. Returns output length and how many
// input bytes were consumed.
func (c *cks) qpDecode(in, out []byte) (int, int) {
	if len(out) == 0 {
		return 0, 0
	}
	i := 0
	result := 0
	var ch byte
	for i < len(in) {
		switch c.qp.state {
		case qpIdle:
			ch = in[i]
			i++
			if ch != '=' {
				break
			}
			c.qp.state = qpEq
			continue

		case qpEq:
			ch = in[i]
			i++
			c.qp.x = ch
			if ch == '\r' {
				// fall to set state below
			} else if ch == '\n' {
				c.qp.state = qpIdle
				continue
			} else if ch >= '0' && ch <= '9' {
				c.qp.n = ch - '0'
			} else if ch >= 'a' && ch <= 'f' {
				c.qp.n = ch - ('a' - 10)
			} else if ch >= 'A' && ch <= 'F' {
				c.qp.n = ch - ('A' - 10)
			} else {
				c.qp.state = qpFail1
				ch = '='
				break
			}
			c.qp.state = qp1
			continue

		case qp1:
			ch = in[i]
			i++
			c.qp.y = ch
			if c.qp.x == '\r' {
				if ch == '\n' {
					c.qp.state = qpIdle
					continue
				}
				c.qp.state = qpFail2
				ch = '='
				break
			} else if ch >= '0' && ch <= '9' {
				ch -= '0'
			} else if ch >= 'a' && ch <= 'f' {
				ch -= ('a' - 10)
			} else if ch >= 'A' && ch <= 'F' {
				ch -= ('A' - 10)
			} else {
				c.qp.state = qpFail2
				ch = '='
				break
			}
			c.qp.state = qpIdle
			ch = byte(c.qp.n<<4) | ch

		case qpFail1:
			c.qp.state = qpIdle
			ch = c.qp.x

		case qpFail2:
			c.qp.state = qpFail3
			ch = c.qp.x

		case qpFail3:
			c.qp.state = qpIdle
			ch = c.qp.y
		}

		out[result] = ch
		result++
		if result >= len(out) {
			break
		}
	}
	return result, i
}

var base64Decode = [128]byte{
	0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
	0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
	0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
	0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
	0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
	0x40, 0x40, 0x40, 62, 0x40, 0x40, 0x40, 63,
	52, 53, 54, 55, 56, 57, 58, 59,
	60, 61, 0x40, 0x40, 0x40, 0x41, 0x40, 0x40,
	0x40, 0, 1, 2, 3, 4, 5, 6,
	7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22,
	23, 24, 25, 0x40, 0x40, 0x40, 0x40, 0x40,
	0x40, 26, 27, 28, 29, 30, 31, 32,
	33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48,
	49, 50, 51, 0x40, 0x40, 0x40, 0x40, 0x40,
}

const (
	b64Bad = 0o100 // B64B
	b64Eq  = 0o101 // B64EQ
)

// b64Decode ports ckmime.c:ck_b64_decode.
func (c *cks) b64Decode(in, out []byte) (int, int) {
	if len(out) < 3 {
		return 0, 0
	}
	outLim := len(out) - 3
	i := 0
	result := 0
	for i < len(in) {
		ci := in[i]
		i++
		if ci >= 128 {
			continue
		}
		v := base64Decode[ci]
		if v == b64Bad {
			continue
		}
		if v == b64Eq {
			switch c.b64.quantumCnt {
			case 2:
				out[result] = byte(c.b64.quantum >> 4) // #nosec G115 -- base64 quantum byte extraction
				result++
			case 3:
				out[result] = byte(c.b64.quantum >> 10)  // #nosec G115 -- base64 quantum byte extraction
				out[result+1] = byte(c.b64.quantum >> 2) // #nosec G115 -- base64 quantum byte extraction
				result += 2
			}
			c.b64.quantumCnt = 0
			if result >= outLim {
				break
			}
		}
		c.b64.quantum = (c.b64.quantum << 6) | uint32(v)
		c.b64.quantumCnt++
		if c.b64.quantumCnt >= 4 {
			c.b64.quantumCnt = 0
			out[result] = byte(c.b64.quantum >> 16)  // #nosec G115 -- base64 quantum byte extraction
			out[result+1] = byte(c.b64.quantum >> 8) // #nosec G115 -- base64 quantum byte extraction
			out[result+2] = byte(c.b64.quantum)      // #nosec G115 -- base64 quantum byte extraction
			result += 3
			if result >= outLim {
				break
			}
		}
	}
	return result, i
}

// ckBody ports ckbody.c:ck_body. Without multipart nesting it streams the whole
// body through decodeSum; the multipart boundary matcher is in ckBodyMultipart.
func (c *cks) ckBody(bp []byte) {
	if c.mimeNest == 0 {
		c.decodeSum(bp)
		return
	}
	c.ckBodyMultipart(bp)
}

// indexByteFromTo returns the absolute index of the first b in p[from:to], or -1.
func indexByteFromTo(p []byte, b byte, from, to int) int {
	if i := bytes.IndexByte(p[from:to], b); i >= 0 {
		return from + i
	}
	return -1
}
