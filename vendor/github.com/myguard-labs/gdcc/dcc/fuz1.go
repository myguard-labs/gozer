package dcc

import (
	"crypto/md5" // #nosec G501 -- DCC Fuz1 checksum is MD5 by protocol
	"hash"
)

// Fuz1 fuzzy body checksum — a faithful port of clntlib/ckfuz1.c.
//
// It lowercases the body, collects only ASCII letters into a line buffer,
// drops short greeting/date lines, strips URL cruft (keeping only host names,
// with third-level labels removed), and MD5s the result. White space, digits
// and punctuation are not summed.

const (
	fuz1MaxLine = 78
	fuz1BufMax  = fuz1MaxLine * 4 // 312, > DCC_MAXDOMAINLEN
	httpsLen    = 5               // len("https")
	fuz1BufSize = fuz1BufMax + httpsLen
	maxFuz1Len  = 4 * 1024

	urlHostMax     = 256 // DCC_MAXDOMAINLEN
	urlLabelMax    = 63
	urlHostMaxSave = 1 + urlHostMax
	urlFailsafe    = 2000
	domsBufSize    = urlHostMaxSave * 2
)

type urlSt int

const (
	urlIdle urlSt = iota
	urlQuote
	urlQH
	urlT1
	urlT2
	urlP
	urlS
	urlColon
	urlSlash1
	urlSlash2
	urlSlash3Start
	urlSlash3
	urlSkippingURL
)

const (
	urlTooLong  = 0x01
	urlSQuoted  = 0x02
	urlDQuoted  = 0x04
	urlQuoted   = urlSQuoted | urlDQuoted
	urlIDN      = 0x08
	urlDOT      = 0x10
	urlUsername = 0x20
)

type urlRes int

const (
	urlResFwd urlRes = iota
	urlResCkSpace
	urlResSkip
)

// ckURL ports CK_URL. start/tld/sld index into the Fuz1 buffer (-1 = NULL);
// dom*/dot*/labelStart/punct index into domsBuf (0 = unset, as in C).
type ckURL struct {
	cref       ckCref
	st         urlSt
	start      int
	tld        int
	sld        int
	urlTotal   int
	domStart   int
	domEnd     int
	dot2       int
	dot1       int
	labelStart int
	punct      int
	doms       int
	flags      byte
	domsBuf    [domsBufSize]byte
}

type fuz1State struct {
	buf   [fuz1BufSize]byte
	cp    int // end of bytes to sum in buf
	eol   int // most recent eol, -1 = none
	total int
	md5   hash.Hash
	c     *cks // back-pointer for the shared URL extractor + Fuz2 word count
}

func newFuz1State() *fuz1State {
	return &fuz1State{md5: md5.New(), eol: -1} // #nosec G401 -- DCC Fuz1 checksum is MD5 by protocol
}

func (f *fuz1State) addSum(length int) {
	if length == 0 {
		return
	}
	if i := maxFuz1Len - (f.total + length); i < 0 {
		length += i
	}
	if length == 0 {
		return
	}
	f.md5.Write(f.buf[:length])
	f.total += length
}

func (u *ckURL) resetDomsBuf(urlStart int) {
	u.start = urlStart
	u.tld = -1
	u.sld = -1
	u.domEnd = u.domStart
	u.labelStart = u.domEnd
	u.punct = 0
	u.dot1 = 0
	u.dot2 = 0
	u.urlTotal = 0
	u.flags &^= urlIDN | urlDOT
}

func (f *fuz1State) urlHostSave(uc byte) {
	u := &f.c.url
	if u.domEnd-u.domStart >= urlHostMax {
		u.resetDomsBuf(-1)
		u.flags |= urlTooLong
		u.st = urlIdle
	}
	if u.flags&urlTooLong != 0 {
		return
	}
	u.domsBuf[u.domEnd] = uc
	u.domEnd++
}

// urlHostEnd ports url_host_end: finalises a captured host name, removes the
// third-level label from the Fuz1 buffer, and (for Fuz2) trims domsBuf.
func (f *fuz1State) urlHostEnd() {
	u := &f.c.url
	if u.punct != 0 {
		u.domEnd = u.punct
	}
	if u.domEnd <= u.domStart || u.flags&urlTooLong != 0 {
		return
	}
	if u.flags&urlIDN != 0 {
		f.punyencode()
	}
	u.domsBuf[u.domEnd] = 0
	u.domEnd++
	// (url_dnsbl skipped: no DNS in the checksum-only path.)

	// Delete third-level domain labels for the fuzzy checksums.
	if u.dot2 != 0 {
		if f.eol == -1 {
			f.cp = u.start
		} else {
			length := f.cp - u.sld
			copy(f.buf[u.start:u.start+length], f.buf[u.sld:u.sld+length])
			if f.eol >= f.cp {
				f.eol = u.start + length
			}
			f.cp = u.start + length
		}
		if f.c.fz2WordCount() < fuz2MinWords {
			length := u.domEnd - u.dot2
			copy(u.domsBuf[u.domStart:u.domStart+length], u.domsBuf[u.dot2:u.dot2+length])
			u.domEnd = u.domStart + length
		}
	}

	u.domStart = u.domEnd
	u.doms++
}

// ckURLStep ports ck_url. pos points at the input index just past uc; cref
// completion may rewind it. Returns the disposition of uc.
func (f *fuz1State) ckURLStep(uc byte, pos *int) urlRes {
	u := &f.c.url

	if uc == '&' || u.cref.st != crefIdle {
		i := u.cref.step(uc)
		if i < 0 {
			return urlResFwd
		}
		*pos -= i
		uc = u.cref.result
	}

	switch u.st {
	case urlIdle:
		if uc == 'h' {
			u.st = urlT1
			u.flags = 0
		} else if uc == '=' {
			u.st = urlQuote
			u.flags = 0
		}

	case urlQuote:
		if uc == 'h' {
			u.st = urlT1
		} else if uc == '"' {
			u.flags |= urlDQuoted
			u.st = urlQH
		} else if uc == '\'' {
			u.flags = urlSQuoted
			u.st = urlQH
		} else {
			u.st = urlIdle
		}

	case urlQH:
		if uc == 'h' {
			u.st = urlT1
		} else {
			u.st = urlIdle
		}

	case urlT1:
		if uc == 't' {
			u.st = urlT2
		} else {
			u.st = urlIdle
		}

	case urlT2:
		if uc == 't' {
			u.st = urlP
		} else {
			u.st = urlIdle
		}

	case urlP:
		if uc == 'p' {
			u.st = urlS
		} else {
			u.st = urlIdle
		}

	case urlS:
		if uc == 's' {
			u.st = urlColon
		} else if uc == ':' {
			u.st = urlSlash1
		} else {
			u.st = urlIdle
		}

	case urlColon:
		if uc == ':' {
			u.st = urlSlash1
		} else {
			u.st = urlIdle
		}

	case urlSlash1:
		if uc == '/' {
			u.st = urlSlash2
		} else {
			u.st = urlIdle
		}

	case urlSlash2:
		if uc == '/' {
			if f.c.fz2WordCount() >= fuz2MinWords {
				u.domStart = 0
			} else {
				for u.domStart > domsBufSize-urlHostMaxSave {
					p := indexByteFrom(u.domsBuf[:], 0, u.domStart)
					if p < 0 {
						// large enough for >= 2 names, so this cannot happen
						panic("bad url.domsBuf")
					}
					p++
					u.domStart -= p
					copy(u.domsBuf[:], u.domsBuf[p:p+u.domStart])
				}
			}
			u.st = urlSlash3Start
			return urlResCkSpace
		}
		u.st = urlIdle

	case urlSlash3Start:
		u.resetDomsBuf(f.cp)
		u.st = urlSlash3
		fallthrough
	case urlSlash3:
		u.urlTotal++
		if u.urlTotal > urlFailsafe {
			u.st = urlIdle
			break
		}
		if !((uc >= 'a' && uc <= 'z') || (uc >= '0' && uc <= '9') || uc == '-' || uc == '_') {
			if uc == '.' && u.punct == 0 {
				if u.flags&urlDOT != 0 {
					u.punct = u.domEnd
					break
				}
				u.flags |= urlDOT
				break
			}
			if uc == '/' || uc == '\\' {
				f.urlHostEnd()
				u.st = urlSkippingURL
				break
			}
			if uc == '"' {
				f.urlHostEnd()
				if u.flags&urlSQuoted != 0 {
					u.st = urlSkippingURL
				} else {
					u.st = urlIdle
				}
				break
			}
			if uc == '\'' {
				f.urlHostEnd()
				if u.flags&urlDQuoted != 0 {
					u.st = urlSkippingURL
				} else {
					u.st = urlIdle
				}
				break
			}
			if uc == '<' || uc == '>' || uc <= ' ' || (uc == 0xa0 && u.flags&urlIDN == 0) {
				f.urlHostEnd()
				if u.flags&urlQuoted != 0 {
					u.st = urlSkippingURL
				} else {
					u.st = urlIdle
				}
				break
			}
			if uc == '@' && u.flags&urlUsername == 0 {
				u.flags |= urlUsername
				f.cp = u.start
				u.st = urlSlash3Start
				break
			}
			if uc == ':' ||
				((uc == ';' || uc == '?' || uc == '&' || uc == '=' || uc == '$' ||
					uc == '+' || uc == '!' || uc == '*' || uc == '(' || uc == ')' ||
					uc == ',') && u.flags&urlUsername == 0) {
				if u.punct == 0 {
					u.punct = u.domEnd
				}
			} else if uc&0xc0 == 0xc0 && u.punct == 0 {
				u.flags |= urlIDN
			} else {
				f.urlHostEnd()
				if u.flags&urlQuoted != 0 {
					u.st = urlSkippingURL
				} else {
					u.st = urlIdle
				}
				break
			}
		}
		if u.punct == 0 {
			if u.flags&urlDOT != 0 {
				u.flags &^= urlDOT
				if u.flags&urlIDN != 0 {
					f.punyencode()
				}
				f.urlHostSave('.')
				u.dot2 = u.dot1
				u.dot1 = u.domEnd
				u.labelStart = u.domEnd
				u.sld = u.tld
				u.tld = f.cp
			}
			f.urlHostSave(uc)
		}

	case urlSkippingURL:
		u.urlTotal++
		if (uc == '"' && u.flags&urlSQuoted == 0) ||
			(uc == '\'' && u.flags&urlDQuoted == 0) ||
			(uc == '>' && u.flags&urlQuoted == 0) ||
			uc == ' ' || uc == '\t' || uc == '\n' || uc == '\r' ||
			(uc == 0xa0 && u.flags&urlIDN == 0) ||
			u.urlTotal > urlFailsafe {
			u.st = urlIdle
		}
		return urlResSkip
	}

	return urlResFwd
}

func dearSucker(buf []byte) bool {
	dearWord := func(w string) bool {
		return len(buf) >= len(w)+1 && string(buf[:len(w)]) == w
	}
	return dearWord("dear") || dearWord("hello") || dearWord("greeting") || dearWord("date")
}

func (f *fuz1State) fuz1(bp []byte) {
	pos := 0
	cp := f.cp
	for {
		if pos >= len(bp) {
			if cp != 0 && f.eol == cp {
				f.addSum(cp)
				cp = 0
				f.eol = -1
				clearBuf(f.buf[:])
			}
			f.cp = cp
			return
		}
		c := toLower(bp[pos])
		pos++

		if c == 'h' || c == '=' || f.c.url.st != urlIdle {
			f.cp = cp
			res := f.ckURLStep(c, &pos)
			cp = f.cp
			switch res {
			case urlResFwd:
			case urlResCkSpace:
				for cp >= fuz1BufSize-urlHostMax {
					if f.eol == -1 {
						f.addSum(cp)
						cp = 0
						f.eol = -1
					} else {
						length := f.eol
						f.addSum(length)
						copy(f.buf[:], f.buf[f.eol:cp])
						cp -= length
						f.eol = -1
					}
					clearBufFrom(f.buf[:], cp)
				}
			case urlResSkip:
				continue
			}
		}

		if isLower(c) {
			f.buf[cp] = c
			cp++
			if cp < fuz1BufSize {
				continue
			}
			f.addSum(cp)
			cp = 0
			f.eol = -1
			clearBuf(f.buf[:])
			f.c.url.st = urlIdle
			continue
		}

		if c == '\n' {
			if f.eol != -1 {
				if length := cp - f.eol; length > 0 && length <= fuz1MaxLine && dearSucker(f.buf[f.eol:cp]) {
					cp = f.eol
					f.c.url.st = urlIdle
					continue
				}
			}
			if cp >= fuz1BufSize-(fuz1MaxLine+httpsLen) {
				f.addSum(cp)
				cp = 0
				f.eol = -1
				clearBuf(f.buf[:])
				f.c.url.st = urlIdle
				continue
			}
			f.eol = cp
		}
	}
}

func (f *fuz1State) final() (Sum, bool) {
	if f.total < 30 {
		return Sum{}, false
	}
	var s Sum
	copy(s[:], f.md5.Sum(nil))
	return s, true
}

// helpers ------------------------------------------------------------------

func clearBuf(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func clearBufFrom(b []byte, from int) {
	for i := from; i < len(b); i++ {
		b[i] = 0
	}
}

func indexByteFrom(b []byte, target byte, limit int) int {
	for i := 0; i < limit && i < len(b); i++ {
		if b[i] == target {
			return i
		}
	}
	return -1
}
