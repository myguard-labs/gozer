package dcc

import (
	"crypto/md5" // #nosec G501 -- DCC Fuz2 checksum is MD5 by protocol
	"hash"
)

// Fuz2 fuzzy body checksum — a faithful port of clntlib/ckfuz2.c.
//
// It folds the body to lower case via the MIME charset table, splits it into
// words, and for each language keeps an MD5 of only the words found in that
// language's dictionary. HTML tags and comments are skipped (and counted as
// "xsummed" filler). The language with the most dictionary words wins.

// Shared Fuz2 thresholds (clntlib/dcc_ck.h). fuz2MinWords is also read by the
// Fuz1 URL code to decide how to manage the host-name buffer.
const (
	fuz2FewWords = 100
	fuz2MinWords = 8
	fuz2LangNum  = 4

	fcA       = 0x61 // FC_A: lowest "letter" fold value
	fcSP      = 0x20 // FC_SP
	fcLT      = 0x3c // FC_LT
	minCkWlen = 3    // MIN_CK_WLEN
	ckWordLen = 16   // sizeof(CK_WORD)
	skipWlen  = ckWordLen + 1
)

// content-type class (subset of CK_CT_* used by Fuz2)
const (
	ckCtText = iota
	ckCtHTML
	ckCtBinary
)

type fuz2St int

const (
	fuz2StWord fuz2St = iota
	fuz2StStartTag
	fuz2StSkipTag
	fuz2StSkipComment
)

type fuz2Lang struct {
	wsummed int
	wtotal  int
	md5     hash.Hash
}

type fuz2State struct {
	wlen    int
	w       ckWord
	st      fuz2St
	cref    ckCref
	btotal  int
	xsummed int
	tagLen  int
	tag     ckWord
	lang    [fuz2LangNum]fuz2Lang

	c *cks // back-pointer for the shared mime charset/content-type + URL
}

func newFuz2State() *fuz2State {
	f := &fuz2State{st: fuz2StWord}
	f.cref.st = crefIdle
	for i := range f.lang {
		f.lang[i].md5 = md5.New() // #nosec G401 -- DCC Fuz2 checksum is MD5 by protocol
	}
	return f
}

func (f *fuz2State) skipWord() { f.wlen = skipWlen }
func (f *fuz2State) junk()     { f.wlen = skipWlen; f.st = fuz2StWord }

func (f *fuz2State) addWord() {
	for tbl := 0; tbl < fuz2LangNum; tbl++ {
		t := &fuz2Tbls[tbl]
		if t.cset != nil && t.cset != f.c.mimeCset {
			continue
		}
		if lookupWord(&f.w, f.wlen, t.words) {
			lp := &f.lang[tbl]
			lp.wtotal++
			lp.md5.Write(f.w[:f.wlen])
			lp.wsummed += f.wlen
		}
	}
}

func (f *fuz2State) fuz2(bp []byte) {
	pos := 0
	for pos < len(bp) {
		switch f.st {
		case fuz2StWord:
			for pos < len(bp) {
				c := bp[pos]
				pos++
				if f.cref.st != crefIdle || (c == '&' && f.c.mimeCt == ckCtHTML) {
					i := f.cref.step(c)
					if i < 0 {
						continue
					}
					pos -= i
					c = f.cref.result
				}
				c = f.c.mimeCset[c]
				if c >= fcA {
					f.btotal++
					if f.wlen < ckWordLen {
						f.w[f.wlen] = c
						f.wlen++
					} else {
						f.skipWord()
					}
					continue
				}
				if c == fcSP {
					if f.wlen >= minCkWlen && f.wlen <= ckWordLen {
						f.addWord()
					}
					f.wlen = 0
					f.w.clear()
					continue
				}
				f.btotal++
				if c == fcLT {
					f.tagLen = 0
					f.tag.clear()
					f.st = fuz2StStartTag
					break
				}
				f.junk()
			}

		case fuz2StStartTag:
			c := toLower(bp[pos])
			if ((isLower(c) || isDigit(c)) && f.tagLen < len(f.tag)) ||
				((c == '/' || c == '!') && f.tagLen == 0) ||
				(c == '-' && f.tagLen >= 1 && f.tagLen <= 2) {
				f.tag[f.tagLen] = c
				f.tagLen++
				f.btotal++
				pos++
				break
			}
			if f.tagLen == 4 && f.c.mimeCt != ckCtHTML && string(f.tag[:4]) == "html" {
				f.c.mimeCt = ckCtHTML
			}
			if f.c.mimeCt == ckCtHTML && f.tagLen > 0 {
				f.xsummed += f.tagLen + 1
				if c == '>' {
					f.xsummed++
					f.btotal++
					pos++
					f.st = fuz2StWord
					break
				}
				if f.tagLen >= 3 && string(f.tag[:3]) == "!--" {
					f.st = fuz2StSkipComment
				} else {
					f.st = fuz2StSkipTag
				}
			} else {
				f.junk()
			}

		case fuz2StSkipTag:
			for pos < len(bp) {
				f.btotal++
				c := bp[pos]
				pos++
				if f.cref.st != crefIdle || c == '&' {
					i := f.cref.step(c)
					if i < 0 {
						continue
					}
					pos -= i
					c = f.cref.result
				}
				if c == '>' {
					f.xsummed++
					f.btotal++
					f.st = fuz2StWord
					break
				}
				if f.c.mimeCset[c] != fcSP {
					f.xsummed++
					f.btotal++
					f.tagLen++
					if f.tagLen > urlFailsafe {
						f.junk()
						break
					}
				}
			}

		case fuz2StSkipComment:
			for pos < len(bp) {
				c := bp[pos]
				pos++
				if c == '>' {
					f.xsummed++
					f.btotal++
					f.st = fuz2StWord
					break
				}
				if f.c.mimeCset[c] != fcSP {
					f.xsummed++
					f.btotal++
					f.tagLen++
					if f.tagLen > urlFailsafe {
						f.junk()
						break
					}
				}
			}
		}
	}
}

// final ports dcc_ck_fuz2_fin: pick the language with the most dictionary
// words, validate, optionally fall back to URL host names, and finalise.
func (f *fuz2State) final(url *ckURL) (Sum, bool) {
	lp := &f.lang[0]
	for i := 1; i < fuz2LangNum; i++ {
		if lp.wtotal < f.lang[i].wtotal {
			lp = &f.lang[i]
		}
	}

	if lp.wtotal < fuz2FewWords && (lp.wsummed+f.xsummed)*10 < f.btotal {
		return Sum{}, false
	}
	if lp.wtotal < fuz2MinWords {
		if url != nil && lp.wtotal+url.doms*(fuz2MinWords/2) >= fuz2MinWords {
			if n := url.domStart - 1; n > 0 {
				lp.md5.Write(url.domsBuf[:n])
			}
		} else {
			return Sum{}, false
		}
	}

	var s Sum
	copy(s[:], lp.md5.Sum(nil))
	return s, true
}
