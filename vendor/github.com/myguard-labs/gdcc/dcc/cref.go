package dcc

// ckCrefState ports CK_CREF (clntlib/dcc_ck.h) — the HTML character-reference
// decoder used inside URL scanning (Fuz1) and HTML text (Fuz2).
type crefSt int

const (
	crefIdle  crefSt = iota // CREF_ST_IDLE
	crefStart               // CREF_ST_START
	crefNum                 // CREF_ST_NUM
	crefDec                 // CREF_ST_DEC
	crefHex                 // CREF_ST_HEX
	crefName                // CREF_ST_NAME
)

type ckCref struct {
	st     crefSt
	w      ckWord
	length int
	result byte
}

// ckWord ports CK_WORD: 16 bytes, also viewed as four uint32 for hashing.
type ckWord [16]byte

func (w *ckWord) clear() {
	for i := range w {
		w[i] = 0
	}
}

func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// ckCrefStep ports clntlib/ckfuz1.c:ck_cref. Returns:
//
//	-1 need more input
//	 0 character in cref.result and the byte is the terminal ';'
//	 1 character in cref.result but stop short before the byte
func (cref *ckCref) step(uc byte) int {
	var n uint
	switch cref.st {
	case crefIdle:
		cref.st = crefStart
		return -1

	case crefStart:
		if uc == '#' {
			cref.st = crefNum
		} else if isLower(uc) || isUpper(uc) {
			cref.w.clear()
			cref.w[0] = uc
			cref.length = 1
			cref.st = crefName
		} else {
			cref.st = crefIdle
			return -1
		}

	case crefNum:
		if uc == 'x' || uc == 'X' {
			cref.result = 0
			cref.st = crefHex
		} else if uc >= '0' && uc <= '9' {
			cref.result = uc - '0'
			cref.st = crefDec
		} else {
			cref.result = '#'
			cref.st = crefIdle
			return 1
		}

	case crefDec:
		if uc >= '0' && uc <= '9' {
			n = uint(cref.result)*10 + uint(uc-'0')
		} else {
			cref.st = crefIdle
			return boolToInt(uc != ';')
		}
		if n > 255 {
			n = 255
		}
		cref.result = byte(n)

	case crefHex:
		if (uc >= 'a' && uc <= 'f') || (uc >= 'A' && uc <= 'F') {
			n = (uint(cref.result) << 4) + uint(uc&0xf) + 9
		} else if uc >= '0' && uc <= '9' {
			n = (uint(cref.result) << 4) + uint(uc-'0')
		} else {
			cref.st = crefIdle
			return boolToInt(uc != ';')
		}
		if n > 255 {
			n = 255
		}
		cref.result = byte(n)

	case crefName:
		if isLower(uc) || isUpper(uc) || isDigit(uc) {
			if cref.length < len(cref.w) {
				cref.w[cref.length] = uc
				cref.length++
			}
		} else {
			cref.result = lookupCref(&cref.w, cref.length)
			cref.st = crefIdle
			return boolToInt(uc != ';')
		}
	}
	return -1
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
