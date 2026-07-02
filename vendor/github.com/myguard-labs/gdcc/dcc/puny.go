package dcc

// Punycode (RFC 3492) encoding of an IDN host label, ported from
// clntlib/ckfuz1.c:punyencode. Used only when a URL host name contains UTF-8;
// the encoded label replaces the raw bytes in domsBuf so the fuzzy/DNSBL host
// names are normalised the same way dccproc normalises them.

const (
	utf8Max         = 0x10ffff
	punyPrefix      = "xn--"
	punyBase        = 36
	punyTmin        = 1
	punyTmax        = 26
	punySkew        = 38
	punyDamp        = 700
	punyInitialBias = 72
	punyInitialN    = 0x80
	punyCode36      = "abcdefghijklmnopqrstuvwxyz0123456789"
)

func punyAdapt(delta, numpoints uint, firsttime bool) int {
	if firsttime {
		delta /= punyDamp
	} else {
		delta /= 2
	}
	delta += delta / numpoints
	k := 0
	for delta > ((punyBase-punyTmin)*punyTmax)/2 {
		delta /= (punyBase - punyTmin)
		k += punyBase
	}
	return k + int(((punyBase-punyTmin+1)*delta)/(delta+punySkew))
}

func (f *fuz1State) punyencode() {
	u := &f.c.url
	u.flags &^= urlIDN

	var puny [urlLabelMax]byte
	punyLen := 0
	punyOut := func(c byte) bool {
		if punyLen >= urlLabelMax {
			return false
		}
		puny[punyLen] = c
		punyLen++
		return true
	}

	// decode UTF-8 (+1 slot guards the C off-by-one read in the m-search)
	var unicode [urlLabelMax + 1]uint32
	unicodeLen := 0
	i := u.labelStart
	for {
		uc := uint32(u.domsBuf[i])
		i++
		if uc&0x80 != 0 {
			switch {
			case uc&0xe0 == 0xc0:
				uc &= 0x1f
				if uc == 0 || i >= u.domEnd {
					return
				}
				uc2 := uint32(u.domsBuf[i]) ^ 0x80
				i++
				if uc2 > 0x3f {
					return
				}
				uc = (uc << 6) | uc2
			case uc&0xf0 == 0xe0:
				uc &= 0x0f
				if uc == 0 || i+1 >= u.domEnd {
					return
				}
				uc2 := uint32(u.domsBuf[i]) ^ 0x80
				uc3 := uint32(u.domsBuf[i+1]) ^ 0x80
				i += 2
				if uc2 > 0x3f || uc3 > 0x3f {
					return
				}
				uc = (((uc << 6) | uc2) << 6) | uc3
			case uc&0xf8 == 0xf0:
				uc &= 0x07
				if uc == 0 || i+2 >= u.domEnd {
					return
				}
				uc2 := uint32(u.domsBuf[i]) ^ 0x80
				uc3 := uint32(u.domsBuf[i+1]) ^ 0x80
				uc4 := uint32(u.domsBuf[i+2]) ^ 0x80
				i += 3
				if uc2 > 0x3f || uc3 > 0x3f || uc4 > 0x3f {
					return
				}
				uc = (((((uc << 6) | uc2) << 6) | uc3) << 6) | uc4
			default:
				return
			}
			if uc > utf8Max {
				return
			}
		}
		if unicodeLen >= urlLabelMax {
			return
		}
		unicode[unicodeLen] = uc
		unicodeLen++
		if i == u.domEnd {
			break
		}
	}

	punyLen = len(punyPrefix)
	copy(puny[:], punyPrefix)

	n := uint(punyInitialN)
	delta := uint(0)
	bias := uint(punyInitialBias)
	b := 0
	for idx := 0; idx < unicodeLen; idx++ {
		uc := unicode[idx] // #nosec G602 -- idx < unicodeLen <= urlLabelMax; array is sized urlLabelMax+1
		if uc >= 0x80 {
			continue
		}
		if !punyOut(byte(uc)) {
			return
		}
		b++
	}
	if b != 0 {
		if !punyOut('-') {
			return
		}
	}

	h := b
	for h < unicodeLen {
		m := uint(utf8Max + 1)
		for idx := 0; idx <= unicodeLen; idx++ {
			if uint(unicode[idx]) < m && uint(unicode[idx]) >= n {
				m = uint(unicode[idx])
			}
		}
		delta += (m - n) * uint(h+1)
		n = m
		for idx := 0; idx < unicodeLen; idx++ {
			uc := uint(unicode[idx]) // #nosec G602 -- idx < unicodeLen <= urlLabelMax; array is sized urlLabelMax+1
			if uc < n {
				delta++
			} else if uc == n {
				q := delta
				for k := uint(punyBase); ; k += punyBase {
					var t uint
					switch {
					case k <= bias:
						t = punyTmin
					case k >= bias+punyTmax:
						t = punyTmax
					default:
						t = k - bias
					}
					if q < t {
						break
					}
					if !punyOut(punyCode36[t+(q-t)%(punyBase-t)]) {
						return
					}
					q = (q - t) / (punyBase - t)
				}
				if !punyOut(punyCode36[q]) {
					return
				}
				bias = uint(punyAdapt(delta, uint(h+1), h == b))
				delta = 0
				h++
			}
		}
		delta++
		n++
	}

	if u.labelStart+punyLen <= urlHostMax {
		u.domEnd = u.labelStart + punyLen
		copy(u.domsBuf[u.labelStart:u.labelStart+punyLen], puny[:punyLen])
	}
}
