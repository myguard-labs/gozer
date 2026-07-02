package razor

import "strings"

// b64table is razor's custom base64 alphabet: the RFC 1521 alphabet with
// s:+:-: and s:/:_: (see Razor2::String). Index = 6-bit value, byte = char.
var b64table = func() [64]byte {
	var t [64]byte
	for i := 0; i <= 25; i++ {
		t[i] = byte(i + 65) // A-Z
	}
	for i := 26; i <= 51; i++ {
		t[i] = byte(i + 71) // a-z
	}
	for i := 52; i <= 61; i++ {
		t[i] = byte(i - 4) // 0-9
	}
	t[62] = '-'
	t[63] = '_'
	return t
}()

// b64rev maps a b64table char back to its 6-bit value (-1 if not in the alphabet).
var b64rev = func() [256]int {
	var r [256]int
	for i := range r {
		r[i] = -1
	}
	for v, c := range b64table {
		r[c] = v
	}
	return r
}()

func hexval(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return 0
}

const hexdigits = "0123456789abcdef"

// hextobase64 ports Razor2::String::hextobase64 byte-exact. It walks the hex
// string in 3-nibble chunks; each chunk is packed low-nibble-first (Perl
// `pack "h3"`) into 2 bytes, then split into two 6-bit values read with Perl
// `vec($bv,$n,1)` semantics (little-endian bit within little-endian byte), each
// mapped through b64table. Verified against perl: "abc"->"XT", a 40-hex SHA1
// digest -> 28 chars (no truncation; the perl truncation block is commented out).
func hextobase64(hs string) string {
	var sb strings.Builder
	for i := 0; i < len(hs); i += 3 {
		n0 := hexval(hs[i])
		n1, n2 := 0, 0
		if i+1 < len(hs) {
			n1 = hexval(hs[i+1])
		}
		if i+2 < len(hs) {
			n2 = hexval(hs[i+2])
		}
		bv := [2]byte{byte((n1 << 4) | n0), byte(n2)} // #nosec G115 -- nibbles, 0..255 by construction
		v1, v2 := 0, 0
		for bit := 0; bit < 6; bit++ {
			v1 = v1*2 + int((bv[bit>>3]>>(bit&7))&1)
		}
		for bit := 6; bit < 12; bit++ {
			v2 = v2*2 + int((bv[bit>>3]>>(bit&7))&1)
		}
		sb.WriteByte(b64table[v1])
		sb.WriteByte(b64table[v2])
	}
	return sb.String()
}

// base64tohex ports Razor2::String::base64tohex (inverse of hextobase64),
// including razor's length-42/66 truncation rules.
func base64tohex(bs string) string {
	var vals []int
	for i := 0; i < len(bs); i++ {
		if v := b64rev[bs[i]]; v >= 0 {
			vals = append(vals, v)
		}
	}
	var sb strings.Builder
	for len(vals) >= 1 {
		var bv [2]byte
		a := vals[0]
		vals = vals[1:]
		// first b64 value fills vec bits 0..5 (MSB at bit0)
		for k := 0; k < 6; k++ {
			i := 5 - k
			if a%2 == 1 {
				bv[i>>3] |= 1 << (i & 7)
			}
			a /= 2
		}
		if len(vals) >= 1 {
			a = vals[0]
			vals = vals[1:]
		} else {
			a = 0
		}
		for k := 0; k < 6; k++ {
			i := 17 - (6 + k)
			if a%2 == 1 {
				bv[i>>3] |= 1 << (i & 7)
			}
			a /= 2
		}
		// unpack "h3": 3 nibbles low-first from the 2 bytes
		sb.WriteByte(hexdigits[bv[0]&0x0f])
		sb.WriteByte(hexdigits[bv[0]>>4])
		sb.WriteByte(hexdigits[bv[1]&0x0f])
	}
	hexstr := sb.String()
	if len(hexstr) == 42 {
		hexstr = hexstr[:40]
	}
	if len(hexstr) == 66 {
		hexstr = hexstr[:64]
	}
	return hexstr
}
