package razor

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- razor protocol mandates SHA1; not a security primitive here
	"encoding/hex"
	"regexp"
	"strings"
)

// ephemeralSeed is razor's fixed PRNG seed (Ephemeral->new default).
const ephemeralSeed = 42

var wsOnlyRe = regexp.MustCompile(`^\s+$`)

// Ephemeral computes the razor Ephemeral (E4) signature of content with the
// default constructor (seed 42, chr(0) separator), byte-exact with
// Razor2::Signature::Ephemeral->new->hexdigest. Used by the parity test.
//
// NB: the default separator is chr(0), NOT newline. razor's
// encode_separator(undef) returns chr(0), and
// `encode_separator(undef) || encode_separator("10")` short-circuits on that
// truthy value, so the intended "\n" never applies. The protocol path uses a
// real ep4 separator (e.g. "10" -> chr(10)); see ephemeralHexdigest / engine.go.
func Ephemeral(content []byte) string {
	return ephemeralHexdigest(content, ephemeralSeed, []byte{0})
}

// encodeSeparator ports Razor2::Signature::Ephemeral::encode_separator for a
// real (non-undef) ep4 separator string: split on "-", chr() each piece, concat.
// e.g. "10" -> "\n"; "10-13" -> "\n\r".
func encodeSeparator(sep string) []byte {
	var out []byte
	for _, p := range strings.Split(sep, "-") {
		n := 0
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				break
			}
			n = n*10 + int(p[i]-'0')
		}
		out = append(out, byte(n))
	}
	return out
}

// ephemeralHexdigest is the parameterized Ephemeral engine. seed and sep come
// from the server ep4 ("seed-separator", default 7542-10) via vr4_signature.
func ephemeralHexdigest(content []byte, seed uint32, sep []byte) string {
	d := newDrand48(seed)
	lines := perlSplit(content, sep)
	nlines := len(lines)

	const sections = 6
	ssize := 100.0 / float64(sections)
	lineno := make([]int, sections)
	for i := 0; i < sections; i++ {
		rel := d.randf(ssize) + float64(i)*ssize
		lineno[i] = int(rel * float64(nlines) / 100.0)
	}
	relOff1 := [2]float64{d.randf(50) + 0*50, d.randf(50) + 1*50}
	relOff2 := [2]float64{d.randf(50) + 0*50, d.randf(50) + 1*50}

	l1 := sumLen(lines, lineno[1], lineno[2])
	l2 := sumLen(lines, lineno[3], lineno[4])
	off1 := [2]int{int(relOff1[0] * float64(l1) / 100.0), int(relOff1[1] * float64(l1) / 100.0)}
	off2 := [2]int{int(relOff2[0] * float64(l2) / 100.0), int(relOff2[1] * float64(l2) / 100.0)}

	sec1 := pickSection(lines, lineno[1], lineno[2], off1[0], off1[1])
	sec2 := pickSection(lines, lineno[3], lineno[4], off2[0], off2[1])

	seclen := len(sec1) + len(sec2)
	if wsOnlyRe.Match(sec1) && wsOnlyRe.Match(sec2) {
		sec1, sec2 = nil, nil
	}
	h := sha1.New() // #nosec G401 -- razor protocol mandates SHA1
	if seclen > 128 {
		h.Write(sec1)
		h.Write(sec2)
	} else {
		h.Write(content)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// perlSplit mimics Perl `split /SEP/, $s` for a literal separator byte sequence:
// split on each occurrence of sep, trailing empty fields removed. razor's ep4
// separators are control chars (chr(0), chr(10), chr(13)) which carry no regex
// meaning, so a literal split matches perl's regex split exactly.
func perlSplit(b, sep []byte) [][]byte {
	var out [][]byte
	if len(sep) == 0 {
		out = append(out, b)
	} else {
		start := 0
		for {
			i := bytes.Index(b[start:], sep)
			if i < 0 {
				out = append(out, b[start:])
				break
			}
			out = append(out, b[start:start+i])
			start += i + len(sep)
		}
	}
	for len(out) > 0 && len(out[len(out)-1]) == 0 {
		out = out[:len(out)-1]
	}
	return out
}

// perlTruthy mimics Perl boolean: "" and "0" are false.
func perlTruthy(b []byte) bool { return len(b) != 0 && !(len(b) == 1 && b[0] == '0') }

func sumLen(lines [][]byte, a, b int) int {
	l := 0
	for i := a; i <= b; i++ {
		if i >= 0 && i < len(lines) && perlTruthy(lines[i]) {
			l += len(lines[i])
		}
	}
	return l
}

// pickSection ports Razor2::Signature::Ephemeral::picksection exactly.
func pickSection(content [][]byte, sline, eline, soffset, eoffset int) []byte {
	x, sc, sl, ec, el := 0, 0, 0, 0, 0
	for i := sline; i <= eline; i++ {
		if i < 0 || i >= len(content) || !perlTruthy(content[i]) {
			continue
		}
		x += len(content[i])
		if x > soffset && sc == 0 {
			sc = len(content[i]) - (x - soffset)
			sl = i
		}
		if x > eoffset {
			ec = len(content[i]) - (x - eoffset)
			el = i
		}
		if ec != 0 {
			break
		}
	}
	if sc < 0 {
		sc = 0
	}
	if ec < 0 {
		ec = 0
	}
	if sl == el {
		if sl >= 0 && sl < len(content) && perlTruthy(content[sl]) {
			return perlSubstrLen(content[sl], sc, ec-sc+1)
		}
		return nil
	}
	var out []byte
	out = append(out, perlSubstrFrom(content[sl], sc)...)
	for i := sl + 1; i <= el-1; i++ {
		out = append(out, content[i]...)
	}
	out = append(out, perlSubstrLen(content[el], 0, ec)...)
	return out
}

// perlSubstrLen replicates Perl substr(s, off, length) for off>=0.
func perlSubstrLen(s []byte, off, length int) []byte {
	n := len(s)
	if off > n {
		return nil
	}
	if off < 0 {
		off = 0
	}
	var end int
	if length < 0 {
		end = n + length
	} else {
		end = off + length
	}
	if end > n {
		end = n
	}
	if end < off {
		return nil
	}
	return s[off:end]
}

func perlSubstrFrom(s []byte, off int) []byte {
	if off >= len(s) {
		return nil
	}
	if off < 0 {
		off = 0
	}
	return s[off:]
}
