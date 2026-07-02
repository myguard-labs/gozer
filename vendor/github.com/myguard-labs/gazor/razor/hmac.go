package razor

import (
	"crypto/sha1" // #nosec G505 -- razor auth protocol mandates SHA1
	"encoding/hex"
)

// xorKey ports Razor2::String::xor_key. Perl string XOR against the longer
// operand pads the shorter with NUL, so for a key shorter than 64 the trailing
// bytes stay 0x36/0x5C. Used to derive the HMAC inner/outer pads from the pass.
func xorKey(key string) (iv1, iv2 []byte) {
	n := 64
	if len(key) > n {
		n = len(key)
	}
	iv1 = make([]byte, n)
	iv2 = make([]byte, n)
	for i := 0; i < n; i++ {
		var base36, base5c, k byte
		if i < 64 {
			base36, base5c = 0x36, 0x5C
		}
		if i < len(key) {
			k = key[i]
		}
		iv1[i] = base36 ^ k
		iv2[i] = base5c ^ k
	}
	return
}

// hmacSHA1 ports Razor2::String::hmac_sha1 (returns the base64 form of
// hmac2_sha1). NB razor's HMAC hashes the *hex string* of the inner digest in
// the outer round, not its raw bytes — reproduced here for byte-exact auth.
func hmacSHA1(text string, iv1, iv2 []byte) string {
	h := sha1.New() // #nosec G401
	h.Write(iv2)
	h.Write([]byte(text))
	d1 := hex.EncodeToString(h.Sum(nil))

	h = sha1.New() // #nosec G401
	h.Write(iv1)
	h.Write([]byte(d1))
	d2 := hex.EncodeToString(h.Sum(nil))

	return hextobase64(d2)
}
