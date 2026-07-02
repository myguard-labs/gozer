package dcc

// lookupCref ports clntlib/cktbls.c:lookup_cref — resolve an HTML character
// reference name to its 8859-1 byte, or 0 if unknown.
//
// CK_WORD_HASH is ntohl(w32[0]^w32[1]^w32[2]^w32[3]) % len. Since the four
// words are loaded in host byte order and then ntohl'd, the result equals the
// XOR of the four 32-bit groups read big-endian — which is what be32 gives,
// so this is host-independent and matches dccproc on amd64.
func lookupCref(w *ckWord, clen int) byte {
	if clen > len(w) || clen == 0 {
		return 0
	}
	h := be32(w[0:4]) ^ be32(w[4:8]) ^ be32(w[8:12]) ^ be32(w[12:16])
	bucket := crefTbl[h%uint32(len(crefTbl))] // #nosec G115 -- bucket count is a small positive table length
	if bucket == nil {
		return 0
	}
	p := 0
	for {
		if p >= len(bucket) {
			return 0
		}
		n := int(bucket[p])
		p++
		if n == 0 {
			return 0
		}
		if n == clen && string(bucket[p:p+n]) == string(w[:n]) {
			return bucket[p+clen]
		}
		p += n + 1
	}
}
