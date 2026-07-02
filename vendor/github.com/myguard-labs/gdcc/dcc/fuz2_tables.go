package dcc

import (
	_ "embed"
	"encoding/binary"
)

// The Fuz2 language word dictionaries, extracted byte-for-byte from
// dcc-2.3.169 clntlib/cktbls.c (word_tbl_*). Each blob is: u32 bucket count,
// then per bucket u16 length + packed "len|word" entries. See gen in
// memory/eilandert/gdcc. Embedding keeps the generated data out of source.

//go:embed fuz2_english.bin
var fuz2EnglishBlob []byte

//go:embed fuz2_spanish.bin
var fuz2SpanishBlob []byte

//go:embed fuz2_polish.bin
var fuz2PolishBlob []byte

//go:embed fuz2_dutch.bin
var fuz2DutchBlob []byte

// fuz2Tbl mirrors FUZ2_TBL: a hash table of word buckets, plus the charset the
// language requires (nil = any; matches the default cset).
type fuz2Tbl struct {
	words [][]byte
	cset  *[256]byte
}

func decodeWordBlob(blob []byte) [][]byte {
	n := binary.BigEndian.Uint32(blob[:4])
	off := 4
	buckets := make([][]byte, n)
	for i := uint32(0); i < n; i++ {
		l := int(binary.BigEndian.Uint16(blob[off : off+2]))
		off += 2
		if l > 0 {
			buckets[i] = blob[off : off+l]
			off += l
		}
	}
	return buckets
}

// fuz2Tbls is the FUZ2_LANG_NUM language tables in order ENGLISH, SPANISH,
// POLISH, DUTCH (cktbls.c:fuz2_tbls). POLISH requires the 8859-2 charset.
var fuz2Tbls = []fuz2Tbl{
	{decodeWordBlob(fuz2EnglishBlob), nil},
	{decodeWordBlob(fuz2SpanishBlob), nil},
	{decodeWordBlob(fuz2PolishBlob), &cset8859_2},
	{decodeWordBlob(fuz2DutchBlob), nil},
}

// lookupWord ports clntlib/ckfuz2.c:lookup_word: hash the word, scan its bucket
// for an exact length+bytes match.
func lookupWord(w *ckWord, wlen int, buckets [][]byte) bool {
	h := be32(w[0:4]) ^ be32(w[4:8]) ^ be32(w[8:12]) ^ be32(w[12:16])
	bucket := buckets[h%uint32(len(buckets))] // #nosec G115 -- bucket count is a small positive table length
	if bucket == nil {
		return false
	}
	p := 0
	for {
		if p >= len(bucket) {
			return false
		}
		n := int(bucket[p])
		p++
		if n == 0 {
			return false
		}
		if n == wlen && string(bucket[p:p+n]) == string(w[:n]) {
			return true
		}
		p += n
	}
}
