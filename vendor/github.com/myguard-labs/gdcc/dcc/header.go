package dcc

import "crypto/md5" // #nosec G501 -- DCC checksums are MD5 by protocol

// hdrCkMax mirrors HDR_CK_MAX (include/dcc_ck.h): a header value is truncated to
// this many retained (non-stripped) bytes before checksumming.
const hdrCkMax = 1024

func isWhite(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

func toLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// str2ck is a faithful port of clntlib/ck.c:str2ck. It strips whitespace,
// the characters <>'", and case, then strips trailing periods, and MD5s the
// result (optionally prefixed by a substitute-header name).
func str2ck(hdrName, str string) Sum {
	cbuf := make([]byte, 0, hdrCkMax)
	for i := 0; i < len(str); i++ {
		if len(cbuf) >= hdrCkMax {
			break
		}
		c := str[i]
		if isWhite(c) || c == '<' || c == '>' || c == '\'' || c == '"' || c == ',' {
			continue
		}
		cbuf = append(cbuf, toLower(c))
	}
	// strip trailing periods (mostly for mail_host)
	for len(cbuf) > 0 && cbuf[len(cbuf)-1] == '.' {
		cbuf = cbuf[:len(cbuf)-1]
	}

	h := md5.New() // #nosec G401 -- DCC header checksum is MD5 by protocol
	if hdrName != "" {
		h.Write([]byte(hdrName))
	}
	h.Write(cbuf)
	var s Sum
	copy(s[:], h.Sum(nil))
	return s
}
