package razor

import (
	"sort"
	"strings"
)

const hexUpper = "0123456789ABCDEF"

// isUnreserved matches URI::Escape's default "unreserved" set (RFC 2396):
// alphanumerics plus the mark characters. razor sigs (custom base64 with - and _),
// engine numbers and ep4 ("7542-10") are all unreserved, so makesis rarely escapes.
func isUnreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("-_.!~*'()", c) >= 0
}

func uriEscape(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			sb.WriteByte(c)
			continue
		}
		sb.WriteByte('%')
		sb.WriteByte(hexUpper[c>>4])
		sb.WriteByte(hexUpper[c&0xf])
	}
	return sb.String()
}

// uriUnescape ports URI::Escape::uri_unescape: %XX -> byte, everything else
// verbatim (notably '+' is NOT turned into a space).
func uriUnescape(s string) string {
	if !strings.ContainsRune(s, '%') {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			sb.WriteByte(byte(hexval(s[i+1])<<4 | hexval(s[i+2]))) // #nosec G115 -- two hex nibbles, 0..255
			i += 2
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// makesis ports Razor2::String::makesis: keys sorted, values uri-escaped,
// joined "k=v&k=v", terminated with CRLF.
func makesis(data map[string]string) string {
	return sis(data, true)
}

// makesisNue ports makesis_nue: same, without uri escaping.
func makesisNue(data map[string]string) string {
	return sis(data, false)
}

func sis(data map[string]string, escape bool) string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte('=')
		if escape {
			sb.WriteString(uriEscape(data[k]))
		} else {
			sb.WriteString(data[k])
		}
		sb.WriteByte('&')
	}
	s := sb.String()
	if len(s) > 0 {
		s = s[:len(s)-1] // drop trailing &
	}
	return s + "\r\n"
}

// parsesis ports Razor2::String::parsesis: strip trailing CR/LF, split on '&',
// each pair on the first '=', uri-unescape the value.
func parsesis(s string) map[string]string {
	s = strings.TrimRight(s, "\n")
	s = strings.TrimRight(s, "\r")
	q := map[string]string{}
	if s == "" {
		return q
	}
	for _, pair := range strings.Split(s, "&") {
		k, v, _ := strings.Cut(pair, "=")
		q[k] = uriUnescape(v)
	}
	return q
}
