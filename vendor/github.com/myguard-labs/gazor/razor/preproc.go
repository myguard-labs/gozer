package razor

import (
	"encoding/base64"
	"regexp"
)

// reBlank matches the header/body separator: \n, optional \r's, \n
// (Perl `split /\n\r*\n/, $text, 2`).
var reBlank = regexp.MustCompile("\n\r*\n")

// splitHdrBody splits "headers\n\nbody" on the first blank line. hasBlank is
// false when there is no blank line (perl: $body is undef).
func splitHdrBody(b []byte) (hdr, body []byte, hasBlank bool) {
	loc := reBlank.FindIndex(b)
	if loc == nil {
		return b, nil, false
	}
	return b[:loc[0]], b[loc[1]:], true
}

func joinHdrBody(hdr, body []byte) []byte {
	out := make([]byte, 0, len(hdr)+2+len(body))
	out = append(out, hdr...)
	out = append(out, '\n', '\n')
	out = append(out, body...)
	return out
}

// preprocManager mirrors Razor2::Preproc::Manager. The VR4 chain runs deHTML;
// the VR8 chain does not (Whiplash needs raw URLs/hrefs). Neither runs
// deHTML_comment (the agent never enables it).
type preprocManager struct {
	deBase64, deQP, deHTML, deNewline bool
}

var (
	managerVR4 = preprocManager{deBase64: true, deQP: true, deHTML: true, deNewline: true}
	managerVR8 = preprocManager{deBase64: true, deQP: true, deHTML: false, deNewline: true}
)

// preproc runs the chain and returns the body (headers stripped), matching
// Razor2::Preproc::Manager::preproc.
func (m preprocManager) preproc(text []byte) []byte {
	if m.deBase64 && deBase64Isit(text) {
		text = deBase64Doit(text)
	}
	if m.deQP && deQPIsit(text) {
		text = deQPDoit(text)
	}
	if m.deHTML && deHTMLIsit(text) {
		text = deHTMLDoit(text)
	}
	if m.deNewline {
		text = deNewlineDoit(text)
	}
	_, body, _ := splitHdrBody(text)
	return body
}

// --- deBase64 ---

var (
	reB64Isit    = regexp.MustCompile(`(?im)^Content-Transfer-Encoding: base64`)
	reB64Extract = regexp.MustCompile(`(?is)Content-Transfer-Encoding: base64(.*)$`)
	reB64Data    = regexp.MustCompile(`(?s)\r?\n\r?\n([^=]*)`)
	reB64Keep    = regexp.MustCompile(`[^A-Za-z0-9+/]`)
)

func deBase64Isit(text []byte) bool { return reB64Isit.Match(text) }

func deBase64Doit(text []byte) []byte {
	hdr, _, _ := splitHdrBody(text)
	var payload []byte
	if m := reB64Extract.FindSubmatch(text); m != nil {
		if d := reB64Data.FindSubmatch(m[1]); d != nil {
			payload = d[1]
		}
	}
	payload = reB64Keep.ReplaceAll(payload, nil)
	return joinHdrBody(hdr, lenientB64Decode(payload))
}

// lenientB64Decode decodes standard base64 (no padding) the way razor's
// uudecode loop does: leftover-tail tolerant. Trims to a decodable length
// rather than failing on malformed mail.
func lenientB64Decode(b []byte) []byte {
	for len(b) > 0 {
		if len(b)%4 == 1 {
			b = b[:len(b)-1] // an isolated trailing char encodes nothing
			continue
		}
		if dec, err := base64.RawStdEncoding.DecodeString(string(b)); err == nil {
			return dec
		}
		b = b[:len(b)-1]
	}
	return nil
}

// --- deQP ---

var (
	reQPIsit = regexp.MustCompile(`(?im)^Content-Transfer-Encoding: quoted-printable`)
	reQPSoft = regexp.MustCompile(`=\r?\n`)
	reQPEsc  = regexp.MustCompile(`=([0-9A-Fa-f]{2})`)
)

func deQPIsit(text []byte) bool {
	hdr, _, _ := splitHdrBody(text)
	return reQPIsit.Match(hdr)
}

func deQPDoit(text []byte) []byte {
	hdr, body, _ := splitHdrBody(text)
	body = reQPSoft.ReplaceAll(body, nil)
	body = reQPEsc.ReplaceAllFunc(body, func(m []byte) []byte {
		return []byte{byte(hexval(m[1])<<4 | hexval(m[2]))} // #nosec G115 -- two hex nibbles, 0..255
	})
	return joinHdrBody(hdr, body)
}

// --- deHTML ---

var (
	reHTMLBody = regexp.MustCompile(`(?is)<HTML>|<BODY|<FONT|<A HREF`)
	reHTMLHdr  = regexp.MustCompile(`(?im)^Content-Type: text/html`)
)

func deHTMLIsit(text []byte) bool {
	hdr, body, _ := splitHdrBody(text)
	if len(body) == 0 {
		return false
	}
	if reHTMLBody.Match(body) {
		return true
	}
	return reHTMLHdr.Match(hdr)
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// htmlTags maps HTML entity names to their byte value, matching
// Razor2::Preproc::deHTML's table (latin1: chr(161)..chr(255) plus the 5 specials).
var htmlTags = func() map[string]byte {
	t := map[string]byte{"lt": '<', "gt": '>', "amp": '&', "quot": '"', "nbsp": ' '}
	names := []string{
		"iexcl", "cent", "pound", "curren", "yen", "brvbar", "sect", "uml", "copy",
		"ordf", "laquo", "not", "shy", "reg", "macr", "deg", "plusmn", "sup2", "sup3",
		"acute", "micro", "para", "middot", "cedil", "sup1", "ordm", "raquo", "frac14",
		"frac12", "frac34", "iquest", "Agrave", "Aacute", "Acirc", "Atilde", "Auml",
		"Aring", "AElig", "Ccedil", "Egrave", "Eacute", "Ecirc", "Euml", "Igrave",
		"Iacute", "Icirc", "Iuml", "ETH", "Ntilde", "Ograve", "Oacute", "Ocirc",
		"Otilde", "Ouml", "times", "Oslash", "Ugrave", "Uacute", "Ucirc", "Uuml",
		"Yacute", "THORN", "szlig", "agrave", "aacute", "acirc", "atilde", "auml",
		"aring", "aelig", "ccedil", "egrave", "eacute", "ecirc", "euml", "igrave",
		"iacute", "icirc", "iuml", "eth", "ntilde", "ograve", "oacute", "ocirc",
		"otilde", "ouml", "divide", "oslash", "ugrave", "uacute", "ucirc", "uuml",
		"yacute", "thorn", "yuml",
	}
	for i, n := range names {
		t[n] = byte(161 + i)
	}
	return t
}()

// htmlXlat ports Razor2::Preproc::deHTML::html_xlat: from i (just past '&'),
// read [a-zA-Z]+ as the entity name, optionally consume a trailing ';', and
// return (chars-consumed, value, found).
func htmlXlat(chars []byte, i int) (int, byte, bool) {
	if i >= len(chars) || !isAlpha(chars[i]) {
		return 0, 0, false
	}
	j := i
	for j < len(chars) && isAlpha(chars[j]) {
		j++
	}
	n := j - i
	if j < len(chars) && chars[j] == ';' {
		n++
	}
	v, ok := htmlTags[string(chars[i:j])]
	if !ok {
		return 0, 0, false
	}
	return n, v, true
}

func deHTMLDoit(text []byte) []byte {
	hdr, body, _ := splitHdrBody(text)
	chars := body
	n := len(chars)
	var last byte
	var quote byte
	sgml := false
	tag := false
	out := make([]byte, 0, n)
	i := 0
	for i < n {
		c := chars[i]
		i++
		if quote != 0 && c == quote {
			if c == '-' && last != '-' {
				last = c
				continue
			}
			last = 0
			quote = 0
		} else if quote == 0 {
			switch {
			case c == '<':
				tag = true
				if i < n && chars[i] == '!' {
					sgml = true
				}
				i++ // consume char after '<' (perl: $chars[$i++])
			case c == '>':
				if tag {
					sgml = false
					tag = false
				}
			case c == '-':
				if sgml && last == '-' {
					quote = '-'
				} else if !tag {
					out = append(out, c)
				}
			case c == '"' || c == '\'':
				if tag {
					quote = c
				} else {
					out = append(out, c)
				}
			case c == '&':
				if ln, ch, ok := htmlXlat(chars, i); ok {
					out = append(out, ch)
					i += ln
				} else {
					out = append(out, c)
				}
			default:
				if !tag {
					out = append(out, c)
				}
			}
		}
		last = c
	}
	return joinHdrBody(hdr, out)
}

// --- deNewline ---

func deNewlineDoit(text []byte) []byte {
	hdr, body, hasBlank := splitHdrBody(text)
	if !hasBlank || len(body) == 0 {
		return text
	}
	end := len(body)
	for end > 0 && body[end-1] == '\n' {
		end--
	}
	if end == len(body) {
		return text // no trailing newlines removed
	}
	return joinHdrBody(hdr, body[:end])
}
