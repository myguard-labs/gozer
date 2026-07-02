package razor

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
)

// prep_mail size caps (Core.pm prepare_parts).
const (
	maxHeader  = 4 * 1024
	maxBody    = 60 * 1024
	maxOrigHdr = 15 * 1024

	// MIME structure limits: bound recursion depth and total parts so a deeply
	// nested or part-bomb message cannot exhaust stack/memory.
	maxMimeDepth = 20
	maxMimeParts = 1024
)

var (
	reFold      = regexp.MustCompile(`\n\s+`)
	reBoundary  = regexp.MustCompile(`(?i)Content-Type: multipart.+boundary=("[^"]+"|\S+)`)
	reContentTy = regexp.MustCompile(`(?i)^Content-Type:`)
	reNonWS     = regexp.MustCompile(`\S`)
	reLastLine  = regexp.MustCompile(`(?s)\n[^\n]*$`)
)

// prepMail ports Razor2::String::prep_mail: split the raw message into the
// original header block plus the preprocessed MIME body parts. reportHeaders
// mirrors the conf flag (default true → keep full headers). ver is the
// X-Razor2-Agent string.
func prepMail(mail []byte, reportHeaders bool, ver string) (headers []byte, parts [][]byte) {
	origHdr, _, _ := splitHdrBody(mail)
	origHdr = append(append([]byte{}, origHdr...), '\n') // put newline back on last header line

	if ver == "" {
		ver = "1"
	}
	count := 0
	mimeparts := splitMime(mail, ver, false, 0, &count)
	for _, mp := range mimeparts {
		if p := prepPart(mp, maxHeader, maxBody); p != nil {
			parts = append(parts, p)
		}
	}

	if !reportHeaders {
		var hdr strings.Builder
		hdr.WriteString("X-Razor2-Headers-Suppressed: 1\n")
		for _, ln := range splitLF(origHdr) {
			if hasPrefixFold(ln, "Content-") || hasPrefixFold(ln, "X-Razor2") {
				hdr.WriteString(ln)
				hdr.WriteByte('\n')
			}
		}
		origHdr = []byte(hdr.String())
	}

	if len(origHdr) > maxOrigHdr {
		origHdr = capWithOriglen(origHdr, "X-Razor2-Origlen-Header", maxOrigHdr)
	}
	return origHdr, parts
}

// leafPart wraps mail as a single non-MIME leaf part (the split_mime "no valid
// MIME" fallback): prefix the agent header, ensure a blank line before the body.
func leafPart(mail []byte, ver string) [][]byte {
	mimepart := []byte("X-Razor2-Agent: " + ver + "\n")
	if len(mail) > 0 && mail[0] == '\n' {
		mimepart = append(mimepart, mail...)
	} else {
		mimepart = append(mimepart, '\n')
		mimepart = append(mimepart, mail...)
	}
	return [][]byte{mimepart}
}

// splitMime ports Razor2::String::split_mime. recursive is false at the top
// level; depth tracks nesting and count the running leaf-part total, both
// bounded (maxMimeDepth/maxMimeParts) against nesting/part-bomb messages.
// Returns one entry per leaf MIME part, each "headers\n\nbody".
func splitMime(mail []byte, ver string, recursive bool, depth int, count *int) [][]byte {
	if depth > maxMimeDepth {
		return leafPart(mail, ver) // too deeply nested: stop recursing, treat as a leaf
	}
	hdr, body, hasBlank := splitHdrBody(mail)

	noValid := false
	if !hasBlank || len(body) == 0 {
		noValid = true
	}
	if recursive && !reContentTy.Match(hdr) {
		noValid = true
	}
	if noValid {
		return leafPart(mail, ver)
	}

	merged := reFold.ReplaceAll(hdr, nil) // merge folded header lines
	var trimmed strings.Builder
	for _, ln := range splitLF(merged) {
		if hasPrefixFold(ln, "Content-") || hasPrefixFold(ln, "X-Razor2") {
			trimmed.WriteString(ln)
			trimmed.WriteByte('\n')
		}
	}
	trimmedHdr := trimmed.String()

	boundary := ""
	if m := reBoundary.FindStringSubmatch(trimmedHdr); m != nil {
		boundary = m[1]
	}

	if boundary == "" {
		th := "X-Razor2-Agent: " + ver + "\n" + trimmedHdr
		return [][]byte{joinHdrBody([]byte(th[:len(th)-1]), body)} // th ends with \n; joinHdrBody adds \n\n
	}
	// Perl strips matched quotes via /^"(.*)"$/, which needs both quotes (len>=2);
	// a lone `"` (possible via the \S+ boundary alternative) must not be stripped.
	if len(boundary) >= 2 && strings.HasPrefix(boundary, `"`) && strings.HasSuffix(boundary, `"`) {
		boundary = boundary[1 : len(boundary)-1]
	}

	// Boundary handling is done with byte-literal scans, NOT compiled regexes:
	// the boundary is attacker-controlled and may contain invalid UTF-8, which
	// regexp.MustCompile rejects (perl's \Q\E quotemeta does not). The separator
	// is \n--<boundary>\r*\n; the closing one is \n--<boundary>--.
	body = trimLastBoundary(body, boundary) // trash last boundary + epilogue
	if hasLeadingBoundary(body, boundary) {
		body = append([]byte("garbage\n"), body...) // RFC-noncompliant leading boundary
	}

	var tmpparts [][]byte
	if !bytes.Contains(body, []byte("--"+boundary)) {
		tmpparts = [][]byte{[]byte("garbage"), body}
	} else {
		tmpparts = splitOnBoundary(body, boundary)
	}
	if len(tmpparts) > 0 {
		tmpparts = tmpparts[1:] // trash preamble (up to first boundary)
	}

	var out [][]byte
	for _, tp := range tmpparts {
		if !reNonWS.Match(tp) {
			continue // whitespace-only part
		}
		if *count >= maxMimeParts {
			break // part-count cap reached; drop the rest
		}
		*count++
		out = append(out, splitMime(tp, ver, true, depth+1, count)...)
	}
	return out
}

// prepPart ports Razor2::String::prep_part. Returns nil if the part has no body.
func prepPart(mail []byte, maxhdr, maxbdy int) []byte {
	hdr, body, hasBlank := splitHdrBody(mail)
	if !hasBlank || len(body) == 0 {
		return nil
	}
	hdr = append(append([]byte{}, hdr...), '\n') // newline back on last header line

	isBinary := enBase64Isit(mail)
	if isBinary {
		body = enBase64Doit(body)
	}
	body = normalizeCRLF(body)
	hdr = normalizeCRLF(hdr)

	if l := len(body); l > maxbdy {
		body = body[:maxbdy]
		if isBinary && len(body) >= 2 {
			body[len(body)-2] = '='
			body[len(body)-1] = '='
		}
		hdr = append([]byte(origlenLine("X-Razor2-Origlen-Body", l)), hdr...)
	}
	if len(hdr) > maxhdr {
		hdr = capWithOriglen(hdr, "X-Razor2-Origlen-Header", maxhdr)
	}

	dude := joinHdrBody(hdr[:len(hdr)-1], body) // hdr ends with \n; joinHdrBody re-adds \n\n
	// (perl: dude = "$hdr\n$body" where hdr already ends in \n)
	return dude
}

func origlenLine(field string, n int) string {
	return field + ": " + strconv.Itoa(n) + "\n"
}

// capWithOriglen prepends the origlen header, then truncates to max removing the
// last incomplete line (Core.pm / prep_part / prep_mail truncation idiom).
func capWithOriglen(hdr []byte, field string, max int) []byte {
	out := append([]byte(origlenLine(field, len(hdr))), hdr...)
	if len(out) > max {
		out = out[:max]
		out = reLastLine.ReplaceAll(out, nil) // remove last, incomplete line
	}
	return out
}

// --- enBase64 ---

func enBase64Isit(text []byte) bool {
	if bytes.HasPrefix(text, []byte("Content-Type-Encoding: 8-bit")) {
		return true
	}
	// first byte in {0x00-0x1F, '|', 0x7F-0xFF}; binary unless it is \t \n \r
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c <= 0x1f || c == '|' || c >= 0x7f {
			return c != '\t' && c != '\n' && c != '\r'
		}
	}
	return false
}

func enBase64Doit(text []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(text)
	var sb strings.Builder
	sb.WriteString("Content-Transfer-Encoding: base64\n\n")
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		sb.WriteString(enc[i:end])
		sb.WriteByte('\n')
	}
	return []byte(sb.String())
}

// --- small helpers ---

func splitLF(b []byte) []string { return strings.Split(string(b), "\n") }

// trimLastBoundary cuts the body at the first "\n--<boundary>--" (the closing
// delimiter), discarding it and the epilogue. Mirrors perl's
// s/\n\Q--$boundary--\E.*$//s.
func trimLastBoundary(body []byte, boundary string) []byte {
	marker := []byte("\n--" + boundary + "--")
	if idx := bytes.Index(body, marker); idx >= 0 {
		return body[:idx]
	}
	return body
}

// hasLeadingBoundary reports whether body begins with "--<boundary>\r*\n"
// (a non-RFC-compliant leading delimiter). Mirrors perl /^\Q--$boundary\E\r*\n/.
func hasLeadingBoundary(body []byte, boundary string) bool {
	pre := []byte("--" + boundary)
	if !bytes.HasPrefix(body, pre) {
		return false
	}
	k := len(pre)
	for k < len(body) && body[k] == '\r' {
		k++
	}
	return k < len(body) && body[k] == '\n'
}

// splitOnBoundary splits body on every "\n--<boundary>\r*\n" delimiter, with
// trailing empty fields removed (perl split semantics). Byte-literal so it is
// safe for arbitrary boundary/body bytes.
func splitOnBoundary(body []byte, boundary string) [][]byte {
	marker := []byte("\n--" + boundary)
	var out [][]byte
	last, i := 0, 0
	for {
		idx := bytes.Index(body[i:], marker)
		if idx < 0 {
			break
		}
		pos := i + idx
		k := pos + len(marker)
		for k < len(body) && body[k] == '\r' {
			k++
		}
		if k < len(body) && body[k] == '\n' {
			out = append(out, body[last:pos])
			last = k + 1
			i = k + 1
		} else {
			i = pos + 1 // not a real delimiter; keep scanning
		}
	}
	out = append(out, body[last:])
	for len(out) > 0 && len(out[len(out)-1]) == 0 {
		out = out[:len(out)-1]
	}
	return out
}

func hasPrefixFold(s, p string) bool {
	return len(s) >= len(p) && strings.EqualFold(s[:len(p)], p)
}
