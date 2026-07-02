package dcc

import "bytes"

// splitHeadersBody splits a raw RFC-822 message into its unfolded header fields
// and the raw body, mirroring dccproc's get_hdr()/main loop. Header field
// continuation lines (starting with space/tab) are joined onto the previous
// field, keeping raw bytes (str2ck strips the embedded line endings anyway).
// The body is everything after the first empty line.
func splitHeadersBody(msg []byte) (fields [][]byte, body []byte) {
	fields = make([][]byte, 0, 4)
	i := 0
	for i < len(msg) {
		nl := bytes.IndexByte(msg[i:], '\n')
		var end int
		if nl < 0 {
			end = len(msg)
		} else {
			end = i + nl + 1
		}
		line := msg[i:end]

		if isBlankLine(line) {
			return fields, msg[end:]
		}
		if len(fields) > 0 && (line[0] == ' ' || line[0] == '\t') {
			last := len(fields) - 1
			fields[last] = fields[last][:len(fields[last])+len(line)]
		} else {
			fields = append(fields, line)
		}
		i = end
	}
	return fields, nil // no blank line: no body
}

// isBlankLine reports whether a physical line (terminator included) is empty,
// i.e. "\n" or "\r\n" — the header/body separator.
func isBlankLine(line []byte) bool {
	switch len(line) {
	case 0:
		return true
	case 1:
		return line[0] == '\n'
	case 2:
		return line[0] == '\r' && line[1] == '\n'
	}
	return false
}

// parseReturnPath ports ck.c:parse_return_path — the env-from value of a
// Return-Path header (leading blanks skipped, trailing CR/LF stripped).
func parseReturnPath(f []byte) (string, bool) {
	if !hasPrefixFold(f, "Return-Path:") {
		return "", false
	}
	v := f[len("Return-Path:"):]
	for len(v) > 0 && (v[0] == ' ' || v[0] == '\t') {
		v = v[1:]
	}
	for len(v) > 0 && (v[len(v)-1] == '\r' || v[len(v)-1] == '\n') {
		v = v[:len(v)-1]
	}
	if len(v) == 0 {
		return "", false
	}
	return string(v), true
}

// parseUnixFrom ports ck.c:parse_unix_from — the address of a UNIX mbox
// "From sender date" separator line (the first body byte of an mbox message).
func parseUnixFrom(f []byte) (string, bool) {
	if len(f) < len("From ") || string(f[:len("From ")]) != "From " {
		return "", false
	}
	v := f[len("From "):]
	for len(v) > 0 && v[0] == ' ' {
		v = v[1:]
	}
	sp := bytes.IndexByte(v, ' ')
	if sp <= 0 {
		return "", false
	}
	return string(v[:sp]), true
}

// hasPrefixFold reports a case-insensitive prefix match (CLITCMP).
func hasPrefixFold(b []byte, prefix string) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if toLower(b[i]) != toLower(prefix[i]) {
			return false
		}
	}
	return true
}

// Checksums computes the DCC checksums for a raw message, returning them in the
// type order dccproc -C prints (skipping ones that are not produced/valid).
// This is the offline debug path; it is the analogue of gazor.Signatures.
func Checksums(msg []byte) []Checksum {
	fields, body := splitHeadersBody(msg)

	c := newCks()
	var fromSum, msgIDSum, recvSum *Sum
	var envFrom string
	var envFromSet bool
	for i, f := range fields {
		// Notice Content-Type / Content-Transfer-Encoding (sets up the body
		// transfer-encoding, charset and any multipart boundary).
		c.ckMimeHdr(f)
		switch {
		case hasPrefixFold(f, "From:"):
			s := str2ck("", string(f[len("From:"):]))
			fromSum = &s
		case hasPrefixFold(f, "Message-ID:"):
			s := str2ck("", string(f[len("Message-ID:"):]))
			msgIDSum = &s
		case hasPrefixFold(f, "Received:"):
			// the last Received header wins
			s := str2ck("", string(f[len("Received:"):]))
			recvSum = &s
		}
		// Envelope sender: a UNIX "From " line (only as the first line) or the
		// first Return-Path header; first wins (matches dccproc).
		if !envFromSet {
			if i == 0 {
				if v, ok := parseUnixFrom(f); ok {
					envFrom, envFromSet = v, true
				}
			}
			if !envFromSet {
				if v, ok := parseReturnPath(f); ok {
					envFrom, envFromSet = v, true
				}
			}
		}
	}
	// dccproc synthesises a checksum of "" when there is no Message-ID.
	msgIDPresent := msgIDSum != nil
	if msgIDSum == nil {
		s := str2ck("", "")
		msgIDSum = &s
	}

	// Body + fuzzy checksums (with MIME multipart / transfer-encoding / charset).
	bodySum, bodyOK, fuz1Sum, fuz1OK, fuz2Sum, fuz2OK := c.computeBody(body)

	var out []Checksum
	add := func(t CkType, s Sum, report bool) {
		out = append(out, Checksum{Type: t, Label: t.label(), Sum: s, Report: report})
	}
	// dccproc -C prints checksums in type order: env_From(2), From(3),
	// Message-ID(5), Received(6), Body(7), Fuz1(8), Fuz2(9).
	if envFromSet {
		add(CkEnvFrom, str2ck("", envFrom), true)
	}
	if fromSum != nil {
		add(CkFrom, *fromSum, true)
	}
	// A real Message-ID is reported; a synthesised empty one is not (rpt2srvr=0).
	add(CkMessageID, *msgIDSum, msgIDPresent)
	if recvSum != nil {
		add(CkReceived, *recvSum, true)
	}
	if bodyOK {
		add(CkBody, bodySum, true)
	}
	if fuz1OK {
		add(CkFuz1, fuz1Sum, true)
	}
	if fuz2OK {
		add(CkFuz2, fuz2Sum, true)
	}
	return out
}
