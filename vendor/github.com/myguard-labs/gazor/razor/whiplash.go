package razor

import (
	"crypto/sha1" // #nosec G505 -- razor protocol mandates SHA1; not a security primitive here
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

var (
	reHexEsc   = regexp.MustCompile(`%([0-9A-Fa-f]{2})`)
	reDecEsc   = regexp.MustCompile(`&#([0-9]{2,3});`)
	reHref     = regexp.MustCompile(`(?is)^.*?href\s*=\s*"?https?://?(.*)$`)
	reHTTP     = regexp.MustCompile(`(?is)^.*?https?://?(.*)$`)
	reAHref    = regexp.MustCompile(`^a href`)
	reStripAH  = regexp.MustCompile(`^a href\s*=\s*`)
	reStripHT  = regexp.MustCompile(`(?i)^http://`)
	reTermHref = regexp.MustCompile(`(?s)(.*?)[>"/?<]`)
	reTermBare = regexp.MustCompile("(?s)(.*?)[>\"/?<\n\r]")
	reAuth     = regexp.MustCompile(`(?si)^[^@]*@`)
	reEqPrefix = regexp.MustCompile(`(?si)\S+=`)
	reCutWS    = regexp.MustCompile(`(?s)[\r\n\s].*$`)
	rePort     = regexp.MustCompile(`:.*$`)
	reIP       = regexp.MustCompile(`^[\d.]+$`)
	reAutolink = regexp.MustCompile(`(?i)\s+(www.[^ /><"` + "\r\n" + `]+)`)
)

// Whiplash computes the razor Whiplash (E8) signatures of text (one per extracted
// URL host), byte-exact with Razor2::Signature::Whiplash->whiplash. Returns nil if
// no hosts are found.
//
// Each signature is SHA1(host)[:12] + SHA1(corrected_len)[:4]. NB: the second hash
// is of corrected_len ALONE, not host+len — razor's Digest::SHA1 hexdigest is
// destructive (resets), so the comment in the perl ("host and corrected length") is
// wrong about the bytes. corrected_len = len(text) - len(text)%100.
func Whiplash(text string) []string {
	if text == "" {
		return nil
	}
	hosts := extractHosts(text)
	if len(hosts) == 0 {
		return nil
	}
	corrected := len(text) - (len(text) % 100)
	var sigs []string
	for _, host := range hosts {
		sigs = append(sigs, sha1hex(host)[:12]+sha1hex(strconv.Itoa(corrected))[:4])
	}
	return sigs
}

func extractHosts(text string) []string {
	if strings.IndexByte(text, '%') >= 0 {
		text = reHexEsc.ReplaceAllStringFunc(text, func(m string) string {
			n, _ := strconv.ParseInt(m[1:], 16, 32)
			return string(rune(n)) // #nosec G115 -- URI-escape value, 0..255
		})
	}
	if strings.Contains(text, "&#") {
		text = reDecEsc.ReplaceAllStringFunc(text, func(m string) string {
			n, _ := strconv.Atoi(reDecEsc.FindStringSubmatch(m)[1])
			return string(rune(n)) // #nosec G115 -- URI-escape value, 0..255
		})
	}

	// Autolinks (\s+www.<...>, e.g. Outlook) are collected RAW and kept ahead of
	// the http-extracted hosts — but only if an http/href URL is also present.
	// With no such URL, razor's extract_hosts returns () and the autolinks are
	// discarded along with everything else.
	var hosts []string
	if containsASCIIFold(text, "www.") {
		for _, m := range reAutolink.FindAllStringSubmatch(text, -1) {
			hosts = append(hosts, m[1])
		}
	}

	if containsASCIIFold(text, "href") {
		if m := reHref.FindStringSubmatch(text); m != nil {
			text = "a href = http://" + m[1]
		} else if m := reHTTP.FindStringSubmatch(text); m != nil {
			text = "http://" + m[1]
		} else {
			return nil
		}
	} else if m := reHTTP.FindStringSubmatch(text); m != nil {
		text = "http://" + m[1]
	} else {
		return nil
	}

	for {
		host := nextHost(text)
		if host == "" {
			break
		}
		canonical := host
		if !reIP.MatchString(host) {
			canonical = canonify(host)
		}
		if !contains(hosts, canonical) && len(canonical) > 1 && strings.Contains(canonical, ".") {
			hosts = append(hosts, canonical)
		}
		i := strings.Index(text, "http://")
		if i < 0 {
			break
		}
		text = text[i+len("http://"):]
	}
	return hosts
}

func containsASCIIFold(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		match := true
		for j := range len(substr) {
			a, b := s[i+j], substr[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// nextHost ports Razor2::Signature::Whiplash::next_host.
func nextHost(w string) string {
	insideHref := false
	if reAHref.MatchString(w) {
		insideHref = true
		w = replaceFirst(reStripAH, w, "")
	}
	w = replaceFirst(reStripHT, w, "")
	if insideHref {
		if m := reTermHref.FindStringSubmatch(w); m != nil {
			w = m[1]
		}
	} else {
		if m := reTermBare.FindStringSubmatch(w); m != nil {
			w = m[1]
		}
	}
	w = replaceFirst(reAuth, w, "")
	w = replaceFirst(reEqPrefix, w, "")
	host := strings.ToLower(replaceFirst(reCutWS, w, ""))
	host = strings.ReplaceAll(host, "=", "")
	host = strings.TrimRight(host, " \t\r\n")
	host = replaceFirst(rePort, host, "")
	return strings.TrimSuffix(host, ".")
}

// canonify reduces a hostname to its registrable domain using the DPL (first match
// wins). Ports Razor2::Signature::Whiplash::canonify with byte-literal suffix
// matching instead of per-pattern compiled regexes (the old approach compiled
// ~1000 regexes per host). A dot pattern like ".com" reproduces the perl
// ([^.]+\Q.com\E)$ — the one non-empty label immediately before the pattern.
func canonify(host string) string {
	for _, pattern := range dpl {
		if !strings.HasSuffix(host, pattern) {
			continue
		}
		if strings.HasPrefix(pattern, ".") {
			label := host[:len(host)-len(pattern)]
			if i := strings.LastIndexByte(label, '.'); i >= 0 {
				label = label[i+1:]
			}
			if label != "" { // perl [^.]+ requires at least one label char
				return label + pattern
			}
			continue
		}
		return pattern
	}
	return host
}

func replaceFirst(re *regexp.Regexp, s, repl string) string {
	loc := re.FindStringIndex(s)
	if loc == nil {
		return s
	}
	return s[:loc[0]] + repl + s[loc[1]:]
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func sha1hex(s string) string {
	h := sha1.New() // #nosec G401 -- razor protocol mandates SHA1
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
