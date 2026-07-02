package razor

import (
	"strconv"
	"strings"
)

// vr4Signature ports Razor2::Client::Engine::vr4_signature. It parses the ep4
// greeting param ("seed-separator", default "7542-10"), computes the Ephemeral
// hexdigest with those params, then encodes it as razor base64 for the wire.
// Returns "" on a malformed ep4 (perl logs and returns undef).
func vr4Signature(text []byte, ep4 string) string {
	seedStr, sepStr, ok := strings.Cut(ep4, "-")
	if !ok || seedStr == "" || sepStr == "" {
		return ""
	}
	var seed uint64
	if v, err := strconv.ParseUint(seedStr, 10, 32); err == nil {
		seed = v
	}
	digest := ephemeralHexdigest(text, uint32(seed), encodeSeparator(sepStr))
	return hextobase64(digest)
}

// vr8Signature ports Razor2::Engine::VR8::signature: compute the Whiplash hex
// signatures (one per extracted URL host), then razor-base64 each. Returns nil
// if Whiplash found no hosts.
func vr8Signature(text string) []string {
	hexSigs := Whiplash(text)
	if len(hexSigs) == 0 {
		return nil
	}
	out := make([]string, 0, len(hexSigs))
	for _, h := range hexSigs {
		out = append(out, hextobase64(h))
	}
	return out
}
