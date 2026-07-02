package razor

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DefaultHomeDirName is the conventional Razor2 home directory under $HOME.
const DefaultHomeDirName = ".razor"

// ResolveHome returns the Razor2 home directory using razor's resolution order:
// the explicit flagHome → $RAZOR_HOME → ~/.razor.
func ResolveHome(flagHome string) string {
	if flagHome != "" {
		return flagHome
	}
	if h := os.Getenv("RAZOR_HOME"); h != "" {
		return h
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, DefaultHomeDirName)
	}
	return DefaultHomeDirName
}

// ParseIdentityFile reads a Razor2 identity file (key=value lines, '#'
// comments, per Razor2::Client::Config::read_file) and returns the user/pass.
// It returns ok=false if both fields are not present.
func ParseIdentityFile(r io.Reader) (Identity, bool) {
	var id Identity
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "user":
			id.User = strings.TrimSpace(v)
		case "pass":
			id.Pass = strings.TrimSpace(v)
		}
	}
	if id.User == "" || id.Pass == "" {
		return Identity{}, false
	}
	return id, true
}

// ResolveIdentity applies the standard fallback chain for report/revoke
// credentials and returns the identity to use, or nil for anonymous (check
// works without an identity):
//
//	GAZOR_USER + GAZOR_PASS env
//	→ RAZOR_USER + RAZOR_PASS env (razor-agent compatible)
//	→ <home>/identity file (key=value)
//	→ nil
//
// flagUser/flagPass (e.g. from CLI flags) take precedence when both are set.
func ResolveIdentity(flagUser, flagPass, home string) *Identity {
	if flagUser != "" && flagPass != "" {
		return &Identity{User: flagUser, Pass: flagPass}
	}
	if u, p := os.Getenv("GAZOR_USER"), os.Getenv("GAZOR_PASS"); u != "" && p != "" {
		return &Identity{User: u, Pass: p}
	}
	if u, p := os.Getenv("RAZOR_USER"), os.Getenv("RAZOR_PASS"); u != "" && p != "" {
		return &Identity{User: u, Pass: p}
	}
	f, err := os.Open(filepath.Join(home, "identity")) // #nosec G304 -- operator-provided razor home (flag/env/default), not attacker input
	if err != nil {
		return nil
	}
	defer f.Close()
	if id, ok := ParseIdentityFile(f); ok {
		return &id
	}
	return nil
}

// WriteIdentityFile persists id as a Razor2 "user=...\npass=..." file (0600) —
// the same key=value format ParseIdentityFile reads back — and returns the path
// written. The write is atomic (temp + rename) so an interrupted save never
// truncates an identity file.
//
// With an explicit out path it writes exactly there (overwriting). Otherwise it
// writes <home>/identity, but never clobbers an existing active identity: if
// <home>/identity already exists it writes <home>/identity-<user> instead and
// returns that path, so a re-registration cannot destroy the current login.
func WriteIdentityFile(home, out string, id Identity) (string, error) {
	if id.User == "" || id.Pass == "" {
		return "", fmt.Errorf("write identity: empty user or pass")
	}
	// home/out are operator-provided (--homedir/--out, GAZOR_HOMEDIR/RAZOR_HOME),
	// not attacker input — same trust model as the rest of this file.
	body := []byte(fmt.Sprintf("user=%s\npass=%s\n", id.User, id.Pass))
	if out != "" {
		if dir := filepath.Dir(out); dir != "" {
			if err := os.MkdirAll(dir, 0o700); err != nil { // #nosec G301 G703 -- operator path
				return "", err
			}
		}
		if err := writeFileAtomic(out, body, 0o600); err != nil { // #nosec G304 G703 -- operator path
			return "", err
		}
		return out, nil
	}
	if err := os.MkdirAll(home, 0o700); err != nil { // #nosec G301 G703 -- operator home dir
		return "", err
	}
	target := filepath.Join(home, "identity")
	if _, err := os.Stat(target); err == nil { // #nosec G304 G703 -- operator home dir
		// active identity exists — don't clobber it
		target = filepath.Join(home, "identity-"+sanitizeUser(id.User))
	}
	if err := writeFileAtomic(target, body, 0o600); err != nil { // #nosec G304 G703 -- operator path
		return "", err
	}
	return target, nil
}

// sanitizeUser keeps a registered username safe as a filename suffix.
func sanitizeUser(u string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_', r == '@':
			return r
		default:
			return '_'
		}
	}, u)
}

// writeFileAtomic writes data to a temp file in the same directory then renames
// it over path, so a reader never observes a half-written credential file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".identity-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
