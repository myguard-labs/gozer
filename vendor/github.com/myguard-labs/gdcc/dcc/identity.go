package dcc

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Identity is a DCC client credential: a numeric client-id and its password.
// The anonymous identity is {ClientID: 1, Password: ""}.
type Identity struct {
	ClientID uint32
	Password string
}

// Anonymous reports whether this identity is the unauthenticated client.
func (id Identity) Anonymous() bool { return id.ClientID <= dccIDAnon || id.Password == "" }

// DefaultIDsPath is the conventional DCC identity file.
const DefaultIDsPath = "/var/dcc/ids"

// ParseIdentityFile reads the first usable non-anonymous client identity from a
// DCC ids-format stream. Lines are "id[,options] passwd1 [passwd2]"; '#' starts
// a comment; blank lines are ignored. Only the current (first) password is used.
func ParseIdentityFile(r io.Reader) (Identity, bool) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// the id may carry ",option=..." suffixes — keep the leading number
		idTok := fields[0]
		if i := strings.IndexByte(idTok, ','); i >= 0 {
			idTok = idTok[:i]
		}
		n, err := strconv.ParseUint(idTok, 10, 32)
		if err != nil || n <= dccIDAnon {
			continue
		}
		return Identity{ClientID: uint32(n), Password: fields[1]}, true
	}
	return Identity{}, false
}

// ResolveIdentity applies the standard fallback chain and returns the client
// identity to use:
//
//	GDCC_CLIENT_ID + GDCC_CLIENT_PASSWD env
//	→ DCC_IDS env (path to an ids file)
//	→ /var/dcc/ids
//	→ anonymous (id 1)
//
// The supplied id/passwd (e.g. from CLI flags) take precedence when non-empty.
func ResolveIdentity(flagID uint32, flagPasswd string) Identity {
	if flagID > dccIDAnon && flagPasswd != "" {
		return Identity{ClientID: flagID, Password: flagPasswd}
	}
	if envID := envClientID(); envID > dccIDAnon {
		if pw := os.Getenv("GDCC_CLIENT_PASSWD"); pw != "" {
			return Identity{ClientID: envID, Password: pw}
		}
	}
	paths := []string{}
	if p := os.Getenv("DCC_IDS"); p != "" {
		paths = append(paths, p)
	}
	paths = append(paths, DefaultIDsPath)
	for _, p := range paths {
		f, err := os.Open(p) // #nosec G304 G703 -- operator-provided ids path (env/default), not attacker input
		if err != nil {
			continue
		}
		id, ok := ParseIdentityFile(f)
		_ = f.Close()
		if ok {
			return id
		}
	}
	return Identity{ClientID: dccIDAnon}
}

func envClientID() uint32 {
	if v := os.Getenv("GDCC_CLIENT_ID"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			return uint32(n)
		}
	}
	return 0
}

// WriteIdentityFile persists id to a DCC ids-format file ("id passwd" lines, the
// form ParseIdentityFile reads), creating the parent dir (0700) and the file
// (0600). Any existing line for the same client-id is replaced (idempotent
// re-register); comments and other ids are preserved. The write is atomic
// (temp + rename) so an interrupted save never truncates a working ids file.
//
// DCC has no client-side registration: the dccd operator issues the numeric
// client-id and password out of band. This only persists a credential you
// already have so later requests authenticate automatically — it does not
// obtain one. The anonymous id (1) needs no credential and is rejected here.
func WriteIdentityFile(path string, id Identity) error {
	if id.ClientID <= dccIDAnon {
		return fmt.Errorf("write ids: client-id must be greater than %d (the anonymous id needs no registration)", dccIDAnon)
	}
	if id.Password == "" {
		return fmt.Errorf("write ids: empty password")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil { // #nosec G301 -- operator ids dir
			return fmt.Errorf("write ids: %w", err)
		}
	}

	var kept []string
	if data, err := os.ReadFile(path); err == nil { // #nosec G304 -- operator-provided ids path (flag/env/default), not attacker input
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimRight(line, "\r")
			if lineID, ok := idOfLine(line); ok && lineID == id.ClientID {
				continue // drop the stale entry; re-added below
			}
			if line != "" {
				kept = append(kept, line)
			}
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("write ids: read %s: %w", path, err)
	}
	kept = append(kept, fmt.Sprintf("%d %s", id.ClientID, id.Password))

	if err := writeFileAtomic(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		return fmt.Errorf("write ids: %w", err)
	}
	return nil
}

// idOfLine returns the client-id parsed from an ids-file line, or ok=false for
// blank, comment, or malformed lines. Used to dedupe on re-register.
func idOfLine(line string) (uint32, bool) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, false
	}
	tok := fields[0]
	if i := strings.IndexByte(tok, ','); i >= 0 {
		tok = tok[:i]
	}
	n, err := strconv.ParseUint(tok, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// writeFileAtomic writes data to a temp file in the same directory then renames
// it over path, so a reader never observes a half-written ids file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ids-*")
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
