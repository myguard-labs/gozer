// Package pyzor implements the Pyzor client wire protocol (the subset gyzor
// needs: check, report, whitelist, ping) over UDP, byte-compatible with the
// reference pyzor client so the public servers accept gyzor's requests.
//
// Reference: pyzor 1.1.2 — pyzor/account.py, pyzor/message.py, pyzor/client.py.
package pyzor

import (
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- pyzor wire protocol mandates SHA1; not a security primitive here
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	protoName     = "pyzor"
	protoVersion  = "2.1"
	anonymousUser = "anonymous"
)

// Account is a client identity. The zero value / Anonymous is used when no
// accounts file matches the server.
type Account struct {
	Username string
	Salt     string
	Key      string
}

// Anonymous is the implicit account that always exists (username "anonymous",
// empty key). The docker backend uses it exclusively.
var Anonymous = Account{Username: anonymousUser, Key: ""}

// hashKey mirrors account.hash_key:  lower(SHA1(user + ":" + lower(key))).
func hashKey(key, user string) string {
	sum := sha1.Sum([]byte(user + ":" + strings.ToLower(key))) // #nosec G401 -- pyzor protocol mandates SHA1
	return strings.ToLower(hex.EncodeToString(sum[:]))
}

// signMsg mirrors account.sign_msg:  lower(SHA1( SHA1(M).raw + ":T:K" ))
// where M is the signed message text, T the epoch timestamp and K the hashed key.
func signMsg(hashedKey string, timestamp int64, signedText string) string {
	inner := sha1.Sum([]byte(signedText)) // #nosec G401 -- pyzor protocol mandates SHA1
	outer := sha1.New()                   // #nosec G401 -- pyzor protocol mandates SHA1
	outer.Write(inner[:])
	outer.Write([]byte(fmt.Sprintf(":%d:%s", timestamp, hashedKey)))
	return strings.ToLower(hex.EncodeToString(outer.Sum(nil)))
}

// keyFromHexStr splits a "salt,key" accounts-file field, mirroring
// account.key_from_hexstr.
func keyFromHexStr(s string) (salt, key string, err error) {
	parts := strings.SplitN(s, ",", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid key %q: missing comma salt divider", s)
	}
	return parts[0], parts[1], nil
}

// GenKey produces a fresh pyzor "salt,key" pair (both lower-hex SHA1 strings)
// in the format the accounts file and the server expect. It mirrors the
// reference `pyzor genkey`:
//
//   - salt = SHA1(random)            — a per-key random value; only the salt is
//     persisted locally, never sent, so it merely makes the key
//     non-reversible. (The reference seeds it from math/random; we use
//     crypto/rand, which is strictly stronger and indistinguishable on the
//     wire since the raw salt is never recovered.)
//   - key  = SHA1(salt_digest)       — when passphrase is empty: a fully random
//     key (recommended). When a passphrase is given, key =
//     SHA1(salt_digest + passphrase), byte-identical to the reference's
//     password-derived key so the resulting pair authenticates against pyzord.
//
// Only the key (with the username) is handed to the pyzord administrator; the
// salt stays client-side.
func GenKey(passphrase string) (salt, key string, err error) {
	rawSalt := make([]byte, sha1.Size)
	if _, err = rand.Read(rawSalt); err != nil {
		return "", "", fmt.Errorf("genkey: read random salt: %w", err)
	}
	var rawKey []byte
	if passphrase == "" {
		rawKey = make([]byte, sha1.Size)
		if _, err = rand.Read(rawKey); err != nil {
			return "", "", fmt.Errorf("genkey: read random key: %w", err)
		}
	}
	salt, key = deriveKey(rawSalt, rawKey, passphrase)
	return salt, key, nil
}

// deriveKey is the pure (deterministic, allocation-free of randomness) core of
// GenKey, split out so the salt/key derivation can be unit-tested against a
// fixed input vector. rawKey is consulted only when passphrase is empty.
func deriveKey(rawSalt, rawKey []byte, passphrase string) (salt, key string) {
	saltDigest := sha1.Sum(rawSalt) // #nosec G401 -- pyzor protocol mandates SHA1
	salt = strings.ToLower(hex.EncodeToString(saltDigest[:]))
	if passphrase == "" {
		return salt, strings.ToLower(hex.EncodeToString(rawKey))
	}
	h := sha1.New() // #nosec G401 -- pyzor protocol mandates SHA1
	h.Write(saltDigest[:])
	h.Write([]byte(passphrase))
	return salt, strings.ToLower(hex.EncodeToString(h.Sum(nil)))
}

// accountLine formats one accounts-file entry for a server, matching the
// "host : port : username : salt,key" form the reference pyzor writes and
// LoadAccounts parses.
func accountLine(s Server, acc Account) string {
	return fmt.Sprintf("%s : %d : %s : %s,%s", s.Host, s.Port, acc.Username, acc.Salt, acc.Key)
}

// SaveAccount persists acc for every server into homedir/accounts (creating
// homedir 0700 and the file 0600). Any pre-existing entry for the same
// host:port is replaced (pyzor keys accounts by server, one per address), so
// re-registering is idempotent. The write is atomic (temp file + rename) so an
// interrupted save never truncates a working accounts file.
func SaveAccount(homedir string, servers []Server, acc Account) (string, error) {
	if homedir == "" {
		return "", fmt.Errorf("save account: empty homedir")
	}
	if len(servers) == 0 {
		return "", fmt.Errorf("save account: no servers to register for")
	}
	if acc.Username == "" {
		return "", fmt.Errorf("save account: empty username")
	}
	if err := os.MkdirAll(homedir, 0o700); err != nil {
		return "", fmt.Errorf("save account: %w", err)
	}
	path := filepath.Join(homedir, "accounts")

	// Servers whose existing lines we are about to replace.
	replace := make(map[string]bool, len(servers))
	for _, s := range servers {
		replace[s.addr()] = true
	}

	var kept []string
	if data, err := os.ReadFile(path); err == nil { // #nosec G304 -- operator-provided homedir (CLI flag/env), not attacker input
		for _, line := range strings.Split(string(data), "\n") {
			if a, ok := accountAddrOfLine(line); ok && replace[a] {
				continue // drop the stale entry; we re-add it below
			}
			if strings.TrimRight(line, "\r") != "" {
				kept = append(kept, strings.TrimRight(line, "\r"))
			}
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("save account: read %s: %w", path, err)
	}

	for _, s := range servers {
		kept = append(kept, accountLine(s, acc))
	}

	if err := writeFileAtomic(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("save account: %w", err)
	}
	return path, nil
}

// accountAddrOfLine returns the "host:port" of an accounts-file line, or ok=false
// for blank/comment/malformed lines. Used to dedupe on re-register.
func accountAddrOfLine(line string) (addr string, ok bool) {
	line = strings.TrimSpace(strings.TrimRight(line, "\r"))
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}
	parts := strings.Split(line, ":")
	if len(parts) != 4 {
		return "", false
	}
	port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return "", false
	}
	return Server{Host: strings.TrimSpace(parts[0]), Port: port}.addr(), true
}

// writeFileAtomic writes data to a temp file in the same directory then renames
// it over path, so a reader never observes a half-written accounts file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".accounts-*")
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
