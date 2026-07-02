package gozer

import (
	"fmt"
	"strings"

	"github.com/myguard-labs/gdcc/dcc"
	"github.com/myguard-labs/gyzor/pyzor"
)

// PyzorRegister generates (or persists a supplied) pyzor identity and writes it
// to the accounts file under home for every server in serversCSV (the public
// pyzor server when empty), so gozer's pyzor client then authenticates with it.
// It returns the saved accounts-file path, the account, and whether the key was
// generated.
//
// A combined "salt,key" in key is split. An empty key generates a fresh random
// key (only the key — with the username — is handed to the pyzord
// administrator). The actual genkey/file-format logic lives in package pyzor
// (gyzor): this is just orchestration, so the on-disk format has one source of
// truth shared with the gyzor CLI.
func PyzorRegister(home, serversCSV, user, key, salt string) (path string, acc pyzor.Account, generated bool, err error) {
	if user == "" {
		return "", pyzor.Account{}, false, fmt.Errorf("pyzor register: user is required")
	}
	if salt == "" {
		if s, k, ok := strings.Cut(key, ","); ok {
			salt, key = s, k
		}
	}
	generated = key == ""
	if generated {
		if salt, key, err = pyzor.GenKey(""); err != nil {
			return "", pyzor.Account{}, false, err
		}
	}
	servers := parsePyzorServers(serversCSV)
	if len(servers) == 0 {
		servers = []pyzor.Server{pyzor.DefaultServer}
	}
	acc = pyzor.Account{Username: user, Salt: salt, Key: key}
	path, err = pyzor.SaveAccount(home, servers, acc)
	return path, acc, generated, err
}

// DCCRegister persists a DCC client-id + password to the ids file at path so
// gozer's dcc client authenticates with it. DCC has no client-side
// registration — the dccd operator issues the id+password out of band — so both
// must be supplied; this only saves them. Validation (id > anonymous, non-empty
// password) and the file format are enforced by dcc.WriteIdentityFile (gdcc),
// the single source of truth shared with the gdcc CLI.
func DCCRegister(path string, clientID uint32, passwd string) error {
	return dcc.WriteIdentityFile(path, dcc.Identity{ClientID: clientID, Password: passwd})
}
