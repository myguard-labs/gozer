// Command gozer is the standalone DCC/Razor/Pyzor backend for rspamd. It speaks
// all three networks in-process — gazor (razor), gyzor (pyzor) and gdcc (DCC) —
// replacing the earlier Python implementation that forked the perl razor,
// python pyzor and dccproc CLIs per message.
//
// Usage:
//
//	gozer [serve] [flags]       run the HTTP backend on GOZER_HOST:GOZER_PORT
//	gozer stats                 fetch and print the local /metrics exposition
//	gozer health                probe the local /health endpoint (HEALTHCHECK)
//	gozer razor-register [...]  obtain a razor identity and persist it
//	gozer pyzor-register [...]  generate/save a pyzor account credential
//	gozer dcc-register [...]    save a DCC client-id + password
//	gozer version               print the version
//
// Every serve option is settable by env var OR CLI flag (flag > env > default);
// see cmdServe for the flag set. The *-register commands persist a credential
// to the same dir/file gozer loads it from, and print it as env-var lines
// (RAZOR_USER/RAZOR_PASS, GYZOR_USER/GYZOR_KEY/GYZOR_SALT, DCC_CLIENT_ID/
// DCC_CLIENT_PASSWD) so it can be passed via the environment instead. They reuse
// the gyzor/gazor/gdcc library register code, so the on-disk formats have a
// single source of truth shared with the standalone CLIs.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/myguard-labs/gazor/razor"
	"github.com/myguard-labs/gdcc/dcc"
	"github.com/myguard-labs/gozer/internal/gozer"
)

var version = "dev"

func main() {
	log.SetFlags(0) // s6 / journald add their own timestamps
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	cmd := "serve"
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-version", "-v":
			fmt.Println("gozer", version)
			return 0
		}
		if !strings.HasPrefix(args[0], "-") {
			cmd, args = args[0], args[1:]
		}
	}
	switch cmd {
	case "serve":
		return cmdServe(args)
	case "stats":
		return cmdStats()
	case "health":
		return cmdHealth()
	case "razor-register":
		return cmdRegister(args)
	case "pyzor-register":
		return cmdPyzorRegister(args)
	case "dcc-register":
		return cmdDCCRegister(args)
	default:
		fmt.Fprintln(os.Stderr, "usage: gozer [serve|stats|health|razor-register|pyzor-register|dcc-register|version]")
		return 2
	}
}

// cmdStats fetches the local /metrics exposition and prints it. Like cmdHealth
// it reuses GOZER_HOST/GOZER_PORT and needs no shell/curl in the image.
func cmdStats() int {
	cfg := gozer.LoadConfig()
	host := cfg.Host
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	url := "http://" + host + ":" + strconv.Itoa(cfg.Port) + "/metrics"
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stats:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "stats: status", resp.StatusCode)
		return 1
	}
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		fmt.Fprintln(os.Stderr, "stats:", err)
		return 1
	}
	return 0
}

// cmdHealth probes the local /health endpoint and exits 0/1. It is the
// container HEALTHCHECK in the distroless image, which ships no shell or curl;
// it reads the same GOZER_HOST/GOZER_PORT the server binds.
func cmdHealth() int {
	cfg := gozer.LoadConfig()
	host := cfg.Host
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	url := "http://" + host + ":" + strconv.Itoa(cfg.Port) + "/health"
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "health:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "health: status", resp.StatusCode)
		return 1
	}
	return 0
}

// cmdServe loads the config from the environment, then overlays any CLI flags
// (flag > env > default) so every option has both forms, and runs the server.
func cmdServe(args []string) int {
	cfg := gozer.LoadConfig()

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.StringVar(&cfg.Host, "host", cfg.Host, "HTTP bind host (GOZER_HOST); serves /check,/report,/revoke,/metrics,/health")
	fs.IntVar(&cfg.Port, "port", cfg.Port, "HTTP bind port (GOZER_PORT, default 8077)")
	fs.DurationVar(&cfg.BackendTimeout, "backend-timeout", cfg.BackendTimeout, "per-request backend budget (GOZER_BACKEND_TIMEOUT)")
	fs.IntVar(&cfg.MaxConcurrent, "max-concurrent", cfg.MaxConcurrent, "max in-flight requests (GOZER_MAX_CONCURRENT)")
	fs.StringVar(&cfg.Token, "token", cfg.Token, "shared-secret for POST endpoints (GOZER_TOKEN[_FILE])")
	fs.DurationVar(&cfg.CacheTTL, "cache-ttl", cfg.CacheTTL, "verdict cache TTL, 0 disables (GOZER_CACHE_TTL)")
	fs.IntVar(&cfg.CacheSize, "cache-size", cfg.CacheSize, "in-memory cache entries (GOZER_CACHE_SIZE)")
	fs.BoolVar(&cfg.Verbose, "verbose", cfg.Verbose, "per-request + startup config logging (GOZER_VERBOSE)")
	fs.BoolVar(&cfg.LogStdout, "log-stdout", cfg.LogStdout, "send info/access logs to stdout; errors stay on stderr (GOZER_LOG_STDOUT)")
	fs.StringVar(&cfg.PyzorHome, "pyzor-home", cfg.PyzorHome, "pyzor home dir (PYZOR_HOME)")
	fs.StringVar(&cfg.RazorHome, "razor-home", cfg.RazorHome, "razor home dir (RAZORHOME)")
	fs.StringVar(&cfg.MinCf, "min-cf", cfg.MinCf, "razor min confidence (RAZOR_MIN_CF)")
	fs.StringVar(&cfg.DCCServers, "dcc-servers", cfg.DCCServers, "DCC servers, comma host[:port] (DCC_SERVERS)")
	fs.StringVar(&cfg.PyzorServers, "pyzor-servers", cfg.PyzorServers, "pyzor servers DNS-bypass, comma host[:port] (GYZOR_SERVERS)")
	fs.StringVar(&cfg.RazorDiscovery, "razor-discovery", cfg.RazorDiscovery, "razor discovery DNS-bypass, comma host[:port] (GAZOR_DISCOVERY)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	srv := gozer.NewServer(cfg)
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("[gozer] server error: %v", err)
		return 1
	}
	return 0
}

// cmdRegister obtains a razor nomination-server identity (anonymous unless
// --user is given) and persists it where gozer loads it from —
// <RazorHome>/gazor-identity by default, or an explicit --out — then prints it
// as RAZOR_USER=/RAZOR_PASS= env lines. The credential is printed BEFORE the
// save so a save failure cannot strand a credential the server already created.
func cmdRegister(args []string) int {
	cfg := gozer.LoadConfig()
	fs := flag.NewFlagSet("razor-register", flag.ContinueOnError)
	user := fs.String("user", "", "register this account (empty = anonymous)")
	pass := fs.String("pass", "", "password for --user")
	home := fs.String("home", cfg.RazorHome, "razor home dir (RAZORHOME)")
	out := fs.String("out", "", "identity file to write (default <home>/"+gozer.IdentityFile+")")
	discovery := fs.String("discovery", razor.DefaultDiscovery, "discovery server")
	timeout := fs.Duration("timeout", 15*time.Second, "network timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	c := &razor.Client{Discovery: *discovery, Timeout: *timeout}
	id, err := c.Register(*user, *pass)
	if err != nil {
		fmt.Fprintln(os.Stderr, "razor-register:", err)
		return 1
	}

	target := *out
	if target == "" {
		target = filepath.Join(*home, gozer.IdentityFile)
	}
	fmt.Println("razor-register: environment variables for this identity (use instead of the file):")
	fmt.Printf("RAZOR_USER=%s\n", id.User)
	fmt.Printf("RAZOR_PASS=%s\n", id.Pass)
	if _, err := razor.WriteIdentityFile("", target, *id); err != nil {
		fmt.Fprintln(os.Stderr, "razor-register: WARNING identity obtained but NOT saved:", err)
		fmt.Fprintln(os.Stderr, "razor-register: copy the RAZOR_USER/RAZOR_PASS lines above — re-registering creates another account")
		return 1
	}
	fmt.Println("razor-register: saved identity to", target)
	return 0
}

// cmdPyzorRegister generates (or persists a supplied) pyzor account credential
// into the accounts file under the pyzor home, then prints it as
// GYZOR_USER=/GYZOR_SALT=/GYZOR_KEY= env lines. Only the username and key (not
// the salt) go to the pyzord administrator.
func cmdPyzorRegister(args []string) int {
	cfg := gozer.LoadConfig()
	fs := flag.NewFlagSet("pyzor-register", flag.ContinueOnError)
	user := fs.String("user", "", "pyzor account username (required)")
	key := fs.String("key", "", "account key hex (or combined salt,key); empty = generate a random key")
	salt := fs.String("salt", "", "account salt hex (optional; cosmetic, not used to sign)")
	home := fs.String("home", cfg.PyzorHome, "pyzor home dir (PYZOR_HOME)")
	servers := fs.String("servers", cfg.PyzorServers, "comma host[:port] to write entries for (default the public server)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *user == "" {
		fmt.Fprintln(os.Stderr, "pyzor-register: --user is required")
		return 2
	}

	path, acc, generated, err := gozer.PyzorRegister(*home, *servers, *user, *key, *salt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pyzor-register:", err)
		return 1
	}
	fmt.Println("pyzor-register: saved account to", path)
	fmt.Println("pyzor-register: environment variables for this identity (use instead of the file):")
	fmt.Printf("GYZOR_USER=%s\n", acc.Username)
	fmt.Printf("GYZOR_SALT=%s\n", acc.Salt)
	fmt.Printf("GYZOR_KEY=%s\n", acc.Key)
	if generated {
		fmt.Println("pyzor-register: give this username and key to the pyzord administrator:")
		fmt.Printf("pyzor-register:   user=%s key=%s\n", acc.Username, acc.Key)
	}
	return 0
}

// cmdDCCRegister persists a DCC client-id + password (issued by the dccd
// operator — DCC has no client-side registration) to the ids file gozer loads
// from, then prints it as DCC_CLIENT_ID=/DCC_CLIENT_PASSWD= env lines.
func cmdDCCRegister(args []string) int {
	cfg := gozer.LoadConfig()
	fs := flag.NewFlagSet("dcc-register", flag.ContinueOnError)
	clientID := fs.Uint("client-id", uint(cfg.DCCClientID), "DCC client-id (>1; issued by the dccd operator)")
	passwd := fs.String("passwd", cfg.DCCClientPass, "DCC client password")
	out := fs.String("out", "", "ids file to write (default DCC_IDS, else "+dcc.DefaultIDsPath+")")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *clientID <= 1 {
		fmt.Fprintln(os.Stderr, "dcc-register: --client-id must be your DCC id (>1; the anonymous id 1 needs no registration)")
		return 2
	}
	if *passwd == "" {
		fmt.Fprintln(os.Stderr, "dcc-register: --passwd is required (DCC ids are issued by the server operator)")
		return 2
	}

	path := *out
	if path == "" {
		if p := os.Getenv("DCC_IDS"); p != "" {
			path = p
		} else {
			path = dcc.DefaultIDsPath
		}
	}
	if err := gozer.DCCRegister(path, uint32(*clientID), *passwd); err != nil { // #nosec G115 -- client-id is a 32-bit DCC field
		fmt.Fprintln(os.Stderr, "dcc-register:", err)
		return 1
	}
	fmt.Println("dcc-register: saved client-id", *clientID, "to", path)
	fmt.Println("dcc-register: environment variables for this identity (use instead of the file):")
	fmt.Printf("DCC_CLIENT_ID=%d\n", *clientID)
	fmt.Printf("DCC_CLIENT_PASSWD=%s\n", *passwd)
	return 0
}
