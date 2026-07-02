package pyzor

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultServer is the public pyzor server used when no servers file is present.
var DefaultServer = Server{Host: "public.pyzor.org", Port: 24441}

const maxPacketSize = 8192

// maxFanout bounds the number of servers queried concurrently per operation, so
// a very large servers file cannot burst an unbounded number of goroutines/UDP
// sockets. Beyond this, queries run in bounded waves.
const maxFanout = 16

// addrTTL bounds reuse of a resolved UDP address before re-resolving.
const addrTTL = 30 * time.Second

// recvPool reuses the per-query 8 KiB receive buffer to cut allocation under
// high-volume use. parseResponse copies the fields it keeps, so the buffer is
// safe to return to the pool after a query.
var recvPool = sync.Pool{New: func() any { b := make([]byte, maxPacketSize); return &b }}

// Server is a pyzor server address.
type Server struct {
	Host string
	Port int
}

func (s Server) addr() string { return net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) }
func (s Server) String() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

// Client issues pyzor queries to one or more servers.
type Client struct {
	Servers  []Server
	Accounts map[string]Account // keyed by "host:port"

	// DefaultAccount, when its Username is non-empty, is used for EVERY server,
	// overriding the per-server Accounts map. It carries an identity supplied
	// explicitly on the CLI/env (--user/--key), which is meant to apply to
	// whatever server is contacted rather than be matched per address.
	DefaultAccount Account
	Timeout        time.Duration

	// Verbose enables per-server debug logging. Server errors are logged
	// regardless of Verbose. Both go to Log (one preformatted line), or to
	// stderr when Log is nil — the shim points Log at its own logger.
	Verbose bool
	Log     func(string)

	addrMu    sync.Mutex           // guards addrCache
	addrCache map[string]addrEntry // resolved UDP addr cache (short TTL)
}

type addrEntry struct {
	addr *net.UDPAddr
	exp  time.Time
}

// resolve returns a (cached) UDP address for s, re-resolving after addrTTL.
// Resolution failures are not cached. Safe for the shared Client gozer reuses.
func (c *Client) resolve(s Server) (*net.UDPAddr, error) {
	key := s.addr()
	now := time.Now()
	c.addrMu.Lock()
	if e, ok := c.addrCache[key]; ok && now.Before(e.exp) {
		c.addrMu.Unlock()
		return e.addr, nil
	}
	c.addrMu.Unlock()

	addr, err := net.ResolveUDPAddr("udp", key)
	if err != nil {
		return nil, err
	}
	c.addrMu.Lock()
	if c.addrCache == nil {
		c.addrCache = make(map[string]addrEntry)
	}
	c.addrCache[key] = addrEntry{addr: addr, exp: now.Add(addrTTL)}
	c.addrMu.Unlock()
	return addr, nil
}

// invalidateAddr drops a cached address after an I/O failure.
func (c *Client) invalidateAddr(s Server) {
	c.addrMu.Lock()
	delete(c.addrCache, s.addr())
	c.addrMu.Unlock()
}

// emit writes one preformatted log line to Log, or stderr if Log is nil.
func (c *Client) emit(s string) {
	if c.Log != nil {
		c.Log(s)
		return
	}
	fmt.Fprintln(os.Stderr, s)
}

// logErr always logs (errors); logDbg logs only when Verbose is set.
func (c *Client) logErr(format string, a ...any) { c.emit("pyzor: " + fmt.Sprintf(format, a...)) }
func (c *Client) logDbg(format string, a ...any) {
	if c.Verbose {
		c.emit("pyzor: " + fmt.Sprintf(format, a...))
	}
}

// ServerResult is the per-server outcome of a check.
type ServerResult struct {
	Server  Server
	Code    int
	Diag    string
	Count   int
	WLCount int
	Err     error
}

// CheckResult aggregates a check across all servers, the way the rspamd shim
// consumes it: total report count and the max whitelist count.
type CheckResult struct {
	Count     int // summed report counts across servers
	Whitelist int // max whitelist count across servers
	Servers   []ServerResult
}

// Config configures a Client. If Servers/Accounts are empty and Home is set,
// they are loaded from Home/servers and Home/accounts (drop-in with ~/.pyzor).
type Config struct {
	Home     string
	Servers  []Server
	Accounts map[string]Account
	// DefaultAccount overrides the per-server map for every server when set
	// (Username non-empty) — see Client.DefaultAccount.
	DefaultAccount Account
	Timeout        time.Duration
	Verbose        bool
	Log            func(string)
}

// New builds a Client from cfg, applying sane defaults (public.pyzor.org, 5s).
func New(cfg Config) *Client {
	servers := cfg.Servers
	if len(servers) == 0 && cfg.Home != "" {
		servers = LoadServers(filepath.Join(cfg.Home, "servers"))
	}
	if len(servers) == 0 {
		servers = []Server{DefaultServer}
	}
	accounts := cfg.Accounts
	if accounts == nil && cfg.Home != "" {
		accounts = LoadAccounts(filepath.Join(cfg.Home, "accounts"))
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{
		Servers:        servers,
		Accounts:       accounts,
		DefaultAccount: cfg.DefaultAccount,
		Timeout:        timeout,
		Verbose:        cfg.Verbose,
		Log:            cfg.Log,
	}
}

func (c *Client) account(s Server) Account {
	// An explicit CLI/env identity applies to every server, overriding the file.
	if c.DefaultAccount.Username != "" {
		return c.DefaultAccount
	}
	if c.Accounts != nil {
		if a, ok := c.Accounts[s.addr()]; ok {
			return a
		}
	}
	return Anonymous
}

// Check computes the digest of the raw message and checks it (message-level API).
func (c *Client) Check(raw []byte) CheckResult { return c.CheckDigest(Compute(raw)) }

// Report computes the digest of the raw message and reports it as spam.
func (c *Client) Report(raw []byte) bool { return c.ReportDigest(Compute(raw)) }

// Whitelist computes the digest of the raw message and whitelists (revokes) it.
func (c *Client) Whitelist(raw []byte) bool { return c.WhitelistDigest(Compute(raw)) }

// CheckDigest queries every server (concurrently) and aggregates. Count and
// Whitelist are the MAX across successful servers, not a sum: pyzor decides a hit
// per-server, and summing replicated/independent servers would inflate the count
// and create false hits. Use CheckResult.Hit for the pyzor-correct verdict.
func (c *Client) CheckDigest(dgst string) CheckResult {
	res := CheckResult{Servers: c.queryAll(func() *request { return newRequest("check", dgst, false) })}
	for _, sr := range res.Servers {
		if sr.Err != nil || sr.Code != 200 {
			continue
		}
		if sr.Count > res.Count {
			res.Count = sr.Count
		}
		if sr.WLCount > res.Whitelist {
			res.Whitelist = sr.WLCount
		}
	}
	return res
}

// Hit reports the reference-pyzor spam verdict for this check. It mirrors
// CheckClientRunner + scripts/pyzor exactly — spam iff:
//   - EVERY queried server replied OK (all_ok), AND
//   - at least one server's report count exceeds rCount (found_hit), AND
//   - NO server's whitelist count exceeds wlCount (a whitelist on ANY server
//     clears the hit; a whitelisted server is not itself counted as a hit).
//
// This is NOT a per-server "any hit" test: a server error, or a whitelist on a
// different server, makes the whole check a miss, exactly as pyzor decides it.
func (r CheckResult) Hit(rCount, wlCount int) bool {
	if len(r.Servers) == 0 {
		return false
	}
	foundHit := false
	for _, sr := range r.Servers {
		if sr.Err != nil || sr.Code != 200 {
			return false // not all_ok -> never a hit
		}
		if sr.WLCount > wlCount {
			return false // whitelisted on any server clears the hit
		}
		if sr.Count > rCount {
			foundHit = true
		}
	}
	return foundHit
}

// AllOK reports whether every queried server returned a successful response.
func (r CheckResult) AllOK() bool {
	if len(r.Servers) == 0 {
		return false
	}
	for _, sr := range r.Servers {
		if sr.Err != nil || sr.Code != 200 {
			return false
		}
	}
	return true
}

// ReportDigest reports the digest as spam to every server; returns true if all OK.
func (c *Client) ReportDigest(dgst string) bool {
	return c.broadcast(func() *request { return newRequest("report", dgst, true) })
}

// WhitelistDigest whitelists (revokes) the digest on every server; true if all OK.
func (c *Client) WhitelistDigest(dgst string) bool {
	return c.broadcast(func() *request { return newRequest("whitelist", dgst, true) })
}

// Ping checks reachability of every server; true if all reply OK.
func (c *Client) Ping() bool {
	return c.broadcast(func() *request { return newRequest("ping", "", false) })
}

// broadcast queries all servers concurrently and reports all-OK.
func (c *Client) broadcast(mk func() *request) bool {
	results := c.queryAll(mk)
	if len(results) == 0 {
		return false
	}
	for _, sr := range results {
		if sr.Err != nil || sr.Code != 200 {
			return false
		}
	}
	return true
}

// queryAll runs one query per server concurrently (a fresh request each, since
// every server gets its own Thread/Time/Sig) so total latency is bounded by the
// slowest server, not the sum — important with unreachable servers in a pipeline.
func (c *Client) queryAll(mk func() *request) []ServerResult {
	results := make([]ServerResult, len(c.Servers))
	var wg sync.WaitGroup
	// Bound concurrent goroutines/sockets so a huge servers list cannot burst
	// unbounded fan-out; beyond maxFanout, queries proceed in waves.
	sem := make(chan struct{}, maxFanout)
	for i, s := range c.Servers {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, s Server) {
			defer wg.Done()
			defer func() { <-sem }()
			sr := ServerResult{Server: s}
			resp, err := c.query(s, mk())
			if err != nil {
				sr.Err = err
			} else {
				sr.Code = resp.code()
				sr.Diag = resp.fields["Diag"]
				sr.Count = resp.intField("Count")
				sr.WLCount = resp.intField("WL-Count")
			}
			results[i] = sr
		}(i, s)
	}
	wg.Wait()
	for _, sr := range results {
		if sr.Err != nil {
			c.logErr("server %s: %v", sr.Server, sr.Err)
		} else {
			c.logDbg("server %s: code=%d count=%d wl=%d", sr.Server, sr.Code, sr.Count, sr.WLCount)
		}
	}
	return results
}

// query signs and sends one request over UDP, reads the response, and validates
// it (complete + matching thread) before returning it.
func (c *Client) query(s Server, req *request) (*response, error) {
	thread := generateThread()
	packet := req.serialize(c.account(s), time.Now().Unix(), thread)

	raddr, err := c.resolve(s)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", s, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		c.invalidateAddr(s) // re-resolve next time instead of waiting out the TTL
		return nil, fmt.Errorf("dial %s: %w", s, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	if _, err := conn.Write(packet); err != nil {
		c.invalidateAddr(s)
		return nil, fmt.Errorf("send %s: %w", s, err)
	}
	bufp := recvPool.Get().(*[]byte)
	defer recvPool.Put(bufp)
	n, err := conn.Read(*bufp)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s, err)
	}
	resp := parseResponse((*bufp)[:n])
	if err := resp.validate(thread); err != nil {
		return nil, fmt.Errorf("%s: %w", s, err)
	}
	// A successful check response MUST carry both count fields; pyzor reads
	// response["Count"]/["WL-Count"] and would raise on a missing/nonnumeric
	// value. Reject such a response instead of silently treating it as 0/0.
	if req.op() == "check" && resp.code() == 200 {
		if err := resp.requireCounts(); err != nil {
			return nil, fmt.Errorf("%s: %w", s, err)
		}
	}
	return resp, nil
}

// --- config files (drop-in with ~/.pyzor in the existing volume) ---

var serverLineRe = regexp.MustCompile(`^[a-zA-Z0-9.-]+:[0-9]+`)

// LoadServers parses a pyzor "servers" file (one host:port per line); falls back
// to the public server when the file is absent or empty. Mirrors
// config.load_servers.
func LoadServers(path string) []Server {
	f, err := os.Open(path) // #nosec G304 -- operator-provided config path (CLI flag/env), not attacker input

	if err != nil {
		return []Server{DefaultServer}
	}
	defer f.Close()

	var servers []Server
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !serverLineRe.MatchString(line) {
			continue
		}
		i := strings.LastIndexByte(line, ':')
		host := line[:i]
		port, err := strconv.Atoi(line[i+1:])
		if err != nil {
			continue
		}
		servers = append(servers, Server{Host: host, Port: port})
	}
	if len(servers) == 0 {
		return []Server{DefaultServer}
	}
	return servers
}

// LoadAccounts parses a pyzor "accounts" file
// ("host : port : username : salt,key"). Mirrors config.load_accounts.
func LoadAccounts(path string) map[string]Account {
	accounts := map[string]Account{}
	f, err := os.Open(path) // #nosec G304 -- operator-provided config path (CLI flag/env), not attacker input

	if err != nil {
		return accounts
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 4 {
			continue
		}
		host := strings.TrimSpace(parts[0])
		port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			continue
		}
		username := strings.TrimSpace(parts[2])
		salt, key, err := keyFromHexStr(strings.TrimSpace(parts[3]))
		if err != nil || (salt == "" && key == "") {
			continue
		}
		accounts[Server{Host: host, Port: port}.addr()] = Account{Username: username, Salt: salt, Key: key}
	}
	return accounts
}
