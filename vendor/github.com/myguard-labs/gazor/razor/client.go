// Package razor is a from-scratch Go reimplementation of the Razor2 client
// (check / report / revoke), byte-compatible with the canonical razor-agents
// perl. The signature engines (Ephemeral/VR4, Whiplash/VR8), the preprocessing
// chain, the SIS/batched-query wire format and the discovery/greeting protocol
// are all ported from Razor2::* and verified against the perl source.
package razor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxResponseBytes caps a single server response so a malicious or broken server
// cannot make the client buffer unbounded data.
const maxResponseBytes = 1 << 20 // 1 MiB

// Defaults mirror Razor2::Client::Config.
const (
	DefaultDiscovery = "discovery.razor.cloudmark.com"
	DefaultPort      = 2703
	defaultBql       = 4
	defaultBqs       = 128
	agentName        = "gazor"
	razorVersion     = "2.85" // client/protocol version advertised to servers
)

// supportedEngines is razor's local set (Razor2::Client::Engine::supported_engines).
var supportedEngines = map[int]bool{4: true, 8: true}

// Identity is the registered nomination-server credential used for report/revoke.
type Identity struct {
	User string
	Pass string
}

// Client talks to razor servers. The zero value is usable after setting at
// least nothing — sensible defaults are filled in by Check/Report/Revoke.
type Client struct {
	Discovery   string   // discovery server (default DefaultDiscovery)
	Discoveries []string // optional discovery-server list; tried in order, first
	//             that returns servers wins. Bypasses Razor2 DNS-based
	//             discovery when set. Overrides Discovery when non-empty.
	Port       int           // server port (default DefaultPort)
	Server     string        // explicit catalogue/nomination server; skips discovery
	MinCf      string        // "ac", "ac+N", "ac-N", or a number; default "ac"
	UseEngines []int         // engines to use; default {4,8}
	Timeout    time.Duration // network timeout; default 15s
	Ident      *Identity     // credentials for report/revoke

	// Verbose enables per-operation debug logging. Errors are logged regardless
	// of Verbose. Both go to Log (a sink for one preformatted line), or to
	// stderr when Log is nil — the shim points Log at its own logger so library
	// diagnostics join the shim's output.
	Verbose bool
	Log     func(string)

	// mu serialises the public operations (Check/CheckSig/Report/Revoke/Register)
	// so a single Client shared across goroutines cannot interleave two protocol
	// sessions over the one connection/session state below.
	mu sync.Mutex

	conn        net.Conn
	br          *bufio.Reader
	connectedTo string
	srvConf     map[string]string
	greeting    map[string]string
	engines     map[int]bool
	minCfVal    int
	authed      bool

	// opCtx/opDeadline bound ONE public operation (set under mu in the entry
	// points). opDeadline is the single total budget for the whole op —
	// discovery, failover, state negotiation, auth and every query batch share
	// it instead of each phase getting a fresh full Timeout.
	opCtx      context.Context
	opDeadline time.Time
}

// beginOp installs the per-operation context and total deadline. ctx==nil is
// treated as context.Background. Called under mu at the start of each public op.
func (c *Client) beginOp(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	c.opCtx = ctx
	c.opDeadline = time.Now().Add(c.timeout())
	if d, ok := ctx.Deadline(); ok && d.Before(c.opDeadline) {
		c.opDeadline = d
	}
}

func (c *Client) endOp() {
	c.opCtx = nil
	c.opDeadline = time.Time{}
}

// budget is the remaining time for the current op, used for each network
// dial/read so the whole operation cannot exceed opDeadline. A floor keeps a
// final attempt from using a zero/negative deadline (which never times out).
func (c *Client) budget() time.Duration {
	if c.opDeadline.IsZero() {
		return c.timeout()
	}
	if rem := time.Until(c.opDeadline); rem > time.Millisecond {
		return rem
	}
	return time.Millisecond
}

// opErr reports the current op's context error (cancelled/expired), or nil.
func (c *Client) opErr() error {
	if c.opCtx != nil {
		return c.opCtx.Err()
	}
	return nil
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 15 * time.Second
}

func (c *Client) useEngines() []int {
	if len(c.UseEngines) > 0 {
		return c.UseEngines
	}
	return []int{4, 8}
}

func (c *Client) port() int {
	if c.Port > 0 {
		return c.Port
	}
	return DefaultPort
}

func (c *Client) bql() int { return atoiDefault(c.srvConf["bql"], defaultBql) }
func (c *Client) bqs() int { return atoiDefault(c.srvConf["bqs"], defaultBqs) }

func (c *Client) ep4() string {
	if e := c.srvConf["ep4"]; e != "" {
		return e
	}
	return "7542-10"
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
func (c *Client) logErr(format string, a ...any) { c.emit("razor: " + fmt.Sprintf(format, a...)) }
func (c *Client) logDbg(format string, a ...any) {
	if c.Verbose {
		c.emit("razor: " + fmt.Sprintf(format, a...))
	}
}

// --- public API ---

// PartSig holds the offline-computed signatures for one body part.
type PartSig struct {
	Index int
	E4    string   // VR4 (Ephemeral) signature; empty if none
	E8    []string // VR8 (Whiplash) signatures
	Skip  bool     // part was skipped as empty
}

// Signatures computes the razor signatures for a raw message offline, using the
// default ep4 (7542-10) and engines {4,8} — no server contact. Useful for
// debugging and for callers that only need the digests.
func Signatures(mail []byte) []PartSig {
	c := &Client{engines: map[int]bool{4: true, 8: true}}
	parts := c.prepare(mail)
	c.computeSigs(parts, "7542-10")
	out := make([]PartSig, 0, len(parts))
	for i, p := range parts {
		ps := PartSig{Index: i, Skip: p.skip, E8: p.sigs[8]}
		if s := p.sigs[4]; len(s) > 0 {
			ps.E4 = s[0]
		}
		out = append(out, ps)
	}
	return out
}

// Check returns whether mail (a raw RFC822 message) is known spam.
func (c *Client) Check(mail []byte) (bool, error) {
	return c.CheckContext(context.Background(), mail)
}

// CheckContext is Check bounded by ctx: ctx's deadline (or Timeout) caps the
// whole operation, and a cancelled ctx aborts discovery/negotiation/queries.
func (c *Client) CheckContext(ctx context.Context, mail []byte) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.beginOp(ctx)
	defer c.endOp()
	spam, err := c.checkLocked(mail)
	if err != nil {
		c.logErr("check failed: %v", err)
	} else {
		c.logDbg("check: spam=%t (%d bytes)", spam, len(mail))
	}
	return spam, err
}

func (c *Client) checkLocked(mail []byte) (bool, error) {
	if err := c.ensureCatalogue(); err != nil {
		return false, err
	}
	defer c.disconnect()

	// Distinguish a negotiation/config failure (no usable engines) from
	// legitimate ham: without engines we cannot make a verdict, so error rather
	// than silently returning "not spam".
	if len(c.engines) == 0 {
		return false, errors.New("no usable engines negotiated with server")
	}

	parts := c.prepare(mail)
	c.computeSigs(parts, c.ep4())

	queries, order := c.buildCheckQueries(parts)
	if len(queries) == 0 {
		return false, nil // no signatures to query (empty/skipped parts), not spam
	}
	resp, err := c.exchange(queries)
	if err != nil {
		return false, err
	}
	if err := c.distribute(order, resp); err != nil {
		return false, err
	}
	return c.checkLogic(parts), nil
}

// CheckSig checks a single precomputed signature (cmd-line style). ep4 is only
// needed for engine 4.
func (c *Client) CheckSig(engine int, sig, ep4 string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.beginOp(context.Background())
	defer c.endOp()
	if err := c.ensureCatalogue(); err != nil {
		return false, err
	}
	defer c.disconnect()
	if !c.engines[engine] {
		return false, fmt.Errorf("engine %d not supported by server", engine)
	}
	q := map[string]string{"a": "c", "e": strconv.Itoa(engine), "s": sig}
	if engine == 4 {
		if ep4 == "" {
			ep4 = c.ep4()
		}
		q["ep4"] = ep4
	}
	batches := toBatchedQuery([]map[string]string{q}, c.bql(), c.bqs(), true)
	resp, err := c.exchange(batches)
	if err != nil {
		return false, err
	}
	var flat []map[string]string
	for _, r := range resp {
		flat = append(flat, fromBatchedQuery(strings.TrimSuffix(r, ".\r\n"))...)
	}
	if len(flat) == 0 {
		return false, nil
	}
	return c.respIsSpam(flat[0]), nil
}

// Report submits mail as spam to a nomination server (requires Ident).
func (c *Client) Report(mail []byte) error { return c.ReportContext(context.Background(), mail) }

// ReportContext is Report bounded by ctx.
func (c *Client) ReportContext(ctx context.Context, mail []byte) error {
	err := c.reportOrRevoke(ctx, mail, false)
	if err != nil {
		c.logErr("report failed: %v", err)
	} else {
		c.logDbg("report: ok (%d bytes)", len(mail))
	}
	return err
}

// Revoke retracts a prior spam report for mail (requires Ident).
func (c *Client) Revoke(mail []byte) error { return c.RevokeContext(context.Background(), mail) }

// RevokeContext is Revoke bounded by ctx.
func (c *Client) RevokeContext(ctx context.Context, mail []byte) error {
	err := c.reportOrRevoke(ctx, mail, true)
	if err != nil {
		c.logErr("revoke failed: %v", err)
	} else {
		c.logDbg("revoke: ok (%d bytes)", len(mail))
	}
	return err
}

// --- signature computation ---

type part struct {
	body       []byte
	cleaned    []byte
	cleanedVR8 []byte
	skip       bool
	sigs       map[int][]string
	sent       []map[string]string
	resp       []map[string]string
	spam       int
	ct         int
}

func (c *Client) prepare(mail []byte) []*part {
	_, bodyparts := prepMail(mail, true, agentName+" v"+razorVersion)
	parts := make([]*part, 0, len(bodyparts))
	for _, b := range bodyparts {
		parts = append(parts, &part{body: normalizeCRLF(b), sigs: map[int][]string{}})
	}
	return parts
}

// computeSigs ports Core.pm compute_sigs: preproc each part (VR8 then VR4),
// apply the empty-part skip rules, then compute the engine signatures.
func (c *Client) computeSigs(parts []*part, ep4 string) {
	engines := c.sortedEngines()
	for _, p := range parts {
		p.cleanedVR8 = managerVR8.preproc(p.body)
		p.cleaned = managerVR4.preproc(p.body)
		clen := len(p.cleanedVR8)

		switch {
		case clen == 0:
			p.skip = true
		case clen < 128 && reContentOnly.Match(p.cleaned):
			p.skip = true
		case !reNonWS.Match(p.cleanedVR8):
			p.skip = true
		}
		if p.skip {
			continue
		}
		for _, e := range engines {
			switch e {
			case 4:
				if s := vr4Signature(p.cleaned, ep4); s != "" {
					p.sigs[4] = []string{s}
				}
			case 8:
				if s := vr8Signature(string(p.cleanedVR8)); len(s) > 0 {
					p.sigs[8] = s
				}
			}
		}
	}
}

// reContentOnly matches the Core.pm "seems empty" rule: a body that is only
// Content-* header lines (no real content).
var reContentOnly = regexp.MustCompile(`(?s)^(Content\S*:[^\n]*\n\r?)+(Content\S*:[^\n]*)?\s*$`)

func (c *Client) sortedEngines() []int {
	var es []int
	for e := range c.engines {
		es = append(es, e)
	}
	sort.Ints(es)
	return es
}

// --- query building / response distribution ---

func (c *Client) buildCheckQueries(parts []*part) ([]string, []*part) {
	var order []*part
	var flat []map[string]string
	for _, p := range parts {
		if p.skip {
			continue
		}
		p.sent = nil
		for _, e := range c.sortedEngines() {
			sigs, ok := p.sigs[e]
			if !ok || len(sigs) == 0 {
				continue
			}
			for _, s := range sigs {
				q := map[string]string{"a": "c", "e": strconv.Itoa(e), "s": s}
				if e == 4 {
					q["ep4"] = c.ep4()
				}
				p.sent = append(p.sent, q)
			}
		}
		if len(p.sent) > 0 {
			flat = append(flat, p.sent...)
			order = append(order, p)
		}
	}
	if len(flat) == 0 {
		return nil, nil
	}
	return toBatchedQuery(flat, c.bql(), c.bqs(), true), order
}

func (c *Client) distribute(order []*part, responses []string) error {
	var flat []map[string]string
	for _, r := range responses {
		flat = append(flat, fromBatchedQuery(strings.TrimSuffix(r, ".\r\n"))...)
	}
	// Require the response count to match the number of submitted queries:
	// missing or extra responses desynchronise part↔response mapping and would
	// otherwise be silently dropped, turning a malformed reply into false ham.
	expected := 0
	for _, p := range order {
		expected += len(p.sent)
	}
	if len(flat) != expected {
		return fmt.Errorf("response cardinality mismatch: got %d responses, want %d", len(flat), expected)
	}
	i := 0
	for _, p := range order {
		for range p.sent {
			p.resp = append(p.resp, flat[i])
			i++
		}
	}
	return nil
}

// respIsSpam ports check_resp for logic_engines='any': sig present (p=1) and
// (no cf, or cf >= min_cf). err responses are never spam. Also records ct.
func (c *Client) respIsSpam(r map[string]string) bool {
	if _, ok := r["err"]; ok {
		return false
	}
	if r["p"] == "1" {
		if cf, ok := r["cf"]; ok {
			return atoiDefault(cf, 0) >= c.minCfVal
		}
		return true
	}
	return false
}

// checkLogic ports check_logic with the defaults logic_engines='any',
// logic_method=4 (any non-contention spam part => spam).
func (c *Client) checkLogic(parts []*part) bool {
	for _, p := range parts {
		if p.skip {
			continue
		}
		p.ct = 0
		p.spam = 0
		for _, r := range p.resp {
			if ct, ok := r["ct"]; ok {
				p.ct = atoiDefault(ct, 0)
			}
			if c.respIsSpam(r) {
				p.spam++
			}
		}
	}
	for _, p := range parts {
		if p.skip || p.ct != 0 {
			continue
		}
		if p.spam > 0 {
			return true
		}
	}
	return false
}

// --- report / revoke ---

func (c *Client) reportOrRevoke(ctx context.Context, mail []byte, revoke bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.beginOp(ctx)
	defer c.endOp()
	if c.Ident == nil || c.Ident.User == "" {
		return errors.New("report/revoke requires an Identity (register first)")
	}
	if err := c.ensureNomination(); err != nil {
		return err
	}
	defer c.disconnect()
	if err := c.authenticate(c.Ident); err != nil {
		return err
	}

	parts := c.prepare(mail)
	c.computeSigs(parts, c.ep4())
	headers, _ := prepMail(mail, true, agentName+" v"+razorVersion)

	dre := atoiDefault(c.srvConf["dre"], 4)
	if revoke {
		return c.sendRevoke(parts)
	}
	return c.sendReport(parts, headers, dre)
}

func (c *Client) sendReport(parts []*part, headers []byte, dre int) error {
	// rcheck round: ask whether the server already has each part's dre sig.
	var order []*part
	var flat []map[string]string
	for _, p := range parts {
		if p.skip {
			continue
		}
		sigs := p.sigs[dre]
		if len(sigs) == 0 {
			continue
		}
		q := map[string]string{"a": "r", "e": strconv.Itoa(dre), "s": sigs[0]}
		if dre == 4 {
			q["ep4"] = c.ep4()
		}
		p.sent = []map[string]string{q}
		flat = append(flat, q)
		order = append(order, p)
	}
	if len(flat) == 0 {
		return nil
	}
	resp, err := c.exchange(toBatchedQuery(flat, c.bql(), c.bqs(), true))
	if err != nil {
		return err
	}
	if err := c.distribute(order, resp); err != nil {
		return err
	}

	// Send only the parts the server actually asked for (err=230). Mark every
	// other part skipped so buildReportChunks uploads exactly the requested
	// parts — Core.pm marks each non-wanted part skipped before make_query, so
	// uploading all non-skip parts would disclose body parts the server has and
	// diverge from the reference protocol.
	wanted := make(map[*part]bool, len(order))
	for _, p := range order {
		if len(p.resp) > 0 && p.resp[0]["err"] == "230" {
			wanted[p] = true
		}
	}
	if len(wanted) == 0 {
		return nil // server already has every part; nothing to upload
	}
	for _, p := range parts {
		if !wanted[p] {
			p.skip = true
		}
	}
	// Pack the report into one or more chunks (headers + as many part bodies as
	// fit under bqs), never truncating; submit each and validate the server's
	// acknowledgement so a rejected report is not reported as success.
	for _, chunk := range buildReportChunks(headers, parts, c.bqs()) {
		q := map[string]string{"a": "r", "message": chunk}
		resp, err := c.exchange(toBatchedQuery([]map[string]string{q}, c.bql(), c.bqs(), true))
		if err != nil {
			return err
		}
		if err := checkReportResp(resp); err != nil {
			return err
		}
	}
	return nil
}

// checkReportResp validates report/revoke acknowledgements (Core.pm
// rcheck_resp): a non-230 err, or res=0, means the server did not accept the
// submission. err=230 ("wants mail") and res=1 ("accepted") are success.
func checkReportResp(responses []string) error {
	if len(responses) == 0 {
		return errors.New("empty report response")
	}
	for _, r := range responses {
		hs := fromBatchedQuery(strings.TrimSuffix(r, ".\r\n"))
		if len(hs) == 0 {
			return errors.New("malformed report response (no fields)")
		}
		for _, h := range hs {
			if e, ok := h["err"]; ok && e != "230" {
				return fmt.Errorf("server returned err %s", e)
			}
			if h["res"] == "0" {
				return errors.New("server did not accept the report")
			}
			// An empty/field-less ack must not pass as success: require an
			// explicit recognized success marker (res=1, or err=230 "wants mail").
			if h["res"] != "1" && h["err"] != "230" {
				return errors.New("report response missing a success result (res=1 / err=230)")
			}
		}
	}
	return nil
}

func (c *Client) sendRevoke(parts []*part) error {
	var flat []map[string]string
	for _, p := range parts {
		if p.skip {
			continue
		}
		for _, e := range c.sortedEngines() {
			for _, s := range p.sigs[e] {
				flat = append(flat, map[string]string{"a": "revoke", "e": strconv.Itoa(e), "s": s})
			}
		}
	}
	if len(flat) == 0 {
		return nil
	}
	resp, err := c.exchange(toBatchedQuery(flat, c.bql(), c.bqs(), true))
	if err != nil {
		return err
	}
	return checkReportResp(resp)
}

// buildReportChunks ports make_query(report): pack the headers plus as many part
// bodies as fit under bqs*1024 into each chunk, emitting MULTIPLE chunks rather
// than truncating once the limit is hit (the perl @dudes loop). At least one
// body is always placed per chunk to guarantee forward progress (prep_part caps
// bodies, so a single body+headers stays under the limit in practice).
func buildReportChunks(headers []byte, parts []*part, bqs int) []string {
	limit := bqs * 1024
	var bodies [][]byte
	for _, p := range parts {
		if !p.skip {
			bodies = append(bodies, p.body)
		}
	}
	var chunks []string
	for n := 0; n < len(bodies); {
		var sb strings.Builder
		sb.Write(headers)
		for n < len(bodies) {
			// stop this chunk once another body would exceed the limit, but only
			// after at least one body has been added (forward progress).
			if sb.Len() > len(headers) && sb.Len()+len(bodies[n]) >= limit {
				break
			}
			sb.WriteString("\r\n")
			sb.Write(bodies[n])
			n++
		}
		chunks = append(chunks, sb.String())
	}
	return chunks
}

// --- registration / auth ---

// Register obtains a new nomination-server identity (a=reg).
func (c *Client) Register(user, pass string) (*Identity, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.beginOp(context.Background())
	defer c.endOp()
	if err := c.ensureNomination(); err != nil {
		return nil, err
	}
	defer c.disconnect()
	q := map[string]string{"a": "reg", "registrar": agentName}
	if user != "" {
		q["user"] = user
	}
	if pass != "" {
		q["pass"] = pass
	}
	resp, err := c.send([]string{makesis(q)})
	if err != nil {
		return nil, err
	}
	r := parsesis(resp[0])
	if e := r["err"]; e != "" {
		return nil, fmt.Errorf("register failed: err %s", e)
	}
	if r["res"] != "1" {
		return nil, fmt.Errorf("register failed: res %q", r["res"])
	}
	return &Identity{User: r["user"], Pass: r["pass"]}, nil
}

// authenticate ports Core.pm authenticate: a=ai -> achal -> HMAC(aresp) -> a=auth.
func (c *Client) authenticate(id *Identity) error {
	if id.User == "" || id.Pass == "" {
		return errors.New("authenticate: empty user/pass")
	}
	resp, err := c.send([]string{makesis(map[string]string{
		"a": "ai", "user": id.User, "cn": "razor-agents", "cv": razorVersion,
	})})
	if err != nil {
		return err
	}
	r := parsesis(resp[0])
	if e := r["err"]; e != "" {
		return fmt.Errorf("authenticate (ai) failed: err %s", e)
	}
	iv1, iv2 := xorKey(id.Pass)
	aresp := hmacSHA1(r["achal"], iv1, iv2)
	resp, err = c.send([]string{makesis(map[string]string{"a": "auth", "aresp": aresp})})
	if err != nil {
		return err
	}
	r = parsesis(resp[0])
	if e := r["err"]; e != "" {
		return fmt.Errorf("authenticate (auth) failed: err %s", e)
	}
	if r["res"] != "1" {
		return fmt.Errorf("authentication failed for user %s", id.User)
	}
	c.authed = true
	return nil
}

// --- connection / discovery ---

func (c *Client) ensureCatalogue() error  { return c.ensureServer("catalogue") }
func (c *Client) ensureNomination() error { return c.ensureServer("nomination") }

func (c *Client) ensureServer(kind string) error {
	if c.Server != "" {
		return c.connectAndPrepare(c.Server)
	}
	// Reuse a recently discovered server list so fresh per-request clients
	// (gozer builds one per message) don't repeat the separate discovery TCP
	// handshake every time. The list is just hostnames; a short TTL picks up
	// Cloudmark changes, and an all-candidates-failed result re-discovers.
	cacheKey := kind + "\x00" + strings.Join(c.discoveryList(), ",")
	servers, cached := discCacheGet(cacheKey)
	if !cached {
		var err error
		servers, err = c.discover(kind)
		if err != nil {
			return err
		}
		discCachePut(cacheKey, servers)
	}
	var lastErr error
	for _, s := range servers {
		if err := c.opErr(); err != nil {
			return err // cancelled/expired — stop trying candidates
		}
		if err := c.connectAndPrepare(s); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	// every candidate failed — drop the cached list so the next op re-discovers
	discCacheDel(cacheKey)
	if lastErr == nil {
		lastErr = fmt.Errorf("no %s servers discovered", kind)
	}
	return lastErr
}

// discCache is a process-global, concurrency-safe short-TTL cache of discovered
// catalogue/nomination server lists, shared across the fresh Clients gozer
// builds per request so discovery is not repeated on every message.
var (
	discMu    sync.Mutex
	discCache = map[string]discEntry{}
)

type discEntry struct {
	servers []string
	exp     time.Time
}

const discCacheTTL = 5 * time.Minute

func discCacheGet(key string) ([]string, bool) {
	discMu.Lock()
	defer discMu.Unlock()
	if e, ok := discCache[key]; ok && time.Now().Before(e.exp) {
		return e.servers, true
	}
	return nil, false
}

func discCachePut(key string, servers []string) {
	discMu.Lock()
	discCache[key] = discEntry{servers: servers, exp: time.Now().Add(discCacheTTL)}
	discMu.Unlock()
}

func discCacheDel(key string) {
	discMu.Lock()
	delete(discCache, key)
	discMu.Unlock()
}

// discoveryList returns the discovery servers to try, in order: the explicit
// Discoveries list if set, else the single Discovery (or the built-in default).
func (c *Client) discoveryList() []string {
	if len(c.Discoveries) > 0 {
		return c.Discoveries
	}
	if c.Discovery != "" {
		return []string{c.Discovery}
	}
	return []string{DefaultDiscovery}
}

// discover queries the discovery server(s) for catalogue ("csl") / nomination
// ("nsl") server lists (Core.pm discover). Multiple discovery servers are tried
// in order; the first that returns a usable list wins (DNS-bypass failover).
func (c *Client) discover(kind string) ([]string, error) {
	want := map[string]string{"catalogue": "csl", "nomination": "nsl"}[kind]
	var lastErr error
	for _, disc := range c.discoveryList() {
		servers, err := c.discoverFrom(disc, want)
		if err != nil {
			lastErr = err
			c.logDbg("discovery %s failed: %v", disc, err)
			continue
		}
		return servers, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no discovery servers configured")
	}
	return nil, lastErr
}

// discoverFrom queries a single discovery server for the wanted server list.
func (c *Client) discoverFrom(disc, want string) ([]string, error) {
	conn, br, err := c.dial(disc)
	if err != nil {
		return nil, fmt.Errorf("discovery dial %s: %w", disc, err)
	}
	defer conn.Close()
	if _, err := readGreeting(conn, br, c.budget()); err != nil {
		return nil, err
	}
	c.conn, c.br = conn, br
	resp, err := c.send([]string{"a=g&pm=" + want + "\r\n"})
	c.conn, c.br = nil, nil
	if err != nil {
		return nil, err
	}
	var servers []string
	seen := map[string]bool{}
	for _, r := range resp {
		for _, h := range fromBatchedQuery(strings.TrimSuffix(r, ".\r\n")) {
			if v := h[want]; v != "" && !seen[v] {
				seen[v] = true
				servers = append(servers, v)
			}
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("discovery server %s returned no %s servers", disc, want)
	}
	return servers, nil
}

// connectAndPrepare dials a server, parses the greeting, fetches its state
// (a=g&pm=state), and computes the engine set + min_cf (compute_server_conf).
func (c *Client) connectAndPrepare(server string) error {
	if err := c.opErr(); err != nil {
		return err // cancelled/expired before dialing
	}
	conn, br, err := c.dial(server)
	if err != nil {
		return err
	}
	greeting, err := readGreeting(conn, br, c.budget())
	if err != nil {
		_ = conn.Close()
		return err
	}
	if greeting["sn"] == "" {
		_ = conn.Close()
		return fmt.Errorf("server %s: unparsable greeting", server)
	}
	c.conn, c.br, c.connectedTo = conn, br, server
	c.greeting = greeting
	c.srvConf = map[string]string{}

	if greeting["a"] == "cg" {
		if _, err := c.sendNoRead([]string{"cn=razor-agents&cv=" + razorVersion + "\r\n"}); err != nil {
			c.disconnect()
			return err
		}
	}
	// We never cache srl, so always fetch state.
	resp, err := c.send([]string{"a=g&pm=state\r\n"})
	if err != nil {
		c.disconnect()
		return err
	}
	for _, r := range resp {
		for _, h := range fromBatchedQuery(strings.TrimSuffix(r, ".\r\n")) {
			for k, v := range h {
				c.srvConf[k] = v
			}
		}
	}
	c.computeServerConf()
	return nil
}

// computeServerConf ports Core.pm compute_server_conf: min_cf from ac, ep4 from
// the greeting, engines from the server's se bitfield ∩ use_engines ∩ supported.
func (c *Client) computeServerConf() {
	c.minCfVal = c.computeMinCf()
	if e := c.greeting["ep4"]; e != "" {
		c.srvConf["ep4"] = e
	}
	serverEng := hexbits2hash(c.srvConf["se"])
	c.engines = map[int]bool{}
	for _, e := range c.useEngines() {
		if supportedEngines[e] && serverEng[e] {
			c.engines[e] = true
		}
	}
}

func (c *Client) computeMinCf() int {
	ac := atoiDefault(c.srvConf["ac"], 0)
	minCf := strings.ReplaceAll(c.MinCf, " ", "")
	if minCf == "" {
		minCf = "ac"
	}
	cf := ac
	switch {
	case strings.HasPrefix(minCf, "ac+"):
		cf = ac + atoiDefault(minCf[3:], 0)
	case strings.HasPrefix(minCf, "ac-"):
		cf = ac - atoiDefault(minCf[3:], 0)
	case minCf == "ac":
		cf = ac
	default:
		if n, err := strconv.Atoi(minCf); err == nil {
			cf = n
		}
	}
	if cf > 100 {
		cf = 100
	}
	if cf < 0 {
		cf = 0
	}
	return cf
}

// --- low-level network ---

func (c *Client) dial(server string) (net.Conn, *bufio.Reader, error) {
	conn, err := net.DialTimeout("tcp", c.serverAddr(server), c.budget())
	if err != nil {
		return nil, nil, err
	}
	return conn, bufio.NewReader(conn), nil
}

// serverAddr resolves a server entry to a dial address. An entry that already
// carries a port (host:port, [ipv6]:port) is used verbatim; otherwise the
// default port is applied. This lets --server / --discovery / Discoveries
// entries pin an explicit port (e.g. 127.0.0.1:2703 for a DNS-bypass) instead
// of always re-wrapping the global port — which produced the bogus host
// "127.0.0.1:2703" and broke the lookup.
func (c *Client) serverAddr(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server // already host:port (or [ipv6]:port)
	}
	host := server
	if strings.HasPrefix(server, "[") && strings.HasSuffix(server, "]") {
		host = server[1 : len(server)-1] // bracketed IPv6 without a port
	}
	return net.JoinHostPort(host, strconv.Itoa(c.port()))
}

func (c *Client) disconnect() {
	if c.conn == nil {
		return
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.conn.Write([]byte("a=q\r\n"))
	_ = c.conn.Close()
	c.conn, c.br, c.connectedTo = nil, nil, ""
	c.authed = false
}

// exchange sends batches and returns one raw response per batch.
func (c *Client) exchange(batches []string) ([]string, error) {
	if len(batches) == 0 {
		return nil, nil
	}
	return c.send(batches)
}

// send writes each message and reads back its response (Core.pm _send).
func (c *Client) send(msgs []string) ([]string, error) {
	if c.conn == nil {
		return nil, errors.New("not connected")
	}
	out := make([]string, 0, len(msgs))
	for _, m := range msgs {
		if err := c.opErr(); err != nil {
			return nil, err // cancelled/expired between batches
		}
		if err := c.writeMsg(m); err != nil {
			return nil, err
		}
		r, err := readResponse(c.conn, c.br, c.budget())
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (c *Client) sendNoRead(msgs []string) ([]string, error) {
	if c.conn == nil {
		return nil, errors.New("not connected")
	}
	for _, m := range msgs {
		if err := c.writeMsg(m); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func (c *Client) writeMsg(m string) error {
	if err := c.conn.SetWriteDeadline(time.Now().Add(c.budget())); err != nil {
		return err
	}
	_, err := c.conn.Write([]byte(m))
	return err
}

// readLineLimited reads up to and including the next '\n', but bounds the line
// at max bytes so a malicious server cannot make ReadString allocate an
// unbounded line that has no newline (the size guards downstream only run AFTER
// ReadString returns). ReadByte is buffered, so this stays cheap.
func readLineLimited(br *bufio.Reader, max int) (string, error) {
	var sb strings.Builder
	for {
		// ReadSlice returns a buffer-sized fragment up to (and including) '\n';
		// ErrBufferFull means the line is longer than the bufio buffer, so keep
		// reading fragments. This is far cheaper than ReadByte per byte while
		// still bounding the line at max.
		frag, err := br.ReadSlice('\n')
		sb.Write(frag)
		if sb.Len() > max {
			return sb.String(), fmt.Errorf("line exceeded %d bytes", max)
		}
		if err == nil {
			return sb.String(), nil // delimiter found — one full line
		}
		if err == bufio.ErrBufferFull {
			continue // more of this line remains in the stream
		}
		return sb.String(), err // EOF / timeout / other
	}
}

// readGreeting reads the single-line server greeting and parses it.
func readGreeting(conn net.Conn, br *bufio.Reader, timeout time.Duration) (map[string]string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	line, err := readLineLimited(br, maxResponseBytes)
	if err != nil && line == "" {
		return nil, err
	}
	return parsesis(line), nil
}

// readResponse accumulates a server response, terminating on a ".\r\n" line, or
// after a short idle once data has arrived (single-line, undelimited replies).
func readResponse(conn net.Conn, br *bufio.Reader, timeout time.Duration) (string, error) {
	var sb strings.Builder
	// Absolute operation deadline: a continuous slow drip cannot keep extending
	// the per-read idle deadline forever — the whole reply must arrive within
	// `timeout` of the first read.
	deadline := time.Now().Add(timeout)
	first := true
	for {
		d := 250 * time.Millisecond
		if first {
			d = timeout
		}
		rd := time.Now().Add(d)
		if rd.After(deadline) {
			rd = deadline
		}
		_ = conn.SetReadDeadline(rd)
		chunk, err := readLineLimited(br, maxResponseBytes)
		if chunk != "" {
			sb.WriteString(chunk)
			first = false
		}
		if sb.Len() > maxResponseBytes {
			return sb.String(), fmt.Errorf("response exceeded %d bytes", maxResponseBytes)
		}
		// readLineLimited returns exactly one line per call, so the protocol
		// terminator is the standalone ".\r\n" line — detect it on the chunk
		// instead of rebuilding and HasSuffix-scanning the whole response each
		// iteration (which was O(n^2)).
		if chunk == ".\r\n" {
			return sb.String(), nil
		}
		if err != nil {
			if (isTimeout(err) || errors.Is(err, io.EOF)) && sb.Len() > 0 {
				return sb.String(), nil // idle/EOF: reply complete
			}
			return sb.String(), err
		}
		if !time.Now().Before(deadline) {
			if sb.Len() > 0 {
				return sb.String(), nil // deadline reached with data: treat as complete
			}
			return sb.String(), fmt.Errorf("response not received within %s", timeout)
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// --- misc helpers ---

func hexbits2hash(hexstr string) map[int]bool {
	n, _ := strconv.ParseUint(strings.TrimSpace(hexstr), 16, 64)
	h := map[int]bool{}
	for i := 0; i < 32; i++ {
		if n&(1<<uint(i)) != 0 {
			h[i+1] = true
		}
	}
	return h
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

func normalizeCRLF(b []byte) []byte {
	first := bytes.Index(b, []byte("\r\n"))
	if first < 0 {
		return b
	}
	out := make([]byte, 0, len(b))
	out = append(out, b[:first]...)
	for i := first; i < len(b); {
		if b[i] != '\r' {
			out = append(out, b[i])
			i++
			continue
		}
		j := i
		for j < len(b) && b[j] == '\r' {
			j++
		}
		if j < len(b) && b[j] == '\n' {
			out = append(out, '\n')
			i = j + 1
			continue
		}
		out = append(out, b[i:j]...)
		i = j
	}
	return out
}
