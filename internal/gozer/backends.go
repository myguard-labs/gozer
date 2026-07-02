package gozer

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/myguard-labs/gazor/razor"
	"github.com/myguard-labs/gdcc/dcc"
	"github.com/myguard-labs/gyzor/pyzor"
)

// opCtx returns a context bounding one backend op by BackendTimeout, plus its
// cancel. It is intentionally detached from the HTTP request: gozer coalesces
// same-key misses (single-flight) and caches the result, so the shared backend
// work must complete for other waiters and the cache even if one caller
// disconnects — only the per-op total deadline applies. gdcc/gazor honour this
// as their one total-operation deadline (cancel-on-return frees sockets/
// goroutines promptly).
func (b *Backends) opCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), b.cfg.BackendTimeout)
}

// Verdict is the /check response: one sub-object per network.
type Verdict struct {
	DCC   DCCResult   `json:"dcc"`
	Razor RazorResult `json:"razor"`
	Pyzor PyzorResult `json:"pyzor"`
}

// DCCResult mirrors the original Python implementation: an action plus the bulk body count (null
// when DCC did not report one).
type DCCResult struct {
	Action string `json:"action"` // "reject" | "accept" | "unknown"
	Bulk   *int   `json:"bulk"`
}

// RazorResult is the razor verdict.
type RazorResult struct {
	Hit bool `json:"hit"`
}

// PyzorResult is the pyzor verdict: report count and whitelist count.
type PyzorResult struct {
	Count int `json:"count"`
	WL    int `json:"wl"`
}

// ReportResult is the /report and /revoke response. DCC is a pointer so it can
// be JSON null: /revoke always reports dcc=null (DCC has no network un-report).
// /report reports true/false (gdcc is in-process and always attempts the send).
type ReportResult struct {
	DCC   *bool `json:"dcc"`
	Razor bool  `json:"razor"`
	Pyzor bool  `json:"pyzor"`
}

// DefaultVerdict is the fail-open /check answer used when a request handler
// panics: every network reports its safe (non-spam / unknown) value.
func DefaultVerdict() Verdict {
	return Verdict{DCC: DCCResult{Action: "unknown"}}
}

// DefaultReport is the fail-open /report or /revoke answer (nothing reported).
func DefaultReport() ReportResult { return ReportResult{} }

// Backends runs the three collaborative-filter networks, all in-process:
// gazor (Razor), gyzor (Pyzor) and gdcc (DCC). A nil logf is tolerated.
type Backends struct {
	cfg     *Config
	pyzor   *pyzor.Client
	dcc     *dcc.Client
	ident   *razor.Identity // nil => report/revoke unavailable for razor
	logf    func(string, ...any)
	metrics *Metrics // optional; nil-safe (counts per-backend errors)
}

// NewBackends wires the pyzor client (servers/accounts loaded from PyzorHome)
// and the razor identity (if configured). logf is the always-on logger: backend
// errors are always logged through it; gazor/gyzor are pointed at it too and
// emit their own per-operation debug lines only when cfg.Verbose is set.
func NewBackends(cfg *Config, logf func(string, ...any)) *Backends {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	b := &Backends{cfg: cfg, logf: logf}
	b.pyzor = pyzor.New(pyzor.Config{
		Home:    cfg.PyzorHome,
		Servers: parsePyzorServers(cfg.PyzorServers), // GYZOR_SERVERS DNS-bypass; nil => homedir/default
		Timeout: cfg.BackendTimeout,
		Verbose: cfg.Verbose,
		Log:     func(line string) { logf("%s", line) },
	})
	// DCC identity: explicit env id/pass win, else DCC_IDS / /var/dcc/ids, else
	// anonymous. Servers default to the public pool when DCC_SERVERS is empty.
	id := dcc.ResolveIdentity(cfg.DCCClientID, cfg.DCCClientPass)
	b.dcc = &dcc.Client{
		Servers:  parseDCCServers(cfg.DCCServers),
		ClientID: id.ClientID,
		Password: id.Password,
		Timeout:  cfg.BackendTimeout,
		Verbose:  cfg.Verbose,
		Log:      func(line string) { logf("%s", line) },
	}
	if cfg.RazorUser != "" && cfg.RazorPass != "" {
		b.ident = &razor.Identity{User: cfg.RazorUser, Pass: cfg.RazorPass}
	}
	return b
}

// HasRazorIdentity reports whether report/revoke can reach razor.
func (b *Backends) HasRazorIdentity() bool { return b.ident != nil }

// razorClient builds a fresh client per call: razor.Client.Check/Report/Revoke
// each open and close their own connection, so the value is single-use. The
// client logs through gozer's logger (errors always; debug when Verbose).
func (b *Backends) razorClient() *razor.Client {
	return &razor.Client{
		Discoveries: splitCommaList(b.cfg.RazorDiscovery), // GAZOR_DISCOVERY DNS-bypass; nil => Razor2 default
		Timeout:     b.cfg.BackendTimeout,
		MinCf:       b.cfg.MinCf,
		Ident:       b.ident,
		Verbose:     b.cfg.Verbose,
		Log:         func(line string) { b.logf("%s", line) },
	}
}

// Check queries all three networks concurrently. healthy is true only when all
// three returned authoritative results; degraded fail-open verdicts must not be
// stored in the long-lived /check cache.
func (b *Backends) Check(msg []byte) (Verdict, bool) {
	v := DefaultVerdict()
	var healthy [3]bool
	b.runParallel(
		func() { v.DCC, healthy[0] = b.checkDCC(msg) },
		func() { v.Razor, healthy[1] = b.checkRazor(msg) },
		func() { v.Pyzor, healthy[2] = b.checkPyzor(msg) },
	)
	return v, healthy[0] && healthy[1] && healthy[2]
}

// Report submits the message as spam to all three networks concurrently.
func (b *Backends) Report(msg []byte) ReportResult {
	var r ReportResult
	b.runParallel(
		func() { r.DCC = b.reportDCC(msg) },
		func() { r.Razor = b.reportRazor(msg) },
		func() { r.Pyzor = b.pyzor.Report(msg) },
	)
	return r
}

// Revoke reports the message as ham where the network supports it. DCC has no
// network un-report, so dcc is always null.
func (b *Backends) Revoke(msg []byte) ReportResult {
	var r ReportResult // r.DCC stays nil -> JSON null
	b.runParallel(
		func() { r.Razor = b.revokeRazor(msg) },
		func() { r.Pyzor = b.pyzor.Whitelist(msg) },
	)
	return r
}

// --- DCC (gdcc, in-process) ---

func (b *Backends) checkDCC(msg []byte) (DCCResult, bool) {
	ctx, cancel := b.opCtx()
	defer cancel()
	res, err := b.dcc.CheckContext(ctx, msg)
	if err != nil {
		b.metrics.backendError("dcc")
		return DCCResult{Action: "unknown"}, false // gdcc already logged the error
	}
	// A body checksum at DCC "many" rejects (matches dccproc's default
	// threshold); a server whitelist accepts; otherwise no opinion.
	v := res.Verdict()
	return DCCResult{Action: v.Action.String(), Bulk: v.Bulk}, true
}

func (b *Backends) reportDCC(msg []byte) *bool {
	ctx, cancel := b.opCtx()
	defer cancel()
	ok := b.dcc.ReportContext(ctx, msg) == nil // gdcc logs the error itself
	return &ok
}

// parseDCCServers turns "h1,h2:6277,[::1]:6277" into gdcc servers. Empty -> nil
// (gdcc then uses the public anonymous pool).
func parseDCCServers(spec string) []dcc.Server {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	var out []dcc.Server
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		host, port := item, 0
		if h, p, err := net.SplitHostPort(item); err == nil {
			host = h
			if n, err := strconv.Atoi(p); err == nil {
				port = n
			}
		} else if strings.HasPrefix(item, "[") && strings.HasSuffix(item, "]") {
			host = item[1 : len(item)-1]
		}
		out = append(out, dcc.Server{Host: host, Port: port})
	}
	return out
}

// parsePyzorServers turns "h1:24441,h2" into gyzor servers. Empty -> nil (gyzor
// then uses the PyzorHome servers file or the public default).
func parsePyzorServers(spec string) []pyzor.Server {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	var out []pyzor.Server
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		host, port := item, pyzor.DefaultServer.Port
		if h, p, err := net.SplitHostPort(item); err == nil {
			host = h
			if n, err := strconv.Atoi(p); err == nil {
				port = n
			}
		} else if strings.HasPrefix(item, "[") && strings.HasSuffix(item, "]") {
			host = item[1 : len(item)-1]
		}
		out = append(out, pyzor.Server{Host: host, Port: port})
	}
	return out
}

// splitCommaList splits a comma list into trimmed non-empty entries (nil when
// empty), for the gazor Discoveries DNS-bypass list.
func splitCommaList(spec string) []string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	var out []string
	for _, item := range strings.Split(spec, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// --- Razor (gazor, in-process) ---

func (b *Backends) checkRazor(msg []byte) (RazorResult, bool) {
	ctx, cancel := b.opCtx()
	defer cancel()
	hit, err := b.razorClient().CheckContext(ctx, msg)
	if err != nil {
		b.metrics.backendError("razor")
		return RazorResult{Hit: false}, false // gazor already logged the error
	}
	return RazorResult{Hit: hit}, true
}

func (b *Backends) reportRazor(msg []byte) bool {
	if b.ident == nil {
		return false
	}
	ctx, cancel := b.opCtx()
	defer cancel()
	if err := b.razorClient().ReportContext(ctx, msg); err != nil {
		return false // gazor already logged the error
	}
	return true
}

func (b *Backends) revokeRazor(msg []byte) bool {
	if b.ident == nil {
		return false
	}
	ctx, cancel := b.opCtx()
	defer cancel()
	if err := b.razorClient().RevokeContext(ctx, msg); err != nil {
		return false // gazor already logged the error
	}
	return true
}

// --- Pyzor (gyzor, in-process) ---

func (b *Backends) checkPyzor(msg []byte) (PyzorResult, bool) {
	// gyzor aggregates across servers (Count/Whitelist are the max across
	// successful servers, the pyzor-correct semantics) and degrades to zero on
	// unreachable servers, so there is no error path here.
	res := b.pyzor.Check(msg)
	if !res.AllOK() {
		// Incomplete evidence: reference Pyzor requires every configured server
		// to answer before a count is authoritative. Return a zero score rather
		// than a partial max that could insert DRP_PYZOR on one server's reply.
		b.metrics.backendError("pyzor")
		return PyzorResult{}, false
	}
	return PyzorResult{Count: res.Count, WL: res.Whitelist}, true
}

// runParallel runs fns concurrently and waits for all to finish. Each fn is
// guarded by a recover so a panicking backend never crashes gozer or aborts its
// siblings; the panicking backend simply leaves its result at the seeded default
// (fail-open). A recovered panic is logged AND counted (gozer_error_total) so it
// is observable rather than silently swallowed.
func (b *Backends) runParallel(fns ...func()) {
	if len(fns) == 0 {
		return
	}
	var wg sync.WaitGroup
	wg.Add(len(fns) - 1)
	for _, fn := range fns[1:] {
		go func(f func()) {
			defer wg.Done()
			b.runGuarded(f)
		}(fn)
	}
	b.runGuarded(fns[0])
	wg.Wait()
}

func (b *Backends) runGuarded(fn func()) {
	defer func() {
		if rec := recover(); rec != nil {
			b.logf("backend panic recovered (fail-open): %v", rec)
			b.metrics.inc(&b.metrics.errorTotal)
		}
	}()
	fn()
}
