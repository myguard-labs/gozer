package gozer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Engine is the backend the server dispatches to. *Backends is the production
// implementation; tests inject a fake to exercise the HTTP layer without live
// razor/pyzor network calls.
type Engine interface {
	Check(msg []byte) (Verdict, bool)
	Report(msg []byte) ReportResult
	Revoke(msg []byte) ReportResult
	HasRazorIdentity() bool
}

// Server is the HTTP front-end: auth, body limits, the bounded-concurrency
// gate, the /check verdict cache, and fail-open dispatch to the engine.
type Server struct {
	cfg     *Config
	engine  Engine
	cache   Cache
	sem     chan struct{}
	flights flightGroup
	epochs  [256]atomic.Uint64
	metrics *Metrics
	info    *log.Logger // access/info — stdout when GOZER_LOG_STDOUT, else stderr
	errl    *log.Logger // errors/warnings — always stderr
}

// newLoggers builds the info (stdout-toggle) and error (always-stderr) loggers.
func newLoggers(cfg *Config) (info, errl *log.Logger) {
	var infoW io.Writer = os.Stderr
	if cfg.LogStdout {
		infoW = os.Stdout
	}
	return log.New(infoW, "[gozer] ", 0), log.New(os.Stderr, "[gozer] ", 0)
}

// NewServer builds the server, its backends and its cache from cfg.
func NewServer(cfg *Config) *Server {
	cfg.sanitize() // re-clamp after any CLI-flag overlay so make(chan) can't panic
	info, errl := newLoggers(cfg)
	s := &Server{cfg: cfg, sem: make(chan struct{}, cfg.MaxConcurrent), metrics: NewMetrics(), info: info, errl: errl}
	// Backend/cache diagnostics are mostly errors → route them to stderr.
	b := NewBackends(cfg, s.errf)
	b.metrics = s.metrics
	s.engine = b
	s.cache = NewCache(cfg, s.errf, s.metrics)
	return s
}

// NewServerWithEngine builds a server around a supplied engine and cache (for
// tests). A nil cache disables caching.
func NewServerWithEngine(cfg *Config, engine Engine, cache Cache) *Server {
	cfg.sanitize()
	info, errl := newLoggers(cfg)
	return &Server{cfg: cfg, engine: engine, cache: cache, sem: make(chan struct{}, cfg.MaxConcurrent), metrics: NewMetrics(), info: info, errl: errl}
}

// logf writes an info/access line (stdout when GOZER_LOG_STDOUT is set).
// #nosec G706 -- callers pass internal constant format strings; args are
// numbers and JSON (encoding/json escapes control chars), never raw message bytes.
func (s *Server) logf(format string, a ...any) { s.info.Printf(format, a...) }

// errf writes an error/warning line — always to stderr regardless of the
// stdout toggle, so a log shipper can separate and alert on the error stream.
func (s *Server) errf(format string, a ...any) { s.errl.Printf(format, a...) }

func (s *Server) vlogf(format string, a ...any) {
	if s.cfg.Verbose {
		s.logf(format, a...)
	}
}

// ListenAndServe binds and serves until the process is signalled.
func (s *Server) ListenAndServe() error {
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	srv := &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second, // Slowloris guard
		// Bound a slow client holding the body or the response: a request must
		// arrive and be answered within the backend budget plus slack, and idle
		// keep-alive connections are reaped.
		ReadTimeout:  s.cfg.BackendTimeout + 20*time.Second,
		WriteTimeout: s.cfg.BackendTimeout + 25*time.Second,
		IdleTimeout:  60 * time.Second,
	}
	s.logStartup(addr)
	return srv.ListenAndServe()
}

func (s *Server) logStartup(addr string) {
	if s.cfg.Token == "" {
		s.errf("WARNING: no GOZER_TOKEN configured — POST endpoints will refuse all " +
			"requests (503). Set GOZER_TOKEN or GOZER_TOKEN_FILE.")
	}
	cache := "off"
	if s.cache != nil {
		cache = "memory"
		if s.cfg.RedisURL != "" {
			cache = "redis"
		}
	}
	s.logf("listening on %s (timeout=%s, max_concurrent=%d, cache=%s ttl=%s, "+
		"razor_identity=%t, verbose=%t, auth=%t)",
		addr, s.cfg.BackendTimeout, s.cfg.MaxConcurrent, cache, s.cfg.CacheTTL,
		s.engine.HasRazorIdentity(), s.cfg.Verbose, s.cfg.Token != "")
	// Under verbose, dump the full resolved config (no secrets) so an operator
	// can confirm env/flag overrides took effect.
	s.vlogf("config: pyzor_home=%s razor_home=%s min_cf=%s dcc_servers=%q "+
		"pyzor_servers=%q razor_discovery=%q cache_size=%d redis=%t max_body=%dB",
		s.cfg.PyzorHome, s.cfg.RazorHome, s.cfg.MinCf, s.cfg.DCCServers,
		s.cfg.PyzorServers, s.cfg.RazorDiscovery, s.cfg.CacheSize,
		s.cfg.RedisURL != "", s.cfg.MaxBody)
	s.logf("repo: %s", RepoURL)
}

// RepoURL is the project's source, logged at startup when log-stdout is on.
const RepoURL = "https://github.com/myguard-labs/gozer"

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/health":
		writeText(w, http.StatusOK, "ok")
	case r.Method == http.MethodGet && r.URL.Path == "/metrics":
		s.metrics.ServeHTTP(w, r)
	case r.Method == http.MethodPost && isBackendPath(r.URL.Path):
		s.handlePost(w, r)
	default:
		writeText(w, http.StatusNotFound, "not found")
	}
}

func isBackendPath(p string) bool {
	return p == "/check" || p == "/report" || p == "/revoke"
}

// maxBodyHardLimit is a constant ceiling on a request body, well above any
// MaxBody, so the int(length) conversion in handlePost is provably bounded.
const maxBodyHardLimit = 1 << 30 // 1 GiB

func (s *Server) handlePost(w http.ResponseWriter, r *http.Request) {
	// Auth: fail closed if no token is configured (503), reject a wrong/absent
	// token (401). The backend never runs unauthenticated.
	ok, configured := s.authed(r)
	if !configured {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gozer token not configured"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	path := r.URL.Path
	s.metrics.incPath(path)

	// Validate the declared length cheaply (no read yet) — reject anything
	// missing, non-positive, or over the body cap. The constant ceiling also
	// lets the static analyzer prove the int(length) conversion below cannot
	// overflow on a 32-bit build (MaxBody is far smaller, but it is a variable).
	length, err := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)
	if err != nil || length <= 0 || length > s.cfg.MaxBody || length > maxBodyHardLimit {
		s.metrics.inc(&s.metrics.errorTotal)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad length"})
		return
	}

	// Acquire a concurrency slot BEFORE buffering the (up to MaxBody) body, so a
	// burst of large uploads cannot hold unbounded goroutines/memory while never
	// consuming a slot. Each request opens razor/pyzor/DCC sockets downstream.
	if !s.acquire() {
		s.metrics.inc(&s.metrics.busyTotal)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "busy"})
		s.errf("%s 503 busy (max_concurrent=%d reached)", path, s.cfg.MaxConcurrent)
		return
	}
	defer func() { <-s.sem }()

	msg := make([]byte, int(length))
	if _, err := io.ReadFull(r.Body, msg); err != nil {
		s.metrics.inc(&s.metrics.errorTotal)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read error"})
		return
	}
	t0 := time.Now()
	defer s.metrics.observeSince(t0)

	// /check is a cacheable idempotent query; /report and /revoke never cache and
	// invalidate any cached /check verdict for the same message.
	var cacheKey string
	if s.cache != nil {
		cacheKey = sha256key(msg)
	}
	var body []byte
	cacheStatus := ""
	if path == "/check" && cacheKey != "" {
		if hit, found := s.cache.Get(cacheKey); found {
			s.metrics.inc(&s.metrics.cacheHit)
			body = hit
			cacheStatus = "hit"
		} else {
			result, shared := s.flights.Do(cacheKey, func() flightResult {
				// A leader may have populated the cache between the first lookup
				// and registering this flight.
				if hit, found := s.cache.Get(cacheKey); found {
					return flightResult{body: hit, fromCache: true}
				}
				s.metrics.inc(&s.metrics.cacheMiss)
				epoch := s.epochs[cacheKey[0]].Load()
				computed, cacheable := s.dispatch(path, msg)
				if cacheable && s.epochs[cacheKey[0]].Load() == epoch {
					s.cache.Put(cacheKey, computed)
				}
				return flightResult{body: computed}
			})
			body = result.body
			if shared {
				s.metrics.inc(&s.metrics.cacheCoalesced)
				cacheStatus = "coalesced"
			} else if result.fromCache {
				s.metrics.inc(&s.metrics.cacheHit)
				cacheStatus = "hit"
			} else {
				cacheStatus = "miss"
			}
		}
	} else {
		if cacheKey != "" {
			s.epochs[cacheKey[0]].Add(1)
		}
		body, _ = s.dispatch(path, msg)
	}
	if (path == "/report" || path == "/revoke") && cacheKey != "" {
		// the message's spam status just changed — drop the stale /check verdict
		// and prevent an older in-flight check from repopulating it afterward.
		s.epochs[cacheKey[0]].Add(1)
		s.cache.Delete(cacheKey)
	}
	if cacheStatus == "hit" || cacheStatus == "coalesced" {
		w.Header().Set("X-DRP-Cache", cacheStatus)
	}
	writeRaw(w, http.StatusOK, "application/json", body)

	if path == "/check" {
		s.vlogf("/check %dB cache=%s %.1fms -> %s", len(msg), cacheStatus, msSince(t0), body) // high volume
	} else {
		// /report + /revoke are rare feedback actions — always log (audit trail).
		s.logf("%s %dB %.1fms -> %s", path, len(msg), msSince(t0), body)
	}
}

func (s *Server) acquire() bool {
	select {
	case s.sem <- struct{}{}:
		return true
	default:
	}
	timer := time.NewTimer(s.cfg.BackendTimeout)
	defer timer.Stop()
	select {
	case s.sem <- struct{}{}:
		return true
	case <-timer.C:
		return false
	}
}

// dispatch runs the backend for path and marshals the verdict. It never lets a
// backend panic reach the caller: on panic it logs and returns safe defaults
// (the rspamd plugin must never see a 500).
func (s *Server) dispatch(path string, msg []byte) (body []byte, cacheable bool) {
	defer func() {
		if rec := recover(); rec != nil {
			s.errf("%s backend panic: %v", path, rec)
			body = defaultJSON(path)
			cacheable = false
		}
	}()
	var v any
	switch path {
	case "/check":
		v, cacheable = s.engine.Check(msg)
	case "/report":
		v = s.engine.Report(msg)
	case "/revoke":
		v = s.engine.Revoke(msg)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return defaultJSON(path), false
	}
	return b, cacheable
}

func defaultJSON(path string) []byte {
	var b []byte
	if path == "/check" {
		b, _ = json.Marshal(DefaultVerdict())
	} else {
		b, _ = json.Marshal(DefaultReport())
	}
	return b
}

// authed validates the shared secret. configured is false when no token is set
// (caller returns 503); ok is the constant-time comparison result.
func (s *Server) authed(r *http.Request) (ok, configured bool) {
	if s.cfg.Token == "" {
		return false, false
	}
	presented := ""
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		presented = strings.TrimSpace(a[len("Bearer "):])
	} else {
		presented = strings.TrimSpace(r.Header.Get("X-DRP-Token"))
	}
	return hmac.Equal([]byte(presented), []byte(s.cfg.Token)), true
}

// --- response helpers ---

func writeText(w http.ResponseWriter, code int, body string) {
	writeRaw(w, code, "text/plain", []byte(body))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"error":"internal"}`)
	}
	writeRaw(w, code, "application/json", b)
}

func writeRaw(w http.ResponseWriter, code int, ctype string, body []byte) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(code)
	_, _ = w.Write(body) // #nosec G705 -- application/json (or text/plain) API response, not an HTML/XSS sink
}

func sha256key(b []byte) string {
	sum := sha256.Sum256(b)
	return string(sum[:])
}

func msSince(t time.Time) float64 { return float64(time.Since(t).Microseconds()) / 1000 }
