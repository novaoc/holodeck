// holodeck — Vela's demo sandbox. Hosts throwaway apps and wipes the whole
// deck once a day. Two kinds of app:
//
//   - static: a bundle with an index.html, served straight from disk.
//   - container: a bundle with a Dockerfile — holodeck builds the image and
//     runs it in a locked-down container, reverse-proxying the app's subdomain
//     to it. This is how "any kind of app" (Node, Python, Go, …) runs while
//     staying boxed in.
//
// Every app is deleted at the daily wipe (03:00 America/Mexico_City by
// default); the GitHub repo is the permanent copy. holodeck sits behind Caddy
// (on-demand TLS gated by /api/tls-check) and is the single ingress — it routes
// each <slug>.<domain> to the right app.
//
// PROVENANCE. Vela is the only thing allowed to deploy. Beyond the bearer
// token, every deploy must carry an HMAC signature of its body made with a
// shared build secret (X-Holodeck-Sign) — so a deploy is cryptographically
// proven to come from Vela's own build pipeline, not from someone replaying the
// endpoint or hosting an arbitrary external repo. A missing or wrong signature
// is refused.
//
// SECURITY POSTURE for the container path (it runs code Vela wrote):
//   - each app in its own container: cap-drop ALL, no-new-privileges, hard
//     memory / CPU / pids caps, and an INTERNAL docker network with NO internet
//     egress (deps are fetched at build time, not run time).
//   - holodeck only ever touches docker resources it labels holodeck=1 or names
//     holodeck-app-* — it never stops, removes, or inspects anything else on
//     the host (this box also runs other production containers).
//   - a hard cap on concurrent apps bounds total load on the shared box.
//
// Residual risk is real: a container is a limit, not a perfect boundary, and
// build steps run arbitrary code. This is a hobby demo deck on a private
// Discord, sized accordingly — not a multi-tenant PaaS.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // embed zoneinfo so America/Mexico_City resolves on alpine
)

const (
	maxBody    = 40 << 20
	maxFiles   = 300
	maxTotal   = 32 << 20
	sweepEvery = 15 * time.Minute
	slotIdle   = 15 * time.Minute // an app idle this long can lose its slot — but only when someone else needs it
)

var slugRe = regexp.MustCompile(`[^a-z0-9-]+`)
var exposeRe = regexp.MustCompile(`(?mi)^\s*EXPOSE\s+(\d+)`)

type server struct {
	data      string
	token     string
	buildKey  []byte // HMAC provenance secret
	domain    string
	loc       *time.Location
	wipeHour  int
	net       string
	mem, cpus string
	pids      string
	maxApps   int
	buildTO   time.Duration
	proxies   sync.Map
	activity  sync.Map // slug -> time.Time of last request (slot-eviction LRU)
	deployMu  sync.Mutex
}

type deployReq struct {
	Name  string `json:"name"`
	Port  int    `json:"port"`
	Files []struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	} `json:"files"`
}

type meta struct {
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Kind      string    `json:"kind"`
	State     string    `json:"state"` // running | sleeping (container apps; slot given away)
	Port      int       `json:"port"`
	Container string    `json:"container"`
	Image     string    `json:"image"`
	Created   time.Time `json:"created"`
}

func main() {
	s := &server{
		data:     envOr("HOLODECK_DATA", "/srv/holodeck"),
		token:    os.Getenv("HOLODECK_TOKEN"),
		buildKey: []byte(os.Getenv("HOLODECK_BUILD_SECRET")),
		domain:   envOr("HOLODECK_DOMAIN", "demo.holode.xyz"),
		wipeHour: atoiOr(os.Getenv("HOLODECK_WIPE_HOUR"), 3),
		net:      envOr("HOLODECK_NET", "holodeck-net"),
		mem:      envOr("HOLODECK_MEM", "512m"),
		cpus:     envOr("HOLODECK_CPUS", "0.5"),
		pids:     envOr("HOLODECK_PIDS", "256"),
		maxApps:  atoiOr(os.Getenv("HOLODECK_MAX_APPS"), 15),
		buildTO:  time.Duration(atoiOr(os.Getenv("HOLODECK_BUILD_TIMEOUT_S"), 300)) * time.Second,
	}
	if s.token == "" || len(s.buildKey) == 0 {
		log.Fatal("HOLODECK_TOKEN and HOLODECK_BUILD_SECRET are required")
	}
	loc, err := time.LoadLocation(envOr("HOLODECK_TZ", "America/Mexico_City"))
	if err != nil {
		log.Fatalf("bad HOLODECK_TZ: %v", err)
	}
	s.loc = loc
	if err := os.MkdirAll(filepath.Join(s.data, "apps"), 0o755); err != nil {
		log.Fatal(err)
	}
	go s.dailyWipe()
	go s.sweep() // backstop if a scheduled wipe was missed (box down at 3am)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/deploy", s.auth(s.handleDeploy))
	mux.HandleFunc("GET /api/apps", s.auth(s.handleList))
	mux.HandleFunc("DELETE /api/apps/{slug}", s.auth(s.handleDelete))
	mux.HandleFunc("GET /api/tls-check", s.handleTLSCheck)
	mux.HandleFunc("/", s.handleServe)

	addr := envOr("HOLODECK_ADDR", ":8700")
	log.Printf("holodeck up on %s — apps at *.%s, daily wipe %02d:00 %s, caps mem=%s cpus=%s",
		addr, s.domain, s.wipeHour, s.loc, s.mem, s.cpus)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func slugify(name string) string {
	base := slugRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	base = strings.Trim(base, "-")
	if len(base) > 30 {
		base = base[:30]
	}
	if base == "" {
		base = "app"
	}
	b := make([]byte, 2)
	_, _ = rand.Read(b)
	return base + "-" + hex.EncodeToString(b)
}

func cleanPath(p string) (string, bool) {
	p = filepath.ToSlash(filepath.Clean("/" + p))[1:]
	if p == "" || strings.HasPrefix(p, ".") || strings.Contains(p, "/.") || len(p) > 250 {
		return "", false
	}
	return p, true
}

// verifySig checks the provenance HMAC: hex(hmac-sha256(buildKey, body)) in the
// X-Holodeck-Sign header. Proves the deploy came from Vela's pipeline and that
// the body wasn't altered in flight.
func (s *server) verifySig(body []byte, header string) bool {
	want := hmac.New(sha256.New, s.buildKey)
	want.Write(body)
	got, err := hex.DecodeString(strings.TrimSpace(header))
	if err != nil {
		return false
	}
	return hmac.Equal(got, want.Sum(nil))
}

func (s *server) handleDeploy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "body too large or unreadable", http.StatusBadRequest)
		return
	}
	if !s.verifySig(body, r.Header.Get("X-Holodeck-Sign")) {
		http.Error(w, "unsigned deploy refused — holodeck only accepts apps signed by Vela's own build pipeline", http.StatusForbidden)
		return
	}
	var req deployReq
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Files) == 0 || len(req.Files) > maxFiles {
		http.Error(w, fmt.Sprintf("need 1-%d files", maxFiles), http.StatusBadRequest)
		return
	}
	hasIndex, hasDockerfile, total := false, false, 0
	var dockerfile string
	for _, f := range req.Files {
		p, ok := cleanPath(f.Path)
		if !ok {
			http.Error(w, "bad path: "+f.Path, http.StatusBadRequest)
			return
		}
		switch p {
		case "index.html":
			hasIndex = true
		case "Dockerfile":
			hasDockerfile = true
			dockerfile = f.Content
		}
		total += len(f.Content)
	}
	if total > maxTotal {
		http.Error(w, "app too large (32MB source cap)", http.StatusBadRequest)
		return
	}
	if !hasDockerfile && !hasIndex {
		http.Error(w, "include a Dockerfile (to run an app) or an index.html (static site)", http.StatusBadRequest)
		return
	}

	slug := slugify(req.Name)
	src := filepath.Join(s.data, "apps", slug, "src")
	for _, f := range req.Files {
		p, _ := cleanPath(f.Path)
		full := filepath.Join(src, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(full, []byte(f.Content), 0o644); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	m := meta{Name: req.Name, Slug: slug, Created: time.Now().UTC(), State: "running"}
	if hasDockerfile {
		m.Kind = "container"
		m.Port = req.Port
		if m.Port == 0 {
			if mt := exposeRe.FindStringSubmatch(dockerfile); mt != nil {
				m.Port, _ = strconv.Atoi(mt[1])
			}
		}
		if m.Port == 0 {
			m.Port = 8080
		}
		m.Image = "holodeck/" + slug + ":latest"
		m.Container = "holodeck-app-" + slug
		if err := s.buildAndRun(&m, src); err != nil {
			_ = os.RemoveAll(filepath.Join(s.data, "apps", slug))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		m.Kind = "static"
	}
	s.writeMeta(m)
	s.activity.Store(slug, time.Now()) // a fresh deploy holds its slot
	log.Printf("deployed %s (%s, %dKB)", slug, m.Kind, total/1024)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"url":     fmt.Sprintf("https://%s.%s/", slug, s.domain),
		"slug":    slug,
		"kind":    m.Kind,
		"expires": s.nextWipe().Format(time.RFC3339),
	})
}

func (s *server) buildAndRun(m *meta, src string) error {
	// Slot discipline: one running container app = one slot. When every slot
	// is taken, an app that's had no traffic for slotIdle gets put to sleep to
	// make room (LRU); if everyone's active, the deploy waits its turn. Idle
	// apps are never touched unless a slot is actually needed.
	s.deployMu.Lock()
	err := s.freeSlot()
	s.deployMu.Unlock()
	if err != nil {
		return err
	}
	bctx, bcancel := context.WithTimeout(context.Background(), s.buildTO)
	defer bcancel()
	if out, err := dockerOut(bctx, "build", "--label", "holodeck=1", "-t", m.Image, src); err != nil {
		if bctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("build timed out after %s", s.buildTO)
		}
		return fmt.Errorf("build failed:\n%s", tail(out, 1500))
	}
	s.stopContainer(m.Container)
	rctx, rcancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer rcancel()
	args := []string{
		"run", "-d",
		"--name", m.Container,
		"--label", "holodeck=1",
		"--network", s.net,
		"--memory", s.mem, "--memory-swap", s.mem,
		"--cpus", s.cpus,
		"--pids-limit", s.pids,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--restart", "unless-stopped",
		m.Image,
	}
	if out, err := dockerOut(rctx, args...); err != nil {
		return fmt.Errorf("couldn't start the app: %s", tail(out, 800))
	}
	s.waitReady(m)
	return nil
}

func (s *server) waitReady(m *meta) {
	target := fmt.Sprintf("http://%s:%d/", m.Container, m.Port)
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := client.Get(target); err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(time.Second)
	}
	log.Printf("app %s not responding on :%d yet (may still be booting)", m.Slug, m.Port)
}

func (s *server) handleList(w http.ResponseWriter, r *http.Request) {
	out := []meta{}
	out = append(out, s.allMeta()...)
	_ = json.NewEncoder(w).Encode(out)
}

func (s *server) handleDelete(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" || slugRe.MatchString(slug) || strings.Contains(slug, "/") {
		http.Error(w, "bad slug", http.StatusBadRequest)
		return
	}
	s.destroy(slug)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleTLSCheck(w http.ResponseWriter, r *http.Request) {
	d := strings.ToLower(r.URL.Query().Get("domain"))
	if d == s.domain {
		return
	}
	if slug, ok := strings.CutSuffix(d, "."+s.domain); ok && !strings.Contains(slug, ".") {
		if st, err := os.Stat(filepath.Join(s.data, "apps", slug)); err == nil && st.IsDir() {
			return
		}
	}
	http.Error(w, "unknown host", http.StatusForbidden)
}

func (s *server) handleServe(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(strings.Split(r.Host, ":")[0])
	w.Header().Set("X-Robots-Tag", "noindex")
	if host == s.domain || (host != "" && !strings.HasSuffix(host, "."+s.domain)) {
		s.landing(w, r)
		return
	}
	slug := strings.TrimSuffix(host, "."+s.domain)
	m, ok := s.readMeta(slug)
	if !ok {
		http.Error(w, "this holodeck program has ended (the deck wipes daily)", http.StatusNotFound)
		return
	}
	s.activity.Store(slug, time.Now()) // slot LRU: any visit counts as activity
	if m.Kind == "container" {
		if m.State == "sleeping" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><title>asleep</title>
<style>body{font-family:system-ui;background:#0A0D13;color:#F5F6F8;display:grid;place-items:center;min-height:100vh;margin:0}main{text-align:center;line-height:1.7}</style>
<main><p>this demo was put to sleep to free a slot for a newer one.</p>
<p>ask Vela to deploy it again if you still need it.</p></main>`)
			return
		}
		s.proxyTo(m).ServeHTTP(w, r)
		return
	}
	s.serveStatic(w, r, slug)
}

func (s *server) proxyTo(m meta) *httputil.ReverseProxy {
	if p, ok := s.proxies.Load(m.Slug); ok {
		return p.(*httputil.ReverseProxy)
	}
	target, _ := url.Parse(fmt.Sprintf("http://%s:%d", m.Container, m.Port))
	p := httputil.NewSingleHostReverseProxy(target)
	p.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><title>starting…</title>
<style>body{font-family:system-ui;background:#0A0D13;color:#F5F6F8;display:grid;place-items:center;min-height:100vh;margin:0}</style>
<p>this app is starting up (or just crashed) — refresh in a few seconds.</p>`)
	}
	s.proxies.Store(m.Slug, p)
	return p
}

func (s *server) serveStatic(w http.ResponseWriter, r *http.Request, slug string) {
	dir := filepath.Join(s.data, "apps", slug, "src")
	p, ok := cleanPath(strings.TrimPrefix(r.URL.Path, "/"))
	if !ok && strings.TrimPrefix(r.URL.Path, "/") != "" {
		http.NotFound(w, r)
		return
	}
	full := filepath.Join(dir, filepath.FromSlash(p))
	if st, err := os.Stat(full); err != nil || st.IsDir() {
		full = filepath.Join(full, "index.html")
		if _, err := os.Stat(full); err != nil {
			http.NotFound(w, r)
			return
		}
	}
	http.ServeFile(w, r, full)
}

func (s *server) landing(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>holodeck</title>
<style>body{font-family:system-ui;background:#0A0D13;color:#F5F6F8;display:grid;place-items:center;min-height:100vh;margin:0}main{text-align:center;line-height:1.7}small{color:#8b93a3}</style>
<main><h1>holodeck</h1><p>Vela's demo deck — ask her to build something and put it online.</p>
<small>the whole deck wipes at %02d:00 %s daily · the repo is the keepsake</small></main>`, s.wipeHour, s.loc)
}

// ── metadata + lifecycle ────────────────────────────────────────────────

func (s *server) metaPath(slug string) string {
	return filepath.Join(s.data, "apps", slug, "meta.json")
}

func (s *server) writeMeta(m meta) {
	if b, err := json.Marshal(m); err == nil {
		_ = os.WriteFile(s.metaPath(m.Slug), b, 0o644)
	}
}

func (s *server) readMeta(slug string) (meta, bool) {
	var m meta
	b, err := os.ReadFile(s.metaPath(slug))
	if err != nil {
		return m, false
	}
	if json.Unmarshal(b, &m) != nil {
		return m, false
	}
	if m.Created.IsZero() {
		if st, err := os.Stat(filepath.Join(s.data, "apps", slug)); err == nil {
			m.Created = st.ModTime()
		}
	}
	return m, true
}

func (s *server) allMeta() []meta {
	entries, _ := os.ReadDir(filepath.Join(s.data, "apps"))
	var out []meta
	for _, e := range entries {
		if e.IsDir() {
			if m, ok := s.readMeta(e.Name()); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

func (s *server) runningCount() int {
	n := 0
	for _, m := range s.allMeta() {
		if m.Kind == "container" && m.State == "running" {
			n++
		}
	}
	return n
}

// lastActive is when a slug last saw a request (deploy time counts as active;
// after a holodeck restart, boot time stands in so fresh idleness is measured).
func (s *server) lastActive(m meta) time.Time {
	if t, ok := s.activity.Load(m.Slug); ok {
		return t.(time.Time)
	}
	return m.Created
}

// freeSlot makes room for one more running container app. If slots remain,
// no-op. Otherwise the LEAST recently used app that's been idle over slotIdle
// is put to sleep — container and image removed, files and page kept, its URL
// explains what happened. If every app saw traffic within slotIdle, the deploy
// is refused instead: nobody actively working loses their demo.
func (s *server) freeSlot() error {
	if s.runningCount() < s.maxApps {
		return nil
	}
	var victim *meta
	var victimAt time.Time
	for _, m := range s.allMeta() {
		if m.Kind != "container" || m.State != "running" {
			continue
		}
		at := s.lastActive(m)
		if time.Since(at) < slotIdle {
			continue
		}
		if victim == nil || at.Before(victimAt) {
			mm := m
			victim, victimAt = &mm, at
		}
	}
	if victim == nil {
		return fmt.Errorf("the deck is full (%d/%d slots) and every app is actively in use — try again in a few minutes", s.maxApps, s.maxApps)
	}
	s.stopContainer(victim.Container)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	_, _ = dockerOut(ctx, "rmi", "-f", victim.Image)
	cancel()
	s.proxies.Delete(victim.Slug)
	victim.State = "sleeping"
	s.writeMeta(*victim)
	log.Printf("slot freed: %s put to sleep (idle %s)", victim.Slug, time.Since(victimAt).Round(time.Minute))
	return nil
}

func (s *server) destroy(slug string) {
	if m, ok := s.readMeta(slug); ok && m.Kind == "container" {
		s.stopContainer(m.Container)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, _ = dockerOut(ctx, "rmi", "-f", m.Image)
		cancel()
	}
	s.proxies.Delete(slug)
	_ = os.RemoveAll(filepath.Join(s.data, "apps", slug))
	log.Printf("destroyed %s", slug)
}

// stopContainer never touches anything not named holodeck-app-* — critical on a
// box shared with production.
func (s *server) stopContainer(name string) {
	if name == "" || !strings.HasPrefix(name, "holodeck-app-") {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = dockerOut(ctx, "rm", "-f", name)
}

// nextWipe is the next daily wipe instant in the configured timezone.
func (s *server) nextWipe() time.Time {
	now := time.Now().In(s.loc)
	next := time.Date(now.Year(), now.Month(), now.Day(), s.wipeHour, 0, 0, 0, s.loc)
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next
}

// dailyWipe deletes EVERY app at the configured hour, each day.
func (s *server) dailyWipe() {
	for {
		time.Sleep(time.Until(s.nextWipe()))
		apps := s.allMeta()
		log.Printf("daily wipe — clearing %d app(s)", len(apps))
		for _, m := range apps {
			s.destroy(m.Slug)
		}
	}
}

// sweep is the backstop: if the box was down at the wipe hour, clear anything
// that outlived a full day so nothing lingers indefinitely.
func (s *server) sweep() {
	for {
		time.Sleep(sweepEvery)
		for _, m := range s.allMeta() {
			if time.Since(m.Created) > 25*time.Hour {
				s.destroy(m.Slug)
			}
		}
	}
}

// ── docker helpers ──────────────────────────────────────────────────────

func dockerOut(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return string(out), err
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
