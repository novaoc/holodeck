package main

// Async verification and reference deploys.
//
// The synchronous /api/verify holds one HTTP connection for the whole Docker
// build — up to 15 minutes — which forced Vela's board to babysit a socket
// and burn agent-turn budget doing nothing. The job API splits that:
//
//	POST /api/verify/ref    signed {repo, sha, …, exp}  → 202 {job_id}
//	GET  /api/jobs/{id}                                 → state / receipt / logs
//	POST /api/deploy/ref    signed {repo, sha, …} + receipt → live URL
//
// Holodex fetches the public GitHub archive for the SHA itself, so what gets
// verified and deployed is structurally what the public repo shows — no
// client upload to trust, and no tarball squeezed twice through a 256 MB
// board. The verified tarball is retained (keyed by job) for the receipt's
// lifetime so the deploy needs no second fetch.
//
// Signatures use the same shared build secret as archive uploads, over the
// canonical below. The exp field bounds replay: a captured request dies with
// its expiry instead of living forever like a signed byte-stream would.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	refCanonicalPrefix = "holodex-ref-v1"
	// Fetch bounds: a source tarball for a generated app is well under a
	// megabyte; anything near the archive cap is suspicious but allowed.
	refFetchTimeout = 2 * time.Minute
	// Retained jobs (and their tarballs) die with their receipts.
	jobTTL = verifyReceiptTTL + 10*time.Minute
)

var (
	repoRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
	shaRe  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func timeoutContext(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// refParams is a signed reference to a public GitHub commit.
type refParams struct {
	Action     string // verify | deploy
	Repo       string // owner/name
	SHA        string // full 40-hex commit
	Name       string
	Target     string
	Dockerfile string
	Port       int
	Exp        int64 // unix seconds; the signature dies here
}

func (p refParams) canonical() string {
	return strings.Join([]string{
		refCanonicalPrefix, p.Action, p.Repo, p.SHA, p.Name, p.Target,
		p.Dockerfile, strconv.Itoa(p.Port), strconv.FormatInt(p.Exp, 10), "",
	}, "\n")
}

func signRef(key []byte, p refParams) string {
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, p.canonical())
	return hex.EncodeToString(mac.Sum(nil))
}

// refParamsFromRequest parses and validates the X-Holodex-* reference headers
// including the signature. Reference requests use only the new header family —
// there is no legacy client to honour on a path that never existed before.
func refParamsFromRequest(r *http.Request, key []byte, action string) (refParams, error) {
	p, err := refFieldsFromRequest(r, action)
	if err != nil {
		return refParams{}, err
	}
	want, err := hex.DecodeString(strings.TrimSpace(r.Header.Get("X-Holodex-Sign")))
	if err != nil {
		return refParams{}, errors.New("bad X-Holodex-Sign")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, p.canonical())
	if subtle.ConstantTimeCompare(want, mac.Sum(nil)) != 1 {
		return refParams{}, errors.New("unsigned reference refused")
	}
	return p, nil
}

// refFieldsFromRequest parses and validates the reference fields without any
// authorization decision — callers add either the per-request signature
// (refParamsFromRequest) or a ticket (handleRefVerify).
func refFieldsFromRequest(r *http.Request, action string) (refParams, error) {
	h := func(name string) string { return strings.TrimSpace(r.Header.Get(name)) }
	port := 0
	if v := h("X-Holodex-Port"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 65535 {
			return refParams{}, errors.New("bad X-Holodex-Port")
		}
		port = n
	}
	exp, err := strconv.ParseInt(h("X-Holodex-Exp"), 10, 64)
	if err != nil {
		return refParams{}, errors.New("bad or missing X-Holodex-Exp")
	}
	p := refParams{
		Action:     action,
		Repo:       h("X-Holodex-Repo"),
		SHA:        strings.ToLower(h("X-Holodex-Sha")),
		Name:       h("X-Holodex-Name"),
		Target:     h("X-Holodex-Target"),
		Dockerfile: h("X-Holodex-Dockerfile"),
		Port:       port,
		Exp:        exp,
	}
	if p.Dockerfile == "" {
		p.Dockerfile = "Dockerfile"
	}
	if !repoRe.MatchString(p.Repo) {
		return refParams{}, errors.New("bad X-Holodex-Repo (owner/name)")
	}
	if !shaRe.MatchString(p.SHA) {
		return refParams{}, errors.New("bad X-Holodex-Sha (full 40-hex commit)")
	}
	// Every field entering canonical() must be provably newline-free and in
	// normal form, or two different header tuples could share one canonical
	// string — and therefore one signature. Go's HTTP layer already rejects
	// raw CR/LF in header values; this must not depend on that.
	if p.Name == "" || len(p.Name) > 100 || strings.ContainsAny(p.Name, "\r\n") {
		return refParams{}, errors.New("missing X-Holodex-Name (max 100 chars, no newlines)")
	}
	if p.Target != "" && !buildTargetRe.MatchString(p.Target) {
		return refParams{}, errors.New("bad X-Holodex-Target")
	}
	if clean, ok := cleanArchivePath(p.Dockerfile); !ok || clean != p.Dockerfile || strings.ContainsAny(p.Dockerfile, "\r\n") {
		return refParams{}, errors.New("bad X-Holodex-Dockerfile (must be a clean relative path)")
	}
	now := time.Now().Unix()
	if p.Exp < now {
		return refParams{}, errors.New("signature expired")
	}
	if p.Exp > now+3700 {
		return refParams{}, errors.New("expiry too far out (max ~1h)")
	}
	return p, nil
}

// fetchGitHubArchive downloads the public commit tarball for repo@sha to
// destDir, returning the file path and its sha256. Public repos only — this
// host deliberately holds no GitHub credentials.
func (s *server) fetchGitHubArchive(repo, sha, destDir string) (string, string, error) {
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return "", "", err
	}
	f, err := os.CreateTemp(destDir, "ref-*.tar.gz")
	if err != nil {
		return "", "", err
	}
	name := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()

	url := fmt.Sprintf("https://codeload.github.com/%s/tar.gz/%s", repo, sha)
	ctx, cancel := timeoutContext(refFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("github fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("github returned %d for %s@%s (private repos cannot use the reference path)", resp.StatusCode, repo, sha[:12])
	}

	digest := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, digest), io.LimitReader(resp.Body, maxArchiveBody+1))
	if err != nil {
		return "", "", err
	}
	if n == 0 {
		return "", "", errors.New("github returned an empty archive")
	}
	if n > maxArchiveBody {
		return "", "", errors.New("archive exceeds the size cap")
	}
	if err := f.Sync(); err != nil {
		return "", "", err
	}
	ok = true
	return name, hex.EncodeToString(digest.Sum(nil)), nil
}

// verifyJob is one queued/running/finished verification.
type verifyJob struct {
	ID      string         `json:"id"`
	Repo    string         `json:"repo"`
	SHA     string         `json:"sha"`
	Name    string         `json:"name"`
	State   string         `json:"state"` // queued | running | done
	Result  map[string]any `json:"result,omitempty"`
	Created time.Time      `json:"created"`

	archive string // retained tarball for the deploy step
	digest  string
	done    time.Time
}

type jobStore struct {
	mu   sync.Mutex
	jobs map[string]*verifyJob
	// seenSigs makes every reference signature single-use: a captured
	// request cannot be replayed inside its expiry window, and an
	// accidentally re-POSTed verify maps back to its original job instead
	// of spawning a second build. Values are the signature's expiry.
	seenSigs map[string]sigUse
	// ticketUses counts verifications spent per worker-job ticket.
	ticketUses map[string]int
	// usedDeployTickets enforces one deploy per deploy ticket.
	usedDeployTickets map[string]bool
}

type sigUse struct {
	jobID string
	exp   int64
}

// maxActiveRefJobs bounds concurrent fetch+verify goroutines. Builds are
// serialized by buildMu anyway; this stops a queue from piling up disk and
// goroutines behind it.
const maxActiveRefJobs = 8

func newJobStore() *jobStore {
	return &jobStore{jobs: map[string]*verifyJob{}, seenSigs: map[string]sigUse{}}
}

// claimSig records a signature's first use. The second caller gets the
// original job's id back instead of a new job.
func (js *jobStore) claimSig(sig, jobID string, exp int64) (string, bool) {
	js.mu.Lock()
	defer js.mu.Unlock()
	if prior, ok := js.seenSigs[sig]; ok {
		return prior.jobID, false
	}
	js.seenSigs[sig] = sigUse{jobID: jobID, exp: exp}
	return jobID, true
}

func (js *jobStore) active() int {
	js.mu.Lock()
	defer js.mu.Unlock()
	n := 0
	for _, j := range js.jobs {
		if j.State != "done" {
			n++
		}
	}
	return n
}

func newJobID() string {
	b := make([]byte, 9)
	if _, err := rand.Read(b); err != nil {
		panic("holodex: no entropy: " + err.Error())
	}
	return "job-" + hex.EncodeToString(b)
}

func (js *jobStore) put(j *verifyJob) {
	js.mu.Lock()
	defer js.mu.Unlock()
	js.jobs[j.ID] = j
}

func (js *jobStore) get(id string) (*verifyJob, bool) {
	js.mu.Lock()
	defer js.mu.Unlock()
	j, ok := js.jobs[id]
	return j, ok
}

// finish records the outcome; expired jobs are swept by gc.
func (js *jobStore) finish(id string, result map[string]any) {
	js.mu.Lock()
	defer js.mu.Unlock()
	if j, ok := js.jobs[id]; ok {
		j.State = "done"
		j.Result = result
		j.done = time.Now()
	}
}

// gc removes finished jobs (and their retained tarballs) once their receipts
// cannot be used any more, and abandoned jobs after a generous multiple of
// the verify timeout.
func (js *jobStore) gc(now time.Time) {
	js.mu.Lock()
	defer js.mu.Unlock()
	for id, j := range js.jobs {
		expired := (j.State == "done" && now.Sub(j.done) > jobTTL) ||
			(j.State != "done" && now.Sub(j.Created) > 4*time.Hour)
		if expired {
			if j.archive != "" {
				_ = os.Remove(j.archive)
			}
			delete(js.jobs, id)
		}
	}
	for sig, use := range js.seenSigs {
		if use.exp < now.Unix() {
			delete(js.seenSigs, sig)
		}
	}
}

// handleRefVerify accepts a signed {repo, sha} reference, fetches the public
// archive itself, and verifies it asynchronously. 202 + job id immediately.
// Authorization is either the per-request build-secret signature (Vela) or a
// budgeted job ticket (the build worker).
func (s *server) handleRefVerify(w http.ResponseWriter, r *http.Request) {
	var p refParams
	var err error
	if rawTicket := strings.TrimSpace(r.Header.Get("X-Holodex-Ticket")); rawTicket != "" {
		t, terr := parseTicketHeader(rawTicket, s.buildKey, time.Now())
		if terr != nil {
			http.Error(w, terr.Error(), http.StatusForbidden)
			return
		}
		p, err = refFieldsFromRequest(r, "verify")
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if p.Repo != t.Repo {
			http.Error(w, "ticket is for a different repository", http.StatusForbidden)
			return
		}
		if err := s.jobs.spendTicketUse(t); err != nil {
			http.Error(w, err.Error(), http.StatusTooManyRequests)
			return
		}
		log.Printf("ticket verify %s@%s job=%s", t.Repo, p.SHA[:12], t.Job)
	} else if p, err = refParamsFromRequest(r, s.buildKey, "verify"); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if p.Target == "" {
		p.Target = "test"
	}
	if s.jobs.active() >= maxActiveRefJobs {
		http.Error(w, "verification queue is full — try again in a minute", http.StatusServiceUnavailable)
		return
	}

	job := &verifyJob{
		ID: newJobID(), Repo: p.Repo, SHA: p.SHA, Name: p.Name,
		State: "queued", Created: time.Now(),
	}
	// Single-use signatures: a re-POST of the same signed request (retry or
	// replay) is answered with the original job instead of a second build.
	// Ticket-authorized requests carry no per-request signature — their
	// replay bound is the ticket's verify budget instead.
	if sig := strings.TrimSpace(r.Header.Get("X-Holodex-Sign")); sig != "" {
		if priorID, fresh := s.jobs.claimSig(sig, job.ID, p.Exp); !fresh {
			writeJSON(w, http.StatusAccepted, map[string]any{"job_id": priorID, "state": "queued", "replayed": true})
			return
		}
	}
	s.jobs.put(job)

	go func() {
		s.jobs.mu.Lock()
		job.State = "running"
		s.jobs.mu.Unlock()

		dir := filepath.Join(s.data, "jobs", "refs")
		fetch := s.fetchRef
		if fetch == nil {
			fetch = s.fetchGitHubArchive
		}
		archive, digest, err := fetch(p.Repo, p.SHA, dir)
		if err != nil {
			s.jobs.finish(job.ID, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		ap := archiveParams{
			Action: "verify", Name: p.Name, Target: p.Target,
			Dockerfile: p.Dockerfile, Port: p.Port,
		}
		_, body := s.verifyArchive(ap, archive, digest)
		if ok, _ := body["ok"].(bool); ok {
			// Retain the exact verified bytes for the deploy step.
			s.jobs.mu.Lock()
			job.archive, job.digest = archive, digest
			s.jobs.mu.Unlock()
			body["sha"] = p.SHA
		} else {
			_ = os.Remove(archive)
		}
		s.jobs.finish(job.ID, body)
	}()

	log.Printf("ref verify queued %s@%s as %s", p.Repo, p.SHA[:12], job.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{"job_id": job.ID, "state": "queued"})
}

// handleJobStatus reports a job. The result object is exactly what the
// synchronous endpoint would have returned, so clients share a parser.
func (s *server) handleJobStatus(w http.ResponseWriter, r *http.Request) {
	job, ok := s.jobs.get(r.PathValue("id"))
	if !ok {
		http.Error(w, "no such job (finished jobs expire with their receipts)", http.StatusNotFound)
		return
	}
	s.jobs.mu.Lock()
	out := map[string]any{
		"id": job.ID, "repo": job.Repo, "sha": job.SHA, "name": job.Name,
		"state": job.State, "created": job.Created.Format(time.RFC3339),
	}
	if job.State == "done" {
		out["result"] = job.Result
	}
	s.jobs.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

// handleRefDeploy deploys the retained archive of a passed reference job. The
// receipt must match the retained bytes' digest — the same gate as an upload
// deploy, minus the upload.
func (s *server) handleRefDeploy(w http.ResponseWriter, r *http.Request) {
	var p refParams
	var err error
	var ticketJob string // non-empty → deploy-ticket authorization, claim on success
	if rawTicket := strings.TrimSpace(r.Header.Get("X-Holodex-Deploy-Ticket")); rawTicket != "" {
		t, terr := parseDeployTicketHeader(rawTicket, s.buildKey, time.Now())
		if terr != nil {
			http.Error(w, terr.Error(), http.StatusForbidden)
			return
		}
		if s.jobs.deployTicketUsed(t.Job) {
			http.Error(w, "deploy ticket already used", http.StatusForbidden)
			return
		}
		p, err = refFieldsFromRequest(r, "deploy")
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if p.Repo != t.Repo {
			http.Error(w, "deploy ticket is for a different repository", http.StatusForbidden)
			return
		}
		ticketJob = t.Job
		log.Printf("ticket deploy %s@%s job=%s", t.Repo, p.SHA[:12], t.Job)
	} else if p, err = refParamsFromRequest(r, s.buildKey, "deploy"); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if p.Target != "" || p.Dockerfile != "Dockerfile" {
		http.Error(w, "reference deploy uses the root Dockerfile and no build target", http.StatusBadRequest)
		return
	}
	if _, fresh := s.jobs.claimSig(strings.TrimSpace(r.Header.Get("X-Holodex-Sign")), "deploy:"+p.SHA, p.Exp); !fresh {
		http.Error(w, "this deploy signature was already used — sign a fresh request", http.StatusConflict)
		return
	}

	// Find the retained archive this receipt actually binds. The same
	// repo@sha can have been verified more than once, and GitHub tarballs
	// are not guaranteed byte-identical across fetches — so match on the
	// digest satisfying the receipt, never on repo@sha alone.
	receipt := strings.TrimSpace(r.Header.Get("X-Holodex-Verify"))
	var archive string
	found := false
	s.jobs.mu.Lock()
	for _, j := range s.jobs.jobs {
		if j.Repo != p.Repo || j.SHA != p.SHA || j.State != "done" || j.archive == "" {
			continue
		}
		found = true
		if verifyReceipt(s.buildKey, receipt, j.digest, time.Now()) {
			archive = j.archive
			break
		}
	}
	s.jobs.mu.Unlock()
	if archive == "" {
		msg := "no verified archive retained for that repo@sha — run a reference verify first"
		if found {
			msg = "deploy refused — this exact archive needs a fresh successful test-stage verification"
		}
		http.Error(w, msg, http.StatusPreconditionFailed)
		return
	}

	// Re-hash the retained file at the moment of use: the receipt must bind
	// the bytes on disk NOW, not the bytes that were there at verification.
	// Anything able to rewrite the retained tarball after the verify would
	// otherwise ship unverified code under a valid receipt.
	if digest, err := fileSHA256(archive); err != nil || !verifyReceipt(s.buildKey, receipt, digest, time.Now()) {
		http.Error(w, "deploy refused — retained archive no longer matches its receipt", http.StatusPreconditionFailed)
		return
	}

	ap := archiveParams{Action: "deploy", Name: p.Name, Dockerfile: "Dockerfile", Port: p.Port}
	status, body := s.deployVerifiedArchive(ap, archive)
	if status == http.StatusOK {
		body["sha"] = p.SHA
		if ticketJob != "" {
			s.jobs.claimDeployTicket(ticketJob)
		}
	}
	writeJSON(w, status, body)
}

// ── job tickets ─────────────────────────────────────────────────────────────
//
// A ticket is Vela's one-time grant letting the build worker run verifications
// without ever holding the build secret: signed once at enqueue over
// {job, repo, max_verifies, exp}, presented on /api/verify/ref in place of the
// per-request HMAC. Holodex counts uses per job id and refuses past budget, so
// a compromised worker can burn at most max_verifies builds on one repo and
// nothing else. Deploys still require Vela's own signature — a ticket cannot
// ship anything.

const ticketCanonicalPrefix = "holodex-ticket-v1"

type ticket struct {
	Job         string
	Repo        string
	MaxVerifies int
	Exp         int64
}

func (t ticket) canonical() string {
	return strings.Join([]string{
		ticketCanonicalPrefix, t.Job, t.Repo,
		strconv.Itoa(t.MaxVerifies), strconv.FormatInt(t.Exp, 10), "",
	}, "\n")
}

func signTicket(key []byte, t ticket) string {
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, t.canonical())
	return hex.EncodeToString(mac.Sum(nil))
}

// ticketHeader is the wire form: job:repo-owner/repo-name:max:exp:sig.
// Colons cannot appear in any field (job ids and repo slugs are validated),
// so the encoding is unambiguous.
func parseTicketHeader(raw string, key []byte, now time.Time) (ticket, error) {
	parts := strings.Split(strings.TrimSpace(raw), ":")
	if len(parts) != 5 {
		return ticket{}, errors.New("bad ticket format (job:owner/repo:max:exp:sig)")
	}
	max, err1 := strconv.Atoi(parts[2])
	exp, err2 := strconv.ParseInt(parts[3], 10, 64)
	if err1 != nil || err2 != nil || max < 1 || max > 32 {
		return ticket{}, errors.New("bad ticket numbers")
	}
	t := ticket{Job: parts[0], Repo: parts[1], MaxVerifies: max, Exp: exp}
	if t.Job == "" || len(t.Job) > 64 || strings.ContainsAny(t.Job, "\r\n:") {
		return ticket{}, errors.New("bad ticket job id")
	}
	if !repoRe.MatchString(t.Repo) {
		return ticket{}, errors.New("bad ticket repo")
	}
	if t.Exp < now.Unix() {
		return ticket{}, errors.New("ticket expired")
	}
	if t.Exp > now.Unix()+8*3600 {
		return ticket{}, errors.New("ticket expiry too far out (max 8h)")
	}
	want, err := hex.DecodeString(parts[4])
	if err != nil {
		return ticket{}, errors.New("bad ticket signature encoding")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, t.canonical())
	if subtle.ConstantTimeCompare(want, mac.Sum(nil)) != 1 {
		return ticket{}, errors.New("ticket signature refused")
	}
	return t, nil
}

// spendTicketUse counts a verification against the ticket's budget.
func (js *jobStore) spendTicketUse(t ticket) error {
	js.mu.Lock()
	defer js.mu.Unlock()
	if js.ticketUses == nil {
		js.ticketUses = map[string]int{}
	}
	if js.ticketUses[t.Job] >= t.MaxVerifies {
		return fmt.Errorf("ticket budget exhausted (%d verifications)", t.MaxVerifies)
	}
	js.ticketUses[t.Job]++
	return nil
}

// ── deploy tickets ──────────────────────────────────────────────────────────
//
// A deploy ticket completes the worker's ownership of a build's lifecycle:
// signed by Vela at enqueue alongside the verify ticket, it lets the worker
// deploy ITS OWN verified result — once, for one repository, and only with a
// receipt proving the exact bytes passed the test gate. The worker still
// never holds the build secret; authority is granted per-job at the moment a
// human approved the request, which is where a deploy signature belongs.

const deployTicketPrefix = "holodex-deploy-ticket-v1"

type deployTicket struct {
	Job  string
	Repo string
	Exp  int64
}

func (t deployTicket) canonical() string {
	return strings.Join([]string{
		deployTicketPrefix, t.Job, t.Repo, strconv.FormatInt(t.Exp, 10), "",
	}, "\n")
}

func signDeployTicket(key []byte, t deployTicket) string {
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, t.canonical())
	return hex.EncodeToString(mac.Sum(nil))
}

// parseDeployTicketHeader validates job:owner/repo:exp:sig.
func parseDeployTicketHeader(raw string, key []byte, now time.Time) (deployTicket, error) {
	parts := strings.Split(strings.TrimSpace(raw), ":")
	if len(parts) != 4 {
		return deployTicket{}, errors.New("bad deploy ticket format (job:owner/repo:exp:sig)")
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return deployTicket{}, errors.New("bad deploy ticket expiry")
	}
	t := deployTicket{Job: parts[0], Repo: parts[1], Exp: exp}
	if t.Job == "" || len(t.Job) > 64 || strings.ContainsAny(t.Job, "\r\n:") {
		return deployTicket{}, errors.New("bad deploy ticket job id")
	}
	if !repoRe.MatchString(t.Repo) {
		return deployTicket{}, errors.New("bad deploy ticket repo")
	}
	if t.Exp < now.Unix() {
		return deployTicket{}, errors.New("deploy ticket expired")
	}
	// Generous ceiling: expiry is replay protection, not queue scheduling — a
	// build may legitimately wait hours behind others before its deploy.
	if t.Exp > now.Unix()+48*3600 {
		return deployTicket{}, errors.New("deploy ticket expiry too far out (max 48h)")
	}
	want, err := hex.DecodeString(parts[3])
	if err != nil {
		return deployTicket{}, errors.New("bad deploy ticket signature encoding")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, t.canonical())
	if subtle.ConstantTimeCompare(want, mac.Sum(nil)) != 1 {
		return deployTicket{}, errors.New("deploy ticket signature refused")
	}
	return t, nil
}

// claimDeployTicket enforces single use. Claim happens only after a
// successful deploy, so a transient failure does not burn the grant.
func (js *jobStore) deployTicketUsed(job string) bool {
	js.mu.Lock()
	defer js.mu.Unlock()
	return js.usedDeployTickets[job]
}

func (js *jobStore) claimDeployTicket(job string) {
	js.mu.Lock()
	defer js.mu.Unlock()
	if js.usedDeployTickets == nil {
		js.usedDeployTickets = map[string]bool{}
	}
	js.usedDeployTickets[job] = true
}
