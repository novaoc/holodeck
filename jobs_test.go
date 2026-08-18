package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testSHA = "0123456789abcdef0123456789abcdef01234567"

// dockerOK is a docker stub for which every build succeeds instantly.
func dockerOK() func(context.Context, ...string) (string, error) {
	return func(_ context.Context, _ ...string) (string, error) { return "ok", nil }
}

func signedRefHeaders(t *testing.T, key []byte, p refParams) http.Header {
	t.Helper()
	h := http.Header{}
	h.Set("Authorization", "Bearer bearer")
	h.Set("X-Holodex-Repo", p.Repo)
	h.Set("X-Holodex-Sha", p.SHA)
	h.Set("X-Holodex-Name", p.Name)
	h.Set("X-Holodex-Target", p.Target)
	h.Set("X-Holodex-Dockerfile", p.Dockerfile)
	if p.Port != 0 {
		h.Set("X-Holodex-Port", strconv.Itoa(p.Port))
	}
	h.Set("X-Holodex-Exp", strconv.FormatInt(p.Exp, 10))
	h.Set("X-Holodex-Sign", signRef(key, p))
	return h
}

func TestRefCanonicalIsStable(t *testing.T) {
	p := refParams{
		Action: "verify", Repo: "Velaoc/pokemart", SHA: testSHA, Name: "pokemart",
		Target: "test", Dockerfile: "Dockerfile", Port: 0, Exp: 1_800_000_000,
	}
	want := "holodex-ref-v1\nverify\nVelaoc/pokemart\n" + testSHA +
		"\npokemart\ntest\nDockerfile\n0\n1800000000\n"
	if got := p.canonical(); got != want {
		t.Fatalf("canonical drifted:\n%q\nwant\n%q", got, want)
	}
}

func TestRefSignatureRejectsTampering(t *testing.T) {
	key := []byte("k")
	p := refParams{Action: "verify", Repo: "a/b", SHA: testSHA, Name: "n",
		Target: "test", Dockerfile: "Dockerfile", Exp: time.Now().Unix() + 600}
	sig := signRef(key, p)

	tampered := p
	tampered.SHA = strings.Repeat("f", 40)
	if signRef(key, tampered) == sig {
		t.Fatal("signature did not cover the sha")
	}
	if signRef([]byte("other"), p) == sig {
		t.Fatal("signature did not depend on the key")
	}
}

func TestRefParamsValidation(t *testing.T) {
	key := []byte("build-secret")
	good := refParams{Action: "verify", Repo: "Velaoc/app", SHA: testSHA,
		Name: "app", Target: "test", Dockerfile: "Dockerfile", Exp: time.Now().Unix() + 600}

	cases := []struct {
		name   string
		mutate func(h http.Header)
		want   string
	}{
		{"bad repo", func(h http.Header) {
			h.Set("X-Holodex-Repo", "../etc")
		}, "bad X-Holodex-Repo"},
		{"short sha", func(h http.Header) {
			h.Set("X-Holodex-Sha", "abc123")
		}, "bad X-Holodex-Sha"},
		{"missing name", func(h http.Header) {
			h.Set("X-Holodex-Name", "")
		}, "missing X-Holodex-Name"},
		{"expired", func(h http.Header) {
			h.Set("X-Holodex-Exp", strconv.FormatInt(time.Now().Unix()-10, 10))
		}, "expired"},
		{"expiry too far", func(h http.Header) {
			h.Set("X-Holodex-Exp", strconv.FormatInt(time.Now().Unix()+86400, 10))
		}, "too far out"},
		{"tampered sign", func(h http.Header) {
			h.Set("X-Holodex-Name", "other-app")
		}, "unsigned reference refused"},
		{"traversal dockerfile", func(h http.Header) {
			h.Set("X-Holodex-Dockerfile", "../Dockerfile")
		}, "bad X-Holodex-Dockerfile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/verify/ref", nil)
			r.Header = signedRefHeaders(t, key, good)
			tc.mutate(r.Header)
			_, err := refParamsFromRequest(r, key, "verify")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}

	// And the untampered request parses.
	r := httptest.NewRequest(http.MethodPost, "/api/verify/ref", nil)
	r.Header = signedRefHeaders(t, key, good)
	p, err := refParamsFromRequest(r, key, "verify")
	if err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
	if p.Repo != good.Repo || p.SHA != good.SHA {
		t.Fatalf("parsed %+v", p)
	}
}

func TestRefVerifyJobLifecycle(t *testing.T) {
	s := &server{
		data: t.TempDir(), token: "bearer", buildKey: []byte("build-secret"),
		verifyTO: time.Minute, buildTO: time.Minute, domain: "demo.test",
		jobs: newJobStore(), maxApps: 3, docker: dockerOK(), loc: time.UTC,
	}
	tarball := githubTar(t,
		tarEntry{name: "Dockerfile", body: "FROM scratch AS test\nFROM scratch\n"},
	)
	s.fetchRef = func(repo, sha, destDir string) (string, string, error) {
		if err := os.MkdirAll(destDir, 0o700); err != nil {
			return "", "", err
		}
		path := filepath.Join(destDir, "fetched.tar.gz")
		if err := os.WriteFile(path, tarball, 0o600); err != nil {
			return "", "", err
		}
		sum := sha256.Sum256(tarball)
		return path, hex.EncodeToString(sum[:]), nil
	}

	p := refParams{Action: "verify", Repo: "Velaoc/app", SHA: testSHA,
		Name: "app", Dockerfile: "Dockerfile", Exp: time.Now().Unix() + 600}
	req := httptest.NewRequest(http.MethodPost, "/api/verify/ref", nil)
	req.Header = signedRefHeaders(t, s.buildKey, p)

	rec := httptest.NewRecorder()
	s.auth(s.handleRefVerify)(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var accepted struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &accepted); err != nil || accepted.JobID == "" {
		t.Fatalf("no job id in %s", rec.Body.String())
	}

	// Poll until the goroutine finishes.
	var result map[string]any
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		statusReq := httptest.NewRequest(http.MethodGet, "/api/jobs/"+accepted.JobID, nil)
		statusReq.Header.Set("Authorization", "Bearer bearer")
		statusReq.SetPathValue("id", accepted.JobID)
		statusRec := httptest.NewRecorder()
		s.auth(s.handleJobStatus)(statusRec, statusReq)
		if statusRec.Code != http.StatusOK {
			t.Fatalf("job status = %d", statusRec.Code)
		}
		var out struct {
			State  string         `json:"state"`
			Result map[string]any `json:"result"`
		}
		if err := json.Unmarshal(statusRec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.State == "done" {
			result = out.Result
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if result == nil {
		t.Fatal("job never finished")
	}
	if ok, _ := result["ok"].(bool); !ok {
		t.Fatalf("verification failed: %v", result)
	}
	receipt, _ := result["receipt"].(string)
	if receipt == "" {
		t.Fatal("no receipt on a passing job")
	}

	// The retained archive digest must satisfy the receipt.
	sum := sha256.Sum256(tarball)
	if !verifyReceipt(s.buildKey, receipt, hex.EncodeToString(sum[:]), time.Now()) {
		t.Fatal("receipt does not bind the fetched bytes")
	}

	// Deploy by reference with that receipt.
	dp := refParams{Action: "deploy", Repo: "Velaoc/app", SHA: testSHA,
		Name: "app", Dockerfile: "Dockerfile", Port: 8080, Exp: time.Now().Unix() + 600}
	depReq := httptest.NewRequest(http.MethodPost, "/api/deploy/ref", nil)
	depReq.Header = signedRefHeaders(t, s.buildKey, dp)
	depReq.Header.Set("X-Holodex-Verify", receipt)
	depRec := httptest.NewRecorder()
	s.auth(s.handleRefDeploy)(depRec, depReq)
	if depRec.Code != http.StatusOK {
		t.Fatalf("ref deploy = %d body=%s", depRec.Code, depRec.Body.String())
	}
	if !strings.Contains(depRec.Body.String(), `"url":"https://app-`) ||
		!strings.Contains(depRec.Body.String(), `.demo.test/"`) {
		t.Fatalf("deploy body missing url: %s", depRec.Body.String())
	}
}

func TestRefDeployWithoutRetainedArchiveIs412(t *testing.T) {
	s := &server{
		data: t.TempDir(), token: "bearer", buildKey: []byte("build-secret"),
		domain: "demo.test", jobs: newJobStore(), docker: dockerOK(),
	}
	dp := refParams{Action: "deploy", Repo: "Velaoc/app", SHA: testSHA,
		Name: "app", Dockerfile: "Dockerfile", Exp: time.Now().Unix() + 600}
	req := httptest.NewRequest(http.MethodPost, "/api/deploy/ref", nil)
	req.Header = signedRefHeaders(t, s.buildKey, dp)
	req.Header.Set("X-Holodex-Verify", "v1:1:deadbeef:test:00")
	rec := httptest.NewRecorder()
	s.auth(s.handleRefDeploy)(rec, req)
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412", rec.Code)
	}
}

func TestJobGCRemovesExpiredJobsAndTarballs(t *testing.T) {
	js := newJobStore()
	dir := t.TempDir()
	tarball := filepath.Join(dir, "kept.tar.gz")
	if err := os.WriteFile(tarball, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	old := &verifyJob{ID: "job-old", State: "done", archive: tarball,
		Created: time.Now().Add(-3 * time.Hour), done: time.Now().Add(-2 * time.Hour)}
	fresh := &verifyJob{ID: "job-fresh", State: "done",
		Created: time.Now(), done: time.Now()}
	stuck := &verifyJob{ID: "job-stuck", State: "running",
		Created: time.Now().Add(-5 * time.Hour)}
	js.put(old)
	js.put(fresh)
	js.put(stuck)

	js.gc(time.Now())

	if _, ok := js.get("job-old"); ok {
		t.Fatal("expired job survived gc")
	}
	if _, err := os.Stat(tarball); !os.IsNotExist(err) {
		t.Fatal("expired job's tarball survived gc")
	}
	if _, ok := js.get("job-fresh"); !ok {
		t.Fatal("fresh job was collected")
	}
	if _, ok := js.get("job-stuck"); ok {
		t.Fatal("abandoned job survived gc")
	}
}

func TestJobStatusUnknownIs404(t *testing.T) {
	s := &server{token: "bearer", jobs: newJobStore()}
	req := httptest.NewRequest(http.MethodGet, "/api/jobs/job-nope", nil)
	req.Header.Set("Authorization", "Bearer bearer")
	req.SetPathValue("id", "job-nope")
	rec := httptest.NewRecorder()
	s.auth(s.handleJobStatus)(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestRefValidationRejectsCanonicalAmbiguity(t *testing.T) {
	key := []byte("build-secret")
	base := refParams{Action: "verify", Repo: "Velaoc/app", SHA: testSHA,
		Name: "app", Target: "test", Dockerfile: "Dockerfile", Exp: time.Now().Unix() + 600}

	cases := map[string]refParams{
		"newline in name":       {Action: "verify", Repo: base.Repo, SHA: base.SHA, Name: "a\nb", Target: base.Target, Dockerfile: base.Dockerfile, Exp: base.Exp},
		"oversized name":        {Action: "verify", Repo: base.Repo, SHA: base.SHA, Name: strings.Repeat("x", 101), Target: base.Target, Dockerfile: base.Dockerfile, Exp: base.Exp},
		"non-normal dockerfile": {Action: "verify", Repo: base.Repo, SHA: base.SHA, Name: base.Name, Target: base.Target, Dockerfile: "./Dockerfile", Exp: base.Exp},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/verify/ref", nil)
			for k, v := range map[string]string{
				"X-Holodex-Repo": p.Repo, "X-Holodex-Sha": p.SHA, "X-Holodex-Name": p.Name,
				"X-Holodex-Target": p.Target, "X-Holodex-Dockerfile": p.Dockerfile,
				"X-Holodex-Exp": strconv.FormatInt(p.Exp, 10), "X-Holodex-Sign": signRef(key, p),
			} {
				// Header.Set panics on invalid values in some paths; use the map
				// directly the way a raw request parser would present them.
				r.Header[k] = []string{v}
			}
			if _, err := refParamsFromRequest(r, key, "verify"); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
}

func TestRefVerifySignaturesAreSingleUse(t *testing.T) {
	s := &server{
		data: t.TempDir(), token: "bearer", buildKey: []byte("build-secret"),
		verifyTO: time.Minute, domain: "demo.test", jobs: newJobStore(),
		docker: dockerOK(), loc: time.UTC,
	}
	s.fetchRef = func(_, _, destDir string) (string, string, error) {
		if err := os.MkdirAll(destDir, 0o700); err != nil {
			return "", "", err
		}
		tb := githubTar(t, tarEntry{name: "Dockerfile", body: "FROM scratch\n"})
		path := filepath.Join(destDir, "f.tar.gz")
		if err := os.WriteFile(path, tb, 0o600); err != nil {
			return "", "", err
		}
		sum := sha256.Sum256(tb)
		return path, hex.EncodeToString(sum[:]), nil
	}
	p := refParams{Action: "verify", Repo: "Velaoc/app", SHA: testSHA,
		Name: "app", Dockerfile: "Dockerfile", Exp: time.Now().Unix() + 600}

	send := func() (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/api/verify/ref", nil)
		req.Header = signedRefHeaders(t, s.buildKey, p)
		rec := httptest.NewRecorder()
		s.auth(s.handleRefVerify)(rec, req)
		var out struct {
			JobID string `json:"job_id"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out.JobID
	}

	code1, job1 := send()
	code2, job2 := send()
	if code1 != http.StatusAccepted || code2 != http.StatusAccepted {
		t.Fatalf("codes = %d, %d", code1, code2)
	}
	if job1 == "" || job1 != job2 {
		t.Fatalf("replayed signature spawned a second job: %q vs %q", job1, job2)
	}
	if n := len(s.jobs.jobs); n != 1 {
		t.Fatalf("job count = %d, want 1", n)
	}
}

func TestRefDeployReplayIs409(t *testing.T) {
	s := &server{
		data: t.TempDir(), token: "bearer", buildKey: []byte("build-secret"),
		domain: "demo.test", jobs: newJobStore(), docker: dockerOK(), loc: time.UTC,
	}
	dp := refParams{Action: "deploy", Repo: "Velaoc/app", SHA: testSHA,
		Name: "app", Dockerfile: "Dockerfile", Exp: time.Now().Unix() + 600}
	send := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/deploy/ref", nil)
		req.Header = signedRefHeaders(t, s.buildKey, dp)
		req.Header.Set("X-Holodex-Verify", "v1:1:d:test:00")
		rec := httptest.NewRecorder()
		s.auth(s.handleRefDeploy)(rec, req)
		return rec.Code
	}
	if code := send(); code != http.StatusPreconditionFailed {
		t.Fatalf("first deploy = %d, want 412 (no retained archive)", code)
	}
	if code := send(); code != http.StatusConflict {
		t.Fatalf("replayed deploy = %d, want 409", code)
	}
}

func TestRefDeployRefusesTamperedRetainedArchive(t *testing.T) {
	s := &server{
		data: t.TempDir(), token: "bearer", buildKey: []byte("build-secret"),
		domain: "demo.test", jobs: newJobStore(), docker: dockerOK(), loc: time.UTC,
		maxApps: 3, buildTO: time.Minute,
	}
	tb := githubTar(t, tarEntry{name: "Dockerfile", body: "FROM scratch\n"})
	sum := sha256.Sum256(tb)
	digest := hex.EncodeToString(sum[:])
	archive := filepath.Join(s.data, "retained.tar.gz")
	if err := os.WriteFile(archive, tb, 0o600); err != nil {
		t.Fatal(err)
	}
	receipt := makeVerifyReceipt(s.buildKey, digest, "test", time.Now())
	s.jobs.put(&verifyJob{ID: "job-x", Repo: "Velaoc/app", SHA: testSHA,
		Name: "app", State: "done", archive: archive, digest: digest,
		Created: time.Now(), done: time.Now()})

	// Tamper with the retained bytes after verification.
	if err := os.WriteFile(archive, append(tb, 0x00), 0o600); err != nil {
		t.Fatal(err)
	}

	dp := refParams{Action: "deploy", Repo: "Velaoc/app", SHA: testSHA,
		Name: "app", Dockerfile: "Dockerfile", Exp: time.Now().Unix() + 600}
	req := httptest.NewRequest(http.MethodPost, "/api/deploy/ref", nil)
	req.Header = signedRefHeaders(t, s.buildKey, dp)
	req.Header.Set("X-Holodex-Verify", receipt)
	rec := httptest.NewRecorder()
	s.auth(s.handleRefDeploy)(rec, req)
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("tampered deploy = %d, want 412", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no longer matches its receipt") {
		t.Fatalf("wrong refusal: %s", rec.Body.String())
	}
}

func TestTicketParseAndBudget(t *testing.T) {
	key := []byte("build-secret")
	tk := ticket{Job: "wj-abc123", Repo: "Velaoc/app", MaxVerifies: 3, Exp: time.Now().Unix() + 3600}
	raw := tk.Job + ":" + tk.Repo + ":3:" + strconv.FormatInt(tk.Exp, 10) + ":" + signTicket(key, tk)

	got, err := parseTicketHeader(raw, key, time.Now())
	if err != nil {
		t.Fatalf("valid ticket refused: %v", err)
	}
	if got.Job != tk.Job || got.MaxVerifies != 3 {
		t.Fatalf("parsed %+v", got)
	}

	// Tampering with the budget must break the signature.
	forged := tk.Job + ":" + tk.Repo + ":32:" + strconv.FormatInt(tk.Exp, 10) + ":" + signTicket(key, tk)
	if _, err := parseTicketHeader(forged, key, time.Now()); err == nil {
		t.Fatal("budget tampering accepted")
	}

	// Expired ticket refused.
	old := ticket{Job: "wj-old", Repo: "Velaoc/app", MaxVerifies: 3, Exp: time.Now().Unix() - 10}
	rawOld := old.Job + ":" + old.Repo + ":3:" + strconv.FormatInt(old.Exp, 10) + ":" + signTicket(key, old)
	if _, err := parseTicketHeader(rawOld, key, time.Now()); err == nil {
		t.Fatal("expired ticket accepted")
	}

	// Budget counting.
	js := newJobStore()
	for i := 0; i < 3; i++ {
		if err := js.spendTicketUse(got); err != nil {
			t.Fatalf("use %d refused: %v", i+1, err)
		}
	}
	if err := js.spendTicketUse(got); err == nil {
		t.Fatal("fourth use exceeded the budget but was allowed")
	}
}

func TestTicketAuthorizedVerify(t *testing.T) {
	key := []byte("build-secret")
	s := &server{
		data: t.TempDir(), token: "bearer", buildKey: key,
		verifyTO: time.Minute, domain: "demo.test", jobs: newJobStore(),
		docker: dockerOK(), loc: time.UTC,
	}
	s.fetchRef = func(_, _, destDir string) (string, string, error) {
		if err := os.MkdirAll(destDir, 0o700); err != nil {
			return "", "", err
		}
		tb := githubTar(t, tarEntry{name: "Dockerfile", body: "FROM scratch\n"})
		path := filepath.Join(destDir, "f.tar.gz")
		if err := os.WriteFile(path, tb, 0o600); err != nil {
			return "", "", err
		}
		sum := sha256.Sum256(tb)
		return path, hex.EncodeToString(sum[:]), nil
	}

	tk := ticket{Job: "wj-1", Repo: "Velaoc/app", MaxVerifies: 2, Exp: time.Now().Unix() + 3600}
	rawTicket := tk.Job + ":" + tk.Repo + ":2:" + strconv.FormatInt(tk.Exp, 10) + ":" + signTicket(key, tk)

	send := func(repo string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/verify/ref", nil)
		r.Header.Set("Authorization", "Bearer bearer")
		r.Header.Set("X-Holodex-Repo", repo)
		r.Header.Set("X-Holodex-Sha", testSHA)
		r.Header.Set("X-Holodex-Name", "app")
		r.Header.Set("X-Holodex-Dockerfile", "Dockerfile")
		r.Header.Set("X-Holodex-Exp", strconv.FormatInt(time.Now().Unix()+600, 10))
		r.Header.Set("X-Holodex-Ticket", rawTicket)
		rec := httptest.NewRecorder()
		s.auth(s.handleRefVerify)(rec, r)
		return rec.Code
	}

	// A ticket for another repo must not authorize this one.
	if code := send("Velaoc/other"); code != http.StatusForbidden {
		t.Fatalf("wrong-repo ticket verify = %d, want 403", code)
	}
	// Two verifies inside budget, third refused.
	if code := send("Velaoc/app"); code != http.StatusAccepted {
		t.Fatalf("ticket verify 1 = %d, want 202", code)
	}
	if code := send("Velaoc/app"); code != http.StatusAccepted {
		t.Fatalf("ticket verify 2 = %d, want 202", code)
	}
	if code := send("Velaoc/app"); code != http.StatusTooManyRequests {
		t.Fatalf("over-budget ticket verify = %d, want 429", code)
	}
}
