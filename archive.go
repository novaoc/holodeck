package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	maxArchiveBody   = 96 << 20
	maxArchiveFiles  = 10_000
	maxArchiveTotal  = 256 << 20
	maxBuildLog      = 16_000
	verifyReceiptTTL = time.Hour
)

var buildTargetRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

type archiveParams struct {
	Action     string
	Name       string
	Target     string
	Dockerfile string
	Port       int
}

func (p archiveParams) canonical() string {
	return strings.Join([]string{
		"holodeck-archive-v1",
		p.Action,
		p.Name,
		p.Target,
		p.Dockerfile,
		strconv.Itoa(p.Port),
		"",
	}, "\n")
}

func archiveParamsFromRequest(r *http.Request, action string) (archiveParams, error) {
	p := archiveParams{
		Action:     action,
		Name:       strings.TrimSpace(r.Header.Get("X-Holodeck-Name")),
		Target:     strings.TrimSpace(r.Header.Get("X-Holodeck-Target")),
		Dockerfile: strings.TrimSpace(r.Header.Get("X-Holodeck-Dockerfile")),
	}
	if p.Name == "" || len(p.Name) > 100 || strings.ContainsAny(p.Name, "\r\n") {
		return p, errors.New("X-Holodeck-Name is required (max 100 characters)")
	}
	if p.Dockerfile == "" {
		p.Dockerfile = "Dockerfile"
	}
	if clean, ok := cleanArchivePath(p.Dockerfile); !ok || clean != p.Dockerfile {
		return p, errors.New("invalid X-Holodeck-Dockerfile path")
	}
	if p.Target != "" && !buildTargetRe.MatchString(p.Target) {
		return p, errors.New("invalid X-Holodeck-Target")
	}
	if raw := strings.TrimSpace(r.Header.Get("X-Holodeck-Port")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 65535 {
			return p, errors.New("X-Holodeck-Port must be 1-65535")
		}
		p.Port = n
	}
	return p, nil
}

func cleanArchivePath(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimPrefix(name, "./")
	clean := path.Clean(name)
	if clean == "." || clean == "" || strings.HasPrefix(clean, "/") || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	if len(clean) > 300 || clean == ".git" || strings.HasPrefix(clean, ".git/") || strings.Contains(clean, "/.git/") {
		return "", false
	}
	return clean, true
}

// receiveArchive streams the signed body to disk. The signature covers both
// the compressed archive and the build metadata so a valid body cannot be
// replayed with a different target, port, or Dockerfile.
func (s *server) receiveArchive(w http.ResponseWriter, r *http.Request, p archiveParams) (string, string, error) {
	jobs := filepath.Join(s.data, "jobs")
	if err := os.MkdirAll(jobs, 0o700); err != nil {
		return "", "", err
	}
	f, err := os.CreateTemp(jobs, "upload-*.tar.gz")
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
	if err := f.Chmod(0o600); err != nil {
		return "", "", err
	}

	mac := hmac.New(sha256.New, s.buildKey)
	digest := sha256.New()
	_, _ = io.WriteString(mac, p.canonical())
	limited := http.MaxBytesReader(w, r.Body, maxArchiveBody)
	n, err := io.Copy(io.MultiWriter(f, mac, digest), limited)
	if err != nil {
		return "", "", fmt.Errorf("archive too large or unreadable: %w", err)
	}
	if n == 0 {
		return "", "", errors.New("empty archive")
	}
	got, err := hex.DecodeString(strings.TrimSpace(r.Header.Get("X-Holodeck-Sign")))
	if err != nil || subtle.ConstantTimeCompare(got, mac.Sum(nil)) != 1 {
		return "", "", errors.New("unsigned archive refused")
	}
	if err := f.Sync(); err != nil {
		return "", "", err
	}
	ok = true
	return name, hex.EncodeToString(digest.Sum(nil)), nil
}

func makeVerifyReceipt(key []byte, digest, target string, now time.Time) string {
	payload := fmt.Sprintf("v1:%d:%s:%s", now.Unix(), digest, target)
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, payload)
	return payload + ":" + hex.EncodeToString(mac.Sum(nil))
}

func verifyReceipt(key []byte, receipt, digest string, now time.Time) bool {
	parts := strings.Split(receipt, ":")
	if len(parts) != 5 || parts[0] != "v1" || parts[2] != digest || parts[3] != "test" {
		return false
	}
	stamp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}
	age := now.Sub(time.Unix(stamp, 0))
	if age < -time.Minute || age > verifyReceiptTTL {
		return false
	}
	payload := strings.Join(parts[:4], ":")
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, payload)
	want, err := hex.DecodeString(parts[4])
	return err == nil && subtle.ConstantTimeCompare(want, mac.Sum(nil)) == 1
}

// extractGitHubArchive safely expands a GitHub tarball and strips its single
// synthetic top-level directory (owner-repo-sha/). Links and special files are
// refused so the archive cannot write outside the workspace or smuggle host
// filesystem references into a Docker build context.
func extractGitHubArchive(archive, dst string) (int64, int, error) {
	f, err := os.Open(archive)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0, 0, fmt.Errorf("not a gzip archive: %w", err)
	}
	defer gz.Close()
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return 0, 0, err
	}

	tr := tar.NewReader(gz)
	var total int64
	files := 0
	root := ""
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return total, files, fmt.Errorf("bad tar archive: %w", err)
		}
		// GitHub currently emits a POSIX global PAX header before the synthetic
		// repository directory. It describes following entries and is not the
		// archive root.
		if h.Typeflag == tar.TypeXGlobalHeader || h.Typeflag == tar.TypeXHeader {
			continue
		}
		name := strings.ReplaceAll(h.Name, "\\", "/")
		parts := strings.SplitN(strings.TrimPrefix(name, "./"), "/", 2)
		if root == "" && len(parts) > 0 {
			root = parts[0]
		}
		if len(parts) < 2 || parts[0] != root || parts[1] == "" {
			continue
		}
		rel, valid := cleanArchivePath(parts[1])
		if !valid {
			return total, files, fmt.Errorf("unsafe archive path %q", h.Name)
		}
		full := filepath.Join(dst, filepath.FromSlash(rel))
		if !strings.HasPrefix(full, filepath.Clean(dst)+string(os.PathSeparator)) {
			return total, files, fmt.Errorf("archive path escapes workspace: %q", h.Name)
		}

		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(full, 0o755); err != nil {
				return total, files, err
			}
		case tar.TypeReg, tar.TypeRegA:
			files++
			if files > maxArchiveFiles || h.Size < 0 || h.Size > maxArchiveTotal || total+h.Size > maxArchiveTotal {
				return total, files, errors.New("archive exceeds source limits")
			}
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return total, files, err
			}
			mode := os.FileMode(0o644)
			if h.FileInfo().Mode()&0o111 != 0 {
				mode = 0o755
			}
			out, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return total, files, err
			}
			n, copyErr := io.CopyN(out, tr, h.Size)
			closeErr := out.Close()
			if copyErr != nil || n != h.Size {
				return total, files, fmt.Errorf("couldn't extract %s: %w", rel, copyErr)
			}
			if closeErr != nil {
				return total, files, closeErr
			}
			total += n
		default:
			return total, files, fmt.Errorf("archive links/special files are not allowed: %q", h.Name)
		}
	}
	if files == 0 {
		return 0, 0, errors.New("archive contains no files")
	}
	return total, files, nil
}

func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	p, err := archiveParamsFromRequest(r, "verify")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if p.Target == "" {
		p.Target = "test"
	}
	archive, digest, err := s.receiveArchive(w, r, p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	defer os.Remove(archive)

	job := slugify("verify-" + p.Name)
	work := filepath.Join(s.data, "jobs", job)
	defer os.RemoveAll(work)
	total, files, err := extractGitHubArchive(archive, work)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	dockerfilePath := filepath.Join(work, filepath.FromSlash(p.Dockerfile))
	if st, err := os.Stat(dockerfilePath); err != nil || st.IsDir() {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Dockerfile not found at " + p.Dockerfile})
		return
	}

	image := "holodeck/" + job + ":verify"
	finalImage := "holodeck/" + job + ":verify-final"
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, _ = s.docker(ctx, "rmi", "-f", image)
		_, _ = s.docker(ctx, "rmi", "-f", finalImage)
		cancel()
	}()
	args := []string{"build", "--progress=plain", "--label", "holodeck=1", "--label", "holodeck-job=1", "-f", dockerfilePath, "-t", image}
	if p.Target != "" {
		args = append(args, "--target", p.Target)
	}
	args = append(args, work)
	ctx, cancel := context.WithTimeout(context.Background(), s.verifyTO)
	defer cancel()
	started := time.Now()
	s.buildMu.Lock()
	logs, buildErr := s.docker(ctx, args...)
	if buildErr == nil {
		// The test stage is the safety gate, but a deployable app must also have
		// a valid final image. This second build normally reuses every expensive
		// layer from the test build.
		finalArgs := []string{
			"build", "--progress=plain", "--label", "holodeck=1", "--label", "holodeck-job=1",
			"-f", dockerfilePath, "-t", finalImage, work,
		}
		finalLogs, finalErr := s.docker(ctx, finalArgs...)
		logs = logs + "\n\n== deployable image ==\n" + finalLogs
		buildErr = finalErr
	}
	s.buildMu.Unlock()
	duration := time.Since(started).Milliseconds()
	if buildErr != nil {
		msg := "verification failed"
		if ctx.Err() == context.DeadlineExceeded {
			msg = fmt.Sprintf("verification timed out after %s", s.verifyTO)
		}
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"ok": false, "error": msg, "logs": tail(logs, maxBuildLog), "duration_ms": duration,
		})
		return
	}
	log.Printf("verified %s (%d files, %dKB, target=%s, %dms)", p.Name, files, total/1024, p.Target, duration)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "logs": tail(logs, maxBuildLog), "files": files, "source_bytes": total, "duration_ms": duration,
		"receipt": makeVerifyReceipt(s.buildKey, digest, p.Target, time.Now()),
	})
}

func (s *server) handleArchiveDeploy(w http.ResponseWriter, r *http.Request) {
	p, err := archiveParamsFromRequest(r, "deploy")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if p.Target != "" || p.Dockerfile != "Dockerfile" {
		http.Error(w, "archive deploy uses the root Dockerfile and no build target", http.StatusBadRequest)
		return
	}
	archive, digest, err := s.receiveArchive(w, r, p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	defer os.Remove(archive)
	if !verifyReceipt(s.buildKey, strings.TrimSpace(r.Header.Get("X-Holodeck-Verify")), digest, time.Now()) {
		http.Error(w, "deploy refused — this exact archive needs a fresh successful test-stage verification", http.StatusPreconditionFailed)
		return
	}

	slug := slugify(p.Name)
	root := filepath.Join(s.data, "apps", slug)
	src := filepath.Join(root, "src")
	total, files, err := extractGitHubArchive(archive, src)
	if err != nil {
		_ = os.RemoveAll(root)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	dockerfile, dockerErr := os.ReadFile(filepath.Join(src, "Dockerfile"))
	_, indexErr := os.Stat(filepath.Join(src, "index.html"))
	if dockerErr != nil && indexErr != nil {
		_ = os.RemoveAll(root)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "archive needs a root Dockerfile or index.html"})
		return
	}

	m := meta{Name: p.Name, Slug: slug, Created: time.Now().UTC(), State: "running"}
	if dockerErr == nil {
		m.Kind = "container"
		m.Port = p.Port
		if m.Port == 0 {
			if mt := exposeRe.FindStringSubmatch(string(dockerfile)); mt != nil {
				m.Port, _ = strconv.Atoi(mt[1])
			}
		}
		if m.Port == 0 {
			m.Port = 8080
		}
		m.Image = "holodeck/" + slug + ":latest"
		m.Container = "holodeck-app-" + slug
		if err := s.buildAndRun(&m, src); err != nil {
			_ = os.RemoveAll(root)
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
			return
		}
	} else {
		m.Kind = "static"
	}
	s.writeMeta(m)
	s.activity.Store(slug, time.Now())
	log.Printf("deployed archive %s (%s, %d files, %dKB)", slug, m.Kind, files, total/1024)
	writeJSON(w, http.StatusOK, map[string]any{
		"url": fmt.Sprintf("https://%s.%s/", slug, s.domain), "slug": slug, "kind": m.Kind,
		"expires": s.nextWipe().Format(time.RFC3339), "files": files, "source_bytes": total,
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
