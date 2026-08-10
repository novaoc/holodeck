package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type tarEntry struct {
	name string
	body string
	mode int64
	kind byte
}

func githubTar(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader,
		PAXRecords: map[string]string{"comment": "github archive metadata"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "owner-repo-deadbeef/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		kind := e.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		h := &tar.Header{Name: "owner-repo-deadbeef/" + e.name, Typeflag: kind, Mode: mode, Size: int64(len(e.body))}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.body != "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func archiveSignature(key []byte, p archiveParams, body []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(p.canonical()))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestExtractGitHubArchive(t *testing.T) {
	body := githubTar(t,
		tarEntry{name: "Dockerfile", body: "FROM scratch\n"},
		tarEntry{name: ".github/workflows/test.yml", body: "name: CI\n"},
		tarEntry{name: "bin/setup", body: "#!/bin/sh\n", mode: 0o755},
	)
	archive := filepath.Join(t.TempDir(), "source.tar.gz")
	if err := os.WriteFile(archive, body, 0o600); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	total, files, err := extractGitHubArchive(archive, dst)
	if err != nil {
		t.Fatal(err)
	}
	if files != 3 || total == 0 {
		t.Fatalf("files=%d total=%d", files, total)
	}
	if _, err := os.Stat(filepath.Join(dst, ".github/workflows/test.yml")); err != nil {
		t.Fatal("dotfiles should survive repository extraction:", err)
	}
	if st, err := os.Stat(filepath.Join(dst, "bin/setup")); err != nil || st.Mode()&0o111 == 0 {
		t.Fatal("executable mode was not preserved")
	}
}

func TestExtractGitHubArchiveRejectsLinksAndTraversal(t *testing.T) {
	for name, entry := range map[string]tarEntry{
		"traversal": {name: "../../outside", body: "owned"},
		"symlink":   {name: "link", kind: tar.TypeSymlink},
		"git data":  {name: ".git/config", body: "bad"},
	} {
		t.Run(name, func(t *testing.T) {
			body := githubTar(t, entry)
			archive := filepath.Join(t.TempDir(), "source.tar.gz")
			if err := os.WriteFile(archive, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := extractGitHubArchive(archive, t.TempDir()); err == nil {
				t.Fatal("unsafe archive was accepted")
			}
		})
	}
}

func TestVerifyArchiveBuildIsSignedEphemeralAndTargeted(t *testing.T) {
	key := []byte("test-build-key")
	var mu sync.Mutex
	var calls [][]string
	s := &server{
		data:     t.TempDir(),
		token:    "bearer",
		buildKey: key,
		verifyTO: time.Minute,
		docker: func(_ context.Context, args ...string) (string, error) {
			mu.Lock()
			calls = append(calls, slices.Clone(args))
			mu.Unlock()
			return "test stage passed", nil
		},
	}
	body := githubTar(t,
		tarEntry{name: "Dockerfile", body: "FROM scratch AS test\n"},
		tarEntry{name: "app.rb", body: "puts :ok\n"},
	)
	p := archiveParams{Action: "verify", Name: "Safe Store", Target: "test", Dockerfile: "Dockerfile"}
	req := httptest.NewRequest(http.MethodPost, "/api/verify", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer bearer")
	req.Header.Set("X-Holodeck-Name", p.Name)
	req.Header.Set("X-Holodeck-Target", p.Target)
	req.Header.Set("X-Holodeck-Dockerfile", p.Dockerfile)
	req.Header.Set("X-Holodeck-Sign", archiveSignature(key, p, body))
	rr := httptest.NewRecorder()
	s.auth(s.handleVerify).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil || result["ok"] != true {
		t.Fatalf("bad response: %s", rr.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 4 {
		t.Fatalf("docker calls=%v", calls)
	}
	joined := strings.Join(calls[0], " ")
	if !strings.Contains(joined, "--target test") || !strings.Contains(joined, "holodeck-job=1") {
		t.Fatalf("verification build lost safety metadata: %s", joined)
	}
	if !strings.Contains(joined, filepath.Join(s.data, "jobs")) {
		t.Fatalf("verification build did not use the validated Dockerfile path: %s", joined)
	}
	if strings.Contains(strings.Join(calls[1], " "), "--target") || calls[1][0] != "build" {
		t.Fatalf("deployable final image was not built: %v", calls[1])
	}
	if calls[2][0] != "rmi" || calls[3][0] != "rmi" {
		t.Fatalf("verification images were not removed: %v", calls[2:])
	}
	entries, err := os.ReadDir(filepath.Join(s.data, "jobs"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("ephemeral job files survived: %v", entries)
	}
}

func TestVerifyArchiveSignatureCoversMetadata(t *testing.T) {
	key := []byte("test-build-key")
	s := &server{data: t.TempDir(), token: "bearer", buildKey: key, verifyTO: time.Minute, docker: dockerOut}
	body := githubTar(t, tarEntry{name: "Dockerfile", body: "FROM scratch AS test\n"})
	signed := archiveParams{Action: "verify", Name: "Original", Target: "test", Dockerfile: "Dockerfile"}
	req := httptest.NewRequest(http.MethodPost, "/api/verify", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer bearer")
	req.Header.Set("X-Holodeck-Name", "Tampered")
	req.Header.Set("X-Holodeck-Target", "test")
	req.Header.Set("X-Holodeck-Dockerfile", "Dockerfile")
	req.Header.Set("X-Holodeck-Sign", archiveSignature(key, signed, body))
	rr := httptest.NewRecorder()
	s.auth(s.handleVerify).ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("metadata tampering should fail, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestVerifyReceiptBindsExactArchiveAndTestTarget(t *testing.T) {
	key := []byte("receipt-key")
	now := time.Unix(1_800_000_000, 0)
	receipt := makeVerifyReceipt(key, "abc123", "test", now)
	if !verifyReceipt(key, receipt, "abc123", now.Add(10*time.Minute)) {
		t.Fatal("fresh receipt for the exact tested archive was rejected")
	}
	if verifyReceipt(key, receipt, "different", now.Add(10*time.Minute)) {
		t.Fatal("receipt accepted a different archive")
	}
	if verifyReceipt(key, receipt, "abc123", now.Add(verifyReceiptTTL+time.Second)) {
		t.Fatal("expired receipt was accepted")
	}
	buildOnly := makeVerifyReceipt(key, "abc123", "build", now)
	if verifyReceipt(key, buildOnly, "abc123", now) {
		t.Fatal("non-test build receipt authorized deployment")
	}
}
