package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsRailsAppRequiresRailsSurface(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"bin/rails", "config/application.rb", "config/database.yml"} {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("ok"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if !isRailsApp(root) {
		t.Fatal("complete Rails surface was not detected")
	}
	if err := os.Remove(filepath.Join(root, "bin/rails")); err != nil {
		t.Fatal(err)
	}
	if isRailsApp(root) {
		t.Fatal("incomplete app was detected as Rails")
	}
}

func TestStartRailsDatabaseCreatesPrivatePreviewEnvironment(t *testing.T) {
	root := t.TempDir()
	var calls [][]string
	s := &server{
		net: "internal-test",
		docker: func(_ context.Context, args ...string) (string, error) {
			calls = append(calls, append([]string(nil), args...))
			return "ok", nil
		},
	}
	m := meta{Slug: "store-abcd"}
	if err := s.startRailsDatabase(&m, root); err != nil {
		t.Fatal(err)
	}
	if m.Database != "holodeck-db-store-abcd" || m.DBVolume != "holodeck-dbdata-store-abcd" {
		t.Fatalf("unexpected database resources: %#v", m)
	}
	info, err := os.Stat(filepath.Join(root, "runtime.env"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("runtime env permissions = %o", info.Mode().Perm())
	}
	env, _ := os.ReadFile(filepath.Join(root, "runtime.env"))
	for _, key := range []string{"SECRET_KEY_BASE=", "DB_HOST=holodeck-db-store-abcd", "VELA_HOLODECK_PREVIEW=1", "STRIPE_PRIVATE_KEY=sk_test_"} {
		if !strings.Contains(string(env), key) {
			t.Fatalf("runtime env missing %s", key)
		}
	}
	if len(calls) < 3 || calls[0][0] != "volume" || calls[1][0] != "run" || calls[2][0] != "exec" {
		t.Fatalf("unexpected Docker sequence: %#v", calls)
	}
}

func TestStopDatabaseOnlyTouchesOwnedNames(t *testing.T) {
	var calls [][]string
	s := &server{docker: func(_ context.Context, args ...string) (string, error) {
		calls = append(calls, append([]string(nil), args...))
		return "", nil
	}}
	s.stopDatabase("postgres-production", "customer-data")
	if len(calls) != 0 {
		t.Fatalf("touched unowned resources: %#v", calls)
	}
	s.stopDatabase("holodeck-db-demo", "holodeck-dbdata-demo")
	if len(calls) != 2 {
		t.Fatalf("owned resources not removed: %#v", calls)
	}
}
