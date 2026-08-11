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
		net:       "internal-test",
		domain:    "demo.holode.xyz",
		mailRelay: &mailRelay{from: "Holodex <noreply@plumb.capital>", hostname: "holodex"},
		docker: func(_ context.Context, args ...string) (string, error) {
			calls = append(calls, append([]string(nil), args...))
			return "ok", nil
		},
	}
	m := meta{Slug: "store-abcd"}
	if err := s.startRailsDatabase(&m, root); err != nil {
		t.Fatal(err)
	}
	if m.Database != "holodex-db-store-abcd" || m.DBVolume != "holodex-dbdata-store-abcd" {
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
	for _, key := range []string{
		"SECRET_KEY_BASE=", "DB_HOST=holodex-db-store-abcd", "VELA_HOLODEX_PREVIEW=1",
		"APP_HOST=store-abcd.demo.holode.xyz",
		"SOLID_QUEUE_IN_PUMA=1",
		"THRUSTER_LOG_REQUESTS=false",
		"SMTP_ADDRESS=holodex", "SMTP_PORT=2525",
		"SMTP_ENABLE_STARTTLS_AUTO=false", "MAILER_FROM=Holodex <noreply@plumb.capital>",
	} {
		if !strings.Contains(string(env), key) {
			t.Fatalf("runtime env missing %s", key)
		}
	}
	if strings.Contains(string(env), "STRIPE_") {
		t.Fatalf("preview env must not contain Stripe entries:\n%s", env)
	}
	if !strings.Contains(strings.Join(calls[0], " "), "holodex=1") {
		t.Fatalf("volume not labeled holodex=1: %#v", calls[0])
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
	s.stopDatabase("holodex-db-demo", "holodex-dbdata-demo")
	if len(calls) != 2 {
		t.Fatalf("owned resources not removed: %#v", calls)
	}
	calls = nil
	s.stopDatabase("holodeck-db-demo", "holodeck-dbdata-demo")
	if len(calls) != 2 {
		t.Fatalf("legacy pre-rename resources must stay removable: %#v", calls)
	}
}

func TestStopContainerAcceptsBothNameFamilies(t *testing.T) {
	var calls [][]string
	s := &server{docker: func(_ context.Context, args ...string) (string, error) {
		calls = append(calls, append([]string(nil), args...))
		return "", nil
	}}
	s.stopContainer("vehicle-underwriter-app-1")
	if len(calls) != 0 {
		t.Fatalf("touched an unowned container: %#v", calls)
	}
	s.stopContainer("holodex-app-demo")
	s.stopContainer("holodeck-app-demo")
	if len(calls) != 2 {
		t.Fatalf("owned containers not removed: %#v", calls)
	}
}

func TestSettingPrefersHolodexAndFallsBackToLegacy(t *testing.T) {
	t.Setenv("HOLODECK_EXAMPLE", "legacy")
	if got := setting("EXAMPLE"); got != "legacy" {
		t.Fatalf("legacy fallback broken: %q", got)
	}
	t.Setenv("HOLODEX_EXAMPLE", "current")
	if got := setting("EXAMPLE"); got != "current" {
		t.Fatalf("HOLODEX_* must win over HOLODECK_*: %q", got)
	}
	if got := settingOr("MISSING_EXAMPLE", "fallback"); got != "fallback" {
		t.Fatalf("default broken: %q", got)
	}
}
