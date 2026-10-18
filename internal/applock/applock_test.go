package applock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SM_CONFIG_DIR", dir)
	return dir
}

func TestSetVerifyClear(t *testing.T) {
	fixture(t)

	if configured, err := Configured(); err != nil || configured {
		t.Fatalf("expected no lock, got %v %v", configured, err)
	}
	if _, err := Verify("anything"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured, got %v", err)
	}

	if err := Set("short", false); err == nil {
		t.Fatal("short passphrase accepted")
	}
	const passphrase = "correct horse battery staple"
	if err := Set(passphrase, false); err != nil {
		t.Fatal(err)
	}
	path, _ := Path()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("verifier mode = %v, want 0600", info.Mode().Perm())
	}
	if configured, err := Configured(); err != nil || !configured {
		t.Fatalf("expected a configured lock, got %v %v", configured, err)
	}
	if ok, err := Verify(passphrase); err != nil || !ok {
		t.Fatalf("verify = %v %v, want true", ok, err)
	}
	if ok, err := Verify("wrong passphrase"); err != nil || ok {
		t.Fatalf("wrong passphrase verify = %v %v, want false", ok, err)
	}
	if err := Set("another passphrase", false); err == nil {
		t.Fatal("overwrote an existing lock without force")
	}
	if err := Set("another passphrase", true); err != nil {
		t.Fatal(err)
	}
	if ok, _ := Verify(passphrase); ok {
		t.Fatal("old passphrase still accepted after reset")
	}
	if err := Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("verifier still exists: %v", err)
	}
	if err := Clear(); err != nil {
		t.Fatalf("clearing a missing lock should be a no-op: %v", err)
	}
}

func TestInvalidVerifierIsReported(t *testing.T) {
	dir := fixture(t)
	path := filepath.Join(dir, fileName)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if configured, err := Configured(); !configured || err == nil {
		t.Fatalf("invalid verifier: configured=%v err=%v", configured, err)
	}
	if _, err := Verify("anything"); err == nil {
		t.Fatal("invalid verifier verified successfully")
	}
}
