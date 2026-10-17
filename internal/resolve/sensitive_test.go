package resolve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikmprakash/agents-secret-manager/internal/manifest"
)

type mapStore map[string]string

func (m mapStore) Get(key string) (string, bool, error) {
	v, ok := m[key]
	return v, ok, nil
}

func TestNonSensitiveValuesAreInjectedButNotRedacted(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SM_CONFIG_DIR", filepath.Join(dir, "config"))
	global, created, err := manifest.EnsureGlobal()
	if err != nil || !created {
		t.Fatalf("ensure global: %v (created=%v)", err, created)
	}
	if err := manifest.AppendSecret(global, "STRIPE_API_KEY", manifest.Secret{Ref: "vault://global/STRIPE_API_KEY", Service: "stripe"}); err != nil {
		t.Fatal(err)
	}
	no := false
	if err := manifest.AppendSecret(global, "STRIPE_BASE_URL", manifest.Secret{Ref: "vault://global/STRIPE_BASE_URL", Service: "stripe", Sensitive: &no}); err != nil {
		t.Fatal(err)
	}
	start := filepath.Join(dir, "proj")
	if err := os.MkdirAll(start, 0o700); err != nil {
		t.Fatal(err)
	}
	loaded, err := manifest.LoadLayers(start)
	if err != nil {
		t.Fatal(err)
	}
	store := mapStore{
		"global/STRIPE_API_KEY":  "sk-live-secret",
		"global/STRIPE_BASE_URL": "https://api.stripe.com",
	}
	res, err := Build(loaded, store, start, Options{Environ: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, masked := res.Redactions["sk-live-secret"]; !masked {
		t.Error("sensitive value missing from redactions")
	}
	if _, masked := res.Redactions["https://api.stripe.com"]; masked {
		t.Error("non-sensitive config value was added to redactions")
	}
	env := map[string]string{}
	for _, kv := range res.Env {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}
	if env["STRIPE_BASE_URL"] != "https://api.stripe.com" || env["STRIPE_API_KEY"] != "sk-live-secret" {
		t.Errorf("values not injected from the vault: %v", env)
	}
}
