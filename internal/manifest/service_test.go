package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testBoolPtr(b bool) *bool { return &b }

func TestServiceAndSensitive(t *testing.T) {
	if !ValidService("stripe") || !ValidService("acme_2.x") || ValidService("no spaces") || ValidService("") {
		t.Error("ValidService misjudges names")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, ".agentsecrets.toml")
	body := `[project]
name = "x"

[secrets.STRIPE_API_KEY]
ref = "vault://global/STRIPE_API_KEY"
transport = "env"
service = "stripe"

[secrets.STRIPE_BASE_URL]
ref = "vault://global/STRIPE_BASE_URL"
transport = "env"
service = "stripe"
sensitive = false

[secrets.OTHER]
ref = "vault://global/OTHER"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.ServiceMembers("stripe"); len(got) != 2 || got[0] != "STRIPE_API_KEY" || got[1] != "STRIPE_BASE_URL" {
		t.Errorf("members = %v", got)
	}
	if services := m.Services(); len(services) != 1 || services[0] != "stripe" {
		t.Errorf("services = %v", services)
	}
	if !m.Secrets["STRIPE_API_KEY"].IsSensitive() || m.Secrets["STRIPE_BASE_URL"].IsSensitive() {
		t.Error("sensitive flag misread")
	}
	bad := strings.Replace(body, `service = "stripe"`, `service = "bad service"`, 1)
	badPath := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(badPath, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(badPath); err == nil {
		t.Error("invalid service accepted")
	}
	// Appending writes both new fields.
	if err := AppendSecret(path, "NEW_KEY", Secret{Ref: "vault://global/NEW_KEY", Service: "other", Sensitive: testBoolPtr(false)}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `service = "other"`) || !strings.Contains(string(data), "sensitive = false") {
		t.Errorf("append lost the new fields:\n%s", data)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("appended manifest does not load: %v", err)
	}
}

func TestSetServiceEditsInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".agentsecrets.toml")
	body := `[project]
name = "x"

[secrets.A]
ref = "vault://global/A"
transport = "env"
scope = ["cmd:gh"]

[secrets.B]
ref = "vault://global/B"
transport = "env"
service = "old"

[secrets.C]
ref = "vault://global/C"
transport = "env"
service = "keep"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetService(path, "B", "new"); err != nil {
		t.Fatal(err)
	}
	m, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if m.Secrets["B"].Service != "new" || m.Secrets["C"].Service != "keep" {
		t.Fatalf("services after move: B=%q C=%q", m.Secrets["B"].Service, m.Secrets["C"].Service)
	}
	if err := SetService(path, "A", "grp"); err != nil {
		t.Fatal(err)
	}
	m, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if m.Secrets["A"].Service != "grp" || len(m.Secrets["A"].Scope) != 1 || m.Secrets["A"].Scope[0] != "cmd:gh" {
		t.Fatalf("A after add: %+v", m.Secrets["A"])
	}
	if err := SetService(path, "A", ""); err != nil {
		t.Fatal(err)
	}
	m, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if m.Secrets["A"].Service != "" || m.Secrets["A"].Transport != "env" {
		t.Fatalf("A after ungroup: %+v", m.Secrets["A"])
	}
	if err := SetService(path, "NOPE", "x"); err == nil {
		t.Error("expected an error for an undeclared secret")
	}
}
