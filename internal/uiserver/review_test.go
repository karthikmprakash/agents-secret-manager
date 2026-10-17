package uiserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/karthikmprakash/agents-secret-manager/internal/recovery"
	"github.com/karthikmprakash/agents-secret-manager/internal/secrets"
)

func jsonBody(t *testing.T, value any) string {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEditableReviewAndConflicts(t *testing.T) {
	_, host, token := newTestServer(t)
	code, _ := do(t, "POST", sURL(host, "/api/add"), token, `{"name":"OLD_KEY","value":"original-private-value","service":"old"}`)
	if code != 200 {
		t.Fatal("fixture add failed")
	}
	text := "OLD_KEY=different-private-value\nmy email address is one@example.org\ntwo@example.org\nNOTE=opaque-value"
	code, body := do(t, "POST", sURL(host, "/api/detect"), token, jsonBody(t, map[string]string{"text": text}))
	if code != 200 {
		t.Fatalf("detect: %d", code)
	}
	var res struct {
		Suggestions []detectView `json:"suggestions"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Suggestions) != 4 || res.Suggestions[0].Conflict != "different" || !res.Suggestions[3].Sensitive {
		t.Fatalf("incorrect review metadata")
	}
	value, group, secret := "edited@example.org", "personal", true
	request := addDetectedRequest{Text: text, Scope: "global", Entries: []detectedEdit{
		{ID: res.Suggestions[0].ID, Name: "OLD_KEY"},
		{ID: res.Suggestions[1].ID, Name: "CONTACT", Value: &value, Service: &group, Sensitive: &secret},
	}}
	code, body = do(t, "POST", sURL(host, "/api/review-detected"), token, jsonBody(t, request))
	if code != 200 || !strings.Contains(string(body), "different") || strings.Contains(string(body), "original-private-value") {
		t.Fatal("review comparison failed")
	}
	code, _ = do(t, "POST", sURL(host, "/api/add-detected"), token, jsonBody(t, request))
	if code != 409 {
		t.Fatalf("conflicting import should refuse the entire batch: %d", code)
	}
	request.Entries[0].Name = "OLD_KEY_COPY"
	code, _ = do(t, "POST", sURL(host, "/api/add-detected"), token, jsonBody(t, request))
	if code != 200 {
		t.Fatalf("edited import: %d", code)
	}
	code, body = do(t, "GET", sURL(host, "/api/state"), token, "")
	if code != 200 || strings.Contains(string(body), value) || strings.Contains(string(body), "private-value") {
		t.Fatal("stored values escaped state")
	}
	var state stateResponse
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatal(err)
	}
	for _, s := range state.Secrets {
		if s.Name == "CONTACT" && (!s.Sensitive || s.Service != "personal") {
			t.Fatal("metadata edits lost")
		}
	}
	// Identical entries are idempotent; a guessed ID is not a value lookup.
	code, _ = do(t, "POST", sURL(host, "/api/add-detected"), token, jsonBody(t, request))
	if code != 200 {
		t.Fatal("same-value import should be idempotent")
	}
	request.Entries[0].ID = "unknown"
	code, _ = do(t, "POST", sURL(host, "/api/add-detected"), token, jsonBody(t, request))
	if code != 400 {
		t.Fatal("unknown source accepted")
	}
	if code, _ := do(t, "POST", sURL(host, "/api/review-detected"), "", jsonBody(t, request)); code != 401 {
		t.Fatal("review requires authentication")
	}
}

func TestDetectCloudflareR2Block(t *testing.T) {
	_, host, token := newTestServer(t)
	text := `Your API Token cfat_EXAMPLEONLYTOKEN0123456789abcdef
Access Key ID 0123456789abcdef0123456789abcdef
Secret Access Key fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
S3 API endpoint https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com`
	code, body := do(t, "POST", sURL(host, "/api/detect"), token, jsonBody(t, map[string]string{"text": text}))
	if code != 200 {
		t.Fatalf("detect: %d", code)
	}
	var res struct {
		Suggestions []detectView `json:"suggestions"`
		Warnings    []any        `json:"warnings"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 0 || len(res.Suggestions) != 4 {
		t.Fatalf("want four clean suggestions, got %s", body)
	}
	names := []string{"CLOUDFLARE_API_TOKEN", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_ENDPOINT"}
	for i, name := range names {
		s := res.Suggestions[i]
		if s.Name != name || s.Service != "cloudflare" || !s.NewGroup || s.Line != i+1 {
			t.Errorf("suggestion %d = %+v", i, s)
		}
	}
	if res.Suggestions[3].Sensitive {
		t.Error("R2 endpoint should be recognized as plain config")
	}
}

func TestServiceBulkUndoChecksCurrentLabels(t *testing.T) {
	_, host, token := newTestServer(t)
	for _, name := range []string{"ONE", "TWO"} {
		code, _ := do(t, "POST", sURL(host, "/api/add"), token, jsonBody(t, addRequest{Name: name, Value: "dummy-" + name, Service: "demo"}))
		if code != 200 {
			t.Fatal("fixture add")
		}
	}
	change := map[string]any{"from": "demo", "to": "renamed", "scope": "global"}
	code, body := do(t, "POST", sURL(host, "/api/service"), token, jsonBody(t, change))
	if code != 200 {
		t.Fatalf("rename: %d", code)
	}
	var result struct {
		Names []string `json:"names"`
	}
	if err := json.Unmarshal(body, &result); err != nil || len(result.Names) != 2 {
		t.Fatal("rename selection lost")
	}
	change["from"], change["to"], change["names"] = "renamed", "demo", result.Names
	code, _ = do(t, "POST", sURL(host, "/api/service"), token, jsonBody(t, change))
	if code != 200 {
		t.Fatal("undo failed")
	}
	code, _ = do(t, "POST", sURL(host, "/api/service"), token, jsonBody(t, change))
	if code != 409 {
		t.Fatal("stale undo must refuse")
	}
}

func TestRecoveryAPI(t *testing.T) {
	_, host, token := newTestServer(t)
	if err := secrets.Initialize(); err != nil {
		t.Fatal(err)
	}
	code, _ := do(t, "POST", sURL(host, "/api/add"), token, `{"name":"TEST_KEY","value":"recovery-private-value"}`)
	if code != 200 {
		t.Fatal("fixture add")
	}
	passphrase := "test recovery passphrase only"
	code, ciphertext := do(t, "POST", sURL(host, "/api/recovery/export"), token, jsonBody(t, recoveryRequest{Passphrase: passphrase}))
	if code != 200 || strings.Contains(string(ciphertext), "recovery-private-value") {
		t.Fatalf("encrypted export: %d", code)
	}
	request := recoveryRequest{Passphrase: passphrase, Data: ciphertext}
	code, body := do(t, "POST", sURL(host, "/api/recovery/inspect"), token, jsonBody(t, request))
	if code != 200 || !strings.Contains(string(body), `"canRestore":false`) || strings.Contains(string(body), "private-value") {
		t.Fatal("archive verification failed")
	}
	request.Confirm = true
	code, _ = do(t, "POST", sURL(host, "/api/recovery/restore"), token, jsonBody(t, request))
	if code != 409 {
		t.Fatal("existing destination should refuse restore")
	}
	if code, _ := do(t, "POST", sURL(host, "/api/recovery/export"), "", jsonBody(t, request)); code != 401 {
		t.Fatal("archive requires auth")
	}
	// Move only the test's environment to a clean destination and new identity.
	dir := t.TempDir()
	t.Setenv("SM_CONFIG_DIR", dir)
	id, _ := age.GenerateX25519Identity()
	t.Setenv("SM_IDENTITY", id.String())
	code, _ = do(t, "POST", sURL(host, "/api/recovery/restore"), token, jsonBody(t, request))
	if code != 200 {
		t.Fatalf("restore to clean destination: %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "vault.age")); err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.Open(ciphertext, "incorrect"); err == nil {
		t.Fatal("incorrect passphrase accepted")
	}
}
