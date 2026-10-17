package uiserver

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/karthikmprakash/agents-secret-manager/internal/store/vaultfile"
)

func newTestServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	cfg := t.TempDir()
	proj := t.TempDir()
	t.Setenv("SM_CONFIG_DIR", cfg)

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SM_IDENTITY", id.String())

	if err := os.WriteFile(filepath.Join(proj, ".agentsecrets.toml"), []byte("[secrets]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(proj)

	s, err := Start(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	return s, u.Host, u.Query().Get("token")
}

func do(t *testing.T, method, url, token string, body string) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, data
}

func TestAuthRequired(t *testing.T) {
	_, host, _ := newTestServer(t)
	code, _ := do(t, "GET", "http://"+host+"/api/state", "", "")
	if code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", code)
	}
	code, _ = do(t, "GET", sURL(host, "/"), "", "")
	if code != http.StatusUnauthorized {
		t.Errorf("index without token = %d, want 401", code)
	}
}

func sURL(host, path string) string { return "http://" + host + path }

func TestAddSecretAndState(t *testing.T) {
	_, host, token := newTestServer(t)

	code, body := do(t, "POST", sURL(host, "/api/add"), token,
		`{"name":"API_KEY","value":"sekret-xyz","scope":"global","transport":"env"}`)
	if code != 200 {
		t.Fatalf("add code = %d: %s", code, body)
	}
	if strings.Contains(string(body), "sekret-xyz") {
		t.Fatal("add response leaked the value")
	}

	code, body = do(t, "GET", sURL(host, "/api/state"), token, "")
	if code != 200 {
		t.Fatalf("state code = %d: %s", code, body)
	}
	if strings.Contains(string(body), "sekret-xyz") {
		t.Fatal("state leaked the value")
	}
	var st stateResponse
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range st.Secrets {
		if s.Name == "API_KEY" && s.Status == "present" && s.Scope == "global" {
			found = true
		}
	}
	if !found {
		t.Fatalf("API_KEY missing from state: %+v", st.Secrets)
	}

	// The vault actually holds it.
	v, err := vaultfile.Open(filepath.Join(os.Getenv("SM_CONFIG_DIR"), "vault.age"), os.Getenv("SM_IDENTITY"))
	if err != nil {
		t.Fatal(err)
	}
	if val, ok, _ := v.Get("api_key"); !ok || val != "sekret-xyz" {
		t.Fatalf("vault value = %q, %v", val, ok)
	}
}

func TestDuplicateAddRejected(t *testing.T) {
	_, host, token := newTestServer(t)
	body := `{"name":"DUP","value":"v","scope":"global","transport":"env"}`
	if code, _ := do(t, "POST", sURL(host, "/api/add"), token, body); code != 200 {
		t.Fatal("first add failed")
	}
	code, data := do(t, "POST", sURL(host, "/api/add"), token, body)
	if code != http.StatusConflict {
		t.Errorf("code = %d, want 409: %s", code, data)
	}
}

func TestRotate(t *testing.T) {
	_, host, token := newTestServer(t)
	if code, _ := do(t, "POST", sURL(host, "/api/add"), token,
		`{"name":"ROT","value":"old","scope":"global","transport":"env"}`); code != 200 {
		t.Fatal("add failed")
	}
	code, data := do(t, "POST", sURL(host, "/api/rotate"), token, `{"name":"ROT","value":"new"}`)
	if code != 200 {
		t.Fatalf("rotate code = %d: %s", code, data)
	}
	v, err := vaultfile.Open(filepath.Join(os.Getenv("SM_CONFIG_DIR"), "vault.age"), os.Getenv("SM_IDENTITY"))
	if err != nil {
		t.Fatal(err)
	}
	if val, _, _ := v.Get("rot"); val != "new" {
		t.Errorf("value = %q", val)
	}
}

func TestAgentsEndpoint(t *testing.T) {
	_, host, token := newTestServer(t)
	code, body := do(t, "GET", sURL(host, "/api/agents"), token, "")
	if code != 200 {
		t.Fatalf("code = %d: %s", code, body)
	}
	var res struct {
		Agents []agentView `json:"agents"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}
	if res.Agents == nil {
		t.Fatal("agents field missing from response")
	}
}
