package uiserver

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
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

func TestDetectAndAdd(t *testing.T) {
	_, host, token := newTestServer(t)
	text := "modal token set --token-id ak-EXAMPLEID --token-secret as-EXAMPLESECRET --profile=test\nmodal profile activate test"
	detectBody, _ := json.Marshal(map[string]string{"text": text})

	code, body := do(t, "POST", sURL(host, "/api/detect"), token, string(detectBody))
	if code != 200 {
		t.Fatalf("detect code = %d: %s", code, body)
	}
	var detected struct {
		Suggestions []struct {
			Name      string `json:"name"`
			Value     string `json:"value"`
			Service   string `json:"service"`
			Sensitive bool   `json:"sensitive"`
			Existing  bool   `json:"existing"`
			NewGroup  bool   `json:"newGroup"`
		} `json:"suggestions"`
	}
	if err := json.Unmarshal(body, &detected); err != nil {
		t.Fatal(err)
	}
	if len(detected.Suggestions) != 3 {
		t.Fatalf("want 3 suggestions, got %d: %s", len(detected.Suggestions), body)
	}
	wantValues := map[string]string{
		"MODAL_TOKEN_ID":     "ak-EXAMPLEID",
		"MODAL_TOKEN_SECRET": "as-EXAMPLESECRET",
		"MODAL_PROFILE":      "test",
	}
	for _, s := range detected.Suggestions {
		if wantValues[s.Name] != s.Value {
			t.Errorf("%s value = %q, want %q", s.Name, s.Value, wantValues[s.Name])
		}
		if s.Service != "modal" {
			t.Errorf("%s service = %q", s.Name, s.Service)
		}
		if s.Name == "MODAL_PROFILE" && s.Sensitive {
			t.Error("profile should be config, not sensitive")
		}
		if s.Name != "MODAL_PROFILE" && !s.Sensitive {
			t.Errorf("%s should be sensitive", s.Name)
		}
		if !s.NewGroup {
			t.Errorf("%s: group should be new", s.Name)
		}
	}

	addBody, _ := json.Marshal(map[string]any{
		"text":  text,
		"names": []string{"MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET", "MODAL_PROFILE"},
		"scope": "global",
	})
	code, body = do(t, "POST", sURL(host, "/api/add-detected"), token, string(addBody))
	if code != 200 {
		t.Fatalf("add-detected code = %d: %s", code, body)
	}

	code, body = do(t, "GET", sURL(host, "/api/state"), token, "")
	if code != 200 {
		t.Fatalf("state code = %d", code)
	}
	var state stateResponse
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatal(err)
	}
	byName := map[string]secretView{}
	for _, s := range state.Secrets {
		byName[s.Name] = s
	}
	for name, sensitive := range map[string]bool{
		"MODAL_TOKEN_ID": true, "MODAL_TOKEN_SECRET": true, "MODAL_PROFILE": false,
	} {
		s, ok := byName[name]
		if !ok {
			t.Fatalf("%s missing after add", name)
		}
		if s.Service != "modal" || s.Sensitive != sensitive {
			t.Errorf("%s = service %q sensitive %v", name, s.Service, s.Sensitive)
		}
	}

	// A second detection sees existing entries and an existing group.
	code, body = do(t, "POST", sURL(host, "/api/detect"), token,
		`{"text":"modal token set --token-id ak-EXAMPLEID --token-secret as-EXAMPLESECRET"}`)
	if code != 200 {
		t.Fatalf("second detect code = %d", code)
	}
	if err := json.Unmarshal(body, &detected); err != nil {
		t.Fatal(err)
	}
	for _, s := range detected.Suggestions {
		if !s.Existing || s.NewGroup {
			t.Errorf("%s: existing=%v newGroup=%v, want true/false", s.Name, s.Existing, s.NewGroup)
		}
	}

	// Missing names are rejected rather than silently dropped.
	code, _ = do(t, "POST", sURL(host, "/api/add-detected"), token,
		`{"text":"MODAL_TOKEN_ID=ak-EXAMPLEID","names":["NOT_THERE"],"scope":"global"}`)
	if code != 400 {
		t.Errorf("unknown selection code = %d, want 400", code)
	}
}

func TestAddDetectedRename(t *testing.T) {
	_, host, token := newTestServer(t)
	const email = "mkarthikprakash919@gmail.com"

	detectBody, _ := json.Marshal(map[string]string{"text": email})
	code, body := do(t, "POST", sURL(host, "/api/detect"), token, string(detectBody))
	if code != 200 {
		t.Fatalf("detect code = %d: %s", code, body)
	}
	var detected struct {
		Suggestions []struct {
			Name      string `json:"name"`
			Value     string `json:"value"`
			Sensitive bool   `json:"sensitive"`
		} `json:"suggestions"`
	}
	if err := json.Unmarshal(body, &detected); err != nil {
		t.Fatal(err)
	}
	if len(detected.Suggestions) != 1 || detected.Suggestions[0].Name != "EMAIL" {
		t.Fatalf("suggestions = %s", body)
	}
	if detected.Suggestions[0].Sensitive || detected.Suggestions[0].Value != email {
		t.Errorf("email suggestion = %+v", detected.Suggestions[0])
	}

	addBody, _ := json.Marshal(map[string]any{
		"text":    email,
		"names":   []string{"EMAIL"},
		"renames": map[string]string{"EMAIL": "PERSONAL_EMAIL"},
		"scope":   "global",
	})
	code, body = do(t, "POST", sURL(host, "/api/add-detected"), token, string(addBody))
	if code != 200 {
		t.Fatalf("add-detected code = %d: %s", code, body)
	}

	code, body = do(t, "GET", sURL(host, "/api/state"), token, "")
	if code != 200 {
		t.Fatalf("state code = %d", code)
	}
	var state stateResponse
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range state.Secrets {
		if s.Name == "PERSONAL_EMAIL" {
			found = true
			if s.Sensitive {
				t.Error("email should be stored as config")
			}
		}
		if s.Name == "EMAIL" {
			t.Error("original suggested name should have been renamed")
		}
	}
	if !found {
		t.Fatal("renamed entry missing")
	}

	badBody, _ := json.Marshal(map[string]any{
		"text":    email,
		"names":   []string{"EMAIL"},
		"renames": map[string]string{"EMAIL": "bad name"},
		"scope":   "global",
	})
	code, _ = do(t, "POST", sURL(host, "/api/add-detected"), token, string(badBody))
	if code != 400 {
		t.Errorf("invalid rename code = %d, want 400", code)
	}
}

func TestMcpConfigSnippets(t *testing.T) {
	_, host, token := newTestServer(t)
	code, body := do(t, "GET", sURL(host, "/api/mcp-config"), token, "")
	if code != 200 {
		t.Fatalf("code = %d: %s", code, body)
	}
	var res struct {
		Snippets []struct {
			Agents []string `json:"agents"`
			Lang   string   `json:"lang"`
			Body   string   `json:"body"`
		} `json:"snippets"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range res.Snippets {
		if s.Lang == "json" && strings.Contains(s.Body, "mcpServers") {
			found = true
		}
	}
	if !found {
		t.Errorf("no mcpServers JSON snippet in %d snippets", len(res.Snippets))
	}
}

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
	if val, ok, _ := v.Get("global/API_KEY"); !ok || val != "sekret-xyz" {
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
	if val, _, _ := v.Get("global/ROT"); val != "new" {
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

func TestInitializeAndCookieRefresh(t *testing.T) {
	s, host, token := newTestServer(t)
	code, body := do(t, "GET", sURL(host, "/api/state"), token, "")
	if code != 200 {
		t.Fatal(string(body))
	}
	var state stateResponse
	_ = json.Unmarshal(body, &state)
	if state.Initialized {
		t.Fatal("new vault unexpectedly initialized")
	}
	if code, body := do(t, "POST", sURL(host, "/api/initialize"), token, "{}"); code != 200 {
		t.Fatal(string(body))
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	res, err := client.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	res, err = client.Get(sURL(host, "/api/state"))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("refresh lost authentication")
	}
	if err := json.NewDecoder(res.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if !state.Initialized {
		t.Fatal("vault not ready")
	}
	u, _ := url.Parse(s.URL)
	for _, c := range jar.Cookies(u) {
		if c.Value == "" {
			t.Fatal("session missing")
		}
	}
}

func TestMutationGuards(t *testing.T) {
	_, host, token := newTestServer(t)
	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{"GET", "/api/add", "", 404},
		{"POST", "/api/setup", "{invalid", 400},
		{"POST", "/api/add", "{\"name\":\"X\",\"value\":\"never-echo-me\",\"unknown\":true}", 400},
		{"POST", "/api/setup", "{} {}", 400},
		{"POST", "/api/setup", "{\"only\":\"not-installed\"}", 404},
	} {
		code, body := do(t, tc.method, sURL(host, tc.path), token, tc.body)
		if code != tc.want {
			t.Errorf("%s %s=%d want %d: %s", tc.method, tc.path, code, tc.want, body)
		}
		if strings.Contains(string(body), "never-echo-me") {
			t.Fatal("error leaked input")
		}
	}
	for _, header := range []struct{ key, value string }{{"Origin", "https://evil.example"}, {"Host", "evil.example"}} {
		req, _ := http.NewRequest("GET", sURL(host, "/api/state"), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		if header.key == "Host" {
			req.Host = header.value
		} else {
			req.Header.Set(header.key, header.value)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatal("cross-origin/host request allowed")
		}
	}
	code, _ := do(t, "POST", sURL(host, "/api/setup?token="+token), "", "{}")
	if code != 401 {
		t.Fatal("query token authorized mutation")
	}
}

func TestBulkImportPreviewAndConflict(t *testing.T) {
	_, host, token := newTestServer(t)
	code, body := do(t, "POST", sURL(host, "/api/import"), token, `{"data":"A=keep-secret\nB=other-secret\n","preview":true}`)
	if code != 200 || strings.Contains(string(body), "keep-secret") {
		t.Fatal("preview failed or leaked values")
	}
	code, body = do(t, "POST", sURL(host, "/api/import"), token, `{"data":"A=keep-secret\nB=other-secret\n","names":["A","B"]}`)
	if code != 200 {
		t.Fatal(string(body))
	}
	code, body = do(t, "POST", sURL(host, "/api/import"), token, `{"data":"A=different\nC=third\n","names":["A","C"]}`)
	if code != 409 {
		t.Fatal("conflicting import not rejected")
	}
	code, body = do(t, "GET", sURL(host, "/api/state"), token, "")
	if strings.Contains(string(body), "keep-secret") || strings.Contains(string(body), "other-secret") {
		t.Fatal("state leaked values")
	}
	var state stateResponse
	_ = json.Unmarshal(body, &state)
	if len(state.Secrets) != 2 {
		t.Fatal("partial conflicting import")
	}
}

func TestMalformedManifestIsNotAnEmptyState(t *testing.T) {
	_, host, token := newTestServer(t)
	if err := os.WriteFile(".agentsecrets.toml", []byte("[broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := do(t, "GET", sURL(host, "/api/state"), token, ""); code != 500 {
		t.Fatal("malformed manifest silently hidden")
	}
}

func TestDoctorDoesNotInvokeAnotherCLIOrLeakContext(t *testing.T) {
	_, host, token := newTestServer(t)
	t.Setenv("HOME", t.TempDir())
	code, body := do(t, "POST", sURL(host, "/api/add"), token, `{"name":"TOKEN","value":"known-secret"}`)
	if code != 200 {
		t.Fatal(string(body))
	}
	if err := os.WriteFile(".env", []byte("TOKEN=known-secret\nUNREGISTERED=must-not-echo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, body = do(t, "POST", sURL(host, "/api/doctor"), token, `{"history":false}`)
	if code != 200 {
		t.Fatal(string(body))
	}
	if strings.Contains(string(body), "known-secret") || strings.Contains(string(body), "must-not-echo") {
		t.Fatal("doctor leaked raw content")
	}
	if !strings.Contains(string(body), `"exit":1`) {
		t.Fatal("doctor did not report finding")
	}
}
