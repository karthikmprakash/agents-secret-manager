package uiserver

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStatePreviewsAndReveal(t *testing.T) {
	_, host, token := newTestServer(t)
	for _, body := range []string{
		`{"name":"CONFIG_URL","value":"https://example.org","sensitive":false}`,
		`{"name":"SECRET_TOKEN","value":"supersecretvalue12345"}`,
	} {
		code, out := do(t, "POST", sURL(host, "/api/add"), token, body)
		if code != 200 {
			t.Fatalf("add: %d %s", code, out)
		}
	}

	code, body := do(t, "GET", sURL(host, "/api/state"), token, "")
	if code != 200 {
		t.Fatalf("state: %d", code)
	}
	var state stateResponse
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatal(err)
	}
	byName := map[string]secretView{}
	for _, secret := range state.Secrets {
		byName[secret.Name] = secret
	}
	config := byName["CONFIG_URL"]
	if config.Sensitive || config.Preview != "https://example.org" {
		t.Fatalf("config preview = %+v", config)
	}
	secret := byName["SECRET_TOKEN"]
	if !secret.Sensitive || !secret.Revealable || secret.Preview == "supersecretvalue12345" {
		t.Fatalf("secret preview = %+v", secret)
	}
	if !strings.HasPrefix(secret.Preview, "••••") || !strings.HasSuffix(secret.Preview, "2345") {
		t.Fatalf("secret hint = %q", secret.Preview)
	}

	code, body = do(t, "POST", sURL(host, "/api/reveal"), token, `{"name":"SECRET_TOKEN"}`)
	if code != 200 {
		t.Fatalf("reveal: %d %s", code, body)
	}
	var revealed struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &revealed); err != nil {
		t.Fatal(err)
	}
	if revealed.Value != "supersecretvalue12345" {
		t.Fatalf("reveal returned %q", revealed.Value)
	}
	if code, _ := do(t, "POST", sURL(host, "/api/reveal"), "", `{"name":"SECRET_TOKEN"}`); code != 401 {
		t.Fatalf("reveal without auth = %d, want 401", code)
	}
}
