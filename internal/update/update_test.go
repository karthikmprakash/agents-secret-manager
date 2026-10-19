package update

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"0.5.2", "0.5.2", 0},
		{"v0.5.3", "0.5.2", 1},
		{"0.5.2", "0.5.3", -1},
		{"0.6.0", "0.5.9", 1},
		{"0.5.2", "0.5.2-dev", 1},
		{"0.5.2-dev", "0.5.2", -1},
		{"0.5.3-dev", "0.5.2", 1},
		{"0.5.2-rc.1", "0.5.2", -1},
		{"0.5.2-rc.2", "0.5.2-rc.1", 1},
	}
	for _, test := range tests {
		if got := Compare(test.a, test.b); got != test.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", test.a, test.b, got, test.want)
		}
	}
}

func TestCheckAndCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SM_CONFIG_DIR", dir)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "sm/0.5.2" {
			t.Errorf("User-Agent = %q", r.Header.Get("User-Agent"))
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"tag_name":     "v0.5.3",
			"html_url":     "https://github.com/karthikmprakash/agents-secret-manager/releases/tag/v0.5.3",
			"published_at": "2026-10-19T12:00:00Z",
		})
	}))
	defer server.Close()
	old := apiURL
	apiURL = server.URL
	defer func() { apiURL = old }()

	result, err := Check(context.Background(), "0.5.2")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Available || result.Latest != "0.5.3" {
		t.Fatalf("result = %+v", result)
	}
	if _, err := os.Stat(filepath.Join(dir, "update.json")); err != nil {
		t.Fatal("cache was not written")
	}
	cached, ok := Cached("0.5.2")
	if !ok || !cached.Available || cached.Latest != "0.5.3" {
		t.Fatalf("cached = %+v ok=%v", cached, ok)
	}
	if cached.CheckedAt.IsZero() || time.Since(cached.CheckedAt) > time.Minute {
		t.Fatalf("checked time = %v", cached.CheckedAt)
	}
}

func TestCheckHandlesFailure(t *testing.T) {
	t.Setenv("SM_CONFIG_DIR", t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusForbidden)
	}))
	defer server.Close()
	old := apiURL
	apiURL = server.URL
	defer func() { apiURL = old }()
	if _, err := Check(context.Background(), "0.5.2"); err == nil {
		t.Fatal("HTTP failure was reported as success")
	}
	if _, ok := Cached("0.5.2"); ok {
		t.Fatal("failed check wrote a cache")
	}
}
