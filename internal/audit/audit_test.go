package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendReadVerify(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		err := Append(dir, Entry{
			TS:      "2026-10-17T09:00:00Z",
			Session: "sess",
			Cmd:     "npm test",
			Secrets: []string{"GITHUB_TOKEN"},
			Action:  "inject",
			CWD:     "/tmp/proj",
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	entries, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(entries))
	}
	if entries[0].Prev != "" {
		t.Errorf("first prev = %q, want empty", entries[0].Prev)
	}
	if entries[1].Prev == "" || !strings.HasPrefix(entries[1].Prev, "sha256:") {
		t.Errorf("second prev = %q", entries[1].Prev)
	}

	n, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("verified %d entries, want 3", n)
	}

	fi, err := os.Stat(Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	if err := Append(dir, Entry{Action: "inject", Cmd: "echo"}); err != nil {
		t.Fatal(err)
	}
	if err := Append(dir, Entry{Action: "inject", Cmd: "echo"}); err != nil {
		t.Fatal(err)
	}

	path := Path(dir)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), `"cmd":"echo"`, `"cmd":"evil"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Verify(dir); err == nil {
		t.Fatal("expected a chain verification error")
	}
}

func TestVerifyEmpty(t *testing.T) {
	dir := t.TempDir()
	n, err := Verify(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("n = %d", n)
	}
	if _, err := os.Stat(filepath.Join(dir, fileName)); !os.IsNotExist(err) {
		t.Error("verify should not create the log")
	}
}
