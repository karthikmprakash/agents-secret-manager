package tpl

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestRender(t *testing.T) {
	out, err := Render(`{"a":"{{sm:A}}","b":"{{ sm:B }}"}`, func(n string) (string, error) {
		switch n {
		case "A":
			return "va", nil
		case "B":
			return "vb", nil
		}
		return "", fmt.Errorf("unknown %s", n)
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"a":"va","b":"vb"}`; out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

func TestRenderUnknown(t *testing.T) {
	_, err := Render("{{sm:NOPE}}", func(string) (string, error) {
		return "", fmt.Errorf("no secret NOPE")
	})
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestRenderUnterminated(t *testing.T) {
	if _, err := Render("x {{sm:A", func(string) (string, error) { return "v", nil }); err == nil {
		t.Fatal("expected an error")
	}
}

func TestWriteAndShred(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "out.json")
	if err := WriteFile(path, []byte("data")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "data" {
		t.Errorf("content = %q", data)
	}

	if err := Shred(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should be gone after Shred")
	}
	if err := Shred(path); err != nil {
		t.Errorf("Shred on a missing file should be nil, got %v", err)
	}
}
