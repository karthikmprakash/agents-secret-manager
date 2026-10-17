package redact

import (
	"bytes"
	"testing"
)

func TestSimple(t *testing.T) {
	var buf bytes.Buffer
	w := New(&buf, map[string]string{"hunter2": "PASSWORD"})
	if _, err := w.Write([]byte("pass=hunter2\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "pass=[redacted:PASSWORD]\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSplitAcrossWrites(t *testing.T) {
	var buf bytes.Buffer
	w := New(&buf, map[string]string{"supersecret": "TOKEN"})
	if _, err := w.Write([]byte("x superse")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("cret y")); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "x [redacted:TOKEN] y"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLongestFirst(t *testing.T) {
	var buf bytes.Buffer
	w := New(&buf, map[string]string{"abcd": "LONG", "ab": "SHORT"})
	if _, err := w.Write([]byte("abcd ab")); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "[redacted:LONG] [redacted:SHORT]"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNoSecrets(t *testing.T) {
	var buf bytes.Buffer
	w := New(&buf, nil)
	if _, err := w.Write([]byte("plain")); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "plain" {
		t.Errorf("got %q", got)
	}
}

func TestEmptyValueIgnored(t *testing.T) {
	var buf bytes.Buffer
	w := New(&buf, map[string]string{"": "EMPTY"})
	if _, err := w.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "abc" {
		t.Errorf("got %q", got)
	}
}

func TestString(t *testing.T) {
	got := String("curl -H x hunter2 y", map[string]string{"hunter2": "PASSWORD"})
	if want := "curl -H x [redacted:PASSWORD] y"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
