package redact

import (
	"bytes"
	"strings"
	"testing"
)

func TestStreamingMatchesOneShotAtEveryChunkSize(t *testing.T) {
	labels := map[string]string{"abcdef": "LONG", "abc": "SHORT", "a": "A", "redacted": "WORD", "xy": "XY"}
	text := "prefix abcdef, abc, a, xy, suffix abcdefxy"
	want := String(text, labels)
	for size := 1; size <= len(text); size++ {
		var out bytes.Buffer
		w := New(&out, labels)
		for i := 0; i < len(text); i += size {
			end := min(i+size, len(text))
			if _, err := w.Write([]byte(text[i:end])); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		if out.String() != want {
			t.Fatalf("chunk=%d differs: %q", size, out.String())
		}
	}
	if !strings.Contains(want, "[redacted:LONG]") {
		t.Fatal("replacement markers were rescanned")
	}
}

func TestOrdinaryOutputDoesNotWaitForExit(t *testing.T) {
	var out bytes.Buffer
	w := New(&out, map[string]string{"a-long-token": "TOKEN"})
	_, _ = w.Write([]byte("ready\n"))
	if out.String() != "ready\n" {
		t.Fatal("ordinary progress output stalled")
	}
}

func FuzzStreaming(f *testing.F) {
	f.Add("prefix secret suffix", "secret", uint8(3))
	f.Add("abcabcdef", "abcdef", uint8(1))
	f.Fuzz(func(t *testing.T, text, secret string, chunk uint8) {
		if len(text) > 20000 || len(secret) > 1000 {
			return
		}
		labels := map[string]string{secret: "VALUE"}
		want := String(text, labels)
		var out bytes.Buffer
		w := New(&out, labels)
		size := int(chunk) + 1
		for i := 0; i < len(text); i += size {
			_, _ = w.Write([]byte(text[i:min(i+size, len(text))]))
		}
		_ = w.Flush()
		if out.String() != want {
			t.Fatal("stream result differs from one-shot")
		}
	})
}

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
