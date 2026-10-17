package generate

import (
	"strings"
	"testing"
)

func TestValue(t *testing.T) {
	v, err := Value("postgres/32")
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 32 {
		t.Errorf("len = %d, want 32", len(v))
	}
	for _, c := range v {
		if !strings.ContainsRune(alnum, c) {
			t.Fatalf("unexpected char %q in %q", c, v)
		}
	}

	h, err := Value("hex/64")
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 64 {
		t.Errorf("hex len = %d, want 64", len(h))
	}

	if _, err := Value("bogus/32"); err == nil {
		t.Error("expected profile error")
	}
	if _, err := Value("hex/4"); err == nil {
		t.Error("expected length error")
	}
}
