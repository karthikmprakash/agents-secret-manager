// Package audit implements the append-only, hash-chained audit log.
//
// Entries are JSONL. Each line carries the SHA-256 of the previous line, so
// interior edits and reordering are detectable. Truncation of the tail and
// edits to the last line are not detectable without an external anchor.
package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const fileName = "audit.jsonl"

// Entry is one audit line. Values are never recorded — names only.
type Entry struct {
	TS      string   `json:"ts"`
	Session string   `json:"session"`
	Cmd     string   `json:"cmd"`
	Secrets []string `json:"secrets,omitempty"`
	Action  string   `json:"action"`
	CWD     string   `json:"cwd"`
	Prev    string   `json:"prev"`
}

// Path returns the audit log location inside dir.
func Path(dir string) string { return filepath.Join(dir, fileName) }

// NewSession returns a short random session id.
func NewSession() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}

// Append links e to the previous entry and appends it to the log.
func Append(dir string, e Entry) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(Path(dir), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	data, err := os.ReadFile(f.Name())
	if err != nil {
		return err
	}
	lines := splitLines(data)
	if len(lines) > 0 {
		e.Prev = Hash(lines[len(lines)-1])
	}

	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	return err
}

// Read returns all entries.
func Read(dir string) ([]Entry, error) {
	data, err := os.ReadFile(Path(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	lines := splitLines(data)
	out := make([]Entry, 0, len(lines))
	for i, line := range lines {
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("audit line %d: %w", i+1, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// Verify walks the hash chain and returns the number of entries.
func Verify(dir string) (int, error) {
	data, err := os.ReadFile(Path(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	lines := splitLines(data)
	prev := ""
	for i, line := range lines {
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return i, fmt.Errorf("line %d: invalid JSON: %w", i+1, err)
		}
		if e.Prev != prev {
			return i, fmt.Errorf("line %d: chain broken (prev %q, want %q)", i+1, e.Prev, prev)
		}
		prev = Hash(line)
	}
	return len(lines), nil
}

// Hash returns "sha256:<hex>" for a line (without its trailing newline).
func Hash(line string) string {
	sum := sha256.Sum256([]byte(line))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func splitLines(data []byte) []string {
	text := strings.TrimSuffix(string(data), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}
