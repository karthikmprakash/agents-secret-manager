// Package tpl renders {{sm:NAME}} templates and materializes them to 0600
// files that are shredded when the wrapper session ends.
package tpl

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	placeholder  = regexp.MustCompile(`\{\{\s*sm:\s*([^{}]+?)\s*\}\}`)
	unterminated = regexp.MustCompile(`\{\{\s*sm:`)
)

// Render replaces {{sm:NAME}} placeholders using resolve. Errors name the
// secret, never a value.
func Render(template string, resolve func(name string) (string, error)) (string, error) {
	var firstErr error
	out := placeholder.ReplaceAllStringFunc(template, func(m string) string {
		if firstErr != nil {
			return m
		}
		name := strings.TrimSpace(placeholder.FindStringSubmatch(m)[1])
		if name == "" {
			firstErr = fmt.Errorf("empty {{sm:}} placeholder")
			return m
		}
		v, err := resolve(name)
		if err != nil {
			firstErr = err
			return m
		}
		return v
	})
	if firstErr != nil {
		return "", firstErr
	}
	if unterminated.MatchString(out) {
		return "", fmt.Errorf("unterminated {{sm:…}} placeholder")
	}
	return out, nil
}

// WriteFile writes data to path atomically with mode 0600, creating parents.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sm-tpl-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful rename

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Shred overwrites path with random bytes and removes it. Best effort: the
// filesystem may not overwrite in place (APFS is copy-on-write).
func Shred(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	fi, statErr := f.Stat()
	if statErr != nil {
		f.Close()
		return os.Remove(path)
	}
	buf := make([]byte, 4096)
	remaining := fi.Size()
	for remaining > 0 {
		n := int64(len(buf))
		if remaining < n {
			n = remaining
		}
		if _, err := rand.Read(buf[:n]); err != nil {
			break
		}
		if _, err := f.Write(buf[:n]); err != nil {
			break
		}
		remaining -= n
	}
	f.Sync()
	f.Close()
	return os.Remove(path)
}
