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
	"syscall"
)

var (
	placeholder  = regexp.MustCompile(`\{\{\s*sm:\s*([^{}]+?)\s*\}\}`)
	unterminated = regexp.MustCompile(`\{\{\s*sm:`)
)

// Render replaces {{sm:NAME}} placeholders using resolve. Errors name the
// secret, never a value.
func Render(template string, resolve func(name string) (string, error)) (string, error) {
	// Validate template syntax before inserting values. A literal placeholder
	// inside a secret is data, not a second template to expand or reject.
	if unterminated.MatchString(placeholder.ReplaceAllString(template, "")) {
		return "", fmt.Errorf("malformed {{sm:NAME}} placeholder")
	}
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
	return out, nil
}

// WriteFile exclusively creates path at 0600. Never destroy an existing file.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(path)
		}
	}()

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
	ok = true
	return nil
}

// Materialize returns a cleanup bound to the inode we created. A command may
// replace the output path; do not overwrite a different file during cleanup.
func Materialize(path string, data []byte) (func() error, error) {
	if err := WriteFile(path, data); err != nil {
		return nil, err
	}
	original, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	return func() error {
		current, err := os.Lstat(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !os.SameFile(original, current) {
			return fmt.Errorf("output path was replaced; left the replacement untouched")
		}
		return Shred(path)
	}, nil
}

// Shred overwrites path with random bytes and removes it. Best effort: the
// filesystem may not overwrite in place (APFS is copy-on-write).
func Shred(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		if fi, e := os.Lstat(path); e == nil && fi.Mode()&os.ModeSymlink != 0 {
			return os.Remove(path)
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
