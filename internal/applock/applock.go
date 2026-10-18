// Package applock stores the desktop app's passphrase verifier.
//
// This is an app-level lock, not a vault key. It gates the desktop UI; the
// vault identity still lives in the Keychain/Secret Service. The verifier is a
// salted Argon2id hash and never contains the passphrase itself.
package applock

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/karthikmprakash/agents-secret-manager/internal/audit"
	"github.com/karthikmprakash/agents-secret-manager/internal/config"
	"github.com/karthikmprakash/agents-secret-manager/internal/safeio"
)

const (
	fileName  = "desktop.lock"
	minLength = 8

	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
)

// ErrNotConfigured means no desktop passphrase has been set.
var ErrNotConfigured = errors.New("no desktop passphrase is set — run `sm lock set`")

type verifier struct {
	Version int    `json:"version"`
	Salt    string `json:"salt"`
	Hash    string `json:"hash"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"key_len"`
}

// Path returns the verifier location inside the sm config directory.
func Path() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, fileName), nil
}

// Configured reports whether a verifier exists and can be parsed.
func Configured() (bool, error) {
	path, err := Path()
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	var v verifier
	if err := json.Unmarshal(data, &v); err != nil || v.Version != 1 || v.Salt == "" || v.Hash == "" {
		return true, fmt.Errorf("desktop lock file is invalid; run `sm lock set --force` to replace it")
	}
	return true, nil
}

// Set stores a new verifier. Existing verifiers are kept unless force is set.
func Set(passphrase string, force bool) error {
	if len([]rune(passphrase)) < minLength {
		return fmt.Errorf("use a passphrase of at least %d characters", minLength)
	}
	path, err := Path()
	if err != nil {
		return err
	}
	if configured, _ := Configured(); configured && !force {
		return fmt.Errorf("a desktop passphrase is already set; use --force to replace it")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	sum := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	v := verifier{
		Version: 1,
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Hash:    base64.StdEncoding.EncodeToString(sum),
		Time:    argonTime,
		Memory:  argonMemory,
		Threads: argonThreads,
		KeyLen:  argonKeyLen,
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := safeio.Write(path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	record("set")
	return nil
}

// Verify returns true when the passphrase matches the stored verifier.
func Verify(passphrase string) (bool, error) {
	path, err := Path()
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, ErrNotConfigured
		}
		return false, err
	}
	var v verifier
	if err := json.Unmarshal(data, &v); err != nil || v.Version != 1 {
		return false, fmt.Errorf("desktop lock file is invalid; run `sm lock set --force` to replace it")
	}
	salt, err := base64.StdEncoding.DecodeString(v.Salt)
	if err != nil {
		return false, fmt.Errorf("desktop lock file is invalid")
	}
	want, err := base64.StdEncoding.DecodeString(v.Hash)
	if err != nil {
		return false, fmt.Errorf("desktop lock file is invalid")
	}
	got := argon2.IDKey([]byte(passphrase), salt, v.Time, v.Memory, v.Threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// Clear removes the verifier. A missing verifier is not an error.
func Clear() error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	record("clear")
	return nil
}

// record writes an audit entry. Lock events are useful; a failure to append
// must not block the user from locking or unlocking the desktop app.
func record(action string) {
	dir, err := config.Dir()
	if err != nil {
		return
	}
	_ = audit.Append(dir, audit.Entry{
		TS:      time.Now().UTC().Format(time.RFC3339),
		Session: audit.NewSession(),
		Action:  "lock",
		Cmd:     "sm lock " + action,
	})
}
