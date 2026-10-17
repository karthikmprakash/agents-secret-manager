// Package generate creates random secret values for `sm add --generate`.
package generate

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

const (
	alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	hex   = "0123456789abcdef"
)

// Value generates a secret. spec is "[profile/]length" — e.g. "postgres/32",
// "hex/64", or just "32" (default profile: alnum).
func Value(spec string) (string, error) {
	profile, lenPart := "alnum", spec
	if i := strings.IndexByte(spec, '/'); i >= 0 {
		profile, lenPart = spec[:i], spec[i+1:]
	}
	// "postgres" is an alias for the default alphanumeric profile.
	if profile == "postgres" {
		profile = "alnum"
	}

	var charset string
	switch profile {
	case "alnum":
		charset = alnum
	case "hex":
		charset = hex
	default:
		return "", fmt.Errorf("unknown generate profile %q (want alnum, hex or postgres)", profile)
	}

	n := 0
	if _, err := fmt.Sscanf(lenPart, "%d", &n); err != nil || n < 8 || n > 256 {
		return "", fmt.Errorf("generate length must be an integer between 8 and 256, got %q", lenPart)
	}
	return randomString(charset, n)
}

func randomString(charset string, n int) (string, error) {
	var b strings.Builder
	b.Grow(n)
	limit := big.NewInt(int64(len(charset)))
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		b.WriteByte(charset[idx.Int64()])
	}
	return b.String(), nil
}
