package resolve

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Dotenv is a parsed .env file: key → value (last occurrence wins).
type Dotenv map[string]string

type envFile struct {
	path string
	vars Dotenv
}

// ParseDotenv parses dotenv content.
//
// v0.1 rules: KEY=VALUE lines, optional `export ` prefix, # comments, blank
// lines, single-quoted raw values, double-quoted values with \n \t \r \" \\
// escapes, unquoted values ending at an inline " #" comment. No variable
// expansion.
func ParseDotenv(data []byte) (Dotenv, error) {
	out := Dotenv{}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		key, rest, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected KEY=VALUE", i+1)
		}
		key = strings.TrimSpace(key)
		if !validEnvKey(key) {
			return nil, fmt.Errorf("line %d: invalid key %q", i+1, key)
		}
		val, err := parseValue(rest)
		if err != nil {
			return nil, fmt.Errorf("line %d (%s): %w", i+1, key, err)
		}
		out[key] = val
	}
	return out, nil
}

func parseValue(rest string) (string, error) {
	v := strings.TrimSpace(rest)
	if v == "" {
		return "", nil
	}
	switch v[0] {
	case '"':
		return unescapeDouble(v)
	case '\'':
		end := strings.IndexByte(v[1:], '\'')
		if end < 0 {
			return "", fmt.Errorf("unterminated single-quoted value")
		}
		if err := checkTrailing(v[2+end:]); err != nil {
			return "", err
		}
		return v[1 : 1+end], nil
	default:
		if idx := indexInlineComment(v); idx >= 0 {
			v = strings.TrimSpace(v[:idx])
		}
		return v, nil
	}
}

func unescapeDouble(v string) (string, error) {
	var b strings.Builder
	for i := 1; i < len(v); i++ {
		switch c := v[i]; c {
		case '\\':
			i++
			if i >= len(v) {
				return "", fmt.Errorf("unterminated escape")
			}
			switch v[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			default:
				b.WriteByte(v[i])
			}
		case '"':
			if err := checkTrailing(v[i+1:]); err != nil {
				return "", err
			}
			return b.String(), nil
		default:
			b.WriteByte(c)
		}
	}
	return "", fmt.Errorf("unterminated double-quoted value")
}

func checkTrailing(tail string) error {
	tail = strings.TrimSpace(tail)
	if tail != "" && !strings.HasPrefix(tail, "#") {
		return fmt.Errorf("unexpected text after quoted value")
	}
	return nil
}

// indexInlineComment finds a '#' preceded by whitespace (an inline comment).
func indexInlineComment(v string) int {
	for i := 1; i < len(v); i++ {
		if v[i] == '#' && (v[i-1] == ' ' || v[i-1] == '\t') {
			return i
		}
	}
	return -1
}

func validEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		switch {
		case r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validProfile(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
		default:
			return false
		}
	}
	return true
}

// loadChain reads .env, .env.<profile> (when set) and .env.local from dir,
// lowest precedence first. Missing files are skipped.
func loadChain(dir, profile string) ([]envFile, error) {
	if profile != "" && !validProfile(profile) {
		return nil, fmt.Errorf("invalid profile %q (use letters, digits, - and _)", profile)
	}
	names := []string{".env"}
	if profile != "" {
		names = append(names, ".env."+profile)
	}
	names = append(names, ".env.local")

	var out []envFile
	for _, name := range names {
		p := filepath.Join(dir, name)
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		vars, err := ParseDotenv(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, envFile{path: p, vars: vars})
	}
	return out, nil
}

func isRef(v string) bool { return strings.HasPrefix(v, "sm://") }

// Keys returns the keys declared in data, in file order, deduplicated.
func Keys(data []byte) []string {
	seen := map[string]bool{}
	var out []string
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if !validEnvKey(key) || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out
}

// ReplaceValues rewrites plaintext assignments in data to refs:
// KEY=REF. Lines for other keys are left untouched. Used by `sm import`.
func ReplaceValues(data []byte, refs map[string]string) []byte {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		trimmed := strings.TrimPrefix(line, "export ")
		key, _, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if ref, ok := refs[key]; ok {
			lines[i] = key + "=" + ref
		}
	}
	return []byte(strings.Join(lines, "\n"))
}
