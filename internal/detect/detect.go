// Package detect extracts credential suggestions from pasted CLI commands and
// env-style assignments. It never stores values or talks to a vault.
package detect

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Suggestion is one parsed entry. Values are used server-side only; API
// responses omit them.
type Suggestion struct {
	Name      string
	Value     string
	Service   string
	Sensitive bool
	Source    string
}

var (
	envLine     = regexp.MustCompile(`^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)
	namePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	placeholder = regexp.MustCompile(`(?i)^(<.*>|\.{3}|x{3,}|your[_-].*|changeme|placeholder|example([-_].*)?)$`)
	emailValue  = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
	urlValue    = regexp.MustCompile(`^https?://[^\s]+$`)
	tokenValue  = regexp.MustCompile(`^[A-Za-z0-9_\-+/=.]{24,}$`)
	tokenPrefix = []string{"sk-", "pk-", "rk-", "ak-", "as-", "ghp_", "github_pat_", "xoxb-", "xoxp-", "whsec_"}

	prefixServices = map[string]string{
		"AWS": "aws", "STRIPE": "stripe", "OPENAI": "openai", "ANTHROPIC": "anthropic",
		"GITHUB": "github", "GH": "github", "MODAL": "modal", "DEEPSEEK": "deepseek",
		"HUGGINGFACE": "huggingface", "HF": "huggingface", "CURSOR": "cursor",
		"SUPABASE": "supabase", "POSTGRES": "postgres", "REDIS": "redis",
		"SLACK": "slack", "DOKPLOY": "dokploy", "VERCEL": "vercel", "FLY": "fly",
	}
)

// Parse returns unique suggestions in first-seen order. Later assignments to
// the same name replace the value in place.
func Parse(text string) []Suggestion {
	var out []Suggestion
	index := map[string]int{}

	add := func(s Suggestion) {
		s.Name = strings.TrimSpace(s.Name)
		s.Value = cleanValue(s.Value)
		if !namePattern.MatchString(s.Name) || !meaningful(s.Value) {
			return
		}
		if s.Service == "" {
			s.Service = serviceFor(s.Name)
		}
		s.Sensitive = sensitive(s.Name, s.Value)
		if i, ok := index[s.Name]; ok {
			out[i] = s
			return
		}
		index[s.Name] = len(out)
		out = append(out, s)
	}

	text = strings.ReplaceAll(text, "\r\n", "\n")
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "$"))
		if strings.HasPrefix(line, "sudo ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "sudo "))
		}
		if m := envLine.FindStringSubmatch(line); m != nil {
			add(Suggestion{Name: m[1], Value: m[2], Source: "environment"})
			continue
		}
		tokens := tokenize(line)
		if len(tokens) == 0 {
			continue
		}
		switch strings.ToLower(filepath.Base(tokens[0])) {
		case "modal":
			parseModal(tokens, add)
			continue
		case "aws":
			parseAWS(tokens, add)
			continue
		}
		parseBareValue(line, add)
	}
	return out
}

// parseBareValue recognizes a single pasted value without a name: an email,
// URL, or token-like string. The suggested name is a starting point; the UI
// lets the user rename it before storing.
func parseBareValue(line string, add func(Suggestion)) {
	value := cleanValue(line)
	if value == "" || strings.ContainsAny(value, " \t") {
		return
	}
	switch {
	case emailValue.MatchString(value):
		add(Suggestion{Name: "EMAIL", Value: value, Source: "plain value"})
	case urlValue.MatchString(value):
		add(Suggestion{Name: "BASE_URL", Value: value, Source: "plain value"})
	case tokenish(value):
		add(Suggestion{Name: "API_TOKEN", Value: value, Source: "plain value"})
	}
}

func tokenish(value string) bool {
	low := strings.ToLower(value)
	for _, prefix := range tokenPrefix {
		if strings.HasPrefix(low, prefix) {
			return true
		}
	}
	return tokenValue.MatchString(value)
}

func parseModal(tokens []string, add func(Suggestion)) {
	if hasSeq(tokens, "token", "set") || hasFlag(tokens, "token-id") || hasFlag(tokens, "token-secret") {
		flags := flags(tokens, 1)
		for _, field := range []struct{ flag, name string }{
			{"token-id", "MODAL_TOKEN_ID"},
			{"token-secret", "MODAL_TOKEN_SECRET"},
			{"profile", "MODAL_PROFILE"},
		} {
			if value := flags[field.flag]; value != "" {
				add(Suggestion{Name: field.name, Value: value, Service: "modal", Source: "modal token set"})
			}
		}
	}
	for i := 0; i+2 < len(tokens); i++ {
		if tokens[i] == "profile" && tokens[i+1] == "activate" {
			add(Suggestion{Name: "MODAL_PROFILE", Value: tokens[i+2], Service: "modal", Source: "modal profile activate"})
			break
		}
	}
}

func parseAWS(tokens []string, add func(Suggestion)) {
	names := map[string]string{
		"aws_access_key_id":     "AWS_ACCESS_KEY_ID",
		"aws_secret_access_key": "AWS_SECRET_ACCESS_KEY",
		"region":                "AWS_REGION",
	}
	for i := 0; i+3 < len(tokens); i++ {
		if tokens[i] != "configure" || tokens[i+1] != "set" {
			continue
		}
		if name, ok := names[strings.ToLower(tokens[i+2])]; ok {
			add(Suggestion{Name: name, Value: tokens[i+3], Service: "aws", Source: "aws configure set"})
		}
	}
}

// tokenize splits a command line on whitespace while honoring quotes.
func tokenize(line string) []string {
	var out []string
	var b strings.Builder
	quote := rune(0)
	escaped := false
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for _, r := range line {
		switch {
		case escaped:
			b.WriteRune(r)
			escaped = false
		case r == '\\' && quote != '\'':
			escaped = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
		case r == ' ' || r == '\t':
			flush()
		default:
			b.WriteRune(r)
		}
	}
	flush()
	return out
}

// flags reads --key=value and --key value pairs starting at from.
func flags(tokens []string, from int) map[string]string {
	out := map[string]string{}
	for i := from; i < len(tokens); i++ {
		token := tokens[i]
		if !strings.HasPrefix(token, "--") || len(token) == 2 {
			continue
		}
		key, value, hasValue := strings.Cut(strings.TrimPrefix(token, "--"), "=")
		if hasValue {
			out[strings.ToLower(key)] = value
			continue
		}
		if i+1 < len(tokens) && !strings.HasPrefix(tokens[i+1], "-") {
			out[strings.ToLower(key)] = tokens[i+1]
			i++
		}
	}
	return out
}

func hasSeq(tokens []string, first, second string) bool {
	for i := 0; i+1 < len(tokens); i++ {
		if tokens[i] == first && tokens[i+1] == second {
			return true
		}
	}
	return false
}

func hasFlag(tokens []string, flag string) bool {
	needle := "--" + flag
	for _, token := range tokens {
		if token == needle || strings.HasPrefix(token, needle+"=") {
			return true
		}
	}
	return false
}

func cleanValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			value = strings.TrimSpace(value[1 : len(value)-1])
		}
	}
	return value
}

func meaningful(value string) bool {
	return value != "" && !placeholder.MatchString(value) && value != "$"
}

func serviceFor(name string) string {
	prefix, _, ok := strings.Cut(strings.ToUpper(name), "_")
	if !ok {
		return ""
	}
	return prefixServices[prefix]
}

func sensitive(name, value string) bool {
	up := strings.ToUpper(name)
	for _, marker := range []string{"SECRET", "TOKEN", "PASSWORD", "PASSWD", "API_KEY", "ACCESS_KEY", "PRIVATE_KEY", "CREDENTIAL"} {
		if strings.Contains(up, marker) {
			return true
		}
	}
	if strings.HasSuffix(up, "_KEY") && !strings.Contains(up, "PUBLIC") {
		return true
	}
	if strings.HasSuffix(up, "_PASS") {
		return true
	}
	low := strings.ToLower(value)
	for _, prefix := range []string{"sk-", "pk-", "rk-", "ak-", "as-", "ghp_", "github_pat_", "xoxb-", "xoxp-", "whsec_"} {
		if strings.HasPrefix(low, prefix) {
			return true
		}
	}
	return false
}
