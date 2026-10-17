// Package detect extracts credential suggestions from pasted CLI commands and
// env-style assignments. It never stores values or talks to a vault.
package detect

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// Suggestion is a proposed entry, never an instruction to execute anything.
type Suggestion struct {
	ID        string
	Name      string
	Value     string
	Service   string
	Sensitive bool
	Source    string
	Line      int
	Reason    string
}

type Warning struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}

type Report struct {
	Suggestions []Suggestion
	Warnings    []Warning
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

// Parse is the convenience API; Analyze also reports unrecognized input.
func Parse(text string) []Suggestion {
	return Analyze(text).Suggestions
}

// Analyze is entirely local. It never runs commands, expands variables, or
// fetches URLs. Different values are preserved even when names collide.
func Analyze(text string) Report {
	report := Report{Suggestions: []Suggestion{}, Warnings: []Warning{}}
	seen := map[string]bool{}
	usedNames := map[string]bool{}
	lineNumber := 0

	add := func(s Suggestion) {
		s.Name = strings.TrimSpace(s.Name)
		s.Value = cleanValue(s.Value)
		if !namePattern.MatchString(s.Name) || !meaningful(s.Value) {
			return
		}
		if s.Service == "" {
			s.Service = serviceFor(s.Name)
		}
		if strings.HasPrefix(s.Value, "sm://") || strings.HasPrefix(s.Value, "vault://") {
			return
		}
		identity := s.Name + "\x00" + s.Value + "\x00" + s.Service
		if seen[identity] {
			return
		}
		seen[identity] = true
		s.Sensitive = sensitive(s.Name, s.Value)
		base := s.Name
		for n := 2; usedNames[s.Name]; n++ {
			s.Name = fmt.Sprintf("%s_%d", base, n)
		}
		usedNames[s.Name] = true
		s.ID = fmt.Sprintf("entry-%d", len(report.Suggestions)+1)
		s.Line = lineNumber
		if s.Sensitive {
			s.Reason = "Secret by default; verify before changing to config."
		} else {
			s.Reason = "Recognized configuration; mark Secret if this value is private."
		}
		report.Suggestions = append(report.Suggestions, s)
	}

	text = strings.ReplaceAll(text, "\r\n", "\n")
	if parseStructured(text, add, &lineNumber) {
		return report
	}
	text = strings.ReplaceAll(text, "\\\n", " ")
	for i, raw := range strings.Split(text, "\n") {
		lineNumber = i + 1
		before := len(report.Suggestions)
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "```") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "$"))
		if strings.HasPrefix(line, "sudo ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "sudo "))
		}
		if m := envLine.FindStringSubmatch(line); m != nil {
			add(Suggestion{Name: m[1], Value: envValue(m[2]), Source: "environment"})
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
		case "curl":
			parseCurl(tokens, add)
			continue
		}
		if m := labeledValue.FindStringSubmatch(line); m != nil {
			add(Suggestion{Name: normalizeName(m[1]), Value: m[2], Source: "labeled text"})
		} else if emails := emailInText.FindAllString(line, -1); len(emails) > 0 {
			for _, email := range emails {
				add(Suggestion{Name: "EMAIL", Value: email, Source: "email in text"})
			}
		} else {
			parseBareValue(line, add)
		}
		if len(report.Suggestions) == before {
			report.Warnings = append(report.Warnings, Warning{Line: lineNumber, Message: "No new value recognized on this line. Review it manually; nothing was executed."})
		}
	}
	return report
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
	if u, err := url.Parse(value); err == nil && u.Scheme != "" && u.Host != "" {
		// Signed links, connection strings and embedded credentials are secrets.
		if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return true
		}
		return u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "postgres" && u.Scheme != "postgresql" && u.Scheme != "redis"
	}
	if emailValue.MatchString(value) {
		return false
	}
	if tokenish(value) {
		return true
	}
	for _, suffix := range []string{"REGION", "PROFILE", "MODEL", "HOST", "PORT", "USERNAME", "EMAIL", "LOG_LEVEL"} {
		if up == suffix || strings.HasSuffix(up, "_"+suffix) {
			return false
		}
	}
	return true // uncertain values must not silently bypass redaction
}
