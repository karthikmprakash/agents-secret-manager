package detect

import (
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	emailInText   = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	labeledValue  = regexp.MustCompile(`(?i)^(?:(?:my|the|your)\s+)?(email(?: address)?|base[_ ]?url|api[_ ]?key|api[_ ]?token|token|password|region|profile|model|username)\s*(?:\s+is\s+|:\s*|=\s*)(.+)$`)
	camelBoundary = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	nonName       = regexp.MustCompile(`[^A-Za-z0-9_]+`)
)

func normalizeName(key string) string {
	key = camelBoundary.ReplaceAllString(key, "${1}_${2}")
	key = strings.Trim(nonName.ReplaceAllString(key, "_"), "_")
	if strings.EqualFold(key, "email_address") {
		key = "EMAIL"
	}
	return strings.ToUpper(key)
}

// YAML's node parser handles both JSON and YAML without expanding custom tags
// or evaluating expressions. Nodes also preserve duplicate keys for review.
func parseStructured(text string, add func(Suggestion), line *int) bool {
	var doc yaml.Node
	if yaml.Unmarshal([]byte(text), &doc) != nil || len(doc.Content) != 1 {
		return false
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode && root.Kind != yaml.SequenceNode {
		return false
	}
	source := "YAML"
	if strings.HasPrefix(strings.TrimSpace(text), "{") || strings.HasPrefix(strings.TrimSpace(text), "[") {
		source = "JSON"
	}
	var walk func(*yaml.Node, string, string, int)
	walk = func(n *yaml.Node, key, service string, depth int) {
		if depth > 16 || n.Kind == yaml.AliasNode {
			return
		}
		switch n.Kind {
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				k := n.Content[i]
				if k.Kind != yaml.ScalarNode {
					continue
				}
				group := service
				if known := prefixServices[strings.ToUpper(k.Value)]; known != "" {
					group = known
				}
				walk(n.Content[i+1], k.Value, group, depth+1)
			}
		case yaml.SequenceNode:
			for _, child := range n.Content {
				walk(child, key, service, depth+1)
			}
		case yaml.ScalarNode:
			if n.Tag != "!!str" && n.Tag != "!!int" && n.Tag != "!!bool" && n.Tag != "!!float" {
				return
			}
			name := normalizeName(key)
			if key == "" {
				*line = n.Line
				parseBareValue(n.Value, add)
				return
			}
			if name == "" || len(name) > 128 {
				return
			}
			if service != "" && serviceFor(name) == "" {
				name = strings.ToUpper(service) + "_" + name
			}
			*line = n.Line
			add(Suggestion{Name: name, Value: n.Value, Service: service, Source: source})
		}
	}
	walk(root, "", "", 0)
	return true
}

func envValue(value string) string {
	if strings.HasPrefix(strings.TrimSpace(value), "\"") || strings.HasPrefix(strings.TrimSpace(value), "'") {
		return value
	}
	if pos := strings.Index(value, " #"); pos >= 0 {
		return strings.TrimSpace(value[:pos])
	}
	return value
}

func parseCurl(tokens []string, add func(Suggestion)) {
	for i := 1; i < len(tokens); i++ {
		token := tokens[i]
		if (token == "-H" || token == "--header") && i+1 < len(tokens) {
			i++
			key, value, ok := strings.Cut(tokens[i], ":")
			if !ok {
				continue
			}
			key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
			if key == "authorization" {
				add(Suggestion{Name: "AUTHORIZATION", Value: value, Source: "curl header"})
			} else if key == "x-api-key" || key == "api-key" {
				add(Suggestion{Name: "API_KEY", Value: value, Source: "curl header"})
			}
		} else if (token == "-u" || token == "--user") && i+1 < len(tokens) {
			i++
			add(Suggestion{Name: "HTTP_CREDENTIALS", Value: tokens[i], Source: "curl credentials"})
		} else if urlValue.MatchString(token) {
			add(Suggestion{Name: "BASE_URL", Value: token, Source: "curl URL"})
		}
	}
}
