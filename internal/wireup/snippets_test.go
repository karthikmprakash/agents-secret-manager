package wireup

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

func TestSnippetsAreValidAndSelfContained(t *testing.T) {
	for _, s := range Snippets("/opt/sm/bin") {
		if len(s.Agents) == 0 || len(s.Files) == 0 || s.Body == "" {
			t.Errorf("incomplete snippet: %+v", s)
		}
		if !strings.Contains(s.Body, "/opt/sm/bin") {
			t.Errorf("%v snippet does not reference the binary:\n%s", s.Agents, s.Body)
		}
		switch s.Lang {
		case "json":
			var v map[string]any
			if err := json.Unmarshal([]byte(s.Body), &v); err != nil {
				t.Errorf("%v JSON snippet does not parse: %v", s.Agents, err)
			}
		case "toml":
			var v map[string]any
			if _, err := toml.Decode(s.Body, &v); err != nil {
				t.Errorf("%v TOML snippet does not parse: %v", s.Agents, err)
			}
		case "yaml":
			var v any
			if err := yaml.Unmarshal([]byte(s.Body), &v); err != nil {
				t.Errorf("%v YAML snippet does not parse: %v", s.Agents, err)
			}
		}
	}
}
