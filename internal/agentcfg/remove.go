package agentcfg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/karthikmprakash/agents-secret-manager/internal/safeio"
	"gopkg.in/yaml.v3"
)

// ParseJSONLoose accepts strict JSON and JSONC (// and /* */ comments).
// Comments are ignored for parsing; callers that write back should expect a
// normalized JSON document.
func ParseJSONLoose(data []byte) (map[string]any, error) {
	var root map[string]any
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]any{}, nil
	}
	if err := json.Unmarshal(data, &root); err == nil {
		return root, nil
	}
	stripped := stripJSONComments(data)
	if err := json.Unmarshal(stripped, &root); err != nil {
		return nil, err
	}
	return root, nil
}

// MergeJSONPath sets keys...name to entry in a JSON/JSONC file, creating
// intermediate objects when needed. Unrelated keys survive. Comments are not
// preserved when the input is JSONC; a .sm-backup file keeps the original.
func MergeJSONPath(path string, keys []string, name string, entry map[string]any) error {
	if len(keys) == 0 || name == "" {
		return fmt.Errorf("merge path is empty")
	}
	unlock, err := safeio.Lock(path + ".sm-lock")
	if err != nil {
		return err
	}
	defer unlock()

	root := map[string]any{}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		root, err = ParseJSONLoose(data)
		if err != nil {
			return fmt.Errorf("%s: not valid JSON or JSONC (%w)", path, err)
		}
	case os.IsNotExist(err):
	default:
		return err
	}
	if root == nil {
		root = map[string]any{}
	}
	node := root
	for _, key := range keys {
		child, ok := node[key]
		if !ok || child == nil {
			next := map[string]any{}
			node[key] = next
			node = next
			continue
		}
		next, ok := child.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: %s is not an object; config unchanged", path, strings.Join(keys, "."))
		}
		node = next
	}
	node[name] = entry

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if bytes.Equal(data, out) {
		return nil
	}
	if err := backup(path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return safeio.Write(path, out, 0o600)
}

// RemoveJSONPath deletes keys...name from a JSON/JSONC file. A missing path is
// not an error. Empty parent objects are left in place.
func RemoveJSONPath(path string, keys []string, name string) error {
	if len(keys) == 0 || name == "" {
		return fmt.Errorf("remove path is empty")
	}
	unlock, err := safeio.Lock(path + ".sm-lock")
	if err != nil {
		return err
	}
	defer unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	root, err := ParseJSONLoose(data)
	if err != nil {
		return fmt.Errorf("%s: not valid JSON or JSONC (%w)", path, err)
	}
	node := root
	for _, key := range keys {
		child, ok := node[key].(map[string]any)
		if !ok {
			return nil
		}
		node = child
	}
	if _, exists := node[name]; !exists {
		return nil
	}
	delete(node, name)
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if bytes.Equal(data, out) {
		return nil
	}
	if err := backup(path); err != nil {
		return err
	}
	return safeio.Write(path, out, 0o600)
}

// RemoveJSONMCPServers deletes mcpServers.sm.
func RemoveJSONMCPServers(path string) error {
	return RemoveJSONPath(path, []string{"mcpServers"}, "sm")
}

// RemoveYAMLMCPServers deletes mcp_servers.<name> from a YAML config. Comments
// and unrelated keys survive because the document is edited as a node tree.
func RemoveYAMLMCPServers(path, name string) error {
	unlock, err := safeio.Lock(path + ".sm-lock")
	if err != nil {
		return err
	}
	defer unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	root := &doc
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			return nil
		}
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("%s: unexpected YAML root (not a mapping)", path)
	}
	servers := mappingValue(root, "mcp_servers")
	if servers == nil || servers.Kind != yaml.MappingNode {
		return nil
	}
	index := -1
	for i := 0; i+1 < len(servers.Content); i += 2 {
		if servers.Content[i].Value == name {
			index = i
			break
		}
	}
	if index < 0 {
		return nil
	}
	servers.Content = append(servers.Content[:index], servers.Content[index+2:]...)

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	if bytes.Equal(data, out) {
		return nil
	}
	if err := backup(path); err != nil {
		return err
	}
	return safeio.Write(path, out, 0o600)
}

// RemoveTOMLTable deletes a [table] span, including nested keys, and validates
// the result before writing.
func RemoveTOMLTable(path, table string) error {
	unlock, err := safeio.Lock(path + ".sm-lock")
	if err != nil {
		return err
	}
	defer unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	text := string(data)
	header := "[" + table + "]"
	lines := strings.Split(text, "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == header {
			start = i
			break
		}
	}
	if start < 0 {
		return nil
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "[") {
			end = i
			break
		}
	}
	result := append([]string{}, lines[:start]...)
	result = append(result, lines[end:]...)
	updated := strings.Join(result, "\n")
	if _, err := toml.Decode(updated, &map[string]any{}); err != nil {
		return fmt.Errorf("%s: change would produce invalid TOML; config unchanged", path)
	}
	out := []byte(updated)
	if bytes.Equal(data, out) {
		return nil
	}
	if err := backup(path); err != nil {
		return err
	}
	return safeio.Write(path, out, 0o600)
}

// RemoveYAMLBlock deletes a marker-delimited block that starts with "# <key>"
// and ends with "# /<key>". A missing block is not an error.
func RemoveYAMLBlock(path, key string) error {
	unlock, err := safeio.Lock(path + ".sm-lock")
	if err != nil {
		return err
	}
	defer unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	text := string(data)
	startMarker, endMarker := "# "+key, "# /"+key
	begin := strings.Index(text, startMarker)
	if begin < 0 {
		return nil
	}
	rel := strings.Index(text[begin:], endMarker)
	if rel < 0 {
		return fmt.Errorf("%s: %q block has no end marker; edit it manually", path, key)
	}
	end := begin + rel + len(endMarker)
	if nl := strings.IndexByte(text[end:], '\n'); nl >= 0 {
		end += nl + 1
	} else {
		end = len(text)
	}
	updated := text[:begin] + text[end:]
	if _, err := yamlUnmarshalValid([]byte(updated)); err != nil {
		return fmt.Errorf("%s: change would produce invalid YAML; config unchanged", path)
	}
	if bytes.Equal(data, []byte(updated)) {
		return nil
	}
	if err := backup(path); err != nil {
		return err
	}
	return safeio.Write(path, []byte(updated), 0o600)
}

func yamlUnmarshalValid(data []byte) (any, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, err
	}
	return node, nil
}

// stripJSONComments removes // and /* */ comments outside strings so JSONC can
// be parsed with encoding/json. It is intentionally small: JSONC comments do
// not nest, and strings are handled byte by byte.
func stripJSONComments(data []byte) []byte {
	var out bytes.Buffer
	inString, escaped := false, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out.WriteByte(c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out.WriteByte(c)
			continue
		}
		if c == '/' && i+1 < len(data) {
			if data[i+1] == '/' {
				for i < len(data) && data[i] != '\n' {
					i++
				}
				out.WriteByte('\n')
				continue
			}
			if data[i+1] == '*' {
				i += 2
				for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
					i++
				}
				i++
				continue
			}
		}
		out.WriteByte(c)
	}
	return out.Bytes()
}
