// Package agentcfg merges sm's MCP server entry into agent configuration
// files, preserving unrelated configuration. A backup is written next to any
// file that gets modified.
package agentcfg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/karthikmprakash/agents-secret-manager/internal/safeio"
	"gopkg.in/yaml.v3"
)

// MergeJSONMCPServers adds or replaces mcpServers["sm"] in a JSON config.
func MergeJSONMCPServers(path string, entry map[string]any) error {
	unlock, err := safeio.Lock(path + ".sm-lock")
	if err != nil {
		return err
	}
	defer unlock()
	root := map[string]any{}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(data) > 0 {
			if err := json.Unmarshal(data, &root); err != nil {
				return fmt.Errorf("%s: not plain JSON (%w) — edit it manually", path, err)
			}
		}
	case os.IsNotExist(err):
	default:
		return err
	}
	if root == nil {
		return fmt.Errorf("config must contain a JSON object")
	}

	servers, _ := root["mcpServers"].(map[string]any)
	if raw, exists := root["mcpServers"]; exists && raw != nil && servers == nil {
		return fmt.Errorf("mcpServers must be an object; config unchanged")
	}
	if servers == nil {
		servers = map[string]any{}
		root["mcpServers"] = servers
	}
	servers["sm"] = entry

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
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

// MergeYAMLMCPServers adds or replaces mcp_servers.<name> in a YAML config
// (Hermes). The document is edited as a node tree so comments and key order
// survive.
func MergeYAMLMCPServers(path, name string, entry map[string]any) error {
	unlock, err := safeio.Lock(path + ".sm-lock")
	if err != nil {
		return err
	}
	defer unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	root := &doc
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			root.Content = []*yaml.Node{{Kind: yaml.MappingNode}}
		}
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("%s: unexpected YAML root (not a mapping)", path)
	}

	servers := mappingValue(root, "mcp_servers")
	if servers == nil {
		servers = &yaml.Node{Kind: yaml.MappingNode}
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "mcp_servers"}, servers)
	}
	if servers.Kind != yaml.MappingNode {
		return fmt.Errorf("%s: mcp_servers is not a mapping", path)
	}

	var entryNode yaml.Node
	if err := entryNode.Encode(entry); err != nil {
		return err
	}
	replaced := false
	for i := 0; i+1 < len(servers.Content); i += 2 {
		if servers.Content[i].Value == name {
			servers.Content[i+1] = &entryNode
			replaced = true
			break
		}
	}
	if !replaced {
		servers.Content = append(servers.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: name}, &entryNode)
	}

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

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// UpsertYAMLBlock replaces the marker-delimited block that starts with
// "# <key>" and ends with "# /<key>", or appends it when absent. This is for
// configs that must not round-trip through a YAML encoder (custom !!js tags,
// comments, formatting); the result is validated by parsing before it lands.
func UpsertYAMLBlock(path, key, block string) error {
	unlock, err := safeio.Lock(path + ".sm-lock")
	if err != nil {
		return err
	}
	defer unlock()

	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	text := string(data)
	startMarker, endMarker := "# "+key, "# /"+key

	updated := ""
	if begin := strings.Index(text, startMarker+"\n"); begin >= 0 {
		rel := strings.Index(text[begin:], endMarker)
		if rel < 0 {
			return fmt.Errorf("%s: %q block has no end marker; edit it manually", path, key)
		}
		tail := text[begin+rel:]
		if nl := strings.Index(tail, "\n"); nl >= 0 {
			tail = tail[nl+1:]
		} else {
			tail = ""
		}
		updated = text[:begin] + block + tail
	} else if filled, ok := replaceTrailingEmptyList(text, block); ok {
		updated = filled
	} else {
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		if text != "" {
			text += "\n"
		}
		updated = text + block
	}

	var node yaml.Node
	if err := yaml.Unmarshal([]byte(updated), &node); err != nil {
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

// replaceTrailingEmptyList fills a file whose only content is "[]" instead of
// appending a second top-level document.
func replaceTrailingEmptyList(text, block string) (string, bool) {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	last := len(lines) - 1
	for last >= 0 && strings.TrimSpace(lines[last]) == "" {
		last--
	}
	if last < 0 || strings.TrimSpace(lines[last]) != "[]" {
		return "", false
	}
	out := strings.Join(lines[:last], "\n")
	if out != "" {
		out += "\n"
	}
	return out + block, true
}

// MergeTOMLMCPServers adds or replaces [mcp_servers.<name>] in a TOML config
// (Codex). Other tables, comments and formatting outside that table survive.
func MergeTOMLMCPServers(path, name string, entry map[string]any) error {
	unlock, err := safeio.Lock(path + ".sm-lock")
	if err != nil {
		return err
	}
	defer unlock()

	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(data) > 0 {
		var root map[string]any
		if _, err := toml.Decode(string(data), &root); err != nil {
			return fmt.Errorf("%s: not plain TOML; edit it manually", path)
		}
	}

	var block strings.Builder
	fmt.Fprintf(&block, "[mcp_servers.%s]\n", name)
	if err := toml.NewEncoder(&block).Encode(entry); err != nil {
		return err
	}

	updated := replaceTOMLTable(string(data), "mcp_servers."+name, block.String())
	var check map[string]any
	if _, err := toml.Decode(updated, &check); err != nil {
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

// replaceTOMLTable replaces a table's line span, or appends it when absent.
func replaceTOMLTable(text, table, block string) string {
	header := "[" + table + "]"
	lines := strings.Split(text, "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == header {
			start = i
			break
		}
	}
	if start == -1 {
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		if text != "" {
			text += "\n"
		}
		return text + block
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
	result = append(result, strings.Split(strings.TrimSuffix(block, "\n"), "\n")...)
	if end < len(lines) {
		result = append(result, lines[end:]...)
	}
	return strings.Join(result, "\n")
}

func backup(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	f, err := os.OpenFile(path+".sm-backup", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil
	} // keep the original, not our previous edit
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
