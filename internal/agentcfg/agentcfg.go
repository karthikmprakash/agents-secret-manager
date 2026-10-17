// Package agentcfg merges sm's MCP server entry into agent configuration
// files, preserving unrelated configuration. A backup is written next to any
// file that gets modified.
package agentcfg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// MergeJSONMCPServers adds or replaces mcpServers["sm"] in a JSON config.
func MergeJSONMCPServers(path string, entry map[string]any) error {
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

	servers, _ := root["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
		root["mcpServers"] = servers
	}
	servers["sm"] = entry

	if err := backup(path); err != nil {
		return err
	}
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}

// MergeYAMLMCPServers adds or replaces mcp_servers.<name> in a YAML config
// (Hermes). The document is edited as a node tree so comments and key order
// survive.
func MergeYAMLMCPServers(path, name string, entry map[string]any) error {
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

	if err := backup(path); err != nil {
		return err
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func backup(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return os.WriteFile(path+".sm-backup", data, 0o600)
}
