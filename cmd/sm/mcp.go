package main

import (
	"context"
	"fmt"

	mcpserver "github.com/karthikmprakash/agents-secret-manager/internal/mcpserver"
)

// cmdMcp runs the stdio MCP server. Nothing may be printed to stdout while it
// runs — stdout is the protocol channel.
func cmdMcp(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("sm mcp takes no arguments")
	}
	return mcpserver.Run(context.Background(), version)
}
