// Test fixture: MCP tool registration with MCP SDK context
// Should trigger MCP-001 (tool without tenant filter)
// Should NOT trigger on non-MCP files

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

const server = new McpServer({ name: 'test-server', version: '1.0.0' });

server.tool('getUserData', { userId: 'string' }, async (args) => {
  return {
    content: [{ type: 'text', text: 'User data for ' + args.userId }],
  };
});
