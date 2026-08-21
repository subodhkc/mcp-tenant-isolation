// Test fixture: MCP tool registration with MCP SDK v2 context
// Should trigger MCP-001 (tool without tenant filter)
// Should NOT trigger on non-MCP files

import { McpServer } from '@modelcontextprotocol/server';

const server = new McpServer({ name: 'test-server', version: '1.0.0' });

server.registerTool(
  'getUserData',
  {
    description: 'Get user data',
    inputSchema: { userId: 'string' } as any,
  },
  async (args) => {
    return {
      content: [{ type: 'text' as const, text: 'User data for ' + args.userId }],
    };
  }
);
