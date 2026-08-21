# Security Policy

## Scope

This policy covers the `mcp-tenant-isolation` npm package and its source code at https://github.com/subodhkc/mcp-tenant-isolation.

The scanner is a static analysis tool. It does not execute code from scanned projects. It parses source files and evaluates pattern-based rules.

## Reporting a Vulnerability

Email: security@haiec.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected version
- Potential impact

Response time: 48 hours for acknowledgment, 7 days for assessment.

## Security Considerations

- The scanner reads files from the filesystem. It does not make network requests except when configured as an MCP server with SSE transport.
- The MCP server binds to `127.0.0.1` by default. SSE transport is opt-in and requires explicit port configuration.
- Suppression files (`.mti-suppressions.json`) are project-local and should be reviewed in code review.
- Baseline files (`.mti-baseline.json`) contain finding fingerprints and file paths — no sensitive data.
- The scanner does not collect telemetry or send scan results anywhere.

## Dependency Security

- `@babel/parser` — used for AST parsing, runs in Node.js process
- `commander` — CLI framework
- `@modelcontextprotocol/server` — MCP server transport (v2 SDK, stdio)
- `zod` — schema validation for MCP tool input schemas
- `fast-glob` — file discovery

All dependencies are pinned in `package.json`. Run `npm audit` regularly.
