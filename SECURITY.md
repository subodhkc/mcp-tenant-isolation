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

### Transport (v2.0.0)

- The MCP server uses **stdio transport only**. SSE transport was removed in v2.0.0.
- The server does not bind to any network port. It communicates over stdin/stdout.
- No network requests are made during scanning or MCP operation.

### Path boundary enforcement (v2.0.0)

All filesystem operations during MCP scans are constrained to the project root configured at server startup. The `PathBoundary` class enforces:

- **Path traversal rejection** — `../` sequences that escape the project root are rejected.
- **Symlink escape detection** — symlinks that resolve outside the project root are rejected via `realpath`.
- **UNC/network path rejection** — `\\server\share` paths are rejected on Windows.
- **Windows case-insensitive normalization** — path comparisons are case-insensitive on Windows.
- **Absolute path containment** — absolute paths outside the project root are rejected.

This boundary applies to: scan paths, config files, suppression files, baseline files, custom rulepack paths, and output file paths.

### Write-tool gating (v2.0.0)

The MCP server is **read-only by default**. Three tools are always available:

- `scan_tenant_isolation` — read-only scan
- `list_tenant_isolation_rules` — read-only rule listing
- `explain_tenant_isolation_rule` — read-only rule details

The suppression tool (`suppress_tenant_isolation_finding`) is only registered when the server is started with `--allow-write-tools`. Without that flag, the write tool does not exist in the MCP tool list.

### Data handling

- Suppression files (`.mti-suppressions.json`) are project-local and should be reviewed in code review.
- Baseline files (`.mti-baseline.json`) contain finding fingerprints and file paths — no sensitive data.
- The scanner does not collect telemetry or send scan results anywhere.

### Supply chain (v2.0.0)

- **npm Trusted Publishing** — packages are published via GitHub Actions OIDC, not long-lived tokens. Each publish uses a short-lived, workflow-specific credential.
- **Provenance attestations** — every published package includes a signed provenance statement in the sigstore transparency log.
- **0 npm audit vulnerabilities** — dependencies are audited on every CI run.
- **Lockfile committed** — CI uses `npm ci` for reproducible installs.

## Dependency Security

- `@babel/parser` — used for AST parsing, runs in Node.js process
- `commander` — CLI framework
- `@modelcontextprotocol/server` — MCP server transport (v2 SDK, stdio)
- `zod` — schema validation for MCP tool input schemas
- `fast-glob` — file discovery

All dependencies are pinned in `package.json`. Run `npm audit` regularly.
