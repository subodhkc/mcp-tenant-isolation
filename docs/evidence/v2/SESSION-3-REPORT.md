# SESSION-3-REPORT — MCP SDK v2 Migration + Legacy SSE Removal + Node Support (Parts 5–7)

**Phase:** TI-2
**Session:** 3
**Date:** 2026-08-21
**Repo:** mcp-tenant-isolation
**Commit cadence:** Uncommitted in working tree (per agreed cadence; Session 8 creates release branch)

## Parts addressed

- **Part 5 — Remove/deprecate legacy SSE transport**
- **Part 6 — MCP SDK v2 migration**
- **Part 7 — Node support and CI matrix**

## Defects closed

| Defect | Title | Status |
|---|---|---|
| D-06 | Legacy SSE `/sse` + `/message` endpoints retained | CLOSED — SSE transport fully removed; v2.0 is stdio-only |
| D-07 | SDK dependency `^1.0.0` (monolithic v1) | CLOSED — migrated to `@modelcontextprotocol/server@2.0.0` (v2 split) |
| D-08 | Node `>=18.0.0` declaration | CLOSED — updated to `>=22.0.0` |
| D-21 | Unsupported compliance keywords in package.json | CLOSED — removed `soc2`, `iso27001`, `hipaa`, `gdpr` keywords (Part 25, batched here) |

## Changes

### MCP SDK v2 migration (Part 6)

**Before (v1 monolithic):**
```ts
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const server = new Server({ name, version }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, ...);
server.setRequestHandler(CallToolRequestSchema, ...);
```

**After (v2 split):**
```ts
import { McpServer } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';

const server = new McpServer({ name, version });
server.registerTool('tool_name', { description, inputSchema: z.object({...}), annotations }, async (args) => {...});
```

Key v2 changes:
- `McpServer` class replaces `Server`
- `registerTool()` replaces `setRequestHandler(ListToolsRequestSchema)` + `setRequestHandler(CallToolRequestSchema)`
- Zod schemas replace raw JSON Schema objects for input
- Tool annotations are passed directly in `registerTool()` options
- `StdioServerTransport` imported from `@modelcontextprotocol/server/stdio`
- No more manual `TOOLS` array + switch/case dispatch

### Legacy SSE removal (Part 5)

- Removed `SSEServerTransport` import
- Removed `createServer` (HTTP server) import
- Removed `/sse` and `/message` endpoint handling
- Removed `transport` and `port` from `McpServerOptions`
- Removed `--transport` and `--port` CLI options
- `server.json` already used stdio only — no change needed
- v2.0 is stdio-only. Remote transport (Streamable HTTP) deferred unless a real business requirement exists.

### Node support and CI matrix (Part 7)

- `engines.node`: `>=18.0.0` → `>=22.0.0`
- `@types/node`: `^20.11.0` → `^22.0.0`
- CI matrix updated:
  - Node: `22.x`, `24.x` (required) + `26.x` canary (experimental, `continue-on-error`)
  - OS: `ubuntu-latest`, `windows-latest`, `macos-latest` (cross-platform matrix)
  - `fail-fast: false` to see all failures
  - Reduced matrix size by excluding some OS×Node combinations
- Deps-check and publish jobs updated to Node 22.x

### Package keywords cleanup (Part 25, batched)

Removed unsupported compliance keywords from `package.json`:
- `soc2`
- `iso27001`
- `hipaa`
- `gdpr`

These implied the scanner certifies compliance, which it does not. `privacy` retained (generic, not a compliance claim).

### MCP context pattern update

`src/parsers/js-parser.ts` — added `@modelcontextprotocol/server` to `MCP_CONTEXT_PATTERNS` so the scanner recognizes v2 SDK imports in scanned code (not just v1).

### README update

- Updated SDK reference: `@modelcontextprotocol/sdk (stdio transport)` → `@modelcontextprotocol/server v2 (stdio transport)`

## Files modified

| File | Changes |
|---|---|
| `src/mcp/server.ts` | Full rewrite: v2 `McpServer` + `registerTool` + zod schemas; SSE removed; stdio-only; tool annotations; boundary enforcement preserved; `READ_ONLY_TOOL_NAMES`/`WRITE_TOOL_NAME`/`TOOL_ANNOTATIONS` exported for testability |
| `src/cli/index.ts` | `mcp` command: removed `--transport` and `--port` options; stdio-only |
| `src/parsers/js-parser.ts` | Added `@modelcontextprotocol/server` to MCP context patterns |
| `package.json` | `engines.node` → `>=22.0.0`; `@types/node` → `^22.0.0`; removed `@modelcontextprotocol/sdk`; added `@modelcontextprotocol/server@^2.0.0` + `zod@^4.4.3`; removed compliance keywords |
| `.github/workflows/ci.yml` | Node matrix 22/24 + 26 canary; OS matrix ubuntu/windows/macos; `fail-fast: false`; deps-check/publish jobs to Node 22 |
| `README.md` | SDK reference updated to v2 |
| `tests/mcp-server.test.ts` | Updated imports for new exports; write-gate tests adapted to v2 API |

## Verification results

| Check | Result |
|---|---|
| typecheck (`tsc --noEmit`) | PASS (0 errors) |
| lint (`eslint src`) | PASS (0 errors, 4 pre-existing warnings — down from 19; v2 migration eliminated most `(args as any)` casts) |
| tests (`vitest run`) | 146 passed, 0 failed (9 test files) |
| build (`tsc`) | PASS |
| stdio smoke test: `initialize` | PASS — returns `protocolVersion: 2025-06-18`, `serverInfo: {name: mcp-tenant-isolation, version: 1.6.2}` |
| stdio smoke test: `tools/list` (default) | PASS — 3 read-only tools, no suppress tool, all `readOnlyHint: true` |
| stdio smoke test: `tools/list` (`--allow-write-tools`) | PASS — 4 tools including suppress with `readOnlyHint: false`, `destructiveHint: true`, `documentedApprover` required |

## Architectural decisions

1. **Stdio-only for v2.0.** Remote transport (Streamable HTTP) is deferred unless a real business requirement exists. The legacy SSE implementation was incomplete and misleading. Removing it eliminates a maintenance burden and a false transport claim.

2. **Zod schemas for input validation.** The v2 SDK uses zod for input schemas, which are automatically converted to JSON Schema in the protocol output. This is more type-safe than the v1 raw JSON Schema objects.

3. **Tool registration is conditional.** The suppress tool is only registered when `allowWriteTools` is true. This is stronger than v1's approach of always listing the tool and rejecting calls — the tool doesn't exist at all in the protocol when write tools are disabled.

4. **Node 26 canary is experimental.** `continue-on-error: true` means Node 26 failures don't block the pipeline. This gives early visibility into Node 26 compatibility without blocking releases.

5. **Cross-platform CI matrix.** Tests now run on Windows, Linux, and macOS to catch platform-specific issues (especially path handling, which is critical for the PathBoundary implementation).

## What was NOT done in this session (deferred to later sessions)

- **Structured output** (Part 8) — Session 4. Scan still returns JSON-in-text; `structuredContent` with `outputSchema` will be added in Session 4.
- **Completeness/coverage** (Parts 9-11) — Session 4. Parser/rule failures still caught/skipped.
- **Stable fingerprint v2** (Part 16) — Session 5.
- **Receipts/Evidence Envelope** (Parts 17-20) — Session 6.
- **OWASP mapping corrections** (Part 24) — Session 5. Keywords removed here; full mapping document in Session 5.
- **README rewrite** (Part 26) — Session 7. Only the SDK reference was updated here.

## Holds preserved

- `MCP_TO_SAAS_EVIDENCE_INGESTION_HOLD` — no cloud calls
- No `@haiec/evidence-core` creation
- No HAIEC SaaS connection
- No ai-appsec runtime dependency
- `PRODUCER_LOCAL_V2_CONFORMANCE`
- Stable MCP Registry entry for v1.6.2 undisturbed (`server.json` unchanged)

## Post-review gap fixes (added during Session 3 review)

Five gaps were identified during review and fixed before proceeding to Session 4:

1. **`tests/fixtures/mcp-tool-registration.ts`** — still imported from `@modelcontextprotocol/sdk/server/mcp.js` (old SDK, uninstalled). Updated to use `@modelcontextprotocol/server` (v2) with `registerTool()` API. This fixture is scanned by the scanner's MCP context detection, so it must reflect current SDK patterns.

2. **`SECURITY.md:33`** — referenced `@modelcontextprotocol/sdk` in the dependency security list. Updated to `@modelcontextprotocol/server` (v2 SDK, stdio). Also added `zod` as a new runtime dependency entry.

3. **`Dockerfile:1,14`** — used `node:20-slim` base image. Updated to `node:22-slim` to match the new `engines.node >=22` requirement.

4. **`action.yml:28`** — used `node-version: 20`. Updated to `node-version: 22` to match the new engine requirement.

5. **Downstream effect analysis:** The `automerge.yml` workflow references the `deps-check` job name from `ci.yml` — this job still exists (updated to Node 22), so no break. The `docker.yml` workflow builds from the Dockerfile (now Node 22) — no direct Node version reference in the workflow itself. The `server.json` MCP registry file already used stdio transport only — no change needed. The `src/index.ts` public API exports `startMcpServer` which still exists with the same function signature (minus the removed `transport`/`port` options, which were optional).

## Exit status

`SESSION_3_COMPLETE` — Parts 5-7 implemented and verified. 4 defects closed (D-06, D-07, D-08, D-21). MCP SDK v2 migration complete with stdio-only transport. Node >=22 with cross-platform CI matrix. All verification passes including stdio smoke tests. No commits made (per agreed cadence).
