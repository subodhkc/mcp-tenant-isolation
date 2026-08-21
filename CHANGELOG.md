# Changelog

## [2.0.0] - 2026-08

### Added
- MCP SDK v2 migration: `@modelcontextprotocol/server` with `registerTool()`, Zod input/output schemas, stdio transport only
- Structured MCP output (`structuredContent`) with bounded findings (20 default), completeness, coverage, limitations, concern families, and scan receipt
- Zod `outputSchema` for `scan_tenant_isolation` tool
- Completeness states: COMPLETE, PARTIAL, ERROR — parser and rule failures now affect completeness
- Coverage metadata: files discovered/parsed/failed, rules available/selected/evaluated/failed/triggered, excluded and unsupported paths
- Concern family aggregation: 8 families (Tenant Context, Data Isolation, Cache & Session, MCP Security, Secrets & Credentials, Vector & Storage, API & Access, Audit & Logging)
- Scan Receipt with rulepack digest, engine version, timestamp, and SHA-256 receipt hash for tamper detection
- Evidence Envelope with SHA-256 envelope hash for verifiable scan artifacts
- Fingerprint v2: semantic fingerprints stable under line movement and formatting changes
- Proof-of-fix states: STILL_PRESENT, RESOLVED_CONFIRMED, NEW, NOT_VERIFIABLE
- OWASP MCP Top 10 mapping (official 2025 categories MCP01:2025 through MCP10:2025)
- Path boundary enforcement: project-root containment, traversal prevention, symlink escape detection, UNC path rejection, Windows case-insensitive comparison, 8.3 short-name handling
- Write-tool gating: MCP server is read-only by default, suppression tool requires `--allow-write-tools` opt-in
- Custom rulepack validation: rule ID format, built-in collision protection, severity validation, required fields, 50-rule limit
- Suppression governance: documented approver field, compensating controls required, permanent exception support with justification
- Cross-platform CI matrix: Ubuntu, Windows, macOS with Node 22.x and 24.x, Node 26.x canary
- 95 new tests (203 total, up from 108): completeness, fingerprint-v2, path-boundary, session6, golden-corpus
- Flow analysis qualification documentation
- Docker and GitHub Action updated to Node 22

### Changed
- MCP transport: stdio only (legacy SSE removed — no `/sse`, `/message`, `--transport`, `--port`)
- Node.js requirement: `>=22.0.0` (was `>=18.0.0`)
- `RULE_ENGINE_VERSION` updated to `2.0.0`
- `schemaVersion` in structured output updated to `2.0.0`
- Reporters (terminal, JSON, AI JSON, Markdown) updated to include concern families and receipt digests
- README completely rewritten with accurate feature documentation

### Fixed
- IDOR-001 rule: was checking `sink.api` for `id:` substring, but `sink.api` only contains the callee name. Fixed to check `sink.argsVars` for `id` presence.
- Parser failure detection: Babel `errorRecovery: true` was silently swallowing parse errors. Added `parseError` field to `JsParseResult` and scanner now records parser failures in coverage.
- CI self-scan step: bash syntax without `shell: bash` declaration would fail on Windows runners. Added explicit `shell: bash`.
- Dockerfile: updated from `node:20-slim` to `node:22-slim` to match engine requirement.
- action.yml: updated from Node 20 to Node 22.
- SECURITY.md: updated dependency listing from `@modelcontextprotocol/sdk` to `@modelcontextprotocol/server`, added `zod`.
- npm audit: fixed high-severity transitive `nanoid` vulnerability (via vitest → vite → postcss → nanoid).

### Removed
- Legacy SSE transport (`SSEServerTransport`, `/sse`, `/message` endpoints)
- `--transport` and `--port` CLI flags for MCP server
- `@modelcontextprotocol/sdk` dependency (replaced by `@modelcontextprotocol/server`)
- Invented OWASP references (`OWASP MCP-SEC-01` through `OWASP MCP-SEC-15`) replaced with official `MCP01:2025` through `MCP10:2025`

## [1.6.2] - 2025-01

### Added
- 93 new tests across 7 test files (108 total, up from 15)
  - `reporters.test.ts` — 27 tests for JSON, SARIF, Terminal, AI JSON, Markdown reporters
  - `cli.test.ts` — 13 tests for CLI commands (scan, rules, init, version, help)
  - `scanner.test.ts` — 11 integration tests for scanner end-to-end behavior
  - `fp-filter.test.ts` — 8 tests for false positive filter logic
  - `suppressions.test.ts` — 13 tests for suppression validation and application
  - `mcp-server.test.ts` — 12 tests for MCP server tool logic
  - `rule-packs.test.ts` — 9 tests for custom rule pack loading
- `mcpName` field in `package.json` for MCP Registry submission
- `server.json` for MCP Registry submission
- `security-events: write` permission in CI workflow for SARIF upload

## [1.6.1] - 2025-01

### Added
- Markdown reporter (`--format markdown`) for shareable PR reports
- Pass/fail verdict in terminal and Markdown reports
- Suppressed and baseline counts in terminal output
- Remediation hints for all 57 rules (was 18/57)
- Rule context descriptions for all 57 rules (was 7/57)
- AI JSON summary now includes activeFindings, suppressedFindings, baselineFindings, verdict
- Pre-built GitHub Action (`action.yml`) — reference `subodhkc/mcp-tenant-isolation@v1`
- Advanced configuration docs in README (authHelpers, tenantGuards, modelScopes, rulePacks, framework)
- Report Formats section in README
- Configurable auth helpers and tenant guards via `.mtirc.json`
- Model scope classification (tenant, user, global) with config overrides
- Non-production path filtering (findings downgraded to INFO severity)
- Framework detection for Next.js App Router, Express, Fastify
- Baseline comparison in scan (marks pre-existing findings)
- Rule execution order sorting
- INFO severity level for non-production and informational findings
- JSON schema for `.mtirc.json` covering all config fields
- CHANGELOG.md, CONTRIBUTING.md, SECURITY.md

### Fixed
- `package.json` version bumped from 1.0.0 to 1.6.1
- `RULE_ENGINE_VERSION` now matches package.json version
- `aiJsonReporter` and `markdownReporter` exported from public API (`src/index.ts`)
- Silent `catch {}` blocks now log error context
- `MtiConfig.output` type aligned with CLI format options (includes `markdown`)
- CI self-scan fails on scanner errors (exit code 2) instead of `|| true`
- CI publish trigger changed to version tags (`v*.*.*`) instead of every main push
- `.gitignore` no longer blocks legitimate JS config files
- Scan result files excluded from git
- JSON schema version uses `RULE_ENGINE_VERSION` dynamically (was hardcoded "1.0")
- `ruleUrl` in AI JSON points to haiec.com landing page (was non-existent GitHub anchors)
- README roadmap updated to reflect current features (rule packs, AI format, Markdown)
- Flow graph conditionally built only when a rule requires it
- `SuppressionStatus` type includes `'baseline'` for baseline-marked findings

### Changed
- Rules now sorted by `executionOrder` before evaluation
- Terminal reporter separates active vs suppressed/baseline findings
- Terminal reporter shows remediation hints per finding
- Community files (CHANGELOG, CONTRIBUTING, SECURITY) and `action.yml` added to npm `files` field

## [1.0.0] - 2024-12

### Initial Release
- 57 rules (42 general multi-tenant + 15 MCP-specific)
- 6-stage pipeline: Parsers, IR, Rule Engine, FP Filter, Reporters, CLI/MCP Server
- Output formats: Terminal, JSON, SARIF 2.1.0
- MCP server with 4 tools for AI agent integration
- CLI with scan, init, rules, suppress, baseline, mcp commands
- Configurable via `.mtirc.json`
- Custom rule packs support
- Suppression system with approval workflow
- Baseline management
- GitHub Actions CI/CD integration
