# Changelog

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
