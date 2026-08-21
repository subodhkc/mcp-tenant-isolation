# SESSION-2-REPORT — Security Boundary + MCP Write Governance (Parts 3–4)

**Phase:** TI-2
**Session:** 2
**Date:** 2026-08-21
**Repo:** mcp-tenant-isolation
**Commit cadence:** Uncommitted in working tree (per agreed cadence; Session 8 creates release branch)

## Parts addressed

- **Part 3 — Project-Root Security Boundary**
- **Part 4 — MCP Write-Tool Governance**

## Defects closed (D-IDs from CURRENT-DEFECT-REGISTER.md)

| Defect | Title | Status |
|---|---|---|
| D-01 | startMcpServer(projectRoot) root not enforced | CLOSED — `startMcpServer` now requires and enforces `projectRoot` via `PathBoundary.create()` |
| D-02 | scan tool accepts arbitrary path | CLOSED — scan path resolved through `boundary.resolve()`; outside-root → `TARGET_OUTSIDE_ALLOWED_ROOT` |
| D-03 | suppression tool accepts arbitrary path | CLOSED — suppress path + suppressions file resolved through boundary |
| D-04 | custom rulepack paths escape root | CLOSED — `loadRulePacks` accepts optional `PathBoundary`; MCP path enforces it; CLI fallback rejects lexically |
| D-05 | symlink/realpath escape | CLOSED — `PathBoundary.resolve()` does `fs.realpath` on existing targets; symlink escape → `SYMLINK_ESCAPE` |
| D-09 | approver is caller-supplied text | CLOSED — renamed to `documentedApprover`; description states it does NOT represent independent human verification |
| D-10 | rule-wide suppression | CLOSED — rule-wide suppression (no fingerprint) only honored when `permanentException: true` |
| D-11 | suppression schema omits concrete identity | CLOSED — `validateSuppression` now requires `fingerprint` (unless `permanentException`) + `ruleId` + expiry |

## Files created

| File | Purpose |
|---|---|
| `src/security/path-boundary.ts` | `PathBoundary` class: realpath-aware, symlink-aware, UNC-rejecting, Windows case-insensitive project-root containment. Error codes: `TARGET_OUTSIDE_ALLOWED_ROOT`, `SYMLINK_ESCAPE`, `INVALID_PATH`. |
| `tests/path-boundary.test.ts` | 15 adversarial tests: creation, traversal rejection, symlink escape, Windows case-insensitivity, missing-path handling. |
| `docs/evidence/v2/SESSION-2-REPORT.md` | This report. |

## Files modified

| File | Changes |
|---|---|
| `src/types.ts` | `SuppressionRule` extended: `documentedApprover`, `permanentException`, `fingerprintVersion`; `approvedBy` deprecated. |
| `src/engine/suppressions.ts` | `validateSuppression` rewritten: requires concrete fingerprint (unless permanent exception), ruleId, documentedApprover, expiry (or permanent exception with justification). `findMatchingSuppression`: rule-wide only if `permanentException: true`. |
| `src/mcp/server.ts` | `startMcpServer` enforces `PathBoundary` from `projectRoot`; scan/suppress resolve through boundary; write tool gated behind `allowWriteTools`; tool annotations (`readOnlyHint`, `destructiveHint`); `PathBoundaryError` surfaced with typed code; `READ_ONLY_TOOLS`/`WRITE_TOOL` exported for testability. |
| `src/engine/rule-pack-loader.ts` | `loadRulePacks` accepts optional `PathBoundary`; rejects rulepack paths that escape root. |
| `src/engine/scanner.ts` | `ScanOptions.boundary` added; passed to `loadRulePacks`. |
| `src/cli/index.ts` | `mcp` command: `--allow-write-tools` option. `suppress` command: `--documented-approver`, `--permanent-exception`, requires `--rule-id`. |
| `tests/suppressions.test.ts` | Updated validation tests for new schema; +7 new tests (fingerprint required, ruleId required, expiry required, past-expiry rejected, permanent exception accepted, permanent exception + expires rejected). |
| `tests/mcp-server.test.ts` | Updated suppress validation test for new schema; +8 write-gate tests (read-only tool count, write tool separation, annotations, documentedApprover required, ruleId required, permanentException supported, approver description wording). |

## Verification results

| Check | Result |
|---|---|
| typecheck (`tsc --noEmit`) | PASS (0 errors) |
| lint (`eslint src`) | PASS (0 errors, 19 pre-existing warnings — none in new files) |
| tests (`vitest run`) | 149 passed, 0 failed (was 119 baseline; +30 new tests) |

## Architectural decisions

1. **PathBoundary.resolve() does realpath BEFORE containment check for existing paths.** This handles Windows 8.3 short-name paths (e.g. `SUBODH~1` → `Subodh Kc`) that would otherwise cause false escapes. Non-existent paths (e.g. output files about to be written) use lexical containment only.

2. **Error code distinction:** `TARGET_OUTSIDE_ALLOWED_ROOT` for paths that are outside root both lexically and via realpath. `SYMLINK_ESCAPE` for paths that are lexically inside but realpath outside (symlink pointing out of root). This distinction is preserved even when realpath runs first.

3. **CLI fallback for rulepacks:** When no `PathBoundary` is provided (CLI `mti scan` without MCP), `loadRulePacks` does a lexical containment check as a fallback. The MCP path always provides the boundary for full realpath-aware containment.

4. **Tool annotations added in v1-compatible form.** The current SDK 1.30.0 supports `ToolAnnotations` (readOnlyHint, destructiveHint). These will be refined to the v2 schema form in Session 3 (MCP SDK v2 migration).

5. **`approvedBy` kept as deprecated fallback.** Existing suppression files with `approvedBy` still work (read as `documentedApprover` fallback). New suppressions should use `documentedApprover`. This preserves backward compat for the v1→v2 migration period.

## Post-review gap fixes (added during Session 2 review)

Three gaps were identified during review and fixed before proceeding to Session 3:

1. **Baseline read not boundary-constrained** — `scanner.ts` loaded baseline via `join(projectRoot, config.baseline)` without containment. A config value like `"baseline": "../../../etc/passwd"` would escape root. Fixed: baseline path now resolved through `boundary.resolve()` when boundary is provided; rejected paths are skipped with a warning (no fallback to unsafe path).

2. **Suppressions read not boundary-constrained** — `applySuppressions` loaded suppressions via `join(projectRoot, config.suppressions)` without containment. Same `../` escape risk. Fixed: suppressions path now resolved through `boundary.resolve()` when boundary is provided; rejected paths skip suppressions (no fallback to unsafe path).

3. **Glob discovery followed symlinks in MCP mode** — `fast-glob` used default `followSymbolicLinks: true`, so a symlink inside root pointing outside would have its target files scanned. Fixed: `followSymbolicLinks` set to `false` when boundary is provided (MCP mode); CLI mode keeps default behavior.

4. **Dynamic import in rule-pack-loader** — `import('node:path')` was inside the loop. Fixed: moved to static import at top of file.

## What was NOT done in this session (deferred to later sessions)

- **MCP SDK v2 migration** (Part 6) — Session 3. Tool annotations will be refined to v2 schema.
- **Legacy SSE removal** (Part 5) — Session 3. The SSE transport code still exists; the boundary is enforced regardless of transport.
- **Structured output** (Part 8) — Session 4. Scan still returns JSON-in-text; boundary enforcement is independent of output format.
- **Completeness/coverage** (Parts 9-11) — Session 4. Parser/rule failures still caught/skipped; will be tracked in completeness model.
- **Stable fingerprint v2** (Part 16) — Session 5. Suppressions use `fingerprintVersion: 1` for now; v2 semantic fingerprint migration in Session 5.
- **Custom rulepack schema validation** (Part 22) — Session 6. Root containment done; full schema/duplicate-ID/collision validation deferred.

## Holds preserved

- `MCP_TO_SAAS_EVIDENCE_INGESTION_HOLD` — no cloud calls
- No `@haiec/evidence-core` creation
- No HAIEC SaaS connection
- No ai-appsec runtime dependency (PathBoundary pattern adapted READ-ONLY from ai-appsec's `src/security/path-boundary.ts`; no import)
- `PRODUCER_LOCAL_V2_CONFORMANCE` — boundary implementation is local-only

## Exit status

`SESSION_2_COMPLETE` — Parts 3-4 implemented and verified. 8 defects closed (D-01, D-02, D-03, D-04, D-05, D-09, D-10, D-11). 30 new tests added. Typecheck + lint + all 149 tests pass. No commits made (per agreed cadence).
