# SESSION-4-REPORT — Structured Output + Completeness + Coverage + Rule Accounting (Parts 8–11)

**Phase:** TI-2
**Session:** 4
**Date:** 2026-08-21
**Repo:** mcp-tenant-isolation
**Commit cadence:** Uncommitted in working tree (per agreed cadence; Session 8 creates release branch)

## Parts addressed

- **Part 8 — Structured output (typed structuredContent with bounded fields)**
- **Part 9 — Completeness semantics (COMPLETE/PARTIAL/ERROR)**
- **Part 10 — Coverage and accounting fields**
- **Part 11 — Rule accounting**

## Defects closed

| Defect | Title | Status |
|---|---|---|
| D-12 | Parser failures caught and logged, not tracked | CLOSED — parse failures now recorded in `CoverageInfo.parseFailureDetails` and affect `completeness` |
| D-13 | Rule failures caught and logged, not tracked | CLOSED — rule failures now recorded in `CoverageInfo.ruleFailureDetails` and affect `completeness` |
| D-14 | No completeness state | CLOSED — `CompletenessState` type added; scanner computes COMPLETE/PARTIAL based on failures |
| D-15 | No coverage/accounting metadata | CLOSED — `CoverageInfo` type added with full file/rule accounting |
| D-16 | MCP returns JSON-in-text, no structuredContent | CLOSED — `structuredContent` with `outputSchema` (zod) added to scan tool |

## Changes

### Types (Part 8-11)

**`src/types.ts`:**
- Added `CompletenessState` type: `'COMPLETE' | 'PARTIAL' | 'ERROR'`
- Added `CoverageInfo` interface with file accounting (filesDiscovered, filesParsed, parseFailures, parseFailureDetails, excludedPaths, unsupportedPaths) and rule accounting (rulesAvailable, rulesSelected, rulesEvaluated, rulesFailed, ruleFailureDetails, rulesTriggered)
- Added `ParseFailure` and `RuleFailure` detail types
- Extended `ScanResult` with `completeness`, `completenessReasons`, `coverage`, `limitations` fields

### Scanner (Part 9-11)

**`src/engine/scanner.ts`:**
- Parse loop: tracks `parseFailures` array and `unsupportedCount`
- Parse failures from `parseJsFile.parseError` field are recorded
- Rule evaluation loop: tracks `rulesEvaluated` count and `ruleFailures` array
- Completeness computation:
  - `COMPLETE`: 0 parse failures and 0 rule failures
  - `PARTIAL`: any parse failures or rule failures
  - `ERROR`: reserved for scan-cannot-run scenarios (not triggered in normal operation)
- Limitations always include:
  - Static analysis only (no runtime verification)
  - Flow analysis scope (intra-procedural or not required)
- Coverage info populated with all accounting fields

### Parser (Part 9 enabler)

**`src/parsers/js-parser.ts`:**
- Added `parseError?: string` field to `JsParseResult`
- Catch block now records the error message instead of silently swallowing it
- This allows the scanner to detect parse failures even when babel's `errorRecovery: true` is enabled

### MCP Server (Part 8)

**`src/mcp/server.ts`:**
- Added `scanOutputSchema` (zod) with all structured output fields:
  - `schemaVersion`, `producerId`, `verdict`, `completeness`, `completenessReasons`
  - `summary` (totalFindings, activeFindings, suppressedFindings, bySeverity, filesScanned, rulesEvaluated, durationMs)
  - `findings` (bounded array with ruleId, title, severity, file, line, description, missingGuards, fingerprint, suppressionStatus)
  - `truncation` (findingsReturned, findingsTotal, truncated)
  - `coverage` (all CoverageInfo fields)
  - `limitations`
- Scan tool now returns `structuredContent` alongside concise text summary
- Verdict computation: ERROR → BLOCK (CRITICAL/HIGH) → REVIEW (MEDIUM/LOW) → PASS (no active findings)
- Output bounding: default 20 findings with truncation metadata preserving exact totals
- `isError: true` only when verdict is ERROR (not for BLOCK/REVIEW — those are valid findings)

### Tests

**`tests/completeness.test.ts`** (new, 13 tests):
- Completeness: COMPLETE with no failures, PARTIAL with parse failures, COMPLETE for empty project
- Coverage: filesDiscovered/filesParsed populated, parseFailures count and details, rulesAvailable/Selected/Evaluated, rulesTriggered, unsupportedPaths with custom config, rulesFilter in accounting
- Limitations: static-analysis-only limitation, flow analysis limitation
- Structured output shape: all required fields present, coverage with all accounting fields

## Verification results

| Check | Result |
|---|---|
| typecheck | PASS (0 errors) |
| lint | PASS (0 errors, 4 pre-existing warnings) |
| tests | 159 passed, 0 failed (10 test files; was 146, +13 new) |
| build | PASS |
| stdio smoke test: `tools/call scan_tenant_isolation` | PASS — returns `structuredContent` with verdict, completeness, coverage, limitations, truncation |

### stdio smoke test details

Self-scan of the mcp-tenant-isolation repo:
- `verdict: "BLOCK"` (4 CRITICAL, 4 MEDIUM findings — MCP-001 and MCP-005 on own server)
- `completeness: "COMPLETE"` (0 parse failures, 0 rule failures)
- `coverage`: 29 files discovered, 29 parsed, 57 rules available, 57 evaluated, 4 triggered
- `truncation`: 8 returned, 8 total, not truncated
- `limitations`: flow analysis + static analysis only
- `isError: false` (BLOCK is a valid verdict, not an error)

## Downstream effects analyzed

| Component | Effect | Status |
|---|---|---|
| `src/reporters/index.ts` | Uses `result.stats`, `result.findings`, `result.ir`, `result.durationMs` — all still present. New fields are additive. | NO BREAK |
| `src/cli/index.ts` | Uses `result.findings` only — new fields are additive. | NO BREAK |
| `src/index.ts` (public API) | Exports `ScanResult`, `ScanStats` types — extended additively. | NO BREAK |
| `tests/mcp-server.test.ts` | Uses `result.stats` — still present. | NO BREAK |
| `tests/scanner.test.ts` | Uses `result.findings`, `result.stats` — still present. | NO BREAK |

## Architectural decisions

1. **Parse failures are signaled, not thrown.** The JS parser uses `errorRecovery: true` and catches errors internally. Instead of changing this behavior (which could break existing tests), the parser now returns a `parseError` field. The scanner checks this field and records the failure. This preserves backward compatibility while enabling completeness tracking.

2. **Completeness is PARTIAL, not ERROR, for parse/rule failures.** ERROR is reserved for scan-cannot-run scenarios (e.g., project root doesn't exist). PARTIAL means the scan ran but some files/rules couldn't be processed. This distinction is important for consumers: PARTIAL results are still usable with caveats; ERROR results are not.

3. **Output bounding defaults to 20 findings.** The full totals are preserved in `truncation.findingsTotal`. This prevents unbounded findings from flooding agent contexts while maintaining accurate counts. Concern-family grouping (Part 12) will be added in Session 6.

4. **Verdict is advisory, not enforcement.** BLOCK means "high-severity findings exist" — it's not a deployment gate. The `isError` flag is only true for ERROR completeness, not BLOCK. This prevents MCP clients from treating security findings as tool errors.

5. **Limitations are always present.** Even a COMPLETE scan has limitations (static analysis only, flow analysis scope). This prevents consumers from assuming COMPLETE means "perfect analysis."

## What was NOT done in this session (deferred to later sessions)

- **Concern families** (Part 12) — Session 6. Findings are bounded but not grouped by concern family yet.
- **Rulepack manifest/digests** (Parts 21-22) — Session 4/6. `rulesAvailable` counts rules but doesn't include rulepack version/digest.
- **Fingerprint v2** (Part 16) — Session 5. Fingerprints are still v1 (line-dependent).
- **Receipt/Evidence Envelope** (Parts 17-20) — Session 6. Structured output has the fields but no receipt/envelope yet.
- **Reporters updated** — Session 7. Reporters still use old output format; will be updated to include completeness/coverage.
- **ERROR completeness scenario** — Not triggered in normal operation. Would require a scan-level failure (e.g., project root doesn't exist). The scanner currently throws in that case rather than returning ERROR. This will be addressed in Session 6 when receipts need to record ERROR states.

## Holds preserved

- `MCP_TO_SAAS_EVIDENCE_INGESTION_HOLD` — no cloud calls
- No `@haiec/evidence-core` creation
- No HAIEC SaaS connection
- No ai-appsec runtime dependency
- `PRODUCER_LOCAL_V2_CONFORMANCE`

## Post-review gap fixes (added during Session 4 review)

Three gaps were identified during review and fixed before proceeding to Session 5:

1. **Reporters did not include completeness/coverage/limitations** — `jsonReporter`, `aiJsonReporter`, `terminalReporter`, and `markdownReporter` all used only `result.stats` and `result.findings`. The new `completeness`, `completenessReasons`, `coverage`, and `limitations` fields were not surfaced to CLI users. Fixed: all four reporters now include the new fields. Terminal and markdown reporters show completeness state when non-COMPLETE. JSON and AI JSON reporters include full coverage and limitations arrays.

2. **`tests/reporters.test.ts` fixtures missing new ScanResult fields** — `makeScanResult()` constructed `ScanResult` without `completeness`, `completenessReasons`, `coverage`, or `limitations`. This caused 13 test failures when reporters accessed the new fields. Fixed: `makeScanResult()` now includes all required fields with COMPLETE defaults.

3. **Downstream effect analysis confirmed:** The `getVerdict()` function in reporters still uses PASS/FAIL (not the MCP server's PASS/REVIEW/BLOCK/ERROR). This is intentional — CLI reporters use a simpler binary verdict for exit-code semantics. The MCP server uses the richer verdict model for agent consumption. These are separate output contracts and should not be unified.

## Exit status

`SESSION_4_COMPLETE` — Parts 8-11 implemented and verified. 5 defects closed (D-12, D-13, D-14, D-15, D-16). Structured output with completeness, coverage, and rule accounting working via stdio. 13 new tests. All verification passes. No commits made (per agreed cadence).

## Cumulative progress (Sessions 1-4)

- **17 of 25 defects closed** (D-01 through D-08, D-09, D-10, D-11, D-12, D-13, D-14, D-15, D-16, D-21)
- **159 tests passing** (was 119 baseline)
- MCP v2 SDK with structured output
- Security boundary + write governance complete
- Completeness + coverage + rule accounting complete
- No commits made (per agreed cadence — Session 8 creates release branch)
