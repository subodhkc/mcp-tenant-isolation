# SESSION-5-REPORT — Provenance + OWASP Remapping + Claims Cleanup + Fingerprint v2 + Proof-of-Fix (Parts 16, 24-25)

**Phase:** TI-2
**Session:** 5
**Date:** 2026-08-21
**Repo:** mcp-tenant-isolation
**Commit cadence:** Uncommitted in working tree (per agreed cadence; Session 8 creates release branch)

## Parts addressed

- **Part 16 — Stable fingerprint v2 + proof-of-fix**
- **Part 24 — OWASP remapping**
- **Part 25 — Claims cleanup**

## Defects closed

| Defect | Title | Status |
|---|---|---|
| D-17 | v1 fingerprints are line-dependent — unstable under formatting/line changes | CLOSED — v2 semantic fingerprints based on ruleId:file:normalizedCode:sortedGuards |
| D-18 | No proof-of-fix state | CLOSED — `ProofOfFixState` type added; scanner computes STILL_PRESENT/NEW/NOT_VERIFIABLE |
| D-19 | Invented OWASP MCP-SEC-01..15 references | CLOSED — remapped to official OWASP MCP Top 10 (MCP01:2025 through MCP10:2025) |
| D-25 | Broad claims: "no false guesses", competitor-binary, "same results every run" | CLOSED — README claims qualified with limitations |

## Changes

### Fingerprint v2 (Part 16)

**`src/rule-spec.ts`:**
- Added `generateFingerprintV2(ruleId, file, codeSnippet, missingGuards)`:
  - Identity: `v2:ruleId:file:normalizedCodeSnippet:sortedMissingGuards`
  - Normalization: all whitespace removed, lowercased
  - Stable under: line movement, whitespace changes, guard ordering
  - NOT stable under: file rename, rule ID change, semantic code change (all intentional)
- `buildFinding()` now uses v2 fingerprints and sets `fingerprintVersion: 2`
- `generateFingerprint()` (v1) retained for migration compatibility
- Added `migrateFingerprintV1ToV2()` — fails closed (returns v1) if v1 fingerprint doesn't match expected

**`src/types.ts`:**
- Added `fingerprintVersion?: number` to `Finding`
- Added `proofOfFix?: ProofOfFixState` to `Finding`
- Added `ProofOfFixState` type: `'STILL_PRESENT' | 'RESOLVED_CONFIRMED' | 'NEW' | 'NOT_VERIFIABLE'`
- Added `fingerprintVersion?: number` to `BaselineFingerprint`

### Proof-of-Fix (Part 16)

**`src/engine/scanner.ts`:**
- Baseline comparison now computes proof-of-fix states:
  - `STILL_PRESENT`: finding exists in both baseline and current scan
  - `NEW`: finding exists in current scan but not in baseline
  - `NOT_VERIFIABLE`: no baseline file exists (fail closed)
- `hasBaseline` now checks file existence, not just fingerprint count (empty baseline = all NEW)
- Resolved count computed: fingerprints in baseline but not in current scan
- Limitations include proof-of-fix summary when baseline present

**`src/cli/index.ts`:**
- Baseline command now records `fingerprintVersion` in baseline entries

### OWASP Remapping (Part 24)

**`src/rules/mcp.ts`:**
- All 15 `owaspMcpRef` values updated from invented `OWASP MCP-SEC-01..15` to official OWASP MCP Top 10:

| Rule | Old Ref | New Ref | OWASP Category |
|---|---|---|---|
| MCP-001 | OWASP MCP-SEC-01 | MCP09:2025 | Shadow MCP Servers |
| MCP-002 | OWASP MCP-SEC-02 | MCP10:2025 | Context Injection & Over-Sharing |
| MCP-003 | OWASP MCP-SEC-03 | MCP01:2025 | Token Mismanagement & Secret Exposure |
| MCP-004 | OWASP MCP-SEC-04 | MCP07:2025 | Insufficient Authentication & Authorization |
| MCP-005 | OWASP MCP-SEC-05 | MCP02:2025 | Privilege Escalation via Scope Creep |
| MCP-006 | OWASP MCP-SEC-06 | MCP10:2025 | Context Injection & Over-Sharing |
| MCP-007 | OWASP MCP-SEC-07 | MCP07:2025 | Insufficient Authentication & Authorization |
| MCP-008 | OWASP MCP-SEC-08 | MCP06:2025 | Intent Flow Subversion |
| MCP-009 | OWASP MCP-SEC-09 | MCP05:2025 | Command Injection & Execution |
| MCP-010 | OWASP MCP-SEC-10 | MCP10:2025 | Context Injection & Over-Sharing |
| MCP-011 | OWASP MCP-SEC-11 | MCP02:2025 | Privilege Escalation via Scope Creep |
| MCP-012 | OWASP MCP-SEC-12 | MCP10:2025 | Context Injection & Over-Sharing |
| MCP-013 | OWASP MCP-SEC-13 | MCP05:2025 | Command Injection & Execution |
| MCP-014 | OWASP MCP-SEC-14 | MCP09:2025 | Shadow MCP Servers |
| MCP-015 | OWASP MCP-SEC-15 | MCP08:2025 | Lack of Audit and Telemetry |

**`docs/OWASP-MAPPING.md`** (new):
- Full mapping document with rationale for each rule-to-OWASP mapping
- Notes that multiple rules may map to the same OWASP category
- Notes that MCP03:2025 (Tool Poisoning) and MCP04:2025 (Supply Chain) are not directly addressed — scope limitation
- Explicit disclaimer: mappings are for triage/reporting, NOT compliance certification

### Claims Cleanup (Part 25)

**`README.md`:**
- Removed competitor-binary claim: "General-purpose security scanners (Snyk, Semgrep, CodeQL) do not understand..." → "General-purpose security scanners are not purpose-built for..."
- Removed "No machine learning, no false guesses" → replaced with deterministic claim + limitations reference
- Removed "You get the same results every run" → replaced with "given the same source code, the scanner produces the same findings"
- Added explicit static analysis limitations paragraph with reference to `limitations` field in scan output

### Public API

**`src/index.ts`:**
- Added exports: `generateFingerprintV2`, `migrateFingerprintV1ToV2`

### Tests

**`tests/fingerprint-v2.test.ts`** (new, 14 tests):
- Fingerprint v2: line movement stability, whitespace stability, guard ordering stability, code change detection, rule ID change detection, file path change detection, format verification, v1 vs v2 difference
- Migration: v1→v2 success, fail-closed on mismatch
- buildFinding: fingerprintVersion = 2
- Proof-of-fix: NOT_VERIFIABLE (no baseline), NEW (empty baseline), STILL_PRESENT (matching baseline)

## Verification results

| Check | Result |
|---|---|
| typecheck | PASS (0 errors) |
| lint | PASS (0 errors, 4 pre-existing warnings) |
| tests | 173 passed, 0 failed (11 test files; was 159, +14 new) |
| build | PASS |

## Architectural decisions

1. **v2 fingerprint removes ALL whitespace, not just collapses it.** Code snippets like `{ }` and `{}` are semantically identical. Collapsing whitespace to a single space still leaves `{ }` ≠ `{}`. Removing all whitespace ensures these match. This is safe because whitespace doesn't change code semantics.

2. **Empty baseline = all NEW, not NOT_VERIFIABLE.** An empty baseline file means "zero known findings at baseline time" — so all current findings are NEW. NOT_VERIFIABLE is reserved for when no baseline file exists at all. This distinction matters for CI: an empty baseline is a valid state, not an error state.

3. **Proof-of-fix fails closed.** Without a baseline, proof-of-fix is NOT_VERIFIABLE, not assumed PASS. This prevents false confidence that findings have been resolved.

4. **OWASP mappings are advisory, not certification.** The mapping document explicitly states that mappings are for triage and reporting. Compliance certification requires additional controls beyond static analysis.

5. **Multiple rules can map to the same OWASP category.** The OWASP MCP Top 10 has 10 categories; the scanner has 15 MCP rules. Several rules map to MCP10:2025 (Context Injection & Over-Sharing) because that category covers multiple tenant isolation concerns (cache poisoning, vector store, tool output scoping).

## Downstream effects analyzed

| Component | Effect | Status |
|---|---|---|
| `src/reporters/index.ts` | Reporters don't show `fingerprintVersion` or `proofOfFix` yet — additive fields, no break | NO BREAK (will be surfaced in Session 7) |
| `src/engine/suppressions.ts` | Suppression matching uses `fingerprint` field — v2 fingerprints are different from v1, so existing suppressions with v1 fingerprints won't match v2 findings | KNOWN MIGRATION ISSUE (see below) |
| `tests/suppressions.test.ts` | Uses hardcoded fingerprints like `'abc123'` — not generated by `buildFinding`, so no break | NO BREAK |
| `tests/reporters.test.ts` | `makeScanResult` doesn't set `fingerprintVersion` or `proofOfFix` — optional fields | NO BREAK |
| `src/mcp/server.ts` | Scan output schema doesn't include `fingerprintVersion` or `proofOfFix` in findings — will be added in Session 6 | NO BREAK (additive) |

### Suppression migration note

Existing suppression files (`.mti-suppressions.json`) contain v1 fingerprints. After the v2 migration, `buildFinding` produces v2 fingerprints. Suppressions with v1 fingerprints will NOT match v2 findings. This is a known migration issue that will be addressed in Session 6 with a suppression migration tool or dual-lookup logic. For now, users who rely on suppressions should re-run `mti suppress` after upgrading to regenerate suppressions with v2 fingerprints.

## What was NOT done in this session (deferred to later sessions)

- **Suppression v1→v2 migration** — Session 6. Need dual-lookup or migration tool.
- **MCP server output includes fingerprintVersion/proofOfFix** — Session 6. Scan output schema needs updating.
- **Reporters show proof-of-fix** — Session 7. Terminal/markdown reporters should show proof-of-fix summary.
- **RESOLVED_CONFIRMED in output** — Session 6. Currently resolved findings are counted in limitations but not included as entries in the findings array (they're absent by definition). Evidence Envelope will record them.
- **Rulepack manifest/digests** — Session 6. `rulesAvailable` counts rules but doesn't include rulepack version/digest.

## Holds preserved

- `MCP_TO_SAAS_EVIDENCE_INGESTION_HOLD` — no cloud calls
- No `@haiec/evidence-core` creation
- No HAIEC SaaS connection
- No ai-appsec runtime dependency
- `PRODUCER_LOCAL_V2_CONFORMANCE`

## Post-review gap fixes (added during Session 5 review)

Four gaps were identified during review and fixed before proceeding to Session 6:

1. **MCP server and CLI suppress commands wrote `fingerprintVersion: 1`** — both `src/cli/index.ts:207` and `src/mcp/server.ts:470` hardcoded `fingerprintVersion: 1` when creating suppressions. Since `buildFinding` now generates v2 fingerprints, new suppressions must record `fingerprintVersion: 2` to match. Fixed: both updated to `fingerprintVersion: 2`.

2. **MCP scan output schema didn't include `fingerprintVersion` or `proofOfFix`** — the `scanOutputSchema` zod definition and the findings mapping in the scan handler only included `fingerprint` and `suppressionStatus`. Fixed: added `fingerprintVersion: z.number().optional()` and `proofOfFix: z.enum([...]).optional()` to the schema, and the handler now maps both fields from findings.

3. **Suppression v1→v2 migration warning** — `src/engine/suppressions.ts` `loadSuppressions()` silently loaded v1 suppressions that would never match v2 findings. Fixed: added a warning when v1 suppressions are detected, advising users to re-run `mti suppress` or match by `ruleId + filePath` instead of fingerprint.

4. **`SuppressionRule.fingerprintVersion` comment outdated** — said "Default 1 for legacy" but new suppressions now default to 2. Fixed: comment updated to "Default 2 for new suppressions."

## Exit status

`SESSION_5_COMPLETE` — Parts 16, 24, 25 implemented and verified. 4 defects closed (D-17, D-18, D-19, D-25). Stable v2 fingerprints, proof-of-fix states, correct OWASP mappings, qualified claims. 14 new tests. All verification passes. No commits made (per agreed cadence).

## Cumulative progress (Sessions 1-5)

- **21 of 25 defects closed** (D-01 through D-08, D-09 through D-19, D-21, D-25)
- **173 tests passing** (was 119 baseline)
- MCP v2 SDK with structured output + completeness + coverage
- Security boundary + write governance complete
- Stable v2 fingerprints + proof-of-fix
- Correct OWASP MCP Top 10 mappings
- Qualified claims in README
- No commits made (per agreed cadence — Session 8 creates release branch)
