# SESSION-6-REPORT — Concern Families + Scan Receipt + Evidence Envelope + Rulepack Security (Parts 12, 17-20, 22-23)

**Phase:** TI-2
**Session:** 6
**Date:** 2026-08-21
**Repo:** mcp-tenant-isolation
**Commit cadence:** Uncommitted in working tree (per agreed cadence; Session 8 creates release branch)

## Parts addressed

- **Part 12 — Concern family aggregation**
- **Parts 17-18 — Scan Receipt (provenance + reproducibility)**
- **Parts 19-20 — Evidence Envelope (structured verifiable output)**
- **Part 22 — Rulepack identity/digest**
- **Part 23 — Custom rulepack security controls**

## Defects closed

| Defect | Title | Status |
|---|---|---|
| D-22 | No concern-family aggregation | CLOSED — 8 concern families map 27 rule categories |
| D-23 | No Scan Receipt / provenance | CLOSED — `ScanReceipt` with producer, engine version, rulepack digest, receipt hash |
| D-24 | No Evidence Envelope | CLOSED — `EvidenceEnvelope` bundles receipt + findings + coverage + limitations + hash |

## Changes

### Concern Families (Part 12)

**`src/engine/concern-families.ts`** (new):
- 8 concern families mapping 27 rule categories:
  - Tenant Context (1 category)
  - Data Isolation (3 categories)
  - Cache & Session (4 categories)
  - MCP Security (9 categories)
  - Secrets & Credentials (2 categories)
  - Vector & Storage (2 categories)
  - API & Access (1 category)
  - Audit & Logging (1 category)
- `getConcernFamily(category)` — maps category to family
- `aggregateConcernFamilies(findings, categoryLookup)` — produces `ConcernFamilySummary[]` sorted by total findings descending

**`src/types.ts`:**
- Added `ConcernFamily` type, `ConcernFamilySummary` interface
- Added `concernFamilies?: ConcernFamilySummary[]` to `ScanResult`

### Scan Receipt (Parts 17-18)

**`src/engine/receipt.ts`** (new):
- `computeRulepackDigest(rules)` — deterministic SHA-256 hash of rule IDs + versions + execution orders (Part 22)
- `buildScanReceipt(result, projectRoot, rulepackDigest)` — provenance metadata with:
  - schemaVersion, producerId, engineVersion, timestamp
  - projectRoot, durationMs, completeness, verdict
  - rulepackDigest, rulesAvailable, rulesSelected
  - filesDiscovered, filesParsed
  - totalFindings, activeFindings, suppressedFindings
  - receiptHash (SHA-256 of receipt content, tamper detection)
- `computeVerdict(result)` — PASS/REVIEW/BLOCK/ERROR based on completeness and finding severities
- `buildEvidenceEnvelope(result, projectRoot, rulepackDigest, concernFamilies, bound)` — bundles receipt + findings + coverage + limitations + hash

**`src/types.ts`:**
- Added `ScanReceipt` interface (17 fields + receiptHash)
- Added `EvidenceEnvelope` interface (receipt + concernFamilies + findings + truncation + coverage + limitations + envelopeHash)
- Added `receipt?: ScanReceipt` to `ScanResult`

### Rulepack Digest (Part 22)

- `computeRulepackDigest()` produces a 32-character hex hash
- Deterministic: sorts rules by ID before hashing
- Changes when rules are added/removed/modified
- Included in Scan Receipt for reproducibility verification

### Custom Rulepack Security (Part 23)

**`src/engine/rule-pack-loader.ts`:**
- Added `validateCustomRule()` function with:
  - Rule ID format validation: must match `PREFIX-NNN` (e.g., `CUST-001`)
  - Required field validation: id, title, description, category, severity, requiredGuards
  - Severity validation: must be one of INFO/LOW/MEDIUM/HIGH/CRITICAL
  - Built-in rule ID collision prevention
  - Maximum custom rule limit (50 rules)
- Rulepack structure validation: must have `rules` array
- Invalid rules are skipped with warnings (fail-open for scanning, fail-closed for invalid rules)

### Scanner Integration

**`src/engine/scanner.ts`:**
- Imports `aggregateConcernFamilies`, `computeRulepackDigest`, `buildScanReceipt`
- Computes concern families from findings using `getRuleById` for category lookup
- Computes rulepack digest from all rules (built-in + custom)
- Builds scan receipt and attaches to `ScanResult`
- Returns `concernFamilies` and `receipt` in scan result

### MCP Server

**`src/mcp/server.ts`:**
- `scanOutputSchema` extended with `concernFamilies` and `receipt` (optional)
- `structuredContent` includes both fields
- Text summary includes concern family breakdown and receipt digest

### Reporters

**`src/reporters/index.ts`:**
- `jsonReporter` now includes `concernFamilies` and `receipt` in JSON output

### Public API

**`src/index.ts`:**
- Added exports: `aggregateConcernFamilies`, `getConcernFamily`, `computeRulepackDigest`, `buildScanReceipt`, `buildEvidenceEnvelope`, `computeVerdict`

### Tests

**`tests/session6.test.ts`** (new, 19 tests):
- Concern families: category mapping, unknown category default, aggregation, suppressed counting, sorting, scan result integration
- Rulepack digest: determinism, change detection, order independence
- Scan receipt: field population, verdict computation, hash determinism
- Evidence envelope: complete envelope, finding bounds, hash determinism
- Custom rulepack security: invalid ID format, built-in collision, invalid severity, valid custom rulepack

## Verification results

| Check | Result |
|---|---|
| typecheck | PASS (0 errors) |
| lint | PASS (0 errors, 4 pre-existing warnings) |
| tests | 192 passed, 0 failed (12 test files; was 173, +19 new) |
| build | PASS |
| stdio smoke test | PASS — structuredContent includes concernFamilies (MCP Security: 8 findings, 2 rules) and receipt (rulepackDigest: 3b7cbee8..., receiptHash: 5fa83c3e...) |

## stdio smoke test details

Self-scan of the mcp-tenant-isolation repo:
- `concernFamilies`: [{family: "MCP Security", totalFindings: 8, activeFindings: 8, ruleIds: ["MCP-001", "MCP-005"]}]
- `receipt`: {schemaVersion: "1.0.0", producerId: "io.github.subodhkc/mcp-tenant-isolation", engineVersion: "1.6.2", verdict: "BLOCK", completeness: "COMPLETE", rulepackDigest: "3b7cbee8e88d0d4a5c1c8cf377f50c21", receiptHash: "5fa83c3eab2771f3d3083ae05b2afd3c"}
- Text summary shows: "Concern families: MCP Security: 8 active, 0 suppressed (2 rules)" and "Receipt: 3b7cbee8 (hash: 5fa83c3e)"

## Architectural decisions

1. **Concern families are advisory, not enforcement.** They group findings for triage but don't affect scan behavior. A finding's severity and verdict are independent of its concern family.

2. **Receipt hash is tamper-detection, not cryptographic authentication.** The SHA-256 hash allows consumers to verify that a receipt hasn't been modified after generation. It does NOT prove who generated it — that requires digital signatures (future work, not in this phase).

3. **Rulepack digest is deterministic and order-independent.** Rules are sorted by ID before hashing, so the same set of rules always produces the same digest regardless of declaration order. This enables reproducibility verification across scans.

4. **Custom rulepack validation is fail-closed for invalid rules, fail-open for scanning.** Invalid custom rules are rejected with warnings, but the scan continues with built-in rules. This prevents a bad custom rulepack from blocking security scanning while still rejecting the invalid rule.

5. **Evidence Envelope is a container, not a transport.** It structures the evidence but doesn't transmit it. Cloud ingestion is still on hold (`MCP_TO_SAAS_EVIDENCE_INGESTION_HOLD`).

## Downstream effects analyzed

| Component | Effect | Status |
|---|---|---|
| `src/reporters/index.ts` | JSON reporter includes concernFamilies and receipt — terminal/markdown don't yet | NO BREAK (additive) |
| `tests/reporters.test.ts` | Fixtures don't set concernFamilies/receipt — optional fields | NO BREAK |
| `src/mcp/server.ts` | Schema and handler updated | NO BREAK |
| `src/cli/index.ts` | CLI doesn't use concernFamilies/receipt directly — reporters handle output | NO BREAK |

## Holds preserved

- `MCP_TO_SAAS_EVIDENCE_INGESTION_HOLD` — no cloud calls
- No `@haiec/evidence-core` creation
- No HAIEC SaaS connection
- No ai-appsec runtime dependency
- `PRODUCER_LOCAL_V2_CONFORMANCE`

## Post-review gap fixes (added during Session 6 review)

Four gaps were identified during review and fixed before proceeding to Session 7:

1. **AI JSON reporter missing concernFamilies and receipt** — `aiJsonReporter` included completeness/coverage/limitations but not the new concern families or receipt. Fixed: added both fields to the AI JSON output.

2. **Terminal reporter missing concern families** — terminal output showed completeness and coverage but not concern family breakdown. Fixed: added "Concern Families" section showing top 5 families with active/suppressed counts.

3. **Markdown reporter missing concern families and receipt** — markdown report didn't include concern family table or receipt digest. Fixed: added "Findings by Concern Family" table and rulepack/receipt digest rows in the summary table.

4. **npm audit: nanoid high-severity vulnerability** — `nanoid@3.3.17` (transitive dev dependency via vitest → vite → postcss) had a high-severity advisory (GHSA-2v37-7h3g-55p8). Fixed via `npm audit fix` — updated to patched version. 0 vulnerabilities remaining. All 192 tests still pass after the fix.

## Exit status

`SESSION_6_COMPLETE` — Parts 12, 17-20, 22-23 implemented and verified. 3 defects closed (D-22, D-23, D-24). Concern families, scan receipt, evidence envelope, rulepack digest, and custom rulepack security all working. 19 new tests. All verification passes including stdio smoke test. No commits made (per agreed cadence).

## Cumulative progress (Sessions 1-6)

- **24 of 25 defects closed** (D-01 through D-08, D-09 through D-19, D-21, D-22, D-23, D-24, D-25)
- **192 tests passing** (was 119 baseline)
- MCP v2 SDK with structured output + completeness + coverage + concern families + receipt
- Security boundary + write governance complete
- Stable v2 fingerprints + proof-of-fix
- Correct OWASP MCP Top 10 mappings
- Scan Receipt + Evidence Envelope
- Custom rulepack security controls
- No commits made (per agreed cadence — Session 8 creates release branch)
