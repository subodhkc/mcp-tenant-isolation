# Session 7 Report — README, CI Matrix, Golden Corpus, Flow Analysis Qualification

**Date:** 2026-08-21
**Phase:** TI-2 — Security Boundary Hardening + MCP V2 + Evidence-Contract Alignment + Release Qualification
**Status:** Complete — no commits made (deferred to Session 8)

## Summary

Session 7 completed README rewrite, CI matrix verification, golden corpus fixture creation, flow-analysis qualification, and full verification. A pre-existing bug in IDOR-001 was found and fixed during golden corpus qualification.

## Review findings

### 1. CI self-scan shell issue

**Problem:** The `self-scan` step in `.github/workflows/ci.yml` used bash syntax (`$?`, `if [ ... ]`) without specifying `shell: bash`. On Windows runners, the default shell is PowerShell, which would fail on this syntax.

**Fix:** Added `shell: bash` to the self-scan step. The matrix runs on Ubuntu, Windows, and macOS, so explicit shell declaration is required for cross-platform consistency.

### 2. IDOR-001 rule bug (pre-existing)

**Problem:** IDOR-001 checked `sink.api.includes('id:')` to detect findUnique calls looking up by ID. However, `sink.api` contains only the callee name (e.g., `prisma.document.findUnique`), not the call arguments. The `id:` substring was never present in `sink.api`, so IDOR-001 could never trigger.

**Root cause:** The parser sets `sink.api` to the callee string only. Call arguments are in `sink.argsVars`. The `nodeToString` function converts object properties to dot notation (e.g., `{where:{id:id}}` becomes `{where.{id.id}}`), so `id:` is not present in argsVars either — it's `id.id`.

**Fix:** Changed the check from `sink.api.includes('id:')` to `sink.argsVars.join(' ').includes('id')`. This correctly detects findUnique calls that use `id` as a lookup key. The tenant guard check (`hasGuard`) still runs afterward, so guarded findUnique calls do not trigger.

**Impact:** IDOR-001 now works as intended. No existing tests broke. The fix is minimal and targeted.

### 3. README accuracy gaps

**Problem:** The previous README contained several inaccuracies:
- Listed `@modelcontextprotocol/sdk` instead of `@modelcontextprotocol/server` in tech stack (already fixed in prior session, verified)
- Did not document structured output (completeness, coverage, concern families, receipt)
- Did not document fingerprint v2 or proof-of-fix
- Did not document path boundary enforcement
- Did not document write-tool gating
- Did not document custom rulepack validation
- Did not document OWASP MCP Top 10 mapping
- CI example used Node 20 instead of Node 22
- Roadmap listed v2.0.0 features as "future" without distinguishing in-development vs. planned

**Fix:** Complete README rewrite covering all current features accurately. See README changes section below.

## README changes

The README was completely rewritten with the following principles:

- **Humanized writer voice:** Direct, professional, no hype. Written as a developer talking to another developer.
- **Both technical and simple English:** Each section starts with a plain-language explanation, then provides technical detail.
- **SEO terms:** Multi-tenant isolation, tenant data leakage, cross-tenant, MCP server security, static analysis, SaaS security, tenant-scoped, IDOR prevention, RLS, cache key scoping.
- **Sales terms:** Value proposition framing ("catches cross-tenant data leakage before it reaches production"), use case orientation, who-uses-this section.
- **Backlinks:** Links to `https://www.haiec.com` (HAIEC — AI security validation and audit-evidence platform) and `https://subodhkc.com` (builder).
- **No AI-like language:** No "delve into", no "unleash", no "supercharge", no ornamental formatting.
- **Accurate claims:** Deterministic rules (not "no false positives"). Static analysis limitations documented. OWASP mapping is advisory, not certification. Suppression approver is recorded attribution, not independent verification.

New sections added:
- Structured output (completeness, coverage, concern families, limitations, receipt, proof-of-fix)
- Fingerprints (v2 semantic, line-movement resistant)
- Custom rule packs (validation rules)
- Suppressions (documented approver, controls, expiry)
- Baselines (proof-of-fix tracking)
- MCP tools table updated with write/opt-in column
- Path boundary enforcement mention
- Roadmap updated with v2.0.0 in-development section

## CI matrix verification

`.github/workflows/ci.yml` verified:

- **Matrix:** Ubuntu, Windows, macOS × Node 22.x, 24.x
- **Exclusions:** Windows 24.x and macOS 24.x skipped to reduce matrix size
- **Node 26 canary:** Ubuntu only, `experimental: true`, `continue-on-error: true`
- **Self-scan:** Fixed with `shell: bash` for cross-platform compatibility
- **Deps-check job:** Dependabot-only, Node 22.x, runs build + test
- **Publish job:** Tag-triggered, Node 22.x, provenance publishing
- **MCP Registry publish:** Tag-triggered, depends on npm publish

YAML syntax is valid. Job dependencies are correct (publish needs build-and-test, registry needs publish).

## Golden corpus results

Created `tests/golden-corpus/golden-corpus.test.ts` with 11 tests covering:

- DBQ-001: findMany without tenant filter (triggers)
- DBQ-001: findMany WITH tenant filter (does not trigger)
- DBQ-004: raw SQL without tenant filter (triggers)
- IDOR-001: findUnique by ID without ownership check (triggers — after bug fix)
- MCP-001: tool without tenant visibility filter (triggers)
- TCM-001: tenant ID from request query (triggers)
- SCH-001: Prisma model without tenant field (triggers)
- SCH-001: Prisma model WITH tenant field (does not trigger)
- False positive resistance: guarded findMany with session org ID (does not trigger)
- Test file exclusion: test files excluded from scanning
- Clean project: empty project returns COMPLETE with zero findings

All 11 tests pass. Tests use temporary directories in OS temp folder, ensuring cross-platform path handling.

## Flow-analysis qualification

Created `docs/FLOW-ANALYSIS-QUALIFICATION.md` documenting:

- **What works:** Flow graph construction, path finding, rule integration
- **What does not work:** Intra-procedural only (no inter-procedural), no inter-file flow, no pointer/alias tracking, no framework-specific flow
- **Which rules use flow analysis:** No built-in rules require flow graph as of v2.0.0. Infrastructure exists for future rules and custom rulepacks.
- **Why this is acceptable:** Tenant isolation defects are primarily missing-guard-at-sink problems. The guard is either present in the where clause or it is not. Inter-procedural flow analysis is not needed for this detection pattern.
- **Future work:** Inter-procedural analysis, cross-file flow, framework-specific middleware→handler flow, alias tracking, taint analysis

## Supply-chain audit

- `npm audit`: 0 vulnerabilities
- `npm run build`: success
- Previous `nanoid` vulnerability (fixed in Session 6 review) remains resolved
- `esbuild@0.28.1` install-script warning: This is a dev dependency (via vitest→vite). The postinstall script (`node install.js`) downloads the platform-specific esbuild binary. This is expected behavior for esbuild and is not a vulnerability. No action needed beyond documenting it. The package is pinned in `package-lock.json` and installed via `npm ci` in CI.

## Verification results

| Check | Result |
|-------|--------|
| Typecheck | PASS |
| Lint | 0 errors, 4 warnings |
| Tests | 203 passed (192 existing + 11 golden corpus) |
| Build | PASS |
| npm audit | 0 vulnerabilities |

## Files changed in Session 7

- `README.md` — complete rewrite
- `.github/workflows/ci.yml` — added `shell: bash` to self-scan step
- `src/rules/general.ts` — fixed IDOR-001 argsVars check (pre-existing bug)
- `tests/golden-corpus/golden-corpus.test.ts` — new (11 tests)
- `docs/FLOW-ANALYSIS-QUALIFICATION.md` — new
- `docs/evidence/v2/SESSION-7-REPORT.md` — new (this file)

## Remaining risks and deferred work

1. **IDOR-001 fix scope:** The fix changes IDOR-001 behavior — it now triggers on findUnique calls that use `id` in argsVars. This is correct behavior but should be verified against real codebases in Session 8 to check for false positive rates.
2. **Flow analysis:** Documented as intra-procedural only. No rules currently use it. Future rules that require inter-procedural analysis will need additional work.
3. **Evidence Envelope CLI exposure:** The Evidence Envelope is available programmatically via the scan result. CLI exposure for evidence envelope export is not yet implemented. Deferred to future work.
4. **esbuild install script:** Documented as expected behavior. No configuration change made. If npm's install-script allowlist mechanism becomes mandatory, a `.npmrc` configuration may be needed.
5. **Session 8 pending:** Release workflow, trusted publishing, registry readiness, release branch, final qualification, ai-appsec conformance, roadmap.

## No-commit status

No commits were made in Session 7. All changes remain uncommitted, consistent with the plan to commit in Session 8 after final qualification.
