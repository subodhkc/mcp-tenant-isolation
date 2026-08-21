# CURRENT-DEFECT-REGISTER — mcp-tenant-isolation v1.6.2

**Phase:** TI-2 — Security Boundary Hardening + MCP v2 + Evidence-Contract Alignment
**Session:** 1 (Baseline + Defect Register)
**Baseline commit:** `1e5278775adc9919aa9c9ae90b1e88a8aab56d79`
**Method:** Empirical/source verification only. Every classification cites exact file/function/line evidence. No defect was classified without reading the source. No fix was applied in this session.

## Summary

| Classification | Count |
|---|---|
| CONFIRMED | 24 |
| PARTIALLY_CONFIRMED | 1 |
| NOT_CONFIRMED | 0 |

**Severity (TI-2 remediation priority):**
- **P0 (security boundary / safety):** 1, 2, 3, 4, 5, 7, 8, 9, 11
- **P1 (evidence contract / correctness):** 10, 12, 13, 14, 15, 16, 17, 18, 19, 24
- **P2 (claims / supply chain / release):** 6, 20, 21, 22, 23, 25

---

## P0 — Security Boundary / Safety

### D-01. startMcpServer(projectRoot) root argument not enforced — CONFIRMED
**Evidence:** `src/mcp/server.ts:133` — `export async function startMcpServer(_projectRoot: string, options?: McpServerOptions)`. The parameter is named `_projectRoot` (underscore = intentionally unused) and is never referenced inside the function. The scan handler at `:169` independently resolves the caller-supplied path: `const scanPath = resolve((args as any).path);`. The CLI passes `projectRoot` at `src/cli/index.ts:283` (`startMcpServer(projectRoot, { transport, port })`), but the server discards it.
**Impact:** The MCP server has no notion of an allowed project root. Any tool call can target any path on the host filesystem regardless of how the server was started.
**Fix locus:** Part 3 (project-root boundary).

### D-02. scan tool accepts arbitrary resolved caller path — CONFIRMED
**Evidence:** `src/mcp/server.ts:168-179` — `case 'scan_tenant_isolation'` does `const scanPath = resolve((args as any).path)` then calls `scan({ projectRoot: scanPath, ... })` with no containment check. `resolve()` with an absolute caller path returns that absolute path unchanged. The input schema (`:38-56`) requires only `path` and imposes no root constraint.
**Impact:** An AI agent (or any MCP client) can scan any directory on disk, including outside the intended project, leaking file structure and source contents into findings.
**Fix locus:** Part 3 (reject with `TARGET_OUTSIDE_ALLOWED_ROOT`).

### D-03. suppression tool accepts arbitrary resolved caller path — CONFIRMED
**Evidence:** `src/mcp/server.ts:286-319` — `case 'suppress_tenant_isolation_finding'` does `const suppressPath = resolve((args as any).path)` then writes `.mti-suppressions.json` into that path (`:311` `join(suppressPath, '.mti-suppressions.json')` and `:319` `writeFile`). No containment check.
**Impact:** A write tool that can create/append files in arbitrary directories. Combined with D-09/D-11 this is an unrestricted filesystem write primitive exposed over MCP by default.
**Fix locus:** Part 3 + Part 4 (write-tool governance + root boundary).

### D-04. custom rulepack paths can resolve outside root — CONFIRMED
**Evidence:** `src/engine/rule-pack-loader.ts:66` — `const fullPath = resolve(projectRoot, packPath);`. Node's `path.resolve` discards `projectRoot` when `packPath` is absolute. A config value `"rulePacks": ["C:/evil/rules.json"]` or `"/etc/passwd"` resolves to that absolute path; `existsSync` + `readFile` then load it. No root containment.
**Impact:** Arbitrary file read from anywhere on disk via `.mtirc.json` `rulePacks`, and execution of attacker-supplied rule logic (the rule's `evaluate` closure runs against the IR).
**Fix locus:** Part 3 + Part 22 (custom rulepack boundary + schema).

### D-05. symlink/realpath escape possibilities — CONFIRMED
**Evidence:** No `realpath`/`realpathSync`/`fs.realpath`/`lstat`/`statSync`/`lstatSync` import exists anywhere in `src/` (grep across all 19 source files returned zero matches). `src/engine/scanner.ts:80-84` uses `fast-glob` with `absolute: true` and default `followSymbolicLinks: true`, returning paths that may traverse symlink targets outside the project root without containment. `resolve()` is lexical only.
**Impact:** A symlink inside the project root pointing outside (e.g. `src/evil -> /etc`) is followed and its target scanned/read/written as if inside-root. No `TARGET_OUTSIDE_ALLOWED_ROOT` possible without realpath-aware containment.
**Fix locus:** Part 3 (realpath-aware containment, Windows case-insensitivity, UNC handling).

### D-07. remote HTTP host binding — CONFIRMED
**Evidence:** `src/mcp/server.ts:380` — `httpServer.listen(port, () => {...})`. No host argument is passed to `listen()`, so Node binds to `0.0.0.0` (all interfaces), not localhost. The CLI exposes this via `src/cli/index.ts:275` (`-t, --transport <type>` accepts `sse`) and `:276` (`--port`).
**Impact:** When SSE transport is selected the MCP server is network-exposed to all interfaces by default.
**Fix locus:** Part 5 (remove legacy SSE; if any remote transport retained, localhost bind + Origin validation + auth).

### D-08. remote Origin validation/auth state — CONFIRMED
**Evidence:** `src/mcp/server.ts:360-378` — the SSE HTTP handler checks only `url.pathname` (`/sse`, `/message`, else 404). There is no `Origin` header check, no `Authorization` check, no session/auth model. Any network client reaching the port can connect to `/sse` and drive the server.
**Impact:** Unauthenticated network-exposed MCP. Combines with D-07 to expose scan/suppress over the network with no auth.
**Fix locus:** Part 5 (preferred: stdio-only for v2.0; if remote retained, mandatory Origin + auth).

### D-09. suppression approver is caller-supplied text — CONFIRMED
**Evidence:** `src/mcp/server.ts:293` — `approvedBy: (args as any).approvedBy` is taken verbatim from the MCP caller (an AI agent). `src/engine/suppressions.ts:80-82` — `validateSuppression` only checks `if (!rule.approvedBy)`, i.e. presence of a non-empty string. No external human-verification step exists. The field name `approvedBy` implies independent human approval that does not occur.
**Impact:** An AI agent can self-approve suppressions, and the recorded state reads as "approved" without any human in the loop.
**Fix locus:** Part 4 (rename to "documented approver identifier"; require concrete fingerprint + ruleId + reason + compensating controls + expiry).

### D-11. suppression schema can omit concrete finding identity — CONFIRMED
**Evidence:** `src/mcp/server.ts:91-128` — input schema `required: ['path', 'reason', 'approvedBy', 'controls']`. `fingerprint` and `file` are NOT required. `src/engine/suppressions.ts:73-95` — `validateSuppression` does not require `fingerprint`, `ruleId`, or `filePath`. A suppression with only `reason`+`approvedBy`+`controls` (and no ruleId/fingerprint/file) is accepted by validation, then matches nothing at match-time (harmless) — but a suppression with `ruleId` only matches ALL findings of that rule (see D-10).
**Impact:** Suppressions can be created without pinning a concrete finding, enabling broad/rule-wide suppressions and making suppression auditability weak.
**Fix locus:** Part 4 (require concrete finding fingerprint by default + ruleId).

---

## P1 — Evidence Contract / Correctness

### D-10. rule-wide suppression availability — CONFIRMED
**Evidence:** `src/engine/suppressions.ts:65-66` — `if (rule.ruleId === finding.ruleId && !rule.filePath && !rule.fingerprint) return true;`. A suppression entry with only `ruleId` (no file, no fingerprint) matches and suppresses EVERY finding of that rule across the whole project. This is reachable from the MCP suppress tool because `ruleId` is optional but accepted, and from the CLI `suppress` command (`src/cli/index.ts:180` `--rule-id` is optional).
**Impact:** One suppression entry can silently disable an entire rule class, masking all tenant-isolation findings of that rule.
**Fix locus:** Part 4 (reject rule-wide suppression unless explicit documented permanent-exception policy).

### D-12. parser failures are caught/skipped — CONFIRMED
**Evidence:** `src/engine/scanner.ts:95-219` — the per-file parse loop wraps each file in `try { ... } catch (err) { console.warn(...) }` (`:215-218`). On failure the file is skipped and a warning is printed. No counter, no completeness flag, no coverage record. `ScanResult` (`src/types.ts:275-281`) has no `completeness`/`parseFailures` field.
**Impact:** A scan that silently skipped 50% of files due to parse errors reports "0 findings" and looks clean. No PARTIAL state is representable.
**Fix locus:** Part 9 (COMPLETE/PARTIAL/ERROR) + Part 10 (coverage model).

### D-13. rule-evaluation failures are caught/skipped — CONFIRMED
**Evidence:** `src/engine/scanner.ts:238-256` — the rule evaluation loop wraps each rule in `try { rule.evaluate(ir, graph) } catch (err) { console.warn(...) }` (`:252-255`). On failure the rule is skipped; `rulesTriggered` is only incremented on success; no `rulesFailed` count is kept. `ScanStats` (`src/types.ts:283-290`) has `rulesEvaluated` and `rulesTriggered` but no `rulesFailed`.
**Impact:** A rule that throws on every file is silently dropped; the scan reports as if that rule was never part of the rule set. Completeness is overstated.
**Fix locus:** Part 9 + Part 11 (rule evaluation accounting: rulesAvailable/rulesSelected/rulesEvaluatedSuccessfully/rulesFailed/rulesTriggered).

### D-14. no COMPLETE/PARTIAL/ERROR coverage contract — CONFIRMED
**Evidence:** `src/types.ts:275-281` — `ScanResult` = `{ findings, ir, stats, durationMs, error? }`. No `completeness`, `verdict`, `coverage`, or `limitations` field. `src/engine/scanner.ts:307-313` returns exactly that shape. `error?` is only set if the whole scan throws (it is not set anywhere in `scan()`; the outer try/catch is in the CLI/MCP layers).
**Impact:** "0 findings" is indistinguishable from "0 findings after silently dropping 30% of files/rules". The contract required by Part 9 does not exist.
**Fix locus:** Part 9 (COMPLETE/PARTIAL/ERROR) — never let 0+PARTIAL read as PASS.

### D-15. finding fingerprint depends on line number — CONFIRMED
**Evidence:** `src/rule-spec.ts:122` — `const fingerprint = generateFingerprint(ruleId, evidence.file, evidence.lineStart);` and `:137-145` — `generateFingerprint(ruleId, file, line)` = `createHash('sha256').update(`${ruleId}:${file}:${line}`).digest('hex').substring(0,16)`. The fingerprint is `sha256(ruleId:file:lineStart)[:16]`. Line movement (inserting a blank line above) changes the fingerprint.
**Impact:** Baselines and suppressions keyed on fingerprint break on any unrelated line insertion; "same issue + line movement → different identity". Proof-of-fix by disappearance is unreliable.
**Fix locus:** Part 16 (fingerprintVersion=2 with semantic identity; line as metadata only; v1→v2 migration).

### D-16. rule revisions are not individually versioned — CONFIRMED
**Evidence:** `src/rule-spec.ts:87` — `version: '1.0.0'` is hardcoded for every rule created via `createRule` (all 57 built-ins and all custom rules). `src/rules/index.ts:13` — `RULE_ENGINE_VERSION = '1.6.2'` (the package version) is the only rule identity used at runtime. No `ruleRevision`, no `rulepackVersion`, no `rulepackDigest`, no `manifestDigest`.
**Impact:** A rule's semantics can change between releases without any per-rule revision change; consumers cannot tell whether a suppression/baseline was made against the same rule semantics. Part 12's rulepack identity contract is absent.
**Fix locus:** Part 12 (Public Rule Manifest with ruleRevision + canonicalSecurityCheckId + digests).

### D-17. OWASP MCP mappings use OWASP MCP-SEC-* — CONFIRMED
**Evidence:** `src/rules/mcp.ts` lines 46, 80, 114, 148, 182, 220, 257, 291, 325, 366, 400, 437, 478, 521, 561 — all 15 MCP rules set `owaspMcpRef: 'OWASP MCP-SEC-01'` … `'OWASP MCP-SEC-15'`. These are invented positional identifiers, not the current authoritative OWASP MCP Top-10 (e.g. `MCP10:2025 Context Injection & Over-Sharing`, `MCP07:2025 Insufficient Authentication & Authorization`). The 42 general rules have NO `owaspMcpRef` at all (grep returned 0 matches in `general.ts`).
**Impact:** Compliance mappings are non-authoritative and could be misrepresented as OWASP-endorsed. General rules lack any OWASP/CWE mapping despite `cweIds` being available.
**Fix locus:** Part 14 (remap to current OWASP MCP identifiers + CWE + OWASP Multi-Tenant guidance where justified; create `docs/OWASP-MAPPING.md`).

### D-24. custom rulepacks lack strong schema/duplicate-ID/source validation — CONFIRMED
**Evidence:** `src/engine/rule-pack-loader.ts:72-119` — `JSON.parse(content) as RulePackFile` with no schema validation. No duplicate-ID check within a pack. No collision check against built-in rule IDs. No severity enum validation. No `sinkKinds` validation against the known `SinkKind` union. No required-field check beyond what `createRule` happens to read. Custom rules are pushed into `customRules` and concatenated with `ALL_RULES` (`scanner.ts:226`), indistinguishable from built-ins at output time. No `customRulepackDigest`, no source recording.
**Impact:** Malformed/colliding custom rules can shadow built-ins or crash evaluation; custom rules can be presented as HAIEC-authored; no deterministic identity for custom rule evidence.
**Fix locus:** Part 22 (schema validation + duplicate/collision rejection + root containment + customRulepackDigest + source attribution).

### D-18. MCP output is JSON text rather than structured evidence — CONFIRMED
**Evidence:** `src/mcp/server.ts:185-213` — the scan tool returns `content: [{ type: 'text', text: JSON.stringify({...}, null, 2) }]`. There is no `structuredContent` field, no output schema, no receipt, no evidence envelope. `list_tenant_isolation_rules` (`:223-243`) and `explain_tenant_isolation_rule` (`:262-283`) likewise return JSON-in-text.
**Impact:** Clients cannot programmatically rely on a typed contract; the entire payload is unstructured text; no evidence contract for HAIEC ingestion.
**Fix locus:** Part 8 (typed structuredContent) + Parts 19-20 (Receipt + Envelope).
**Severity note:** Reclassified from P0 to P1 — this is an evidence-contract/agent-quality issue, not a filesystem security boundary escape.

### D-19. output is effectively unbounded — CONFIRMED
**Evidence:** `src/mcp/server.ts:199-209` — `findings: result.findings.map(...)` returns every finding with no bound, no truncation, no total-vs-returned distinction. The CLI reporters also emit all findings (e.g. `src/reporters/index.ts:21` `findings: sortBySeverity(result.findings)`).
**Impact:** A large project can produce thousands of findings dumped into a single MCP text content block, blowing agent context windows with no concern-family grouping or sample bound.
**Fix locus:** Part 18 (concern families grouping + default bound ~20 + exact totals preserved).
**Severity note:** Reclassified from P0 to P1 — this is an agent-quality/evidence issue, not a filesystem security boundary escape.

---

## P2 — Claims / Supply Chain / Release

### D-06. legacy SSE /message behavior — CONFIRMED
**Evidence:** `src/mcp/server.ts:359-382` — SSE transport is implemented and advertised. `:371-373` — the `/message` endpoint returns `405` with `"Use SSE transport client to send messages"` (i.e. the message endpoint is non-functional stub). `src/cli/index.ts:275` exposes `-t sse`. `README.md:277` states "MCP: @modelcontextprotocol/sdk (stdio transport)" — understating that SSE is actually implemented. The current SSE implementation is the legacy HTTP+SSE pattern (separate `/sse` + `/message`), not Streamable HTTP.
**Impact:** A legacy, non-current remote transport is shipped and CLI-selectable, with a broken `/message` handler and the network/auth defects of D-07/D-08.
**Fix locus:** Part 5 (remove/deprecate legacy SSE; v2.0 preferred stdio-only; if remote retained it must be Streamable HTTP with localhost+Origin+auth).

### D-20. Node 18/20 CI/runtime support is stale — CONFIRMED
**Evidence:** `package.json:77` — `"engines": { "node": ">=18.0.0" }`. `.github/workflows/ci.yml:19` — `node-version: [18.x, 20.x]`. CI runs only on `ubuntu-latest` (`:12`). No Windows or macOS in the matrix. Node 18 is EOL; Node 20 is approaching EOL. v2.0 must support Node 22 LTS + 24 LTS (+ 26 canary).
**Impact:** Stale runtime support and single-OS CI; no cross-platform semantic-equality qualification.
**Fix locus:** Part 7 (engines.node >=22) + Part 25 (Windows/Linux/macOS Node22/24 matrix).

### D-21. publish workflow rebuilds rather than publishes exact qualified artifact — CONFIRMED
**Evidence:** `.github/workflows/ci.yml:78-102` — `publish` job: `checkout` → `npm ci` → `npm run build` → `npm publish --provenance`. The tarball published is built fresh on the publish runner, NOT the tarball that was qualified by `build-and-test`. There is no "build once → test tarball → publish same tarball" flow; no SHA-256 of the canonical artifact; no matrix test of the same `.tgz`.
**Impact:** The artifact that passed CI is not the artifact that ships. A build-environment difference (npm resolution, transitive deps) can produce a different tarball at publish time.
**Fix locus:** Part 29 (build-once → canonical .tgz → SHA-256 → matrix test SAME .tgz → publish exact qualified artifact).

### D-22. NPM_TOKEN publishing rather than preferred OIDC model — PARTIALLY_CONFIRMED
**Evidence:** `.github/workflows/ci.yml:99-102` — `npm publish --provenance` with `NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}`. Provenance IS enabled (`--provenance` + `id-token: write` at `:84`). However publishing still authenticates with a long-lived `NPM_TOKEN` secret rather than npm Trusted Publishing (GitHub Actions OIDC → npm trust configuration on the npm side, no long-lived token).
**Impact:** A long-lived npm token exists in repo secrets; not the strongest supply-chain model. Provenance is present, so this is PARTIAL, not full defect.
**Fix locus:** Part 30 (move toward GitHub Actions OIDC + npm Trusted Publishing; eliminate long-lived NPM_TOKEN where practical; founder-controlled release gate).

### D-23. README says inline MCP scanning but schema only supports path — CONFIRMED
**Evidence:** `README.md:120` — MCP tools table row: `scan_tenant_isolation | Scan a file path or inline code. Returns structured findings.` But `src/mcp/server.ts:38-56` — the `scan_tenant_isolation` inputSchema has only `path` (string, required), `severity`, `rules`. There is no `code`/`inline` property. The schema description (`:43`) says "Project root path to scan". Inline code scanning is not supported by the MCP tool.
**Impact:** Documentation claims a capability the MCP interface does not provide.
**Fix locus:** Part 23 (correct MCP documentation; do not claim inline scanning if only path is accepted).

### D-25. broad claims such as "no false guesses" / competitor binary claims — CONFIRMED
**Evidence:** `README.md:22` — "General-purpose security scanners (Snyk, Semgrep, CodeQL) do not understand tenant isolation patterns or MCP server architecture." `README.md:24` — "No machine learning, no false guesses. ... You get the same results every run." These are broad/competitor-binary claims not empirically qualified in the repo. (The deterministic claim is defensible but "no false guesses" overclaims; "same results every run" needs explicit coverage/limitations framing per Part 9.)
**Impact:** Overclaiming that the TI-2 positioning section (Part 23) requires replacing with qualified language.
**Fix locus:** Part 23 (replace with the preferred differentiation + qualified deterministic claim language).

---

## Notes on items NOT in the 25-list but observed (recorded for later sessions)

These are not part of the 25-defect register but were observed during verification and are tracked for the relevant later part:

- **Flow-graph behavior (Part 27 qualification, not a defect):** `src/engine/flow-graph.ts:77` uses substring matching (`source.symbol.includes(srcSym) || srcSym.includes(source.symbol)`) and `:88` (`v.includes(asgn.dst) || asgn.dst.includes(v)`). This is substring-collision-prone (renamed variables won't match; unrelated symbols with overlapping substrings will false-match). No interprocedural/CFG support; flow is intra-IR assignment only. To be qualified as SUPPORTED/PARTIAL/UNSUPPORTED in Session 7 (Part 27).
- **Report completeness (Part 28, not a defect):** `src/reporters/index.ts` JSON/AI/SARIF/Markdown reporters emit `stats` and `findings` but no `completeness`, `coverage`, `limitations`, or rulepack identity. SARIF could imply a complete scan for a PARTIAL run. To be aligned in Session 7 (Part 28).
- **`haiec-scan-results-v*.json` files in repo root:** 11 large scan-result JSON files (v1..v10, ~25 MB total) sit in the working tree root and are not in `.gitignore`. Pre-push secret/private-file/absolute-path scan (Part 34) must address these before the RC branch push.
- **Docker workflow (`.github/workflows/docker.yml`):** tag-triggered Docker Hub push using `DOCKERHUB_TOKEN`. Not in the 25-list; Part 29/30 supply-chain work should decide whether Docker publishing is in scope for v2.0-rc1.

---

## Exit status of this session

`SESSION_1_COMPLETE` — Baseline frozen (`docs/evidence/v2/BASELINE.json`); all 25 defect candidates empirically classified with file/function evidence; no code changes made; no commits made (per agreed commit cadence: uncommitted until Session 8).
