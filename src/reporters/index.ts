/**
 * Reporters - JSON, SARIF 2.1.0, Terminal
 */

import type { ScanResult, Finding, Severity } from '../types.js';
import { RULE_ENGINE_VERSION, ALL_RULES } from '../rules/index.js';

const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

function sortBySeverity<T extends { severity: Severity }>(items: T[]): T[] {
  return [...items].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
}

export function jsonReporter(result: ScanResult): string {
  return JSON.stringify({
    schema: `mcp-tenant-isolation/${RULE_ENGINE_VERSION}`,
    engineVersion: RULE_ENGINE_VERSION,
    timestamp: result.ir.scanTimestamp,
    durationMs: result.durationMs,
    stats: result.stats,
    findings: sortBySeverity(result.findings),
  }, null, 2);
}


const REMEDIATION_HINTS: Record<string, string> = {
  'TCM-001': 'Extract tenant ID from the authenticated session or JWT token, not from request headers or query parameters. Use req.session.organizationId or req.user.tenantId.',
  'TCM-002': 'Do not accept tenantId as a client-provided parameter. Derive it from the auth context. If client sends tenantId, ignore it and use the session value.',
  'TCM-003': 'Propagate tenant context through async boundaries. Use AsyncLocalStorage or explicit context objects instead of relying on global variables.',
  'TCM-004': 'Validate that the tenant ID in the request matches the tenant in the session token. Reject mismatches with 403.',
  'TCM-005': 'Set tenant context in middleware before route handlers. Use a middleware that sets req.tenantId from the session for all subsequent handlers.',
  'TCM-006': 'Do not cache tenant context in module-level variables. Each request must resolve tenant context independently to prevent cross-request leakage.',
  'DBQ-001': 'Add organizationId to the where clause of findMany queries. Example: prisma.model.findMany({ where: { organizationId } })',
  'DBQ-002': 'Add organizationId to findUnique where clause or verify ownership after fetch. Example: prisma.model.findUnique({ where: { id, organizationId } })',
  'DBQ-003': 'Add organizationId to update/delete where clause. Example: prisma.model.update({ where: { id, organizationId } })',
  'DBQ-004': 'Add tenant filter to raw SQL queries. Use parameterized tenantId in WHERE clause. Never concatenate tenantId into SQL strings.',
  'DBQ-005': 'Add organizationId to Drizzle query where clause. Example: db.select().from(table).where(eq(table.organizationId, tenantId))',
  'DBQ-006': 'Enable RLS on tenant-scoped tables that receive queries. Example: ALTER TABLE ... ENABLE ROW LEVEL SECURITY; CREATE POLICY ... USING (organization_id = current_setting(\'app.organization_id\')::uuid)',
  'DBQ-007': 'Replace USING(true) / WITH CHECK(true) with tenant-specific predicate. Example: USING (organization_id = current_setting(\'app.organization_id\')::uuid)',
  'DBQ-008': 'Add organizationId to Prisma include/select nested queries. Use where inside include: { child: { where: { organizationId } } }',
  'DBQ-009': 'Add organizationId filter to aggregate/count/groupBy queries. Example: prisma.model.aggregate({ where: { organizationId }, _count: true })',
  'DBQ-010': 'Add organizationId to upsert where clause. Example: prisma.model.upsert({ where: { id_organizationId: { id, organizationId } }, ... })',
  'IDOR-001': 'Verify that the requested resource belongs to the caller tenant before returning it. Add a tenant ownership check after fetch.',
  'IDOR-002': 'Add tenant ownership verification to API routes that accept record IDs. Verify result.organizationId matches session tenant before returning data. Example: if (result.organizationId !== req.tenantId) return 403.',
  'IDOR-003': 'Verify tenant ownership before returning resource by ID. Add: if (result.organizationId !== req.tenantId) return 403.',
  'IDOR-004': 'Check tenant ownership before allowing update/delete operations. Verify result.organizationId matches session tenant before modifying.',
  'IDOR-005': 'Validate that bulk operations do not cross tenant boundaries. Check all referenced IDs belong to the caller tenant before processing.',
  'CSI-001': 'Include tenantId in cache keys to prevent cross-tenant cache leakage. Use key format: tenant:{tenantId}:{resourceKey}.',
  'CSI-002': 'Scope session data by tenant. Do not share session state across tenants. Use tenant-specific session namespaces.',
  'CSI-003': 'Flush tenant-scoped cache entries on tenant context change. Implement cache invalidation hooks tied to tenant lifecycle events.',
  'CSI-004': 'Do not use global singleton caches for tenant-scoped data. Use per-tenant cache instances or tenant-prefixed keys.',
  'API-001': 'Add per-tenant rate limiting. Use a rate limiter keyed by tenantId + endpoint, not just IP address.',
  'API-002': 'Ensure all API route handlers call requireOrganizationAccess() or validateTenantContext() before database queries.',
  'API-003': 'Include tenantId/organizationId in API response metadata for attribution.',
  'FSI-001': 'Include tenantId in file paths or metadata to prevent cross-tenant file access. Use paths like tenants/{tenantId}/files/{fileId}.',
  'FSI-002': 'Validate tenant ownership before file operations. Check that the file belongs to the caller tenant before read/write/delete.',
  'FSI-003': 'Use tenant-scoped S3 bucket prefixes or separate buckets per tenant. Never use shared prefixes without tenant ID in the key.',
  'FSI-004': 'Add tenant ID to blob storage metadata. Use Azure Blob tags or S3 metadata to tag objects with tenantId for access control.',
  'LOG-001': 'Include organizationId/tenantId in log entries for tenant attribution. Add tenant context to your structured logger.',
  'LOG-002': 'Include organizationId/tenantId in audit log entries for data access. Audit logs must be traceable to a specific tenant for compliance.',
  'LOG-003': 'Avoid logging raw database results near unfiltered queries. Add tenant context to error logs and redact sensitive data from error messages.',
  'LOG-004': 'Do not strip tenantId from structured log output. Ensure logging configuration preserves tenant context for audit traceability.',
  'SCH-001': 'Add organizationId field to the Prisma model, or mark it as user-scoped/global in .mtirc.json if intentionally non-tenant.',
  'SCH-002': 'Add organizationId or tenantId column to CREATE TABLE statements in SQL migrations for tenant-scoped tables.',
  'SCH-003': 'Add tenant column as first field in compound indexes. Example: @@index([organizationId, ...otherFields])',
  'SCH-004': 'Enable RLS on tables with tenant columns. Example: ALTER TABLE ... ENABLE ROW LEVEL SECURITY;',
  'SCH-005': 'Replace USING(true) / WITH CHECK(true) with tenant-specific predicate. Example: USING (organization_id = current_setting(\'app.organization_id\')::uuid)',
  'SCH-006': 'Add tenant column to foreign key relationships. Include organizationId in FK references to prevent cross-tenant references.',
  'MCP-001': 'Filter MCP tool visibility by tenant. Use tenantToolFilter or allowedTools per tenant in the MCP server configuration.',
  'MCP-002': 'Prefix MCP cache keys with tenantId. Use cache key format: mcp:{tenantId}:{toolName}:{paramsHash}.',
  'MCP-003': 'Bind MCP sessions to both user and tenant. Include userId and tenantId in session creation and validate on every request.',
  'MCP-004': 'Filter MCP tool visibility by tenant. Use tenantToolFilter or allowedTools per tenant.',
  'MCP-005': 'Implement per-tenant rate limiting on MCP tool calls. Use a token bucket or sliding window keyed by tenantId + toolName.',
  'MCP-006': 'Use tenant namespaces in vector stores. Create separate collections or partition vectors by tenantId prefix.',
  'MCP-007': 'Sanitize tool descriptions to prevent injection. Do not include user input in tool description templates.',
  'MCP-008': 'Isolate MCP cache entries by tenant. Use tenantId in cache keys.',
  'MCP-009': 'Use per-tenant service accounts or API keys. Do not share a single credential across tenants for external API calls.',
  'MCP-010': 'Implement deterministic session cleanup on client disconnect. Use onDisconnect handlers to purge session data.',
  'MCP-011': 'Include tenant identifier in MCP telemetry events. Do not strip tenantId from telemetry payloads.',
  'MCP-012': 'Bind MCP server to 127.0.0.1 only. Do not bind to 0.0.0.0 unless behind a reverse proxy with auth.',
  'MCP-013': 'Restrict filesystem access to tenant-specific root directories. Use tenants/{tenantId}/ as the filesystem root for each session.',
  'MCP-014': 'Prefix artifact storage with tenantId. Use paths like artifacts/{tenantId}/{artifactId} to prevent cross-tenant access.',
  'MCP-015': 'Register MCP tools with tenant namespace prefix. Use tool names like {tenantId}_{toolName} or filter by tenant context.',
};

const RULE_CONTEXT: Record<string, string> = {
  'TCM-001': 'Detects tenant ID sourced from client input (headers, query params, body) instead of the authenticated session. Client-controlled tenant IDs enable tenant switching attacks.',
  'TCM-002': 'Detects tenantId accepted as a function parameter without validation against the session. This allows callers to impersonate other tenants.',
  'TCM-003': 'Detects tenant context lost across async boundaries (setTimeout, Promise.then, event handlers). Global tenant state may leak between concurrent requests.',
  'TCM-004': 'Detects mismatches between tenant ID in the request and the session token. An attacker may attempt to access another tenant by modifying the request tenant ID.',
  'TCM-005': 'Detects route handlers that access database queries without a prior tenant context middleware. Without middleware, some routes may skip tenant setup.',
  'TCM-006': 'Detects module-level caching of tenant context. If tenant ID is cached in a global variable, concurrent requests will cross-contaminate.',
  'DBQ-001': 'This rule detects Prisma findMany queries that lack a tenant filter (organizationId/tenantId) in the WHERE clause. Without this filter, data from all tenants may be returned.',
  'DBQ-002': 'This rule detects findUnique queries that look up records by ID only, without verifying the record belongs to the caller tenant. This is an IDOR risk.',
  'DBQ-003': 'This rule detects update/delete operations without a tenant field in the WHERE clause, allowing cross-tenant modification.',
  'DBQ-004': 'This rule detects raw SQL queries ($queryRaw, $executeRaw) without a tenant filter in the WHERE clause. Raw SQL bypasses ORM-level tenant scoping.',
  'DBQ-005': 'This rule detects Drizzle ORM queries that lack a tenant filter in the where clause. Same risk as DBQ-001 but for Drizzle users.',
  'DBQ-006': 'This rule detects tenant-scoped tables with active database queries but no RLS policy enabled. Cross-tenant data access is possible at the database level.',
  'DBQ-007': 'This rule detects RLS policies that use USING(true) or WITH CHECK(true), effectively disabling row-level security. Queries on these tables are not isolated.',
  'DBQ-008': 'This rule detects Prisma include/select nested queries without tenant filters on the included relations. Parent-level filtering does not protect nested reads.',
  'DBQ-009': 'This rule detects aggregate/count/groupBy queries without a tenant filter. Aggregates across tenants leak statistics and counts.',
  'DBQ-010': 'This rule detects upsert calls without a tenant filter in the where clause. Upserts may create or update records in the wrong tenant.',
  'IDOR-001': 'This rule detects direct object references without tenant ownership verification. Accessing resources by ID without checking tenant ownership is a classic IDOR vulnerability.',
  'IDOR-002': 'This rule detects API routes that accept record IDs from the client without verifying the record belongs to the caller tenant. Classic IDOR vulnerability via route parameter.',
  'IDOR-003': 'This rule detects findUnique by ID without subsequent tenant ownership check. The lookup returns the record regardless of tenant, enabling cross-tenant access.',
  'IDOR-004': 'This rule detects update/delete by ID without tenant ownership verification. An attacker can modify or delete another tenant resources by guessing IDs.',
  'IDOR-005': 'This rule detects bulk operations that reference multiple IDs without verifying all belong to the caller tenant. Bulk endpoints may mix tenant data.',
  'CSI-001': 'This rule detects cache operations without tenant ID in the cache key. Shared cache keys cause cross-tenant data leakage.',
  'CSI-002': 'This rule detects session management without tenant binding. Sessions not bound to a tenant can be used to access other tenants data.',
  'CSI-003': 'This rule detects cache writes without corresponding invalidation on tenant context change. Stale cache entries may serve wrong tenant data.',
  'CSI-004': 'This rule detects global singleton cache patterns (module-level Map, LRU cache) used for tenant-scoped data. Singletons share state across tenants.',
  'API-001': 'This rule detects API endpoints without per-tenant rate limiting. Without tenant-keyed limits, one tenant can exhaust API quotas for all tenants.',
  'API-002': 'This rule detects API routes with database queries lacking tenant filters, which may return cross-tenant data in responses.',
  'API-003': 'This rule detects API responses without tenant attribution metadata. Responses without tenant context cannot be audited for cross-tenant access.',
  'FSI-001': 'This rule detects file storage operations without tenant ID in the path or key. Shared file paths allow cross-tenant file access.',
  'FSI-002': 'This rule detects file operations without tenant ownership verification. Files accessed by path without tenant check enable cross-tenant file access.',
  'FSI-003': 'This rule detects S3/blob storage calls without tenant-scoped bucket prefixes. Shared prefixes allow cross-tenant file enumeration and access.',
  'FSI-004': 'This rule detects blob storage uploads without tenant metadata. Files without tenant metadata cannot be access-controlled at the storage layer.',
  'LOG-001': 'This rule detects logging calls without tenant context, making it impossible to attribute logs to specific tenants for auditing.',
  'LOG-002': 'This rule detects audit log entries for data access operations that do not include tenant context. Audit logs without tenant attribution fail compliance requirements.',
  'LOG-003': 'This rule detects error logging near unfiltered database operations. Error logs may include cross-tenant data from query results.',
  'LOG-004': 'This rule detects structured logging configurations that strip tenantId from log output. Audit trails cannot attribute actions to specific tenants.',
  'SCH-001': 'This rule detects Prisma models without a tenant isolation field (organizationId, tenantId). Models without tenant fields cannot be isolated at the data level.',
  'SCH-002': 'This rule detects SQL CREATE TABLE statements without a tenant column. Tables without tenant columns cannot be isolated at the data level.',
  'SCH-003': 'This rule detects indexes that do not start with the tenant column, causing queries to scan across tenants and reducing performance.',
  'SCH-004': 'This rule detects SQL tables with tenant columns but no RLS enabled. RLS provides defense-in-depth at the database level.',
  'SCH-005': 'This rule detects RLS policies that use USING(true) or WITH CHECK(true), effectively disabling row-level security for all tenants.',
  'SCH-006': 'This rule detects foreign key relationships without tenant column. Allows cross-tenant references between tables.',
  'MCP-001': 'This rule detects MCP tool handlers without tenant-based visibility filtering. All tenants see all tools, including tools scoped to specific tenants.',
  'MCP-002': 'This rule detects MCP tool result caching without tenant prefix in cache keys. Cached results from one tenant may be served to another.',
  'MCP-003': 'This rule detects MCP sessions bound only to a session ID without user or tenant binding. Session hijacking enables cross-tenant access.',
  'MCP-004': 'This rule detects MCP token forwarding without RFC 8693 token exchange. Forwarding original tokens leaks tenant credentials to downstream services.',
  'MCP-005': 'This rule detects MCP tool calls without per-tenant rate limiting. One tenant can exhaust tool call quotas for all tenants.',
  'MCP-006': 'This rule detects vector store usage without tenant namespaces. Shared vector stores allow cross-tenant similarity search results.',
  'MCP-007': 'This rule detects MCP tool descriptions that include user input without sanitization. Injected descriptions can mislead the AI agent.',
  'MCP-008': 'This rule detects MCP credential vaults without tenant scoping. Stored credentials may be accessible across tenants.',
  'MCP-009': 'This rule detects MCP server code using a single shared API key for all tenant API calls. Compromise of the key affects all tenants.',
  'MCP-010': 'This rule detects MCP session handling without cleanup on disconnect. Abandoned sessions accumulate and may be reused.',
  'MCP-011': 'This rule detects MCP telemetry events without tenant identifier. Telemetry without tenant context cannot be attributed for billing or monitoring.',
  'MCP-012': 'This rule detects MCP server binding to 0.0.0.0 instead of 127.0.0.1. Binding to all interfaces exposes the server to network access.',
  'MCP-013': 'This rule detects MCP filesystem tool handlers without tenant root directory restriction. Tools can access files outside the tenant scope.',
  'MCP-014': 'This rule detects MCP artifact storage without tenant prefix. Artifacts may be accessible across tenants.',
  'MCP-015': 'This rule detects MCP tool registration without tenant namespace. Dynamically registered tools may collide across tenants.',
};

export function aiJsonReporter(result: ScanResult): string {
  const findingsWithContext = sortBySeverity(result.findings).map(f => ({
    ...f,
    remediation: REMEDIATION_HINTS[f.ruleId] ?? 'Review the finding and add appropriate tenant isolation guards.',
    context: RULE_CONTEXT[f.ruleId] ?? '',
    ruleUrl: `https://www.haiec.com/mcp-tenant-isolation#rule-${f.ruleId.toLowerCase()}`,
  }));

  const byRule: Record<string, { count: number; severity: string; sampleFile: string }> = {};
  for (const f of result.findings) {
    if (!byRule[f.ruleId]) {
      byRule[f.ruleId] = {
        count: 0,
        severity: f.severity,
        sampleFile: f.evidence.file,
      };
    }
    byRule[f.ruleId].count++;
  }

  return JSON.stringify({
    schema: `mcp-tenant-isolation/${RULE_ENGINE_VERSION}-ai`,
    engineVersion: RULE_ENGINE_VERSION,
    timestamp: result.ir.scanTimestamp,
    durationMs: result.durationMs,
    stats: result.stats,
    summary: {
      totalFindings: result.stats.totalFindings,
      activeFindings: result.findings.filter(f => f.suppressionStatus !== 'suppressed' && f.suppressionStatus !== 'baseline').length,
      suppressedFindings: result.findings.filter(f => f.suppressionStatus === 'suppressed').length,
      baselineFindings: result.findings.filter(f => f.suppressionStatus === 'baseline').length,
      verdict: getVerdict(result),
      byRule: Object.entries(byRule)
        .sort(([, a], [, b]) => b.count - a.count)
        .reduce((acc, [k, v]) => { acc[k] = v; return acc; }, {} as Record<string, any>),
      topPriorities: Object.entries(byRule)
        .filter(([, v]) => v.severity === 'CRITICAL' || v.severity === 'HIGH')
        .sort(([, a], [, b]) => SEVERITY_RANK[a.severity as Severity] - SEVERITY_RANK[b.severity as Severity] || b.count - a.count)
        .slice(0, 5)
        .map(([k, v]) => ({ ruleId: k, count: v.count, severity: v.severity })),
    },
    findings: findingsWithContext,
  }, null, 2);
}


export function sarifReporter(result: ScanResult): string {
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcp-tenant-isolation',
            version: RULE_ENGINE_VERSION,
            informationUri: 'https://github.com/subodhkc/mcp-tenant-isolation',
            rules: getSarifRules(),
          },
        },
        results: sortBySeverity(result.findings).map((f) => toSarifResult(f)),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

function getSarifRules() {
  return ALL_RULES.map((r) => ({
    id: r.id,
    name: r.title,
    shortDescription: { text: r.title },
    fullDescription: { text: r.description },
    helpUri: `https://www.haiec.com/mcp-tenant-isolation#rule-${r.id.toLowerCase()}`,
    defaultConfiguration: { level: severityToSarifLevel(r.severity) },
    properties: {
      category: r.category,
      cwe: r.compliance?.cweIds ?? [],
      owaspMcpRef: r.compliance?.owaspMcpRef,
    },
  }));
}

function toSarifResult(finding: Finding) {
  return {
    ruleId: finding.ruleId,
    level: severityToSarifLevel(finding.severity),
    message: {
      text: finding.description,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: finding.evidence.file,
          },
          region: {
            startLine: finding.evidence.lineStart,
            endLine: finding.evidence.lineEnd,
          },
        },
      },
    ],
    partialFingerprints: {
      primaryLocationLineHash: finding.fingerprint,
    },
    properties: {
      severity: finding.severity,
      confidence: finding.confidence,
      missingGuards: finding.missingGuards,
      presentGuards: finding.presentGuards,
      suppressionStatus: finding.suppressionStatus ?? 'active',
    },
  };
}

function severityToSarifLevel(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
      return 'note';
    case 'INFO':
      return 'none';
    default:
      return 'none';
  }
}


export function terminalReporter(result: ScanResult): string {
  const lines: string[] = [];
  const { stats, findings, durationMs } = result;

  // Header
  lines.push('');
  lines.push('  mcp-tenant-isolation - Tenant Isolation Scanner');
  lines.push('  -----------------------------------------------');
  lines.push('');

  // Stats
  lines.push(`  Files scanned:    ${stats.filesScanned}`);
  lines.push(`  Rules evaluated:  ${stats.rulesEvaluated}`);
  lines.push(`  Rules triggered:  ${stats.rulesTriggered}`);
  lines.push(`  Duration:         ${durationMs}ms`);
  lines.push('');

  // Severity summary
  lines.push('  Findings by severity:');
  lines.push(`    CRITICAL: ${stats.bySeverity.CRITICAL}`);
  lines.push(`    HIGH:     ${stats.bySeverity.HIGH}`);
  lines.push(`    MEDIUM:   ${stats.bySeverity.MEDIUM}`);
  lines.push(`    LOW:      ${stats.bySeverity.LOW}`);
  lines.push(`    INFO:     ${stats.bySeverity.INFO ?? 0}`);
  lines.push(`    Total:    ${stats.totalFindings}`);
  lines.push('');

  // Suppression/baseline summary
  const suppressedCount = findings.filter(f => f.suppressionStatus === 'suppressed').length;
  const baselineCount = findings.filter(f => f.suppressionStatus === 'baseline').length;
  if (suppressedCount > 0 || baselineCount > 0) {
    lines.push('  Status:');
    if (suppressedCount > 0) lines.push(`    Suppressed: ${suppressedCount}`);
    if (baselineCount > 0) lines.push(`    Baseline:   ${baselineCount}`);
    lines.push('');
  }

  // Verdict
  const verdict = getVerdict(result);
  const verdictLabel = verdict === 'PASS' ? 'PASS' : 'FAIL';
  lines.push(`  Verdict: ${verdictLabel}`);
  lines.push('');

  if (findings.length === 0) {
    lines.push('  No tenant isolation issues found.');
    lines.push('');
    return lines.join('\n');
  }

  // Findings (show active first, then suppressed/baseline)
  const active = sortBySeverity(findings.filter(f => f.suppressionStatus !== 'suppressed' && f.suppressionStatus !== 'baseline'));
  const others = findings.filter(f => f.suppressionStatus === 'suppressed' || f.suppressionStatus === 'baseline');

  if (active.length > 0) {
    lines.push('  Active Findings:');
    lines.push('  -----------------------------------------------');
    lines.push('');
    for (const finding of active) {
      const sevLabel = severityLabel(finding.severity);
      lines.push(`  ${sevLabel} ${finding.ruleId}`);
      lines.push(`  ${finding.title}`);
      lines.push(`  ${finding.evidence.file}:${finding.evidence.lineStart}`);
      lines.push(`  ${finding.description}`);
      if (finding.missingGuards.length > 0) {
        lines.push(`  Missing guards: ${finding.missingGuards.join(', ')}`);
      }
      const hint = REMEDIATION_HINTS[finding.ruleId];
      if (hint) {
        lines.push(`  Fix: ${hint}`);
      }
      lines.push('');
    }
  }

  if (others.length > 0) {
    lines.push(`  Suppressed/Baseline (${others.length}):`);
    lines.push('  -----------------------------------------------');
    for (const finding of others) {
      const tag = finding.suppressionStatus === 'suppressed' ? '[SUPPRESSED]' : '[BASELINE]';
      lines.push(`  ${tag} ${finding.ruleId} - ${finding.evidence.file}:${finding.evidence.lineStart}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

export function markdownReporter(result: ScanResult): string {
  const { stats, findings, durationMs } = result;
  const verdict = getVerdict(result);
  const active = findings.filter(f => f.suppressionStatus !== 'suppressed' && f.suppressionStatus !== 'baseline');
  const suppressed = findings.filter(f => f.suppressionStatus === 'suppressed');
  const baseline = findings.filter(f => f.suppressionStatus === 'baseline');

  const lines: string[] = [];
  lines.push('# Tenant Isolation Scan Report');
  lines.push('');
  lines.push(`**Scanner:** mcp-tenant-isolation v${RULE_ENGINE_VERSION}`);
  lines.push(`**Date:** ${result.ir.scanTimestamp ?? new Date().toISOString()}`);
  lines.push(`**Duration:** ${durationMs}ms`);
  lines.push(`**Verdict:** ${verdict}`);
  lines.push('');

  lines.push('## Summary');
  lines.push('');
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| Files scanned | ${stats.filesScanned} |`);
  lines.push(`| Rules evaluated | ${stats.rulesEvaluated} |`);
  lines.push(`| Rules triggered | ${stats.rulesTriggered} |`);
  lines.push(`| Total findings | ${stats.totalFindings} |`);
  lines.push(`| Active findings | ${active.length} |`);
  if (suppressed.length > 0) lines.push(`| Suppressed | ${suppressed.length} |`);
  if (baseline.length > 0) lines.push(`| Baseline | ${baseline.length} |`);
  lines.push('');

  lines.push('### Findings by Severity');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  lines.push(`| CRITICAL | ${stats.bySeverity.CRITICAL} |`);
  lines.push(`| HIGH | ${stats.bySeverity.HIGH} |`);
  lines.push(`| MEDIUM | ${stats.bySeverity.MEDIUM} |`);
  lines.push(`| LOW | ${stats.bySeverity.LOW} |`);
  lines.push(`| INFO | ${stats.bySeverity.INFO ?? 0} |`);
  lines.push('');

  if (active.length === 0 && suppressed.length === 0 && baseline.length === 0) {
    lines.push('## Result');
    lines.push('');
    lines.push('No tenant isolation issues found.');
    lines.push('');
    return lines.join('\n');
  }

  // Group by rule
  const byRule: Record<string, typeof findings> = {};
  for (const f of active) {
    if (!byRule[f.ruleId]) byRule[f.ruleId] = [];
    byRule[f.ruleId].push(f);
  }

  lines.push('## Active Findings');
  lines.push('');
  for (const [ruleId, ruleFindings] of Object.entries(byRule).sort((a, b) => {
    const sevA = a[1][0]?.severity ?? 'INFO';
    const sevB = b[1][0]?.severity ?? 'INFO';
    return SEVERITY_RANK[sevA] - SEVERITY_RANK[sevB] || b[1].length - a[1].length;
  })) {
    const first = ruleFindings[0];
    lines.push(`### ${ruleId} - ${first.title} (${ruleFindings.length} findings)`);
    lines.push('');
    lines.push(`**Severity:** ${first.severity}`);
    lines.push(`**Description:** ${first.description}`);
    lines.push('');
    const hint = REMEDIATION_HINTS[ruleId];
    if (hint) {
      lines.push(`**Remediation:** ${hint}`);
      lines.push('');
    }
    lines.push('| File | Line |');
    lines.push('|------|------|');
    for (const f of ruleFindings.slice(0, 20)) {
      lines.push(`| ${f.evidence.file} | ${f.evidence.lineStart} |`);
    }
    if (ruleFindings.length > 20) {
      lines.push(`| ... and ${ruleFindings.length - 20} more | |`);
    }
    lines.push('');
  }

  if (suppressed.length > 0) {
    lines.push('## Suppressed Findings');
    lines.push('');
    lines.push('| Rule | File | Line |');
    lines.push('|------|------|------|');
    for (const f of suppressed) {
      lines.push(`| ${f.ruleId} | ${f.evidence.file} | ${f.evidence.lineStart} |`);
    }
    lines.push('');
  }

  if (baseline.length > 0) {
    lines.push('## Baseline Findings (pre-existing)');
    lines.push('');
    lines.push('| Rule | File | Line |');
    lines.push('|------|------|------|');
    for (const f of baseline) {
      lines.push(`| ${f.ruleId} | ${f.evidence.file} | ${f.evidence.lineStart} |`);
    }
    lines.push('');
  }

  lines.push('---');
  lines.push('');
  lines.push(`Generated by [mcp-tenant-isolation](https://www.haiec.com/mcp-tenant-isolation) v${RULE_ENGINE_VERSION}`);
  lines.push('');

  return lines.join('\n');
}

function getVerdict(result: ScanResult): 'PASS' | 'FAIL' {
  const active = result.findings.filter(
    f => f.suppressionStatus !== 'suppressed' && f.suppressionStatus !== 'baseline'
  );
  const hasCriticalOrHigh = active.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
  return hasCriticalOrHigh ? 'FAIL' : 'PASS';
}

function severityLabel(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL':
      return '[CRITICAL]';
    case 'HIGH':
      return '[HIGH]    ';
    case 'MEDIUM':
      return '[MEDIUM]  ';
    case 'LOW':
      return '[LOW]     ';
    case 'INFO':
      return '[INFO]    ';
    default:
      return '[UNKNOWN] ';
  }
}
