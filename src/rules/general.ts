/**
 * General Multi-Tenant Rules - 42 rules across 8 categories
 *
 * TCM: Tenant Context Management (6)
 * DBQ: Database Query Isolation (10)
 * IDOR: IDOR Prevention (5)
 * CSI: Cache & Session Isolation (4)
 * API: API Security (3)
 * FSI: File Storage Isolation (4)
 * LOG: Logging & Audit (4)
 * SCH: Schema & Migration (6)
 */

import type { RuleSpec } from '../rule-spec.js';
import { createRule, buildFinding, buildEvidence } from '../rule-spec.js';
import {
  TENANT_ISOLATION_GUARDS,
  AUTHENTICATION_GUARDS,
  hasGuard,
  findMissingGuards,
  findPresentGuards,
} from '../guards.js';
import type { Finding, IR, Sink, PrismaModelInfo } from '../types.js';

/**
 * Check if a file has any auth signals within the same function scope as a sink.
 * Uses functionStartLine/functionEndLine if available for precise scoping.
 */
function functionHasAuthSignal(
  ir: IR,
  file: string,
  fnStart?: number,
  fnEnd?: number
): boolean {
  return ir.authSignals.some((sig) => {
    if (sig.location.file !== file) return false;
    if (fnStart && fnEnd) {
      return sig.location.line >= fnStart && sig.location.line <= fnEnd;
    }
    return true; // fallback to file-level if no function range
  });
}

/**
 * Extract the Prisma model name from a sink API string.
 * e.g., "prisma.user.findMany" → "user", "db.organization.update" → "organization"
 */
function getModelNameFromSink(sink: Sink): string | null {
  const match = sink.api.match(/(?:prisma|db|tx|transaction|connection|drizzle|pool|supabase|kysely)\.(\w+)\./);
  return match?.[1] ?? null;
}

/**
 * Check if a model is tenant-scoped based on Prisma schema info.
 * Returns true for unknown models (safe default — don't suppress findings).
 */
function isTenantScopedModel(ir: IR, modelName: string | null): boolean {
  if (!modelName) return true; // Unknown model — don't suppress
  const model = ir.prismaModels?.find(
    (m: PrismaModelInfo) => m.name.toLowerCase() === modelName.toLowerCase()
  );
  if (!model) return true; // Unknown model — don't suppress
  return model.hasTenantField || model.scope === 'tenant';
}

// TCM - Tenant Context Management (6)

const TCM_001 = createRule({
  id: 'TCM-001',
  category: 'Tenant Context Management',
  title: 'Tenant ID from client input instead of session',
  description:
    'Tenant ID is derived from client input (req.body, req.query, params) instead of authenticated session. Allows tenant spoofing.',
  severity: 'CRITICAL',
  requiredGuards: [...AUTHENTICATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 10,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    for (const source of ir.sources) {
      if (
        source.kind === 'user' ||
        source.kind === 'query_param'
      ) {
        const code = source.symbol;
        if (
          (code.includes('tenantId') || code.includes('organizationId')) &&
          !code.includes('session.') &&
          !code.includes('auth()') &&
          !code.includes('getServerSession')
        ) {
          const missing = findMissingGuards(code, AUTHENTICATION_GUARDS);
          const present = findPresentGuards(code, AUTHENTICATION_GUARDS);
          findings.push(
            buildFinding(
              'TCM-001',
              'Tenant ID from client input instead of session',
              'CRITICAL',
              'Tenant ID is derived from client input instead of authenticated session. Allows tenant spoofing.',
              buildEvidence(source.location.file, source.location.line, source.location.line, code),
              missing,
              present
            )
          );
        }
      }
    }
    return findings;
  },
});

const TCM_002 = createRule({
  id: 'TCM-002',
  category: 'Tenant Context Management',
  title: 'Missing tenant context in async boundaries',
  description:
    'Tenant context is not propagated across async boundaries (setTimeout, queue, event emitter). AsyncLocalStorage not used.',
  severity: 'CRITICAL',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 11,
  evaluate: (ir) => {
    const findings = [];
    for (const entry of ir.entrypoints) {
      if (entry.type === 'background_job') {
        const hasAsyncLocal = ir.assignments.some(
          (a) => a.dst.includes('AsyncLocalStorage') || a.dst.includes('asyncLocalStorage')
        );
        if (!hasAsyncLocal) {
          const code = `Background job at ${entry.path} without AsyncLocalStorage`;
          findings.push(
            buildFinding(
              'TCM-002',
              'Missing tenant context in async boundaries',
              'CRITICAL',
              'Background job does not use AsyncLocalStorage for tenant context propagation.',
              buildEvidence(entry.location.file, entry.location.line, entry.location.line, code),
              ['AsyncLocalStorage'],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const TCM_003 = createRule({
  id: 'TCM-003',
  category: 'Tenant Context Management',
  title: 'No AsyncLocalStorage for tenant context',
  description:
    'Project does not use AsyncLocalStorage or equivalent for tenant context propagation.',
  severity: 'CRITICAL',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 12,
  evaluate: (ir) => {
    const hasAsyncLocal = ir.assignments.some(
      (a) => a.dst.includes('AsyncLocalStorage') || a.srcSyms.some((s) => s.includes('AsyncLocalStorage'))
    );
    if (!hasAsyncLocal && ir.entrypoints.length > 5) {
      return [
        buildFinding(
          'TCM-003',
          'No AsyncLocalStorage for tenant context',
          'CRITICAL',
          'Project has multiple entrypoints but does not use AsyncLocalStorage for tenant context.',
          buildEvidence('<project>', 0, 0, 'No AsyncLocalStorage import detected'),
          ['AsyncLocalStorage'],
          []
        ),
      ];
    }
    return [];
  },
});

const TCM_004 = createRule({
  id: 'TCM-004',
  category: 'Tenant Context Management',
  title: 'Tenant ID from URL path instead of JWT',
  description:
    'Tenant ID is extracted from URL path parameters instead of JWT token. Allows cross-tenant access by changing URL.',
  severity: 'CRITICAL',
  requiredGuards: [...AUTHENTICATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 13,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    for (const source of ir.sources) {
      if (source.kind === 'query_param' && source.symbol.includes('tenantId')) {
        const code = `URL param ${source.symbol} used as tenant identifier`;
        findings.push(
          buildFinding(
            'TCM-004',
            'Tenant ID from URL path instead of JWT',
            'CRITICAL',
            'Tenant ID extracted from URL path. Should come from JWT/session.',
            buildEvidence(source.location.file, source.location.line, source.location.line, code),
            [...AUTHENTICATION_GUARDS],
            []
          )
        );
      }
    }
    return findings;
  },
});

const TCM_005 = createRule({
  id: 'TCM-005',
  category: 'Tenant Context Management',
  title: 'Missing tenant context in queue handler',
  description:
    'Queue/job handler does not extract or propagate tenant context from job payload.',
  severity: 'CRITICAL',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 14,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    for (const entry of ir.entrypoints) {
      if (entry.type === 'background_job') {
        const hasTenant = ir.tenantScopes.some(
          (ts) => ts.entrypointId === entry.id && ts.hasTenantFilter
        );
        if (!hasTenant) {
          findings.push(
            buildFinding(
              'TCM-005',
              'Missing tenant context in queue handler',
              'CRITICAL',
              `Queue handler ${entry.path} does not extract tenant context from job payload.`,
              buildEvidence(entry.location.file, entry.location.line, entry.location.line, `Handler: ${entry.path}`),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const TCM_006 = createRule({
  id: 'TCM-006',
  category: 'Tenant Context Management',
  title: 'Tenant context lost in error handling',
  description:
    'Error handler does not preserve tenant context for logging and audit.',
  severity: 'CRITICAL',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 15,
  evaluate: (ir): Finding[] => {
    // Check for catch blocks that log without tenant context
    const findings: Finding[] = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'log' && sink.api.includes('catch')) {
        const hasTenant = ir.tenantScopes.some(
          (ts) => ts.appliesToSinkId === sink.id && ts.hasTenantFilter
        );
        if (!hasTenant) {
          findings.push(
            buildFinding(
              'TCM-006',
              'Tenant context lost in error handling',
              'CRITICAL',
              'Error handler logs without tenant context.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

// DBQ - Database Query Isolation (10)

const DBQ_001 = createRule({
  id: 'DBQ-001',
  category: 'Database Query Isolation',
  title: 'findMany without organizationId filter',
  description:
    'Database findMany query on tenant-scoped model does not include organizationId/tenantId in WHERE clause.',
  severity: 'CRITICAL',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639', 'CWE-200'],
  executionOrder: 20,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'db_read' && sink.api.includes('findMany')) {
        if (!isTenantScopedModel(ir, getModelNameFromSink(sink))) continue;
        const hasTenant = ir.tenantScopes.some(
          (ts) => ts.appliesToSinkId === sink.id && ts.hasTenantFilter
        );
        const hasAuth = functionHasAuthSignal(ir, sink.location.file, sink.functionStartLine, sink.functionEndLine);
        if (!hasTenant && !hasAuth) {
          const missing = findMissingGuards(sink.api, TENANT_ISOLATION_GUARDS);
          const present = findPresentGuards(sink.api, TENANT_ISOLATION_GUARDS);
          findings.push(
            buildFinding(
              'DBQ-001',
              'findMany without organizationId filter',
              'CRITICAL',
              'findMany query on tenant-scoped model without tenant filter in WHERE clause.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              missing,
              present
            )
          );
        }
      }
    }
    return findings;
  },
});

const DBQ_002 = createRule({
  id: 'DBQ-002',
  category: 'Database Query Isolation',
  title: 'findUnique by ID without tenant ownership',
  description:
    'findUnique query uses only ID without verifying tenant ownership. Allows IDOR.',
  severity: 'HIGH',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639', 'CWE-284'],
  executionOrder: 21,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'db_read' && sink.api.includes('findUnique')) {
        if (!isTenantScopedModel(ir, getModelNameFromSink(sink))) continue;
        const hasTenant = ir.tenantScopes.some(
          (ts) => ts.appliesToSinkId === sink.id && ts.hasTenantFilter
        );
        const hasAuth = functionHasAuthSignal(ir, sink.location.file, sink.functionStartLine, sink.functionEndLine);
        if (!hasTenant && !hasAuth) {
          findings.push(
            buildFinding(
              'DBQ-002',
              'findUnique by ID without tenant ownership',
              'HIGH',
              'findUnique by ID only - no tenant ownership check. IDOR risk.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const DBQ_003 = createRule({
  id: 'DBQ-003',
  category: 'Database Query Isolation',
  title: 'update/delete without tenant field',
  description:
    'update or delete operation on tenant-scoped model without tenant field in WHERE clause.',
  severity: 'CRITICAL',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639', 'CWE-284'],
  executionOrder: 22,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (
        sink.kind === 'db_write' &&
        (sink.api.includes('update') || sink.api.includes('delete'))
      ) {
        if (!isTenantScopedModel(ir, getModelNameFromSink(sink))) continue;
        const hasTenant = ir.tenantScopes.some(
          (ts) => ts.appliesToSinkId === sink.id && ts.hasTenantFilter
        );
        const hasAuth = functionHasAuthSignal(ir, sink.location.file, sink.functionStartLine, sink.functionEndLine);
        if (!hasTenant && !hasAuth) {
          findings.push(
            buildFinding(
              'DBQ-003',
              'update/delete without tenant field',
              'CRITICAL',
              'update/delete without tenant field in WHERE. Cross-tenant modification risk.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const DBQ_004 = createRule({
  id: 'DBQ-004',
  category: 'Database Query Isolation',
  title: 'Raw SQL ($queryRaw) without tenant filter',
  description:
    'Raw SQL query via $queryRaw or $executeRaw does not include tenant filter.',
  severity: 'CRITICAL',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639', 'CWE-89'],
  executionOrder: 23,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (
        sink.kind === 'db_read' &&
        (sink.api.includes('queryRaw') || sink.api.includes('executeRaw'))
      ) {
        const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS) ||
          hasGuard(sink.argsVars.join(' '), TENANT_ISOLATION_GUARDS) ||
          ir.tenantScopes.some((ts) => ts.appliesToSinkId === sink.id && ts.hasTenantFilter);
        const hasAuth = functionHasAuthSignal(ir, sink.location.file, sink.functionStartLine, sink.functionEndLine);
        if (!hasTenant && !hasAuth) {
          findings.push(
            buildFinding(
              'DBQ-004',
              'Raw SQL ($queryRaw) without tenant filter',
              'CRITICAL',
              'Raw SQL query without tenant filter. Cross-tenant data exposure.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const DBQ_005 = createRule({
  id: 'DBQ-005',
  category: 'Database Query Isolation',
  title: 'Drizzle select() without .where(eq(tenantId))',
  description:
    'Drizzle ORM select query does not include .where(eq(tenantId, ...)) clause.',
  severity: 'CRITICAL',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 24,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'db_read' && sink.api.includes('select') && sink.api.includes('drizzle')) {
        const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS) ||
          hasGuard(sink.argsVars.join(' '), TENANT_ISOLATION_GUARDS) ||
          ir.tenantScopes.some((ts) => ts.appliesToSinkId === sink.id && ts.hasTenantFilter);
        const hasAuth = functionHasAuthSignal(ir, sink.location.file, sink.functionStartLine, sink.functionEndLine);
        if (!hasTenant && !hasAuth) {
          findings.push(
            buildFinding(
              'DBQ-005',
              'Drizzle select() without .where(eq(tenantId))',
              'CRITICAL',
              'Drizzle select without tenant filter in .where().',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const DBQ_006 = createRule({
  id: 'DBQ-006',
  category: 'Database Query Isolation',
  title: 'Missing RLS policy on tenant-scoped table',
  description:
    'Tenant-scoped table does not have Row Level Security policy enabled.',
  severity: 'MEDIUM',
  requiredGuards: ['row_level_security', 'rls'],
  cweIds: ['CWE-639', 'CWE-668'],
  executionOrder: 25,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    const tables = ir.sqlTables ?? [];
    const rlsEnabled = ir.sqlRlsEnabledTables ?? [];
    for (const table of tables) {
      if (table.hasTenantColumn && !rlsEnabled.includes(table.name)) {
        const tableNameLower = table.name.toLowerCase();
        const hasQuery = ir.sinks.some(
          (s) => s.kind === 'db_read' && getModelNameFromSink(s)?.toLowerCase() === tableNameLower
        );
        if (hasQuery) {
          findings.push(
            buildFinding(
              'DBQ-006',
              'Missing RLS policy on tenant-scoped table',
              'MEDIUM',
              `Database queries on table "${table.name}" are not protected by RLS. Cross-tenant data access is possible.`,
              buildEvidence(table.location.file, table.location.line, table.location.line, `CREATE TABLE ${table.name}`),
              ['row_level_security', 'rls'],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const DBQ_007 = createRule({
  id: 'DBQ-007',
  category: 'Database Query Isolation',
  title: 'RLS policy uses USING(true)',
  description:
    'RLS policy uses USING(true) or WITH CHECK(true), effectively disabling row-level security.',
  severity: 'CRITICAL',
  requiredGuards: [],
  cweIds: ['CWE-639', 'CWE-668'],
  executionOrder: 26,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    const policies = ir.sqlRlsPolicies ?? [];
    for (const policy of policies) {
      if (policy.isBypassed) {
        const policyTableLower = policy.tableName.toLowerCase();
        const hasQuery = ir.sinks.some(
          (s) => s.kind === 'db_read' && getModelNameFromSink(s)?.toLowerCase() === policyTableLower
        );
        if (hasQuery) {
          findings.push(
            buildFinding(
              'DBQ-007',
              'RLS policy uses USING(true)',
              'CRITICAL',
              `RLS policy "${policy.policyName}" on table "${policy.tableName}" uses USING(true) or WITH CHECK(true), allowing all rows. Queries on this table are not isolated.`,
              buildEvidence(policy.location.file, policy.location.line, policy.location.line, `CREATE POLICY ${policy.policyName}`),
              [],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const DBQ_008 = createRule({
  id: 'DBQ-008',
  category: 'Database Query Isolation',
  title: 'Prisma include on relation without tenant filter',
  description:
    'Prisma include/select on relation does not include tenant filter on the related model.',
  severity: 'CRITICAL',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 27,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'db_read' && (sink.api.includes('include:') || sink.api.includes('select:'))) {
        if (!isTenantScopedModel(ir, getModelNameFromSink(sink))) continue;
        const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS) ||
          hasGuard(sink.argsVars.join(' '), TENANT_ISOLATION_GUARDS) ||
          ir.tenantScopes.some((ts) => ts.appliesToSinkId === sink.id && ts.hasTenantFilter);
        const hasAuth = functionHasAuthSignal(ir, sink.location.file, sink.functionStartLine, sink.functionEndLine);
        if (!hasTenant && !hasAuth) {
          findings.push(
            buildFinding(
              'DBQ-008',
              'Prisma include on relation without tenant filter',
              'CRITICAL',
              'Prisma include/select on relation without tenant filter on related model.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const DBQ_009 = createRule({
  id: 'DBQ-009',
  category: 'Database Query Isolation',
  title: 'Aggregate query without tenant filter',
  description:
    'Aggregate query (count, aggregate, groupBy) on tenant-scoped model without tenant filter.',
  severity: 'HIGH',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639', 'CWE-200'],
  executionOrder: 28,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (
        sink.kind === 'db_read' &&
        (sink.api.includes('count') || sink.api.includes('aggregate') || sink.api.includes('groupBy'))
      ) {
        if (!isTenantScopedModel(ir, getModelNameFromSink(sink))) continue;
        const hasTenant = ir.tenantScopes.some(
          (ts) => ts.appliesToSinkId === sink.id && ts.hasTenantFilter
        );
        const hasAuth = functionHasAuthSignal(ir, sink.location.file, sink.functionStartLine, sink.functionEndLine);
        if (!hasTenant && !hasAuth) {
          findings.push(
            buildFinding(
              'DBQ-009',
              'Aggregate query without tenant filter',
              'HIGH',
              'Aggregate query without tenant filter. Cross-tenant data leakage.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const DBQ_010 = createRule({
  id: 'DBQ-010',
  category: 'Database Query Isolation',
  title: 'upsert without tenant field in where',
  description:
    'upsert operation does not include tenant field in WHERE clause. Can update cross-tenant records.',
  severity: 'CRITICAL',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639', 'CWE-284'],
  executionOrder: 29,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'db_write' && sink.api.includes('upsert')) {
        if (!isTenantScopedModel(ir, getModelNameFromSink(sink))) continue;
        const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS) ||
          hasGuard(sink.argsVars.join(' '), TENANT_ISOLATION_GUARDS) ||
          ir.tenantScopes.some((ts) => ts.appliesToSinkId === sink.id && ts.hasTenantFilter);
        const hasAuth = functionHasAuthSignal(ir, sink.location.file, sink.functionStartLine, sink.functionEndLine);
        if (!hasTenant && !hasAuth) {
          findings.push(
            buildFinding(
              'DBQ-010',
              'upsert without tenant field in where',
              'CRITICAL',
              'upsert without tenant field in WHERE. Cross-tenant update risk.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

// IDOR - IDOR Prevention (5)

const IDOR_001 = createRule({
  id: 'IDOR-001',
  category: 'IDOR Prevention',
  title: 'findUnique by ID only, no tenant check',
  description:
    'API route looks up record by ID without verifying tenant ownership.',
  severity: 'CRITICAL',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 30,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'db_read' && sink.api.includes('findUnique') && sink.api.includes('id:')) {
        if (!isTenantScopedModel(ir, getModelNameFromSink(sink))) continue;
        const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS) ||
          hasGuard(sink.argsVars.join(' '), TENANT_ISOLATION_GUARDS) ||
          ir.tenantScopes.some((ts) => ts.appliesToSinkId === sink.id && ts.hasTenantFilter);
        const hasAuth = functionHasAuthSignal(ir, sink.location.file, sink.functionStartLine, sink.functionEndLine);
        if (!hasTenant && !hasAuth) {
          findings.push(
            buildFinding(
              'IDOR-001',
              'findUnique by ID only, no tenant check',
              'CRITICAL',
              'Record lookup by ID without tenant ownership verification.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const IDOR_002 = createRule({
  id: 'IDOR-002',
  category: 'IDOR Prevention',
  title: 'API route accepts id without tenant ownership',
  description:
    'API route accepts record ID from client without verifying the record belongs to the tenant.',
  severity: 'CRITICAL',
  requiredGuards: [...TENANT_ISOLATION_GUARDS, ...AUTHENTICATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 31,
  evaluate: (ir) => {
    const findings = [];
    for (const entry of ir.entrypoints) {
      if (entry.type === 'api_route' && entry.path.includes(':id') || entry.path.includes('[id]')) {
        const hasAuth = entry.authSignals.length > 0;
        const hasTenant = ir.tenantScopes.some(
          (ts) => ts.entrypointId === entry.id && ts.hasTenantFilter
        );
        if (!hasTenant) {
          findings.push(
            buildFinding(
              'IDOR-002',
              'API route accepts id without tenant ownership',
              'CRITICAL',
              `Route ${entry.path} accepts ID without tenant ownership check.`,
              buildEvidence(entry.location.file, entry.location.line, entry.location.line, `Route: ${entry.path}`),
              [...TENANT_ISOLATION_GUARDS],
              hasAuth ? [...AUTHENTICATION_GUARDS] : []
            )
          );
        }
      }
    }
    return findings;
  },
});

const IDOR_003 = createRule({
  id: 'IDOR-003',
  category: 'IDOR Prevention',
  title: 'File download by ID without tenant check',
  description:
    'File download endpoint accepts file ID without verifying tenant ownership.',
  severity: 'CRITICAL',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 32,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'file_read' || sink.kind === 'object_storage') {
        const hasTenant = ir.tenantScopes.some(
          (ts) => ts.appliesToSinkId === sink.id && ts.hasTenantFilter
        );
        const hasAuth = functionHasAuthSignal(ir, sink.location.file, sink.functionStartLine, sink.functionEndLine);
        if (!hasTenant && !hasAuth && sink.argsVars.some((v) => v.includes('id') || v.includes('fileId'))) {
          findings.push(
            buildFinding(
              'IDOR-003',
              'File download by ID without tenant check',
              'CRITICAL',
              'File download by ID without tenant ownership verification.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const IDOR_004 = createRule({
  id: 'IDOR-004',
  category: 'IDOR Prevention',
  title: 'Update/Delete by ID without tenant verification',
  description:
    'Update or delete operation uses record ID without verifying tenant ownership.',
  severity: 'CRITICAL',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639', 'CWE-284'],
  executionOrder: 33,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (
        sink.kind === 'db_write' &&
        (sink.api.includes('update') || sink.api.includes('delete')) &&
        sink.api.includes('id:')
      ) {
        const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS) ||
          hasGuard(sink.argsVars.join(' '), TENANT_ISOLATION_GUARDS) ||
          ir.tenantScopes.some((ts) => ts.appliesToSinkId === sink.id && ts.hasTenantFilter);
        const hasAuth = functionHasAuthSignal(ir, sink.location.file, sink.functionStartLine, sink.functionEndLine);
        if (!hasTenant && !hasAuth) {
          findings.push(
            buildFinding(
              'IDOR-004',
              'Update/Delete by ID without tenant verification',
              'CRITICAL',
              'Update/delete by ID without tenant ownership check.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const IDOR_005 = createRule({
  id: 'IDOR-005',
  category: 'IDOR Prevention',
  title: 'Webhook accepts external ID without tenant mapping',
  description:
    'Webhook handler accepts external ID from third-party without mapping to internal tenant-scoped record.',
  severity: 'CRITICAL',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 34,
  evaluate: (ir) => {
    const findings = [];
    for (const entry of ir.entrypoints) {
      if (entry.type === 'webhook') {
        const hasTenant = ir.tenantScopes.some(
          (ts) => ts.entrypointId === entry.id && ts.hasTenantFilter
        );
        if (!hasTenant) {
          findings.push(
            buildFinding(
              'IDOR-005',
              'Webhook accepts external ID without tenant mapping',
              'CRITICAL',
              `Webhook ${entry.path} accepts external ID without tenant mapping.`,
              buildEvidence(entry.location.file, entry.location.line, entry.location.line, `Webhook: ${entry.path}`),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

// CSI - Cache & Session Isolation (4)

const CSI_001 = createRule({
  id: 'CSI-001',
  category: 'Cache & Session Isolation',
  title: 'Redis cache key without tenant prefix',
  description:
    'Redis cache key does not include tenant prefix. Cross-tenant cache poisoning possible.',
  severity: 'LOW',
  requiredGuards: ['tenantPrefix', 'cachePrefix', 'keyPrefix', 'namespacePrefix', 'tenantCacheKey', 'scopedCacheKey', 'tenantId', 'organizationId'],
  cweIds: ['CWE-639'],
  executionOrder: 40,
  evaluate: (ir) => {
    const findings = [];
    const CLIENT_SIDE_PATH_PATTERNS = ['/hooks/', '/components/', '/lib/llmverify/hooks/'];
    for (const sink of ir.sinks) {
      if (sink.kind === 'cache_write' || sink.kind === 'cache_read') {
        // Skip client-side cache (React Query, SWR, etc.) — not server-side Redis
        const isClientSide = CLIENT_SIDE_PATH_PATTERNS.some((p) => sink.location.file.includes(p));
        if (isClientSide) continue;
        const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS);
        if (!hasTenant) {
          findings.push(
            buildFinding(
              'CSI-001',
              'Redis cache key without tenant prefix',
              'LOW',
              'Cache key without tenant prefix. Cross-tenant cache poisoning.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              ['tenantPrefix', 'cachePrefix', 'keyPrefix'],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const CSI_002 = createRule({
  id: 'CSI-002',
  category: 'Cache & Session Isolation',
  title: 'Session data without tenant scoping',
  description:
    'Session storage does not include tenant scoping. Session data can leak across tenants.',
  severity: 'HIGH',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 41,
  evaluate: (ir) => {
    const findings = [];
    for (const entry of ir.entrypoints) {
      if (entry.authSignals.some((s) => s.includes('session'))) {
        const hasTenant = ir.tenantScopes.some(
          (ts) => ts.entrypointId === entry.id && ts.hasTenantFilter
        );
        if (!hasTenant) {
          findings.push(
            buildFinding(
              'CSI-002',
              'Session data without tenant scoping',
              'HIGH',
              `Session at ${entry.path} does not include tenant scoping.`,
              buildEvidence(entry.location.file, entry.location.line, entry.location.line, `Session at: ${entry.path}`),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const CSI_003 = createRule({
  id: 'CSI-003',
  category: 'Cache & Session Isolation',
  title: 'Cache key from user input only',
  description:
    'Cache key is constructed from user input only, without tenant context. Allows cache key collision.',
  severity: 'HIGH',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 42,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'cache_write' || sink.kind === 'cache_read') {
        const isUserInput = sink.argsVars.some((v) =>
          ir.sources.some((s) => s.symbol === v && (s.kind === 'user' || s.kind === 'query_param'))
        );
        const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS);
        if (isUserInput && !hasTenant) {
          findings.push(
            buildFinding(
              'CSI-003',
              'Cache key from user input only',
              'HIGH',
              'Cache key from user input without tenant context. Collision risk.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const CSI_004 = createRule({
  id: 'CSI-004',
  category: 'Cache & Session Isolation',
  title: 'Cache invalidation not scoped to tenant',
  description:
    'Cache invalidation is not scoped to tenant. One tenant can invalidate another tenant\'s cache.',
  severity: 'HIGH',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 43,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'cache_write' && (sink.api.includes('del') || sink.api.includes('invalidate') || sink.api.includes('flush'))) {
        const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS);
        if (!hasTenant) {
          findings.push(
            buildFinding(
              'CSI-004',
              'Cache invalidation not scoped to tenant',
              'HIGH',
              'Cache invalidation without tenant scoping. Cross-tenant cache wipe.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

// API - API Security (3)

const API_001 = createRule({
  id: 'API-001',
  category: 'API Security',
  title: 'Rate limiter without tenantId',
  description:
    'Rate limiter does not include tenantId as key. Single tenant can exhaust shared rate limit.',
  severity: 'HIGH',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-770'],
  executionOrder: 50,
  evaluate: (ir) => {
    const findings = [];
    for (const entry of ir.entrypoints) {
      if (entry.type === 'api_route') {
        const hasRateLimit = entry.authSignals.some((s) =>
          s.includes('rateLimit') || s.includes('throttle')
        );
        if (hasRateLimit) {
          const hasTenant = ir.tenantScopes.some(
            (ts) => ts.entrypointId === entry.id && ts.hasTenantFilter
          );
          if (!hasTenant) {
            findings.push(
              buildFinding(
                'API-001',
                'Rate limiter without tenantId',
                'HIGH',
                `Rate limiter at ${entry.path} does not use tenantId as key.`,
                buildEvidence(entry.location.file, entry.location.line, entry.location.line, `Route: ${entry.path}`),
                [...TENANT_ISOLATION_GUARDS],
                []
              )
            );
          }
        }
      }
    }
    return findings;
  },
});

const API_002 = createRule({
  id: 'API-002',
  category: 'API Security',
  title: 'API response includes cross-tenant data',
  description:
    'API response includes data from multiple tenants. Over-fetching beyond tenant boundary.',
  severity: 'MEDIUM',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-200'],
  executionOrder: 51,
  evaluate: (ir) => {
    const findings: Finding[] = [];
    const seenFiles = new Set<string>();
    for (const sink of ir.sinks) {
      if (sink.kind === 'db_read' && !seenFiles.has(sink.location.file)) {
        const isApiRoute = sink.location.file.includes('/api/') || sink.location.file.includes('route.ts');
        if (!isApiRoute) continue;
        const hasTenant = ir.tenantScopes.some(
          (ts) => ts.appliesToSinkId === sink.id && ts.hasTenantFilter
        );
        const hasAuth = functionHasAuthSignal(ir, sink.location.file, sink.functionStartLine, sink.functionEndLine);
        if (!hasTenant && !hasAuth) {
          seenFiles.add(sink.location.file);
          findings.push(
            buildFinding(
              'API-002',
              'API response includes cross-tenant data',
              'MEDIUM',
              'API route has database query without tenant filter. Response may include cross-tenant data.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const API_003 = createRule({
  id: 'API-003',
  category: 'API Security',
  title: 'Missing tenantId in API response metadata',
  description:
    'API response does not include tenantId in metadata. Impossible to attribute API calls to tenants.',
  severity: 'MEDIUM',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-778'],
  executionOrder: 52,
  evaluate: (ir) => {
    const findings: Finding[] = [];
    const seenFiles = new Set<string>();
    for (const sink of ir.sinks) {
      if ((sink.kind === 'db_read' || sink.kind === 'db_write') && !seenFiles.has(sink.location.file)) {
        const isApiRoute = sink.location.file.includes('/api/') || sink.location.file.includes('route.ts');
        if (!isApiRoute) continue;
        const fileScopes = ir.tenantScopes.filter(
          (ts) => ts.location.file === sink.location.file
        );
        const hasAnyTenant = fileScopes.some((ts) => ts.hasTenantFilter);
        const hasAuth = functionHasAuthSignal(ir, sink.location.file, sink.functionStartLine, sink.functionEndLine);
        if (!hasAnyTenant && !hasAuth) {
          seenFiles.add(sink.location.file);
          findings.push(
            buildFinding(
              'API-003',
              'Missing tenantId in API response metadata',
              'MEDIUM',
              'API route has no tenant context in any database operation. Response metadata cannot attribute calls to tenants.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

// FSI - File Storage Isolation (4)

const FSI_001 = createRule({
  id: 'FSI-001',
  category: 'File Storage Isolation',
  title: 'S3/Blob upload without tenant prefix',
  description:
    'S3 or Blob upload does not include tenant prefix in object key. Cross-tenant file access.',
  severity: 'HIGH',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 60,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'object_storage' && (sink.api.includes('put') || sink.api.includes('upload'))) {
        const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS);
        if (!hasTenant) {
          findings.push(
            buildFinding(
              'FSI-001',
              'S3/Blob upload without tenant prefix',
              'HIGH',
              'File upload without tenant prefix in object key.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const FSI_002 = createRule({
  id: 'FSI-002',
  category: 'File Storage Isolation',
  title: 'File download without tenant ownership',
  description:
    'File download does not verify tenant ownership of the file.',
  severity: 'HIGH',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 61,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'object_storage' && (sink.api.includes('get') || sink.api.includes('download'))) {
        const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS);
        if (!hasTenant) {
          findings.push(
            buildFinding(
              'FSI-002',
              'File download without tenant ownership',
              'HIGH',
              'File download without tenant ownership verification.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const FSI_003 = createRule({
  id: 'FSI-003',
  category: 'File Storage Isolation',
  title: 'Presigned URL without tenant scoping',
  description:
    'Presigned URL is generated without tenant scoping. URL can be shared across tenants.',
  severity: 'HIGH',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 62,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'object_storage' && sink.api.includes('presign')) {
        const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS);
        if (!hasTenant) {
          findings.push(
            buildFinding(
              'FSI-003',
              'Presigned URL without tenant scoping',
              'HIGH',
              'Presigned URL without tenant scoping. Shareable across tenants.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const FSI_004 = createRule({
  id: 'FSI-004',
  category: 'File Storage Isolation',
  title: 'Static file serving without tenant path validation',
  description:
    'Static file serving does not validate tenant path. Path traversal risk.',
  severity: 'HIGH',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-22', 'CWE-639'],
  executionOrder: 63,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'file_read' && sink.api.includes('sendFile')) {
        const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS);
        if (!hasTenant) {
          findings.push(
            buildFinding(
              'FSI-004',
              'Static file serving without tenant path validation',
              'HIGH',
              'Static file serving without tenant path validation. Path traversal risk.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

// LOG - Logging & Audit (4)

const LOG_001 = createRule({
  id: 'LOG-001',
  category: 'Logging & Audit',
  title: 'Log entry missing tenantId',
  description:
    'Log entry does not include tenantId. Impossible to attribute log entries to tenants.',
  severity: 'INFO',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-778'],
  executionOrder: 70,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'log') {
        // Only flag logs in API routes or server-side handler files
        const isApiFile = sink.location.file.includes('/api/') ||
          sink.location.file.includes('route.ts') ||
          sink.location.file.includes('server.ts') ||
          sink.location.file.includes('handler.ts');
        if (!isApiFile) continue;

        // Only flag structured log calls (object args), skip plain string logs
        const hasStructuredArgs = sink.argsVars.some(a => a.includes('{'));
        if (!hasStructuredArgs) continue;

        const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS) ||
          hasGuard(sink.argsVars.join(' '), TENANT_ISOLATION_GUARDS);
        if (!hasTenant) {
          findings.push(
            buildFinding(
              'LOG-001',
              'Log entry missing tenantId',
              'INFO',
              'Log entry without tenantId. Cannot attribute to tenant.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const LOG_002 = createRule({
  id: 'LOG-002',
  category: 'Logging & Audit',
  title: 'Audit log missing tenant context for data access',
  description:
    'Audit log for data access does not include tenant context.',
  severity: 'MEDIUM',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-778'],
  executionOrder: 71,
  evaluate: (ir) => {
    const findings = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'log' && (sink.api.includes('audit') || sink.api.includes('access'))) {
        const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS) ||
          hasGuard(sink.argsVars.join(' '), TENANT_ISOLATION_GUARDS);
        if (!hasTenant) {
          findings.push(
            buildFinding(
              'LOG-002',
              'Audit log missing tenant context for data access',
              'MEDIUM',
              'Audit log for data access without tenant context.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const LOG_003 = createRule({
  id: 'LOG-003',
  category: 'Logging & Audit',
  title: 'Error log includes cross-tenant data',
  description:
    'Error log includes data from multiple tenants. Cross-tenant data leakage via logs.',
  severity: 'INFO',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-200', 'CWE-532'],
  executionOrder: 72,
  evaluate: (ir) => {
    const findings: Finding[] = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'log' && (sink.api.includes('error') || sink.api.includes('Error'))) {
        const nearbyDbSinks = ir.sinks.filter(
          (s) =>
            (s.kind === 'db_read' || s.kind === 'db_write') &&
            s.location.file === sink.location.file &&
            Math.abs(s.location.line - sink.location.line) <= 5
        );
        // Only flag if the error log actually references a DB result variable
        const logArgs = sink.argsVars.join(' ');
        const referencesDbResult = nearbyDbSinks.some((dbSink) =>
          dbSink.argsVars.some((v) => logArgs.includes(v))
        );
        const hasUnfilteredDb = nearbyDbSinks.some(
          (dbSink) => !ir.tenantScopes.some(
            (ts) => ts.appliesToSinkId === dbSink.id && ts.hasTenantFilter
          )
        );
        if (hasUnfilteredDb && referencesDbResult) {
          findings.push(
            buildFinding(
              'LOG-003',
              'Error log includes cross-tenant data',
              'INFO',
              'Error logging near unfiltered database operations may log cross-tenant data.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...TENANT_ISOLATION_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

const LOG_004 = createRule({
  id: 'LOG-004',
  category: 'Logging & Audit',
  title: 'Structured log strips tenantId',
  description:
    'Structured logging configuration strips tenantId from log output.',
  severity: 'MEDIUM',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-778'],
  executionOrder: 73,
  evaluate: (ir) => {
    const findings: Finding[] = [];
    for (const asgn of ir.assignments) {
      const dst = asgn.dst.toLowerCase();
      const srcStr = asgn.srcSyms.join(' ').toLowerCase();
      if (
        (dst.includes('redact') || dst.includes('sanitize') || dst.includes('strip') || dst.includes('remove')) &&
        (srcStr.includes('tenantid') || srcStr.includes('tenant_id') || srcStr.includes('organizationid') || srcStr.includes('org_id'))
      ) {
        findings.push(
          buildFinding(
            'LOG-004',
            'Structured log strips tenantId',
            'MEDIUM',
            'Logging configuration strips tenantId from output. Audit trail cannot attribute actions to tenants.',
            buildEvidence(asgn.location.file, asgn.location.line, asgn.location.line, `${asgn.dst} = ${asgn.srcSyms.join(', ')}`),
            [...TENANT_ISOLATION_GUARDS],
            []
          )
        );
      }
    }
    return findings;
  },
});

// SCH - Schema & Migration (6)

const SCH_001 = createRule({
  id: 'SCH-001',
  category: 'Schema & Migration',
  title: 'Prisma model without tenant field',
  description:
    'Prisma model does not include tenant field (organizationId, tenantId, workspaceId).',
  severity: 'MEDIUM',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 80,
  evaluate: (_ir) => {
    // Detection at Prisma parser level
    return [];
  },
});

const SCH_002 = createRule({
  id: 'SCH-002',
  category: 'Schema & Migration',
  title: 'Migration adds table without tenant column',
  description:
    'SQL migration creates a new table without a tenant column.',
  severity: 'HIGH',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 81,
  evaluate: (_ir) => {
    // Detection at SQL parser level
    return [];
  },
});

const SCH_003 = createRule({
  id: 'SCH-003',
  category: 'Schema & Migration',
  title: 'Index without tenant column as first field',
  description:
    'Database index does not include tenant column as the first field. Inefficient tenant-scoped queries.',
  severity: 'MEDIUM',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 82,
  evaluate: (_ir) => {
    // Detection at Prisma/SQL parser level
    return [];
  },
});

const SCH_004 = createRule({
  id: 'SCH-004',
  category: 'Schema & Migration',
  title: 'RLS not enabled on tenant-scoped table',
  description:
    'Tenant-scoped table does not have ENABLE ROW LEVEL SECURITY in migration.',
  severity: 'HIGH',
  requiredGuards: ['row_level_security', 'rls'],
  cweIds: ['CWE-668'],
  executionOrder: 83,
  evaluate: (_ir) => {
    // Detection at SQL parser level
    return [];
  },
});

const SCH_005 = createRule({
  id: 'SCH-005',
  category: 'Schema & Migration',
  title: 'RLS policy uses USING(true) or WITH CHECK(true)',
  description:
    'RLS policy uses USING(true) or WITH CHECK(true), effectively disabling row-level security.',
  severity: 'HIGH',
  requiredGuards: [],
  cweIds: ['CWE-668'],
  executionOrder: 84,
  evaluate: (_ir) => {
    // Detection at SQL parser level
    return [];
  },
});

const SCH_006 = createRule({
  id: 'SCH-006',
  category: 'Schema & Migration',
  title: 'Foreign key without tenant column (cross-tenant ref)',
  description:
    'Foreign key relationship does not include tenant column. Allows cross-tenant references.',
  severity: 'HIGH',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  cweIds: ['CWE-639'],
  executionOrder: 85,
  evaluate: (ir) => {
    const findings: Finding[] = [];
    const models = ir.prismaModels ?? [];
    for (const model of models) {
      if (!model.hasTenantField) continue;
      for (const field of model.fields) {
        if (!field.isRelation) continue;
        const relatedModel = models.find((m) => m.name === field.type);
        if (relatedModel && relatedModel.hasTenantField) {
          const hasTenantInRelation = model.fields.some(
            (f) => f.isTenantField && f.name.toLowerCase().includes(field.type.toLowerCase().replace(/model/i, '').toLowerCase())
          );
          if (!hasTenantInRelation) {
            findings.push(
              buildFinding(
                'SCH-006',
                'Foreign key without tenant column (cross-tenant ref)',
                'HIGH',
                `Relation "${field.name}" on model "${model.name}" references "${field.type}" without tenant column. Cross-tenant references possible.`,
                buildEvidence(model.location.file, model.location.line, model.location.line, `${field.name} ${field.type}`),
                [...TENANT_ISOLATION_GUARDS],
                []
              )
            );
          }
        }
      }
    }
    return findings;
  },
});




export const GENERAL_RULES: RuleSpec[] = [
  TCM_001, TCM_002, TCM_003, TCM_004, TCM_005, TCM_006,
  DBQ_001, DBQ_002, DBQ_003, DBQ_004, DBQ_005, DBQ_006, DBQ_007, DBQ_008, DBQ_009, DBQ_010,
  IDOR_001, IDOR_002, IDOR_003, IDOR_004, IDOR_005,
  CSI_001, CSI_002, CSI_003, CSI_004,
  API_001, API_002, API_003,
  FSI_001, FSI_002, FSI_003, FSI_004,
  LOG_001, LOG_002, LOG_003, LOG_004,
  SCH_001, SCH_002, SCH_003, SCH_004, SCH_005, SCH_006,
];
