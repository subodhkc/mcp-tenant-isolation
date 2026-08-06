/**
 * Scanner - Main scan orchestrator
 *
 * 1. Discover files (glob)
 * 2. Parse each file with appropriate parser
 * 3. Merge into single IR
 * 4. Build flow graph
 * 5. Evaluate all rules
 * 6. Filter false positives
 * 7. Apply suppressions
 * 8. Return ScanResult
 */

import { readFile } from 'node:fs/promises';
import { existsSync, readFileSync } from 'node:fs';
import { extname, relative, join } from 'node:path';
import fg from 'fast-glob';
import type {
  IR,
  ScanResult,
  ScanStats,
  Finding,
  Severity,
  ParsedFile,
  MtiConfig,
  SqlTable,
  SqlRlsPolicy,
  PrismaModelInfo,
  FlowGraph,
} from '../types.js';
import { parseJsFile } from '../parsers/js-parser.js';
import { parsePrismaSchema, findModelsWithoutTenantField, findIndexesWithoutTenantFirst } from '../parsers/prisma-parser.js';
import { parseSqlMigration, findTablesWithoutRls, findBypassedRlsPolicies } from '../parsers/sql-parser.js';
import { ALL_RULES } from '../rules/index.js';
import { loadRulePacks } from './rule-pack-loader.js';
import { buildFlowGraph } from './flow-graph.js';
import { filterFalsePositives } from './fp-filter.js';
import { applySuppressions } from './suppressions.js';
import { buildFinding, buildEvidence } from '../rule-spec.js';


const DEFAULT_INCLUDE_PATTERNS = [
  '**/*.{ts,tsx,js,jsx}',
  '**/*.prisma',
  '**/*.sql',
];

const DEFAULT_EXCLUDE_PATTERNS = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.next/**',
  '**/.git/**',
  '**/coverage/**',
  '**/*.test.{ts,js}',
  '**/*.spec.{ts,js}',
  '**/*.d.ts',
  '**/e2e/**',
  '**/smoke-test*',
  '**/prisma/archive/**',
];


export interface ScanOptions {
  projectRoot: string;
  config?: MtiConfig;
  severityFilter?: Severity;
  rulesFilter?: string[];
  noSuppress?: boolean;
}

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const startTime = Date.now();
  const { projectRoot, config, severityFilter, rulesFilter, noSuppress } = options;

  // 1. Discover files
  const includePatterns = config?.paths?.include ?? DEFAULT_INCLUDE_PATTERNS;
  const excludePatterns = config?.paths?.exclude ?? DEFAULT_EXCLUDE_PATTERNS;

  const files = await fg(includePatterns, {
    cwd: projectRoot,
    ignore: excludePatterns,
    absolute: true,
  });

  // 2. Parse files
  const irParts: Partial<IR>[] = [];
  const parsedFiles: ParsedFile[] = [];
  const parserFindings: Finding[] = [];
  const allSqlTables: SqlTable[] = [];
  const allSqlRlsPolicies: SqlRlsPolicy[] = [];
  const allSqlRlsEnabledTables: string[] = [];
  const allPrismaModels: PrismaModelInfo[] = [];

  for (const file of files) {
    try {
      const content = await readFile(file, 'utf-8');
      const ext = extname(file);

      if (ext === '.ts' || ext === '.tsx' || ext === '.js' || ext === '.jsx') {
        const result = parseJsFile(content, file, projectRoot, {
          authHelpers: config?.authHelpers,
          tenantGuards: config?.tenantGuards,
          framework: config?.framework,
        });
        irParts.push(result.ir);
        parsedFiles.push(result.file);
      } else if (ext === '.prisma') {
        const result = parsePrismaSchema(content, file, projectRoot);
        parsedFiles.push(result.file);
        const relPath = relative(projectRoot, file);

        for (const model of result.models) {
          // Apply user-configured model scope overrides
          let scope = model.scope;
          if (config?.modelScopes?.userScoped?.includes(model.name)) {
            scope = 'user';
          } else if (config?.modelScopes?.global?.includes(model.name)) {
            scope = 'global';
          } else if (config?.modelScopes?.tenantScoped?.includes(model.name)) {
            scope = 'tenant';
          }
          allPrismaModels.push({
            name: model.name,
            hasTenantField: model.hasTenantField,
            tenantFieldName: model.tenantFieldName,
            scope,
            fields: model.fields.map((f) => ({
              name: f.name,
              type: f.type,
              isRelation: f.isRelation,
              isTenantField: f.isTenantField,
            })),
            location: model.location,
          });
        }

        for (const model of findModelsWithoutTenantField(result.models)) {
          parserFindings.push(buildFinding(
            'SCH-001',
            'Prisma model missing tenant field',
            'HIGH',
            `Model "${model.name}" has no tenant isolation field (organizationId, tenantId, etc.).`,
            buildEvidence(relPath, model.location.line, model.location.line, `model ${model.name} {`),
            ['tenantId', 'organizationId'],
            []
          ));
        }

        for (const { model, index } of findIndexesWithoutTenantFirst(result.models)) {
          parserFindings.push(buildFinding(
            'SCH-002',
            'Index missing tenant column as first field',
            'MEDIUM',
            `Index on "${model}" does not start with the tenant column. Queries may scan across tenants.`,
            buildEvidence(relPath, index.location.line, index.location.line, `@@index([${index.fields.join(', ')}])`),
            ['tenantId'],
            []
          ));
        }
      } else if (ext === '.sql') {
        const result = parseSqlMigration(content, file, projectRoot);
        parsedFiles.push(result.file);
        const relPath = relative(projectRoot, file);

        allSqlTables.push(...result.tables);
        allSqlRlsPolicies.push(...result.rlsPolicies);
        allSqlRlsEnabledTables.push(...result.rlsEnabledTables);

        for (const table of findTablesWithoutRls(result.tables, result.rlsEnabledTables)) {
          parserFindings.push(buildFinding(
            'SCH-003',
            'Table with tenant column missing RLS',
            'CRITICAL',
            `Table "${table.name}" has a tenant column but RLS is not enabled. Cross-tenant data access is possible.`,
            buildEvidence(relPath, table.location.line, table.location.line, `CREATE TABLE ${table.name}`),
            ['row_level_security', 'rls'],
            []
          ));
        }

        for (const policy of findBypassedRlsPolicies(result.rlsPolicies)) {
          parserFindings.push(buildFinding(
            'SCH-004',
            'RLS policy bypassed with USING(true) or WITH CHECK(true)',
            'CRITICAL',
            `RLS policy "${policy.policyName}" on table "${policy.tableName}" uses true bypass, allowing all rows.`,
            buildEvidence(relPath, policy.location.line, policy.location.line, `CREATE POLICY ${policy.policyName}`),
            ['row_level_security', 'rls'],
            []
          ));
        }

        for (const table of result.tables) {
          if (table.hasTenantColumn) {
            const hasTenantIndex = result.indexes.some(
              (idx) => idx.tableName === table.name && idx.hasTenantFirst
            );
            if (!hasTenantIndex) {
              parserFindings.push(buildFinding(
                'SCH-005',
                'Missing tenant-first index on table',
                'MEDIUM',
                `Table "${table.name}" has a tenant column but no index starting with it. Query performance across tenants will degrade.`,
                buildEvidence(relPath, table.location.line, table.location.line, `CREATE TABLE ${table.name}`),
                ['tenant_filter'],
                []
              ));
            }
          }
        }
      }
    } catch (err) {
      // Skip unreadable files but log for debugging
      console.warn(`[mti] Failed to parse ${relative(projectRoot, file)}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // 3. Merge IR
  const ir: IR = mergeIR(irParts, projectRoot, parsedFiles, allSqlTables, allSqlRlsPolicies, allSqlRlsEnabledTables, allPrismaModels);

  // 4. Load custom rule packs
  const customRules = await loadRulePacks(projectRoot, config?.rulePacks);
  const allRules = [...ALL_RULES, ...customRules];

  // 5. Build flow graph (only if a rule requires it)
  const needsFlowGraph = allRules.some(r => r.requiresFlowGraph);
  const graph: FlowGraph = needsFlowGraph ? buildFlowGraph(ir) : { nodes: new Set<string>(), edges: new Map<string, Set<string>>(), metadata: new Map<string, any>() };

  // 6. Evaluate rules
  let findings: Finding[] = [...parserFindings];
  const rulesToRun = filterRules(allRules, rulesFilter, config?.rules?.exclude)
    .sort((a, b) => a.executionOrder - b.executionOrder);
  let rulesTriggered = 0;

  for (const rule of rulesToRun) {
    try {
      const ruleFindings = rule.evaluate(ir, graph);
      if (ruleFindings.length > 0) {
        rulesTriggered++;
        // Apply severity override from config
        const severityOverride = config?.rules?.severity?.[rule.id];
        if (severityOverride) {
          for (const f of ruleFindings) {
            f.severity = severityOverride;
          }
        }
        findings.push(...ruleFindings);
      }
    } catch (err) {
      // Rule evaluation error - skip rule but log for debugging
      console.warn(`[mti] Rule ${rule.id} evaluation error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // 6. Filter false positives
  findings = filterFalsePositives(findings, ir);

  // 6b. Downgrade findings in non-production paths (scripts, diagnostics, etc.)
  const nonProdPatterns = config?.paths?.nonProduction;
  if (nonProdPatterns && nonProdPatterns.length > 0) {
    for (const f of findings) {
      if (nonProdPatterns.some((p) => f.evidence.file.includes(p))) {
        f.severity = 'INFO';
      }
    }
  }

  // 7. Apply baseline (mark pre-existing findings)
  const baselinePath = config?.baseline
    ? join(projectRoot, config.baseline)
    : join(projectRoot, '.mti-baseline.json');
  const baselineFingerprints = loadBaselineFingerprints(baselinePath);
  if (baselineFingerprints.size > 0) {
    for (const f of findings) {
      if (baselineFingerprints.has(f.fingerprint)) {
        f.suppressionStatus = 'baseline';
      }
    }
  }

  // 8. Apply suppressions
  if (!noSuppress) {
    findings = applySuppressions(findings, projectRoot, config?.suppressions);
  }

  // 8. Apply severity filter
  if (severityFilter) {
    findings = filterBySeverity(findings, severityFilter);
  }

  // 9. Build stats
  const stats = buildStats(findings, parsedFiles.length, rulesToRun.length, rulesTriggered, allRules);

  return {
    findings,
    ir,
    stats,
    durationMs: Date.now() - startTime,
  };
}


function loadBaselineFingerprints(baselinePath: string): Set<string> {
  if (!existsSync(baselinePath)) return new Set();
  try {
    const content = readFileSync(baselinePath, 'utf-8');
    const baseline = JSON.parse(content);
    if (baseline.fingerprints && Array.isArray(baseline.fingerprints)) {
      return new Set(baseline.fingerprints.map((f: { fingerprint: string }) => f.fingerprint));
    }
  } catch {
    // Baseline file invalid — treat as no baseline
  }
  return new Set();
}


function mergeIR(
  parts: Partial<IR>[],
  projectRoot: string,
  files: ParsedFile[],
  sqlTables?: SqlTable[],
  sqlRlsPolicies?: SqlRlsPolicy[],
  sqlRlsEnabledTables?: string[],
  prismaModels?: PrismaModelInfo[],
): IR {
  const ir: IR = {
    projectRoot,
    scanTimestamp: new Date().toISOString(),
    entrypoints: [],
    sources: [],
    sinks: [],
    assignments: [],
    authSignals: [],
    tenantScopes: [],
    mcpTools: [],
    mcpSessions: [],
    mcpCredentialVaults: [],
    mcpResources: [],
    mcpCacheEntries: [],
    files,
    sqlTables,
    sqlRlsPolicies,
    sqlRlsEnabledTables,
    prismaModels,
  };

  for (const part of parts) {
    if (part.entrypoints) ir.entrypoints.push(...part.entrypoints);
    if (part.sources) ir.sources.push(...part.sources);
    if (part.sinks) ir.sinks.push(...part.sinks);
    if (part.assignments) ir.assignments.push(...part.assignments);
    if (part.authSignals) ir.authSignals.push(...part.authSignals);
    if (part.tenantScopes) ir.tenantScopes.push(...part.tenantScopes);
    if (part.mcpTools) ir.mcpTools.push(...part.mcpTools);
    if (part.mcpSessions) ir.mcpSessions.push(...part.mcpSessions);
    if (part.mcpCredentialVaults) ir.mcpCredentialVaults.push(...part.mcpCredentialVaults);
    if (part.mcpResources) ir.mcpResources.push(...part.mcpResources);
    if (part.mcpCacheEntries) ir.mcpCacheEntries.push(...part.mcpCacheEntries);
  }

  return ir;
}


function filterRules(rules: typeof ALL_RULES, rulesFilter?: string[], excludedRules?: string[]) {
  let result = rules;
  if (rulesFilter && rulesFilter.length > 0) {
    result = result.filter((r) => rulesFilter.includes(r.id));
  }
  if (excludedRules && excludedRules.length > 0) {
    result = result.filter((r) => !excludedRules.includes(r.id));
  }
  return result;
}


const SEVERITY_ORDER: Record<Severity, number> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

function filterBySeverity(findings: Finding[], minSeverity: Severity): Finding[] {
  const minLevel = SEVERITY_ORDER[minSeverity];
  return findings.filter((f) => SEVERITY_ORDER[f.severity] >= minLevel);
}


function buildStats(
  findings: Finding[],
  filesScanned: number,
  rulesEvaluated: number,
  rulesTriggered: number,
  rules?: typeof ALL_RULES
): ScanStats {
  const bySeverity: Record<Severity, number> = {
    INFO: 0,
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
    CRITICAL: 0,
  };
  const byCategory: Record<string, number> = {};
  const ruleList = rules ?? ALL_RULES;

  for (const f of findings) {
    bySeverity[f.severity]++;
    const rule = ruleList.find((r) => r.id === f.ruleId);
    if (rule) {
      byCategory[rule.category] = (byCategory[rule.category] ?? 0) + 1;
    }
  }

  return {
    totalFindings: findings.length,
    bySeverity,
    byCategory,
    filesScanned,
    rulesEvaluated,
    rulesTriggered,
  };
}
