/**
 * MCP Server - Model Context Protocol integration (v2 SDK)
 *
 * Exposes tools for AI agents:
 * 1. scan_tenant_isolation - Run scan and return findings (read-only)
 * 2. list_tenant_isolation_rules - List all available rules (read-only)
 * 3. explain_tenant_isolation_rule - Get detailed explanation of a rule (read-only)
 * 4. suppress_tenant_isolation_finding - Add a suppression (WRITE; gated)
 *
 * SECURITY BOUNDARY (Part 3):
 * The server establishes ONE explicit allowed project root at startup.
 * All filesystem operations are constrained to that root via PathBoundary.
 * Any path that escapes the root returns TARGET_OUTSIDE_ALLOWED_ROOT.
 *
 * WRITE-TOOL GOVERNANCE (Part 4):
 * Default MCP mode is READ-ONLY. The suppression tool is only exposed when
 * the server is started with allowWriteTools: true (--allow-write-tools).
 *
 * TRANSPORT (Part 5):
 * v2.0 supports stdio only. Legacy SSE transport has been removed.
 * Remote transport (Streamable HTTP) is deferred unless a real business
 * requirement exists.
 *
 * MCP SDK v2 (Part 6):
 * Uses @modelcontextprotocol/server with registerTool() and zod schemas.
 *
 * PRODUCER_LOCAL_V2_CONFORMANCE.
 */

import { McpServer } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { existsSync } from 'node:fs';
import { scan } from '../engine/scanner.js';
import { ALL_RULES, RULE_COUNT, RULE_ENGINE_VERSION } from '../rules/index.js';
import { validateSuppression } from '../engine/suppressions.js';
import { PathBoundary, PathBoundaryError } from '../security/path-boundary.js';
import type { MtiConfig, SuppressionRule } from '../types.js';

export interface McpServerOptions {
  /**
   * When true, the suppression write tool is exposed. Default: false (read-only).
   * Set via --allow-write-tools on the CLI.
   */
  allowWriteTools?: boolean;
}

// ============================================
// TOOL METADATA (exported for testability)
// ============================================

export const READ_ONLY_TOOL_NAMES = [
  'scan_tenant_isolation',
  'list_tenant_isolation_rules',
  'explain_tenant_isolation_rule',
] as const;

export const WRITE_TOOL_NAME = 'suppress_tenant_isolation_finding' as const;

export const TOOL_ANNOTATIONS = {
  scan: { readOnlyHint: true },
  list: { readOnlyHint: true },
  explain: { readOnlyHint: true },
  suppress: { readOnlyHint: false, destructiveHint: true },
} as const;

// ============================================
// ZOD INPUT SCHEMAS
// ============================================

const scanInputSchema = z.object({
  path: z
    .string()
    .optional()
    .describe(
      'Project root path to scan. Must be within the allowed project root. If omitted, scans the allowed root itself.'
    ),
  severity: z
    .enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
    .optional()
    .describe('Minimum severity filter'),
  rules: z
    .string()
    .optional()
    .describe('Comma-separated rule IDs to run (empty = all)'),
});

// ============================================
// ZOD OUTPUT SCHEMA (structuredContent — Part 8)
// ============================================

const scanOutputSchema = z.object({
  schemaVersion: z.string(),
  producerId: z.string(),
  verdict: z.enum(['PASS', 'REVIEW', 'BLOCK', 'ERROR']),
  completeness: z.enum(['COMPLETE', 'PARTIAL', 'ERROR']),
  completenessReasons: z.array(z.string()),
  summary: z.object({
    totalFindings: z.number(),
    activeFindings: z.number(),
    suppressedFindings: z.number(),
    bySeverity: z.record(z.string(), z.number()),
    filesScanned: z.number(),
    rulesEvaluated: z.number(),
    durationMs: z.number(),
  }),
  findings: z.array(
    z.object({
      ruleId: z.string(),
      title: z.string(),
      severity: z.enum(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
      file: z.string(),
      line: z.number(),
      description: z.string(),
      missingGuards: z.array(z.string()),
      fingerprint: z.string(),
      fingerprintVersion: z.number().optional(),
      suppressionStatus: z.enum(['active', 'suppressed', 'baseline']),
      proofOfFix: z.enum(['STILL_PRESENT', 'RESOLVED_CONFIRMED', 'NEW', 'NOT_VERIFIABLE']).optional(),
    })
  ),
  truncation: z.object({
    findingsReturned: z.number(),
    findingsTotal: z.number(),
    truncated: z.boolean(),
  }),
  coverage: z.object({
    filesDiscovered: z.number(),
    filesParsed: z.number(),
    parseFailures: z.number(),
    parseFailureDetails: z.array(
      z.object({ file: z.string(), error: z.string() })
    ),
    excludedPaths: z.number(),
    unsupportedPaths: z.number(),
    rulesAvailable: z.number(),
    rulesSelected: z.number(),
    rulesEvaluated: z.number(),
    rulesFailed: z.number(),
    ruleFailureDetails: z.array(
      z.object({ ruleId: z.string(), error: z.string() })
    ),
    rulesTriggered: z.number(),
  }),
  limitations: z.array(z.string()),
  concernFamilies: z.array(
    z.object({
      family: z.string(),
      totalFindings: z.number(),
      activeFindings: z.number(),
      suppressedFindings: z.number(),
      bySeverity: z.record(z.string(), z.number()),
      ruleIds: z.array(z.string()),
    })
  ).optional(),
  receipt: z.object({
    schemaVersion: z.string(),
    producerId: z.string(),
    engineVersion: z.string(),
    timestamp: z.string(),
    projectRoot: z.string(),
    durationMs: z.number(),
    completeness: z.enum(['COMPLETE', 'PARTIAL', 'ERROR']),
    verdict: z.enum(['PASS', 'REVIEW', 'BLOCK', 'ERROR']),
    rulepackDigest: z.string(),
    rulesAvailable: z.number(),
    rulesSelected: z.number(),
    filesDiscovered: z.number(),
    filesParsed: z.number(),
    totalFindings: z.number(),
    activeFindings: z.number(),
    suppressedFindings: z.number(),
    receiptHash: z.string(),
  }).optional(),
});

const listInputSchema = z.object({
  category: z.string().optional().describe('Filter by category'),
});

const explainInputSchema = z.object({
  ruleId: z.string().describe('Rule ID (e.g., TCM-001, MCP-001)'),
});

const suppressInputSchema = z.object({
  path: z
    .string()
    .optional()
    .describe('Project root path. Must be within the allowed project root.'),
  ruleId: z.string().describe('Rule ID to suppress (required)'),
  fingerprint: z
    .string()
    .optional()
    .describe('Concrete finding fingerprint to suppress (required unless permanentException)'),
  file: z.string().optional().describe('File path to suppress (optional, scopes to a file)'),
  reason: z
    .string()
    .describe(
      'Suppression reason (min 10 characters). For permanent exceptions, must justify the lack of expiry.'
    ),
  documentedApprover: z
    .string()
    .describe(
      'Documented approver identifier. This records who documented the suppression; it does NOT represent independent human verification.'
    ),
  approvedBy: z
    .string()
    .optional()
    .describe('Deprecated: use documentedApprover. Legacy approver field.'),
  expires: z
    .string()
    .optional()
    .describe('Expiry date (ISO 8601). Required unless permanentException is true.'),
  controls: z
    .string()
    .describe('Comma-separated compensating controls (required)'),
  permanentException: z
    .boolean()
    .optional()
    .describe(
      'If true, marks a documented permanent exception (expires may be omitted). Reason must justify why no expiry applies.'
    ),
});

// ============================================
// SERVER STARTUP
// ============================================

export async function startMcpServer(
  projectRoot: string,
  options?: McpServerOptions
): Promise<void> {
  const allowWriteTools = options?.allowWriteTools === true;

  // Establish the ONE allowed project root (Part 3 security boundary).
  const boundary = await PathBoundary.create(projectRoot);
  const allowedRoot = boundary.getRoot();

  const server = new McpServer({
    name: 'mcp-tenant-isolation',
    version: RULE_ENGINE_VERSION,
  });

  // ============================================
  // READ-ONLY TOOLS
  // ============================================

  server.registerTool(
    'scan_tenant_isolation',
    {
      description:
        'Run tenant isolation scan on a project. Returns findings with rule IDs, severity, file locations, and missing guards. The path must be within the allowed project root configured at server startup.',
      inputSchema: scanInputSchema,
      outputSchema: scanOutputSchema,
      annotations: TOOL_ANNOTATIONS.scan,
    },
    async (args) => {
      try {
        const scanPath = args.path
          ? await boundary.resolve(args.path)
          : allowedRoot;
        const rulesFilter = args.rules
          ?.split(',')
          .map((r: string) => r.trim());

        const config = await loadConfig(allowedRoot);
        const result = await scan({
          projectRoot: scanPath,
          config,
          severityFilter: args.severity,
          rulesFilter,
          boundary,
        });

        const activeFindings = result.findings.filter(
          (f) => f.suppressionStatus !== 'suppressed'
        );

        // Output bounding: default 20 representative findings (Part 8/12).
        // Full totals are preserved in truncation metadata.
        const FINDINGS_BOUND = 20;
        const allFindingsMapped = result.findings.map((f) => ({
          ruleId: f.ruleId,
          title: f.title,
          severity: f.severity,
          file: f.evidence.file,
          line: f.evidence.lineStart,
          description: f.description,
          missingGuards: f.missingGuards,
          fingerprint: f.fingerprint,
          fingerprintVersion: f.fingerprintVersion ?? 2,
          suppressionStatus: (f.suppressionStatus ?? 'active') as 'active' | 'suppressed' | 'baseline',
          proofOfFix: f.proofOfFix,
        }));
        const truncatedFindings = allFindingsMapped.slice(0, FINDINGS_BOUND);
        const truncated = allFindingsMapped.length > FINDINGS_BOUND;

        // Verdict: ERROR if completeness is ERROR; BLOCK if CRITICAL/HIGH findings;
        // REVIEW if MEDIUM/LOW; PASS if no active findings.
        let verdict: 'PASS' | 'REVIEW' | 'BLOCK' | 'ERROR';
        if (result.completeness === 'ERROR') {
          verdict = 'ERROR';
        } else if (activeFindings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')) {
          verdict = 'BLOCK';
        } else if (activeFindings.length > 0) {
          verdict = 'REVIEW';
        } else {
          verdict = 'PASS';
        }

        const structuredContent = {
          schemaVersion: '2.0.0',
          producerId: 'io.github.subodhkc/mcp-tenant-isolation',
          verdict,
          completeness: result.completeness,
          completenessReasons: result.completenessReasons,
          summary: {
            totalFindings: result.stats.totalFindings,
            activeFindings: activeFindings.length,
            suppressedFindings:
              result.findings.length - activeFindings.length,
            bySeverity: result.stats.bySeverity,
            filesScanned: result.stats.filesScanned,
            rulesEvaluated: result.stats.rulesEvaluated,
            durationMs: result.durationMs,
          },
          findings: truncatedFindings,
          truncation: {
            findingsReturned: truncatedFindings.length,
            findingsTotal: allFindingsMapped.length,
            truncated,
          },
          coverage: result.coverage,
          limitations: result.limitations,
          concernFamilies: result.concernFamilies,
          receipt: result.receipt,
        };

        // Concise text summary for agents that prefer text.
        const textSummary = [
          `mcp-tenant-isolation scan result:`,
          `  Verdict: ${verdict}`,
          `  Completeness: ${result.completeness}`,
          `  Findings: ${activeFindings.length} active, ${result.findings.length - activeFindings.length} suppressed (showing ${truncatedFindings.length} of ${allFindingsMapped.length})`,
          `  Files: ${result.coverage.filesParsed} parsed, ${result.coverage.parseFailures} parse failures, ${result.coverage.unsupportedPaths} unsupported`,
          `  Rules: ${result.coverage.rulesEvaluated} evaluated, ${result.coverage.rulesFailed} failed, ${result.coverage.rulesTriggered} triggered`,
          `  Duration: ${result.durationMs}ms`,
        ];
        if (result.concernFamilies && result.concernFamilies.length > 0) {
          textSummary.push(`  Concern families:`);
          for (const cf of result.concernFamilies.slice(0, 5)) {
            textSummary.push(`    - ${cf.family}: ${cf.activeFindings} active, ${cf.suppressedFindings} suppressed (${cf.ruleIds.length} rules)`);
          }
        }
        if (result.receipt) {
          textSummary.push(`  Receipt: ${result.receipt.rulepackDigest.substring(0, 8)} (hash: ${result.receipt.receiptHash.substring(0, 8)})`);
        }
        if (result.completenessReasons.length > 0) {
          textSummary.push(`  Completeness reasons:`);
          for (const reason of result.completenessReasons) {
            textSummary.push(`    - ${reason}`);
          }
        }
        if (result.limitations.length > 0) {
          textSummary.push(`  Limitations:`);
          for (const lim of result.limitations.slice(0, 3)) {
            textSummary.push(`    - ${lim}`);
          }
        }

        return {
          content: [
            {
              type: 'text' as const,
              text: textSummary.join('\n'),
            },
          ],
          structuredContent,
          isError: verdict === 'ERROR',
        };
      } catch (err) {
        return boundaryErrorResponse(err);
      }
    }
  );

  server.registerTool(
    'list_tenant_isolation_rules',
    {
      description:
        'List all 57 tenant isolation rules with IDs, titles, categories, and severity.',
      inputSchema: listInputSchema,
      annotations: TOOL_ANNOTATIONS.list,
    },
    async (args) => {
      let rules = ALL_RULES;
      if (args.category) {
        rules = rules.filter((r) => r.category === args.category);
      }

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                engineVersion: RULE_ENGINE_VERSION,
                totalRules: RULE_COUNT,
                rules: rules.map((r) => ({
                  id: r.id,
                  title: r.title,
                  category: r.category,
                  severity: r.severity,
                  description: r.description,
                  suppressible: r.suppressible,
                  owaspMcpRef: r.compliance.owaspMcpRef,
                  cweIds: r.compliance.cweIds,
                })),
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  server.registerTool(
    'explain_tenant_isolation_rule',
    {
      description:
        'Get detailed explanation of a specific rule including description, required guards, compliance mappings, and remediation guidance.',
      inputSchema: explainInputSchema,
      annotations: TOOL_ANNOTATIONS.explain,
    },
    async (args) => {
      const rule = ALL_RULES.find((r) => r.id === args.ruleId);

      if (!rule) {
        return {
          content: [
            {
              type: 'text' as const,
              text: `Rule ${args.ruleId} not found. Use list_tenant_isolation_rules to see available rules.`,
            },
          ],
          isError: true,
        };
      }

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                id: rule.id,
                title: rule.title,
                category: rule.category,
                severity: rule.severity,
                description: rule.description,
                requiredGuards: rule.requiredGuards,
                positiveControls: rule.positiveControls,
                compliance: rule.compliance,
                version: rule.version,
                executionOrder: rule.executionOrder,
                requiresFlowGraph: rule.requiresFlowGraph,
                suppressible: rule.suppressible,
                remediation: generateRemediation(rule),
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // ============================================
  // WRITE TOOL (gated behind allowWriteTools)
  // ============================================

  if (allowWriteTools) {
    server.registerTool(
      'suppress_tenant_isolation_finding',
      {
        description:
          'Add a suppression for a finding. Requires a concrete finding fingerprint, ruleId, documented approver identifier, reason, compensating controls, and an expiry (or a documented permanent exception). Only available when the server is started with --allow-write-tools. The path must be within the allowed project root.',
        inputSchema: suppressInputSchema,
        annotations: TOOL_ANNOTATIONS.suppress,
      },
      async (args) => {
        try {
          const suppressPath = args.path
            ? await boundary.resolve(args.path)
            : allowedRoot;

          const suppression: SuppressionRule = {
            ruleId: args.ruleId,
            fingerprint: args.fingerprint,
            filePath: args.file,
            reason: args.reason,
            documentedApprover:
              args.documentedApprover ?? args.approvedBy,
            expires: args.expires,
            compensatingControls: args.controls
              ?.split(',')
              .map((c: string) => c.trim()),
            permanentException: args.permanentException === true,
            fingerprintVersion: 2,
          };

          const errors = validateSuppression(suppression);
          if (errors.length > 0) {
            return {
              content: [
                {
                  type: 'text' as const,
                  text: `Invalid suppression:\n${errors.map((e) => `- ${e}`).join('\n')}`,
                },
              ],
              isError: true,
            };
          }

          const suppressionsPath = await boundary.resolve(
            join(suppressPath, '.mti-suppressions.json'),
            { resolveSymlinks: false, allowMissing: true }
          );
          let existing = { suppress: [] as SuppressionRule[] };
          if (existsSync(suppressionsPath)) {
            const content = await readFile(suppressionsPath, 'utf-8');
            existing = JSON.parse(content);
          }

          existing.suppress.push(suppression);
          await writeFile(
            suppressionsPath,
            JSON.stringify(existing, null, 2) + '\n',
            'utf-8'
          );

          return {
            content: [
              {
                type: 'text' as const,
                text: `Suppression added to .mti-suppressions.json (documented approver: ${suppression.documentedApprover ?? 'unspecified'})`,
              },
            ],
          };
        } catch (err) {
          return boundaryErrorResponse(err);
        }
      }
    );
  }

  // ============================================
  // CONNECT (stdio only — Part 5)
  // ============================================

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

// ============================================
// HELPERS
// ============================================

async function loadConfig(allowedRoot: string): Promise<MtiConfig | undefined> {
  const configPath = join(allowedRoot, '.mtirc.json');
  if (!existsSync(configPath)) return undefined;
  try {
    const content = await readFile(configPath, 'utf-8');
    return JSON.parse(content) as MtiConfig;
  } catch (err) {
    console.warn(
      `[mti] Failed to load config: ${err instanceof Error ? err.message : String(err)}`
    );
    return undefined;
  }
}

function generateRemediation(rule: (typeof ALL_RULES)[number]): string {
  const guards =
    rule.requiredGuards.length > 0
      ? `Add required guards: ${rule.requiredGuards.join(', ')}`
      : 'Review the data flow and add appropriate tenant isolation controls.';

  return [
    `Remediation for ${rule.id}:`,
    `1. ${rule.description}`,
    `2. ${guards}`,
    `3. Ensure tenant context is propagated from authenticated session.`,
    `4. Add tests verifying tenant isolation for the affected data flow.`,
    `5. Run 'mti scan' to verify the finding is resolved.`,
  ].join('\n');
}

function boundaryErrorResponse(err: unknown): {
  content: [{ type: 'text'; text: string }];
  isError: boolean;
} {
  if (err instanceof PathBoundaryError) {
    return {
      content: [
        {
          type: 'text' as const,
          text: `${err.code}: ${err.message}`,
        },
      ],
      isError: true,
    };
  }
  return {
    content: [
      {
        type: 'text' as const,
        text: `Error: ${err instanceof Error ? err.message : String(err)}`,
      },
    ],
    isError: true,
  };
}
