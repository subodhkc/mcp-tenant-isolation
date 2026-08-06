/**
 * MCP Server - Model Context Protocol integration
 *
 * Exposes 4 tools for AI agents:
 * 1. scan_tenant_isolation - Run scan and return findings
 * 2. list_tenant_isolation_rules - List all available rules
 * 3. explain_tenant_isolation_rule - Get detailed explanation of a rule
 * 4. suppress_tenant_isolation_finding - Add a suppression
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { existsSync } from 'node:fs';
import { createServer } from 'node:http';
import { scan } from '../engine/scanner.js';
import { ALL_RULES, RULE_COUNT, RULE_ENGINE_VERSION } from '../rules/index.js';
import { validateSuppression } from '../engine/suppressions.js';
import type { MtiConfig, SuppressionRule } from '../types.js';

export interface McpServerOptions {
  transport?: 'stdio' | 'sse';
  port?: number;
}


const TOOLS = [
  {
    name: 'scan_tenant_isolation',
    description:
      'Run tenant isolation scan on a project. Returns findings with rule IDs, severity, file locations, and missing guards.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: {
          type: 'string',
          description: 'Project root path to scan',
        },
        severity: {
          type: 'string',
          enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
          description: 'Minimum severity filter',
        },
        rules: {
          type: 'string',
          description: 'Comma-separated rule IDs to run (empty = all)',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'list_tenant_isolation_rules',
    description:
      'List all 57 tenant isolation rules with IDs, titles, categories, and severity.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        category: {
          type: 'string',
          description: 'Filter by category',
        },
      },
    },
  },
  {
    name: 'explain_tenant_isolation_rule',
    description:
      'Get detailed explanation of a specific rule including description, required guards, compliance mappings, and remediation guidance.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        ruleId: {
          type: 'string',
          description: 'Rule ID (e.g., TCM-001, MCP-001)',
        },
      },
      required: ['ruleId'],
    },
  },
  {
    name: 'suppress_tenant_isolation_finding',
    description:
      'Add a suppression for a finding. Requires reason, approver, and compensating controls.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        path: {
          type: 'string',
          description: 'Project root path',
        },
        ruleId: {
          type: 'string',
          description: 'Rule ID to suppress',
        },
        fingerprint: {
          type: 'string',
          description: 'Finding fingerprint to suppress',
        },
        file: {
          type: 'string',
          description: 'File path to suppress',
        },
        reason: {
          type: 'string',
          description: 'Suppression reason (min 10 characters)',
        },
        approvedBy: {
          type: 'string',
          description: 'Approver username',
        },
        expires: {
          type: 'string',
          description: 'Expiry date (ISO 8601)',
        },
        controls: {
          type: 'string',
          description: 'Comma-separated compensating controls',
        },
      },
      required: ['path', 'reason', 'approvedBy', 'controls'],
    },
  },
];


export async function startMcpServer(_projectRoot: string, options?: McpServerOptions): Promise<void> {
  const transportType = options?.transport ?? 'stdio';
  const port = options?.port ?? 3001;

  const server = new Server(
    {
      name: 'mcp-tenant-isolation',
      version: RULE_ENGINE_VERSION,
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // ============================================
  // LIST TOOLS HANDLER
  // ============================================

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: TOOLS,
    };
  });

  // ============================================
  // CALL TOOL HANDLER
  // ============================================

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      switch (name) {
        case 'scan_tenant_isolation': {
          const scanPath = resolve((args as any).path);
          const severity = (args as any).severity;
          const rulesFilter = (args as any).rules?.split(',').map((r: string) => r.trim());

          const config = await loadConfig(scanPath);
          const result = await scan({
            projectRoot: scanPath,
            config,
            severityFilter: severity,
            rulesFilter,
          });

          const activeFindings = result.findings.filter(
            (f) => f.suppressionStatus !== 'suppressed'
          );

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  summary: {
                    totalFindings: result.stats.totalFindings,
                    activeFindings: activeFindings.length,
                    suppressedFindings: result.findings.length - activeFindings.length,
                    bySeverity: result.stats.bySeverity,
                    filesScanned: result.stats.filesScanned,
                    rulesEvaluated: result.stats.rulesEvaluated,
                    durationMs: result.durationMs,
                  },
                  findings: result.findings.map((f) => ({
                    ruleId: f.ruleId,
                    title: f.title,
                    severity: f.severity,
                    file: f.evidence.file,
                    line: f.evidence.lineStart,
                    description: f.description,
                    missingGuards: f.missingGuards,
                    fingerprint: f.fingerprint,
                    suppressionStatus: f.suppressionStatus ?? 'active',
                  })),
                }, null, 2),
              },
            ],
          };
        }

        case 'list_tenant_isolation_rules': {
          const category = (args as any).category;
          let rules = ALL_RULES;
          if (category) {
            rules = rules.filter((r) => r.category === category);
          }

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
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
                }, null, 2),
              },
            ],
          };
        }

        case 'explain_tenant_isolation_rule': {
          const ruleId = (args as any).ruleId;
          const rule = ALL_RULES.find((r) => r.id === ruleId);

          if (!rule) {
            return {
              content: [
                {
                  type: 'text',
                  text: `Rule ${ruleId} not found. Use list_tenant_isolation_rules to see available rules.`,
                },
              ],
              isError: true,
            };
          }

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
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
                }, null, 2),
              },
            ],
          };
        }

        case 'suppress_tenant_isolation_finding': {
          const suppressPath = resolve((args as any).path);
          const suppression: SuppressionRule = {
            ruleId: (args as any).ruleId,
            fingerprint: (args as any).fingerprint,
            filePath: (args as any).file,
            reason: (args as any).reason,
            approvedBy: (args as any).approvedBy,
            expires: (args as any).expires,
            compensatingControls: (args as any).controls?.split(',').map((c: string) => c.trim()),
          };

          const errors = validateSuppression(suppression);
          if (errors.length > 0) {
            return {
              content: [
                {
                  type: 'text',
                  text: `Invalid suppression:\n${errors.map((e) => `- ${e}`).join('\n')}`,
                },
              ],
              isError: true,
            };
          }

          const suppressionsPath = join(suppressPath, '.mti-suppressions.json');
          let existing = { suppress: [] as SuppressionRule[] };
          if (existsSync(suppressionsPath)) {
            const content = await readFile(suppressionsPath, 'utf-8');
            existing = JSON.parse(content);
          }

          existing.suppress.push(suppression);
          await writeFile(suppressionsPath, JSON.stringify(existing, null, 2) + '\n', 'utf-8');

          return {
            content: [
              {
                type: 'text',
                text: `Suppression added to .mti-suppressions.json`,
              },
            ],
          };
        }

        default:
          return {
            content: [
              {
                type: 'text',
                text: `Unknown tool: ${name}`,
              },
            ],
            isError: true,
          };
      }
    } catch (err) {
      return {
        content: [
          {
            type: 'text',
            text: `Error: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    }
  });

  // ============================================
  // CONNECT
  // ============================================

  if (transportType === 'sse') {
    const httpServer = createServer(async (req, res) => {
      const url = new URL(req.url ?? '', `http://localhost:${port}`);

      if (url.pathname === '/sse') {
        const sseTransport = new SSEServerTransport('/message', res);
        await server.connect(sseTransport);
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
        });
      } else if (url.pathname === '/message') {
        res.writeHead(405, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Use SSE transport client to send messages' }));
      } else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found. Use /sse for SSE connection.' }));
      }
    });

    httpServer.listen(port, () => {
      console.log(`MCP server listening on http://localhost:${port}/sse`);
    });
  } else {
    const transport = new StdioServerTransport();
    await server.connect(transport);
  }
}


async function loadConfig(projectRoot: string): Promise<MtiConfig | undefined> {
  const configPath = join(projectRoot, '.mtirc.json');
  if (!existsSync(configPath)) return undefined;
  try {
    const content = await readFile(configPath, 'utf-8');
    return JSON.parse(content) as MtiConfig;
  } catch (err) {
    console.warn(`[mti] Failed to load config: ${err instanceof Error ? err.message : String(err)}`);
    return undefined;
  }
}

function generateRemediation(rule: typeof ALL_RULES[number]): string {
  const guards = rule.requiredGuards.length > 0
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
