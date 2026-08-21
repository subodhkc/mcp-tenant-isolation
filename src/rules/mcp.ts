/**
 * MCP-Specific Rules - 15 rules for Model Context Protocol servers
 *
 * MCP-001: Tool Visibility Scoping
 * MCP-002: Cache Key Tenant Prefix
 * MCP-003: Session Binding to User+Tenant
 * MCP-004: Token Exchange (RFC 8693)
 * MCP-005: Per-Tenant Rate Limiting
 * MCP-006: Vector Store Tenant Namespace
 * MCP-007: Tool Description Injection
 * MCP-008: Credential Vault Tenant Scoping
 * MCP-009: Shared Service Account
 * MCP-010: Session Cleanup on Disconnect
 * MCP-011: Telemetry Tenant Identifier
 * MCP-012: Local Bind (127.0.0.1)
 * MCP-013: Filesystem Tenant Root
 * MCP-014: Cross-Tenant Artifact Leakage
 * MCP-015: Dynamic Tool Namespace
 */

import type { RuleSpec } from '../rule-spec.js';
import { createRule, buildFinding, buildEvidence } from '../rule-spec.js';
import {
  MCP_TOOL_VISIBILITY_GUARDS,
  MCP_CACHE_PREFIX_GUARDS,
  MCP_SESSION_BINDING_GUARDS,
  MCP_CREDENTIAL_VAULT_GUARDS,
  MCP_RATE_LIMIT_GUARDS,
  MCP_VECTOR_STORE_GUARDS,
  MCP_FILESYSTEM_GUARDS,
  TENANT_ISOLATION_GUARDS,
  hasGuard,
} from '../guards.js';
import type { Finding } from '../types.js';

// MCP-001: Tool Visibility Scoping

const MCP_001 = createRule({
  id: 'MCP-001',
  category: 'MCP Tool Visibility',
  title: 'Tool handler has no tenant-based visibility filter',
  description:
    'MCP tool handler does not implement tenant-based tool visibility scoping. All tenants can see all tools.',
  severity: 'CRITICAL',
  requiredGuards: [...MCP_TOOL_VISIBILITY_GUARDS],
  owaspMcpRef: 'MCP09:2025',
  cweIds: ['CWE-639'],
  executionOrder: 100,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    for (const tool of ir.mcpTools) {
      if (tool.visibilityScoping === 'none') {
        findings.push(
          buildFinding(
            'MCP-001',
            'Tool handler has no tenant-based visibility filter',
            'CRITICAL',
            `Tool "${tool.name}" has no tenant-based visibility scoping. All tenants can discover and invoke this tool.`,
            buildEvidence(tool.location.file, tool.location.line, tool.location.line, `Tool: ${tool.name}`),
            [...MCP_TOOL_VISIBILITY_GUARDS],
            []
          )
        );
      }
    }
    return findings;
  },
});

// MCP-002: Cache Key Tenant Prefix

const MCP_002 = createRule({
  id: 'MCP-002',
  category: 'MCP Cache Isolation',
  title: 'Tool results cached without tenant prefix',
  description:
    'MCP tool results are cached without a tenant prefix in the cache key. Cross-tenant cache poisoning possible.',
  severity: 'CRITICAL',
  requiredGuards: [...MCP_CACHE_PREFIX_GUARDS],
  owaspMcpRef: 'MCP10:2025',
  cweIds: ['CWE-639'],
  executionOrder: 101,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    for (const cache of ir.mcpCacheEntries) {
      if (!cache.hasTenantPrefix) {
        findings.push(
          buildFinding(
            'MCP-002',
            'Tool results cached without tenant prefix',
            'CRITICAL',
            `Cache key "${cache.cacheKeyVar}" does not include tenant prefix. Cross-tenant cache poisoning.`,
            buildEvidence(cache.location.file, cache.location.line, cache.location.line, `Cache key: ${cache.cacheKeyVar}`),
            [...MCP_CACHE_PREFIX_GUARDS],
            []
          )
        );
      }
    }
    return findings;
  },
});

// MCP-003: Session Binding to User+Tenant

const MCP_003 = createRule({
  id: 'MCP-003',
  category: 'MCP Session Security',
  title: 'Session ID used as sole authorization',
  description:
    'MCP session is not bound to both user and tenant. Session ID alone is used for authorization.',
  severity: 'CRITICAL',
  requiredGuards: [...MCP_SESSION_BINDING_GUARDS],
  owaspMcpRef: 'MCP01:2025',
  cweIds: ['CWE-639', 'CWE-384'],
  executionOrder: 102,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    for (const session of ir.mcpSessions) {
      if (!session.boundToUser || !session.boundToTenant) {
        findings.push(
          buildFinding(
            'MCP-003',
            'Session ID used as sole authorization',
            'CRITICAL',
            `Session "${session.sessionIdVar}" is not bound to both user and tenant. Session hijacking enables cross-tenant access.`,
            buildEvidence(session.location.file, session.location.line, session.location.line, `Session: ${session.sessionIdVar}`),
            [...MCP_SESSION_BINDING_GUARDS],
            []
          )
        );
      }
    }
    return findings;
  },
});

// MCP-004: Token Exchange (RFC 8693)

const MCP_004 = createRule({
  id: 'MCP-004',
  category: 'MCP Token Security',
  title: 'Original token forwarded instead of token exchange',
  description:
    'MCP server forwards the original OAuth token to downstream APIs instead of performing token exchange per RFC 8693.',
  severity: 'HIGH',
  requiredGuards: ['tokenExchange', 'rfc8693', 'exchangedToken', 'downstreamToken'],
  owaspMcpRef: 'MCP07:2025',
  cweIds: ['CWE-287'],
  executionOrder: 103,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    for (const vault of ir.mcpCredentialVaults) {
      if (!vault.tenantScoped) {
        findings.push(
          buildFinding(
            'MCP-004',
            'Original token forwarded instead of token exchange',
            'HIGH',
            `Credential "${vault.credentialVar}" is not tenant-scoped. Original token may be forwarded without exchange.`,
            buildEvidence(vault.location.file, vault.location.line, vault.location.line, `Credential: ${vault.credentialVar}`),
            ['tokenExchange', 'rfc8693'],
            []
          )
        );
      }
    }
    return findings;
  },
});

// MCP-005: Per-Tenant Rate Limiting

const MCP_005 = createRule({
  id: 'MCP-005',
  category: 'MCP Rate Limiting',
  title: 'No per-tenant rate limiting on tool calls',
  description:
    'MCP tool handler does not implement per-tenant rate limiting. Single tenant can exhaust shared quota.',
  severity: 'MEDIUM',
  requiredGuards: [...MCP_RATE_LIMIT_GUARDS],
  owaspMcpRef: 'MCP02:2025',
  cweIds: ['CWE-770'],
  executionOrder: 104,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    for (const tool of ir.mcpTools) {
      const hasRateLimit = ir.authSignals.some(
        (a) => a.entrypointId === tool.entrypointId &&
        (a.name.includes('rateLimit') || a.name.includes('throttle'))
      );
      if (!hasRateLimit) {
        findings.push(
          buildFinding(
            'MCP-005',
            'No per-tenant rate limiting on tool calls',
            'MEDIUM',
            `Tool "${tool.name}" has no per-tenant rate limiting. Shared quota exhaustion risk.`,
            buildEvidence(tool.location.file, tool.location.line, tool.location.line, `Tool: ${tool.name}`),
            [...MCP_RATE_LIMIT_GUARDS],
            []
          )
        );
      }
    }
    return findings;
  },
});

// MCP-006: Vector Store Tenant Namespace

const MCP_006 = createRule({
  id: 'MCP-006',
  category: 'MCP Vector Store',
  title: 'Shared vector store without tenant namespaces',
  description:
    'MCP server uses a shared vector store without tenant-specific namespaces or partitions. Cross-tenant retrieval possible.',
  severity: 'HIGH',
  requiredGuards: [...MCP_VECTOR_STORE_GUARDS],
  owaspMcpRef: 'MCP10:2025',
  cweIds: ['CWE-639'],
  executionOrder: 105,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'vector_search') {
        const hasNamespace = hasGuard(sink.api, MCP_VECTOR_STORE_GUARDS);
        if (!hasNamespace) {
          findings.push(
            buildFinding(
              'MCP-006',
              'Shared vector store without tenant namespaces',
              'HIGH',
              'Vector store query without tenant namespace. Cross-tenant retrieval.',
              buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
              [...MCP_VECTOR_STORE_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

// MCP-007: Tool Description Injection

const MCP_007 = createRule({
  id: 'MCP-007',
  category: 'MCP Tool Description',
  title: 'Tool description could bypass isolation',
  description:
    'Tool description includes dynamic content from user input. Could be used for prompt injection to bypass isolation.',
  severity: 'MEDIUM',
  requiredGuards: [],
  owaspMcpRef: 'MCP07:2025',
  cweIds: ['CWE-77', 'CWE-94'],
  executionOrder: 106,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    for (const tool of ir.mcpTools) {
      if (tool.description && tool.description.includes('${')) {
        findings.push(
          buildFinding(
            'MCP-007',
            'Tool description could bypass isolation',
            'MEDIUM',
            `Tool "${tool.name}" has dynamic content in description. Prompt injection risk.`,
            buildEvidence(tool.location.file, tool.location.line, tool.location.line, `Tool: ${tool.name}`),
            [],
            []
          )
        );
      }
    }
    return findings;
  },
});

// MCP-008: Credential Vault Tenant Scoping

const MCP_008 = createRule({
  id: 'MCP-008',
  category: 'MCP Credential Vault',
  title: 'Credential vault stores tokens without tenant scoping',
  description:
    'MCP credential vault stores API tokens without tenant-specific scoping. Cross-tenant credential access.',
  severity: 'CRITICAL',
  requiredGuards: [...MCP_CREDENTIAL_VAULT_GUARDS],
  owaspMcpRef: 'MCP06:2025',
  cweIds: ['CWE-639', 'CWE-522'],
  executionOrder: 107,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    for (const vault of ir.mcpCredentialVaults) {
      if (!vault.tenantScoped) {
        findings.push(
          buildFinding(
            'MCP-008',
            'Credential vault stores tokens without tenant scoping',
            'CRITICAL',
            `Credential "${vault.credentialVar}" is not tenant-scoped. Cross-tenant credential access.`,
            buildEvidence(vault.location.file, vault.location.line, vault.location.line, `Credential: ${vault.credentialVar}`),
            [...MCP_CREDENTIAL_VAULT_GUARDS],
            []
          )
        );
      }
    }
    return findings;
  },
});

// MCP-009: Shared Service Account

const MCP_009 = createRule({
  id: 'MCP-009',
  category: 'MCP Service Account',
  title: 'Single shared API key for all tenant API calls',
  description:
    'MCP server uses a single shared API key for all tenant API calls instead of per-tenant credentials.',
  severity: 'HIGH',
  requiredGuards: [...MCP_CREDENTIAL_VAULT_GUARDS],
  owaspMcpRef: 'MCP05:2025',
  cweIds: ['CWE-639'],
  executionOrder: 108,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    if (ir.mcpCredentialVaults.length === 0 && ir.mcpTools.length > 0) {
      for (const tool of ir.mcpTools) {
        const hasCreds = ir.sinks.some(
          (s) => s.entrypointId === tool.entrypointId &&
          (s.api.includes('apiKey') || s.api.includes('API_KEY') || s.api.includes('serviceAccount'))
        );
        if (hasCreds) {
          findings.push(
            buildFinding(
              'MCP-009',
              'Single shared API key for all tenant API calls',
              'HIGH',
              `Tool "${tool.name}" uses shared API key. No per-tenant credential vault.`,
              buildEvidence(tool.location.file, tool.location.line, tool.location.line, `Tool: ${tool.name}`),
              [...MCP_CREDENTIAL_VAULT_GUARDS],
              []
            )
          );
          break;
        }
      }
    }
    return findings;
  },
});

// MCP-010: Session Cleanup on Disconnect

const MCP_010 = createRule({
  id: 'MCP-010',
  category: 'MCP Session Lifecycle',
  title: 'No deterministic session cleanup on disconnect',
  description:
    'MCP server does not implement deterministic session cleanup on client disconnect. Stale sessions may retain access.',
  severity: 'MEDIUM',
  requiredGuards: [],
  owaspMcpRef: 'MCP10:2025',
  cweIds: ['CWE-613'],
  executionOrder: 109,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    for (const session of ir.mcpSessions) {
      if (!session.cleanupOnDisconnect) {
        findings.push(
          buildFinding(
            'MCP-010',
            'No deterministic session cleanup on disconnect',
            'MEDIUM',
            `Session "${session.sessionIdVar}" has no cleanup on disconnect. Stale session risk.`,
            buildEvidence(session.location.file, session.location.line, session.location.line, `Session: ${session.sessionIdVar}`),
            ['cleanupOnDisconnect'],
            []
          )
        );
      }
    }
    return findings;
  },
});

// MCP-011: Telemetry Tenant Identifier

const MCP_011 = createRule({
  id: 'MCP-011',
  category: 'MCP Telemetry',
  title: 'Telemetry strips tenant identifier',
  description:
    'MCP telemetry configuration strips tenantId from telemetry data. Cannot attribute tool usage to tenants.',
  severity: 'LOW',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  owaspMcpRef: 'MCP02:2025',
  cweIds: ['CWE-778'],
  executionOrder: 110,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'log' && (sink.api.includes('telemetry') || sink.api.includes('metrics') || sink.api.includes('trace'))) {
        const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS);
        if (!hasTenant) {
          findings.push(
            buildFinding(
              'MCP-011',
              'Telemetry strips tenant identifier',
              'LOW',
              'Telemetry output without tenant identifier. Cannot attribute to tenant.',
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

// MCP-012: Local Bind (127.0.0.1)

const MCP_012 = createRule({
  id: 'MCP-012',
  category: 'MCP Network Security',
  title: 'MCP server binds to 0.0.0.0 instead of 127.0.0.1',
  description:
    'MCP server binds to 0.0.0.0 or all interfaces instead of 127.0.0.1. Exposes server to network.',
  severity: 'HIGH',
  requiredGuards: [],
  owaspMcpRef: 'MCP10:2025',
  cweIds: ['CWE-668'],
  executionOrder: 111,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    for (const entry of ir.entrypoints) {
      if (entry.type === 'mcp_tool_handler' || entry.type === 'mcp_resource_handler') {
        // Check if server binds to 0.0.0.0
        const hasWideBind = ir.assignments.some(
          (a) => a.dst.includes('listen') || a.srcSyms.some((s) => s.includes('0.0.0.0') || s.includes('::'))
        );
        if (hasWideBind) {
          findings.push(
            buildFinding(
              'MCP-012',
              'MCP server binds to 0.0.0.0 instead of 127.0.0.1',
              'HIGH',
              'MCP server binds to all interfaces. Should bind to 127.0.0.1.',
              buildEvidence(entry.location.file, entry.location.line, entry.location.line, `Entry: ${entry.path}`),
              [],
              []
            )
          );
          break;
        }
      }
    }
    return findings;
  },
});

// MCP-013: Filesystem Tenant Root

const MCP_013 = createRule({
  id: 'MCP-013',
  category: 'MCP Filesystem',
  title: 'Tool handler accesses filesystem without tenant root',
  description:
    'MCP tool handler accesses filesystem without a tenant-specific root directory. Path traversal across tenants.',
  severity: 'HIGH',
  requiredGuards: [...MCP_FILESYSTEM_GUARDS],
  owaspMcpRef: 'MCP05:2025',
  cweIds: ['CWE-22', 'CWE-639'],
  executionOrder: 112,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    for (const tool of ir.mcpTools) {
      const hasFileAccess = ir.sinks.some(
        (s) => s.entrypointId === tool.entrypointId &&
        (s.kind === 'file_read' || s.kind === 'file_write')
      );
      if (hasFileAccess) {
        const hasTenantRoot = ir.tenantScopes.some(
          (ts) => ts.entrypointId === tool.entrypointId && ts.hasTenantFilter
        );
        if (!hasTenantRoot) {
          findings.push(
            buildFinding(
              'MCP-013',
              'Tool handler accesses filesystem without tenant root',
              'HIGH',
              `Tool "${tool.name}" accesses filesystem without tenant root. Path traversal risk.`,
              buildEvidence(tool.location.file, tool.location.line, tool.location.line, `Tool: ${tool.name}`),
              [...MCP_FILESYSTEM_GUARDS],
              []
            )
          );
        }
      }
    }
    return findings;
  },
});

// MCP-014: Cross-Tenant Artifact Leakage

const MCP_014 = createRule({
  id: 'MCP-014',
  category: 'MCP Artifact Storage',
  title: 'Artifact storage without tenant prefix',
  description:
    'MCP artifact storage (files, images, outputs) does not include tenant prefix. Cross-tenant artifact access.',
  severity: 'HIGH',
  requiredGuards: [...TENANT_ISOLATION_GUARDS],
  owaspMcpRef: 'MCP09:2025',
  cweIds: ['CWE-639'],
  executionOrder: 113,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    for (const sink of ir.sinks) {
      if (sink.kind === 'object_storage' && sink.entrypointId) {
        const isMcpTool = ir.mcpTools.some((t) => t.entrypointId === sink.entrypointId);
        if (isMcpTool) {
          const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS);
          if (!hasTenant) {
            findings.push(
              buildFinding(
                'MCP-014',
                'Artifact storage without tenant prefix',
                'HIGH',
                'MCP tool artifact storage without tenant prefix. Cross-tenant access.',
                buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
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

// MCP-015: Dynamic Tool Namespace

const MCP_015 = createRule({
  id: 'MCP-015',
  category: 'MCP Tool Registration',
  title: 'Tools registered without tenant namespace',
  description:
    'MCP tools are registered dynamically without tenant-specific namespace. Tool name collisions across tenants.',
  severity: 'MEDIUM',
  requiredGuards: [...TENANT_ISOLATION_GUARDS, ...MCP_TOOL_VISIBILITY_GUARDS],
  owaspMcpRef: 'MCP08:2025',
  cweIds: ['CWE-639'],
  executionOrder: 114,
  evaluate: (ir): Finding[] => {
    const findings: Finding[] = [];
    for (const tool of ir.mcpTools) {
      if (!tool.name.includes(':') && !tool.name.includes('/') && !tool.name.includes('_')) {
        const hasTenant = ir.tenantScopes.some(
          (ts) => ts.entrypointId === tool.entrypointId && ts.hasTenantFilter
        );
        if (!hasTenant) {
          findings.push(
            buildFinding(
              'MCP-015',
              'Tools registered without tenant namespace',
              'MEDIUM',
              `Tool "${tool.name}" registered without tenant namespace. Name collision risk.`,
              buildEvidence(tool.location.file, tool.location.line, tool.location.line, `Tool: ${tool.name}`),
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


export const MCP_RULES: RuleSpec[] = [
  MCP_001, MCP_002, MCP_003, MCP_004, MCP_005,
  MCP_006, MCP_007, MCP_008, MCP_009, MCP_010,
  MCP_011, MCP_012, MCP_013, MCP_014, MCP_015,
];
