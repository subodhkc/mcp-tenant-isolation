/**
 * JavaScript/TypeScript AST Parser
 *
 * Uses @babel/parser to parse JS/TS source code and extract
 * IR elements: entrypoints, sources, sinks, assignments, auth signals,
 * tenant scopes, MCP tool definitions, sessions, credential vaults, cache entries.
 */

import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import * as t from '@babel/types';
import type {
  IR,
  Entrypoint,
  Source,
  Sink,
  Assignment,
  AuthSignal,
  TenantScope,
  MCPToolDefinition,
  MCPSession,
  MCPCredentialVault,
  MCPResource,
  MCPCacheEntry,
  ParsedFile,
  Location,
  SinkKind,
} from '../types.js';
import {
  TENANT_ISOLATION_GUARDS,
  AUTHENTICATION_GUARDS,
  MCP_TOOL_VISIBILITY_GUARDS,
  MCP_CACHE_PREFIX_GUARDS,
  MCP_SESSION_BINDING_GUARDS,
  MCP_CREDENTIAL_VAULT_GUARDS,
  hasGuard,
} from '../guards.js';

// Handle ESM/CJS interop for @babel/traverse
const traverse: typeof _traverse = (_traverse as any).default || _traverse;


const PARSE_OPTIONS = {
  sourceType: 'module' as const,
  plugins: [
    'typescript',
    'jsx',
    'decorators-legacy',
    'classProperties',
    'objectRestSpread',
    'optionalChaining',
    'nullishCoalescingOperator',
    'asyncGenerators',
    'dynamicImport',
    'exportDefaultFrom',
    'exportNamespaceFrom',
  ] as const,
  errorRecovery: true,
} satisfies Parameters<typeof parse>[1];

// HELPER: NODE TO LOCATION

function toLocation(node: t.Node, filename: string): Location {
  return {
    file: filename,
    line: node.loc?.start.line ?? 0,
    column: node.loc?.start.column ?? 0,
  };
}

function getEnclosingFunctionRange(path: any): { start: number; end: number } | null {
  let current = path.parentPath;
  while (current) {
    const node = current.node;
    if (
      t.isFunctionDeclaration(node) ||
      t.isFunctionExpression(node) ||
      t.isArrowFunctionExpression(node) ||
      t.isObjectMethod(node) ||
      t.isClassMethod(node)
    ) {
      if (node.loc) {
        return { start: node.loc.start.line, end: node.loc.end.line };
      }
      return null;
    }
    current = current.parentPath;
  }
  return null;
}

function nodeToString(node: t.Node): string {
  if (t.isIdentifier(node)) return node.name;
  if (t.isMemberExpression(node)) {
    return `${nodeToString(node.object)}.${nodeToString(node.property)}`;
  }
  if (t.isCallExpression(node)) {
    return `${nodeToString(node.callee)}(${node.arguments.map((a) => nodeToString(a)).join(', ')})`;
  }
  if (t.isStringLiteral(node)) return node.value;
  if (t.isNumericLiteral(node)) return String(node.value);
  if (t.isObjectProperty(node)) {
    const key = t.isIdentifier(node.key) ? node.key.name :
                t.isStringLiteral(node.key) ? node.key.value : '';
    const value = node.value ? nodeToString(node.value) : '';
    return value ? `${key}.${value}` : key;
  }
  if (t.isObjectExpression(node)) {
    return `{${node.properties.map((p) => nodeToString(p)).join(', ')}}`;
  }
  if (t.isSpreadElement(node)) {
    return `...${nodeToString(node.argument)}`;
  }
  if (t.isArrowFunctionExpression(node) || t.isFunctionExpression(node)) {
    return '<fn>';
  }
  if (t.isAwaitExpression(node)) {
    return `await ${nodeToString(node.argument)}`;
  }
  if (t.isBinaryExpression(node)) {
    return `${nodeToString(node.left)} ${node.operator} ${nodeToString(node.right)}`;
  }
  if (t.isTemplateLiteral(node)) {
    return node.quasis.map((q) => q.value.cooked).join('');
  }
  if (t.isNullLiteral(node)) return 'null';
  if (t.isBooleanLiteral(node)) return String(node.value);
  return '';
}


const DB_CLIENT_PREFIXES = [
  'prisma.',
  'db.',
  'tx.',
  'transaction.',
  'client.',
  'connection.',
  'drizzle.',
  'pool.',
  'query.',
  'supabase.',
  'kysely.',
];

function isDbClient(callee: string): boolean {
  return DB_CLIENT_PREFIXES.some((prefix) => callee.startsWith(prefix));
}

export interface JsParseResult {
  ir: Partial<IR>;
  file: ParsedFile;
}

export function parseJsFile(
  sourceCode: string,
  filename: string,
  projectRoot: string,
  config?: { authHelpers?: string[]; tenantGuards?: string[]; framework?: string }
): JsParseResult {
  const framework = config?.framework ?? 'auto';
  const detectExpress = framework === 'auto' || framework === 'express' || framework === 'fastify';
  const detectNextjs = framework === 'auto' || framework === 'nextjs-app-router' || framework === 'nextjs-pages';
  const startTime = Date.now();
  const lines = sourceCode.split('\n');
  const lineCount = lines.length;

  const entrypoints: Entrypoint[] = [];
  const sources: Source[] = [];
  const sinks: Sink[] = [];
  const assignments: Assignment[] = [];
  const authSignals: AuthSignal[] = [];
  const tenantScopes: TenantScope[] = [];
  const mcpTools: MCPToolDefinition[] = [];
  const mcpSessions: MCPSession[] = [];
  const mcpCredentialVaults: MCPCredentialVault[] = [];
  const mcpResources: MCPResource[] = [];
  const mcpCacheEntries: MCPCacheEntry[] = [];

  let ast: t.File;
  try {
    ast = parse(sourceCode, PARSE_OPTIONS) as t.File;
  } catch (_err) {
    return {
      ir: {},
      file: {
        path: filename,
        language: filename.endsWith('.ts') ? 'typescript' : 'javascript',
        lineCount,
        parseTimeMs: Date.now() - startTime,
      },
    };
  }

  const relativePath = filename.replace(projectRoot, '').replace(/^\//, '');

  traverse(ast, {
    // ============================================
    // ENTRYPPOINTS: API routes, server actions, webhooks, MCP handlers
    // ============================================
    ExportNamedDeclaration(path) {
      const node = path.node;
      if (t.isFunctionDeclaration(node.declaration)) {
        const fnName = node.declaration.id?.name ?? '';
        const loc = toLocation(node, relativePath);

        // Detect MCP tool registration
        if (fnName.toLowerCase().includes('tool') || fnName.toLowerCase().includes('handler')) {
          entrypoints.push({
            id: `entry-${relativePath}-${loc.line}`,
            type: 'mcp_tool_handler',
            path: fnName,
            location: loc,
            authSignals: [],
            isStreaming: false,
          });
        }
      }
    },

    // ============================================
    // SOURCES: User input, session, query params
    // ============================================
    MemberExpression(path) {
      const node = path.node;
      const expr = nodeToString(node);

      // Detect req.body, req.query, req.params (Express-style) - only for express/fastify/auto
      if (detectExpress && (expr.startsWith('req.body') || expr.startsWith('req.query') || expr.startsWith('req.params'))) {
        sources.push({
          id: `src-${relativePath}-${node.loc?.start.line ?? 0}`,
          kind: expr.startsWith('req.query') ? 'query_param' : 'user',
          symbol: expr,
          location: toLocation(node, relativePath),
        });
      }

      // Detect Next.js App Router sources: request.json(), request.headers.get(), searchParams.get() - only for nextjs/auto
      if (detectNextjs && (expr.startsWith('request.json') || expr.startsWith('request.body') ||
          expr.startsWith('request.headers.get') || expr.startsWith('request.headers'))) {
        sources.push({
          id: `src-${relativePath}-${node.loc?.start.line ?? 0}`,
          kind: expr.includes('headers') ? 'header' : 'user',
          symbol: expr,
          location: toLocation(node, relativePath),
        });
      }

      // Detect searchParams.get() (Next.js App Router URL params) - only for nextjs/auto
      if (detectNextjs && (expr.startsWith('searchParams.get') || expr.startsWith('searchParams.'))) {
        sources.push({
          id: `src-${relativePath}-${node.loc?.start.line ?? 0}`,
          kind: 'query_param',
          symbol: expr,
          location: toLocation(node, relativePath),
        });
      }

      // Detect request.nextUrl.searchParams (Next.js) - only for nextjs/auto
      if (detectNextjs && (expr.startsWith('request.nextUrl.searchParams') || expr.startsWith('request.nextUrl'))) {
        sources.push({
          id: `src-${relativePath}-${node.loc?.start.line ?? 0}`,
          kind: 'query_param',
          symbol: expr,
          location: toLocation(node, relativePath),
        });
      }

      // Detect session.user, session.tenantId
      if (expr.startsWith('session.')) {
        sources.push({
          id: `src-${relativePath}-${node.loc?.start.line ?? 0}`,
          kind: 'session',
          symbol: expr,
          location: toLocation(node, relativePath),
        });
      }
    },

    // ============================================
    // SINKS: Database, cache, file, log, vector, credential
    // ============================================
    CallExpression(path) {
      const node = path.node;
      const callee = nodeToString(node.callee);
      const loc = toLocation(node, relativePath);
      const args = node.arguments.map((a) => nodeToString(a)).filter(Boolean);
      const fnRange = getEnclosingFunctionRange(path);

      // Database operations - require known DB client prefix to avoid false positives
      const isDbCall = isDbClient(callee);

      if (isDbCall && (callee.includes('findMany') || callee.includes('findFirst'))) {
        sinks.push({
          id: `sink-${relativePath}-${loc.line}`,
          kind: 'db_read' as SinkKind,
          api: callee,
          argsVars: args,
          location: loc,
          functionStartLine: fnRange?.start,
          functionEndLine: fnRange?.end,
        });
      }
      if (isDbCall && callee.includes('findUnique')) {
        sinks.push({
          id: `sink-${relativePath}-${loc.line}`,
          kind: 'db_read' as SinkKind,
          api: callee,
          argsVars: args,
          location: loc,
          functionStartLine: fnRange?.start,
          functionEndLine: fnRange?.end,
        });
      }
      if (isDbCall && (callee.includes('create') || callee.includes('update') || callee.includes('delete') || callee.includes('upsert'))) {
        sinks.push({
          id: `sink-${relativePath}-${loc.line}`,
          kind: 'db_write' as SinkKind,
          api: callee,
          argsVars: args,
          location: loc,
          functionStartLine: fnRange?.start,
          functionEndLine: fnRange?.end,
        });
      }
      if (isDbCall && (callee.includes('queryRaw') || callee.includes('executeRaw'))) {
        sinks.push({
          id: `sink-${relativePath}-${loc.line}`,
          kind: 'db_read' as SinkKind,
          api: callee,
          argsVars: args,
          location: loc,
          functionStartLine: fnRange?.start,
          functionEndLine: fnRange?.end,
        });
      }
      if (isDbCall && (callee.includes('count') || callee.includes('aggregate') || callee.includes('groupBy'))) {
        sinks.push({
          id: `sink-${relativePath}-${loc.line}`,
          kind: 'db_read' as SinkKind,
          api: callee,
          argsVars: args,
          location: loc,
          functionStartLine: fnRange?.start,
          functionEndLine: fnRange?.end,
        });
      }

      // Drizzle ORM specific methods
      if (isDbCall && callee.includes('select')) {
        sinks.push({
          id: `sink-${relativePath}-${loc.line}`,
          kind: 'db_read' as SinkKind,
          api: callee,
          argsVars: args,
          location: loc,
          functionStartLine: fnRange?.start,
          functionEndLine: fnRange?.end,
        });
      }
      if (isDbCall && (callee.includes('insert') || callee.includes('execute'))) {
        sinks.push({
          id: `sink-${relativePath}-${loc.line}`,
          kind: 'db_write' as SinkKind,
          api: callee,
          argsVars: args,
          location: loc,
          functionStartLine: fnRange?.start,
          functionEndLine: fnRange?.end,
        });
      }

      // Cache operations - server-side only (Redis, memcached)
      if (callee.includes('redis.get') || callee.includes('redis.set') || callee.includes('redis.del') ||
          callee.includes('memcached.get') || callee.includes('memcached.set') ||
          callee.includes('cacheClient.get') || callee.includes('cacheClient.set')) {
        sinks.push({
          id: `sink-${relativePath}-${loc.line}`,
          kind: (callee.includes('set') ? 'cache_write' : 'cache_read') as SinkKind,
          api: callee,
          argsVars: args,
          location: loc,
        });
      }

      // File operations
      if (callee.includes('readFile') || callee.includes('writeFile') || callee.includes('sendFile')) {
        sinks.push({
          id: `sink-${relativePath}-${loc.line}`,
          kind: (callee.includes('write') ? 'file_write' : 'file_read') as SinkKind,
          api: callee,
          argsVars: args,
          location: loc,
        });
      }

      // Object storage (S3, Blob)
      if (callee.includes('putObject') || callee.includes('getObject') || callee.includes('upload') || callee.includes('presign')) {
        sinks.push({
          id: `sink-${relativePath}-${loc.line}`,
          kind: 'object_storage' as SinkKind,
          api: callee,
          argsVars: args,
          location: loc,
        });
      }

      // Logging - structured loggers only (not console.log, not prisma.auditLog.create)
      if (callee.startsWith('logger.') || callee.startsWith('log.info') || callee.startsWith('log.warn') ||
          callee.startsWith('log.error') || callee.startsWith('log.debug') ||
          callee.startsWith('pino.') || callee.startsWith('winston.') ||
          callee.startsWith('auditLogger.') || callee.startsWith('audit_logger.')) {
        sinks.push({
          id: `sink-${relativePath}-${loc.line}`,
          kind: 'log' as SinkKind,
          api: callee,
          argsVars: args,
          location: loc,
        });
      }

      // Vector search
      if (callee.includes('vectorSearch') || callee.includes('similaritySearch') || callee.includes('query')) {
        if (callee.includes('vector') || callee.includes('embedding') || callee.includes('similarity')) {
          sinks.push({
            id: `sink-${relativePath}-${loc.line}`,
            kind: 'vector_search' as SinkKind,
            api: callee,
            argsVars: args,
            location: loc,
          });
        }
      }

      // Auth signals (built-in guards + user-configured auth helpers)
      const allAuthGuards = config?.authHelpers
        ? [...AUTHENTICATION_GUARDS, ...config.authHelpers]
        : AUTHENTICATION_GUARDS;
      if (hasGuard(callee, allAuthGuards)) {
        authSignals.push({
          id: `auth-${relativePath}-${loc.line}`,
          type: 'session_check',
          name: callee,
          location: loc,
        });
      }

      // MCP tool registration: server.tool(), server.registerTool()
      if (callee.includes('server.tool') || callee.includes('registerTool') || callee.includes('tools.set')) {
        const toolName = args[0] ?? 'unknown';
        const loc = toLocation(node, relativePath);
        const code = sourceCode.split('\n').slice(loc.line - 1, loc.line + 5).join('\n');
        const hasTenantFilter = hasGuard(code, TENANT_ISOLATION_GUARDS);
        const hasVisibility = hasGuard(code, MCP_TOOL_VISIBILITY_GUARDS);

        mcpTools.push({
          id: `mcp-tool-${relativePath}-${loc.line}`,
          name: toolName,
          location: loc,
          hasTenantFilter,
          visibilityScoping: hasVisibility ? 'static' : 'none',
          parameters: args,
        });
      }

      // MCP session creation
      if (callee.includes('createSession') || callee.includes('sessionId')) {
        const code = sourceCode.split('\n').slice(loc.line - 1, loc.line + 3).join('\n');
        mcpSessions.push({
          id: `mcp-session-${relativePath}-${loc.line}`,
          sessionIdVar: args[0] ?? callee,
          location: loc,
          boundToUser: hasGuard(code, MCP_SESSION_BINDING_GUARDS) && code.includes('userId'),
          boundToTenant: hasGuard(code, MCP_SESSION_BINDING_GUARDS) && (code.includes('tenantId') || code.includes('organizationId')),
          cleanupOnDisconnect: code.includes('cleanup') || code.includes('destroy') || code.includes('disconnect'),
        });
      }

      // MCP credential vault
      if (callee.includes('getCredential') || callee.includes('getToken') || callee.includes('apiKey') || callee.includes('secret')) {
        const code = sourceCode.split('\n').slice(loc.line - 1, loc.line + 3).join('\n');
        const tenantScoped = hasGuard(code, MCP_CREDENTIAL_VAULT_GUARDS);
        mcpCredentialVaults.push({
          id: `mcp-vault-${relativePath}-${loc.line}`,
          location: loc,
          tenantScoped,
          credentialVar: args[0] ?? callee,
        });
      }

      // MCP cache operations - server-side cache only
      if (callee.includes('redis.get') || callee.includes('redis.set') ||
          callee.includes('cacheClient.get') || callee.includes('cacheClient.set') ||
          callee.includes('cacheStore.get') || callee.includes('cacheStore.set')) {
        const code = sourceCode.split('\n').slice(loc.line - 1, loc.line + 3).join('\n');
        const hasTenantPrefix = hasGuard(code, MCP_CACHE_PREFIX_GUARDS);
        mcpCacheEntries.push({
          id: `mcp-cache-${relativePath}-${loc.line}`,
          cacheKeyVar: args[0] ?? callee,
          location: loc,
          hasTenantPrefix,
        });
      }
    },

    // ============================================
    // ASSIGNMENTS: Variable assignments
    // ============================================
    AssignmentExpression(path) {
      const node = path.node;
      const dst = nodeToString(node.left);
      const srcSyms: string[] = [];

      if (t.isIdentifier(node.right)) {
        srcSyms.push(node.right.name);
      } else if (t.isCallExpression(node.right)) {
        srcSyms.push(nodeToString(node.right.callee));
      } else if (t.isMemberExpression(node.right)) {
        srcSyms.push(nodeToString(node.right));
      }

      if (dst) {
        assignments.push({
          id: `asgn-${relativePath}-${node.loc?.start.line ?? 0}`,
          dst,
          srcSyms,
          location: toLocation(node, relativePath),
        });
      }
    },

    // ============================================
    // VARIABLE DECLARATIONS
    // ============================================
    VariableDeclarator(path) {
      const node = path.node;
      const dst = nodeToString(node.id);
      const srcSyms: string[] = [];

      if (node.init) {
        if (t.isIdentifier(node.init)) {
          srcSyms.push(node.init.name);
        } else if (t.isCallExpression(node.init)) {
          srcSyms.push(nodeToString(node.init.callee));
        } else if (t.isMemberExpression(node.init)) {
          srcSyms.push(nodeToString(node.init));
        }
      }

      if (dst) {
        assignments.push({
          id: `asgn-${relativePath}-${node.loc?.start.line ?? 0}`,
          dst,
          srcSyms,
          location: toLocation(node, relativePath),
        });
      }
    },
  });

  // Build tenant scopes by checking if sinks have tenant guards nearby
  for (const sink of sinks) {
    // Use full function body if available, otherwise fall back to 7-line window
    let code: string;
    if (sink.functionStartLine && sink.functionEndLine) {
      code = sourceCode.split('\n').slice(
        Math.max(0, sink.functionStartLine - 1),
        sink.functionEndLine
      ).join('\n');
    } else {
      code = sourceCode.split('\n').slice(
        Math.max(0, sink.location.line - 3),
        sink.location.line + 3
      ).join('\n');
    }
    // Also check argsVars for tenant guards (captures serialized where clauses)
    const argsStr = sink.argsVars.join(' ');
    const combined = `${code}\n${argsStr}`;
    const allTenantGuards = config?.tenantGuards
      ? [...TENANT_ISOLATION_GUARDS, ...config.tenantGuards]
      : TENANT_ISOLATION_GUARDS;
    const hasTenantFilter = hasGuard(combined, allTenantGuards);
    const tenantVars = allTenantGuards.filter((g) => combined.includes(g));

    tenantScopes.push({
      id: `tscope-${sink.id}`,
      location: sink.location,
      hasTenantFilter,
      tenantVars,
      appliesToSinkId: sink.id,
    });
  }

  const parseTimeMs = Date.now() - startTime;

  return {
    ir: {
      entrypoints,
      sources,
      sinks,
      assignments,
      authSignals,
      tenantScopes,
      mcpTools,
      mcpSessions,
      mcpCredentialVaults,
      mcpResources,
      mcpCacheEntries,
    },
    file: {
      path: relativePath,
      language: filename.endsWith('.ts') ? 'typescript' : 'javascript',
      lineCount,
      parseTimeMs,
    },
  };
}
