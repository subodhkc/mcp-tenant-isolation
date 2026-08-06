/**
 * mcp-tenant-isolation - Core Type Definitions
 *
 * Self-contained types for the tenant isolation scanner.
 * Standalone scanner with no external dependencies.
 */


export interface Location {
  file: string;
  line: number;
  column: number;
}

export interface Evidence {
  file: string;
  lineStart: number;
  lineEnd: number;
  codeSnippet: string;
}


export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

// INTERMEDIATE REPRESENTATION (IR)

export type EntrypointType =
  | 'api_route'
  | 'server_action'
  | 'webhook'
  | 'background_job'
  | 'mcp_tool_handler'
  | 'mcp_resource_handler';

export interface Entrypoint {
  id: string;
  type: EntrypointType;
  path: string;
  location: Location;
  authSignals: string[];
  isStreaming: boolean;
}

export type SourceKind =
  | 'user'
  | 'session'
  | 'external'
  | 'webhook'
  | 'query_param'
  | 'header'
  | 'mcp_tool_input'
  | 'mcp_resource_uri'
  | 'mcp_session';

export interface Source {
  id: string;
  kind: SourceKind;
  symbol: string;
  entrypointId?: string;
  location: Location;
}

export type SinkKind =
  | 'db_read'
  | 'db_write'
  | 'http_fetch'
  | 'file_read'
  | 'file_write'
  | 'object_storage'
  | 'cache_read'
  | 'cache_write'
  | 'log'
  | 'vector_search'
  | 'credential_vault'
  | 'mcp_tool_call'
  | 'mcp_resource_access';

export interface Sink {
  id: string;
  kind: SinkKind;
  api: string;
  argsVars: string[];
  location: Location;
  entrypointId?: string;
  functionStartLine?: number;
  functionEndLine?: number;
}

export interface Assignment {
  id: string;
  dst: string;
  srcSyms: string[];
  location: Location;
  entrypointId?: string;
}

export interface AuthSignal {
  id: string;
  type: 'decorator' | 'middleware' | 'guard' | 'session_check';
  name: string;
  location: Location;
  entrypointId?: string;
}


export interface TenantScope {
  id: string;
  location: Location;
  entrypointId?: string;
  hasTenantFilter: boolean;
  tenantVars: string[];
  appliesToSinkId: string;
}

// MCP-SPECIFIC IR TYPES

export interface MCPToolDefinition {
  id: string;
  name: string;
  description?: string;
  location: Location;
  entrypointId?: string;
  hasTenantFilter: boolean;
  visibilityScoping: 'none' | 'static' | 'dynamic';
  parameters: string[];
}

export interface MCPSession {
  id: string;
  sessionIdVar: string;
  location: Location;
  boundToUser: boolean;
  boundToTenant: boolean;
  cleanupOnDisconnect: boolean;
}

export interface MCPCredentialVault {
  id: string;
  location: Location;
  tenantScoped: boolean;
  credentialVar: string;
}

export interface MCPResource {
  id: string;
  uri: string;
  location: Location;
  tenantScoped: boolean;
}

export interface MCPCacheEntry {
  id: string;
  cacheKeyVar: string;
  location: Location;
  hasTenantPrefix: boolean;
}


export interface IR {
  projectRoot: string;
  scanTimestamp: string;
  entrypoints: Entrypoint[];
  sources: Source[];
  sinks: Sink[];
  assignments: Assignment[];
  authSignals: AuthSignal[];
  tenantScopes: TenantScope[];
  mcpTools: MCPToolDefinition[];
  mcpSessions: MCPSession[];
  mcpCredentialVaults: MCPCredentialVault[];
  mcpResources: MCPResource[];
  mcpCacheEntries: MCPCacheEntry[];
  files: ParsedFile[];
  sqlTables?: SqlTable[];
  sqlRlsPolicies?: SqlRlsPolicy[];
  sqlRlsEnabledTables?: string[];
  prismaModels?: PrismaModelInfo[];
}

export interface ParsedFile {
  path: string;
  language: 'typescript' | 'javascript' | 'prisma' | 'sql';
  lineCount: number;
  parseTimeMs: number;
}


export interface SqlTable {
  name: string;
  columns: string[];
  hasTenantColumn: boolean;
  tenantColumnName?: string;
  location: Location;
}

export interface SqlRlsPolicy {
  tableName: string;
  policyName: string;
  using: string;
  withCheck: string;
  isBypassed: boolean;
  location: Location;
}

export interface PrismaModelInfo {
  name: string;
  hasTenantField: boolean;
  tenantFieldName?: string;
  scope: 'tenant' | 'user' | 'global';
  fields: { name: string; type: string; isRelation: boolean; isTenantField: boolean }[];
  location: Location;
}


export type NodeType = string;

export interface NodeMetadata {
  entrypointId: string;
  location: Location;
  kind: string;
  confidence: number;
}

export interface FlowGraph {
  nodes: Set<NodeType>;
  edges: Map<NodeType, Set<NodeType>>;
  metadata: Map<NodeType, NodeMetadata>;
}

export interface FlowPath {
  nodes: NodeType[];
  entrypointId: string;
  sourceKind: string;
  sinkKind: string;
  length: number;
}


export type DiffStatus = 'new' | 'existing' | 'regressed' | 'fixed';
export type SuppressionStatus = 'active' | 'suppressed' | 'baseline';

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: number;
  description: string;
  evidence: Evidence;
  missingGuards: string[];
  presentGuards: string[];
  fingerprint: string;
  diffStatus?: DiffStatus;
  suppressionStatus?: SuppressionStatus;
  suppressionReason?: string;
  suppressionExpires?: string;
}


export interface RuleMeta {
  ruleId: string;
  title: string;
  category: string;
  defaultSeverity: Severity;
  executionOrder: number;
  requiresFlowGraph: boolean;
  suppressible: boolean;
  description: string;
  owaspMcpRef?: string;
  cweIds?: string[];
}

export type RuleEvaluator = (ir: IR, graph: FlowGraph) => Finding[];


export interface ScanResult {
  findings: Finding[];
  ir: IR;
  stats: ScanStats;
  durationMs: number;
  error?: string;
}

export interface ScanStats {
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<string, number>;
  filesScanned: number;
  rulesEvaluated: number;
  rulesTriggered: number;
}


export interface MtiConfig {
  rules?: {
    severity?: Record<string, Severity>;
    exclude?: string[];
  };
  paths?: {
    include?: string[];
    exclude?: string[];
    nonProduction?: string[];
  };
  suppressions?: string;
  baseline?: string;
  rulePacks?: string[];
  authHelpers?: string[];
  tenantGuards?: string[];
  modelScopes?: {
    userScoped?: string[];
    global?: string[];
    tenantScoped?: string[];
  };
  framework?: 'nextjs-app-router' | 'nextjs-pages' | 'express' | 'fastify' | 'auto';
  output?: 'terminal' | 'json' | 'sarif' | 'ai' | 'markdown';
}


export interface SuppressionRule {
  fingerprint?: string;
  ruleId?: string;
  filePath?: string;
  reason: string;
  expires?: string;
  approvedBy?: string;
  compensatingControls?: string[];
}

export interface SuppressionFile {
  suppress: SuppressionRule[];
}


export interface BaselineFingerprint {
  fingerprint: string;
  ruleId: string;
  severity: Severity;
  file: string;
  line: number;
}

export interface Baseline {
  version: string;
  project: string;
  createdAt: string;
  fingerprints: BaselineFingerprint[];
}


export const EXIT_CODES = {
  NO_FINDINGS: 0,
  FINDINGS_FOUND: 1,
  ERROR: 2,
} as const;
