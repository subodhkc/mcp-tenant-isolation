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

/**
 * Proof-of-fix state (Part 16).
 * - STILL_PRESENT: finding exists in both baseline and current scan
 * - RESOLVED_CONFIRMED: finding was in baseline but not in current scan (verified gone)
 * - NEW: finding exists in current scan but not in baseline
 * - NOT_VERIFIABLE: proof-of-fix cannot be determined (e.g., no baseline, parse failure)
 */
export type ProofOfFixState = 'STILL_PRESENT' | 'RESOLVED_CONFIRMED' | 'NEW' | 'NOT_VERIFIABLE';

/**
 * Concern family (Part 12). Higher-level grouping of rule categories
 * for triage and reporting. Multiple categories map to one concern family.
 */
export type ConcernFamily =
  | 'Tenant Context'
  | 'Data Isolation'
  | 'Cache & Session'
  | 'MCP Security'
  | 'Secrets & Credentials'
  | 'Vector & Storage'
  | 'API & Access'
  | 'Audit & Logging';

/** Aggregated finding counts by concern family (Part 12). */
export interface ConcernFamilySummary {
  family: ConcernFamily;
  totalFindings: number;
  activeFindings: number;
  suppressedFindings: number;
  bySeverity: Record<Severity, number>;
  ruleIds: string[];
}

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
  /** Fingerprint version: 1 = line-dependent (legacy), 2 = semantic (stable under line movement). */
  fingerprintVersion?: number;
  diffStatus?: DiffStatus;
  suppressionStatus?: SuppressionStatus;
  suppressionReason?: string;
  suppressionExpires?: string;
  /** Proof-of-fix state relative to a baseline (Part 16). */
  proofOfFix?: ProofOfFixState;
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
  /** Completeness state (Part 9). COMPLETE = no failures; PARTIAL = some parse/rule failures; ERROR = scan could not run. */
  completeness: CompletenessState;
  /** Human-readable reasons for non-COMPLETE completeness. */
  completenessReasons: string[];
  /** Coverage and accounting metadata (Part 10-11). */
  coverage: CoverageInfo;
  /** Known limitations of this scan run (e.g., unsupported file types, flow analysis gaps). */
  limitations: string[];
  /** Concern family aggregation (Part 12). */
  concernFamilies?: ConcernFamilySummary[];
  /** Scan receipt for reproducibility and provenance (Parts 17-18). */
  receipt?: ScanReceipt;
}

/**
 * Scan Receipt (Parts 17-18). Provenance and reproducibility metadata
 * for a scan run. Allows consumers to verify what was scanned, when,
 * with what engine/rules, and under what configuration.
 */
export interface ScanReceipt {
  /** Receipt schema version. */
  schemaVersion: string;
  /** Producer identity (package name). */
  producerId: string;
  /** Engine version (RULE_ENGINE_VERSION). */
  engineVersion: string;
  /** ISO 8601 timestamp of the scan. */
  timestamp: string;
  /** Project root path scanned. */
  projectRoot: string;
  /** Scan duration in milliseconds. */
  durationMs: number;
  /** Completeness state. */
  completeness: CompletenessState;
  /** Verdict (PASS/REVIEW/BLOCK/ERROR). */
  verdict: 'PASS' | 'REVIEW' | 'BLOCK' | 'ERROR';
  /** Rulepack digest (hash of rule definitions for reproducibility, Part 22). */
  rulepackDigest: string;
  /** Number of rules available. */
  rulesAvailable: number;
  /** Number of rules selected (after filters). */
  rulesSelected: number;
  /** Number of files discovered. */
  filesDiscovered: number;
  /** Number of files parsed. */
  filesParsed: number;
  /** Total findings (active + suppressed + baseline). */
  totalFindings: number;
  /** Active findings count. */
  activeFindings: number;
  /** Suppressed findings count. */
  suppressedFindings: number;
  /** SHA-256 hash of the receipt content (excluding this field) for tamper detection. */
  receiptHash: string;
}

/**
 * Evidence Envelope (Parts 19-20). A structured container that bundles
 * the scan receipt, findings, coverage, and limitations into a single
 * verifiable artifact. This is the canonical output format for evidence
 * sharing and future cloud ingestion.
 */
export interface EvidenceEnvelope {
  /** Envelope schema version. */
  schemaVersion: string;
  /** Producer identity. */
  producerId: string;
  /** ISO 8601 timestamp. */
  timestamp: string;
  /** The scan receipt (provenance). */
  receipt: ScanReceipt;
  /** Concern family aggregation. */
  concernFamilies: ConcernFamilySummary[];
  /** Bounded findings array. */
  findings: Finding[];
  /** Truncation metadata. */
  truncation: {
    findingsReturned: number;
    findingsTotal: number;
    truncated: boolean;
  };
  /** Coverage info. */
  coverage: CoverageInfo;
  /** Completeness reasons. */
  completenessReasons: string[];
  /** Limitations. */
  limitations: string[];
  /** SHA-256 hash of the envelope content (excluding this field) for tamper detection. */
  envelopeHash: string;
}

/** Completeness state for a scan run. */
export type CompletenessState = 'COMPLETE' | 'PARTIAL' | 'ERROR';

/** Coverage and accounting metadata for a scan run. */
export interface CoverageInfo {
  // File accounting
  filesDiscovered: number;
  filesParsed: number;
  parseFailures: number;
  parseFailureDetails: ParseFailure[];
  excludedPaths: number;
  unsupportedPaths: number;

  // Rule accounting
  rulesAvailable: number;
  rulesSelected: number;
  rulesEvaluated: number;
  rulesFailed: number;
  ruleFailureDetails: RuleFailure[];
  rulesTriggered: number;
}

/** Details about a single parse failure. */
export interface ParseFailure {
  file: string;
  error: string;
}

/** Details about a single rule evaluation failure. */
export interface RuleFailure {
  ruleId: string;
  error: string;
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
  /** @deprecated Use documentedApprover. "approvedBy" implied independent human verification that does not occur. */
  approvedBy?: string;
  /**
   * Documented approver identifier. This is a recorded attribution string,
   * NOT a claim of independent human verification. Renamed from approvedBy
   * to avoid implying approval that did not occur.
   */
  documentedApprover?: string;
  compensatingControls?: string[];
  /**
   * If true, the suppression is a documented permanent exception and
   * `expires` may be omitted. Must include a justification in `reason`
   * explaining why no expiry applies.
   */
  permanentException?: boolean;
  /** Fingerprint schema version (1 = line-based legacy, 2 = semantic stable). Default 2 for new suppressions. */
  fingerprintVersion?: 1 | 2;
}

export interface SuppressionFile {
  suppress: SuppressionRule[];
}


export interface BaselineFingerprint {
  fingerprint: string;
  /** Fingerprint version: 1 = line-dependent (legacy), 2 = semantic (stable). */
  fingerprintVersion?: number;
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
