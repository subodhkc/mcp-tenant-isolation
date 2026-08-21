/**
 * mcp-tenant-isolation - Main Entry Point
 *
 * Public API for programmatic usage.
 */

export { scan } from './engine/scanner.js';
export type { ScanOptions } from './engine/scanner.js';
export { buildFlowGraph, findPaths } from './engine/flow-graph.js';
export { filterFalsePositives } from './engine/fp-filter.js';
export { applySuppressions, validateSuppression } from './engine/suppressions.js';
export { jsonReporter, sarifReporter, terminalReporter, aiJsonReporter, markdownReporter } from './reporters/index.js';
export { ALL_RULES, GENERAL_RULES, MCP_RULES, RULE_COUNT, RULE_ENGINE_VERSION, getRuleById, getRulesByCategory, getRuleCategories } from './rules/index.js';
export { createRule, buildFinding, buildEvidence, generateFingerprint, generateFingerprintV2, migrateFingerprintV1ToV2 } from './rule-spec.js';
export type { RuleSpec, CreateRuleOptions, ComplianceMapping } from './rule-spec.js';
export {
  TENANT_ISOLATION_GUARDS,
  AUTHENTICATION_GUARDS,
  AUTHORIZATION_GUARDS,
  MCP_TOOL_VISIBILITY_GUARDS,
  MCP_CACHE_PREFIX_GUARDS,
  MCP_SESSION_BINDING_GUARDS,
  MCP_CREDENTIAL_VAULT_GUARDS,
  MCP_RATE_LIMIT_GUARDS,
  MCP_VECTOR_STORE_GUARDS,
  MCP_FILESYSTEM_GUARDS,
  ALL_GUARDS,
  GUARDS_BY_CATEGORY,
  hasGuard,
  findMissingGuards,
  findPresentGuards,
} from './guards.js';
export type {
  IR,
  FlowGraph,
  FlowPath,
  Finding,
  ScanResult,
  ScanStats,
  Severity,
  Location,
  Evidence,
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
  MtiConfig,
  SuppressionRule,
  SuppressionFile,
  Baseline,
  BaselineFingerprint,
  EXIT_CODES,
} from './types.js';
export { parseJsFile } from './parsers/js-parser.js';
export { parsePrismaSchema, findModelsWithoutTenantField, findIndexesWithoutTenantFirst } from './parsers/prisma-parser.js';
export { parseSqlMigration, findTablesWithoutRls, findBypassedRlsPolicies } from './parsers/sql-parser.js';
export { startMcpServer } from './mcp/server.js';
export { aggregateConcernFamilies, getConcernFamily } from './engine/concern-families.js';
export { computeRulepackDigest, buildScanReceipt, buildEvidenceEnvelope, computeVerdict } from './engine/receipt.js';
