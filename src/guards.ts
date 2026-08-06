/**
 * Guard Definitions for Tenant Isolation Rules
 *
 * Guards are security controls that prevent unsafe data flows.
 * A finding is only raised if required guards are missing.
 *
 * DETECTION METHOD: Pattern-based string matching on AST nodes.
 *
 * LIMITATIONS (documented for transparency):
 * - Detection is substring matching, not semantic analysis
 * - Aliased imports won't be detected (e.g., `z.parse` vs `zod.parse`)
 * - Custom validation functions won't be detected
 * - No data flow tracking through guard application
 *
 * KNOWN FALSE NEGATIVES:
 * - Custom validation wrappers
 * - Aliased library imports
 * - Validation in separate utility files
 *
 * KNOWN FALSE POSITIVES:
 * - Guard detected but not on the vulnerable path
 * - Guard present but incorrectly implemented
 */


export const TENANT_ISOLATION_GUARDS = [
  'tenantId',
  'organizationId',
  'workspaceId',
  'tenant_filter',
  'org_filter',
  'namespace',
  'tenant_scope',
  'row_level_security',
  'rls',
  'orgId',
  'tenant_id',
] as const;


export const AUTHENTICATION_GUARDS = [
  'auth()',
  'getServerSession',
  'getSession',
  'verifyToken',
  'requireAuth',
  'authenticate',
  'isAuthenticated',
  'checkAuth',
  'jwt.verify',
  'session.user',
  'requireOrganizationAccess',
  'requireTenantAccess',
] as const;


export const AUTHORIZATION_GUARDS = [
  'checkPermission',
  'hasRole',
  'hasPermission',
  'authorize',
  'rbac',
  'acl',
  'can()',
  'ability.can',
  'policy.authorize',
] as const;

// MCP-SPECIFIC GUARDS

export const MCP_TOOL_VISIBILITY_GUARDS = [
  'tenantTools',
  'allowedTools',
  'toolAllowlist',
  'toolVisibility',
  'tenantToolFilter',
  'toolScope',
  'visibleTools',
  'enabledTools',
] as const;

export const MCP_CACHE_PREFIX_GUARDS = [
  'tenantPrefix',
  'cachePrefix',
  'keyPrefix',
  'namespacePrefix',
  'tenantCacheKey',
  'scopedCacheKey',
] as const;

export const MCP_SESSION_BINDING_GUARDS = [
  'session.userId',
  'session.tenantId',
  'session.organizationId',
  'boundToUser',
  'boundToTenant',
  'sessionBinding',
  'userTenantBinding',
] as const;

export const MCP_CREDENTIAL_VAULT_GUARDS = [
  'tenantCredentials',
  'scopedCredentials',
  'tenantToken',
  'perTenantToken',
  'credentialScope',
  'vaultNamespace',
] as const;

export const MCP_RATE_LIMIT_GUARDS = [
  'tenantRateLimit',
  'perTenantLimit',
  'rateLimitByTenant',
  'tenantThrottle',
] as const;

export const MCP_VECTOR_STORE_GUARDS = [
  'tenantNamespace',
  'vectorNamespace',
  'tenantCollection',
  'scopedIndex',
  'tenantPartition',
] as const;

export const MCP_FILESYSTEM_GUARDS = [
  'tenantRoot',
  'tenantDir',
  'scopedRoot',
  'tenantPath',
  'sandboxPath',
] as const;


export const ALL_GUARDS = [
  ...TENANT_ISOLATION_GUARDS,
  ...AUTHENTICATION_GUARDS,
  ...AUTHORIZATION_GUARDS,
  ...MCP_TOOL_VISIBILITY_GUARDS,
  ...MCP_CACHE_PREFIX_GUARDS,
  ...MCP_SESSION_BINDING_GUARDS,
  ...MCP_CREDENTIAL_VAULT_GUARDS,
  ...MCP_RATE_LIMIT_GUARDS,
  ...MCP_VECTOR_STORE_GUARDS,
  ...MCP_FILESYSTEM_GUARDS,
] as const;


export const GUARDS_BY_CATEGORY: Record<string, readonly string[]> = {
  tenant_isolation: TENANT_ISOLATION_GUARDS,
  authentication: AUTHENTICATION_GUARDS,
  authorization: AUTHORIZATION_GUARDS,
  mcp_tool_visibility: MCP_TOOL_VISIBILITY_GUARDS,
  mcp_cache_prefix: MCP_CACHE_PREFIX_GUARDS,
  mcp_session_binding: MCP_SESSION_BINDING_GUARDS,
  mcp_credential_vault: MCP_CREDENTIAL_VAULT_GUARDS,
  mcp_rate_limit: MCP_RATE_LIMIT_GUARDS,
  mcp_vector_store: MCP_VECTOR_STORE_GUARDS,
  mcp_filesystem: MCP_FILESYSTEM_GUARDS,
};


export function hasGuard(code: string, guards: readonly string[]): boolean {
  return guards.some((guard) => code.includes(guard));
}

export function findMissingGuards(
  code: string,
  requiredGuards: readonly string[]
): string[] {
  return requiredGuards.filter((guard) => !code.includes(guard));
}

export function findPresentGuards(
  code: string,
  guards: readonly string[]
): string[] {
  return guards.filter((guard) => code.includes(guard));
}
