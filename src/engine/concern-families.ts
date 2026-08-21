/**
 * Concern Family Mapping (Part 12)
 *
 * Maps rule categories to higher-level concern families for triage and reporting.
 * Multiple categories map to one concern family.
 */

import type { ConcernFamily, ConcernFamilySummary, Finding, Severity } from '../types.js';

const CATEGORY_TO_FAMILY: Record<string, ConcernFamily> = {
  // Tenant Context
  'Tenant Context Management': 'Tenant Context',

  // Data Isolation
  'Database Query Isolation': 'Data Isolation',
  'IDOR Prevention': 'Data Isolation',
  'Schema & Migration': 'Data Isolation',

  // Cache & Session
  'Cache & Session Isolation': 'Cache & Session',
  'MCP Session Security': 'Cache & Session',
  'MCP Session Lifecycle': 'Cache & Session',
  'MCP Cache Isolation': 'Cache & Session',

  // MCP Security
  'MCP Tool Visibility': 'MCP Security',
  'MCP Tool Description': 'MCP Security',
  'MCP Tool Registration': 'MCP Security',
  'MCP Rate Limiting': 'MCP Security',
  'MCP Network Security': 'MCP Security',
  'MCP Filesystem': 'MCP Security',
  'MCP Telemetry': 'MCP Security',
  'MCP Service Account': 'MCP Security',
  'MCP Artifact Storage': 'MCP Security',

  // Secrets & Credentials
  'MCP Token Security': 'Secrets & Credentials',
  'MCP Credential Vault': 'Secrets & Credentials',

  // Vector & Storage
  'MCP Vector Store': 'Vector & Storage',
  'File Storage Isolation': 'Vector & Storage',

  // API & Access
  'API Security': 'API & Access',

  // Audit & Logging
  'Logging & Audit': 'Audit & Logging',
};

/**
 * Get the concern family for a rule category.
 * Returns 'Audit & Logging' as a default for unknown categories.
 */
export function getConcernFamily(category: string): ConcernFamily {
  return CATEGORY_TO_FAMILY[category] ?? 'Audit & Logging';
}

/**
 * Aggregate findings by concern family (Part 12).
 * Returns one summary per concern family that has at least one finding.
 */
export function aggregateConcernFamilies(
  findings: Finding[],
  categoryLookup: (ruleId: string) => string | undefined
): ConcernFamilySummary[] {
  const familyMap = new Map<ConcernFamily, ConcernFamilySummary>();

  for (const f of findings) {
    const category = categoryLookup(f.ruleId);
    if (!category) continue;
    const family = getConcernFamily(category);

    if (!familyMap.has(family)) {
      familyMap.set(family, {
        family,
        totalFindings: 0,
        activeFindings: 0,
        suppressedFindings: 0,
        bySeverity: { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 } as Record<Severity, number>,
        ruleIds: [],
      });
    }

    const summary = familyMap.get(family)!;
    summary.totalFindings++;
    summary.bySeverity[f.severity]++;

    if (f.suppressionStatus === 'suppressed') {
      summary.suppressedFindings++;
    } else {
      summary.activeFindings++;
    }

    if (!summary.ruleIds.includes(f.ruleId)) {
      summary.ruleIds.push(f.ruleId);
    }
  }

  // Sort by total findings descending, then by family name
  return [...familyMap.values()].sort((a, b) => {
    if (b.totalFindings !== a.totalFindings) return b.totalFindings - a.totalFindings;
    return a.family.localeCompare(b.family);
  });
}
