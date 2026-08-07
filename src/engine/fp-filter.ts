/**
 * False Positive Filter
 *
 * Filters out findings that are likely false positives:
 * - Findings in test files
 * - Findings in type definitions
 * - Findings in non-production code paths (demo, scripts, legacy, etc.)
 * - Findings with positive controls present
 */

import type { Finding, IR } from '../types.js';

const TEST_FILE_INDICATORS = [
  '.test.',
  '.spec.',
  '__tests__/',
  '/test/',
  '/tests/',
  'test-utils',
  'mock',
  'fixture',
];

const TYPE_DEF_INDICATORS = [
  '.d.ts',
  '/types/',
  '/interfaces/',
  'types.ts',
  'types.tsx',
];

const EXCLUDED_PATH_PATTERNS = [
  'demo-repos/',
  'demo/',
  '/examples/',
  '/example/',
  '/samples/',
  'Old Files/',
  '/archive/',
  '/backup/',
  '/legacy/',
  '/scripts/',
  '/bin/',
  '/tools/',
  'Private Ai',
  '.stories.',
  '.story.',
  '/e2e/',
  '.e2e.',
  '.cy.',
  '/__mocks__/',
  '/mocks/',
  '/fixtures/',
];

// API route patterns that don't require tenant context.
// Public routes: forms, downloads, badges, certificates, disclosures, verify endpoints.
// Webhook routes: authenticated by signature verification, not tenant context.
// Cron routes: authenticated by cron secret, not tenant context.
// Admin routes: authenticated by admin/superadmin auth, not tenant context.
// Monitoring routes: health checks, metrics, error reporting.
const PUBLIC_API_ROUTE_PATTERNS = [
  '/api/contact',
  '/api/consultation',
  '/api/lead-capture',
  '/api/leads/capture',
  '/api/newsletter',
  '/api/unsubscribe',
  '/api/early-access',
  '/api/download',
  '/api/playbook-download',
  '/api/intake-form',
  '/api/wordpress-waitlist',
  '/api/certification/join',
  '/api/risk-assessment/lead',
  '/api/enforcement-preview/lead',
  '/api/exposure-score/submit',
  '/api/badge/',
  '/api/cert-badge',
  '/api/certificate/',
  '/api/compliance/certificate',
  '/api/verify/',
  '/api/disclosure/',
  '/api/v1/nyc-public-disclosure',
  '/api/github-app/public-',
  '/api/github-app/recent-scans',
  '/api/evidence/request',
  '/api/external-ai-snapshot/download',
];

const WEBHOOK_API_ROUTE_PATTERNS = [
  '/api/stripe/webhook',
  '/api/webhooks/',
  '/api/nyc-webhooks',
];

const CRON_API_ROUTE_PATTERNS = [
  '/api/cron/',
];

const ADMIN_API_ROUTE_PATTERNS = [
  '/api/admin/',
];

const MONITORING_API_ROUTE_PATTERNS = [
  '/api/monitoring/',
  '/api/errors/report',
  '/api/ai-security/health',
];

// Rules that should be filtered for non-tenant API routes
const API_RULES_TO_FILTER = ['API-002', 'API-003'];

export function filterFalsePositives(findings: Finding[], _ir: IR): Finding[] {
  return findings.filter((finding) => {
    // Skip findings in test files
    if (isTestFile(finding.evidence.file)) return false;

    // Skip findings in type definition files
    if (isTypeDefinition(finding.evidence.file)) return false;

    // Skip findings in non-production code paths
    if (isExcludedPath(finding.evidence.file)) return false;

    // Skip API-002/API-003 in non-tenant API routes (public, webhook, cron, admin, monitoring)
    if (API_RULES_TO_FILTER.includes(finding.ruleId) && isNonTenantApiRoute(finding.evidence.file)) return false;

    // Skip findings with empty missing guards (if all guards present)
    if (finding.missingGuards.length === 0 && finding.presentGuards.length > 0) return false;

    return true;
  });
}

function isTestFile(filepath: string): boolean {
  return TEST_FILE_INDICATORS.some((indicator) => filepath.includes(indicator));
}

function isTypeDefinition(filepath: string): boolean {
  return TYPE_DEF_INDICATORS.some((indicator) => filepath.includes(indicator));
}

function isExcludedPath(filepath: string): boolean {
  return EXCLUDED_PATH_PATTERNS.some((pattern) => filepath.includes(pattern));
}

function isNonTenantApiRoute(filepath: string): boolean {
  const allPatterns = [
    ...PUBLIC_API_ROUTE_PATTERNS,
    ...WEBHOOK_API_ROUTE_PATTERNS,
    ...CRON_API_ROUTE_PATTERNS,
    ...ADMIN_API_ROUTE_PATTERNS,
    ...MONITORING_API_ROUTE_PATTERNS,
  ];
  return allPatterns.some((pattern) => filepath.includes(pattern));
}
