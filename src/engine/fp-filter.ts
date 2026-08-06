/**
 * False Positive Filter
 *
 * Filters out findings that are likely false positives:
 * - Findings in test files
 * - Findings in type definitions
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

export function filterFalsePositives(findings: Finding[], _ir: IR): Finding[] {
  return findings.filter((finding) => {
    // Skip findings in test files
    if (isTestFile(finding.evidence.file)) return false;

    // Skip findings in type definition files
    if (isTypeDefinition(finding.evidence.file)) return false;

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
