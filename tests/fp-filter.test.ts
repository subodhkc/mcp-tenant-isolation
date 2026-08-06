import { describe, it, expect } from 'vitest';
import { filterFalsePositives } from '../src/engine/fp-filter.js';
import type { Finding, IR } from '../src/types.js';

function makeFinding(file: string, overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'DBQ-001',
    title: 'Missing tenant filter',
    severity: 'HIGH',
    confidence: 0.9,
    description: 'Query lacks tenant filter',
    evidence: {
      file,
      lineStart: 1,
      lineEnd: 1,
      codeSnippet: 'prisma.findMany({})',
    },
    missingGuards: ['organizationId'],
    presentGuards: [],
    fingerprint: 'fp-' + file,
    suppressionStatus: 'active',
    ...overrides,
  };
}

const emptyIR: IR = {
  projectRoot: '/test',
  scanTimestamp: '2026-01-01T00:00:00.000Z',
  entrypoints: [],
  sources: [],
  sinks: [],
  assignments: [],
  authSignals: [],
  tenantScopes: [],
  mcpTools: [],
  mcpSessions: [],
  mcpCredentialVaults: [],
  mcpResources: [],
  mcpCacheEntries: [],
  files: [],
};

describe('False Positive Filter', () => {
  it('should filter out findings in test files', () => {
    const findings = [
      makeFinding('src/api/users.test.ts'),
      makeFinding('src/api/users/route.ts'),
    ];
    const filtered = filterFalsePositives(findings, emptyIR);

    expect(filtered).toHaveLength(1);
    expect(filtered[0].evidence.file).toBe('src/api/users/route.ts');
  });

  it('should filter out findings in spec files', () => {
    const findings = [
      makeFinding('src/utils/auth.spec.ts'),
      makeFinding('src/utils/auth.ts'),
    ];
    const filtered = filterFalsePositives(findings, emptyIR);

    expect(filtered).toHaveLength(1);
    expect(filtered[0].evidence.file).toBe('src/utils/auth.ts');
  });

  it('should filter out findings in __tests__ directory', () => {
    const findings = [
      makeFinding('src/__tests__/users.test.ts'),
      makeFinding('src/users/route.ts'),
    ];
    const filtered = filterFalsePositives(findings, emptyIR);

    expect(filtered).toHaveLength(1);
  });

  it('should filter out findings in type definition files', () => {
    const findings = [
      makeFinding('src/types/users.d.ts'),
      makeFinding('src/types/users.ts'),
      makeFinding('src/api/users/route.ts'),
    ];
    const filtered = filterFalsePositives(findings, emptyIR);

    expect(filtered).toHaveLength(1);
    expect(filtered[0].evidence.file).toBe('src/api/users/route.ts');
  });

  it('should filter out findings with empty missingGuards but present guards', () => {
    const findings = [
      makeFinding('src/api/users/route.ts', { missingGuards: [], presentGuards: ['organizationId'] }),
      makeFinding('src/api/posts/route.ts', { missingGuards: ['organizationId'], presentGuards: [] }),
    ];
    const filtered = filterFalsePositives(findings, emptyIR);

    expect(filtered).toHaveLength(1);
    expect(filtered[0].evidence.file).toBe('src/api/posts/route.ts');
  });

  it('should filter out findings in fixture files (contains "fixture" indicator)', () => {
    const findings = [
      makeFinding('src/api/fixture-data.ts'),
      makeFinding('src/api/users/route.ts'),
    ];
    const filtered = filterFalsePositives(findings, emptyIR);

    expect(filtered).toHaveLength(1);
    expect(filtered[0].evidence.file).toBe('src/api/users/route.ts');
  });

  it('should keep all findings when none match FP patterns', () => {
    const findings = [
      makeFinding('src/api/users/route.ts'),
      makeFinding('src/api/posts/route.ts'),
    ];
    const filtered = filterFalsePositives(findings, emptyIR);

    expect(filtered).toHaveLength(2);
  });

  it('should filter out mock files', () => {
    const findings = [
      makeFinding('src/mocks/db.ts'),
      makeFinding('src/api/users/route.ts'),
    ];
    const filtered = filterFalsePositives(findings, emptyIR);

    expect(filtered).toHaveLength(1);
    expect(filtered[0].evidence.file).toBe('src/api/users/route.ts');
  });
});
