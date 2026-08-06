import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { applySuppressions, validateSuppression } from '../src/engine/suppressions.js';
import type { Finding, SuppressionRule } from '../src/types.js';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'DBQ-001',
    title: 'Missing tenant filter',
    severity: 'HIGH',
    confidence: 0.9,
    description: 'Query lacks tenant filter',
    evidence: {
      file: 'src/api/users/route.ts',
      lineStart: 10,
      lineEnd: 10,
      codeSnippet: 'prisma.findMany({})',
    },
    missingGuards: ['organizationId'],
    presentGuards: [],
    fingerprint: 'fp-001',
    suppressionStatus: 'active',
    ...overrides,
  };
}

describe('Suppression Validation', () => {
  it('should reject suppression without reason', () => {
    const errors = validateSuppression({
      reason: '',
      approvedBy: 'admin',
      compensatingControls: ['network-isolation'],
    });
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some(e => e.includes('reason'))).toBe(true);
  });

  it('should reject suppression with short reason', () => {
    const errors = validateSuppression({
      reason: 'short',
      approvedBy: 'admin',
      compensatingControls: ['network-isolation'],
    });
    expect(errors.some(e => e.includes('reason'))).toBe(true);
  });

  it('should reject suppression without approvedBy', () => {
    const errors = validateSuppression({
      reason: 'This is a valid reason for suppression',
      approvedBy: '',
      compensatingControls: ['network-isolation'],
    });
    expect(errors.some(e => e.includes('approvedBy'))).toBe(true);
  });

  it('should reject suppression without compensating controls', () => {
    const errors = validateSuppression({
      reason: 'This is a valid reason for suppression',
      approvedBy: 'admin',
      compensatingControls: [],
    });
    expect(errors.some(e => e.includes('compensating'))).toBe(true);
  });

  it('should reject invalid expiry date', () => {
    const errors = validateSuppression({
      reason: 'This is a valid reason for suppression',
      approvedBy: 'admin',
      compensatingControls: ['network-isolation'],
      expires: 'not-a-date',
    });
    expect(errors.some(e => e.includes('ISO 8601'))).toBe(true);
  });

  it('should accept valid suppression', () => {
    const errors = validateSuppression({
      reason: 'This is a valid reason for suppression',
      approvedBy: 'admin',
      compensatingControls: ['network-isolation'],
      expires: '2027-01-01T00:00:00.000Z',
    });
    expect(errors).toHaveLength(0);
  });
});

describe('Apply Suppressions', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = join(tmpdir(), `mti-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('should suppress finding by fingerprint match', () => {
    const suppressions: SuppressionRule[] = [
      {
        fingerprint: 'fp-001',
        reason: 'Accepted risk for legacy endpoint',
        approvedBy: 'admin',
        compensatingControls: ['network-isolation'],
      },
    ];
    writeFileSync(
      join(tempDir, '.mti-suppressions.json'),
      JSON.stringify({ suppress: suppressions })
    );

    const findings = [makeFinding()];
    const result = applySuppressions(findings, tempDir);

    expect(result[0].suppressionStatus).toBe('suppressed');
    expect(result[0].suppressionReason).toContain('Accepted risk');
  });

  it('should suppress finding by ruleId + file match', () => {
    const suppressions: SuppressionRule[] = [
      {
        ruleId: 'DBQ-001',
        filePath: 'src/api/users/route.ts',
        reason: 'Accepted risk for this specific endpoint',
        approvedBy: 'admin',
        compensatingControls: ['network-isolation'],
      },
    ];
    writeFileSync(
      join(tempDir, '.mti-suppressions.json'),
      JSON.stringify({ suppress: suppressions })
    );

    const findings = [makeFinding()];
    const result = applySuppressions(findings, tempDir);

    expect(result[0].suppressionStatus).toBe('suppressed');
  });

  it('should suppress all findings of a rule by ruleId only', () => {
    const suppressions: SuppressionRule[] = [
      {
        ruleId: 'DBQ-001',
        reason: 'Suppressing all DBQ-001 findings temporarily',
        approvedBy: 'admin',
        compensatingControls: ['network-isolation'],
      },
    ];
    writeFileSync(
      join(tempDir, '.mti-suppressions.json'),
      JSON.stringify({ suppress: suppressions })
    );

    const findings = [
      makeFinding({ fingerprint: 'fp-001', evidence: { file: 'a.ts', lineStart: 1, lineEnd: 1, codeSnippet: 'x' } }),
      makeFinding({ fingerprint: 'fp-002', evidence: { file: 'b.ts', lineStart: 2, lineEnd: 2, codeSnippet: 'y' } }),
    ];
    const result = applySuppressions(findings, tempDir);

    expect(result.every(f => f.suppressionStatus === 'suppressed')).toBe(true);
  });

  it('should not suppress when no suppressions file exists', () => {
    const findings = [makeFinding()];
    const result = applySuppressions(findings, tempDir);

    expect(result[0].suppressionStatus).toBe('active');
  });

  it('should re-activate expired suppressions', () => {
    const suppressions: SuppressionRule[] = [
      {
        fingerprint: 'fp-001',
        reason: 'Old suppression that has expired',
        approvedBy: 'admin',
        compensatingControls: ['network-isolation'],
        expires: '2020-01-01T00:00:00.000Z',
      },
    ];
    writeFileSync(
      join(tempDir, '.mti-suppressions.json'),
      JSON.stringify({ suppress: suppressions })
    );

    const findings = [makeFinding()];
    const result = applySuppressions(findings, tempDir);

    expect(result[0].suppressionStatus).toBe('active');
  });

  it('should keep active suppression for non-expired entries', () => {
    const suppressions: SuppressionRule[] = [
      {
        fingerprint: 'fp-001',
        reason: 'Active suppression with future expiry',
        approvedBy: 'admin',
        compensatingControls: ['network-isolation'],
        expires: '2099-01-01T00:00:00.000Z',
      },
    ];
    writeFileSync(
      join(tempDir, '.mti-suppressions.json'),
      JSON.stringify({ suppress: suppressions })
    );

    const findings = [makeFinding()];
    const result = applySuppressions(findings, tempDir);

    expect(result[0].suppressionStatus).toBe('suppressed');
    expect(result[0].suppressionExpires).toBe('2099-01-01T00:00:00.000Z');
  });

  it('should not suppress findings that do not match any rule', () => {
    const suppressions: SuppressionRule[] = [
      {
        ruleId: 'DBQ-002',
        reason: 'Suppressing DBQ-002 only',
        approvedBy: 'admin',
        compensatingControls: ['network-isolation'],
      },
    ];
    writeFileSync(
      join(tempDir, '.mti-suppressions.json'),
      JSON.stringify({ suppress: suppressions })
    );

    const findings = [makeFinding({ ruleId: 'DBQ-001' })];
    const result = applySuppressions(findings, tempDir);

    expect(result[0].suppressionStatus).toBe('active');
  });
});
