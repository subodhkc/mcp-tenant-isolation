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

  it('should reject suppression without documented approver', () => {
    const errors = validateSuppression({
      ruleId: 'DBQ-001',
      fingerprint: 'fp-001',
      reason: 'This is a valid reason for suppression',
      compensatingControls: ['network-isolation'],
      expires: '2027-01-01T00:00:00.000Z',
    });
    expect(errors.some(e => e.includes('documented approver'))).toBe(true);
  });

  it('should reject suppression without compensating controls', () => {
    const errors = validateSuppression({
      ruleId: 'DBQ-001',
      fingerprint: 'fp-001',
      reason: 'This is a valid reason for suppression',
      documentedApprover: 'admin',
      compensatingControls: [],
      expires: '2027-01-01T00:00:00.000Z',
    });
    expect(errors.some(e => e.includes('compensating'))).toBe(true);
  });

  it('should reject invalid expiry date', () => {
    const errors = validateSuppression({
      ruleId: 'DBQ-001',
      fingerprint: 'fp-001',
      reason: 'This is a valid reason for suppression',
      documentedApprover: 'admin',
      compensatingControls: ['network-isolation'],
      expires: 'not-a-date',
    });
    expect(errors.some(e => e.includes('ISO 8601'))).toBe(true);
  });

  it('should reject suppression without fingerprint (rule-wide) when not permanent exception', () => {
    const errors = validateSuppression({
      ruleId: 'DBQ-001',
      reason: 'This is a valid reason for suppression',
      documentedApprover: 'admin',
      compensatingControls: ['network-isolation'],
      expires: '2027-01-01T00:00:00.000Z',
    });
    expect(errors.some(e => e.includes('fingerprint'))).toBe(true);
  });

  it('should reject suppression without ruleId', () => {
    const errors = validateSuppression({
      fingerprint: 'fp-001',
      reason: 'This is a valid reason for suppression',
      documentedApprover: 'admin',
      compensatingControls: ['network-isolation'],
      expires: '2027-01-01T00:00:00.000Z',
    });
    expect(errors.some(e => e.includes('ruleId'))).toBe(true);
  });

  it('should reject suppression without expiry and without permanent exception', () => {
    const errors = validateSuppression({
      ruleId: 'DBQ-001',
      fingerprint: 'fp-001',
      reason: 'This is a valid reason for suppression',
      documentedApprover: 'admin',
      compensatingControls: ['network-isolation'],
    });
    expect(errors.some(e => e.includes('expiry'))).toBe(true);
  });

  it('should reject past expiry date', () => {
    const errors = validateSuppression({
      ruleId: 'DBQ-001',
      fingerprint: 'fp-001',
      reason: 'This is a valid reason for suppression',
      documentedApprover: 'admin',
      compensatingControls: ['network-isolation'],
      expires: '2020-01-01T00:00:00.000Z',
    });
    expect(errors.some(e => e.includes('future'))).toBe(true);
  });

  it('should accept valid suppression with fingerprint, ruleId, and expiry', () => {
    const errors = validateSuppression({
      ruleId: 'DBQ-001',
      fingerprint: 'fp-001',
      reason: 'This is a valid reason for suppression',
      documentedApprover: 'admin',
      compensatingControls: ['network-isolation'],
      expires: '2027-01-01T00:00:00.000Z',
    });
    expect(errors).toHaveLength(0);
  });

  it('should accept permanent exception with justification and no expiry', () => {
    const errors = validateSuppression({
      ruleId: 'DBQ-001',
      reason: 'Permanent exception: this rule is intentionally disabled for global models; no expiry applies.',
      documentedApprover: 'admin',
      compensatingControls: ['network-isolation'],
      permanentException: true,
    });
    expect(errors).toHaveLength(0);
  });

  it('should reject permanent exception that also sets expires', () => {
    const errors = validateSuppression({
      ruleId: 'DBQ-001',
      reason: 'Permanent exception with no expiry applies here.',
      documentedApprover: 'admin',
      compensatingControls: ['network-isolation'],
      permanentException: true,
      expires: '2027-01-01T00:00:00.000Z',
    });
    expect(errors.some(e => e.includes('expires'))).toBe(true);
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

  it('should suppress all findings of a rule by ruleId only when permanent exception', () => {
    const suppressions: SuppressionRule[] = [
      {
        ruleId: 'DBQ-001',
        reason: 'Permanent exception: suppressing all DBQ-001 findings for global models; no expiry applies.',
        documentedApprover: 'admin',
        compensatingControls: ['network-isolation'],
        permanentException: true,
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
