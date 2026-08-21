/**
 * Fingerprint v2 and Proof-of-Fix tests (Part 16).
 *
 * Verifies:
 * - v2 fingerprints are stable under line movement
 * - v2 fingerprints are stable under whitespace changes
 * - v2 fingerprints change when code changes
 * - v2 fingerprints change when rule ID changes
 * - v1 fingerprints can be migrated to v2
 * - buildFinding produces fingerprintVersion: 2
 * - Proof-of-fix states: STILL_PRESENT, NEW, NOT_VERIFIABLE
 */
import { describe, it, expect } from 'vitest';
import {
  generateFingerprint,
  generateFingerprintV2,
  migrateFingerprintV1ToV2,
  buildFinding,
  buildEvidence,
} from '../src/rule-spec.js';
import { scan } from '../src/engine/scanner.js';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

describe('Fingerprint v2 (Part 16)', () => {
  it('should be stable under line movement', () => {
    const fp1 = generateFingerprintV2('DBQ-001', 'src/route.ts', 'prisma.user.findMany({})', ['organizationId']);
    const fp2 = generateFingerprintV2('DBQ-001', 'src/route.ts', 'prisma.user.findMany({})', ['organizationId']);
    expect(fp1).toBe(fp2);
    // v1 would differ if line changed; v2 doesn't include line
    const v1a = generateFingerprint('DBQ-001', 'src/route.ts', 10);
    const v1b = generateFingerprint('DBQ-001', 'src/route.ts', 15);
    expect(v1a).not.toBe(v1b); // v1 is line-dependent
  });

  it('should be stable under whitespace changes in code snippet', () => {
    const fp1 = generateFingerprintV2('DBQ-001', 'src/route.ts', 'prisma.user.findMany({})', ['organizationId']);
    const fp2 = generateFingerprintV2('DBQ-001', 'src/route.ts', '  prisma.user.findMany( { } )  ', ['organizationId']);
    expect(fp1).toBe(fp2); // whitespace normalized
  });

  it('should be stable under guard ordering changes', () => {
    const fp1 = generateFingerprintV2('DBQ-001', 'src/route.ts', 'findMany({})', ['organizationId', 'tenantId']);
    const fp2 = generateFingerprintV2('DBQ-001', 'src/route.ts', 'findMany({})', ['tenantId', 'organizationId']);
    expect(fp1).toBe(fp2); // guards sorted before hashing
  });

  it('should change when code snippet changes', () => {
    const fp1 = generateFingerprintV2('DBQ-001', 'src/route.ts', 'prisma.user.findMany({})', ['organizationId']);
    const fp2 = generateFingerprintV2('DBQ-001', 'src/route.ts', 'prisma.user.findUnique({})', ['organizationId']);
    expect(fp1).not.toBe(fp2);
  });

  it('should change when rule ID changes', () => {
    const fp1 = generateFingerprintV2('DBQ-001', 'src/route.ts', 'findMany({})', ['organizationId']);
    const fp2 = generateFingerprintV2('DBQ-002', 'src/route.ts', 'findMany({})', ['organizationId']);
    expect(fp1).not.toBe(fp2);
  });

  it('should change when file path changes', () => {
    const fp1 = generateFingerprintV2('DBQ-001', 'src/route.ts', 'findMany({})', ['organizationId']);
    const fp2 = generateFingerprintV2('DBQ-001', 'src/other.ts', 'findMany({})', ['organizationId']);
    expect(fp1).not.toBe(fp2);
  });

  it('should produce 16-character hex string', () => {
    const fp = generateFingerprintV2('DBQ-001', 'src/route.ts', 'findMany({})', ['organizationId']);
    expect(fp).toMatch(/^[a-f0-9]{16}$/);
  });

  it('should be different from v1 fingerprint', () => {
    const v1 = generateFingerprint('DBQ-001', 'src/route.ts', 10);
    const v2 = generateFingerprintV2('DBQ-001', 'src/route.ts', 'findMany({})', ['organizationId']);
    expect(v1).not.toBe(v2);
  });
});

describe('Fingerprint migration (Part 16)', () => {
  it('should migrate v1 to v2 when details match', () => {
    const ruleId = 'DBQ-001';
    const file = 'src/route.ts';
    const line = 10;
    const snippet = 'findMany({})';
    const guards = ['organizationId'];

    const v1 = generateFingerprint(ruleId, file, line);
    const v2 = migrateFingerprintV1ToV2(v1, ruleId, file, line, snippet, guards);
    const expectedV2 = generateFingerprintV2(ruleId, file, snippet, guards);
    expect(v2).toBe(expectedV2);
  });

  it('should fail closed (return v1) when v1 fingerprint does not match', () => {
    const v1 = 'invalidfingerprint';
    const result = migrateFingerprintV1ToV2(v1, 'DBQ-001', 'src/route.ts', 10, 'findMany({})', ['organizationId']);
    expect(result).toBe(v1); // returns v1 unchanged
  });
});

describe('buildFinding with v2 fingerprint (Part 16)', () => {
  it('should set fingerprintVersion to 2', () => {
    const finding = buildFinding(
      'DBQ-001',
      'Missing tenant filter',
      'HIGH',
      'findMany lacks organizationId',
      buildEvidence('src/route.ts', 10, 10, 'prisma.user.findMany({})'),
      ['organizationId'],
      []
    );
    expect(finding.fingerprintVersion).toBe(2);
    expect(finding.fingerprint).toMatch(/^[a-f0-9]{16}$/);
  });
});

describe('Proof-of-Fix (Part 16)', () => {
  let dir: string;

  it('should set proofOfFix to NOT_VERIFIABLE when no baseline exists', async () => {
    dir = join(tmpdir(), `mti-pof-nobaseline-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(join(dir, 'src'), { recursive: true });
    writeFileSync(
      join(dir, 'src', 'route.ts'),
      `export async function GET(req) {
  const users = await prisma.user.findMany({});
  return Response.json(users);
}
`
    );
    try {
      const result = await scan({ projectRoot: dir });
      // No baseline file → all findings should be NOT_VERIFIABLE
      const findingsWithPof = result.findings.filter(f => f.proofOfFix);
      expect(findingsWithPof.length).toBeGreaterThan(0);
      expect(findingsWithPof.every(f => f.proofOfFix === 'NOT_VERIFIABLE')).toBe(true);
      // Limitations should mention NOT_VERIFIABLE
      expect(result.limitations.some(l => l.includes('NOT_VERIFIABLE'))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('should set proofOfFix to NEW when baseline exists but finding is new', async () => {
    dir = join(tmpdir(), `mti-pof-new-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(join(dir, 'src'), { recursive: true });
    writeFileSync(
      join(dir, 'src', 'route.ts'),
      `export async function GET(req) {
  const users = await prisma.user.findMany({});
  return Response.json(users);
}
`
    );
    // Create an empty baseline (no fingerprints)
    writeFileSync(
      join(dir, '.mti-baseline.json'),
      JSON.stringify({
        version: '1.0.0',
        project: dir,
        createdAt: new Date().toISOString(),
        fingerprints: [],
      })
    );
    try {
      const result = await scan({ projectRoot: dir });
      // Baseline exists but is empty → all findings are NEW
      const findingsWithPof = result.findings.filter(f => f.proofOfFix);
      if (findingsWithPof.length > 0) {
        expect(findingsWithPof.every(f => f.proofOfFix === 'NEW')).toBe(true);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('should set proofOfFix to STILL_PRESENT when finding matches baseline', async () => {
    dir = join(tmpdir(), `mti-pof-still-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(join(dir, 'src'), { recursive: true });
    writeFileSync(
      join(dir, 'src', 'route.ts'),
      `export async function GET(req) {
  const users = await prisma.user.findMany({});
  return Response.json(users);
}
`
    );
    // First scan to get fingerprints
    const firstResult = await scan({ projectRoot: dir });
    // Create baseline with the current fingerprints
    writeFileSync(
      join(dir, '.mti-baseline.json'),
      JSON.stringify({
        version: '1.0.0',
        project: dir,
        createdAt: new Date().toISOString(),
        fingerprints: firstResult.findings.map(f => ({
          fingerprint: f.fingerprint,
          fingerprintVersion: f.fingerprintVersion ?? 2,
          ruleId: f.ruleId,
          severity: f.severity,
          file: f.evidence.file,
          line: f.evidence.lineStart,
        })),
      })
    );
    try {
      // Second scan with baseline present
      const result = await scan({ projectRoot: dir });
      const stillPresent = result.findings.filter(f => f.proofOfFix === 'STILL_PRESENT');
      const newFindings = result.findings.filter(f => f.proofOfFix === 'NEW');
      // Findings that match baseline should be STILL_PRESENT
      expect(stillPresent.length).toBeGreaterThan(0);
      // No new findings since code didn't change
      expect(newFindings.length).toBe(0);
      // Limitations should mention proof-of-fix summary
      expect(result.limitations.some(l => l.includes('still present'))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
