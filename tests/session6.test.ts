/**
 * Concern Families, Scan Receipt, Evidence Envelope, and Rulepack Security tests
 * (Parts 12, 17-20, 22-23).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { scan } from '../src/engine/scanner.js';
import { aggregateConcernFamilies, getConcernFamily } from '../src/engine/concern-families.js';
import { computeRulepackDigest, buildScanReceipt, buildEvidenceEnvelope, computeVerdict } from '../src/engine/receipt.js';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ALL_RULES, getRuleById } from '../src/rules/index.js';
import type { Finding, ScanResult, Severity } from '../src/types.js';

function makeFinding(ruleId: string, severity: Severity, file: string): Finding {
  return {
    ruleId,
    title: 'Test finding',
    severity,
    confidence: 0.9,
    description: 'Test',
    evidence: { file, lineStart: 1, lineEnd: 1, codeSnippet: 'test' },
    missingGuards: ['tenantId'],
    presentGuards: [],
    fingerprint: 'abc123',
    fingerprintVersion: 2,
    suppressionStatus: 'active',
  };
}

function makeTempProject(): string {
  const dir = join(tmpdir(), `mti-s6-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(join(dir, 'src'), { recursive: true });
  writeFileSync(
    join(dir, 'src', 'route.ts'),
    `export async function GET(req) {
  const users = await prisma.user.findMany({});
  return Response.json(users);
}
`
  );
  return dir;
}

describe('Concern Families (Part 12)', () => {
  it('should map known categories to correct families', () => {
    expect(getConcernFamily('Tenant Context Management')).toBe('Tenant Context');
    expect(getConcernFamily('Database Query Isolation')).toBe('Data Isolation');
    expect(getConcernFamily('IDOR Prevention')).toBe('Data Isolation');
    expect(getConcernFamily('MCP Tool Visibility')).toBe('MCP Security');
    expect(getConcernFamily('MCP Token Security')).toBe('Secrets & Credentials');
    expect(getConcernFamily('MCP Vector Store')).toBe('Vector & Storage');
    expect(getConcernFamily('API Security')).toBe('API & Access');
    expect(getConcernFamily('Logging & Audit')).toBe('Audit & Logging');
  });

  it('should default unknown categories to Audit & Logging', () => {
    expect(getConcernFamily('Unknown Category')).toBe('Audit & Logging');
  });

  it('should aggregate findings by concern family', () => {
    const findings: Finding[] = [
      makeFinding('DBQ-001', 'HIGH', 'src/a.ts'),
      makeFinding('DBQ-002', 'MEDIUM', 'src/b.ts'),
      makeFinding('MCP-001', 'CRITICAL', 'src/mcp.ts'),
      makeFinding('IDOR-001', 'HIGH', 'src/c.ts'),
    ];
    const families = aggregateConcernFamilies(findings, (id) => getRuleById(id)?.category);
    expect(families.length).toBeGreaterThan(0);
    // DBQ-001, DBQ-002, IDOR-001 all map to Data Isolation
    const dataIsolation = families.find(f => f.family === 'Data Isolation');
    expect(dataIsolation).toBeDefined();
    expect(dataIsolation!.totalFindings).toBe(3);
    expect(dataIsolation!.activeFindings).toBe(3);
    expect(dataIsolation!.ruleIds).toContain('DBQ-001');
    expect(dataIsolation!.ruleIds).toContain('IDOR-001');
    // MCP-001 maps to MCP Security
    const mcpSecurity = families.find(f => f.family === 'MCP Security');
    expect(mcpSecurity).toBeDefined();
    expect(mcpSecurity!.totalFindings).toBe(1);
  });

  it('should count suppressed findings separately', () => {
    const findings: Finding[] = [
      { ...makeFinding('DBQ-001', 'HIGH', 'src/a.ts'), suppressionStatus: 'suppressed' },
      makeFinding('DBQ-002', 'MEDIUM', 'src/b.ts'),
    ];
    const families = aggregateConcernFamilies(findings, (id) => getRuleById(id)?.category);
    const dataIsolation = families.find(f => f.family === 'Data Isolation');
    expect(dataIsolation!.totalFindings).toBe(2);
    expect(dataIsolation!.activeFindings).toBe(1);
    expect(dataIsolation!.suppressedFindings).toBe(1);
  });

  it('should sort by total findings descending', () => {
    const findings: Finding[] = [
      makeFinding('MCP-001', 'CRITICAL', 'src/mcp.ts'),
      makeFinding('DBQ-001', 'HIGH', 'src/a.ts'),
      makeFinding('DBQ-002', 'MEDIUM', 'src/b.ts'),
    ];
    const families = aggregateConcernFamilies(findings, (id) => getRuleById(id)?.category);
    expect(families[0].totalFindings).toBeGreaterThanOrEqual(families[1].totalFindings);
  });

  it('should populate concernFamilies in scan result', async () => {
    const dir = makeTempProject();
    try {
      const result = await scan({ projectRoot: dir });
      expect(result.concernFamilies).toBeDefined();
      expect(result.concernFamilies!.length).toBeGreaterThan(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('Rulepack Digest (Part 22)', () => {
  it('should produce a deterministic 32-char hex digest', () => {
    const rules = ALL_RULES.map(r => ({ id: r.id, version: r.version, executionOrder: r.executionOrder }));
    const digest1 = computeRulepackDigest(rules);
    const digest2 = computeRulepackDigest(rules);
    expect(digest1).toBe(digest2);
    expect(digest1).toMatch(/^[a-f0-9]{32}$/);
  });

  it('should change when rules are added or removed', () => {
    const rules = ALL_RULES.map(r => ({ id: r.id, version: r.version, executionOrder: r.executionOrder }));
    const digest1 = computeRulepackDigest(rules);
    const digest2 = computeRulepackDigest(rules.slice(0, -1));
    expect(digest1).not.toBe(digest2);
  });

  it('should be order-independent (sorted by ID)', () => {
    const rules = ALL_RULES.map(r => ({ id: r.id, version: r.version, executionOrder: r.executionOrder }));
    const shuffled = [...rules].reverse();
    const digest1 = computeRulepackDigest(rules);
    const digest2 = computeRulepackDigest(shuffled);
    expect(digest1).toBe(digest2);
  });
});

describe('Scan Receipt (Parts 17-18)', () => {
  it('should populate receipt in scan result', async () => {
    const dir = makeTempProject();
    try {
      const result = await scan({ projectRoot: dir });
      expect(result.receipt).toBeDefined();
      expect(result.receipt!.schemaVersion).toBe('1.0.0');
      expect(result.receipt!.producerId).toBe('io.github.subodhkc/mcp-tenant-isolation');
      expect(result.receipt!.engineVersion).toBeTruthy();
      expect(result.receipt!.timestamp).toBeTruthy();
      expect(result.receipt!.projectRoot).toBe(dir);
      expect(result.receipt!.durationMs).toBeGreaterThanOrEqual(0);
      expect(result.receipt!.completeness).toBe('COMPLETE');
      expect(result.receipt!.verdict).toBeTruthy();
      expect(result.receipt!.rulepackDigest).toMatch(/^[a-f0-9]{32}$/);
      expect(result.receipt!.rulesAvailable).toBe(57);
      expect(result.receipt!.rulesSelected).toBe(57);
      expect(result.receipt!.receiptHash).toMatch(/^[a-f0-9]{32}$/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('should compute verdict correctly', async () => {
    const dir = makeTempProject();
    try {
      const result = await scan({ projectRoot: dir });
      // The fixture triggers DBQ-001 (HIGH) → verdict should be BLOCK
      expect(result.receipt!.verdict).toBe('BLOCK');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('should produce deterministic receipt hash for same input', () => {
    const baseResult: ScanResult = {
      findings: [],
      ir: { projectRoot: '/test', scanTimestamp: '2026-01-01T00:00:00.000Z', entrypoints: [], sources: [], sinks: [], assignments: [], authSignals: [], tenantScopes: [], mcpTools: [], mcpSessions: [], mcpCredentialVaults: [], mcpResources: [], mcpCacheEntries: [], files: [] },
      stats: { totalFindings: 0, bySeverity: { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }, byCategory: {}, filesScanned: 0, rulesEvaluated: 0, rulesTriggered: 0 },
      durationMs: 42,
      completeness: 'COMPLETE',
      completenessReasons: [],
      coverage: { filesDiscovered: 0, filesParsed: 0, parseFailures: 0, parseFailureDetails: [], excludedPaths: 0, unsupportedPaths: 0, rulesAvailable: 57, rulesSelected: 57, rulesEvaluated: 57, rulesFailed: 0, ruleFailureDetails: [], rulesTriggered: 0 },
      limitations: [],
    };
    const r1 = buildScanReceipt(baseResult, '/test', 'abcd1234');
    const r2 = buildScanReceipt(baseResult, '/test', 'abcd1234');
    expect(r1.receiptHash).toBe(r2.receiptHash);
  });
});

describe('Evidence Envelope (Parts 19-20)', () => {
  it('should build a complete envelope from scan result', async () => {
    const dir = makeTempProject();
    try {
      const result = await scan({ projectRoot: dir });
      const envelope = buildEvidenceEnvelope(
        result,
        dir,
        result.receipt!.rulepackDigest,
        result.concernFamilies ?? []
      );
      expect(envelope.schemaVersion).toBe('1.0.0');
      expect(envelope.producerId).toBe('io.github.subodhkc/mcp-tenant-isolation');
      expect(envelope.receipt).toBeDefined();
      expect(envelope.concernFamilies).toBeDefined();
      expect(envelope.findings).toBeDefined();
      expect(envelope.truncation).toBeDefined();
      expect(envelope.coverage).toBeDefined();
      expect(envelope.completenessReasons).toBeDefined();
      expect(envelope.limitations).toBeDefined();
      expect(envelope.envelopeHash).toMatch(/^[a-f0-9]{32}$/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('should bound findings to the specified limit', async () => {
    const dir = makeTempProject();
    try {
      const result = await scan({ projectRoot: dir });
      const envelope = buildEvidenceEnvelope(
        result,
        dir,
        result.receipt!.rulepackDigest,
        result.concernFamilies ?? [],
        2 // bound to 2 findings
      );
      expect(envelope.findings.length).toBeLessThanOrEqual(2);
      expect(envelope.truncation.truncated).toBe(result.findings.length > 2);
      expect(envelope.truncation.findingsTotal).toBe(result.findings.length);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('should produce deterministic envelope hash for same input', async () => {
    const dir = makeTempProject();
    try {
      const result = await scan({ projectRoot: dir });
      const e1 = buildEvidenceEnvelope(result, dir, result.receipt!.rulepackDigest, result.concernFamilies ?? []);
      const e2 = buildEvidenceEnvelope(result, dir, result.receipt!.rulepackDigest, result.concernFamilies ?? []);
      expect(e1.envelopeHash).toBe(e2.envelopeHash);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('Custom Rulepack Security (Part 23)', () => {
  it('should reject rulepack with invalid rule ID format', async () => {
    const dir = makeTempProject();
    // Create a rulepack with an invalid ID
    writeFileSync(
      join(dir, 'bad-rulepack.json'),
      JSON.stringify({
        rules: [{
          id: 'invalid',
          category: 'Custom',
          title: 'Bad rule',
          description: 'Test',
          severity: 'HIGH',
          requiredGuards: ['tenantId'],
        }],
      })
    );
    try {
      const result = await scan({
        projectRoot: dir,
        config: { rulePacks: ['bad-rulepack.json'] },
      });
      // The invalid rule should not be loaded
      expect(result.coverage.rulesAvailable).toBe(57); // only built-in rules
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('should reject rule that collides with built-in rule ID', async () => {
    const dir = makeTempProject();
    writeFileSync(
      join(dir, 'collision-rulepack.json'),
      JSON.stringify({
        rules: [{
          id: 'DBQ-001', // collides with built-in
          category: 'Custom',
          title: 'Collision',
          description: 'Test',
          severity: 'HIGH',
          requiredGuards: ['tenantId'],
        }],
      })
    );
    try {
      const result = await scan({
        projectRoot: dir,
        config: { rulePacks: ['collision-rulepack.json'] },
      });
      expect(result.coverage.rulesAvailable).toBe(57); // collision rejected
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('should reject rule with invalid severity', async () => {
    const dir = makeTempProject();
    writeFileSync(
      join(dir, 'bad-severity.json'),
      JSON.stringify({
        rules: [{
          id: 'CUST-001',
          category: 'Custom',
          title: 'Bad severity',
          description: 'Test',
          severity: 'ULTRA',
          requiredGuards: ['tenantId'],
        }],
      })
    );
    try {
      const result = await scan({
        projectRoot: dir,
        config: { rulePacks: ['bad-severity.json'] },
      });
      expect(result.coverage.rulesAvailable).toBe(57);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('should accept a valid custom rulepack', async () => {
    const dir = makeTempProject();
    writeFileSync(
      join(dir, 'good-rulepack.json'),
      JSON.stringify({
        rules: [{
          id: 'CUST-001',
          category: 'Custom',
          title: 'Valid custom rule',
          description: 'Detects custom pattern',
          severity: 'HIGH',
          requiredGuards: ['tenantId'],
          sinkKinds: ['db_read'],
          filePatterns: ['/api/'],
        }],
      })
    );
    try {
      const result = await scan({
        projectRoot: dir,
        config: { rulePacks: ['good-rulepack.json'] },
      });
      expect(result.coverage.rulesAvailable).toBe(58); // 57 built-in + 1 custom
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
