import { describe, it, expect } from 'vitest';
import { scan } from '../src/engine/scanner.js';
import { join } from 'node:path';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, 'fixtures');

describe('Scanner Integration', () => {
  it('should scan fixtures directory and return results', async () => {
    const result = await scan({ projectRoot: fixturesDir });

    expect(result).toBeDefined();
    expect(result.stats).toBeDefined();
    expect(result.stats.filesScanned).toBeGreaterThan(0);
    expect(result.stats.rulesEvaluated).toBe(57);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('should detect findings in fixture files', async () => {
    const result = await scan({ projectRoot: fixturesDir });

    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some(f => f.ruleId === 'SCH-001')).toBe(true);
    expect(result.findings.some(f => f.ruleId === 'SCH-004')).toBe(true);
  });

  it('should populate bySeverity stats correctly', async () => {
    const result = await scan({ projectRoot: fixturesDir });

    const totalFromSeverity = Object.values(result.stats.bySeverity).reduce((a, b) => a + b, 0);
    expect(totalFromSeverity).toBe(result.stats.totalFindings);
  });

  it('should populate byCategory stats correctly', async () => {
    const result = await scan({ projectRoot: fixturesDir });

    const totalFromCategory = Object.values(result.stats.byCategory).reduce((a, b) => a + b, 0);
    expect(totalFromCategory).toBe(result.stats.totalFindings);
  });

  it('should include parsed files in IR', async () => {
    const result = await scan({ projectRoot: fixturesDir });

    expect(result.ir.files.length).toBeGreaterThan(0);
    const languages = result.ir.files.map(f => f.language);
    expect(languages).toContain('typescript');
    expect(languages).toContain('prisma');
    expect(languages).toContain('sql');
  });

  it('should apply severity filter', async () => {
    const allResults = await scan({ projectRoot: fixturesDir });
    const criticalOnly = await scan({ projectRoot: fixturesDir, severityFilter: 'CRITICAL' });

    expect(criticalOnly.findings.length).toBeLessThanOrEqual(allResults.findings.length);
    expect(criticalOnly.findings.every(f => f.severity === 'CRITICAL')).toBe(true);
  });

  it('should apply rules filter to rule-evaluated findings', async () => {
    const allResults = await scan({ projectRoot: fixturesDir });
    const filtered = await scan({ projectRoot: fixturesDir, rulesFilter: ['SCH-001'] });

    expect(filtered.stats.rulesEvaluated).toBeLessThanOrEqual(allResults.stats.rulesEvaluated);
  });

  it('should return empty findings for empty directory', async () => {
    const result = await scan({ projectRoot: join(fixturesDir, 'empty-nonexistent') });

    expect(result.findings).toHaveLength(0);
    expect(result.stats.filesScanned).toBe(0);
  });

  it('should include fingerprints in findings', async () => {
    const result = await scan({ projectRoot: fixturesDir });

    for (const finding of result.findings) {
      expect(finding.fingerprint).toBeTruthy();
      expect(typeof finding.fingerprint).toBe('string');
    }
  });

  it('should include evidence with file and line numbers', async () => {
    const result = await scan({ projectRoot: fixturesDir });

    for (const finding of result.findings) {
      expect(finding.evidence.file).toBeTruthy();
      expect(finding.evidence.lineStart).toBeGreaterThan(0);
    }
  });

  it('should set rulesTriggered to count of rules that produced findings', async () => {
    const result = await scan({ projectRoot: fixturesDir });

    expect(result.stats.rulesTriggered).toBeGreaterThanOrEqual(0);
 expect(result.stats.rulesTriggered).toBeLessThanOrEqual(57);
  });
});
