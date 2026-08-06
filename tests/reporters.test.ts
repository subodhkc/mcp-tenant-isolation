import { describe, it, expect } from 'vitest';
import { jsonReporter, sarifReporter, terminalReporter, aiJsonReporter, markdownReporter } from '../src/reporters/index.js';
import type { ScanResult, Finding, IR, ScanStats } from '../src/types.js';
import { RULE_ENGINE_VERSION } from '../src/rules/index.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'DBQ-001',
    title: 'Missing tenant filter on findMany',
    severity: 'HIGH',
    confidence: 0.9,
    description: 'findMany query lacks organizationId in where clause',
    evidence: {
      file: 'src/api/users/route.ts',
      lineStart: 10,
      lineEnd: 10,
      codeSnippet: 'prisma.user.findMany({})',
    },
    missingGuards: ['organizationId'],
    presentGuards: [],
    fingerprint: 'abc123',
    suppressionStatus: 'active',
    ...overrides,
  };
}

function makeScanResult(findings: Finding[] = [makeFinding()]): ScanResult {
  const ir: IR = {
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

  const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 } as ScanStats['bySeverity'];
  const byCategory: Record<string, number> = {};
  for (const f of findings) {
    bySeverity[f.severity]++;
    byCategory['Database Query Isolation'] = (byCategory['Database Query Isolation'] ?? 0) + 1;
  }

  return {
    findings,
    ir,
    stats: {
      totalFindings: findings.length,
      bySeverity,
      byCategory,
      filesScanned: 5,
      rulesEvaluated: 57,
      rulesTriggered: findings.length > 0 ? 1 : 0,
    },
    durationMs: 42,
  };
}

describe('JSON Reporter', () => {
  it('should produce valid JSON with schema version', () => {
    const result = makeScanResult();
    const output = jsonReporter(result);
    const parsed = JSON.parse(output);

    expect(parsed.schema).toBe(`mcp-tenant-isolation/${RULE_ENGINE_VERSION}`);
    expect(parsed.engineVersion).toBe(RULE_ENGINE_VERSION);
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].ruleId).toBe('DBQ-001');
  });

  it('should include stats and duration', () => {
    const result = makeScanResult();
    const parsed = JSON.parse(jsonReporter(result));

    expect(parsed.stats.totalFindings).toBe(1);
    expect(parsed.stats.bySeverity.HIGH).toBe(1);
    expect(parsed.durationMs).toBe(42);
  });

  it('should handle empty findings', () => {
    const result = makeScanResult([]);
    const parsed = JSON.parse(jsonReporter(result));

    expect(parsed.findings).toHaveLength(0);
    expect(parsed.stats.totalFindings).toBe(0);
  });
});

describe('SARIF Reporter', () => {
  it('should produce SARIF 2.1.0 compliant output', () => {
    const result = makeScanResult();
    const output = sarifReporter(result);
    const parsed = JSON.parse(output);

    expect(parsed.version).toBe('2.1.0');
    expect(parsed.$schema).toBe('https://json.schemastore.org/sarif-2.1.0.json');
    expect(parsed.runs).toHaveLength(1);
  });

  it('should include tool driver with name and version', () => {
    const parsed = JSON.parse(sarifReporter(makeScanResult()));

    expect(parsed.runs[0].tool.driver.name).toBe('mcp-tenant-isolation');
    expect(parsed.runs[0].tool.driver.version).toBe(RULE_ENGINE_VERSION);
  });

  it('should include all 57 rules in driver.rules', () => {
    const parsed = JSON.parse(sarifReporter(makeScanResult()));

    expect(parsed.runs[0].tool.driver.rules.length).toBe(57);
  });

  it('should map severity to SARIF levels correctly', () => {
    const criticalResult = makeScanResult([makeFinding({ severity: 'CRITICAL' })]);
    const criticalParsed = JSON.parse(sarifReporter(criticalResult));
    expect(criticalParsed.runs[0].results[0].level).toBe('error');

    const mediumResult = makeScanResult([makeFinding({ severity: 'MEDIUM' })]);
    const mediumParsed = JSON.parse(sarifReporter(mediumResult));
    expect(mediumParsed.runs[0].results[0].level).toBe('warning');

    const lowResult = makeScanResult([makeFinding({ severity: 'LOW' })]);
    const lowParsed = JSON.parse(sarifReporter(lowResult));
    expect(lowParsed.runs[0].results[0].level).toBe('note');
  });

  it('should include location with file and line', () => {
    const parsed = JSON.parse(sarifReporter(makeScanResult()));

    expect(parsed.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('src/api/users/route.ts');
    expect(parsed.runs[0].results[0].locations[0].physicalLocation.region.startLine).toBe(10);
  });

  it('should include fingerprint as partialFingerprints', () => {
    const parsed = JSON.parse(sarifReporter(makeScanResult()));

    expect(parsed.runs[0].results[0].partialFingerprints.primaryLocationLineHash).toBe('abc123');
  });
});

describe('Terminal Reporter', () => {
  it('should show PASS verdict when no critical/high findings', () => {
    const result = makeScanResult([makeFinding({ severity: 'LOW' })]);
    const output = terminalReporter(result);

    expect(output).toContain('Verdict: PASS');
  });

  it('should show FAIL verdict when high findings exist', () => {
    const result = makeScanResult([makeFinding({ severity: 'HIGH' })]);
    const output = terminalReporter(result);

    expect(output).toContain('Verdict: FAIL');
  });

  it('should show PASS verdict when findings are all suppressed', () => {
    const result = makeScanResult([makeFinding({ severity: 'CRITICAL', suppressionStatus: 'suppressed' })]);
    const output = terminalReporter(result);

    expect(output).toContain('Verdict: PASS');
  });

  it('should display file path and line number for findings', () => {
    const output = terminalReporter(makeScanResult());

    expect(output).toContain('src/api/users/route.ts:10');
  });

  it('should display remediation hint', () => {
    const output = terminalReporter(makeScanResult());

    expect(output).toContain('Fix:');
    expect(output).toContain('organizationId');
  });

  it('should display suppressed/baseline section when present', () => {
    const result = makeScanResult([
      makeFinding({ severity: 'LOW' }),
      makeFinding({ severity: 'HIGH', suppressionStatus: 'suppressed', ruleId: 'DBQ-002' }),
    ]);
    const output = terminalReporter(result);

    expect(output).toContain('Suppressed/Baseline');
    expect(output).toContain('[SUPPRESSED]');
  });

  it('should show no issues message when findings empty', () => {
    const output = terminalReporter(makeScanResult([]));

    expect(output).toContain('No tenant isolation issues found.');
  });
});

describe('AI JSON Reporter', () => {
  it('should include remediation hints for findings', () => {
    const parsed = JSON.parse(aiJsonReporter(makeScanResult()));

    expect(parsed.findings[0].remediation).toBeTruthy();
    expect(parsed.findings[0].remediation).toContain('organizationId');
  });

  it('should include rule context for findings', () => {
    const parsed = JSON.parse(aiJsonReporter(makeScanResult()));

    expect(parsed.findings[0].context).toBeTruthy();
    expect(parsed.findings[0].context.length).toBeGreaterThan(10);
  });

  it('should include summary with verdict and counts', () => {
    const parsed = JSON.parse(aiJsonReporter(makeScanResult([makeFinding({ severity: 'HIGH' })])));

    expect(parsed.summary.verdict).toBe('FAIL');
    expect(parsed.summary.activeFindings).toBe(1);
    expect(parsed.summary.suppressedFindings).toBe(0);
  });

  it('should include ruleUrl pointing to haiec.com', () => {
    const parsed = JSON.parse(aiJsonReporter(makeScanResult()));

    expect(parsed.findings[0].ruleUrl).toContain('haiec.com/mcp-tenant-isolation');
  });

  it('should include byRule breakdown', () => {
    const parsed = JSON.parse(aiJsonReporter(makeScanResult([
      makeFinding(),
      makeFinding({ ruleId: 'DBQ-002', fingerprint: 'def456' }),
    ])));

    expect(parsed.summary.byRule['DBQ-001']).toBeDefined();
    expect(parsed.summary.byRule['DBQ-001'].count).toBe(1);
  });
});

describe('Markdown Reporter', () => {
  it('should produce markdown with header and verdict', () => {
    const output = markdownReporter(makeScanResult([makeFinding({ severity: 'HIGH' })]));

    expect(output).toContain('# Tenant Isolation Scan Report');
    expect(output).toContain('**Verdict:** FAIL');
    expect(output).toContain(`v${RULE_ENGINE_VERSION}`);
  });

  it('should include summary table', () => {
    const output = markdownReporter(makeScanResult());

    expect(output).toContain('## Summary');
    expect(output).toContain('| Files scanned | 5 |');
    expect(output).toContain('| Total findings | 1 |');
  });

  it('should group findings by rule', () => {
    const output = markdownReporter(makeScanResult([
      makeFinding(),
      makeFinding({ fingerprint: 'def456', evidence: { file: 'other.ts', lineStart: 5, lineEnd: 5, codeSnippet: 'test' } }),
    ]));

    expect(output).toContain('### DBQ-001');
    expect(output).toContain('(2 findings)');
  });

  it('should include remediation in markdown', () => {
    const output = markdownReporter(makeScanResult());

    expect(output).toContain('**Remediation:**');
  });

  it('should show no issues message when empty', () => {
    const output = markdownReporter(makeScanResult([]));

    expect(output).toContain('No tenant isolation issues found.');
  });

  it('should include link to haiec.com at bottom', () => {
    const output = markdownReporter(makeScanResult());

    expect(output).toContain('haiec.com/mcp-tenant-isolation');
  });
});
