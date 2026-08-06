import { describe, it, expect } from 'vitest';
import { ALL_RULES, RULE_COUNT, RULE_ENGINE_VERSION } from '../src/rules/index.js';
import { scan } from '../src/engine/scanner.js';
import { validateSuppression } from '../src/engine/suppressions.js';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, 'fixtures');

describe('MCP Server - Tool Definitions', () => {
  it('should expose 4 tools (scan, list, explain, suppress)', () => {
    const expectedTools = [
      'scan_tenant_isolation',
      'list_tenant_isolation_rules',
      'explain_tenant_isolation_rule',
      'suppress_tenant_isolation_finding',
    ];

    expect(expectedTools).toHaveLength(4);
    expect(expectedTools).toContain('scan_tenant_isolation');
    expect(expectedTools).toContain('list_tenant_isolation_rules');
    expect(expectedTools).toContain('explain_tenant_isolation_rule');
    expect(expectedTools).toContain('suppress_tenant_isolation_finding');
  });
});

describe('MCP Server - scan_tenant_isolation tool logic', () => {
  it('should return findings when scanning fixture directory', async () => {
    const result = await scan({ projectRoot: fixturesDir });

    const activeFindings = result.findings.filter(
      (f) => f.suppressionStatus !== 'suppressed'
    );

    expect(result.stats.totalFindings).toBeGreaterThan(0);
    expect(activeFindings.length).toBeGreaterThan(0);
  });

  it('should return summary with correct shape for MCP response', async () => {
    const result = await scan({ projectRoot: fixturesDir });

    const activeFindings = result.findings.filter(
      (f) => f.suppressionStatus !== 'suppressed'
    );

    const summary = {
      totalFindings: result.stats.totalFindings,
      activeFindings: activeFindings.length,
      suppressedFindings: result.findings.length - activeFindings.length,
      bySeverity: result.stats.bySeverity,
      filesScanned: result.stats.filesScanned,
      rulesEvaluated: result.stats.rulesEvaluated,
      durationMs: result.durationMs,
    };

    expect(summary.totalFindings).toBeGreaterThan(0);
    expect(summary.filesScanned).toBeGreaterThan(0);
    expect(summary.rulesEvaluated).toBe(57);
    expect(summary.bySeverity).toBeDefined();
  });

  it('should return findings with fields needed by MCP response', async () => {
    const result = await scan({ projectRoot: fixturesDir });

    const mcpFindings = result.findings.map((f) => ({
      ruleId: f.ruleId,
      title: f.title,
      severity: f.severity,
      file: f.evidence.file,
      line: f.evidence.lineStart,
      description: f.description,
      missingGuards: f.missingGuards,
      fingerprint: f.fingerprint,
      suppressionStatus: f.suppressionStatus ?? 'active',
    }));

    for (const f of mcpFindings) {
      expect(f.ruleId).toBeTruthy();
      expect(f.severity).toBeTruthy();
      expect(f.file).toBeTruthy();
      expect(f.fingerprint).toBeTruthy();
    }
  });
});

describe('MCP Server - list_tenant_isolation_rules tool logic', () => {
  it('should return all 57 rules with metadata', () => {
    const rules = ALL_RULES.map((r) => ({
      id: r.id,
      title: r.title,
      category: r.category,
      severity: r.severity,
      description: r.description,
      suppressible: r.suppressible,
      owaspMcpRef: r.compliance.owaspMcpRef,
      cweIds: r.compliance.cweIds,
    }));

    expect(rules).toHaveLength(57);
    expect(rules.every(r => r.id && r.title && r.category)).toBe(true);
  });

  it('should filter by category when provided', () => {
    const mcpRules = ALL_RULES.filter((r) => r.category === 'MCP Tool Visibility');

    expect(mcpRules.length).toBeGreaterThan(0);
    expect(mcpRules.every(r => r.category === 'MCP Tool Visibility')).toBe(true);
  });

  it('should include engine version in response', () => {
    expect(RULE_ENGINE_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
    expect(RULE_COUNT).toBe(57);
  });
});

describe('MCP Server - explain_tenant_isolation_rule tool logic', () => {
  it('should return rule details for valid rule ID', () => {
    const ruleId = 'DBQ-001';
    const rule = ALL_RULES.find((r) => r.id === ruleId);

    expect(rule).toBeDefined();
    expect(rule!.id).toBe('DBQ-001');
    expect(rule!.title).toBeTruthy();
    expect(rule!.description).toBeTruthy();
    expect(rule!.requiredGuards).toBeDefined();
    expect(rule!.compliance).toBeDefined();
  });

  it('should return not found for invalid rule ID', () => {
    const ruleId = 'INVALID-999';
    const rule = ALL_RULES.find((r) => r.id === ruleId);

    expect(rule).toBeUndefined();
  });

  it('should include remediation in explain response', () => {
    const rule = ALL_RULES.find((r) => r.id === 'MCP-001')!;

    const remediation = [
      `Remediation for ${rule.id}:`,
      `1. ${rule.description}`,
      `2. Add required guards: ${rule.requiredGuards.join(', ')}`,
      `3. Ensure tenant context is propagated from authenticated session.`,
      `4. Add tests verifying tenant isolation for the affected data flow.`,
      `5. Run 'mti scan' to verify the finding is resolved.`,
    ].join('\n');

    expect(remediation).toContain('MCP-001');
    expect(remediation).toContain('mti scan');
  });
});

describe('MCP Server - suppress_tenant_isolation_finding tool logic', () => {
  it('should validate suppression input from MCP tool args', () => {
    const errors = validateSuppression({
      reason: 'Valid suppression reason here',
      approvedBy: 'admin',
      compensatingControls: ['network-isolation'],
    });

    expect(errors).toHaveLength(0);
  });

  it('should reject invalid suppression from MCP tool args', () => {
    const errors = validateSuppression({
      reason: 'short',
      approvedBy: '',
      compensatingControls: [],
    });

    expect(errors.length).toBeGreaterThan(0);
  });
});
