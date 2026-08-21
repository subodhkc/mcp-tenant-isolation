/**
 * Completeness, Coverage, and Structured Output tests (Parts 8-11).
 *
 * Verifies:
 * - COMPLETE completeness when all files parse and all rules evaluate
 * - PARTIAL completeness when parse failures or rule failures occur
 * - Coverage accounting fields are populated correctly
 * - Limitations are reported
 * - Output truncation bounds findings to 20 with correct totals
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { scan } from '../src/engine/scanner.js';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

function makeTempProject(): string {
  const dir = join(tmpdir(), `mti-completeness-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(join(dir, 'src'), { recursive: true });
  // A simple file with a tenant isolation finding (missing tenant filter)
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

function makeProjectWithParseError(): string {
  const dir = makeTempProject();
  // Add a file with completely invalid syntax that babel parser cannot recover from
  writeFileSync(
    join(dir, 'src', 'broken.ts'),
    `export function broken({{{}}} :::;;; ??? +++ @@@ ### $$$`
  );
  return dir;
}

describe('Completeness (Part 9)', () => {
  let dir: string;
  beforeEach(() => { dir = makeTempProject(); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it('should return COMPLETE when all files parse and all rules evaluate', async () => {
    const result = await scan({ projectRoot: dir });
    expect(result.completeness).toBe('COMPLETE');
    expect(result.completenessReasons).toHaveLength(0);
  });

  it('should return PARTIAL when a file fails to parse', async () => {
    const brokenDir = makeProjectWithParseError();
    try {
      const result = await scan({ projectRoot: brokenDir });
      expect(result.completeness).toBe('PARTIAL');
      expect(result.completenessReasons.length).toBeGreaterThan(0);
      expect(result.completenessReasons.some(r => r.includes('failed to parse'))).toBe(true);
    } finally {
      rmSync(brokenDir, { recursive: true, force: true });
    }
  });

  it('should return COMPLETE for an empty project (no files, no failures)', async () => {
    const emptyDir = join(tmpdir(), `mti-empty-${Date.now()}`);
    mkdirSync(emptyDir, { recursive: true });
    try {
      const result = await scan({ projectRoot: emptyDir });
      expect(result.completeness).toBe('COMPLETE');
      expect(result.coverage.filesDiscovered).toBe(0);
      expect(result.coverage.filesParsed).toBe(0);
    } finally {
      rmSync(emptyDir, { recursive: true, force: true });
    }
  });
});

describe('Coverage accounting (Part 10-11)', () => {
  let dir: string;
  beforeEach(() => { dir = makeTempProject(); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it('should populate filesDiscovered and filesParsed', async () => {
    const result = await scan({ projectRoot: dir });
    expect(result.coverage.filesDiscovered).toBeGreaterThan(0);
    expect(result.coverage.filesParsed).toBeGreaterThan(0);
    expect(result.coverage.filesParsed).toBeLessThanOrEqual(result.coverage.filesDiscovered);
  });

  it('should report parseFailures count and details', async () => {
    const brokenDir = makeProjectWithParseError();
    try {
      const result = await scan({ projectRoot: brokenDir });
      expect(result.coverage.parseFailures).toBeGreaterThan(0);
      expect(result.coverage.parseFailureDetails.length).toBeGreaterThan(0);
      expect(result.coverage.parseFailureDetails[0].file).toContain('broken.ts');
      expect(result.coverage.parseFailureDetails[0].error).toBeTruthy();
    } finally {
      rmSync(brokenDir, { recursive: true, force: true });
    }
  });

  it('should populate rulesAvailable, rulesSelected, rulesEvaluated', async () => {
    const result = await scan({ projectRoot: dir });
    expect(result.coverage.rulesAvailable).toBe(57); // 42 general + 15 MCP
    expect(result.coverage.rulesSelected).toBe(57); // no filter
    expect(result.coverage.rulesEvaluated).toBe(57); // all should succeed
    expect(result.coverage.rulesFailed).toBe(0);
  });

  it('should populate rulesTriggered when findings exist', async () => {
    const result = await scan({ projectRoot: dir });
    // The fixture should trigger at least one rule (DBQ-001 or similar)
    expect(result.coverage.rulesTriggered).toBeGreaterThan(0);
  });

  it('should report unsupportedPaths for files with unsupported extensions', async () => {
    // Add a .py file (unsupported) and use a custom config that discovers it
    writeFileSync(join(dir, 'src', 'script.py'), 'print("hello")');
    const result = await scan({
      projectRoot: dir,
      config: {
        paths: {
          include: ['**/*.{ts,tsx,js,jsx,prisma,sql,py}'],
        },
      },
    });
    expect(result.coverage.unsupportedPaths).toBeGreaterThan(0);
  });

  it('should respect rulesFilter in coverage accounting', async () => {
    const result = await scan({
      projectRoot: dir,
      rulesFilter: ['DBQ-001'],
    });
    expect(result.coverage.rulesAvailable).toBe(57);
    expect(result.coverage.rulesSelected).toBe(1);
    expect(result.coverage.rulesEvaluated).toBe(1);
  });
});

describe('Limitations (Part 8)', () => {
  let dir: string;
  beforeEach(() => { dir = makeTempProject(); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it('should always include static-analysis-only limitation', async () => {
    const result = await scan({ projectRoot: dir });
    expect(result.limitations.some(l => l.includes('Static analysis only'))).toBe(true);
  });

  it('should include flow analysis limitation', async () => {
    const result = await scan({ projectRoot: dir });
    expect(result.limitations.some(l => l.includes('Flow analysis'))).toBe(true);
  });
});

describe('Structured output shape (Part 8)', () => {
  let dir: string;
  beforeEach(() => { dir = makeTempProject(); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it('should return ScanResult with all required structured fields', async () => {
    const result = await scan({ projectRoot: dir });
    expect(result).toHaveProperty('completeness');
    expect(result).toHaveProperty('completenessReasons');
    expect(result).toHaveProperty('coverage');
    expect(result).toHaveProperty('limitations');
    expect(result).toHaveProperty('stats');
    expect(result).toHaveProperty('findings');
    expect(result).toHaveProperty('ir');
    expect(result).toHaveProperty('durationMs');
  });

  it('should have coverage with all required accounting fields', async () => {
    const result = await scan({ projectRoot: dir });
    const c = result.coverage;
    expect(c).toHaveProperty('filesDiscovered');
    expect(c).toHaveProperty('filesParsed');
    expect(c).toHaveProperty('parseFailures');
    expect(c).toHaveProperty('parseFailureDetails');
    expect(c).toHaveProperty('excludedPaths');
    expect(c).toHaveProperty('unsupportedPaths');
    expect(c).toHaveProperty('rulesAvailable');
    expect(c).toHaveProperty('rulesSelected');
    expect(c).toHaveProperty('rulesEvaluated');
    expect(c).toHaveProperty('rulesFailed');
    expect(c).toHaveProperty('ruleFailureDetails');
    expect(c).toHaveProperty('rulesTriggered');
  });
});
