import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync, mkdirSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliPath = join(__dirname, '..', 'dist', 'cli', 'index.js');

function runCli(args: string[], cwd?: string): { stdout: string; stderr: string; exitCode: number } {
  const result = spawnSync('node', [cliPath, ...args], {
    cwd: cwd ?? __dirname,
    encoding: 'utf-8',
    timeout: 30000,
  });
  return {
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    exitCode: result.status ?? 1,
  };
}

function runCliOutput(args: string[], outputFilePath: string, cwd?: string): string {
  runCli([...args, '--output', outputFilePath], cwd);
  if (existsSync(outputFilePath)) {
    return readFileSync(outputFilePath, 'utf-8');
  }
  return '';
}

describe('CLI - rules command', () => {
  it('should list all 57 rules', () => {
    const result = runCli(['rules']);

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('57 rules');
  });

  it('should list rule categories', () => {
    const result = runCli(['rules']);

    expect(result.stdout).toContain('Tenant Context Management');
    expect(result.stdout).toContain('Database Query Isolation');
    expect(result.stdout).toContain('MCP Tool Visibility');
  });
});

describe('CLI - scan command', () => {
  let tempDir: string;
  let outputPath: string;

  beforeEach(() => {
    tempDir = join(tmpdir(), `mti-cli-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    outputPath = join(tempDir, 'results.json');
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('should scan fixtures and exit with code 1 when findings found', () => {
    const fixturesDir = join(__dirname, 'fixtures');
    const result = runCli(['scan', '--path', fixturesDir, '--format', 'terminal']);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toContain('Verdict: FAIL');
  });

  it('should output JSON format when requested', () => {
    const fixturesDir = join(__dirname, 'fixtures');
    const content = runCliOutput(['scan', '--path', fixturesDir, '--format', 'json'], outputPath);

    const parsed = JSON.parse(content);
    expect(parsed.findings).toBeDefined();
    expect(parsed.stats).toBeDefined();
  });

  it('should output SARIF format when requested', () => {
    const fixturesDir = join(__dirname, 'fixtures');
    const sarifOutput = join(tempDir, 'sarif.json');
    const content = runCliOutput(['scan', '--path', fixturesDir, '--format', 'sarif'], sarifOutput);

    const parsed = JSON.parse(content);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs).toBeDefined();
  });

  it('should output AI JSON format when requested', () => {
    const fixturesDir = join(__dirname, 'fixtures');
    const aiOutput = join(tempDir, 'ai.json');
    const content = runCliOutput(['scan', '--path', fixturesDir, '--format', 'ai'], aiOutput);

    const parsed = JSON.parse(content);
    expect(parsed.summary).toBeDefined();
    expect(parsed.summary.verdict).toBeDefined();
  });

  it('should output markdown format when requested', () => {
    const fixturesDir = join(__dirname, 'fixtures');
    const mdOutput = join(tempDir, 'report.md');
    const content = runCliOutput(['scan', '--path', fixturesDir, '--format', 'markdown'], mdOutput);

    expect(content).toContain('# Tenant Isolation Scan Report');
  });

  it('should filter by severity', () => {
    const fixturesDir = join(__dirname, 'fixtures');
    const content = runCliOutput(['scan', '--path', fixturesDir, '--format', 'json', '--severity', 'CRITICAL'], outputPath);

    const parsed = JSON.parse(content);
    expect(parsed.findings.every((f: any) => f.severity === 'CRITICAL')).toBe(true);
  });

  it('should filter by specific rules', () => {
    const fixturesDir = join(__dirname, 'fixtures');
    const content = runCliOutput(['scan', '--path', fixturesDir, '--format', 'json', '--rules', 'SCH-001'], outputPath);

    const parsed = JSON.parse(content);
    expect(parsed.stats.rulesEvaluated).toBeLessThanOrEqual(57);
  });

  it('should write output to file when --output is specified', () => {
    const fixturesDir = join(__dirname, 'fixtures');
    runCli(['scan', '--path', fixturesDir, '--format', 'json', '--output', outputPath]);

    expect(existsSync(outputPath)).toBe(true);
    const content = readFileSync(outputPath, 'utf-8');
    expect(JSON.parse(content).findings).toBeDefined();
  });
});

describe('CLI - init command', () => {
  it('should create .mtirc.json config file', () => {
    const tempDir = join(tmpdir(), `mti-init-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });

    const result = runCli(['init'], tempDir);

    expect(result.exitCode).toBe(0);
    expect(existsSync(join(tempDir, '.mtirc.json'))).toBe(true);

    rmSync(tempDir, { recursive: true, force: true });
  });
});

describe('CLI - version and help', () => {
  it('should show version with --version flag', () => {
    const result = runCli(['--version']);

    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('should show help with --help flag', () => {
    const result = runCli(['--help']);

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('scan');
    expect(result.stdout).toContain('rules');
    expect(result.stdout).toContain('init');
  });
});
