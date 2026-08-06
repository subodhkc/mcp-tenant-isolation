import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadRulePacks } from '../src/engine/rule-pack-loader.js';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

describe('Rule Pack Loader', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = join(tmpdir(), `mti-rpack-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('should return empty array when no packs specified', async () => {
    const rules = await loadRulePacks(tempDir);
    expect(rules).toHaveLength(0);
  });

  it('should return empty array when packPaths is empty', async () => {
    const rules = await loadRulePacks(tempDir, []);
    expect(rules).toHaveLength(0);
  });

  it('should load a custom rule pack from JSON file', async () => {
    const packPath = 'custom-rules.json';
    writeFileSync(
      join(tempDir, packPath),
      JSON.stringify({
        rules: [
          {
            id: 'CUSTOM-001',
            category: 'Custom',
            title: 'Custom tenant check',
            description: 'Detects custom tenant isolation issue',
            severity: 'HIGH',
            requiredGuards: ['organizationId'],
            cweIds: ['CWE-639'],
            sinkKinds: ['db_read'],
            filePatterns: ['/api/'],
          },
        ],
      })
    );

    const rules = await loadRulePacks(tempDir, [packPath]);

    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe('CUSTOM-001');
    expect(rules[0].title).toBe('Custom tenant check');
    expect(rules[0].severity).toBe('HIGH');
  });

  it('should load multiple rule packs', async () => {
    writeFileSync(
      join(tempDir, 'pack1.json'),
      JSON.stringify({
        rules: [
          {
            id: 'CUSTOM-001',
            category: 'Custom',
            title: 'Rule 1',
            description: 'Desc 1',
            severity: 'HIGH',
            requiredGuards: ['organizationId'],
          },
        ],
      })
    );
    writeFileSync(
      join(tempDir, 'pack2.json'),
      JSON.stringify({
        rules: [
          {
            id: 'CUSTOM-002',
            category: 'Custom',
            title: 'Rule 2',
            description: 'Desc 2',
            severity: 'MEDIUM',
            requiredGuards: ['tenantId'],
          },
        ],
      })
    );

    const rules = await loadRulePacks(tempDir, ['pack1.json', 'pack2.json']);

    expect(rules).toHaveLength(2);
    expect(rules.map(r => r.id)).toContain('CUSTOM-001');
    expect(rules.map(r => r.id)).toContain('CUSTOM-002');
  });

  it('should warn and skip non-existent pack file', async () => {
    const rules = await loadRulePacks(tempDir, ['nonexistent.json']);

    expect(rules).toHaveLength(0);
  });

  it('should warn and skip invalid JSON pack file', async () => {
    writeFileSync(join(tempDir, 'bad.json'), '{ invalid json }');

    const rules = await loadRulePacks(tempDir, ['bad.json']);

    expect(rules).toHaveLength(0);
  });

  it('should set default executionOrder when not specified', async () => {
    writeFileSync(
      join(tempDir, 'pack.json'),
      JSON.stringify({
        rules: [
          {
            id: 'CUSTOM-001',
            category: 'Custom',
            title: 'Test',
            description: 'Test',
            severity: 'HIGH',
            requiredGuards: ['organizationId'],
          },
        ],
      })
    );

    const rules = await loadRulePacks(tempDir, ['pack.json']);

    expect(rules[0].executionOrder).toBe(200);
  });

  it('should set default suppressible to true when not specified', async () => {
    writeFileSync(
      join(tempDir, 'pack.json'),
      JSON.stringify({
        rules: [
          {
            id: 'CUSTOM-001',
            category: 'Custom',
            title: 'Test',
            description: 'Test',
            severity: 'HIGH',
            requiredGuards: ['organizationId'],
          },
        ],
      })
    );

    const rules = await loadRulePacks(tempDir, ['pack.json']);

    expect(rules[0].suppressible).toBe(true);
  });

  it('should use custom executionOrder when specified', async () => {
    writeFileSync(
      join(tempDir, 'pack.json'),
      JSON.stringify({
        rules: [
          {
            id: 'CUSTOM-001',
            category: 'Custom',
            title: 'Test',
            description: 'Test',
            severity: 'HIGH',
            requiredGuards: ['organizationId'],
            executionOrder: 50,
          },
        ],
      })
    );

    const rules = await loadRulePacks(tempDir, ['pack.json']);

    expect(rules[0].executionOrder).toBe(50);
  });
});
