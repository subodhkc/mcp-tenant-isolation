import { describe, it, expect } from 'vitest';
import { parseJsFile } from '../src/parsers/js-parser.js';
import { parsePrismaSchema, findModelsWithoutTenantField } from '../src/parsers/prisma-parser.js';
import { parseSqlMigration, findTablesWithoutRls } from '../src/parsers/sql-parser.js';
import { ALL_RULES, RULE_COUNT, getRuleCategories } from '../src/rules/index.js';
import { TENANT_ISOLATION_GUARDS, hasGuard } from '../src/guards.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const fixturesDir = join(__dirname, 'fixtures');

// ============================================
// RULES TESTS
// ============================================

describe('Rules', () => {
  it('should have exactly 57 rules', () => {
    expect(RULE_COUNT).toBe(57);
  });

  it('should have 42 general rules', () => {
    const generalRules = ALL_RULES.filter((r) => !r.id.startsWith('MCP-'));
    expect(generalRules.length).toBe(42);
  });

  it('should have 15 MCP-specific rules', () => {
    const mcpRules = ALL_RULES.filter((r) => r.id.startsWith('MCP-'));
    expect(mcpRules.length).toBe(15);
  });

  it('all rules should have unique IDs', () => {
    const ids = ALL_RULES.map((r) => r.id);
    const uniqueIds = new Set(ids);
    expect(ids.length).toBe(uniqueIds.size);
  });

  it('all rules should have required fields', () => {
    for (const rule of ALL_RULES) {
      expect(rule.id).toBeTruthy();
      expect(rule.title).toBeTruthy();
      expect(rule.description).toBeTruthy();
      expect(rule.category).toBeTruthy();
      expect(rule.severity).toBeTruthy();
      expect(typeof rule.evaluate).toBe('function');
    }
  });

  it('should have expected categories', () => {
    const categories = getRuleCategories();
    expect(categories).toContain('Tenant Context Management');
    expect(categories).toContain('Database Query Isolation');
    expect(categories).toContain('MCP Tool Visibility');
  });
});

// ============================================
// GUARDS TESTS
// ============================================

describe('Guards', () => {
  it('should detect tenant isolation guards', () => {
    expect(hasGuard('organizationId', TENANT_ISOLATION_GUARDS)).toBe(true);
    expect(hasGuard('tenantId', TENANT_ISOLATION_GUARDS)).toBe(true);
    expect(hasGuard('userId', TENANT_ISOLATION_GUARDS)).toBe(false);
  });

  it('should detect guards in code snippets', () => {
    const code = 'where: { organizationId: session.user.orgId }';
    expect(hasGuard(code, TENANT_ISOLATION_GUARDS)).toBe(true);
  });

  it('should not detect guards in unrelated code', () => {
    const code = 'console.log("hello world")';
    expect(hasGuard(code, TENANT_ISOLATION_GUARDS)).toBe(false);
  });
});

// ============================================
// JS PARSER TESTS
// ============================================

describe('JS Parser', () => {
  it('should parse missing-tenant-filter fixture', () => {
    const code = readFileSync(join(fixturesDir, 'missing-tenant-filter.ts'), 'utf-8');
    const result = parseJsFile(code, 'missing-tenant-filter.ts', '/test');

    expect(result.ir.sinks).toBeDefined();
    expect(result.ir.sinks!.length).toBeGreaterThan(0);

    const dbSinks = result.ir.sinks!.filter((s) => s.kind === 'db_read' || s.kind === 'db_write');
    expect(dbSinks.length).toBeGreaterThan(0);
  });

  it('should parse proper-tenant-filter fixture', () => {
    const code = readFileSync(join(fixturesDir, 'proper-tenant-filter.ts'), 'utf-8');
    const result = parseJsFile(code, 'proper-tenant-filter.ts', '/test');

    expect(result.ir.sinks).toBeDefined();
    expect(result.ir.sources).toBeDefined();
    expect(result.ir.sources!.some((s) => s.kind === 'session')).toBe(true);
  });
});

// ============================================
// PRISMA PARSER TESTS
// ============================================

describe('Prisma Parser', () => {
  it('should parse schema-missing-tenant fixture', () => {
    const code = readFileSync(join(fixturesDir, 'schema-missing-tenant.prisma'), 'utf-8');
    const result = parsePrismaSchema(code, 'schema.prisma', '/test');

    expect(result.models.length).toBe(2);

    const postModel = result.models.find((m) => m.name === 'Post');
    expect(postModel).toBeDefined();
    expect(postModel!.hasTenantField).toBe(false);

    const userModel = result.models.find((m) => m.name === 'User');
    expect(userModel).toBeDefined();
    expect(userModel!.hasTenantField).toBe(true);
  });

  it('should find models without tenant fields', () => {
    const code = readFileSync(join(fixturesDir, 'schema-missing-tenant.prisma'), 'utf-8');
    const result = parsePrismaSchema(code, 'schema.prisma', '/test');
    const withoutTenant = findModelsWithoutTenantField(result.models);

    expect(withoutTenant.length).toBe(1);
    expect(withoutTenant[0].name).toBe('Post');
  });
});

// ============================================
// SQL PARSER TESTS
// ============================================

describe('SQL Parser', () => {
  it('should parse missing-rls fixture', () => {
    const code = readFileSync(join(fixturesDir, 'missing-rls.sql'), 'utf-8');
    const result = parseSqlMigration(code, 'migration.sql', '/test');

    expect(result.tables.length).toBe(1);
    expect(result.tables[0].name).toBe('posts');
    expect(result.tables[0].hasTenantColumn).toBe(true);
    expect(result.rlsEnabledTables.length).toBe(0);
  });

  it('should find tables without RLS', () => {
    const code = readFileSync(join(fixturesDir, 'missing-rls.sql'), 'utf-8');
    const result = parseSqlMigration(code, 'migration.sql', '/test');
    const withoutRls = findTablesWithoutRls(result.tables, result.rlsEnabledTables);

    expect(withoutRls.length).toBe(1);
    expect(withoutRls[0].name).toBe('posts');
  });
});
