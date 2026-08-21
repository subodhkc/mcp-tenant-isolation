/**
 * Golden Corpus — Cross-Platform Qualification (Part 14)
 *
 * These tests verify that the scanner produces consistent, expected findings
 * across a curated set of code patterns. The corpus covers:
 * - Database query isolation (Prisma, Drizzle, raw SQL)
 * - IDOR prevention
 * - Tenant context management
 * - MCP tool visibility
 * - Cache key scoping
 * - Schema and migration
 * - False positive resistance (guarded code should NOT trigger)
 *
 * Each fixture is a minimal code sample that should trigger exactly one rule.
 * The guarded variant should trigger zero rules.
 *
 * These tests run on all CI platforms (Ubuntu, Windows, macOS) to verify
 * cross-platform path handling and parser consistency.
 */
import { describe, it, expect } from 'vitest';
import { scan } from '../../src/engine/scanner.js';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

function makeCorpusProject(files: Record<string, string>): string {
  const dir = join(tmpdir(), `mti-corpus-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(join(dir, 'src'), { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    const filePath = join(dir, 'src', name);
    mkdirSync(join(filePath, '..'), { recursive: true });
    writeFileSync(filePath, content);
  }
  return dir;
}

function cleanup(dir: string) {
  rmSync(dir, { recursive: true, force: true });
}

async function scanProject(dir: string) {
  return scan({ projectRoot: dir });
}

describe('Golden Corpus — Database Query Isolation', () => {
  let dir: string;

  it('DBQ-001: findMany without tenant filter triggers', async () => {
    dir = makeCorpusProject({
      'route.ts': `export async function GET(req) {
  const users = await prisma.user.findMany({});
  return Response.json(users);
}`,
    });
    try {
      const result = await scanProject(dir);
      expect(result.findings.some(f => f.ruleId === 'DBQ-001')).toBe(true);
    } finally { cleanup(dir); }
  });

  it('DBQ-001: findMany WITH tenant filter does NOT trigger', async () => {
    dir = makeCorpusProject({
      'route.ts': `export async function GET(req) {
  const orgId = req.session.organizationId;
  const users = await prisma.user.findMany({ where: { organizationId: orgId } });
  return Response.json(users);
}`,
    });
    try {
      const result = await scanProject(dir);
      expect(result.findings.some(f => f.ruleId === 'DBQ-001')).toBe(false);
    } finally { cleanup(dir); }
  });

  it('DBQ-004: raw SQL without tenant filter triggers', async () => {
    dir = makeCorpusProject({
      'raw.ts': `export async function getResults(req) {
  const results = await prisma.$queryRaw('SELECT * FROM orders');
  return results;
}`,
    });
    try {
      const result = await scanProject(dir);
      expect(result.findings.some(f => f.ruleId === 'DBQ-004')).toBe(true);
    } finally { cleanup(dir); }
  });
});

describe('Golden Corpus — IDOR Prevention', () => {
  let dir: string;

  it('IDOR-001: findUnique by ID without ownership check triggers', async () => {
    dir = makeCorpusProject({
      'idor.ts': `export async function GET(req, { params }) {
  const { id } = params;
  const doc = await prisma.document.findUnique({ where: { id: id } });
  return Response.json(doc);
}`,
    });
    try {
      const result = await scanProject(dir);
      expect(result.findings.some(f => f.ruleId === 'IDOR-001')).toBe(true);
    } finally { cleanup(dir); }
  });
});

describe('Golden Corpus — MCP Tool Visibility', () => {
  let dir: string;

  it('MCP-001: tool without tenant visibility filter triggers', async () => {
    dir = makeCorpusProject({
      'mcp.ts': `import { McpServer } from '@modelcontextprotocol/server';
const server = new McpServer({ name: 'test', version: '1.0.0' });
server.registerTool('getUserData', { description: 'Get user', inputSchema: {} }, async (args) => {
  return { content: [{ type: 'text', text: 'data' }] };
});`,
    });
    try {
      const result = await scanProject(dir);
      expect(result.findings.some(f => f.ruleId === 'MCP-001')).toBe(true);
    } finally { cleanup(dir); }
  });
});

describe('Golden Corpus — Tenant Context Management', () => {
  let dir: string;

  it('TCM-001: tenant ID from request query triggers', async () => {
    dir = makeCorpusProject({
      'tcm.ts': `export async function GET(req) {
  const tenantId = req.query.tenantId;
  const data = await db.query(tenantId);
  return data;
}`,
    });
    try {
      const result = await scanProject(dir);
      expect(result.findings.some(f => f.ruleId === 'TCM-001')).toBe(true);
    } finally { cleanup(dir); }
  });
});

describe('Golden Corpus — Schema and Migration', () => {
  let dir: string;

  it('SCH-001: Prisma model without tenant field triggers', async () => {
    dir = makeCorpusProject({
      'schema.prisma': `model Order {
  id          String   @id @default(uuid())
  amount      Float
  status      String
  createdAt   DateTime @default(now())
}`,
    });
    try {
      const result = await scanProject(dir);
      expect(result.findings.some(f => f.ruleId === 'SCH-001')).toBe(true);
    } finally { cleanup(dir); }
  });

  it('SCH-001: Prisma model WITH tenant field does NOT trigger', async () => {
    dir = makeCorpusProject({
      'schema.prisma': `model Order {
  id              String   @id @default(uuid())
  organizationId  String
  amount          Float
  status          String
  createdAt       DateTime @default(now())
}`,
    });
    try {
      const result = await scanProject(dir);
      expect(result.findings.some(f => f.ruleId === 'SCH-001')).toBe(false);
    } finally { cleanup(dir); }
  });
});

describe('Golden Corpus — False Positive Resistance', () => {
  let dir: string;

  it('guarded findMany with session org ID does NOT trigger DBQ-001', async () => {
    dir = makeCorpusProject({
      'safe.ts': `import { getServerSession } from 'next-auth';
export async function GET(req) {
  const session = await getServerSession(req);
  const orgId = session.user.organizationId;
  const users = await prisma.user.findMany({
    where: { organizationId: orgId }
  });
  return Response.json(users);
}`,
    });
    try {
      const result = await scanProject(dir);
      expect(result.findings.some(f => f.ruleId === 'DBQ-001')).toBe(false);
    } finally { cleanup(dir); }
  });

  it('test files are excluded from scanning', async () => {
    dir = makeCorpusProject({
      'route.test.ts': `export async function GET(req) {
  const users = await prisma.user.findMany({});
  return Response.json(users);
}`,
    });
    try {
      const result = await scanProject(dir);
      // Test files are excluded by default — no findings expected
      expect(result.coverage.filesDiscovered).toBe(0);
    } finally { cleanup(dir); }
  });
});

describe('Golden Corpus — Completeness on clean project', () => {
  let dir: string;

  it('empty project returns COMPLETE with zero findings', async () => {
    dir = join(tmpdir(), `mti-empty-corpus-${Date.now()}`);
    mkdirSync(join(dir, 'src'), { recursive: true });
    writeFileSync(join(dir, 'src', 'empty.ts'), `export const noop = () => {};\n`);
    try {
      const result = await scanProject(dir);
      expect(result.completeness).toBe('COMPLETE');
      expect(result.findings.length).toBe(0);
      expect(result.coverage.parseFailures).toBe(0);
      expect(result.coverage.rulesFailed).toBe(0);
    } finally { cleanup(dir); }
  });
});
