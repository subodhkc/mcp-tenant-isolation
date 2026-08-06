/**
 * SQL Migration Parser
 *
 * Parses SQL migration files to detect:
 * - CREATE TABLE without tenant columns
 * - Missing ENABLE ROW LEVEL SECURITY
 * - RLS policies with USING(true) or WITH CHECK(true)
 * - Missing indexes on tenant columns
 */

import type { ParsedFile, Location } from '../types.js';
import { TENANT_ISOLATION_GUARDS } from '../guards.js';


export interface SqlTable {
  name: string;
  columns: string[];
  hasTenantColumn: boolean;
  tenantColumnName?: string;
  location: Location;
}

export interface SqlRlsPolicy {
  tableName: string;
  policyName: string;
  using: string;
  withCheck: string;
  isBypassed: boolean;
  location: Location;
}

export interface SqlIndex {
  tableName: string;
  columns: string[];
  hasTenantFirst: boolean;
  location: Location;
}

export interface SqlParseResult {
  tables: SqlTable[];
  rlsEnabledTables: string[];
  rlsPolicies: SqlRlsPolicy[];
  indexes: SqlIndex[];
  file: ParsedFile;
}


export function parseSqlMigration(
  sourceCode: string,
  filename: string,
  projectRoot: string
): SqlParseResult {
  const startTime = Date.now();
  const lines = sourceCode.split('\n');
  const relativePath = filename.replace(projectRoot, '').replace(/^\//, '');

  const tables: SqlTable[] = [];
  const rlsEnabledTables: string[] = [];
  const rlsPolicies: SqlRlsPolicy[] = [];
  const indexes: SqlIndex[] = [];

  let currentTable: SqlTable | null = null;
  let inCreateTable = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const lineNum = i + 1;

    // Skip comment lines
    if (line.startsWith('--')) continue;

    // Detect CREATE TABLE
    const createMatch = line.match(/create\s+table\s+(?:if\s+not\s+exists\s+)?["`?]?(\w+)["`]?/i);
    if (createMatch) {
      currentTable = {
        name: createMatch[1],
        columns: [],
        hasTenantColumn: false,
        location: { file: relativePath, line: lineNum, column: 0 },
      };
      inCreateTable = true;
      continue;
    }

    // End of CREATE TABLE
    if (inCreateTable && line.includes(');')) {
      if (currentTable) {
        const tenantCol = currentTable.columns.find((c) =>
          TENANT_ISOLATION_GUARDS.some((g) =>
            c.toLowerCase().replace(/_/g, '').includes(g.toLowerCase().replace(/_/g, ''))
          )
        );
        currentTable.hasTenantColumn = !!tenantCol;
        currentTable.tenantColumnName = tenantCol;
        tables.push(currentTable);
      }
      currentTable = null;
      inCreateTable = false;
      continue;
    }

    // Parse columns inside CREATE TABLE
    if (inCreateTable && currentTable) {
      const colMatch = line.match(/^\s*["`]?(\w+)["`]?\s+/);
      if (colMatch && !colMatch[1].toLowerCase().startsWith('constraint') &&
          !colMatch[1].toLowerCase().startsWith('primary') &&
          !colMatch[1].toLowerCase().startsWith('foreign') &&
          !colMatch[1].toLowerCase().startsWith('unique') &&
          !colMatch[1].toLowerCase().startsWith('check')) {
        currentTable.columns.push(colMatch[1]);
      }
      continue;
    }

    // Detect ENABLE ROW LEVEL SECURITY
    const rlsMatch = line.match(/alter\s+table\s+["`]?(\w+)["`]?\s+enable\s+row\s+level\s+security/i);
    if (rlsMatch) {
      rlsEnabledTables.push(rlsMatch[1]);
      continue;
    }

    // Detect CREATE POLICY
    const policyMatch = line.match(
      /create\s+policy\s+["`]?(\w+)["`]?\s+on\s+["`]?(\w+)["`]?\s+(?:for\s+\w+\s+)?(?:to\s+\w+\s+)?using\s*\(([^)]+)\)/i
    );
    if (policyMatch) {
      const using = policyMatch[3].trim();
      const isBypassed = using.toLowerCase() === 'true' || using === '1';
      // Check for WITH CHECK on same or next line
      let withCheck = '';
      const withCheckMatch = line.match(/with\s+check\s*\(([^)]+)\)/i);
      if (withCheckMatch) {
        withCheck = withCheckMatch[1].trim();
      } else if (i + 1 < lines.length) {
        const nextLineWithCheck = lines[i + 1].match(/with\s+check\s*\(([^)]+)\)/i);
        if (nextLineWithCheck) {
          withCheck = nextLineWithCheck[1].trim();
        }
      }
      const isWithCheckBypassed = withCheck.toLowerCase() === 'true' || withCheck === '1';

      rlsPolicies.push({
        tableName: policyMatch[2],
        policyName: policyMatch[1],
        using,
        withCheck,
        isBypassed: isBypassed || isWithCheckBypassed,
        location: { file: relativePath, line: lineNum, column: 0 },
      });
      continue;
    }

    // Detect CREATE INDEX
    const indexMatch = line.match(
      /create\s+(?:unique\s+)?index\s+["`]?(\w+)["`]?\s+on\s+["`]?(\w+)["`]?\s*\(([^)]+)\)/i
    );
    if (indexMatch) {
      const columns = indexMatch[3].split(',').map((c) => c.trim().replace(/["`]/g, ''));
      const hasTenantFirst = columns.length > 0 &&
        TENANT_ISOLATION_GUARDS.some((g) =>
          columns[0].toLowerCase().replace(/_/g, '').includes(g.toLowerCase().replace(/_/g, ''))
        );
      indexes.push({
        tableName: indexMatch[2],
        columns,
        hasTenantFirst,
        location: { file: relativePath, line: lineNum, column: 0 },
      });
      continue;
    }
  }

  return {
    tables,
    rlsEnabledTables,
    rlsPolicies,
    indexes,
    file: {
      path: relativePath,
      language: 'sql',
      lineCount: lines.length,
      parseTimeMs: Date.now() - startTime,
    },
  };
}

// HELPER: Find tables without RLS

export function findTablesWithoutRls(
  tables: SqlTable[],
  rlsEnabledTables: string[]
): SqlTable[] {
  return tables.filter(
    (t) => t.hasTenantColumn && !rlsEnabledTables.includes(t.name)
  );
}

// HELPER: Find bypassed RLS policies

export function findBypassedRlsPolicies(policies: SqlRlsPolicy[]): SqlRlsPolicy[] {
  return policies.filter((p) => p.isBypassed);
}
