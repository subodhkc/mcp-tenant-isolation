/**
 * Prisma Schema Parser
 *
 * Parses .prisma files to extract models, fields, relations, and indexes.
 * Detects tenant-scoped models (with organizationId/tenantId fields) and
 * models missing tenant fields.
 */

import type { ParsedFile, Location } from '../types.js';
import { TENANT_ISOLATION_GUARDS } from '../guards.js';


export interface PrismaModel {
  name: string;
  fields: PrismaField[];
  location: Location;
  hasTenantField: boolean;
  tenantFieldName?: string;
  scope: 'tenant' | 'user' | 'global';
  indexes: PrismaIndex[];
}

export interface PrismaField {
  name: string;
  type: string;
  isRelation: boolean;
  isTenantField: boolean;
  location: Location;
}

export interface PrismaIndex {
  fields: string[];
  isCompound: boolean;
  hasTenantFirst: boolean;
  location: Location;
}

export interface PrismaParseResult {
  models: PrismaModel[];
  file: ParsedFile;
}


export function parsePrismaSchema(
  sourceCode: string,
  filename: string,
  projectRoot: string
): PrismaParseResult {
  const startTime = Date.now();
  const lines = sourceCode.split('\n');
  const relativePath = filename.replace(projectRoot, '').replace(/^\//, '');
  const models: PrismaModel[] = [];

  let currentModel: PrismaModel | null = null;
  let inModelBlock = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const lineNum = i + 1;

    // Detect model start
    const modelMatch = line.match(/^model\s+(\w+)\s*\{/);
    if (modelMatch) {
      currentModel = {
        name: modelMatch[1],
        fields: [],
        location: { file: relativePath, line: lineNum, column: 0 },
        hasTenantField: false,
        scope: 'global',
        indexes: [],
      };
      inModelBlock = true;
      continue;
    }

    // Detect model end
    if (inModelBlock && line === '}') {
      if (currentModel) {
        // Check if any field is a tenant field
        const tenantField = currentModel.fields.find((f) => f.isTenantField);
        currentModel.hasTenantField = !!tenantField;
        currentModel.tenantFieldName = tenantField?.name;
        // Classify model scope: tenant (has orgId/tenantId), user (has userId), global (neither)
        const hasUserField = currentModel.fields.some(
          (f) => f.name.toLowerCase() === 'userid' || f.name.toLowerCase() === 'user_id'
        );
        if (currentModel.hasTenantField) {
          currentModel.scope = 'tenant';
        } else if (hasUserField) {
          currentModel.scope = 'user';
        } else {
          currentModel.scope = 'global';
        }
        models.push(currentModel);
      }
      currentModel = null;
      inModelBlock = false;
      continue;
    }

    // Parse fields inside model
    if (inModelBlock && currentModel) {
      // Skip empty lines and comments
      if (!line || line.startsWith('//') || line.startsWith('///')) continue;

      // Detect index declarations
      const indexMatch = line.match(/^@@index\(\[([^\]]+)\]/);
      if (indexMatch) {
        const fields = indexMatch[1].split(',').map((f) => f.trim().replace(/"/g, ''));
        const hasTenantFirst = fields.length > 0 &&
          TENANT_ISOLATION_GUARDS.some((g) => fields[0].toLowerCase().includes(g.toLowerCase()));
        currentModel.indexes.push({
          fields,
          isCompound: fields.length > 1,
          hasTenantFirst,
          location: { file: relativePath, line: lineNum, column: 0 },
        });
        continue;
      }

      // Detect @@map, @@id, etc.
      if (line.startsWith('@@')) continue;

      // Parse field: fieldName Type modifiers
      const fieldMatch = line.match(/^(\w+)\s+(\w+)/);
      if (fieldMatch) {
        const fieldName = fieldMatch[1];
        const fieldType = fieldMatch[2];
        const isRelation = fieldType.charAt(0) === fieldType.charAt(0).toUpperCase() &&
          !['String', 'Int', 'Boolean', 'DateTime', 'Json', 'Float', 'BigInt', 'Decimal', 'Bytes'].includes(fieldType);
        const isTenantField = TENANT_ISOLATION_GUARDS.some((g) =>
          fieldName.toLowerCase() === g.toLowerCase() ||
          fieldName.toLowerCase() === g.replace('_', '').toLowerCase()
        );

        currentModel.fields.push({
          name: fieldName,
          type: fieldType,
          isRelation,
          isTenantField,
          location: { file: relativePath, line: lineNum, column: 0 },
        });
      }
    }
  }

  return {
    models,
    file: {
      path: relativePath,
      language: 'prisma',
      lineCount: lines.length,
      parseTimeMs: Date.now() - startTime,
    },
  };
}

// HELPER: Find models without tenant fields

export function findModelsWithoutTenantField(models: PrismaModel[]): PrismaModel[] {
  // Flag models that lack tenant isolation and are not explicitly user-scoped.
  // User-scoped models (userId only) are excluded as they are intentionally user-scoped.
  // Global models (no tenant field, no userId) are flagged as they may need tenant isolation.
  return models.filter((m) => !m.hasTenantField && m.scope !== 'user');
}

// HELPER: Find user-scoped models (for INFO-level reporting)

export function findUserScopedModels(models: PrismaModel[]): PrismaModel[] {
  return models.filter((m) => m.scope === 'user');
}

// HELPER: Find indexes without tenant first

export function findIndexesWithoutTenantFirst(models: PrismaModel[]): { model: string; index: PrismaIndex }[] {
  const results: { model: string; index: PrismaIndex }[] = [];
  for (const model of models) {
    // Only check indexes on models that have tenant fields and are not user-scoped
    if (model.hasTenantField && model.scope !== 'user') {
      for (const index of model.indexes) {
        if (!index.hasTenantFirst) {
          results.push({ model: model.name, index });
        }
      }
    }
  }
  return results;
}
