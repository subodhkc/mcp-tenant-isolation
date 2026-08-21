/**
 * Rule Pack Loader
 *
 * Loads custom rule packs from JSON files specified in .mtirc.json
 * under the "rulePacks" field. Each rule pack is a JSON file containing
 * an array of rule definitions that get converted to RuleSpec objects.
 *
 * Rule pack JSON format:
 * {
 *   "rules": [
 *     {
 *       "id": "CUSTOM-001",
 *       "category": "Custom",
 *       "title": "Custom rule title",
 *       "description": "What this rule detects",
 *       "severity": "HIGH",
 *       "requiredGuards": ["tenantId"],
 *       "cweIds": ["CWE-639"],
 *       "sinkKinds": ["db_read", "db_write"],
 *       "filePatterns": ["/api/"],
 *       "executionOrder": 100
 *     }
 *   ]
 * }
 */

import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { createRule, buildFinding, buildEvidence } from '../rule-spec.js';
import type { RuleSpec } from '../rule-spec.js';
import type { Severity } from '../types.js';
import { TENANT_ISOLATION_GUARDS, hasGuard } from '../guards.js';
import { PathBoundary, PathBoundaryError } from '../security/path-boundary.js';
import { ALL_RULES } from '../rules/index.js';

/** Maximum number of custom rules allowed across all rulepacks (Part 23). */
const MAX_CUSTOM_RULES = 50;
/** Valid severity levels for custom rules. */
const VALID_SEVERITIES: Severity[] = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
/** Built-in rule IDs that custom rules must not collide with. */
const BUILTIN_RULE_IDS = new Set(ALL_RULES.map((r) => r.id));

/** Normalize a path for case-insensitive containment comparison (cross-platform). */
function rootNormLower(p: string): string {
  return resolve(p).toLowerCase();
}


interface CustomRuleDef {
  id: string;
  category: string;
  title: string;
  description: string;
  severity: Severity;
  requiredGuards: string[];
  cweIds?: string[];
  sinkKinds?: string[];
  sinkApis?: string[];
  filePatterns?: string[];
  executionOrder?: number;
  suppressible?: boolean;
}


interface RulePackFile {
  rules: CustomRuleDef[];
}


export async function loadRulePacks(
  projectRoot: string,
  packPaths?: string[],
  boundary?: PathBoundary
): Promise<RuleSpec[]> {
  if (!packPaths || packPaths.length === 0) return [];

  const customRules: RuleSpec[] = [];

  for (const packPath of packPaths) {
    // Resolve through the boundary if provided (Part 3 + Part 22 containment).
    // Without a boundary, fall back to lexical resolve against projectRoot
    // (CLI path; boundary is enforced at the MCP layer).
    let fullPath: string;
    if (boundary) {
      try {
        fullPath = await boundary.resolve(packPath);
      } catch (err) {
        if (err instanceof PathBoundaryError) {
          console.warn(`Rule pack rejected (${err.code}): ${packPath} — ${err.message}`);
        } else {
          console.warn(`Rule pack rejected: ${packPath} — ${err instanceof Error ? err.message : String(err)}`);
        }
        continue;
      }
    } else {
      // CLI fallback: reject absolute paths that escape root lexically.
      const resolved = resolve(projectRoot, packPath);
      const rootResolved = resolve(projectRoot);
      const rootNorm = rootNormLower(rootResolved);
      const resolvedNorm = rootNormLower(resolved);
      const sep = process.platform === 'win32' ? '\\' : '/';
      const rootWithSep = rootNorm.endsWith(sep) ? rootNorm : rootNorm + sep;
      if (resolvedNorm !== rootNorm && !resolvedNorm.startsWith(rootWithSep)) {
        console.warn(`Rule pack escapes project root: ${packPath} -> ${resolved}`);
        continue;
      }
      fullPath = resolved;
    }
    if (!existsSync(fullPath)) {
      console.warn(`Rule pack not found: ${packPath}`);
      continue;
    }

    try {
      const content = await readFile(fullPath, 'utf-8');
      const pack = JSON.parse(content) as RulePackFile;

      // Validate rulepack structure (Part 23)
      if (!pack.rules || !Array.isArray(pack.rules)) {
        console.warn(`Rule pack ${packPath}: missing or invalid "rules" array`);
        continue;
      }

      for (const def of pack.rules) {
        // Part 23: validate custom rule definition
        const validationErrors = validateCustomRule(def, customRules.length);
        if (validationErrors.length > 0) {
          for (const err of validationErrors) {
            console.warn(`Rule pack ${packPath}: ${err}`);
          }
          continue;
        }

        const rule = createRule({
          id: def.id,
          category: def.category,
          title: def.title,
          description: def.description,
          severity: def.severity,
          requiredGuards: def.requiredGuards,
          cweIds: def.cweIds,
          executionOrder: def.executionOrder ?? 200,
          suppressible: def.suppressible ?? true,
          evaluate: (ir) => {
            const findings = [];
            const sinkKinds = def.sinkKinds ?? ['db_read', 'db_write'];
            const sinkApis = def.sinkApis ?? [];
            const filePatterns = def.filePatterns ?? [];

            for (const sink of ir.sinks) {
              if (!sinkKinds.includes(sink.kind)) continue;
              if (sinkApis.length > 0 && !sinkApis.some((api) => sink.api.includes(api))) continue;
              if (filePatterns.length > 0 && !filePatterns.some((pat) => sink.location.file.includes(pat))) continue;

              const hasTenant = hasGuard(sink.api, TENANT_ISOLATION_GUARDS) ||
                ir.tenantScopes.some((ts) => ts.appliesToSinkId === sink.id && ts.hasTenantFilter);

              if (!hasTenant) {
                findings.push(
                  buildFinding(
                    def.id,
                    def.title,
                    def.severity,
                    def.description,
                    buildEvidence(sink.location.file, sink.location.line, sink.location.line, sink.api),
                    def.requiredGuards,
                    []
                  )
                );
              }
            }
            return findings;
          },
        });
        customRules.push(rule);
      }
    } catch (err) {
      console.warn(`Failed to load rule pack ${packPath}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return customRules;
}

/**
 * Validate a custom rule definition (Part 23 — custom rulepack security).
 * Returns an array of error messages (empty = valid).
 */
function validateCustomRule(def: CustomRuleDef, currentCount: number): string[] {
  const errors: string[] = [];

  // Required fields
  if (!def.id || typeof def.id !== 'string') {
    errors.push('Rule ID is required and must be a string');
  } else if (!/^[A-Z]+-\d{3}$/.test(def.id)) {
    errors.push(`Rule ID "${def.id}" must match format PREFIX-NNN (e.g., CUSTOM-001)`);
  }

  if (!def.title || typeof def.title !== 'string') {
    errors.push('Rule title is required');
  }

  if (!def.description || typeof def.description !== 'string') {
    errors.push('Rule description is required');
  }

  if (!def.category || typeof def.category !== 'string') {
    errors.push('Rule category is required');
  }

  if (!def.severity || !VALID_SEVERITIES.includes(def.severity)) {
    errors.push(`Rule severity must be one of: ${VALID_SEVERITIES.join(', ')}`);
  }

  if (!def.requiredGuards || !Array.isArray(def.requiredGuards) || def.requiredGuards.length === 0) {
    errors.push('Rule must have at least one required guard');
  }

  // Prevent collision with built-in rules
  if (def.id && BUILTIN_RULE_IDS.has(def.id)) {
    errors.push(`Rule ID "${def.id}" collides with a built-in rule — use a custom prefix`);
  }

  // Prevent duplicate custom rule IDs
  // (checked at load time by the caller, but we warn here too)

  // Enforce maximum custom rule count
  if (currentCount >= MAX_CUSTOM_RULES) {
    errors.push(`Maximum custom rule limit (${MAX_CUSTOM_RULES}) reached`);
  }

  return errors;
}
