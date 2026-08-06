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
import { resolve } from 'node:path';
import { existsSync } from 'node:fs';
import { createRule, buildFinding, buildEvidence } from '../rule-spec.js';
import type { RuleSpec } from '../rule-spec.js';
import type { Severity } from '../types.js';
import { TENANT_ISOLATION_GUARDS, hasGuard } from '../guards.js';


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
  packPaths?: string[]
): Promise<RuleSpec[]> {
  if (!packPaths || packPaths.length === 0) return [];

  const customRules: RuleSpec[] = [];

  for (const packPath of packPaths) {
    const fullPath = resolve(projectRoot, packPath);
    if (!existsSync(fullPath)) {
      console.warn(`Rule pack not found: ${packPath}`);
      continue;
    }

    try {
      const content = await readFile(fullPath, 'utf-8');
      const pack = JSON.parse(content) as RulePackFile;

      for (const def of pack.rules) {
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
