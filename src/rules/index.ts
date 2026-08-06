/**
 * Rules Index - All 57 rules (42 general + 15 MCP-specific)
 */

import type { RuleSpec } from '../rule-spec.js';
import { GENERAL_RULES } from './general.js';
import { MCP_RULES } from './mcp.js';

export const ALL_RULES: RuleSpec[] = [...GENERAL_RULES, ...MCP_RULES];

export const RULE_COUNT = ALL_RULES.length;

export const RULE_ENGINE_VERSION = '1.6.1';

export function getRuleById(id: string): RuleSpec | undefined {
  return ALL_RULES.find((r) => r.id === id);
}

export function getRulesByCategory(category: string): RuleSpec[] {
  return ALL_RULES.filter((r) => r.category === category);
}

export function getRuleCategories(): string[] {
  return [...new Set(ALL_RULES.map((r) => r.category))];
}

export { GENERAL_RULES, MCP_RULES };
