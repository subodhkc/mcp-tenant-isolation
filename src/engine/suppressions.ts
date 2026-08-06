/**
 * Suppression Engine
 *
 * Applies suppression rules from .mti-suppressions.json to findings.
 * Suppressions require: reason, approvedBy, compensatingControls, expiry.
 */

import { join } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import type { Finding, SuppressionRule, SuppressionFile } from '../types.js';

export function applySuppressions(
  findings: Finding[],
  projectRoot: string,
  suppressionsPath?: string
): Finding[] {
  // Suppressions are applied lazily - we mark findings as suppressed
  // but don't remove them, so they appear in reports with suppression status
  const suppressions = loadSuppressions(projectRoot, suppressionsPath);
  if (suppressions.length === 0) return findings;

  const now = new Date();

  return findings.map((finding) => {
    const match = findMatchingSuppression(finding, suppressions);
    if (match && (!match.expires || new Date(match.expires) > now)) {
      return {
        ...finding,
        suppressionStatus: 'suppressed',
        suppressionReason: match.reason,
        suppressionExpires: match.expires,
      };
    }
    return {
      ...finding,
      suppressionStatus: 'active',
    };
  });
}

function loadSuppressions(projectRoot: string, suppressionsPath?: string): SuppressionRule[] {
  const suppressionsFile = suppressionsPath ?? join(projectRoot, '.mti-suppressions.json');
  if (!existsSync(suppressionsFile)) return [];
  try {
    const content = readFileSync(suppressionsFile, 'utf-8');
    const parsed = JSON.parse(content) as SuppressionFile;
    return parsed.suppress ?? [];
  } catch (err) {
    console.warn(`[mti] Failed to load suppressions: ${err instanceof Error ? err.message : String(err)}`);
    return [];
  }
}

function findMatchingSuppression(
  finding: Finding,
  suppressions: SuppressionRule[]
): SuppressionRule | undefined {
  return suppressions.find((rule) => {
    // Match by fingerprint
    if (rule.fingerprint && rule.fingerprint === finding.fingerprint) return true;

    // Match by ruleId + file
    if (rule.ruleId === finding.ruleId && rule.filePath === finding.evidence.file) return true;

    // Match by ruleId only (suppress all findings of this rule)
    if (rule.ruleId === finding.ruleId && !rule.filePath && !rule.fingerprint) return true;

    return false;
  });
}


export function validateSuppression(rule: SuppressionRule): string[] {
  const errors: string[] = [];

  if (!rule.reason || rule.reason.length < 10) {
    errors.push('Suppression must include a reason (min 10 characters)');
  }

  if (!rule.approvedBy) {
    errors.push('Suppression must include approvedBy');
  }

  if (!rule.compensatingControls || rule.compensatingControls.length === 0) {
    errors.push('Suppression must include at least one compensating control');
  }

  if (rule.expires) {
    const expiry = new Date(rule.expires);
    if (isNaN(expiry.getTime())) {
      errors.push('Suppression expires must be a valid ISO 8601 date');
    }
  }

  return errors;
}
