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
    const rules = parsed.suppress ?? [];
    // Warn about v1 suppressions that may not match v2 findings (Part 16 migration)
    const v1Count = rules.filter(r => r.fingerprint && (r.fingerprintVersion ?? 1) === 1).length;
    if (v1Count > 0) {
      console.warn(
        `[mti] ${v1Count} suppression(s) use v1 fingerprints (line-dependent). ` +
        `Findings now use v2 semantic fingerprints. v1 suppressions may not match. ` +
        `Re-run "mti suppress" to regenerate suppressions with v2 fingerprints, ` +
        `or match by ruleId + filePath instead of fingerprint.`
      );
    }
    return rules;
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
    // Match by fingerprint (preferred concrete identity)
    if (rule.fingerprint && rule.fingerprint === finding.fingerprint) return true;

    // Match by ruleId + file (scoped to a file)
    if (rule.ruleId === finding.ruleId && rule.filePath === finding.evidence.file) return true;

    // Rule-wide suppression (no fingerprint, no filePath) is ONLY honored
    // when explicitly marked as a documented permanent exception.
    if (
      rule.ruleId === finding.ruleId &&
      !rule.filePath &&
      !rule.fingerprint &&
      rule.permanentException === true
    ) {
      return true;
    }

    return false;
  });
}


export function validateSuppression(rule: SuppressionRule): string[] {
  const errors: string[] = [];

  if (!rule.reason || rule.reason.length < 10) {
    errors.push('Suppression must include a reason (min 10 characters)');
  }

  // Approver: accept documentedApprover (preferred) or legacy approvedBy.
  // The field records a documented approver identifier; it does NOT represent
  // independent human verification.
  const approver = rule.documentedApprover ?? rule.approvedBy;
  if (!approver) {
    errors.push('Suppression must include a documented approver identifier (documentedApprover)');
  }

  if (!rule.compensatingControls || rule.compensatingControls.length === 0) {
    errors.push('Suppression must include at least one compensating control');
  }

  // Concrete finding identity: require fingerprint by default.
  // Rule-wide suppression (no fingerprint) is only permitted as a documented
  // permanent exception.
  if (!rule.fingerprint) {
    if (!rule.permanentException) {
      errors.push(
        'Suppression must include a concrete finding fingerprint (rule-wide suppression requires permanentException: true with justification in reason)'
      );
    }
  }

  // ruleId is required so the suppression is attributable to a specific check.
  if (!rule.ruleId) {
    errors.push('Suppression must include ruleId');
  }

  // Expiry: required unless explicitly a documented permanent exception.
  if (rule.permanentException) {
    if (rule.expires) {
      errors.push('Permanent exception suppressions must not set expires');
    }
    // Require the reason to justify the permanent exception.
    if (rule.reason && !/permanent|indefinite|no expiry|does not expire/i.test(rule.reason)) {
      errors.push(
        'Permanent exception suppressions must justify the lack of expiry in the reason field'
      );
    }
  } else {
    if (!rule.expires) {
      errors.push('Suppression must include an expiry date (ISO 8601) or set permanentException: true');
    } else {
      const expiry = new Date(rule.expires);
      if (isNaN(expiry.getTime())) {
        errors.push('Suppression expires must be a valid ISO 8601 date');
      } else if (expiry.getTime() <= Date.now()) {
        errors.push('Suppression expires must be a future date');
      }
    }
  }

  return errors;
}
