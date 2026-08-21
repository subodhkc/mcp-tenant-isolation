/**
 * Scan Receipt and Evidence Envelope (Parts 17-20)
 *
 * Provenance, reproducibility, and structured evidence output.
 */

import { createHash } from 'node:crypto';
import type {
  ScanResult,
  ScanReceipt,
  EvidenceEnvelope,
  ConcernFamilySummary,
} from '../types.js';
import { RULE_ENGINE_VERSION } from '../rules/index.js';

const PRODUCER_ID = 'io.github.subodhkc/mcp-tenant-isolation';
const RECEIPT_SCHEMA_VERSION = '1.0.0';
const ENVELOPE_SCHEMA_VERSION = '1.0.0';

/**
 * Compute the rulepack digest (Part 22).
 * Hash of all rule IDs + versions + execution orders for reproducibility.
 * This allows consumers to verify that the same rule set was used across scans.
 */
export function computeRulepackDigest(
  rules: Array<{ id: string; version: string; executionOrder: number }>
): string {
  // Sort by ID for deterministic ordering
  const sorted = [...rules].sort((a, b) => a.id.localeCompare(b.id));
  const content = sorted
    .map((r) => `${r.id}@${r.version}#${r.executionOrder}`)
    .join('|');
  return createHash('sha256').update(content).digest('hex').substring(0, 32);
}

/**
 * Compute the verdict from a scan result.
 * ERROR if completeness is ERROR; BLOCK if CRITICAL/HIGH active findings;
 * REVIEW if MEDIUM/LOW active; PASS if no active findings.
 */
export function computeVerdict(result: ScanResult): 'PASS' | 'REVIEW' | 'BLOCK' | 'ERROR' {
  if (result.completeness === 'ERROR') return 'ERROR';
  const active = result.findings.filter((f) => f.suppressionStatus !== 'suppressed');
  if (active.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH')) return 'BLOCK';
  if (active.length > 0) return 'REVIEW';
  return 'PASS';
}

/**
 * Build a Scan Receipt from a scan result (Parts 17-18).
 * The receipt contains provenance and reproducibility metadata.
 */
export function buildScanReceipt(
  result: ScanResult,
  projectRoot: string,
  rulepackDigest: string
): ScanReceipt {
  const activeFindings = result.findings.filter((f) => f.suppressionStatus !== 'suppressed').length;
  const suppressedFindings = result.findings.length - activeFindings;
  const verdict = computeVerdict(result);

  // Build receipt content without the hash field for hash computation
  const receiptContent: Omit<ScanReceipt, 'receiptHash'> = {
    schemaVersion: RECEIPT_SCHEMA_VERSION,
    producerId: PRODUCER_ID,
    engineVersion: RULE_ENGINE_VERSION,
    timestamp: result.ir.scanTimestamp,
    projectRoot,
    durationMs: result.durationMs,
    completeness: result.completeness,
    verdict,
    rulepackDigest,
    rulesAvailable: result.coverage.rulesAvailable,
    rulesSelected: result.coverage.rulesSelected,
    filesDiscovered: result.coverage.filesDiscovered,
    filesParsed: result.coverage.filesParsed,
    totalFindings: result.findings.length,
    activeFindings,
    suppressedFindings,
  };

  const receiptHash = createHash('sha256')
    .update(JSON.stringify(receiptContent))
    .digest('hex')
    .substring(0, 32);

  return { ...receiptContent, receiptHash };
}

/**
 * Build an Evidence Envelope from a scan result (Parts 19-20).
 * The envelope bundles the receipt, findings, coverage, and limitations
 * into a single verifiable artifact.
 */
export function buildEvidenceEnvelope(
  result: ScanResult,
  projectRoot: string,
  rulepackDigest: string,
  concernFamilies: ConcernFamilySummary[],
  findingsBound = 20
): EvidenceEnvelope {
  const receipt = buildScanReceipt(result, projectRoot, rulepackDigest);

  // Bounded findings
  const allFindings = result.findings;
  const truncatedFindings = allFindings.slice(0, findingsBound);
  const truncated = allFindings.length > findingsBound;

  const envelopeContent: Omit<EvidenceEnvelope, 'envelopeHash'> = {
    schemaVersion: ENVELOPE_SCHEMA_VERSION,
    producerId: PRODUCER_ID,
    timestamp: result.ir.scanTimestamp,
    receipt,
    concernFamilies,
    findings: truncatedFindings,
    truncation: {
      findingsReturned: truncatedFindings.length,
      findingsTotal: allFindings.length,
      truncated,
    },
    coverage: result.coverage,
    completenessReasons: result.completenessReasons,
    limitations: result.limitations,
  };

  const envelopeHash = createHash('sha256')
    .update(JSON.stringify(envelopeContent))
    .digest('hex')
    .substring(0, 32);

  return { ...envelopeContent, envelopeHash };
}
