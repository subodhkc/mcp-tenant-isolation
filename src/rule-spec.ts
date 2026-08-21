/**
 * RuleSpec - Core Abstraction for Deterministic Tenant Isolation Rules
 *
 * Each rule answers: "Is there a path from X to Y without Z?"
 *
 * Pattern-based detection with deterministic rules.
 * Every finding is explainable with: rule ID, path, line number, missing guard.
 */

import { createHash } from 'node:crypto';
import type { Severity, Finding, IR, FlowGraph, Evidence } from './types.js';


export interface ComplianceMapping {
  owaspMcpRef?: string;
  cweIds: string[];
  safeAssertion: string;
  unsafeAssertions: string[];
}


export interface RuleSpec {
  id: string;
  category: string;
  title: string;
  description: string;
  severity: Severity;

  // Flow definition - what patterns to look for
  sources: string[];
  sinks: string[];

  // Guard requirements - controls that must be present
  requiredGuards: string[];

  // Positive controls that suppress findings
  positiveControls: string[];

  // Compliance mappings
  compliance: ComplianceMapping;

  // Rule metadata
  version: string;
  executionOrder: number;
  requiresFlowGraph: boolean;
  suppressible: boolean;

  // Evaluator function - checks IR and returns findings
  evaluate: (ir: IR, graph: FlowGraph) => Finding[];
}

// HELPER: CREATE RULE

export interface CreateRuleOptions {
  id: string;
  category: string;
  title: string;
  description: string;
  severity: Severity;
  requiredGuards: string[];
  positiveControls?: string[];
  owaspMcpRef?: string;
  cweIds?: string[];
  executionOrder?: number;
  requiresFlowGraph?: boolean;
  suppressible?: boolean;
  evaluate: (ir: IR, graph: FlowGraph) => Finding[];
}

export function createRule(options: CreateRuleOptions): RuleSpec {
  return {
    id: options.id,
    category: options.category,
    title: options.title,
    description: options.description,
    severity: options.severity,
    sources: [],
    sinks: [],
    requiredGuards: options.requiredGuards,
    positiveControls: options.positiveControls ?? [],
    compliance: {
      owaspMcpRef: options.owaspMcpRef,
      cweIds: options.cweIds ?? [],
      safeAssertion: `Guard present: ${options.requiredGuards.join(', ')}`,
      unsafeAssertions: [`Missing required guards: ${options.requiredGuards.join(', ')}`],
    },
    version: '1.0.0',
    executionOrder: options.executionOrder ?? 100,
    requiresFlowGraph: options.requiresFlowGraph ?? false,
    suppressible: options.suppressible ?? true,
    evaluate: options.evaluate,
  };
}

// HELPER: BUILD EVIDENCE

export function buildEvidence(
  file: string,
  lineStart: number,
  lineEnd: number,
  codeSnippet: string
): Evidence {
  return {
    file,
    lineStart,
    lineEnd,
    codeSnippet,
  };
}

// HELPER: BUILD FINDING

export function buildFinding(
  ruleId: string,
  title: string,
  severity: Severity,
  description: string,
  evidence: Evidence,
  missingGuards: string[],
  presentGuards: string[]
): Finding {
  const fingerprint = generateFingerprintV2(ruleId, evidence.file, evidence.codeSnippet, missingGuards);
  return {
    ruleId,
    title,
    severity,
    confidence: 0.9,
    description,
    evidence,
    missingGuards,
    presentGuards,
    fingerprint,
    fingerprintVersion: 2,
  };
}


/**
 * v1 fingerprint (legacy, line-dependent).
 * Identity: ruleId:file:lineStart
 * NOT stable under line movement or formatting changes.
 * Retained for migration compatibility.
 */
export function generateFingerprint(
  ruleId: string,
  file: string,
  line: number
): string {
  return createHash('sha256')
    .update(`${ruleId}:${file}:${line}`)
    .digest('hex')
    .substring(0, 16);
}

/**
 * v2 fingerprint (semantic, stable under line movement).
 * Identity: ruleId:file:normalizedCodeSnippet:sortedMissingGuards
 * Stable under:
 * - Line movement (line number is metadata, not identity)
 * - Whitespace/formatting changes (code snippet is normalized)
 * - Guard ordering (missing guards are sorted)
 * NOT stable under:
 * - File rename (file path is part of identity — intentional)
 * - Rule ID change (rule ID is part of identity — intentional)
 * - Semantic code change (code snippet changes — intentional)
 */
export function generateFingerprintV2(
  ruleId: string,
  file: string,
  codeSnippet: string,
  missingGuards: string[]
): string {
  // Normalize code snippet: remove all whitespace (semantic identity ignores formatting),
  // lowercase for case-insensitive stability
  const normalizedSnippet = codeSnippet
    .replace(/\s+/g, '')
    .toLowerCase();
  const sortedGuards = [...missingGuards].sort().join(',');
  return createHash('sha256')
    .update(`v2:${ruleId}:${file}:${normalizedSnippet}:${sortedGuards}`)
    .digest('hex')
    .substring(0, 16);
}

/**
 * Migrate a v1 fingerprint to v2 if possible.
 * Returns the v2 fingerprint if the original finding details are available,
 * otherwise returns the v1 fingerprint unchanged (cannot migrate without details).
 */
export function migrateFingerprintV1ToV2(
  v1Fingerprint: string,
  ruleId: string,
  file: string,
  line: number,
  codeSnippet: string,
  missingGuards: string[]
): string {
  // Verify the v1 fingerprint matches what we'd generate
  const expectedV1 = generateFingerprint(ruleId, file, line);
  if (v1Fingerprint !== expectedV1) {
    // Can't verify — return v1 as-is (migration fails closed)
    return v1Fingerprint;
  }
  return generateFingerprintV2(ruleId, file, codeSnippet, missingGuards);
}
