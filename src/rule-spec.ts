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
  const fingerprint = generateFingerprint(ruleId, evidence.file, evidence.lineStart);
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
  };
}


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
