/**
 * Flow Graph Builder
 *
 * Builds a directed graph from IR elements:
 * - Nodes: entrypoints, sources, sinks, assignments
 * - Edges: data flow from source -> assignment -> sink
 */

import type { IR, FlowGraph, FlowPath, NodeType, NodeMetadata } from '../types.js';

export function buildFlowGraph(ir: IR): FlowGraph {
  const nodes = new Set<NodeType>();
  const edges = new Map<NodeType, Set<NodeType>>();
  const metadata = new Map<NodeType, NodeMetadata>();

  // Add entrypoints as nodes
  for (const entry of ir.entrypoints) {
    const nodeId = `entry:${entry.id}`;
    nodes.add(nodeId);
    edges.set(nodeId, new Set());
    metadata.set(nodeId, {
      entrypointId: entry.id,
      location: entry.location,
      kind: 'entrypoint',
      confidence: 1.0,
    });
  }

  // Add sources as nodes, connect to entrypoints
  for (const source of ir.sources) {
    const nodeId = `source:${source.id}`;
    nodes.add(nodeId);
    edges.set(nodeId, new Set());
    metadata.set(nodeId, {
      entrypointId: source.entrypointId ?? '',
      location: source.location,
      kind: `source:${source.kind}`,
      confidence: 0.9,
    });

    if (source.entrypointId) {
      const entryNode = `entry:${source.entrypointId}`;
      if (nodes.has(entryNode)) {
        edges.get(entryNode)?.add(nodeId);
      }
    }
  }

  // Add sinks as nodes
  for (const sink of ir.sinks) {
    const nodeId = `sink:${sink.id}`;
    nodes.add(nodeId);
    edges.set(nodeId, new Set());
    metadata.set(nodeId, {
      entrypointId: sink.entrypointId ?? '',
      location: sink.location,
      kind: `sink:${sink.kind}`,
      confidence: 0.9,
    });
  }

  // Add assignments as edges: source sym -> dst
  for (const asgn of ir.assignments) {
    const nodeId = `asgn:${asgn.id}`;
    nodes.add(nodeId);
    edges.set(nodeId, new Set());
    metadata.set(nodeId, {
      entrypointId: asgn.entrypointId ?? '',
      location: asgn.location,
      kind: 'assignment',
      confidence: 0.8,
    });

    // Connect sources to assignment
    for (const srcSym of asgn.srcSyms) {
      for (const source of ir.sources) {
        if (source.symbol.includes(srcSym) || srcSym.includes(source.symbol)) {
          const srcNode = `source:${source.id}`;
          if (nodes.has(srcNode)) {
            edges.get(srcNode)?.add(nodeId);
          }
        }
      }
    }

    // Connect assignment to sinks that use the dst variable
    for (const sink of ir.sinks) {
      if (sink.argsVars.some((v) => v.includes(asgn.dst) || asgn.dst.includes(v))) {
        const sinkNode = `sink:${sink.id}`;
        if (nodes.has(sinkNode)) {
          edges.get(nodeId)?.add(sinkNode);
        }
      }
    }
  }

  return { nodes, edges, metadata };
}


export function findPaths(
  graph: FlowGraph,
  sourceKind: string,
  sinkKind: string
): FlowPath[] {
  const paths: FlowPath[] = [];

  for (const [startNode, startMeta] of graph.metadata) {
    if (!startMeta.kind.startsWith(`source:${sourceKind}`)) continue;

    for (const [endNode, endMeta] of graph.metadata) {
      if (!endMeta.kind.startsWith(`sink:${sinkKind}`)) continue;

      const path = dfs(graph, startNode, endNode);
      if (path && path.length > 0) {
        paths.push({
          nodes: path,
          entrypointId: startMeta.entrypointId,
          sourceKind,
          sinkKind,
          length: path.length,
        });
      }
    }
  }

  return paths;
}

function dfs(
  graph: FlowGraph,
  start: NodeType,
  target: NodeType,
  visited: Set<NodeType> = new Set(),
  path: NodeType[] = []
): NodeType[] | null {
  if (start === target) {
    return [...path, start];
  }
  if (visited.has(start)) return null;

  visited.add(start);
  const neighbors = graph.edges.get(start);
  if (neighbors) {
    for (const next of neighbors) {
      const result = dfs(graph, next, target, new Set(visited), [...path, start]);
      if (result) return result;
    }
  }

  return null;
}
