# Flow Analysis Qualification

**Version:** 1.0
**Date:** 2026-08-21

## Overview

The scanner includes a flow graph engine (`src/engine/flow-graph.ts`) that builds an intra-procedural data flow graph from the intermediate representation (IR). Rules that set `requiresFlowGraph: true` use this graph to trace paths from sources to sinks.

## Current state

### What works

- **Flow graph construction**: The `buildFlowGraph()` function creates a graph of nodes (sources, sinks, assignments, auth signals) and edges (data flow relationships).
- **Path finding**: The `findPaths()` function traces paths from entrypoints through sources to sinks.
- **Rule integration**: Rules that set `requiresFlowGraph: true` receive the graph as a parameter and can query it.

### What does not work (known limitations)

1. **Intra-procedural only.** The flow graph traces data flow within a single function body. It does not trace flow across function boundaries (function calls, returns, callbacks). If `tenantId` is extracted in a helper function and used in a query in another function, the flow graph will not connect them.

2. **No inter-file flow.** Data flow across files is not traced. If `tenantId` is passed from a middleware file to a route handler in another file, the flow graph will not connect them.

3. **No pointer/alias tracking.** Variable aliases and object property propagation are not fully traced. If `const orgId = tenantId; const result = await find({ orgId })`, the flow graph may not connect `tenantId` to the `find` call through the `orgId` alias.

4. **No framework-specific flow.** Next.js middleware → route handler flow, Express middleware → handler flow, and similar framework-specific data propagation patterns are not traced.

### Which rules use flow analysis

Most rules in the current rule set do NOT require flow graph analysis. They use pattern-based detection: they check whether a sink (e.g., a `findMany` call) has a tenant guard nearby (e.g., `organizationId` in the where clause). This is sufficient for most tenant isolation patterns because the guard is typically co-located with the sink.

Rules that set `requiresFlowGraph: true` are listed in the rule metadata. As of v2.0.0, no built-in rules require flow graph analysis. The flow graph infrastructure exists for future rules that need it and for custom rule packs that opt in.

### Why this is acceptable

The scanner's value proposition is catching missing tenant guards at the sink level. You do not need inter-procedural flow analysis to determine that a `findMany({})` call is missing an `organizationId` filter. The guard is either present in the where clause or it is not.

Flow analysis becomes necessary when you want to verify that a tenant ID derived from a trusted source (session) reaches a sink without being overwritten by an untrusted source (request body). This is a harder problem that requires inter-procedural analysis, which is beyond the current scope.

## Qualification criteria

A rule is qualified for flow analysis if:

1. It sets `requiresFlowGraph: true` in its rule spec
2. It receives the flow graph and queries it correctly
3. It produces findings only when the flow graph confirms a source-to-sink path without guards
4. It does not produce false positives on code where guards are present but not on the same line as the sink

## Future work

- Inter-procedural flow analysis (function call graph)
- Cross-file flow tracing
- Framework-specific middleware → handler flow
- Alias and pointer tracking
- Taint analysis from request input to database sink

These are deferred to a future version. The current scanner focuses on pattern-based detection, which covers the majority of tenant isolation defects in practice.
