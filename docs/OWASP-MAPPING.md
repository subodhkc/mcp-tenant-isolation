# OWASP MCP Top 10 Mapping

**Version:** 1.0
**Date:** 2026-08-21
**Source:** [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) (v0.1, 2025)

## Purpose

This document maps `mcp-tenant-isolation` MCP rules to the official OWASP MCP Top 10 (2025) categories. It replaces the previously invented `OWASP MCP-SEC-01..15` references, which were not real OWASP identifiers.

## Official OWASP MCP Top 10 Categories

| ID | Title |
|---|---|
| MCP01:2025 | Token Mismanagement & Secret Exposure |
| MCP02:2025 | Privilege Escalation via Scope Creep |
| MCP03:2025 | Tool Poisoning |
| MCP04:2025 | Software Supply Chain Attacks & Dependency Tampering |
| MCP05:2025 | Command Injection & Execution |
| MCP06:2025 | Intent Flow Subversion |
| MCP07:2025 | Insufficient Authentication & Authorization |
| MCP08:2025 | Lack of Audit and Telemetry |
| MCP09:2025 | Shadow MCP Servers |
| MCP10:2025 | Context Injection & Over-Sharing |

## Rule Mapping

### Direct Mappings

| Rule ID | Rule Title | OWASP MCP Ref | Rationale |
|---|---|---|---|
| MCP-001 | Tool handler has no tenant-based visibility filter | MCP09:2025 | Tools without tenant scoping are shadow-accessible across tenants |
| MCP-002 | Tool results cached without tenant prefix | MCP10:2025 | Context over-sharing via shared cache keys |
| MCP-003 | Session ID used as sole authorization | MCP01:2025 | Token/session mismanagement — session not bound to user+tenant |
| MCP-004 | Original token forwarded instead of token exchange | MCP07:2025 | Insufficient authorization — token not exchanged per RFC 8693 |
| MCP-005 | No per-tenant rate limiting on tool calls | MCP02:2025 | Scope creep via resource exhaustion |
| MCP-006 | Shared vector store without tenant namespaces | MCP10:2025 | Context over-sharing via cross-tenant vector retrieval |
| MCP-007 | Tool description could bypass isolation | MCP07:2025 | Insufficient authorization — dynamic content in tool descriptions |
| MCP-008 | Credential vault stores tokens without tenant scoping | MCP06:2025 | Intent flow subversion — wrong tenant receives wrong credentials |
| MCP-009 | Single shared API key for all tenant API calls | MCP05:2025 | Command injection surface — shared credentials enable cross-tenant access |
| MCP-010 | No deterministic session cleanup on disconnect | MCP10:2025 | Context over-sharing — stale sessions retain tenant access |
| MCP-011 | Telemetry strips tenant identifier | MCP02:2025 | Privilege escalation — cannot attribute tool usage to tenants |
| MCP-012 | MCP server binds to 0.0.0.0 instead of 127.0.0.1 | MCP10:2025 | Context over-sharing — network exposure of local server |
| MCP-013 | Tool handler accesses filesystem without tenant root | MCP05:2025 | Command injection via filesystem path traversal |
| MCP-014 | Artifact storage without tenant prefix | MCP09:2025 | Shadow access — cross-tenant artifact access |
| MCP-015 | Tools registered without tenant namespace | MCP08:2025 | Lack of audit — tool name collisions prevent tenant attribution |

### General Rules (non-MCP-specific)

General rules (TCM-*, DBQ-*, IDOR-*, SCH-*, etc.) map to standard CWE categories rather than OWASP MCP Top 10. Their `owaspMcpRef` field is intentionally absent (`undefined`). These rules address tenant isolation concerns in multi-tenant SaaS code that predate MCP and are not specific to MCP server architecture.

## Migration Notes

- The previous `OWASP MCP-SEC-01..15` references were invented and did not correspond to any real OWASP standard.
- The new mappings use the official `MCP01:2025` through `MCP10:2025` format.
- Multiple rules may map to the same OWASP MCP category (e.g., MCP-001 and MCP-014 both map to MCP09:2025).
- Some OWASP MCP categories (MCP03:2025 Tool Poisoning, MCP04:2025 Supply Chain) are not directly addressed by this scanner's rules. This is a scope limitation, not a defect — the scanner focuses on tenant isolation, not supply chain or tool poisoning detection.

## Scope Limitations

This scanner does NOT certify compliance with OWASP MCP Top 10. The mappings above indicate which OWASP MCP category a rule is most relevant to, for triage and reporting purposes only. Compliance certification requires additional controls, processes, and evidence beyond static analysis.

## References

- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [OWASP MCP Top 10 GitHub](https://github.com/OWASP/www-project-mcp-top-10/)
- [MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
