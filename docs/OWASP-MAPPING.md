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
| MCP-002 | Tool returns data without tenant context verification | MCP07:2025 | Missing authorization on tool responses |
| MCP-003 | Credential vault accessible across tenant boundaries | MCP01:2025 | Secret exposure across tenant boundaries |
| MCP-004 | Session binding missing between MCP session and tenant | MCP07:2025 | Insufficient authentication binding |
| MCP-005 | No per-tenant rate limiting on tool calls | MCP02:2025 | Scope creep via resource exhaustion |
| MCP-006 | Cache key missing tenant prefix | MCP10:2025 | Context injection via shared cache |
| MCP-007 | Resource handler has no tenant-based access control | MCP07:2025 | Missing authorization on resources |
| MCP-008 | Prompt injection surface in tool description | MCP06:2025 | Intent flow subversion via tool descriptions |
| MCP-009 | Tool input not validated against tenant schema | MCP05:2025 | Injection via unvalidated tool input |
| MCP-010 | Vector store query missing tenant filter | MCP10:2025 | Context over-sharing via vector store |
| MCP-011 | MCP server exposes admin tools to all tenants | MCP02:2025 | Privilege escalation via scope creep |
| MCP-012 | Tool output not scoped to requesting tenant | MCP10:2025 | Context over-sharing via tool output |
| MCP-013 | Filesystem access without tenant root boundary | MCP05:2025 | Command injection via filesystem escape |
| MCP-014 | Dynamic tool registration without tenant validation | MCP09:2025 | Shadow MCP servers via dynamic registration |
| MCP-015 | Missing audit log for tenant-scoped tool calls | MCP08:2025 | Lack of audit and telemetry |

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
