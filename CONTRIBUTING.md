# Contributing to mcp-tenant-isolation

## Development Setup

```bash
git clone https://github.com/subodhkc/mcp-tenant-isolation.git
cd mcp-tenant-isolation
npm install
npm run build
npm test
```

## Workflow

1. Fork the repository and create a feature branch
2. Run `npm run typecheck` and `npm run lint` before submitting
3. Add tests for any new rules or features
4. Ensure `npm test` passes
5. Update README.md if adding new CLI options or config fields
6. Submit a pull request with a clear description

## Adding a New Rule

1. Define the rule in `src/rules/general.ts` or `src/rules/mcp.ts`
2. Use `createRule()` from `src/rule-spec.ts`
3. Assign a unique rule ID (e.g., `DBQ-011`)
4. Set `executionOrder` to control when the rule runs
5. Add remediation hint in `src/reporters/index.ts` (`REMEDIATION_HINTS`)
6. Add test fixtures in `tests/fixtures/`
7. Add test cases in `tests/rules.test.ts`

## Rule Pack Format

Custom rule packs are JSON files with this structure:

```json
{
  "rules": [
    {
      "id": "CUSTOM-001",
      "category": "Custom",
      "title": "Custom rule title",
      "description": "What this rule detects",
      "severity": "HIGH",
      "requiredGuards": ["tenantId"],
      "sinkKinds": ["db_read", "db_write"],
      "filePatterns": ["/api/"]
    }
  ]
}
```

Reference in `.mtirc.json`:

```json
{
  "rulePacks": ["./custom-rules.json"]
}
```

## Code Style

- TypeScript strict mode
- ESM modules (Node16 module resolution)
- No unused locals or parameters
- Explicit return types on exported functions

## Reporting Issues

Use GitHub Issues. Include:
- Scanner version (`mti --version`)
- Node.js version
- Minimal reproduction (file snippet + `.mtirc.json` if applicable)
- Expected vs actual behavior
