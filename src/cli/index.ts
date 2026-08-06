/**
 * CLI - mti (mcp-tenant-isolation)
 *
 * Commands: scan, init, rules, suppress, baseline, mcp
 * Exit codes: 0 (no findings), 1 (findings), 2 (error)
 */

import { Command } from 'commander';
import { readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { existsSync } from 'node:fs';
import { scan } from '../engine/scanner.js';
import { jsonReporter, sarifReporter, terminalReporter, aiJsonReporter, markdownReporter } from '../reporters/index.js';
import { ALL_RULES, RULE_COUNT, RULE_ENGINE_VERSION, getRuleCategories } from '../rules/index.js';
import { validateSuppression } from '../engine/suppressions.js';
import { EXIT_CODES } from '../types.js';
import type { MtiConfig, Severity, Baseline, BaselineFingerprint, SuppressionRule } from '../types.js';


const program = new Command();

program
  .name('mti')
  .description('mcp-tenant-isolation - Deterministic tenant isolation scanner')
  .version(RULE_ENGINE_VERSION);


program
  .command('scan')
  .description('Scan project for tenant isolation issues')
  .option('-p, --path <path>', 'project root path', process.cwd())
  .option('-f, --format <format>', 'output format: terminal, json, sarif, ai, markdown', 'terminal')
  .option('-o, --output <file>', 'output file path')
  .option('-s, --severity <level>', 'minimum severity: LOW, MEDIUM, HIGH, CRITICAL')
  .option('-r, --rules <ids>', 'comma-separated rule IDs to run')
  .option('--no-suppress', 'do not apply suppressions')
  .option('--config <path>', 'path to .mtirc.json config file')
  .action(async (options) => {
    try {
      const projectRoot = resolve(options.path);
      const config = await loadConfig(projectRoot, options.config);

      const severityFilter = options.severity?.toUpperCase() as Severity | undefined;
      const rulesFilter = options.rules?.split(',').map((r: string) => r.trim());

      const result = await scan({
        projectRoot,
        config,
        severityFilter,
        rulesFilter,
        noSuppress: options.noSuppress,
      });

      // Generate output - config.output overrides CLI default but explicit --format wins
      const format = options.format !== 'terminal' ? options.format : (config?.output ?? 'terminal');
      let output: string;
      switch (format) {
        case 'json':
          output = jsonReporter(result);
          break;
        case 'sarif':
          output = sarifReporter(result);
          break;
        case 'ai':
          output = aiJsonReporter(result);
          break;
        case 'markdown':
        case 'md':
          output = markdownReporter(result);
          break;
        case 'terminal':
        default:
          output = terminalReporter(result);
          break;
      }

      // Write to file or stdout
      if (options.output) {
        await writeFile(options.output, output, 'utf-8');
        console.log(`Results written to ${options.output}`);
      } else {
        console.log(output);
      }

      // Exit code
      const activeFindings = result.findings.filter(
        (f) => f.suppressionStatus !== 'suppressed'
      );
      process.exitCode = activeFindings.length > 0
        ? EXIT_CODES.FINDINGS_FOUND
        : EXIT_CODES.NO_FINDINGS;
    } catch (err) {
      console.error('Error:', err instanceof Error ? err.message : String(err));
      process.exitCode = EXIT_CODES.ERROR;
    }
  });


program
  .command('init')
  .description('Create .mtirc.json config file')
  .option('-p, --path <path>', 'project root path', process.cwd())
  .action(async (options) => {
    try {
      const projectRoot = resolve(options.path);
      const configPath = join(projectRoot, '.mtirc.json');

      if (existsSync(configPath)) {
        console.error('.mtirc.json already exists');
        process.exitCode = EXIT_CODES.ERROR;
        return;
      }

      const defaultConfig: MtiConfig = {
        rules: {
          severity: {},
          exclude: [],
        },
        paths: {
          include: ['**/*.{ts,tsx,js,jsx}', '**/*.prisma', '**/*.sql'],
          exclude: ['**/node_modules/**', '**/dist/**', '**/.next/**'],
        },
        suppressions: '.mti-suppressions.json',
        baseline: '.mti-baseline.json',
      };

      await writeFile(configPath, JSON.stringify(defaultConfig, null, 2) + '\n', 'utf-8');
      console.log('Created .mtirc.json');
      process.exitCode = EXIT_CODES.NO_FINDINGS;
    } catch (err) {
      console.error('Error:', err instanceof Error ? err.message : String(err));
      process.exitCode = EXIT_CODES.ERROR;
    }
  });


program
  .command('rules')
  .description('List all available rules')
  .option('-c, --category <category>', 'filter by category')
  .option('-j, --json', 'output as JSON')
  .action((options) => {
    let rules = ALL_RULES;
    if (options.category) {
      rules = rules.filter((r) => r.category === options.category);
    }

    if (options.json) {
      console.log(JSON.stringify(rules.map((r) => ({
        id: r.id,
        title: r.title,
        category: r.category,
        severity: r.severity,
        description: r.description,
        suppressible: r.suppressible,
      })), null, 2));
    } else {
      console.log(`\n  mcp-tenant-isolation - ${RULE_COUNT} rules (v${RULE_ENGINE_VERSION})\n`);
      console.log('  Categories:');
      for (const cat of getRuleCategories()) {
        const count = rules.filter((r) => r.category === cat).length;
        if (count > 0) {
          console.log(`    ${cat} (${count})`);
        }
      }
      console.log('');
      for (const rule of rules) {
        console.log(`  [${rule.severity.padEnd(8)}] ${rule.id} - ${rule.title}`);
      }
      console.log('');
    }
    process.exitCode = EXIT_CODES.NO_FINDINGS;
  });


program
  .command('suppress')
  .description('Add a suppression for a finding')
  .option('-p, --path <path>', 'project root path', process.cwd())
  .option('--rule-id <id>', 'rule ID to suppress')
  .option('--fingerprint <fp>', 'finding fingerprint to suppress')
  .option('--file <file>', 'file path to suppress')
  .option('--reason <reason>', 'suppression reason (required)')
  .option('--approved-by <user>', 'approver (required)')
  .option('--expires <date>', 'expiry date (ISO 8601)')
  .option('--controls <controls>', 'comma-separated compensating controls (required)')
  .action(async (options) => {
    try {
      if (!options.reason || !options.approvedBy || !options.controls) {
        console.error('Required: --reason, --approved-by, --controls');
        process.exitCode = EXIT_CODES.ERROR;
        return;
      }

      const suppression = {
        ruleId: options.ruleId,
        fingerprint: options.fingerprint,
        filePath: options.file,
        reason: options.reason,
        approvedBy: options.approvedBy,
        expires: options.expires,
        compensatingControls: options.controls.split(',').map((c: string) => c.trim()),
      };

      const errors = validateSuppression(suppression);
      if (errors.length > 0) {
        console.error('Invalid suppression:');
        errors.forEach((e) => console.error(`  - ${e}`));
        process.exitCode = EXIT_CODES.ERROR;
        return;
      }

      const projectRoot = resolve(options.path);
      const suppressionsPath = join(projectRoot, '.mti-suppressions.json');

      let existing: { suppress: SuppressionRule[] } = { suppress: [] };
      if (existsSync(suppressionsPath)) {
        const content = await readFile(suppressionsPath, 'utf-8');
        existing = JSON.parse(content);
      }

      existing.suppress.push(suppression);
      await writeFile(suppressionsPath, JSON.stringify(existing, null, 2) + '\n', 'utf-8');
      console.log('Suppression added to .mti-suppressions.json');
      process.exitCode = EXIT_CODES.NO_FINDINGS;
    } catch (err) {
      console.error('Error:', err instanceof Error ? err.message : String(err));
      process.exitCode = EXIT_CODES.ERROR;
    }
  });


program
  .command('baseline')
  .description('Create or update baseline of current findings')
  .option('-p, --path <path>', 'project root path', process.cwd())
  .option('--update', 'update existing baseline with new findings')
  .action(async (options) => {
    try {
      const projectRoot = resolve(options.path);
      const config = await loadConfig(projectRoot);
      const baselinePath = join(projectRoot, config?.baseline ?? '.mti-baseline.json');

      const result = await scan({ projectRoot, config });

      const fingerprints: BaselineFingerprint[] = result.findings.map((f) => ({
        fingerprint: f.fingerprint,
        ruleId: f.ruleId,
        severity: f.severity,
        file: f.evidence.file,
        line: f.evidence.lineStart,
      }));

      const baseline: Baseline = {
        version: RULE_ENGINE_VERSION,
        project: projectRoot,
        createdAt: new Date().toISOString(),
        fingerprints,
      };

      await writeFile(baselinePath, JSON.stringify(baseline, null, 2) + '\n', 'utf-8');
      console.log(`Baseline created with ${fingerprints.length} findings at ${baselinePath}`);
      process.exitCode = EXIT_CODES.NO_FINDINGS;
    } catch (err) {
      console.error('Error:', err instanceof Error ? err.message : String(err));
      process.exitCode = EXIT_CODES.ERROR;
    }
  });


program
  .command('mcp')
  .description('Start MCP server for AI agent integration')
  .option('-p, --path <path>', 'project root path', process.cwd())
  .option('-t, --transport <type>', 'transport type: stdio or sse', 'stdio')
  .option('--port <number>', 'port for SSE transport', '3001')
  .action(async (options) => {
    try {
      const projectRoot = resolve(options.path);
      const transport = options.transport as 'stdio' | 'sse';
      const port = parseInt(options.port, 10);
      const { startMcpServer } = await import('../mcp/server.js');
      await startMcpServer(projectRoot, { transport, port });
    } catch (err) {
      console.error('Error:', err instanceof Error ? err.message : String(err));
      process.exitCode = EXIT_CODES.ERROR;
    }
  });


async function loadConfig(projectRoot: string, configPath?: string): Promise<MtiConfig | undefined> {
  const path = configPath ?? join(projectRoot, '.mtirc.json');
  if (!existsSync(path)) return undefined;
  try {
    const content = await readFile(path, 'utf-8');
    return JSON.parse(content) as MtiConfig;
  } catch (err) {
    console.warn(`[mti] Failed to load config from ${path}: ${err instanceof Error ? err.message : String(err)}`);
    return undefined;
  }
}


export function runCli(): void {
  program.parse(process.argv);
}

runCli();
