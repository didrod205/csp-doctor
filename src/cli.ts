#!/usr/bin/env node
/** cspcheck command-line interface. */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { cac } from "cac";
import pc from "picocolors";
import pkg from "../package.json";
import { analyzePolicy, buildReport } from "./analyze.js";
import { DEFAULT_CONFIG } from "./config.js";
import { loadConfig } from "./load-config.js";
import { loadFromContent, loadInputs, readStdin, type InputPolicy } from "./loader.js";
import { parsePolicies } from "./parse.js";
import { printReport } from "./report/console.js";
import { toJSON } from "./report/json.js";
import { toMarkdown } from "./report/markdown.js";
import type { Config, PolicyReport, Report } from "./types.js";

const cli = cac("cspcheck");

function fail(message: string): never {
  console.error(`${pc.red("cspcheck:")} ${message}`);
  process.exit(2);
}

interface ScanOptions {
  policy?: string;
  config?: string;
  ignore?: string;
  reportOnly?: boolean;
  json?: string;
  md?: string;
  minScore?: string;
  quiet?: boolean;
}

cli
  .command("scan [...files]", "Lint a CSP from a string, files, or stdin")
  .option("-p, --policy <csp>", "Lint this CSP string directly")
  .option("--config <file>", "Path to a config file")
  .option("--ignore <rules>", "Comma-separated rule ids to ignore")
  .option("--report-only", "Treat a --policy/stdin string as a Report-Only policy")
  .option("--json <file>", "Write a JSON report to this path")
  .option("--md <file>", "Write a Markdown report to this path")
  .option("--min-score <n>", "CI gate: exit non-zero if the overall score is below this")
  .option("--quiet", "Show only per-policy summary lines")
  .example('  cspcheck scan -p "default-src \'self\'; script-src \'self\' \'unsafe-inline\'"')
  .example("  cspcheck scan index.html _headers")
  .example("  curl -sI https://example.com | cspcheck scan")
  .action((files: string[], options: ScanOptions) => {
    try {
      const config: Config = loadConfig(options.config);
      if (options.ignore) {
        config.ignore = [...config.ignore, ...options.ignore.split(",").map((s) => s.trim()).filter(Boolean)];
      }

      const inputs: InputPolicy[] = [];
      if (options.policy) {
        inputs.push({ source: "policy", policy: options.policy, reportOnly: Boolean(options.reportOnly) });
      }
      if (files && files.length > 0) {
        inputs.push(...loadInputs(files));
      }
      if (inputs.length === 0) {
        if (process.stdin.isTTY) fail("provide a --policy string, a file, or pipe a CSP via stdin.");
        const stdin = readStdin();
        const loaded = loadFromContent(stdin, "<stdin>");
        if (options.reportOnly) loaded.forEach((l) => (l.reportOnly = true));
        inputs.push(...loaded);
      }
      if (inputs.length === 0) fail("no CSP found in the input.");

      const policies: PolicyReport[] = inputs.flatMap((input) =>
        parsePolicies(input.policy, input.reportOnly, input.source).map((p) =>
          analyzePolicy(input.source, p, config),
        ),
      );

      const report = buildReport(policies, {
        version: pkg.version,
        generatedAt: new Date().toISOString(),
      });

      printReport(report, Boolean(options.quiet));

      if (options.json) {
        writeFileSync(resolve(options.json), toJSON(report));
        console.log(pc.dim(`\nWrote JSON report → ${options.json}`));
      }
      if (options.md) {
        writeFileSync(resolve(options.md), toMarkdown(report));
        console.log(pc.dim(`Wrote Markdown report → ${options.md}`));
      }

      const minScore = options.minScore !== undefined ? Number(options.minScore) : config.minScore;
      if (report.summary.score < minScore) {
        console.error(`\n${pc.red("cspcheck:")} score ${report.summary.score} is below the minimum ${minScore}.`);
        process.exit(1);
      }
    } catch (e) {
      fail((e as Error).message);
    }
  });

cli
  .command("report <input>", "Render a saved JSON report as Markdown")
  .option("--md <file>", "Write Markdown to this path instead of stdout")
  .action((input: string, options: { md?: string }) => {
    try {
      const report = JSON.parse(readFileSync(resolve(input), "utf8")) as Report;
      const md = toMarkdown(report);
      if (options.md) {
        writeFileSync(resolve(options.md), md);
        console.log(`Wrote ${options.md}`);
      } else {
        process.stdout.write(md);
      }
    } catch (e) {
      fail((e as Error).message);
    }
  });

cli
  .command("init", "Write a cspcheck.config.json with the defaults")
  .option("--force", "Overwrite an existing config")
  .action((options: { force?: boolean }) => {
    const file = resolve("cspcheck.config.json");
    if (existsSync(file) && !options.force) {
      console.error(`${pc.red("cspcheck:")} cspcheck.config.json already exists (use --force).`);
      process.exit(1);
    }
    writeFileSync(file, JSON.stringify(DEFAULT_CONFIG, null, 2) + "\n");
    console.log("Created cspcheck.config.json");
  });

cli.help();
cli.version(pkg.version);
cli.parse();
