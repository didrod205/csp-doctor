/** Orchestrator: run the checks over a policy and assemble reports. */

import {
  checkEmpty,
  checkHardening,
  checkMissingDirectives,
  checkScriptSrc,
} from "./checks.js";
import { parsePolicies } from "./parse.js";
import { gradeFor, scoreFindings } from "./score.js";
import type { Config, Finding, Policy, PolicyReport, Report } from "./types.js";

const SEVERITY_ORDER: Record<string, number> = { error: 0, warning: 1, info: 2, pass: 3 };

/** Analyze a single parsed policy (pure). */
export function analyzePolicy(source: string, policy: Policy, config: Config): PolicyReport {
  const ignore = new Set(config.ignore);
  const empty = checkEmpty(policy);
  const findings: Finding[] = (
    empty.length > 0
      ? [...empty, ...checkHardening(policy)]
      : [
          ...checkScriptSrc(policy, config),
          ...checkMissingDirectives(policy),
          ...checkHardening(policy),
        ]
  ).filter((f) => !ignore.has(f.rule));

  findings.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));

  const counts = { error: 0, warning: 0, info: 0 };
  for (const f of findings) {
    if (f.severity === "error") counts.error++;
    else if (f.severity === "warning") counts.warning++;
    else if (f.severity === "info") counts.info++;
  }
  const score = scoreFindings(findings);

  return { source, reportOnly: policy.reportOnly, score, grade: gradeFor(score), counts, findings };
}

/** Convenience: parse a CSP string and analyze every policy in it. */
export function analyzeCsp(source: string, csp: string, config: Config, reportOnly = false): PolicyReport[] {
  return parsePolicies(csp, reportOnly, source).map((policy) => analyzePolicy(source, policy, config));
}

export function buildReport(
  policies: PolicyReport[],
  meta: { version: string; generatedAt: string },
): Report {
  const errors = policies.reduce((s, p) => s + p.counts.error, 0);
  const warnings = policies.reduce((s, p) => s + p.counts.warning, 0);
  const infos = policies.reduce((s, p) => s + p.counts.info, 0);
  const score = policies.length
    ? Math.round(policies.reduce((s, p) => s + p.score, 0) / policies.length)
    : 100;

  return {
    tool: "cspcheck",
    version: meta.version,
    generatedAt: meta.generatedAt,
    summary: { policies: policies.length, score, grade: gradeFor(score), errors, warnings, infos },
    policies,
  };
}
