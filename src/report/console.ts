/** Colored console output for `scan`. */

import pc from "picocolors";
import type { Report, Severity } from "../types.js";

const MARK: Record<Severity, string> = { error: "✗", warning: "⚠", info: "ℹ", pass: "✓" };

function color(severity: Severity, text: string): string {
  if (severity === "error") return pc.red(text);
  if (severity === "warning") return pc.yellow(text);
  if (severity === "info") return pc.blue(text);
  return pc.green(text);
}

function gradeColor(grade: string): (s: string) => string {
  if (grade === "A" || grade === "B") return pc.green;
  if (grade === "C" || grade === "D") return pc.yellow;
  return pc.red;
}

export function printReport(report: Report, quiet = false): void {
  for (const p of report.policies) {
    const g = gradeColor(p.grade);
    const ro = p.reportOnly ? pc.dim(" · report-only") : "";
    console.log(`\n${pc.bold(p.source)}  ${g(`${p.score}/100 (${p.grade})`)}${ro}`);
    if (quiet) continue;
    if (p.findings.length === 0) {
      console.log(`  ${pc.green("✓ no issues found")}`);
      continue;
    }
    for (const f of p.findings) {
      const dir = f.directive ? pc.dim(`[${f.directive}]`) : "";
      console.log(`  ${color(f.severity, MARK[f.severity])} ${f.title} ${dir} ${pc.dim(f.rule)}`);
      if (f.fix) console.log(`      ${pc.dim("→ " + f.fix.split("\n")[0])}`);
    }
  }

  const s = report.summary;
  const g = gradeColor(s.grade);
  console.log(
    `\n${pc.bold("Overall")}  ${g(`${s.score}/100 (${s.grade})`)} ` +
      pc.dim(`· ${s.policies} policy(ies), ${s.errors} error(s), ${s.warnings} warning(s), ${s.infos} info(s)`),
  );
}
