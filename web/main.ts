/**
 * csp-doctor playground — lint a Content-Security-Policy entirely in the browser.
 * Reuses the library's pure analysis core (parse + checks + the bypassable-host
 * list). Your policy never leaves the page — a local-first alternative to pasting
 * it into Google's online CSP Evaluator.
 */

import { analyzeCsp } from "../src/analyze.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { extractPolicies } from "../src/extract.js";
import { CATEGORY_LABELS, type PolicyReport, type Severity } from "../src/types.js";

const SAMPLE =
  "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https: ajax.googleapis.com; img-src *";

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

const ICON: Record<Severity, string> = { error: "✗", warning: "⚠", info: "ℹ", pass: "✓" };

function gradeClass(grade: string): string {
  if (grade === "A" || grade === "B") return "grade-A";
  if (grade === "C" || grade === "D") return "grade-C";
  return "grade-F";
}

function renderFindings(report: PolicyReport): string {
  if (report.findings.length === 0) {
    return `<div class="ok">✓ No issues — this policy is locked down.</div>`;
  }
  return report.findings
    .map(
      (f) => `<div class="finding sev-${f.severity}">
        <span class="finding-icon">${ICON[f.severity]}</span>
        <div class="finding-body">
          <div class="finding-title">${esc(f.title)}
            <span class="cat-tag">${esc(CATEGORY_LABELS[f.category])}</span>
            ${f.directive ? `<span class="dir-tag">${esc(f.directive)}</span>` : ""}
          </div>
          <div class="finding-msg">${esc(f.message)}</div>
          ${f.fix ? `<div class="finding-fix">→ ${esc(f.fix)}</div>` : ""}
        </div>
      </div>`,
    )
    .join("");
}

function renderReport(report: PolicyReport, index: number, total: number): string {
  const ro = report.reportOnly ? `<span class="status warn">report-only</span>` : "";
  const head = total > 1 ? `<div class="policy-head">Policy ${index + 1} of ${total} ${ro}</div>` : ro ? `<div class="policy-head">${ro}</div>` : "";
  return `<div class="pane">
    ${head}
    <h2>Audit <span class="score-badge ${gradeClass(report.grade)}">${report.score}/100 (${report.grade})</span></h2>
    ${renderFindings(report)}
  </div>`;
}

function render(): void {
  const value = $<HTMLTextAreaElement>("csp").value;
  const out = $("output");
  if (!value.trim()) {
    out.classList.add("hidden");
    return;
  }
  const extracted = extractPolicies(value);
  const reports = extracted.flatMap((e) => analyzeCsp(e.label, e.policy, DEFAULT_CONFIG, e.reportOnly));
  out.classList.remove("hidden");
  out.innerHTML = reports.map((r, i) => renderReport(r, i, reports.length)).join("") ||
    `<div class="pane muted">No policy detected — paste a Content-Security-Policy value.</div>`;
}

function init(): void {
  $<HTMLTextAreaElement>("csp").addEventListener("input", render);
  $("sample").addEventListener("click", () => {
    $<HTMLTextAreaElement>("csp").value = SAMPLE;
    render();
  });
  $("clear").addEventListener("click", () => {
    $<HTMLTextAreaElement>("csp").value = "";
    render();
  });
}

init();
