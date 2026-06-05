/** Core types for csp-doctor. */

export type Severity = "error" | "warning" | "info" | "pass";

export type Category = "xss" | "allowlist" | "missing" | "hardening" | "meta";

export const CATEGORIES: Category[] = ["xss", "allowlist", "missing", "hardening", "meta"];

export const CATEGORY_LABELS: Record<Category, string> = {
  xss: "XSS exposure",
  allowlist: "Allowlist bypass",
  missing: "Missing directives",
  hardening: "Hardening",
  meta: "Policy meta",
};

export interface Finding {
  rule: string;
  category: Category;
  severity: Severity;
  /** The directive this is about, when applicable. */
  directive?: string;
  /** The offending source expression, when applicable. */
  source?: string;
  title: string;
  message: string;
  fix?: string;
}

/** A parsed CSP policy: directive name → its source-expression list. */
export interface Policy {
  reportOnly: boolean;
  directives: Map<string, string[]>;
  raw: string;
  /** Where this policy came from (file, <meta>, header, stdin). */
  label?: string;
}

export interface PolicyReport {
  source: string;
  reportOnly: boolean;
  score: number;
  grade: string;
  counts: { error: number; warning: number; info: number };
  findings: Finding[];
}

export interface Report {
  tool: "csp-doctor";
  version: string;
  generatedAt: string;
  summary: {
    policies: number;
    score: number;
    grade: string;
    errors: number;
    warnings: number;
    infos: number;
  };
  policies: PolicyReport[];
}

export interface Config {
  /** Rule ids to ignore. */
  ignore: string[];
  /** Extra hostnames to treat as bypass-prone (merged with the built-in list). */
  bypassHosts: string[];
  /** Hostnames you have audited and want to allow (suppress bypass findings). */
  allowHosts: string[];
  /** CI gate: minimum overall score. */
  minScore: number;
}
