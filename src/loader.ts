/** Read CSP from files (or stdin) and extract the policy strings. */

import { readFileSync, statSync } from "node:fs";
import { relative, resolve } from "node:path";
import { extractPolicies } from "./extract.js";

export interface InputPolicy {
  source: string;
  policy: string;
  reportOnly: boolean;
}

function label(source: string, kind: string, index: number, total: number): string {
  const parts = [source];
  if (kind !== "policy") parts.push(`(${kind})`);
  if (total > 1) parts.push(`#${index + 1}`);
  return parts.join(" ");
}

export function loadFromContent(content: string, source: string): InputPolicy[] {
  const extracted = extractPolicies(content, "policy");
  return extracted.map((e, i) => ({
    source: label(source, e.label, i, extracted.length),
    policy: e.policy,
    reportOnly: e.reportOnly,
  }));
}

export function loadInputs(targets: string[]): InputPolicy[] {
  const out: InputPolicy[] = [];
  const cwd = process.cwd();
  for (const target of targets) {
    const abs = resolve(target);
    try {
      if (!statSync(abs).isFile()) continue;
    } catch {
      throw new Error(`path not found: ${target}`);
    }
    const rel = abs.startsWith(cwd) ? relative(cwd, abs) || abs : abs;
    out.push(...loadFromContent(readFileSync(abs, "utf8"), rel));
  }
  return out;
}

export function readStdin(): string {
  try {
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}
