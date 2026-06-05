/**
 * Parse a Content-Security-Policy string into structured policies. A single
 * serialized value may carry multiple policies separated by commas (how multiple
 * CSP headers combine); each policy is a `;`-separated list of directives, and
 * each directive is a name followed by whitespace-separated source expressions.
 */

import type { Policy } from "./types.js";

/** Split a serialized CSP value into one or more policies. */
export function parsePolicies(value: string, reportOnly = false, label?: string): Policy[] {
  return value
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean)
    .map((raw) => parseOnePolicy(raw, reportOnly, label));
}

function parseOnePolicy(raw: string, reportOnly: boolean, label?: string): Policy {
  const directives = new Map<string, string[]>();
  for (const part of raw.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0]!.toLowerCase();
    if (directives.has(name)) continue; // first wins, per spec
    directives.set(name, tokens.slice(1));
  }
  return { reportOnly, directives, raw, label };
}

// --- source-expression helpers ------------------------------------------

export const UNSAFE_INLINE = "'unsafe-inline'";
export const UNSAFE_EVAL = "'unsafe-eval'";
export const UNSAFE_HASHES = "'unsafe-hashes'";
export const STRICT_DYNAMIC = "'strict-dynamic'";
export const NONE = "'none'";
export const SELF = "'self'";

export function isNonce(source: string): boolean {
  return /^'nonce-[A-Za-z0-9+/_-]+={0,2}'$/.test(source);
}

export function isHash(source: string): boolean {
  return /^'sha(256|384|512)-[A-Za-z0-9+/_-]+={0,2}'$/.test(source);
}

/** A keyword source like 'self', 'unsafe-inline', 'none' (quoted). */
export function isKeyword(source: string): boolean {
  return source.startsWith("'") && source.endsWith("'");
}

/** A bare scheme source like `https:`, `data:`, `blob:`. */
export function schemeOf(source: string): string | null {
  const m = /^([a-z][a-z0-9+.-]*):$/i.exec(source);
  return m ? m[1]!.toLowerCase() : null;
}

/** Extract the host of a host-source (strips scheme, port, path). null if not a host. */
export function hostOf(source: string): string | null {
  if (isKeyword(source) || schemeOf(source)) return null;
  let s = source.replace(/^[a-z][a-z0-9+.-]*:\/\//i, ""); // scheme://
  s = s.split("/")[0]!; // drop path
  s = s.split(":")[0]!; // drop port
  return s.toLowerCase() || null;
}
