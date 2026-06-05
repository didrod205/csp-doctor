/** Directive knowledge: which directives exist and how they fall back. */

import type { Policy } from "./types.js";

/** Fetch directives that fall back to `default-src` when absent. */
export const FETCH_DIRECTIVES = new Set([
  "child-src",
  "connect-src",
  "font-src",
  "frame-src",
  "img-src",
  "manifest-src",
  "media-src",
  "object-src",
  "prefetch-src",
  "script-src",
  "script-src-elem",
  "script-src-attr",
  "style-src",
  "style-src-elem",
  "style-src-attr",
  "worker-src",
]);

/** Directives that do NOT fall back to default-src (absent = unrestricted). */
export const NON_FALLBACK = new Set([
  "base-uri",
  "form-action",
  "frame-ancestors",
  "sandbox",
  "report-uri",
  "report-to",
]);

export const ALL_KNOWN = new Set<string>([
  ...FETCH_DIRECTIVES,
  ...NON_FALLBACK,
  "default-src",
  "upgrade-insecure-requests",
  "block-all-mixed-content",
  "require-trusted-types-for",
  "trusted-types",
]);

export function get(policy: Policy, directive: string): string[] | undefined {
  return policy.directives.get(directive);
}

export interface Effective {
  sources: string[];
  /** Which directive actually supplied the sources. */
  from: string;
}

/**
 * Effective source list for a directive, applying default-src fallback for
 * fetch directives. Returns undefined when the directive is unrestricted
 * (neither it nor default-src is set).
 */
export function effective(policy: Policy, directive: string): Effective | undefined {
  const own = policy.directives.get(directive);
  if (own) return { sources: own, from: directive };
  if (FETCH_DIRECTIVES.has(directive)) {
    const def = policy.directives.get("default-src");
    if (def) return { sources: def, from: "default-src" };
  }
  return undefined;
}

/** Effective script execution sources (script-src → default-src). */
export function effectiveScript(policy: Policy): Effective | undefined {
  return effective(policy, "script-src");
}

export function effectiveObject(policy: Policy): Effective | undefined {
  return effective(policy, "object-src");
}
