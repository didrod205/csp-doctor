/**
 * The weakness rule set. Each function inspects a parsed policy and returns
 * findings. The analysis is *nonce/hash/strict-dynamic aware*: an
 * `'unsafe-inline'` that a modern browser ignores (because a nonce is present)
 * is reported very differently from one that actually opens the door.
 */

import { effective, effectiveObject, effectiveScript, get } from "./directives.js";
import { findBypass } from "./hosts.js";
import {
  hostOf,
  isHash,
  isNonce,
  NONE,
  schemeOf,
  STRICT_DYNAMIC,
  UNSAFE_EVAL,
  UNSAFE_HASHES,
  UNSAFE_INLINE,
} from "./parse.js";
import type { Config, Finding, Policy } from "./types.js";

export function checkScriptSrc(policy: Policy, config: Config): Finding[] {
  const out: Finding[] = [];
  const eff = effectiveScript(policy);

  if (!eff) {
    out.push({
      rule: "no-script-src",
      category: "xss",
      severity: "error",
      directive: "script-src",
      title: "No script-src or default-src — scripts are unrestricted",
      message: "Without script-src (or a default-src fallback), the page can load and run scripts from anywhere.",
      fix: "Add a `script-src` (ideally `'self'` + a nonce + `'strict-dynamic'`).",
    });
    return out;
  }

  const sources = eff.sources;
  const where = eff.from;
  const hasNonceOrHash = sources.some((s) => isNonce(s) || isHash(s));
  const hasStrictDynamic = sources.includes(STRICT_DYNAMIC);

  if (sources.includes(UNSAFE_INLINE)) {
    if (hasNonceOrHash || hasStrictDynamic) {
      out.push({
        rule: "unsafe-inline-ignored",
        category: "xss",
        severity: "info",
        directive: where,
        source: UNSAFE_INLINE,
        title: "'unsafe-inline' present but ignored by modern browsers",
        message: "A nonce/hash/strict-dynamic is present, so browsers that support them ignore 'unsafe-inline' (it remains a fallback for very old browsers).",
        fix: "Safe to keep as a fallback; or remove it once you no longer support pre-2016 browsers.",
      });
    } else {
      out.push({
        rule: "unsafe-inline",
        category: "xss",
        severity: "error",
        directive: where,
        source: UNSAFE_INLINE,
        title: "'unsafe-inline' in script-src defeats XSS protection",
        message: "Inline <script> blocks and on*= handlers execute — exactly what CSP is meant to stop.",
        fix: "Remove 'unsafe-inline' and use a per-request nonce (`'nonce-…'`) or hashes, plus `'strict-dynamic'`.",
      });
    }
  }

  if (sources.includes(UNSAFE_EVAL)) {
    out.push({
      rule: "unsafe-eval",
      category: "xss",
      severity: "warning",
      directive: where,
      source: UNSAFE_EVAL,
      title: "'unsafe-eval' allows eval() / new Function()",
      message: "String-to-code execution stays enabled, widening the XSS surface.",
      fix: "Remove 'unsafe-eval' and refactor any eval()/new Function() usage.",
    });
  }

  if (sources.includes(UNSAFE_HASHES)) {
    out.push({
      rule: "unsafe-hashes",
      category: "xss",
      severity: "info",
      directive: where,
      source: UNSAFE_HASHES,
      title: "'unsafe-hashes' permits inline event handlers",
      message: "Allows hashed inline event handlers (on*=) — weaker than moving them to addEventListener.",
      fix: "Prefer external listeners over 'unsafe-hashes' where you can.",
    });
  }

  for (const source of sources) {
    if (source === "*") {
      out.push({
        rule: "wildcard-script",
        category: "xss",
        severity: "error",
        directive: where,
        source,
        title: "Wildcard `*` in script-src",
        message: "Any host can serve scripts — the allowlist is effectively open.",
        fix: "Replace `*` with specific hosts, or a nonce + 'strict-dynamic'.",
      });
      continue;
    }
    const scheme = schemeOf(source);
    if (scheme === "https") {
      out.push({
        rule: "scheme-https-script",
        category: "xss",
        severity: "warning",
        directive: where,
        source,
        title: "`https:` scheme source in script-src",
        message: "Any HTTPS origin can serve scripts — barely narrower than a wildcard.",
        fix: "List specific hosts instead of the bare `https:` scheme.",
      });
    } else if (scheme === "http") {
      out.push({
        rule: "scheme-http-script",
        category: "xss",
        severity: "error",
        directive: where,
        source,
        title: "`http:` scheme source in script-src",
        message: "Allows scripts over plaintext HTTP — trivially man-in-the-middled.",
        fix: "Remove `http:`; serve and allow scripts over HTTPS only.",
      });
    } else if (scheme === "data") {
      out.push({
        rule: "data-uri-script",
        category: "xss",
        severity: "error",
        directive: where,
        source,
        title: "`data:` in script-src",
        message: "data: URIs can carry attacker-controlled JavaScript — a direct XSS vector.",
        fix: "Remove `data:` from script-src.",
      });
    }
  }

  // Allowlisted hosts that enable a bypass — unless strict-dynamic ignores them.
  if (!hasStrictDynamic) {
    const flagged = new Set<string>();
    for (const source of sources) {
      const host = hostOf(source);
      if (!host) continue;
      const bypass = findBypass(host, config.bypassHosts, config.allowHosts);
      if (bypass && !flagged.has(host)) {
        flagged.add(host);
        out.push({
          rule: "bypass-host",
          category: "allowlist",
          severity: "warning",
          directive: where,
          source,
          title: `Allowlisted host enables a CSP bypass: ${host}`,
          message: `${host} ${bypass.reason}, so an attacker can run scripts despite the policy.`,
          fix: "Drop the host and switch to a nonce + 'strict-dynamic' (which ignores host allowlists).",
        });
      }
    }
  } else if (!hasNonceOrHash) {
    out.push({
      rule: "strict-dynamic-no-nonce",
      category: "xss",
      severity: "warning",
      directive: where,
      title: "'strict-dynamic' has no nonce or hash to anchor it",
      message: "'strict-dynamic' ignores host allowlists and trusts script-inserted scripts, but needs a nonce/hash to bootstrap — without one, no scripts load (or you fall back to the allowlist).",
      fix: "Add a per-request `'nonce-…'` (or a hash) alongside 'strict-dynamic'.",
    });
  }

  return out;
}

export function checkMissingDirectives(policy: Policy): Finding[] {
  const out: Finding[] = [];

  const obj = effectiveObject(policy);
  if (!obj || !obj.sources.includes(NONE)) {
    out.push({
      rule: "missing-object-src",
      category: "missing",
      severity: obj ? "info" : "warning",
      directive: "object-src",
      title: obj ? "object-src is not 'none'" : "No object-src (or default-src)",
      message: "<object>/<embed> can load plugins (Flash, PDF) that execute scripts and bypass other directives.",
      fix: "Add `object-src 'none'` unless you genuinely embed plugins.",
    });
  }

  if (!get(policy, "base-uri")) {
    out.push({
      rule: "missing-base-uri",
      category: "missing",
      severity: "warning",
      directive: "base-uri",
      title: "No base-uri",
      message: "An injected <base> tag can rewrite relative script URLs to an attacker's host — bypassing your allowlist.",
      fix: "Add `base-uri 'none'` (or `'self'`). It does not fall back to default-src.",
    });
  }

  if (!get(policy, "frame-ancestors")) {
    out.push({
      rule: "missing-frame-ancestors",
      category: "missing",
      severity: "warning",
      directive: "frame-ancestors",
      title: "No frame-ancestors",
      message: "Nothing stops other sites from framing yours (clickjacking). frame-ancestors replaces X-Frame-Options.",
      fix: "Add `frame-ancestors 'self'` (or `'none'`).",
    });
  }

  if (!get(policy, "default-src")) {
    out.push({
      rule: "missing-default-src",
      category: "missing",
      severity: "info",
      directive: "default-src",
      title: "No default-src fallback",
      message: "Fetch directives you didn't list (connect-src, font-src, …) are unrestricted.",
      fix: "Add a restrictive `default-src` (e.g. `'self'`) as a backstop.",
    });
  }

  return out;
}

export function checkHardening(policy: Policy): Finding[] {
  const out: Finding[] = [];

  if (policy.reportOnly) {
    out.push({
      rule: "report-only",
      category: "meta",
      severity: "info",
      title: "Report-Only policy — it does not block anything",
      message: "Content-Security-Policy-Report-Only reports violations but enforces nothing. Promote it to the enforcing header when ready.",
      fix: "Serve it as `Content-Security-Policy` (not `…-Report-Only`) to actually block.",
    });
  }

  const hasReportUri = !!get(policy, "report-uri");
  const hasReportTo = !!get(policy, "report-to");
  if (hasReportUri && !hasReportTo) {
    out.push({
      rule: "deprecated-report-uri",
      category: "hardening",
      severity: "info",
      directive: "report-uri",
      title: "report-uri is deprecated",
      message: "Modern browsers prefer the `report-to` directive (with a Reporting-Endpoints header).",
      fix: "Add `report-to` alongside `report-uri` (keep both during migration).",
    });
  }

  return out;
}

export function checkEmpty(policy: Policy): Finding[] {
  const meaningful = [...policy.directives.keys()].filter(
    (d) => d !== "report-uri" && d !== "report-to",
  );
  if (meaningful.length === 0) {
    return [
      {
        rule: "empty-policy",
        category: "xss",
        severity: "error",
        title: "Policy has no restricting directives",
        message: "This CSP only configures reporting (or nothing) — it restricts no resources.",
        fix: "Add at least `default-src 'self'` and `object-src 'none'`.",
      },
    ];
  }
  return [];
}
