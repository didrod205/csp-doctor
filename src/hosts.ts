/**
 * Hosts known to undermine a CSP allowlist — the data moat. Allowlisting any of
 * these in `script-src` lets an attacker bypass the policy, because they host
 * JSONP endpoints (callback=… returns attacker-controlled JS) or copies of
 * AngularJS/Angular (whose template engine is a known CSP-bypass gadget). This
 * is the core insight behind Google's CSP Evaluator, baked in for offline use.
 */

export interface BypassHost {
  host: string;
  reason: string;
}

export const BYPASS_HOSTS: BypassHost[] = [
  { host: "ajax.googleapis.com", reason: "hosts AngularJS (CSP-bypass gadget)" },
  { host: "*.googleapis.com", reason: "JSONP endpoints + hosted libraries" },
  { host: "www.googleapis.com", reason: "JSONP endpoints" },
  { host: "www.google.com", reason: "JSONP endpoints (e.g. /complete/search)" },
  { host: "translate.googleapis.com", reason: "JSONP endpoint" },
  { host: "cdnjs.cloudflare.com", reason: "hosts AngularJS / Angular" },
  { host: "cdn.jsdelivr.net", reason: "hosts AngularJS / arbitrary npm packages" },
  { host: "unpkg.com", reason: "serves arbitrary npm packages (incl. Angular)" },
  { host: "ajax.aspnetcdn.com", reason: "Microsoft Ajax CDN hosts Angular" },
  { host: "yandex.st", reason: "hosts AngularJS" },
  { host: "api.flickr.com", reason: "JSONP endpoint" },
  { host: "cdn.rawgit.com", reason: "serves arbitrary GitHub-hosted scripts" },
  { host: "rawgit.com", reason: "serves arbitrary GitHub-hosted scripts" },
  { host: "swiftype.com", reason: "JSONP endpoint" },
];

function normalize(host: string): string {
  return host.toLowerCase().replace(/\.$/, "");
}

/** Does allowlisting `cspHost` permit loading from a known bypass host? */
function covers(cspHost: string, known: string): boolean {
  const a = normalize(cspHost);
  const b = normalize(known);
  if (a === b) return true;
  // CSP wildcard `*.x.com` covers any subdomain `a.x.com`.
  if (a.startsWith("*.")) {
    const suffix = a.slice(1); // ".x.com"
    if (b === a.slice(2) || b.endsWith(suffix)) return true;
  }
  // Known wildcard `*.x.com` is matched by a specific allowlisted subdomain.
  if (b.startsWith("*.")) {
    const suffix = b.slice(1);
    if (a === b.slice(2) || a.endsWith(suffix)) return true;
  }
  return false;
}

/** Return the matching bypass host (with reason) for a CSP host source, if any. */
export function findBypass(
  cspHost: string,
  extra: string[] = [],
  allow: string[] = [],
): BypassHost | null {
  if (allow.some((h) => normalize(h) === normalize(cspHost))) return null;
  const list: BypassHost[] = [...BYPASS_HOSTS, ...extra.map((h) => ({ host: h, reason: "user-flagged host" }))];
  for (const entry of list) {
    if (covers(cspHost, entry.host)) return entry;
  }
  return null;
}
