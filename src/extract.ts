/**
 * Pull CSP policy strings out of whatever the user points us at: a raw policy,
 * an HTML file's `<meta http-equiv>`, an HTTP headers file (`_headers`, nginx
 * `add_header`, Apache `Header set`), or a JSON config (e.g. vercel.json).
 */

export interface Extracted {
  policy: string;
  reportOnly: boolean;
  label: string;
}

const META_RE = /<meta\b[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi;
const META_CONTENT_RE = /content\s*=\s*("([^"]*)"|'([^']*)')/i;
const HEADER_RE = /content-security-policy(-report-only)?\s*:\s*(.+)/gi;
const DIRECTIVE_RE = /(?:add_header|Header\s+set)\s+Content-Security-Policy(-Report-Only)?\s+(?:"([^"]*)"|'([^']*)')/gi;

function dedupe(items: Extracted[]): Extracted[] {
  const seen = new Set<string>();
  return items.filter((i) => {
    const key = `${i.reportOnly}|${i.policy}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return i.policy.trim().length > 0;
  });
}

function fromJson(content: string): Extracted[] {
  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch {
    return [];
  }
  const out: Extracted[] = [];
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const item of node) walk(item);
      return;
    }
    if (node && typeof node === "object") {
      const obj = node as Record<string, unknown>;
      const key = typeof obj.key === "string" ? obj.key.toLowerCase() : "";
      if (key.startsWith("content-security-policy") && typeof obj.value === "string") {
        out.push({ policy: obj.value, reportOnly: key.endsWith("report-only"), label: "json" });
      }
      // Direct { "Content-Security-Policy": "..." } form.
      for (const [k, v] of Object.entries(obj)) {
        if (k.toLowerCase().startsWith("content-security-policy") && typeof v === "string") {
          out.push({ policy: v, reportOnly: k.toLowerCase().endsWith("report-only"), label: "json" });
        }
        if (v && typeof v === "object") walk(v);
      }
    }
  };
  walk(data);
  return out;
}

export function extractPolicies(content: string, label = "policy"): Extracted[] {
  // 1. HTML <meta>.
  const metas: Extracted[] = [];
  for (const tag of content.match(META_RE) ?? []) {
    const m = META_CONTENT_RE.exec(tag);
    const value = m ? (m[2] ?? m[3] ?? "") : "";
    if (value.trim()) metas.push({ policy: value, reportOnly: false, label: "meta" });
  }
  if (metas.length) return dedupe(metas);

  // 2. nginx/Apache directives.
  const directives: Extracted[] = [];
  let dm: RegExpExecArray | null;
  DIRECTIVE_RE.lastIndex = 0;
  while ((dm = DIRECTIVE_RE.exec(content)) !== null) {
    directives.push({ policy: (dm[2] ?? dm[3])!, reportOnly: !!dm[1], label: "header" });
  }
  if (directives.length) return dedupe(directives);

  // 3. JSON config.
  const json = fromJson(content);
  if (json.length) return dedupe(json);

  // 4. Header lines (`Content-Security-Policy: …`).
  const headers: Extracted[] = [];
  let hm: RegExpExecArray | null;
  HEADER_RE.lastIndex = 0;
  while ((hm = HEADER_RE.exec(content)) !== null) {
    headers.push({ policy: hm[2]!.trim(), reportOnly: !!hm[1], label: "header" });
  }
  if (headers.length) return dedupe(headers);

  // 5. Treat the whole thing as a raw policy.
  const trimmed = content.trim();
  return trimmed ? [{ policy: trimmed, reportOnly: false, label }] : [];
}
