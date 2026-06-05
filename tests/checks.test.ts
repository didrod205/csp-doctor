import { describe, expect, it } from "vitest";
import { parsePolicies } from "../src/parse.js";
import { checkScriptSrc, checkMissingDirectives, checkHardening } from "../src/checks.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import type { Config } from "../src/types.js";

function script(csp: string, config: Config = DEFAULT_CONFIG) {
  return checkScriptSrc(parsePolicies(csp)[0]!, config);
}
const rules = (fs: { rule: string }[]) => fs.map((f) => f.rule);

describe("checkScriptSrc", () => {
  it("flags 'unsafe-inline' as an error when nothing mitigates it", () => {
    const f = script("script-src 'self' 'unsafe-inline'").find((x) => x.rule === "unsafe-inline");
    expect(f?.severity).toBe("error");
  });

  it("downgrades 'unsafe-inline' to info when a nonce is present", () => {
    const r = rules(script("script-src 'self' 'nonce-abc==' 'unsafe-inline'"));
    expect(r).toContain("unsafe-inline-ignored");
    expect(r).not.toContain("unsafe-inline");
  });

  it("flags unsafe-eval, wildcard and data: in script-src", () => {
    expect(rules(script("script-src 'unsafe-eval'"))).toContain("unsafe-eval");
    expect(rules(script("script-src *"))).toContain("wildcard-script");
    expect(rules(script("script-src data:"))).toContain("data-uri-script");
  });

  it("flags a bypassable allowlisted host", () => {
    expect(rules(script("script-src 'self' ajax.googleapis.com"))).toContain("bypass-host");
  });

  it("suppresses the host bypass finding when 'strict-dynamic' is present", () => {
    const r = rules(script("script-src 'nonce-x==' 'strict-dynamic' ajax.googleapis.com"));
    expect(r).not.toContain("bypass-host");
  });

  it("warns when 'strict-dynamic' has no nonce or hash", () => {
    expect(rules(script("script-src 'strict-dynamic' 'self'"))).toContain("strict-dynamic-no-nonce");
  });

  it("falls back to default-src when script-src is absent", () => {
    expect(rules(script("default-src 'self' 'unsafe-inline'"))).toContain("unsafe-inline");
  });

  it("flags a total absence of script restriction", () => {
    expect(rules(script("img-src 'self'"))).toContain("no-script-src");
  });
});

describe("checkMissingDirectives", () => {
  const missing = (csp: string) => rules(checkMissingDirectives(parsePolicies(csp)[0]!));

  it("flags missing object-src, base-uri and frame-ancestors", () => {
    const r = missing("script-src 'self'");
    expect(r).toEqual(expect.arrayContaining(["missing-object-src", "missing-base-uri", "missing-frame-ancestors"]));
  });

  it("is satisfied by a locked-down policy", () => {
    const r = missing("default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    expect(r).not.toContain("missing-object-src");
    expect(r).not.toContain("missing-base-uri");
    expect(r).not.toContain("missing-frame-ancestors");
  });
});

describe("checkHardening", () => {
  it("flags a report-only policy", () => {
    const p = parsePolicies("script-src 'self'", true)[0]!;
    expect(rules(checkHardening(p))).toContain("report-only");
  });
});
