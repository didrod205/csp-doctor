import { describe, expect, it } from "vitest";
import { extractPolicies } from "../src/extract.js";

describe("extractPolicies", () => {
  it("pulls a policy from an HTML <meta http-equiv>", () => {
    const html = `<meta http-equiv="Content-Security-Policy" content="default-src 'self'">`;
    const r = extractPolicies(html);
    expect(r).toHaveLength(1);
    expect(r[0]!.policy).toBe("default-src 'self'");
    expect(r[0]!.label).toBe("meta");
  });

  it("pulls a policy from an HTTP header line, marking report-only", () => {
    const r = extractPolicies("Content-Security-Policy-Report-Only: script-src 'self'");
    expect(r[0]!.policy).toBe("script-src 'self'");
    expect(r[0]!.reportOnly).toBe(true);
  });

  it("pulls a policy from an nginx add_header directive", () => {
    const conf = `add_header Content-Security-Policy "default-src 'self'; object-src 'none'";`;
    expect(extractPolicies(conf)[0]!.policy).toBe("default-src 'self'; object-src 'none'");
  });

  it("pulls a policy from a vercel.json-style config", () => {
    const json = JSON.stringify({
      headers: [{ source: "/(.*)", headers: [{ key: "Content-Security-Policy", value: "default-src 'self'" }] }],
    });
    expect(extractPolicies(json)[0]!.policy).toBe("default-src 'self'");
  });

  it("treats a bare string as a raw policy", () => {
    const r = extractPolicies("script-src 'self' 'unsafe-inline'");
    expect(r[0]!.policy).toBe("script-src 'self' 'unsafe-inline'");
    expect(r[0]!.label).toBe("policy");
  });

  it("returns nothing for empty input", () => {
    expect(extractPolicies("   ")).toHaveLength(0);
  });
});
