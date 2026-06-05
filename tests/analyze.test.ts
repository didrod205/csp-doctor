import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { analyzeCsp, buildReport } from "../src/analyze.js";
import { loadFromContent } from "../src/loader.js";
import { analyzePolicy } from "../src/analyze.js";
import { parsePolicies } from "../src/parse.js";
import { DEFAULT_CONFIG } from "../src/config.js";

const read = (f: string) => readFileSync(resolve("examples", f), "utf8");
const META = { version: "test", generatedAt: "2026-06-04T00:00:00Z" };
const idsOf = (csp: string) =>
  new Set(analyzeCsp("t", csp, DEFAULT_CONFIG).flatMap((p) => p.findings.map((f) => f.rule)));

describe("analyzeCsp (integration)", () => {
  it("scores a modern nonce + strict-dynamic policy an A", () => {
    const [r] = analyzeCsp("strong", read("strong.csp.txt").trim(), DEFAULT_CONFIG);
    expect(r!.grade).toBe("A");
    expect(r!.counts.error).toBe(0);
  });

  it("fails a permissive policy and lists its holes", () => {
    const ids = idsOf(read("weak.csp.txt").trim());
    expect(ids.has("unsafe-inline")).toBe(true);
    expect(ids.has("unsafe-eval")).toBe(true);
    expect(ids.has("bypass-host")).toBe(true);
    expect(ids.has("missing-frame-ancestors")).toBe(true);
  });

  it("extracts and analyzes a policy from an HTML file", () => {
    const inputs = loadFromContent(read("page.html"), "page.html");
    expect(inputs).toHaveLength(1);
    const reports = inputs.flatMap((i) =>
      parsePolicies(i.policy, i.reportOnly, i.source).map((p) => analyzePolicy(i.source, p, DEFAULT_CONFIG)),
    );
    expect(reports[0]!.source).toContain("(meta)");
    expect(reports[0]!.findings.some((f) => f.rule === "unsafe-inline")).toBe(true);
  });

  it("respects the ignore list", () => {
    const reports = analyzeCsp("t", "script-src 'unsafe-inline'", { ...DEFAULT_CONFIG, ignore: ["unsafe-inline"] });
    expect(reports[0]!.findings.some((f) => f.rule === "unsafe-inline")).toBe(false);
  });

  it("flags an empty / reporting-only policy as having no restrictions", () => {
    expect(idsOf("report-uri /csp").has("empty-policy")).toBe(true);
  });

  it("buildReport aggregates policies", () => {
    const report = buildReport(
      [
        ...analyzeCsp("a", read("strong.csp.txt").trim(), DEFAULT_CONFIG),
        ...analyzeCsp("b", read("weak.csp.txt").trim(), DEFAULT_CONFIG),
      ],
      META,
    );
    expect(report.summary.policies).toBe(2);
    expect(report.summary.errors).toBeGreaterThan(0);
  });
});
