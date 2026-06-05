import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_CONFIG, parseConfig, mergeConfig } from "../src/config.js";
import { loadConfig } from "../src/load-config.js";

describe("config", () => {
  it("parses and merges over defaults", () => {
    const cfg = parseConfig(JSON.stringify({ minScore: 80, allowHosts: ["cdn.jsdelivr.net"] }));
    expect(cfg.minScore).toBe(80);
    expect(cfg.allowHosts).toEqual(["cdn.jsdelivr.net"]);
    expect(cfg.ignore).toEqual(DEFAULT_CONFIG.ignore);
  });

  it("throws a clear error on invalid JSON", () => {
    expect(() => parseConfig("{ broken")).toThrow(/invalid config/);
  });

  it("mergeConfig ignores undefined overrides", () => {
    const cfg = mergeConfig(DEFAULT_CONFIG, { minScore: undefined as unknown as number });
    expect(cfg.minScore).toBe(DEFAULT_CONFIG.minScore);
  });

  it("loadConfig returns defaults when no file is present", () => {
    const dir = mkdtempSync(join(tmpdir(), "cspcheck-"));
    expect(loadConfig(undefined, dir).minScore).toBe(DEFAULT_CONFIG.minScore);
    rmSync(dir, { recursive: true, force: true });
  });

  it("loadConfig reads an explicit file", () => {
    const dir = mkdtempSync(join(tmpdir(), "cspcheck-"));
    const file = join(dir, "cspcheck.config.json");
    writeFileSync(file, JSON.stringify({ minScore: 70 }));
    expect(loadConfig(file).minScore).toBe(70);
    rmSync(dir, { recursive: true, force: true });
  });
});
