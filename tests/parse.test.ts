import { describe, expect, it } from "vitest";
import { parsePolicies, isNonce, isHash, schemeOf, hostOf } from "../src/parse.js";

describe("parsePolicies", () => {
  it("parses directives and their source lists", () => {
    const [p] = parsePolicies("default-src 'self'; script-src 'self' https://cdn.example.com");
    expect(p!.directives.get("default-src")).toEqual(["'self'"]);
    expect(p!.directives.get("script-src")).toEqual(["'self'", "https://cdn.example.com"]);
  });

  it("lowercases directive names and keeps the first occurrence", () => {
    const [p] = parsePolicies("SCRIPT-SRC 'self'; script-src 'unsafe-inline'");
    expect(p!.directives.get("script-src")).toEqual(["'self'"]);
  });

  it("splits multiple comma-separated policies", () => {
    const policies = parsePolicies("script-src 'self', default-src 'none'");
    expect(policies).toHaveLength(2);
  });
});

describe("source helpers", () => {
  it("recognizes nonces and hashes", () => {
    expect(isNonce("'nonce-aGVsbG8='")).toBe(true);
    expect(isNonce("'self'")).toBe(false);
    expect(isHash("'sha256-abc123='")).toBe(true);
    expect(isHash("'sha999-x='")).toBe(false);
  });

  it("extracts schemes", () => {
    expect(schemeOf("https:")).toBe("https");
    expect(schemeOf("data:")).toBe("data");
    expect(schemeOf("https://x.com")).toBeNull();
  });

  it("extracts hosts (stripping scheme, port, path)", () => {
    expect(hostOf("https://cdn.example.com:8443/a/b")).toBe("cdn.example.com");
    expect(hostOf("ajax.googleapis.com")).toBe("ajax.googleapis.com");
    expect(hostOf("'self'")).toBeNull();
    expect(hostOf("data:")).toBeNull();
  });
});
