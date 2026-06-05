import { describe, expect, it } from "vitest";
import { findBypass } from "../src/hosts.js";

describe("findBypass", () => {
  it("flags a known bypass host exactly", () => {
    expect(findBypass("ajax.googleapis.com")?.host).toBe("ajax.googleapis.com");
    expect(findBypass("cdn.jsdelivr.net")).not.toBeNull();
  });

  it("does not flag a benign host", () => {
    expect(findBypass("cdn.mycompany.com")).toBeNull();
    expect(findBypass("self.example.org")).toBeNull();
  });

  it("matches a CSP wildcard that covers a bypass subdomain", () => {
    // Allowlisting *.googleapis.com covers ajax.googleapis.com (bypassable).
    expect(findBypass("*.googleapis.com")).not.toBeNull();
  });

  it("matches a specific host against a known wildcard entry", () => {
    // The list has *.googleapis.com; a specific subdomain should match it.
    expect(findBypass("translate.googleapis.com")).not.toBeNull();
  });

  it("honors user-supplied extra and allow lists", () => {
    expect(findBypass("evil.cdn.net", ["evil.cdn.net"])?.reason).toMatch(/user-flagged/);
    expect(findBypass("ajax.googleapis.com", [], ["ajax.googleapis.com"])).toBeNull();
  });
});
