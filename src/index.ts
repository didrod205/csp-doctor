/**
 * csp-doctor — lint a Content-Security-Policy for XSS holes, locally and
 * deterministically. Parses a CSP and flags 'unsafe-inline', wildcards, missing
 * object-src/base-uri/frame-ancestors, and allowlisted hosts known to bypass CSP
 * — nonce/hash/strict-dynamic aware. No website, no API key.
 *
 * ```ts
 * import { analyzeCsp, DEFAULT_CONFIG } from "csp-doctor";
 * const [report] = analyzeCsp("policy", "script-src 'self' 'unsafe-inline'", DEFAULT_CONFIG);
 * ```
 */

export { analyzePolicy, analyzeCsp, buildReport } from "./analyze.js";
export { parsePolicies, hostOf, schemeOf, isNonce, isHash } from "./parse.js";
export { extractPolicies, type Extracted } from "./extract.js";
export { effective, effectiveScript, effectiveObject } from "./directives.js";
export { BYPASS_HOSTS, findBypass, type BypassHost } from "./hosts.js";
export {
  checkScriptSrc,
  checkMissingDirectives,
  checkHardening,
  checkEmpty,
} from "./checks.js";
export { scoreFindings, gradeFor } from "./score.js";
export { DEFAULT_CONFIG, CONFIG_FILENAMES, parseConfig, mergeConfig } from "./config.js";
export {
  CATEGORIES,
  CATEGORY_LABELS,
  type Category,
  type Config,
  type Finding,
  type Policy,
  type PolicyReport,
  type Report,
  type Severity,
} from "./types.js";
