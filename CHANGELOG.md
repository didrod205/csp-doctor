# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-06-05

Docs/metadata release — the published library and CLI (`dist/`) are unchanged
from 0.1.0.

### Added

- A **browser playground** — paste a Content-Security-Policy to see its XSS holes
  ranked, entirely client-side (the same pure analysis core; nothing uploaded).
  Live at <https://didrod205.github.io/csp-doctor/>. README now links it.
- Internal: the playground source (`web/`, built to `docs/` for GitHub Pages).
  Not part of the npm package.

## [0.1.0] - 2026-06-04

Initial public release.

### Added

- **CSP weakness analysis**: `'unsafe-inline'` / `'unsafe-eval'` / `'unsafe-hashes'`,
  wildcards, bare `https:`/`http:`/`data:` script sources, missing `object-src`/
  `base-uri`/`frame-ancestors`/`default-src`, deprecated `report-uri`, and
  Report-Only policies (which block nothing).
- **Allowlist-bypass detection** against a built-in list of hosts known to
  undermine a CSP (JSONP endpoints, hosted AngularJS), with CSP/known wildcard
  matching — the core insight behind Google's CSP Evaluator, offline.
- **Nonce / hash / strict-dynamic awareness**: `'unsafe-inline'` is downgraded to
  info when a nonce/hash makes it moot, host-bypass findings are suppressed under
  `'strict-dynamic'`, and `'strict-dynamic'` without a nonce is flagged.
- **Directive fallback model** (`script-src`/`object-src` → `default-src`; `base-uri`/
  `frame-ancestors` don't fall back).
- **Extraction** from a raw string, HTML `<meta http-equiv>`, `_headers`, nginx
  `add_header`, Apache `Header set`, and JSON configs (vercel.json).
- `scan`/`report`/`init` CLI with `--policy`, stdin, JSON/Markdown export, and a CI
  score gate. Zero-dependency, browser-safe core; library API + types.
