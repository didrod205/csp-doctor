<div align="center">

# 🛡️ csp-doctor

### Lint your Content-Security-Policy for XSS holes — locally, no website to paste into.

[![npm version](https://img.shields.io/npm/v/csp-doctor.svg?color=success)](https://www.npmjs.com/package/csp-doctor)
[![bundle size](https://img.shields.io/bundlephobia/minzip/csp-doctor?label=core%20gzip)](https://bundlephobia.com/package/csp-doctor)
[![CI](https://github.com/didrod205/csp-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/didrod205/csp-doctor/actions/workflows/ci.yml)
[![types](https://img.shields.io/npm/types/csp-doctor.svg)](https://www.npmjs.com/package/csp-doctor)
[![license](https://img.shields.io/npm/l/csp-doctor.svg)](./LICENSE)

**[🌐 Try the browser playground →](https://didrod205.github.io/csp-doctor/)** &nbsp;·&nbsp; paste a CSP, see its XSS holes ranked. Nothing is uploaded — it all runs client-side.

</div>

You added a `Content-Security-Policy` to stop XSS. But a single `'unsafe-inline'`
in `script-src` silently turns the whole thing off, a wildcard or bare `https:`
lets any host serve scripts, and allowlisting a CDN like `ajax.googleapis.com`
opens a JSONP/AngularJS bypass — so an attacker runs scripts *despite* your policy.
The only good analyzer, Google's CSP Evaluator, is **a website you paste into** —
not something you can run in CI.

**csp-doctor lints a CSP for these holes locally and deterministically** — from a
string, an HTML `<meta>`, or a headers file — and it's **nonce / hash /
strict-dynamic aware**, so it won't cry wolf about an `'unsafe-inline'` that
modern browsers already ignore.

```bash
npx csp-doctor scan -p "default-src 'self'; script-src 'self' 'unsafe-inline' ajax.googleapis.com"
```

```
policy  57/100 (F)
  ✗ 'unsafe-inline' in script-src defeats XSS protection            [script-src]
  ⚠ Allowlisted host enables a CSP bypass: ajax.googleapis.com      [script-src]
  ⚠ No base-uri                                                     [base-uri]
  ⚠ No frame-ancestors                                              [frame-ancestors]
```

---

## Why csp-doctor?

- 🎯 **It knows the bypasses.** The built-in list of hosts that undermine an
  allowlist (JSONP endpoints, hosted AngularJS) is the core insight behind Google's
  CSP Evaluator — baked in for offline use.
- 🧠 **Nonce / hash / strict-dynamic aware.** It understands that a nonce makes
  `'unsafe-inline'` a harmless fallback, and that `'strict-dynamic'` ignores host
  allowlists — so it grades a *modern* CSP correctly instead of flagging everything.
- 🔒 **Local & deterministic.** No website, no API key, runs offline and in CI.
  Same policy → same result. Fail the PR that ships `'unsafe-inline'`.
- 🧩 **Reads it from anywhere.** A raw policy, an HTML `<meta http-equiv>`, an
  `_headers` file, nginx `add_header`, Apache `Header set`, or `vercel.json`.

Why not paste it into an LLM? The bypassable-host list and directive-fallback rules
(`script-src` → `default-src`, `base-uri` doesn't fall back) are exact, evolving
facts a chatbot gets wrong — and you need this gating *every* CSP change, not once.

## Install

```bash
# run it now
npx csp-doctor scan -p "<your CSP>"

# or add it
npm install -g csp-doctor      # global CLI
npm install -D csp-doctor      # CI dependency
```

Node ≥ 18. The core is dependency-free and browser-safe (ready for a web playground).

## Quick start

```bash
csp-doctor scan -p "default-src 'self'; script-src 'self' 'nonce-abc'"   # a string
csp-doctor scan index.html                                               # from <meta>
csp-doctor scan _headers vercel.json                                     # from configs
curl -sI https://example.com | csp-doctor scan                           # from live headers
csp-doctor scan -p "<csp>" --min-score 80                                # CI gate
csp-doctor init                                                          # write a config
```

See [`examples/sample-report.md`](./examples/sample-report.md), and
[`examples/strong.csp.txt`](./examples/strong.csp.txt) for a policy that scores 100.

## What it checks

| Group | Examples |
| ----- | -------- |
| **XSS exposure** | `'unsafe-inline'` (error — or info when a nonce/hash makes it moot), `'unsafe-eval'`, wildcard `*`, bare `https:`/`http:`, `data:` in `script-src` |
| **Allowlist bypass** | hosts known to break a CSP allowlist (JSONP / hosted AngularJS), unless `'strict-dynamic'` neutralizes the allowlist |
| **Missing directives** | no `object-src 'none'`, no `base-uri`, no `frame-ancestors`, no `default-src` fallback |
| **Hardening & meta** | `'strict-dynamic'` without a nonce, deprecated `report-uri`, and Report-Only policies (which **block nothing**) |

Each finding is a weighted error / warning / info; the policy rolls up to a 0–100
score and an A–F grade you can gate in CI.

## Real scenarios

**1. Gate your CSP in CI.** A PR that adds `'unsafe-inline'` or a bypassable CDN to
your policy fails the build:

```yaml
# .github/workflows/ci.yml
- run: npx csp-doctor scan next.config.js --min-score 85   # or your _headers / meta
```

**2. Audit a policy before you ship it.** Paste the header you're about to deploy
and see the holes — locally, without sending your config to a third-party site.

**3. Triage a security finding.** A scanner said "weak CSP" — `csp-doctor scan` tells
you *which* directive and *why*, with the exact fix.

## Configuration

`csp-doctor init` writes `csp-doctor.config.json`:

```jsonc
{
  "ignore": [],          // rule ids to skip, e.g. ["missing-default-src"]
  "bypassHosts": [],     // extra hosts to treat as bypass-prone
  "allowHosts": [],      // hosts you've audited and accept (suppress the finding)
  "minScore": 0          // CI gate threshold
}
```

## Library API

```ts
import { analyzeCsp, DEFAULT_CONFIG } from "csp-doctor";

const [report] = analyzeCsp("inline", "script-src 'self' 'unsafe-inline'", DEFAULT_CONFIG);
for (const f of report.findings) console.log(f.severity, f.rule, f.directive);
```

Also exported: `analyzePolicy`, `parsePolicies`, `extractPolicies`, `findBypass`,
`BYPASS_HOSTS`, and types. The core has zero runtime dependencies.

## Roadmap

- 🤖 **Optional `--ai` layer (bring-your-own key)** to draft a hardened
  replacement policy for your app. The core stays 100% offline and deterministic.
- `require-trusted-types-for` / Trusted Types scoring.
- `style-src` and `connect-src` specific checks (CSS exfiltration, beacon hosts).
- Suggest the migration to a nonce + `'strict-dynamic'` policy automatically.
- ✅ **A browser playground** — paste a policy, see the audit, nothing uploaded.
  [Live here](https://didrod205.github.io/csp-doctor/).

## 💖 Sponsor

csp-doctor is free and MIT-licensed, built and maintained in spare time. If it caught
a hole in your CSP, please consider supporting it:

- ⭐ **Star this repo** — the simplest free way to help others find it.
- 🍋 **[Sponsor via Lemon Squeezy](https://elab-studio.lemonsqueezy.com/checkout/buy/5d059b89-51d0-456b-b33a-ed56994f7010)** — one-time or recurring.

> The bypassable-host insight is owed to the research behind
> [Google's CSP Evaluator](https://csp-evaluator.withgoogle.com). csp-doctor is an
> independent, offline implementation and is not affiliated with it.

## License

[MIT](./LICENSE) © csp-doctor contributors
