# Contributing to cspcheck

Thanks for your interest! Most contributions are a new weakness rule or an
addition to the bypassable-host list — both small and data-driven.

## Getting started

```bash
git clone https://github.com/didrod205/cspcheck.git
cd cspcheck
npm install
npm test            # vitest
npm run typecheck   # tsc --noEmit
npm run build       # tsup → dist/
node dist/cli.js scan examples/weak.csp.txt
```

## Project layout

```
src/
  parse.ts          # CSP string → policies/directives/sources (+ source helpers)
  directives.ts     # directive fallback model (script-src → default-src, …)
  hosts.ts          # the bypassable-host list + matching (the data moat)
  checks.ts         # the weakness rule set (nonce/hash/strict-dynamic aware)
  extract.ts        # pull CSP from raw / <meta> / headers / JSON
  analyze.ts        # orchestrator + report builder
  score.ts          # weighted score + grade
  config.ts         # pure defaults/merge      load-config.ts # fs loading
  loader.ts         # read files / stdin
  report/           # console / json / markdown
  cli.ts            # cac CLI
tests/              # vitest specs (incl. integration over examples/)
examples/           # weak / strong CSPs + an HTML page
```

## Adding a bypass host

Edit `BYPASS_HOSTS` in `src/hosts.ts` with the `host` and a `reason` (why it
allows a bypass — JSONP endpoint, hosted Angular, etc.). **Cite the source** in the
PR; a wrong entry trains people to ignore the tool. Add a test in
`tests/hosts.test.ts`.

## Adding a weakness rule

Add a check to `src/checks.ts` returning `Finding[]`, register it in `analyze.ts`,
and add a positive + negative test in `tests/checks.test.ts`.

## Quality bar

- [ ] Rules are nonce/hash/strict-dynamic aware where relevant (no false alarms on
      a correct modern policy — `strong.csp.txt` must stay 100/100).
- [ ] Values reflect the CSP spec / documented browser behaviour.
- [ ] `npm run typecheck && npm test && npm run build` all pass.
- [ ] Regenerated `examples/sample-report.*` if output changed.
