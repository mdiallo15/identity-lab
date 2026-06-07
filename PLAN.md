# identity-lab — Plan & Notes

Living doc. Update as work lands. Keep entries short. Newest at top.

---

## Current state (June 2026)

- **Branch:** `main` clean.
- **Stack:** Next.js (App Router), TypeScript.
- **Labs shipped:** CSP (analyzer + sandbox + bypasses), Identity (passkey,
  JWT, JWT forging workbench, agent identity, phishing-resistant), Authz
  (patterns + simulator), SSRF (analyzer + targets + hardening), Prompt
  Injection (patterns + simulator + defenses), IAM PrivEsc, Detection
  Engineering, Supply Chain v2, RAG, Agent Identity (attestation, inventory,
  token-exchange).
- **APIs:** passkey register/authenticate, scan, ssrf-test, ssrf-fetch.
- **Lib modules:** one per lab domain.
- **Tracker state:** `TASKS.md` Ready queue empty, Blocked empty.
- **Release state:** latest shipped backlog commit completed local validation; GitHub CI / Security Scan / CodeQL green.

## Recently completed

- `016fe93` — Final backlog closeout: per-lab Open Graph/Twitter metadata, server wrappers for `/iam-privesc` and `/rag`, JWT vector verification script, `TASKS.md` / `PROMPT.md` zero-backlog cleanup (T-19, T-20).
- `cde12d4` — OpenAPI document, CodeQL workflow, native sitemap and robots metadata routes (T-16, T-17, T-18).
- `84851b5` — Scenario deep-link sweep across SSRF, Prompt Injection, IAM PrivEsc, and Detection Engineering; kickoff prompt updated for autonomous continuation (T-09, T-10, T-11, T-12).
- `9794d3a` — Converted the remaining static routes into live labs: phishing-resistant MFA, CSP bypasses, AuthZ patterns, CSP shapes; README sync; shared LabFrame.
- `13db94a` — `/api/scan` hardened against DNS rebinding via Node DNS re-resolution and redirect revalidation (T-24).
- `13e8b37` — Next.js upgrade to clear CI audit gate (T-23).

- `192fa5c` — SARIF 2.1.0 export verification: zero-dep validator + CI script covering all 5 lab surfaces (T-03).
- `c6a7e73` — Agent Identity token-exchange: 3 decoded JWTs side-by-side + claims diff (T-02).
- `983bc6b` — JWT forging workbench: copy-as-curl affordance with per-attack reproduction notes (T-01).
- `044bdde` — SSRF v2: live fetcher sandbox, 10 scenarios, naive vs hardened, `/api/ssrf-fetch`.
- `a80e156` — Prompt Injection v2: live tool-call agent loop, 5 tools, 12 scenarios, telemetry export.
- `8cb1938` — Cross-linked /identity/jwt and /identity/forge; 'What this proves' panel on the workbench.
- `691980b` — Identity Lab v2: JWT forging workbench.
- `9067e49` — Azure IAM scenario accuracy fix.
- `7bdb9cd` — IAM PrivEsc + Detection Engineering labs.
- `f649794` — Supply Chain v2 made interactive.
- `3fbcbff` — New labs: Supply Chain + RAG Security.

## Next up

_No active backlog. Add new tasks to `TASKS.md` before the next autonomous session._

## In progress

- _(none)_

## Backlog / ideas

- E2E test (Playwright) covering one happy path per lab.
- Any newly discovered content gaps, lab ideas, or repo-platform improvements should be added to `TASKS.md` first, then reflected here only if they remain intentionally deferred.

## Conventions

- Commit per logical change; short imperative subject lines.
- Update this file when finishing or starting non-trivial work.
- Each lab should be independently demoable from its index page.
