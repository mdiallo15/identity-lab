# identity-lab — Plan & Notes

Living doc. Update as work lands. Keep entries short. Newest at top.

---

## Current state (May 2026)

- **Branch:** `main` clean.
- **Stack:** Next.js (App Router), TypeScript.
- **Labs shipped:** CSP (analyzer + sandbox + bypasses), Identity (passkey,
  JWT, JWT forging workbench, agent identity, phishing-resistant), Authz
  (patterns + simulator), SSRF (analyzer + targets + hardening), Prompt
  Injection (patterns + simulator + defenses), IAM PrivEsc, Detection
  Engineering, Supply Chain v2, RAG, Agent Identity (attestation, inventory,
  token-exchange).
- **APIs:** passkey register/authenticate, scan, ssrf-test.
- **Lib modules:** one per lab domain.

## Recently completed

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

_Pick one and start. Move to "In progress" when picked up._

- [ ] Agent Identity: end-to-end token-exchange demo wiring (T-02).
- [ ] SARIF export verification across labs (T-03).
- [ ] Detection Engineering: at least one canned ruleset per lab (T-04).
- [ ] Landing page: surface the new labs above the fold (T-05).

## In progress

- _(none)_

## Backlog / ideas

- Per-lab "what you should learn" callout box, consistent across labs.
- Shared lab chrome component to reduce drift between labs.
- E2E test (Playwright) covering one happy path per lab.
- Public deploy + linkable scenario URLs (`?scenario=` query param everywhere).
- Threat-model card per lab page.

## Conventions

- Commit per logical change; short imperative subject lines.
- Update this file when finishing or starting non-trivial work.
- Each lab should be independently demoable from its index page.
