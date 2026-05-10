# identity-lab — Tasks

Atomic, agent-runnable tasks. Each is small enough to finish + commit in one
session. Pick the top unblocked task, do it, commit, move it to "Done".

**Agent rules**
- Read `PLAN.md` and this file before starting.
- Pick the topmost unchecked task in "Ready". Move it to "In progress".
- Make the change, run `npm run build` (or `next build`) and lint. Fix issues
  you introduce.
- Commit with a short imperative subject. Do not push unless asked.
- Move the task to "Done" with the commit SHA. Update `PLAN.md` if needed.

---

## In progress

- _(none)_

## Ready (ordered, top = next)

### T-01 — JWT forging workbench: polish + cross-link
- **Files:** `app/identity/forge/page.tsx`, `app/identity/jwt/page.tsx`,
  `lib/jwt-forge.ts`.
- **Do:** Add inline links from `/identity/jwt` to `/identity/forge`. Ensure
  the workbench has a clear "what this proves" panel and a copy-as-curl
  affordance for any HTTP scenarios.
- **Done when:** Both pages cross-link; workbench has explanatory panel and
  copy-curl works for at least one scenario.

### T-02 — Agent Identity: token-exchange end-to-end demo
- **Files:** `app/agent-identity/token-exchange/page.tsx`,
  `lib/agent-identity.ts`, possibly a new mock issuer route under
  `app/api/`.
- **Do:** Wire a mock STS that performs RFC 8693 token exchange between a
  user token and an agent-scoped token. Show input/output JWTs decoded
  side-by-side. No real OAuth provider required.
- **Done when:** User can click "Exchange" and see decoded source + exchanged
  token with claims diff highlighted.

### T-03 — SARIF export verification across labs
- **Files:** `lib/sarif.ts`, `app/_components/export-buttons.tsx`, all lab
  pages that surface findings.
- **Do:** For every lab that currently exports SARIF, verify the file
  validates against the SARIF 2.1.0 schema (use `ajv` locally or the SARIF
  validator). Fix any schema violations.
- **Done when:** All exported SARIF files validate; commit notes which labs
  were audited.

### T-04 — Detection Engineering: one canned ruleset per lab
- **Files:** `lib/detection.ts`, `app/detection-engineering/page.tsx`.
- **Do:** For each lab domain (CSP, JWT, SSRF, IAM, Supply Chain, RAG,
  Prompt Injection, Agent Identity), provide at least one detection rule
  (Sigma or pseudo-Sigma) with a short rationale.
- **Done when:** Detection page lists rules grouped by lab; each rule has
  rationale + suggested data source.

### T-05 — Home page: surface new labs above the fold
- **Files:** `app/page.tsx`, `app/_components/`.
- **Do:** Reorder the lab grid so the most recent labs (JWT forge, Agent
  Identity, IAM PrivEsc, Detection Engineering, Supply Chain v2, RAG)
  appear first with a "new" pill. No new deps.
- **Done when:** Home reflects current lab inventory; "new" pills auto-clear
  via a `since` date in `lib/`.

## Blocked

- _(none)_

## Done

- _(none yet — move completed tasks here with commit SHA)_

## Notes

- Each task is intentionally scoped to ~1 commit. Split if it grows.
- If a task reveals a larger problem, stop, write a new task for it, and
  flag the original as Blocked.
