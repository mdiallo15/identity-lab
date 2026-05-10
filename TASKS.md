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

### T-01c — SSRF v2: live fetcher sandbox

- **Files:** `app/ssrf/analyzer/page.tsx`, new `app/api/ssrf-fetch/route.ts`, `lib/ssrf.ts`.
- **Do:** Add a sandboxed `/api/ssrf-fetch` endpoint with 10-scenario catalog (decimal/hex/octal IPs, IPv6, DNS rebinding mock, AWS IMDSv1 path, GCP metadata Host header, Redis CRLF, K8s SA token, gopher://). Naive fetcher vs hardened fetcher side-by-side with allowlist + URL parsing.
- **Done when:** user can submit any catalog URL and see naive + hardened response with rationale.

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

- **2026-05-10 (commit a80e156)** — Prompt Injection v2: live tool-call agent loop. Five-tool surface (`read_file`, `kb_search`, `web_fetch`, `send_email`, `update_calendar`), 12 deterministic scenarios spanning direct override, indirect injection, KB poisoning, exfil-via-markdown-image, tool-call hijack, prompt leakage, confused-deputy README, BEC-via-injected-invoice, two-step indirect chain, CSV imperative + formula injection. Naive vs hardened traces rendered side-by-side with provenance tags, refusal rules, and explicit leak markers; editable hardened policy (email/web allowlist + spotlighting toggle); JSON telemetry export. References: Greshake et al. 2023, Bargury BlackHat 2024, embracethered Copilot disclosures, OWASP LLM Top 10 2025, FBI IC3 BEC PSA, PortSwigger LLM attacks, NCSC AI guidelines.
- **2026-05-10 (commit 8cb1938)** — Cross-linked `/identity/jwt` and `/identity/forge`: callout on the inspector pointing at the forging workbench, and a "What this proves" panel on the workbench summarising the four CVE-class attacks (alg=none CVE-2015-9235, RS→HS confusion CVE-2016-10555, kid traversal, tamper-no-resign) with the matching defense for each.
- **2026-05-03 (commit f649794)** — Supply Chain v2: editable `package.json` + registry textareas, live re-analysis, Levenshtein typosquat checker against 40+ popular npm/PyPI names.
- **2026-05-03 (commit 7bdb9cd)** — IAM Privilege Escalation lab: 12 published techniques across AWS/Azure/GCP, BFS attack-path enumerator, editable principal graph. Modeled on Rhino Security, SpecterOps, CloudGoat.
- **2026-05-03 (commit 7bdb9cd)** — Detection Engineering lab: Sigma-style match engine, 5 ground-truth-labeled scenarios (Midnight Blizzard, Storm-0558, Volt Typhoon, Hafnium), live precision/recall/F1.
- **2026-05-03 (commit 9067e49)** — Fixed Azure IAM accuracy bug: `Application.ReadWrite.All` is a Graph _application_ permission held by SPs, not user-held. Split into three accurate techniques (`az-app-admin-role`, `az-app-owner`, `az-sp-graph-app-readwrite`).
- **2026-05-03 (commit 691980b)** — Identity Lab v2 / JWT forging workbench at `/identity/forge`: real WebCrypto RSA-2048 keypair, four canonical forgeries (alg=none CVE-2015-9235, RS→HS confusion CVE-2016-10555, kid traversal, claim-tamper-no-resign) against an intentionally-misconfigurable verifier. T-01 partially done (workbench shipped) — still need cross-link from `/identity/jwt`.

## Notes

- Each task is intentionally scoped to ~1 commit. Split if it grows.
- If a task reveals a larger problem, stop, write a new task for it, and
  flag the original as Blocked.

## Session log

- **2026-05-10** — Two tasks shipped (T-00, T-01b). Cross-linked the JWT inspector and forging workbench with a 'What this proves' panel covering the four CVE-class verifier bugs (8cb1938). Then promoted the prompt-injection simulator into a live five-tool agent loop with 12 scenarios, a hardened policy editor, side-by-side traces, and JSON telemetry export (a80e156). Remaining outstanding work: T-01c (SSRF v2 live fetcher sandbox), T-01 (JWT workbench copy-as-curl polish), T-02 (Agent Identity token-exchange e2e).
- **2026-05-03** — Shipped 4 commits (f649794, 7bdb9cd, 9067e49, 691980b). Three labs and one accuracy fix. Remaining outstanding work: T-02 (Agent Identity token-exchange e2e), Prompt Injection v2 (live tool-call agent loop), SSRF v2 (live fetcher sandbox), T-01 cross-link from `/identity/jwt` to `/identity/forge`. Quality bar this session: every lab has editable inputs + live analyzer + cited references; no read-only showcases.
