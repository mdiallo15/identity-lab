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

- **2026-05-17 (commit 192fa5c)** — SARIF 2.1.0 export verification. Added `validateSarif()` to `lib/sarif.ts` — zero-dep structural validator covering $schema/version pins, run shape, tool.driver.name, rule.id uniqueness and reference resolution, level vocabulary (`error|warning|note|none`), security-severity numeric range [0,10], and locations shape. Added `scripts/validate-sarif.mjs` that transpiles `lib/sarif.ts` in-memory via the `typescript` devDep (no new runtime deps) and exercises every SARIF surface against fixture findings. All six surfaces validate: `csp/analyzer`, `api/scan`, `authz/patterns`, `ssrf/analyzer`, `agent-identity/inventory`, plus the empty-findings edge case. CI now runs `npm run validate-sarif` before `npm run build`.
- **2026-05-17 (commit c6a7e73)** — Agent Identity token-exchange end-to-end demo: three decoded JWTs side-by-side (subject_token / actor_token / exchanged access_token) with copyable compact JWS strings, a claims diff table colouring every claim by origin (from subject_token / from actor_token / minted by STS / narrowed by STS), and a per-claim explanation grounded in RFC 8693 §1.2 (principal preservation) and §4.1 (`act` claim). The IdP-warnings panel still surfaces offboarded users, wildcard scope, oversize TTL, and missing attestation. Updated `lib/agent-identity.ts` with `buildSubjectJwt`, `buildActorJwt`, `buildExchangedJwt`, and `diffExchangedClaim`.
- **2026-05-10 (commit 983bc6b)** — JWT forging workbench polish: copy-as-curl affordance under each forged token (curl line targeting `https://api.example.com/admin/users` with `Authorization: Bearer <forged>`, plus separate copy buttons for the raw token and the bare Authorization header). Per-attack reproduction note explains the verifier-side bug each forgery exploits (CVE-2015-9235 alg=none, CVE-2016-10555 RS→HS, kid path traversal, decode-then-trust). Cross-link from `/identity/jwt` to `/identity/forge` and 'What this proves' panel were shipped in T-00.
- **2026-05-10 (commit 044bdde)** — SSRF v2: live fetcher sandbox at `/ssrf/analyzer` with a 10-payload catalog (decimal/hex/octal-encoded IPv4 → AWS IMDS, IPv6 loopback, DNS-rebinding mock, AWS IMDSv1 path, GCP metadata via Host-header smuggling, Redis CRLF injection, K8s API ServiceAccount token, gopher:// → Redis RCE) and a sandboxed `/api/ssrf-fetch` endpoint that mirrors the same deterministic transcripts for curl/SIEM replay. Naive vs hardened fetchers run side-by-side; the hardened rule chain (H-SCHEME / H-CRLF / H-HEADERS / H-CANON / H-IPRANGE / H-IPV6 / H-PINIP) labels every block. References: Capital One IMDS breach (KrebsOnSecurity), Orange Tsai BlackHat 2017 URL-parser SSRF, OWASP SSRF cheat sheet, NCC Group Singularity rebinder, MITRE ATT&CK T1552.007, Tarunkant Gopherus, AWS IMDSv2 docs.
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

- **2026-05-17 (cont.)** — T-03 shipped: zero-dep SARIF 2.1.0 validator + Node script exercising all 5 lab surfaces (`csp/analyzer`, `api/scan`, `authz/patterns`, `ssrf/analyzer`, `agent-identity/inventory`) + empty-findings edge case. All validate clean. Wired `npm run validate-sarif` into CI.
- **2026-05-17** — T-02 shipped: RFC 8693 token-exchange playground now renders subject_token, actor_token, and exchanged access_token decoded side-by-side, plus a claims-diff table with origin badges (subject / actor / sts / narrowed). Page reuses existing `exchangeToken()` warnings (offboarded user, wildcard scope, TTL, no attestation). Bundle 3.8 kB.
- **2026-05-10 (cont.)** — Third task this session: T-01c SSRF v2 live fetcher sandbox shipped (044bdde). 10-payload catalog + naive vs hardened fetchers + sandboxed `/api/ssrf-fetch`. Hardened rule chain labelled (H-SCHEME / H-CRLF / H-HEADERS / H-CANON / H-IPRANGE / H-IPV6 / H-PINIP). Remaining outstanding work: T-01 (JWT workbench copy-as-curl polish), T-02 (Agent Identity token-exchange e2e).
- **2026-05-10** — Two tasks shipped (T-00, T-01b). Cross-linked the JWT inspector and forging workbench with a 'What this proves' panel covering the four CVE-class verifier bugs (8cb1938). Then promoted the prompt-injection simulator into a live five-tool agent loop with 12 scenarios, a hardened policy editor, side-by-side traces, and JSON telemetry export (a80e156). Remaining outstanding work: T-01c (SSRF v2 live fetcher sandbox), T-01 (JWT workbench copy-as-curl polish), T-02 (Agent Identity token-exchange e2e).
- **2026-05-03** — Shipped 4 commits (f649794, 7bdb9cd, 9067e49, 691980b). Three labs and one accuracy fix. Remaining outstanding work: T-02 (Agent Identity token-exchange e2e), Prompt Injection v2 (live tool-call agent loop), SSRF v2 (live fetcher sandbox), T-01 cross-link from `/identity/jwt` to `/identity/forge`. Quality bar this session: every lab has editable inputs + live analyzer + cited references; no read-only showcases.
