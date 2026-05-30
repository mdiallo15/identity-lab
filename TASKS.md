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

### T-07 — Threat-model card component per lab

- **Files:** `app/_components/threat-model.tsx` (new), each lab index.
- **Do:** Compact STRIDE-style table per lab (Spoofing / Tampering /
  Repudiation / Info-disclosure / DoS / EoP) listing the lab's covered
  threats and pointing at the demo scenario for each.
- **Done when:** Every lab index renders a threat-model card; the card
  links to the relevant scenario inside the lab.

### T-08 — Deep-link `?scenario=` in CSP analyzer

- **Files:** `app/csp/analyzer/page.tsx`, `app/csp/sandbox/page.tsx`.
- **Do:** Read `?scenario=` from `useSearchParams`, hydrate the editor
  with the matching catalog payload. Update the URL on selection so
  links are shareable.
- **Done when:** Linking to `/csp/analyzer?scenario=<id>` opens the
  analyzer pre-loaded with that scenario.

### T-09 — Deep-link `?scenario=` in SSRF analyzer

- **Files:** `app/ssrf/analyzer/page.tsx`.
- **Do:** Same pattern as T-08 — hydrate fetcher inputs from the URL,
  update the URL on click.
- **Done when:** `/ssrf/analyzer?scenario=<id>` opens with that fetcher
  payload pre-selected.

### T-10 — Deep-link `?scenario=` in Prompt Injection simulator

- **Files:** `app/prompt-injection/simulator/page.tsx`.
- **Do:** Same pattern as T-08 against AGENT_SCENARIOS.
- **Done when:** `/prompt-injection/simulator?scenario=<id>` runs that
  scenario on first paint.

### T-11 — Deep-link `?scenario=` in IAM PrivEsc

- **Files:** `app/iam-privesc/page.tsx`, `lib/iam-privesc.ts`.
- **Do:** Same pattern — pre-select the technique by id from the URL.
- **Done when:** Each AWS/Azure/GCP technique has a stable shareable URL.

### T-12 — Deep-link `?scenario=` in Detection Engineering

- **Files:** `app/detection-engineering/page.tsx`.
- **Do:** Pre-select the labelled scenario (Midnight Blizzard,
  Storm-0558, Volt Typhoon, Hafnium) from the URL.
- **Done when:** Each rule has a stable shareable URL surfacing its
  precision/recall against the labelled set.

### T-13 — Shared LabFrame component (pilot)

- **Files:** `app/_components/lab-frame.tsx` (new), `app/csp/layout.tsx`
  (pilot consumer).
- **Do:** Extract repeated header/lede/breadcrumb chrome into a
  `<LabFrame>` server component. Pilot on the CSP lab only first.
- **Done when:** CSP lab routes render through `<LabFrame>` with no
  visual regression.

### T-14 — Apply LabFrame to remaining labs

- **Files:** all `app/<lab>/layout.tsx`.
- **Do:** Replace the duplicated chrome in `identity`, `ssrf`,
  `prompt-injection`, `authz`, and `agent-identity` layouts with
  `<LabFrame>`.
- **Done when:** Every lab layout uses `<LabFrame>`; no per-lab
  duplication.

### T-15 — README: replace stale "Planned" section

- **Files:** `README.md`.
- **Do:** Remove the "Planned" section (Prompt Injection + SSRF have
  shipped; SSRF is currently misdescribed as planned). Replace with a
  current lab inventory table.
- **Done when:** README reflects the shipped state; no dead "planned"
  bullets.

### T-16 — OpenAPI document for public APIs

- **Files:** `app/api-docs/openapi.json/route.ts` (new GET handler) or
  `public/openapi.json`.
- **Do:** Author a single OpenAPI 3.1 document covering `/api/scan`,
  `/api/ssrf-fetch`, `/api/identity/passkey/register`,
  `/api/identity/passkey/authenticate`, and `/api/ssrf-test`. Hand-
  authored — no new deps.
- **Done when:** `GET /api-docs/openapi.json` (or `/openapi.json`)
  returns a valid OpenAPI 3.1 doc.

### T-17 — CodeQL workflow on repository source

- **Files:** `.github/workflows/codeql.yml` (new).
- **Do:** Add `github/codeql-action/init` + `analyze` for `javascript`
  on push/pull_request and weekly schedule. This is the right way to
  feed Code Scanning (the existing security-scan workflow scans
  external URLs — Code Scanning rejects non-`file://` SARIF).
- **Done when:** CodeQL runs against the repo source and uploads to
  Code Scanning.

### T-18 — Native sitemap + robots

- **Files:** `app/sitemap.ts` (new), `app/robots.ts` (new).
- **Do:** Implement Next-native `MetadataRoute.Sitemap` covering every
  static lab route, and a permissive `robots.txt` excluding `/api`.
- **Done when:** `/sitemap.xml` and `/robots.txt` are served.

### T-19 — Open Graph + Twitter Card metadata per lab

- **Files:** every `app/<lab>/page.tsx` `metadata` export and root
  `app/layout.tsx`.
- **Do:** Add `openGraph` and `twitter` metadata blocks (title,
  description, type=`website`, url) so lab links unfurl with the right
  card.
- **Done when:** Every lab page has OG + Twitter metadata; manual paste
  into a card validator renders correctly (recorded in commit body).

### T-20 — Cross-tool JWT vector script

- **Files:** `scripts/verify-jwt-vectors.mjs` (new).
- **Do:** Generate a small set of forged JWTs from `lib/jwt-forge.ts`
  (alg=none, alg-confusion, kid traversal, tamper-no-resign), serialise
  them, and document the expected verifier behaviour for each
  (accept / reject) so the workbench's claims can be cross-checked
  against a third-party JWT library by hand.
- **Done when:** `npm run verify-jwt-vectors` prints each vector + the
  expected outcome under a strict verifier and a permissive one.

## Blocked

- _(none)_

## Done

- **2026-05-30 (commit T-07)** — Per-lab STRIDE threat-model card shipped on all ten labs. New `app/_components/threat-model.tsx` takes an `entries: readonly ThreatEntry[]` prop (data is inlined in each page so client labs don't ship the full corpus). `ThreatEntry` type lives in `lib/labs.ts`. Each card lists 4 STRIDE-classified threats with a colour-coded tag (S/T/R/I/D/E) and a deep-link to the scenario inside the lab that demonstrates the threat. Cards use the existing dark CSS tokens, with a red left border to differentiate from the cyan "what you'll learn" callout. Bundle: detection-engineering still 7.69 kB; iam-privesc 9.75 → 10.2; rag 9.28 → 9.77; supply-chain 12.9 → 13.5 (over ceiling; T-22 follow-up queued).
- **2026-05-30 (commit T-21)** — Bundle audit + split for /detection-engineering. Moved `LAB_RULES`, `LabKey`, `LabRule` out of `lib/detection.ts` into a new server-only module `lib/detection-lab-rules.ts`. Split `app/detection-engineering/page.tsx` into a server component (renders the lab-rule catalog server-side) plus a thin `<ScenarioRunner />` client island that imports only the live-editor primitives from `lib/detection.ts`. Route size 14.2 kB → 7.68 kB; First Load JS 116 kB → 110 kB; comfortably under the 12 kB ceiling. Lab-rule corpus no longer ships to the browser as JavaScript at all.
- **2026-05-30 (commit T-06)** — Per-lab "what you'll learn" callout shipped on all ten labs (CSP, Identity, SSRF, Prompt Injection, AuthZ, Agent Identity, IAM PrivEsc, Detection Engineering, Supply Chain, RAG). New `app/_components/learn-callout.tsx` reads from a `LAB_LEARN` map in `lib/labs.ts` so the bullets live with the lab metadata, not in JSX. Four concrete takeaways per lab (no marketing copy). Styled as a left-bordered cyan callout pinned above the lede.
- **2026-05-30 (commit T-05)** — Home page lab grid reordered: newest first (Detection Engineering, Agent Identity, IAM PrivEsc, Supply Chain, RAG, Prompt Injection v2, SSRF v2), with the long-running tiles (Identity, CSP, AuthZ) below. New `lib/labs.ts` exposes `LAB_SINCE` (per-route launch dates) + `isNewLab(href)` with a configurable `NEW_WINDOW_DAYS` threshold (default 60). The `<NewPill>` chip on each tile auto-clears when the launch date drops out of the window, so the page never carries stale flags. Updated tile copy where lab v2 work shipped (forging workbench, agent loop simulator, fetcher sandbox, claims diff).
- **2026-05-30 (commit T-04)** — Detection Engineering per-lab ruleset. New `LAB_RULES` catalog in `lib/detection.ts` with one Sigma-equivalent rule per lab domain (CSP / JWT / SSRF / IAM / Supply Chain / RAG / Prompt Injection / Agent Identity), each with rationale, data source, ATT&CK or OWASP / CVE handle, pseudo-Sigma body, published reference, and known-FP shape. Detection page renders them grouped by lab under existing scenarios. References include Capital One IMDS, Rhino Security AWS PassRole, Greshake et al. 2023 indirect prompt injection, Bargury BlackHat 2024 Copilot, RFC 8693 §4.1.
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

- **2026-05-30 (cont.)** — T-07 shipped: STRIDE threat-model card on all 10 labs; queued T-22 (split /supply-chain bundle).
- **2026-05-30 (cont.)** — T-21 shipped: split /detection-engineering into server page + ScenarioRunner client island; route 14.2 kB → 7.68 kB.
- **2026-05-30 (cont.)** — T-06 shipped: `<LearnCallout>` on all 10 labs with bullets sourced from `LAB_LEARN` in `lib/labs.ts`.
- **2026-05-30 (cont.)** — T-05 shipped: home grid reordered newest-first, `<NewPill>` chip + `lib/labs.ts` (`LAB_SINCE` + `isNewLab` with 60-day auto-clear).
- **2026-05-30** — Continuous-mode session start. Phase 0 sync clean. Phase 1: regenerated backlog — added 15 atomic tasks T-06..T-20 from PLAN.md backlog/ideas + README cleanup. T-04 shipped: per-lab Sigma ruleset (8 rules, one per lab domain) on the Detection Engineering page.
- **2026-05-17 (cont.)** — T-03 shipped: zero-dep SARIF 2.1.0 validator + Node script exercising all 5 lab surfaces (`csp/analyzer`, `api/scan`, `authz/patterns`, `ssrf/analyzer`, `agent-identity/inventory`) + empty-findings edge case. All validate clean. Wired `npm run validate-sarif` into CI.
- **2026-05-17** — T-02 shipped: RFC 8693 token-exchange playground now renders subject_token, actor_token, and exchanged access_token decoded side-by-side, plus a claims-diff table with origin badges (subject / actor / sts / narrowed). Page reuses existing `exchangeToken()` warnings (offboarded user, wildcard scope, TTL, no attestation). Bundle 3.8 kB.
- **2026-05-10 (cont.)** — Third task this session: T-01c SSRF v2 live fetcher sandbox shipped (044bdde). 10-payload catalog + naive vs hardened fetchers + sandboxed `/api/ssrf-fetch`. Hardened rule chain labelled (H-SCHEME / H-CRLF / H-HEADERS / H-CANON / H-IPRANGE / H-IPV6 / H-PINIP). Remaining outstanding work: T-01 (JWT workbench copy-as-curl polish), T-02 (Agent Identity token-exchange e2e).
- **2026-05-10** — Two tasks shipped (T-00, T-01b). Cross-linked the JWT inspector and forging workbench with a 'What this proves' panel covering the four CVE-class verifier bugs (8cb1938). Then promoted the prompt-injection simulator into a live five-tool agent loop with 12 scenarios, a hardened policy editor, side-by-side traces, and JSON telemetry export (a80e156). Remaining outstanding work: T-01c (SSRF v2 live fetcher sandbox), T-01 (JWT workbench copy-as-curl polish), T-02 (Agent Identity token-exchange e2e).
- **2026-05-03** — Shipped 4 commits (f649794, 7bdb9cd, 9067e49, 691980b). Three labs and one accuracy fix. Remaining outstanding work: T-02 (Agent Identity token-exchange e2e), Prompt Injection v2 (live tool-call agent loop), SSRF v2 (live fetcher sandbox), T-01 cross-link from `/identity/jwt` to `/identity/forge`. Quality bar this session: every lab has editable inputs + live analyzer + cited references; no read-only showcases.
