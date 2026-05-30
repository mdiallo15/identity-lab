// Lab metadata. Today the only field used is "since" (ISO date), which
// drives the "new" pill on the home page. Pills auto-clear after the
// NEW_WINDOW_DAYS threshold so the page never carries stale flags.

export const NEW_WINDOW_DAYS = 60;

// Per-route launch / major-revision dates. Update these when a lab ships
// a v2 — the "new" pill will rehang for NEW_WINDOW_DAYS.
export const LAB_SINCE: Record<string, string> = {
  "/identity/forge": "2026-05-03",
  "/agent-identity": "2026-05-03",
  "/agent-identity/token-exchange": "2026-05-17",
  "/iam-privesc": "2026-05-03",
  "/detection-engineering": "2026-05-30",
  "/supply-chain": "2026-05-03",
  "/rag": "2026-04-26",
  "/prompt-injection": "2026-05-10",
  "/ssrf": "2026-05-10",
};

export function isNewLab(href: string, now: Date = new Date()): boolean {
  const since = LAB_SINCE[href];
  if (!since) return false;
  const t = Date.parse(since);
  if (Number.isNaN(t)) return false;
  const ageMs = now.getTime() - t;
  return ageMs >= 0 && ageMs <= NEW_WINDOW_DAYS * 24 * 60 * 60 * 1000;
}

// Per-lab "what you'll learn" bullets, surfaced as a callout box at the
// top of each lab landing page. Concrete takeaways only — no marketing
// copy. The point is for the reader to know what understanding they
// will leave the lab with.
export const LAB_LEARN: Record<string, readonly string[]> = {
  "/csp": [
    "Why `unsafe-inline` + wildcard hosts collapses a CSP to no-op.",
    "Nonce vs hash vs `strict-dynamic` — when to pick each.",
    "Three real bypasses (JSONP, `base-uri`, dangling markup) and the rules that catch them.",
    "How to migrate from report-only to enforce without breaking the page.",
  ],
  "/identity": [
    "The four MFA archetypes (passkey, push, OTP, SMS) ranked by phishing-resistance.",
    "Why `alg=none` (CVE-2015-9235) and RS↔HS confusion (CVE-2016-10555) keep being forgeable.",
    "How to forge each token class against an intentionally-misconfigurable verifier.",
    "Workload identity primitives: SPIFFE, OIDC, and the RFC 8693 `act` claim.",
  ],
  "/ssrf": [
    "Why 169.254.169.254 is the most-attacked IP on the internet (Capital One, 2019).",
    "IPv4 encoding bypasses (decimal / hex / octal), IPv6 loopback, and DNS rebinding.",
    "The seven hardening rules a fetcher must apply (H-SCHEME / H-CRLF / H-IPRANGE / …).",
    "Why IMDSv2 and egress firewalls are necessary but not sufficient on their own.",
  ],
  "/prompt-injection": [
    "Direct vs indirect injection — same model, different attack surface.",
    "Tool-call hijacking and confused-deputy attacks via tool descriptions.",
    "Spotlighting, allowlists, and provenance tagging as the three defense layers.",
    "Why the model alone cannot be trusted to enforce policy on adversarial input.",
  ],
  "/authz": [
    "Why BOLA is OWASP API Security Top 10 #1 in 2023 and 2024.",
    "403 vs 404 leakage and sequential-ID enumeration — both are exploitable.",
    "Owner-scope checks belong in the data layer, not the controller.",
    "Mass-assignment as the second half of the BOLA story.",
  ],
  "/agent-identity": [
    "RFC 8693 token exchange as the standards-track delegation primitive.",
    "How the `act` claim makes user→agent calls attributable in audit logs.",
    "Six attestation surfaces (GitHub OIDC, AWS Nitro, Azure MI, GCP WIF, TPM, App Attest) compared.",
    "Drift surfaces: long-lived secrets, missing attestation, scope drift, audit-log gaps.",
  ],
  "/iam-privesc": [
    "`iam:PassRole` + `RunInstances` / `CreateFunction` as the canonical AWS chain.",
    "Azure equivalents: Application.ReadWrite.All and AppRoleAssignment.ReadWrite.All.",
    "GCP: `iam.serviceAccounts.actAs` is the role you must guard.",
    "BFS over the principal graph finds multi-hop chains humans miss in review.",
  ],
  "/detection-engineering": [
    "Naive vs tuned rules — precision / recall / F1 against ground-truth labelled events.",
    "Sigma-style condition trees over Sysmon, CloudTrail, and Entra sign-ins.",
    "Per-lab Sigma starter rules with concrete data-source guidance.",
    "ATT&CK technique mapping per rule so dashboards roll up cleanly.",
  ],
  "/supply-chain": [
    "Eight real registry compromises replayed: event-stream → tj-actions (2018–2025).",
    "Install hooks + post-install network reach = the exfil class to detect at install time.",
    "Build provenance via Sigstore and npm provenance attestations.",
    "Typosquat patterns derived from real campaigns, not theoretical Levenshtein lists.",
  ],
  "/rag": [
    "Indirect prompt injection lands in your KB before it lands in your model.",
    "PoisonedRAG ranking-attack mechanics (Zou et al. 2024).",
    "Markdown-image canary exfil — and why it's hard to filter post-hoc.",
    "Spotlighting + URL allowlist + grounding + dedup as the four defense layers.",
  ],
};
