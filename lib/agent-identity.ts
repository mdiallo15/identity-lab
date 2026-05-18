// audit-ignore-file
// Agent identity lab — domain logic.
//
// Two interactive surfaces in this lab:
//   1. Token exchange playground (RFC 8693). Given a user subject_token and an
//      agent actor_token, derive a downscoped, time-bounded delegated token
//      whose payload contains the `act` claim that makes user→agent calls
//      attributable in audit logs.
//   2. Agent inventory + drift detector. Static fixture of an enterprise agent
//      population, with eight drift / hygiene rules (AGT01-AGT08) covering
//      the failure modes I see most often: long-lived secrets, missing
//      attestation, scope drift, dormant agents, audit-log gaps.
//
// All cryptography here is illustrative. A real RFC 8693 deployment uses your
// IdP's signer; the demo keeps the math local to the browser so the lab works
// without an LLM API key, an IdP, or a backend.
//
// References:
//   RFC 8693 — OAuth 2.0 Token Exchange (https://www.rfc-editor.org/rfc/rfc8693)
//   RFC 9449 — OAuth 2.0 DPoP (sender-constrained tokens)
//   NIST AI 600-1 §2.5 — generative AI profile, info-security control category
//   NIST SP 800-63-4 (draft) — non-person entity treatment
//   CSA AI Controls Matrix — agent / non-human identity controls
//   SPIFFE / SPIRE — workload identity primitives
//   AWS IAM Roles Anywhere; Azure managed identity; GCP workload identity
//     federation; GitHub Actions OIDC — the four mainstream attestation
//     surfaces a builder is likely to wire up first.

import type { SarifFinding, SarifSeverity } from "./sarif";

// -------------------------- Token-exchange playground -----------------------

export type AttestationKind =
  | "github-oidc"
  | "aws-nitro"
  | "azure-managed-id"
  | "gcp-wif"
  | "tpm"
  | "apple-attest"
  | "none";

export interface UserSubject {
  id: string;
  label: string;
  email: string;
  aal: "AAL1" | "AAL2" | "AAL3";
  amr: string[]; // authentication-method references, e.g. ["passkey", "hwk"]
  active: boolean;
}

export interface AgentActor {
  id: string;
  label: string;
  workload: string; // SPIFFE-style ID, e.g. spiffe://prod/agent/code-reviewer/v3
  attestation: AttestationKind;
  defaultScopes: string[];
  defaultAud: string;
}

export const USER_SUBJECTS: UserSubject[] = [
  {
    id: "u_marwan",
    label: "Marwan (passkey, current)",
    email: "marwan@example.com",
    aal: "AAL3",
    amr: ["passkey", "hwk"],
    active: true,
  },
  {
    id: "u_alice",
    label: "Alice (passkey, current)",
    email: "alice@example.com",
    aal: "AAL2",
    amr: ["passkey"],
    active: true,
  },
  {
    id: "u_bob_offboarded",
    label: "Bob (offboarded — should be inactive)",
    email: "bob@former.example.com",
    aal: "AAL2",
    amr: ["password", "totp"],
    active: false,
  },
];

export const AGENT_ACTORS: AgentActor[] = [
  {
    id: "a_code_reviewer",
    label: "Code-reviewer agent (GitHub Actions)",
    workload: "spiffe://prod/agent/code-reviewer/v3",
    attestation: "github-oidc",
    defaultScopes: ["read:repo", "write:issues"],
    defaultAud: "api.github.com",
  },
  {
    id: "a_calendar_assistant",
    label: "Calendar assistant (Azure managed identity)",
    workload: "spiffe://prod/agent/calendar-assistant/v1",
    attestation: "azure-managed-id",
    defaultScopes: ["read:calendar", "write:calendar"],
    defaultAud: "graph.microsoft.com",
  },
  {
    id: "a_finance_summarizer",
    label: "Finance summarizer (AWS Nitro Enclave)",
    workload: "spiffe://prod/agent/finance-summarizer/v2",
    attestation: "aws-nitro",
    defaultScopes: ["read:reports"],
    defaultAud: "finance-api.example.com",
  },
  {
    id: "a_legacy_bot",
    label: "Legacy bot (no attestation, long-lived API key)",
    workload: "legacy://bot-7",
    attestation: "none",
    defaultScopes: ["*"],
    defaultAud: "internal-api.example.com",
  },
];

export interface ExchangeRequest {
  userId: string;
  agentId: string;
  scopes: string[];
  audience: string;
  ttlSeconds: number;
}

export interface ExchangedTokenClaims {
  iss: string;
  sub: string; // user
  azp: string; // authorized party (the agent's IdP client_id)
  aud: string; // resource the token can be presented to
  scope: string;
  iat: number;
  exp: number;
  jti: string;
  // RFC 8693: act conveys "acting party" for delegation.
  act: {
    sub: string; // agent workload id
    azp: string;
    iss: string;
    attestation: AttestationKind;
  };
  // Optional sender-constraint hint (RFC 9449 DPoP / mTLS cnf).
  cnf?: { jkt?: string };
}

export interface ExchangeResult {
  request: {
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange";
    requested_token_type: "urn:ietf:params:oauth:token-type:access_token";
    subject_token: string; // opaque label here, not a real signed JWT
    subject_token_type: "urn:ietf:params:oauth:token-type:jwt";
    actor_token: string;
    actor_token_type: "urn:ietf:params:oauth:token-type:jwt";
    audience: string;
    scope: string;
  };
  claims: ExchangedTokenClaims;
  auditLine: string;
  warnings: string[]; // surfaced UX-level checks (offboarded user, wildcard scope, ttl too long, no attestation)
}

const ISS = "https://idp.lab.marwandiallo.com";

function randomJti(): string {
  // Browser-safe; falls back to Math.random for environments without crypto.
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return Math.random().toString(36).slice(2);
}

export function exchangeToken(req: ExchangeRequest): ExchangeResult {
  const user = USER_SUBJECTS.find((u) => u.id === req.userId);
  const agent = AGENT_ACTORS.find((a) => a.id === req.agentId);
  if (!user || !agent) {
    throw new Error("Unknown user or agent");
  }
  const now = Math.floor(Date.now() / 1000);
  const claims: ExchangedTokenClaims = {
    iss: ISS,
    sub: user.id,
    azp: agent.id,
    aud: req.audience,
    scope: req.scopes.join(" "),
    iat: now,
    exp: now + req.ttlSeconds,
    jti: randomJti(),
    act: {
      sub: agent.workload,
      azp: agent.id,
      iss: ISS,
      attestation: agent.attestation,
    },
    cnf:
      agent.attestation !== "none"
        ? { jkt: "demo-thumbprint-" + agent.id.slice(2, 8) }
        : undefined,
  };

  const auditLine =
    `${new Date(now * 1000).toISOString()} ` +
    `principal=${user.id} ` +
    `acting_as=${agent.workload} ` +
    `attestation=${agent.attestation} ` +
    `aud=${req.audience} ` +
    `scope="${req.scopes.join(" ")}" ` +
    `ttl=${req.ttlSeconds}s ` +
    `jti=${claims.jti}`;

  const warnings: string[] = [];
  if (!user.active) {
    warnings.push(
      "Subject user is marked inactive (offboarded). The IdP should refuse the exchange entirely; this lab surfaces the warning so you can see the failure mode.",
    );
  }
  if (req.scopes.includes("*") || req.scopes.some((s) => s.endsWith(":*"))) {
    warnings.push(
      "Wildcard scope requested. RFC 8693 token exchange is intended to downscope, not preserve full authority — pick the smallest set of scopes the task actually needs.",
    );
  }
  if (req.ttlSeconds > 3600) {
    warnings.push(
      "TTL longer than 1 hour. Delegated agent tokens should be short-lived (300–900s is typical). Re-exchange on demand instead of issuing a long-lived token.",
    );
  }
  if (agent.attestation === "none") {
    warnings.push(
      "Agent has no attestation. The exchange still works but the audit trail cannot prove which workload presented the actor_token. Wire up a workload-attestation surface (GitHub OIDC, AWS Nitro, Azure managed identity, GCP WIF) before relying on this in production.",
    );
  }

  return {
    request: {
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
      subject_token: `<user-jwt for ${user.id}>`,
      subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
      actor_token: `<workload-jwt for ${agent.workload}>`,
      actor_token_type: "urn:ietf:params:oauth:token-type:jwt",
      audience: req.audience,
      scope: req.scopes.join(" "),
    },
    claims,
    auditLine,
    warnings,
  };
}

// ---- JWT encode/decode side-by-side helpers (RFC 8693 demo) ---------------

// Minimal base64url for JSON. Browser btoa + URL-safe transforms; for SSR
// fallback we route through Buffer when available.
function b64url(input: string): string {
  let raw: string;
  if (typeof btoa === "function") {
    // btoa wants Latin-1; encode UTF-8 first.
    const bytes = new TextEncoder().encode(input);
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    raw = btoa(bin);
  } else {
    // Node fallback.
    raw = Buffer.from(input, "utf-8").toString("base64");
  }
  return raw.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

// Deterministic demo signature — FNV-1a 32-bit over the signing input,
// rendered as 8 hex chars then base64url. Pedagogical only; the JWT lab
// at /identity/forge and /identity/jwt covers real signature mechanics.
function demoSig(signingInput: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < signingInput.length; i++) {
    h ^= signingInput.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  const hex = h.toString(16).padStart(8, "0");
  // Prefix with "demo-" so it's obvious in the UI this is not a real HMAC.
  return b64url("demo-" + hex);
}

export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  compact: string; // header.payload.signature
}

function encodeJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): DecodedJwt {
  const h = b64url(JSON.stringify(header));
  const p = b64url(JSON.stringify(payload));
  const s = demoSig(`${h}.${p}`);
  return { header, payload, compact: `${h}.${p}.${s}` };
}

// The user's authenticator-bound JWT presented as subject_token in the
// token-exchange request. Claims mirror what an OIDC IdP would emit after
// a passkey login: standard OpenID claims plus amr/acr for AAL signalling.
export function buildSubjectJwt(user: UserSubject, now?: number): DecodedJwt {
  const iat = now ?? Math.floor(Date.now() / 1000);
  return encodeJwt(
    { alg: "RS256", typ: "JWT", kid: "idp-2026-05" },
    {
      iss: ISS,
      sub: user.id,
      email: user.email,
      aud: "agents.idp.lab.marwandiallo.com",
      iat,
      exp: iat + 3600,
      amr: user.amr,
      acr: user.aal,
      jti: `usr-${user.id}-${iat}`,
    },
  );
}

// The agent's workload-attested JWT presented as actor_token. Claims model
// what an attested workload-identity surface emits (GitHub OIDC, AWS Nitro
// attestation doc relayed through STS, Azure managed identity, GCP WIF).
export function buildActorJwt(agent: AgentActor, now?: number): DecodedJwt {
  const iat = now ?? Math.floor(Date.now() / 1000);
  return encodeJwt(
    { alg: "RS256", typ: "JWT", kid: `wl-${agent.attestation}` },
    {
      iss: ISS,
      sub: agent.workload,
      azp: agent.id,
      aud: ISS,
      iat,
      exp: iat + 600,
      attestation: agent.attestation,
      scope: agent.defaultScopes.join(" "),
      jti: `wl-${agent.id}-${iat}`,
    },
  );
}

export function buildExchangedJwt(claims: ExchangedTokenClaims): DecodedJwt {
  return encodeJwt(
    { alg: "RS256", typ: "JWT", kid: "idp-2026-05" },
    claims as unknown as Record<string, unknown>,
  );
}

export type ClaimOrigin =
  | "subject" // inherited unchanged from the user's subject_token
  | "actor" // derived from the agent's actor_token (act.* family)
  | "sts" // newly minted by the STS for this exchange
  | "narrowed"; // bounded down from the actor_token's claim

// Diff one exchanged-token claim against the two input tokens so the UI can
// colour every line and explain *why* it's there. The mapping is deliberate:
//   sub  — must be the user (RFC 8693 §1.2). Inherited from subject_token.
//   act  — synthesised by the STS from the actor_token's identity claims.
//   aud  — narrowed: the request asked for one audience; the STS minted a
//          token only valid against it. The actor_token's own aud was the STS.
//   scope — narrowed: should be a subset of what the actor *could* request.
//   azp / cnf / jti / iat / exp / iss — fresh from the STS.
export function diffExchangedClaim(
  key: keyof ExchangedTokenClaims,
  exchanged: ExchangedTokenClaims,
  subject: DecodedJwt,
  actor: DecodedJwt,
): { origin: ClaimOrigin; note: string } {
  const subPayload = subject.payload;
  const actPayload = actor.payload;
  if (key === "sub") {
    return {
      origin: "subject",
      note: "Inherited from subject_token. RFC 8693 §1.2 requires the principal to remain the user.",
    };
  }
  if (key === "act") {
    return {
      origin: "actor",
      note: "Synthesised by the STS from actor_token. The act claim makes user→agent delegation visible in audit.",
    };
  }
  if (key === "aud") {
    return {
      origin: "sts",
      note: "Minted for this exchange. The actor_token's own aud was the STS itself; the resulting token is bound to the requested resource.",
    };
  }
  if (key === "scope") {
    const requested = String(exchanged.scope).split(" ").filter(Boolean);
    const allowed = String(actPayload.scope ?? "")
      .split(" ")
      .filter(Boolean);
    const isSubset =
      !allowed.includes("*") &&
      requested.every((s) => allowed.includes(s) || allowed.includes("*"));
    if (allowed.includes("*")) {
      return {
        origin: "narrowed",
        note: "actor_token holds a wildcard scope — the STS narrowed it to the explicit set you requested. Replace the wildcard at the agent boundary.",
      };
    }
    return isSubset
      ? {
          origin: "narrowed",
          note: "Subset of actor_token.scope. Token exchange exists to downscope, not preserve full authority.",
        }
      : {
          origin: "sts",
          note: "Requested scope is NOT a subset of actor_token.scope — a real STS would refuse this exchange.",
        };
  }
  if (key === "iss") {
    return {
      origin: "sts",
      note: "Re-issued by the STS. Receiving services trust the STS, not the workload directly.",
    };
  }
  if (key === "azp") {
    return {
      origin: "sts",
      note: "Authorized party — the agent's IdP client_id. Resources can pin azp to a specific agent.",
    };
  }
  if (key === "cnf") {
    return {
      origin: "sts",
      note: "Sender-constraint (RFC 9449 DPoP / mTLS). Receiving services reject the token if presented by a key the cnf doesn't bind.",
    };
  }
  if (key === "exp" || key === "iat" || key === "jti") {
    void subPayload;
    return {
      origin: "sts",
      note: "Fresh per-exchange. exp drives the agent token's TTL; jti enables replay defence.",
    };
  }
  return { origin: "sts", note: "Issued by the STS." };
}

// -------------------------- Inventory + drift detector ----------------------

export interface InventoryAgent {
  id: string;
  label: string;
  owner: string;
  workload: string;
  attestation: AttestationKind;
  scopes: string[];
  baselineScopes: string[]; // what the agent was approved for at onboarding
  lastSeen: string; // ISO date
  delegatedUserActive: boolean;
  emitsActClaim: boolean;
  longLivedSecret: boolean;
  sharedIdentityWith?: string[]; // ids of other agents sharing the same credential
}

const todayMinusDays = (n: number): string => {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - n);
  return d.toISOString().slice(0, 10);
};

export const INVENTORY: InventoryAgent[] = [
  {
    id: "agt-code-reviewer",
    label: "code-reviewer (GitHub Actions)",
    owner: "platform-eng",
    workload: "spiffe://prod/agent/code-reviewer/v3",
    attestation: "github-oidc",
    scopes: ["read:repo", "write:issues"],
    baselineScopes: ["read:repo", "write:issues"],
    lastSeen: todayMinusDays(0),
    delegatedUserActive: true,
    emitsActClaim: true,
    longLivedSecret: false,
  },
  {
    id: "agt-calendar-assistant",
    label: "calendar-assistant (Azure MI)",
    owner: "productivity",
    workload: "spiffe://prod/agent/calendar-assistant/v1",
    attestation: "azure-managed-id",
    scopes: ["read:calendar", "write:calendar", "read:mail"],
    baselineScopes: ["read:calendar", "write:calendar"],
    lastSeen: todayMinusDays(2),
    delegatedUserActive: true,
    emitsActClaim: true,
    longLivedSecret: false,
  },
  {
    id: "agt-finance-summarizer",
    label: "finance-summarizer (Nitro Enclave)",
    owner: "finance-platform",
    workload: "spiffe://prod/agent/finance-summarizer/v2",
    attestation: "aws-nitro",
    scopes: ["read:reports"],
    baselineScopes: ["read:reports"],
    lastSeen: todayMinusDays(5),
    delegatedUserActive: true,
    emitsActClaim: true,
    longLivedSecret: false,
  },
  {
    id: "agt-legacy-bot",
    label: "legacy-bot (no attestation)",
    owner: "unknown",
    workload: "legacy://bot-7",
    attestation: "none",
    scopes: ["*"],
    baselineScopes: ["read:tickets"],
    lastSeen: todayMinusDays(1),
    delegatedUserActive: false,
    emitsActClaim: false,
    longLivedSecret: true,
  },
  {
    id: "agt-dormant-summarizer",
    label: "old-summarizer (dormant)",
    owner: "former-team",
    workload: "spiffe://prod/agent/old-summarizer/v1",
    attestation: "github-oidc",
    scopes: ["read:repo", "write:repo"],
    baselineScopes: ["read:repo"],
    lastSeen: todayMinusDays(142),
    delegatedUserActive: true,
    emitsActClaim: false,
    longLivedSecret: false,
  },
  {
    id: "agt-shared-credential",
    label: "support-helper-A (shared cred)",
    owner: "support-eng",
    workload: "shared://support-helpers",
    attestation: "none",
    scopes: ["read:tickets", "write:tickets"],
    baselineScopes: ["read:tickets", "write:tickets"],
    lastSeen: todayMinusDays(0),
    delegatedUserActive: true,
    emitsActClaim: false,
    longLivedSecret: true,
    sharedIdentityWith: ["agt-shared-credential-b"],
  },
  {
    id: "agt-shared-credential-b",
    label: "support-helper-B (shared cred)",
    owner: "support-eng",
    workload: "shared://support-helpers",
    attestation: "none",
    scopes: ["read:tickets", "write:tickets"],
    baselineScopes: ["read:tickets", "write:tickets"],
    lastSeen: todayMinusDays(0),
    delegatedUserActive: true,
    emitsActClaim: false,
    longLivedSecret: true,
    sharedIdentityWith: ["agt-shared-credential"],
  },
];

export interface DriftFinding extends SarifFinding {
  agentId: string;
}

const DORMANT_DAYS = 90;

function daysSince(iso: string): number {
  const then = new Date(iso + "T00:00:00Z").getTime();
  const now = Date.now();
  return Math.floor((now - then) / 86_400_000);
}

export function analyzeInventory(): DriftFinding[] {
  const findings: DriftFinding[] = [];

  for (const a of INVENTORY) {
    if (a.longLivedSecret) {
      findings.push({
        agentId: a.id,
        id: "AGT01",
        severity: "critical",
        title: "Long-lived secret in use",
        detail: `Agent ${a.label} authenticates with a long-lived API key or static credential. A leaked secret is reusable indefinitely; nothing about the request is bound to the workload that issued it. This is the dominant agent-identity failure mode in 2026.`,
        fix: "Replace with a federated workload identity: GitHub Actions OIDC, AWS IAM Roles Anywhere, Azure managed identity, or GCP workload identity federation. Issue short-lived tokens (5–15 minutes), re-exchange on demand.",
      });
    }

    if (a.attestation === "none") {
      findings.push({
        agentId: a.id,
        id: "AGT02",
        severity: "high",
        title: "No workload attestation",
        detail: `Agent ${a.label} has no platform attestation. The audit trail cannot distinguish "this workload" from "anything that holds the secret." Compromise of the runner is indistinguishable from legitimate use.`,
        fix: "Move the workload onto a platform with built-in attestation (GitHub Actions, Azure managed identity, AWS Nitro, GCP WIF, TPM-backed host). Bind the agent token's cnf claim to the attested key.",
      });
    }

    const driftAdded = a.scopes.filter((s) => !a.baselineScopes.includes(s));
    if (driftAdded.length > 0) {
      findings.push({
        agentId: a.id,
        id: "AGT03",
        severity: "high",
        title: "Scope drift since baseline",
        detail: `Agent ${a.label} now holds scopes that were not in its onboarding baseline: ${driftAdded.join(", ")}. Scope accretion is the agent-side equivalent of a human user accumulating permissions across role changes.`,
        fix: "Re-baseline against current task requirements. Remove scopes the agent does not actively use. Add a quarterly access review for non-human identities.",
      });
    }

    if (a.scopes.includes("*") || a.scopes.some((s) => s.endsWith(":*"))) {
      findings.push({
        agentId: a.id,
        id: "AGT04",
        severity: "high",
        title: "Wildcard scope on agent identity",
        detail: `Agent ${a.label} holds a wildcard scope. RFC 8693 token exchange is intended to issue the smallest possible scope per task, not preserve admin-equivalent authority across delegations.`,
        fix: "Enumerate the actual scopes the agent requires per task type. Issue a different token per task. Revisit any tooling that requires wildcard scope.",
      });
    }

    if (daysSince(a.lastSeen) > DORMANT_DAYS) {
      findings.push({
        agentId: a.id,
        id: "AGT05",
        severity: "medium",
        title: `Dormant agent (last seen ${daysSince(a.lastSeen)}d ago)`,
        detail: `Agent ${a.label} has not been observed acting in ${daysSince(a.lastSeen)} days. Dormant agents accumulate access without producing detection signal. They are also the agent population most likely to be quietly resurrected by an attacker.`,
        fix: "Treat any non-human identity dormant beyond your threshold (typically 90 days) as a leaver. Disable the workload, revoke the credential, document the retirement.",
      });
    }

    if (!a.delegatedUserActive) {
      findings.push({
        agentId: a.id,
        id: "AGT06",
        severity: "critical",
        title: "Delegating user no longer active",
        detail: `Agent ${a.label} is configured to act on behalf of a user whose account is inactive. The agent retains effective authority that the human-side offboarding process did not retract.`,
        fix: "Tie agent identity lifecycle to the lifecycle of its delegating principal. Disable the agent at the same time the user is offboarded; require explicit re-binding to a current user before re-enabling.",
      });
    }

    if (!a.emitsActClaim) {
      findings.push({
        agentId: a.id,
        id: "AGT07",
        severity: "medium",
        title: "Tokens issued without act claim",
        detail: `Agent ${a.label} produces tokens that do not include the RFC 8693 \`act\` claim. Audit logs on the receiving service record the human user as the actor, even though the agent is the one executing — making post-incident attribution impossible.`,
        fix: "Switch the agent token issuer to RFC 8693 token exchange. Populate `sub` with the user, `act` with the agent workload identity. Confirm receiving services log both.",
      });
    }

    if (a.sharedIdentityWith && a.sharedIdentityWith.length > 0) {
      findings.push({
        agentId: a.id,
        id: "AGT08",
        severity: "high",
        title: "Workload identity shared across agents",
        detail: `Agent ${a.label} shares a credential or workload identity with: ${a.sharedIdentityWith.join(", ")}. Audit logs cannot distinguish which agent took which action; revocation of one disables the others.`,
        fix: "Provision a distinct workload identity per agent. Use SPIFFE IDs or provider-native per-workload identities. Never share a credential across agents 'because it was easier'.",
      });
    }
  }

  return findings;
}

export function severityRank(s: SarifSeverity): number {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s];
}

// -------------------------- Attestation comparison fixture ------------------

export interface AttestationOption {
  kind: AttestationKind;
  label: string;
  bestFor: string;
  bindsTo: string;
  ttl: string;
  rotation: string;
  trustRoot: string;
  notes: string;
}

export const ATTESTATION_OPTIONS: AttestationOption[] = [
  {
    kind: "github-oidc",
    label: "GitHub Actions OIDC",
    bestFor: "CI/CD agents, build-time tooling, deploy workflows",
    bindsTo: "Repository + workflow + ref + job + environment",
    ttl: "≤ 6 hours (default 15 min)",
    rotation: "Per workflow run, automatic",
    trustRoot: "GitHub OIDC issuer JWKS",
    notes:
      "The lowest-friction path off long-lived API keys for any agent that runs in CI. Cloud providers (AWS, Azure, GCP) all accept GitHub's OIDC token directly.",
  },
  {
    kind: "aws-nitro",
    label: "AWS Nitro Enclave attestation",
    bestFor: "High-sensitivity agents (financial, PII, key custody)",
    bindsTo: "Enclave image hash (PCRs), parent instance, region",
    ttl: "Attestation document signed at request time",
    rotation: "Per attestation request",
    trustRoot: "AWS Nitro root of trust certificate chain",
    notes:
      "Hardware-backed. The attestation document includes PCR measurements of the enclave image, so a runtime modification of the agent invalidates the proof.",
  },
  {
    kind: "azure-managed-id",
    label: "Azure managed identity",
    bestFor: "Agents on Azure compute (App Service, Functions, AKS, VMs)",
    bindsTo: "Azure resource ID + tenant + subscription",
    ttl: "≤ 24 hours, refreshed automatically",
    rotation: "Platform-managed",
    trustRoot: "Microsoft Entra ID",
    notes:
      "System-assigned identity is the simplest pattern; user-assigned identity is required when multiple workloads share an identity intentionally (most agents should be system-assigned).",
  },
  {
    kind: "gcp-wif",
    label: "GCP Workload Identity Federation",
    bestFor: "Agents that run outside GCP and need GCP API access",
    bindsTo: "External issuer + claim mapping rules",
    ttl: "≤ 12 hours (configurable)",
    rotation: "Per token exchange",
    trustRoot: "External OIDC issuer + WIF pool policy",
    notes:
      "Lets a GitHub OIDC token, AWS STS token, or any RFC 7519 JWT be exchanged for a Google access token without storing a service-account key.",
  },
  {
    kind: "tpm",
    label: "TPM 2.0 quote",
    bestFor: "On-prem agents, edge devices, hardware roots of trust",
    bindsTo: "TPM endorsement key + PCR set + boot measurements",
    ttl: "Quote signed at request time",
    rotation: "Per quote",
    trustRoot: "TPM manufacturer EK certificate",
    notes:
      "Most rigorous attestation surface available without going to a TEE; also the highest operational lift. Worth it for agents that hold key material on the host.",
  },
  {
    kind: "apple-attest",
    label: "Apple App Attest",
    bestFor: "Agents that ride along inside an iOS/macOS client",
    bindsTo: "App bundle ID + device hardware key",
    ttl: "Per assertion",
    rotation: "Per assertion",
    trustRoot: "Apple Anonymous Attestation CA",
    notes:
      "The right primitive for endpoint-resident assistants. Less common in server-side agent stacks but increasingly relevant as agents move into client apps.",
  },
];
