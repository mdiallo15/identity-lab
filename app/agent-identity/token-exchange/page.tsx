"use client";

import { useMemo, useState } from "react";
import {
  AGENT_ACTORS,
  USER_SUBJECTS,
  buildActorJwt,
  buildExchangedJwt,
  buildSubjectJwt,
  diffExchangedClaim,
  exchangeToken,
  type ClaimOrigin,
  type DecodedJwt,
  type ExchangeResult,
  type ExchangedTokenClaims,
} from "../../../lib/agent-identity";

const SCOPE_PRESETS: Record<string, string[]> = {
  "Read-only review": ["read:repo"],
  "Code review (recommended)": ["read:repo", "write:issues"],
  "Calendar minimal": ["read:calendar"],
  "Calendar full": ["read:calendar", "write:calendar"],
  "Reports read": ["read:reports"],
  "Wildcard (anti-pattern)": ["*"],
};

const ORIGIN_COLOR: Record<ClaimOrigin, string> = {
  subject: "var(--low)",
  actor: "var(--medium)",
  sts: "var(--accent)",
  narrowed: "var(--ok)",
};

const ORIGIN_LABEL: Record<ClaimOrigin, string> = {
  subject: "from subject_token",
  actor: "from actor_token",
  sts: "minted by STS",
  narrowed: "narrowed by STS",
};

export default function TokenExchangePlayground() {
  const [userId, setUserId] = useState(USER_SUBJECTS[0].id);
  const [agentId, setAgentId] = useState(AGENT_ACTORS[0].id);
  const [scopeKey, setScopeKey] = useState("Code review (recommended)");
  const [audience, setAudience] = useState(AGENT_ACTORS[0].defaultAud);
  const [ttl, setTtl] = useState(600);

  // Freeze "now" per exchange so all three JWTs and the audit line line up.
  const [nowSeed, setNowSeed] = useState(() => Math.floor(Date.now() / 1000));

  const result: ExchangeResult = useMemo(() => {
    return exchangeToken({
      userId,
      agentId,
      scopes: SCOPE_PRESETS[scopeKey],
      audience,
      ttlSeconds: ttl,
    });
    // Re-run when nowSeed changes too so jti rotates on Exchange.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId, agentId, scopeKey, audience, ttl, nowSeed]);

  const subject: DecodedJwt = useMemo(() => {
    const u = USER_SUBJECTS.find((x) => x.id === userId)!;
    return buildSubjectJwt(u, nowSeed);
  }, [userId, nowSeed]);

  const actor: DecodedJwt = useMemo(() => {
    const a = AGENT_ACTORS.find((x) => x.id === agentId)!;
    return buildActorJwt(a, nowSeed);
  }, [agentId, nowSeed]);

  const exchanged: DecodedJwt = useMemo(
    () => buildExchangedJwt(result.claims),
    [result.claims],
  );

  const onAgentChange = (id: string) => {
    setAgentId(id);
    const a = AGENT_ACTORS.find((x) => x.id === id);
    if (a) setAudience(a.defaultAud);
  };

  const exchangedKeys = Object.keys(result.claims) as Array<
    keyof ExchangedTokenClaims
  >;

  return (
    <>
      <h1>Token-exchange playground</h1>
      <p className="lede">
        RFC 8693 OAuth 2.0 Token Exchange end-to-end. The IdP receives a
        user&apos;s passkey-bound <code>subject_token</code> and the
        agent&apos;s workload-attested <code>actor_token</code>, then mints a
        downscoped delegated token whose <code>act</code> claim records the
        agent identity. Edit any input — the three decoded JWTs and the
        claims diff re-run on every keystroke.
      </p>

      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: "0.75rem",
          marginBlock: "1.25rem",
        }}
      >
        <Field label="Subject (user)">
          <select
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            style={{ width: "100%" }}
          >
            {USER_SUBJECTS.map((u) => (
              <option key={u.id} value={u.id}>
                {u.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Actor (agent)">
          <select
            value={agentId}
            onChange={(e) => onAgentChange(e.target.value)}
            style={{ width: "100%" }}
          >
            {AGENT_ACTORS.map((a) => (
              <option key={a.id} value={a.id}>
                {a.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Scopes">
          <select
            value={scopeKey}
            onChange={(e) => setScopeKey(e.target.value)}
            style={{ width: "100%" }}
          >
            {Object.keys(SCOPE_PRESETS).map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Audience">
          <input
            value={audience}
            onChange={(e) => setAudience(e.target.value)}
            style={{ width: "100%" }}
          />
        </Field>
        <Field label={`TTL (s): ${ttl}`}>
          <input
            type="range"
            min={60}
            max={7200}
            step={60}
            value={ttl}
            onChange={(e) => setTtl(Number(e.target.value))}
            style={{ width: "100%" }}
          />
        </Field>
        <div style={{ display: "flex", alignItems: "end" }}>
          <button
            type="button"
            onClick={() => setNowSeed(Math.floor(Date.now() / 1000))}
            style={{
              width: "100%",
              padding: "0.5rem 0.8rem",
              background: "var(--accent)",
              color: "var(--bg)",
              border: "none",
              fontWeight: 600,
              fontSize: "0.85rem",
              cursor: "pointer",
            }}
          >
            Exchange ↻
          </button>
        </div>
      </section>

      {result.warnings.length > 0 && (
        <section
          style={{
            border: "1px solid var(--high)",
            background: "rgba(248, 113, 113, 0.08)",
            padding: "0.75rem 1rem",
            marginBlock: "1rem",
          }}
        >
          <strong style={{ color: "var(--high)" }}>IdP warnings</strong>
          <ul style={{ margin: "0.5rem 0 0", paddingLeft: "1.2rem" }}>
            {result.warnings.map((w, i) => (
              <li key={i} style={{ fontSize: "0.85rem" }}>
                {w}
              </li>
            ))}
          </ul>
        </section>
      )}

      <h2>Tokens, side-by-side</h2>
      <p style={{ fontSize: "0.9rem", color: "var(--ink-dim)" }}>
        Click any token to copy its compact JWS string. The signature segment
        is a deterministic demo hash (so the lab works offline); the JWT lab
        at <a href="/identity/jwt">/identity/jwt</a> covers real signing.
      </p>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr 1fr",
          gap: "0.75rem",
          alignItems: "stretch",
        }}
      >
        <TokenColumn
          title="subject_token"
          subtitle="user, passkey-bound"
          tone="var(--low)"
          jwt={subject}
        />
        <TokenColumn
          title="actor_token"
          subtitle="agent workload, attested"
          tone="var(--medium)"
          jwt={actor}
        />
        <TokenColumn
          title="access_token (exchanged)"
          subtitle="delegated, downscoped, time-bound"
          tone="var(--accent)"
          jwt={exchanged}
          diffKeys={exchangedKeys}
          diffFor={(k) => diffExchangedClaim(k, result.claims, subject, actor)}
        />
      </div>

      <h2 style={{ marginTop: "1.5rem" }}>Claims diff</h2>
      <p style={{ fontSize: "0.9rem", color: "var(--ink-dim)" }}>
        Every claim in the exchanged token, coloured by origin. The point of
        token exchange is downscoping plus attribution — both should be
        visible here.
      </p>
      <table
        style={{
          width: "100%",
          borderCollapse: "collapse",
          fontSize: "0.82rem",
        }}
      >
        <thead>
          <tr style={{ textAlign: "left", color: "var(--ink-dim)" }}>
            <th style={{ padding: "0.3rem 0.5rem" }}>claim</th>
            <th style={{ padding: "0.3rem 0.5rem" }}>origin</th>
            <th style={{ padding: "0.3rem 0.5rem" }}>value</th>
            <th style={{ padding: "0.3rem 0.5rem" }}>why</th>
          </tr>
        </thead>
        <tbody>
          {exchangedKeys.map((k) => {
            const d = diffExchangedClaim(k, result.claims, subject, actor);
            const v = (result.claims as unknown as Record<string, unknown>)[
              k
            ];
            return (
              <tr key={k} style={{ borderTop: "1px solid var(--rule)" }}>
                <td
                  style={{
                    padding: "0.35rem 0.5rem",
                    fontFamily: "var(--mono, monospace)",
                  }}
                >
                  {k}
                </td>
                <td style={{ padding: "0.35rem 0.5rem" }}>
                  <span
                    style={{
                      display: "inline-block",
                      padding: "0.1rem 0.5rem",
                      border: `1px solid ${ORIGIN_COLOR[d.origin]}`,
                      color: ORIGIN_COLOR[d.origin],
                      fontSize: "0.72rem",
                      textTransform: "uppercase",
                      letterSpacing: "0.04em",
                    }}
                  >
                    {ORIGIN_LABEL[d.origin]}
                  </span>
                </td>
                <td
                  style={{
                    padding: "0.35rem 0.5rem",
                    fontFamily: "var(--mono, monospace)",
                    wordBreak: "break-all",
                  }}
                >
                  {typeof v === "string" || typeof v === "number"
                    ? String(v)
                    : JSON.stringify(v)}
                </td>
                <td
                  style={{
                    padding: "0.35rem 0.5rem",
                    color: "var(--ink-dim)",
                  }}
                >
                  {d.note}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <h2 style={{ marginTop: "1.5rem" }}>RFC 8693 request</h2>
      <pre style={{ fontSize: "0.78rem" }}>
        <code>
          {`POST /token HTTP/1.1
Host: idp.lab.marwandiallo.com
Content-Type: application/x-www-form-urlencoded

grant_type=${result.request.grant_type}
&requested_token_type=${result.request.requested_token_type}
&subject_token=${subject.compact}
&subject_token_type=${result.request.subject_token_type}
&actor_token=${actor.compact}
&actor_token_type=${result.request.actor_token_type}
&audience=${encodeURIComponent(result.request.audience)}
&scope=${encodeURIComponent(result.request.scope)}`}
        </code>
      </pre>

      <h2>Audit log line</h2>
      <pre style={{ fontSize: "0.8rem" }}>
        <code>{result.auditLine}</code>
      </pre>
      <p style={{ fontSize: "0.85rem", color: "var(--ink-dim)" }}>
        Without <code>act</code>, the same line would read{" "}
        <code>principal={result.claims.sub}</code> with no record of the
        agent — making the call indistinguishable from the user typing it
        themselves.
      </p>

      <h2>References</h2>
      <ul>
        <li>
          <a
            href="https://www.rfc-editor.org/rfc/rfc8693"
            target="_blank"
            rel="noopener noreferrer"
          >
            RFC 8693 — OAuth 2.0 Token Exchange
          </a>{" "}
          (§1.2 principal preservation; §4.1 <code>act</code> claim)
        </li>
        <li>
          <a
            href="https://www.rfc-editor.org/rfc/rfc9449"
            target="_blank"
            rel="noopener noreferrer"
          >
            RFC 9449 — Demonstrating Proof of Possession (DPoP)
          </a>{" "}
          — sender-constraint via <code>cnf.jkt</code>
        </li>
        <li>
          <a
            href="https://csrc.nist.gov/pubs/sp/800/63/4/2pd"
            target="_blank"
            rel="noopener noreferrer"
          >
            NIST SP 800-63-4 (draft) — Digital Identity Guidelines
          </a>{" "}
          — non-person entity treatment
        </li>
        <li>
          <a
            href="https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/"
            target="_blank"
            rel="noopener noreferrer"
          >
            SPIFFE — workload identity URIs
          </a>{" "}
          (the <code>act.sub</code> shape used above)
        </li>
        <li>
          <a
            href="https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect"
            target="_blank"
            rel="noopener noreferrer"
          >
            GitHub Actions OIDC
          </a>
          ,{" "}
          <a
            href="https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview"
            target="_blank"
            rel="noopener noreferrer"
          >
            Azure managed identity
          </a>
          ,{" "}
          <a
            href="https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html"
            target="_blank"
            rel="noopener noreferrer"
          >
            AWS Nitro Enclaves
          </a>
          ,{" "}
          <a
            href="https://cloud.google.com/iam/docs/workload-identity-federation"
            target="_blank"
            rel="noopener noreferrer"
          >
            GCP Workload Identity Federation
          </a>{" "}
          — the four mainstream actor_token attestation surfaces.
        </li>
      </ul>
    </>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label>
      <span
        style={{
          display: "block",
          fontSize: "0.78rem",
          color: "var(--ink-dim)",
          marginBottom: "0.25rem",
        }}
      >
        {label}
      </span>
      {children}
    </label>
  );
}

function TokenColumn({
  title,
  subtitle,
  tone,
  jwt,
  diffKeys,
  diffFor,
}: {
  title: string;
  subtitle: string;
  tone: string;
  jwt: DecodedJwt;
  diffKeys?: Array<keyof ExchangedTokenClaims>;
  diffFor?: (k: keyof ExchangedTokenClaims) => {
    origin: ClaimOrigin;
    note: string;
  };
}) {
  const [copied, setCopied] = useState(false);
  function copy() {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard
        .writeText(jwt.compact)
        .then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        })
        .catch(() => window.prompt("Copy:", jwt.compact));
    } else {
      window.prompt("Copy:", jwt.compact);
    }
  }
  return (
    <div
      style={{
        border: `1px solid ${tone}`,
        padding: "0.65rem 0.75rem",
        background: "var(--bg-elev)",
        display: "flex",
        flexDirection: "column",
        gap: "0.4rem",
      }}
    >
      <div>
        <strong style={{ color: tone, fontSize: "0.85rem" }}>{title}</strong>
        <div style={{ fontSize: "0.72rem", color: "var(--ink-dim)" }}>
          {subtitle}
        </div>
      </div>
      <button
        type="button"
        onClick={copy}
        title="Click to copy compact JWS"
        style={{
          fontSize: "0.7rem",
          padding: "0.3rem 0.4rem",
          background: "var(--bg)",
          color: "var(--ink-dim)",
          border: "1px solid var(--rule)",
          textAlign: "left",
          fontFamily: "var(--mono, monospace)",
          wordBreak: "break-all",
          cursor: "pointer",
        }}
      >
        {copied ? "✓ copied" : jwt.compact}
      </button>
      <Section heading="header">
        <KvList obj={jwt.header} />
      </Section>
      <Section heading="payload">
        <KvList
          obj={jwt.payload}
          tones={
            diffKeys && diffFor
              ? Object.fromEntries(
                  diffKeys.map((k) => [
                    k,
                    ORIGIN_COLOR[diffFor(k).origin],
                  ]),
                )
              : undefined
          }
        />
      </Section>
    </div>
  );
}

function Section({
  heading,
  children,
}: {
  heading: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <div
        style={{
          fontSize: "0.68rem",
          color: "var(--ink-dim)",
          textTransform: "uppercase",
          letterSpacing: "0.05em",
          marginBottom: "0.2rem",
        }}
      >
        {heading}
      </div>
      {children}
    </div>
  );
}

function KvList({
  obj,
  tones,
}: {
  obj: Record<string, unknown>;
  tones?: Record<string, string>;
}) {
  return (
    <div
      style={{
        fontFamily: "var(--mono, monospace)",
        fontSize: "0.74rem",
        background: "var(--bg)",
        border: "1px solid var(--rule)",
        padding: "0.35rem 0.5rem",
      }}
    >
      {Object.entries(obj).map(([k, v]) => (
        <div
          key={k}
          style={{
            display: "grid",
            gridTemplateColumns: "auto 1fr",
            gap: "0.4rem",
            padding: "0.1rem 0",
            color: tones?.[k] ?? "var(--ink)",
            wordBreak: "break-all",
          }}
        >
          <span style={{ color: "var(--ink-dim)" }}>{k}:</span>
          <span>
            {typeof v === "string" || typeof v === "number"
              ? String(v)
              : JSON.stringify(v)}
          </span>
        </div>
      ))}
    </div>
  );
}
