"use client";

import { useMemo, useState } from "react";
import {
  AGENT_ACTORS,
  USER_SUBJECTS,
  exchangeToken,
  type ExchangeResult,
} from "../../../lib/agent-identity";

const SCOPE_PRESETS: Record<string, string[]> = {
  "Read-only review": ["read:repo"],
  "Code review (recommended)": ["read:repo", "write:issues"],
  "Calendar minimal": ["read:calendar"],
  "Calendar full": ["read:calendar", "write:calendar"],
  "Reports read": ["read:reports"],
  "Wildcard (anti-pattern)": ["*"],
};

export default function TokenExchangePlayground() {
  const [userId, setUserId] = useState(USER_SUBJECTS[0].id);
  const [agentId, setAgentId] = useState(AGENT_ACTORS[0].id);
  const [scopeKey, setScopeKey] = useState("Code review (recommended)");
  const [audience, setAudience] = useState(AGENT_ACTORS[0].defaultAud);
  const [ttl, setTtl] = useState(600);

  const result: ExchangeResult = useMemo(() => {
    return exchangeToken({
      userId,
      agentId,
      scopes: SCOPE_PRESETS[scopeKey],
      audience,
      ttlSeconds: ttl,
    });
  }, [userId, agentId, scopeKey, audience, ttl]);

  const onAgentChange = (id: string) => {
    setAgentId(id);
    const a = AGENT_ACTORS.find((x) => x.id === id);
    if (a) setAudience(a.defaultAud);
  };

  return (
    <>
      <h1>Token-exchange playground</h1>
      <p className="lede">
        RFC 8693 OAuth 2.0 Token Exchange in motion. The user has authenticated
        with a passkey. The agent has its own workload identity. The exchange
        produces a downscoped, time-bounded token whose <code>act</code> claim
        captures the delegation — so receiving services log <em>both</em> the
        user and the acting agent in their audit trail.
      </p>

      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: "1rem",
          marginBlock: "1.5rem",
        }}
      >
        <label>
          <span style={{ display: "block", fontSize: "0.85rem" }}>
            Subject (user)
          </span>
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
        </label>

        <label>
          <span style={{ display: "block", fontSize: "0.85rem" }}>
            Actor (agent)
          </span>
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
        </label>

        <label>
          <span style={{ display: "block", fontSize: "0.85rem" }}>Scopes</span>
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
        </label>

        <label>
          <span style={{ display: "block", fontSize: "0.85rem" }}>
            Audience
          </span>
          <input
            value={audience}
            onChange={(e) => setAudience(e.target.value)}
            style={{ width: "100%" }}
          />
        </label>

        <label>
          <span style={{ display: "block", fontSize: "0.85rem" }}>
            TTL (seconds): {ttl}
          </span>
          <input
            type="range"
            min={60}
            max={7200}
            step={60}
            value={ttl}
            onChange={(e) => setTtl(Number(e.target.value))}
            style={{ width: "100%" }}
          />
        </label>
      </section>

      {result.warnings.length > 0 && (
        <section
          style={{
            border: "1px solid #c2410c",
            background: "rgba(194, 65, 12, 0.08)",
            padding: "0.75rem 1rem",
            borderRadius: 8,
            marginBlock: "1rem",
          }}
        >
          <strong style={{ color: "#c2410c" }}>IdP warnings</strong>
          <ul style={{ margin: "0.5rem 0 0", paddingLeft: "1.2rem" }}>
            {result.warnings.map((w, i) => (
              <li key={i} style={{ fontSize: "0.9rem" }}>
                {w}
              </li>
            ))}
          </ul>
        </section>
      )}

      <h2>RFC 8693 request</h2>
      <pre>
        <code>
          {`POST /token HTTP/1.1
Host: idp.lab.marwandiallo.com
Content-Type: application/x-www-form-urlencoded

grant_type=${result.request.grant_type}
&requested_token_type=${result.request.requested_token_type}
&subject_token=${result.request.subject_token}
&subject_token_type=${result.request.subject_token_type}
&actor_token=${result.request.actor_token}
&actor_token_type=${result.request.actor_token_type}
&audience=${result.request.audience}
&scope=${encodeURIComponent(result.request.scope)}`}
        </code>
      </pre>

      <h2>Delegated token claims (decoded)</h2>
      <pre>
        <code>{JSON.stringify(result.claims, null, 2)}</code>
      </pre>
      <p style={{ fontSize: "0.85rem", color: "var(--ink-dim, #888)" }}>
        <strong>What to look at:</strong> <code>sub</code> is the user;{" "}
        <code>act.sub</code> is the agent's workload identity;{" "}
        <code>act.attestation</code> records which platform vouched for the
        agent; <code>aud</code> and <code>scope</code> bound where and how the
        token can be presented; <code>cnf.jkt</code> sender-constrains the
        token (RFC 9449 DPoP).
      </p>

      <h2>What the audit log shows</h2>
      <pre>
        <code>{result.auditLine}</code>
      </pre>
      <p>
        Without <code>act</code>, the same line would say{" "}
        <code>principal={result.claims.sub}</code> with no record of the agent
        — making the call indistinguishable from the user typing it in
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
          </a>
        </li>
        <li>
          <a
            href="https://www.rfc-editor.org/rfc/rfc9449"
            target="_blank"
            rel="noopener noreferrer"
          >
            RFC 9449 — Demonstrating Proof of Possession (DPoP)
          </a>
        </li>
        <li>
          <a
            href="https://csrc.nist.gov/pubs/sp/800/63/4/2pd"
            target="_blank"
            rel="noopener noreferrer"
          >
            NIST SP 800-63-4 (draft) — Digital Identity Guidelines
          </a>
        </li>
      </ul>
    </>
  );
}
