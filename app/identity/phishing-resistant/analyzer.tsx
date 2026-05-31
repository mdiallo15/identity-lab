"use client";

import { useMemo, useState } from "react";
import {
  ATTACKS,
  FACTORS,
  analyzeMfa,
  type AttackScenario,
  type Factor,
} from "@/lib/phishing-resistant";

const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;

export default function PhishingResistantAnalyzer() {
  const [factorId, setFactorId] = useState<Factor["id"]>("passkey");
  const [attackId, setAttackId] = useState<AttackScenario["id"]>("aitm");
  const [fallbackEnabled, setFallbackEnabled] = useState(false);
  const [helpdeskResetWeak, setHelpdeskResetWeak] = useState(false);
  const [tokenBindingEnabled, setTokenBindingEnabled] = useState(false);
  const [numberMatchingEnabled, setNumberMatchingEnabled] = useState(true);

  const activeAttack = ATTACKS.find((a) => a.id === attackId) ?? ATTACKS[0];
  const activeFactor = FACTORS.find((f) => f.id === factorId) ?? FACTORS[0];
  const result = useMemo(
    () =>
      analyzeMfa({
        factorId,
        attackId,
        fallbackEnabled,
        helpdeskResetWeak,
        tokenBindingEnabled,
        numberMatchingEnabled,
      }),
    [
      factorId,
      attackId,
      fallbackEnabled,
      helpdeskResetWeak,
      tokenBindingEnabled,
      numberMatchingEnabled,
    ],
  );

  const findings = [...result.findings].sort(
    (a, b) => sevOrder[a.severity] - sevOrder[b.severity] || a.id.localeCompare(b.id),
  );

  return (
    <>
      <div
        style={{
          marginTop: "0.4rem",
          padding: "0.6rem 0.8rem",
          border: "1px dashed var(--rule)",
          fontSize: "0.78rem",
          color: "var(--ink-dim)",
          background: "var(--bg-elev)",
        }}
      >
        <strong>How this works.</strong> Pick a factor and an attack path,
        then change the recovery and session controls. The lab scores whether
        the attacker is blocked, forced into a degraded path, or fully
        compromises the account/session.
      </div>

      <h2 style={{ marginTop: "1.5rem" }}>Attack replay</h2>
      <div className="csp-scenarios">
        {ATTACKS.map((attack) => (
          <button
            key={attack.id}
            type="button"
            onClick={() => setAttackId(attack.id)}
            className="csp-scenario-card"
            data-active={attack.id === attackId}
          >
            <span className="csp-scenario-cat">attack</span>
            <span className="csp-scenario-title">{attack.title}</span>
          </button>
        ))}
      </div>

      <div className="csp-scenario-detail">
        <p>{activeAttack.blurb}</p>
        <p style={{ fontSize: "0.78rem", color: "var(--ink-dim)" }}>
          References:{" "}
          {activeAttack.references.map((ref, index) => (
            <span key={ref.url}>
              {index > 0 ? " · " : ""}
              <a href={ref.url} target="_blank" rel="noopener noreferrer">
                {ref.label}
              </a>
            </span>
          ))}
        </p>
      </div>

      <h2 style={{ marginTop: "1.5rem" }}>Live controls</h2>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1.1fr 1fr",
          gap: "0.9rem",
          marginTop: "0.6rem",
        }}
      >
        <section className="card">
          <label style={{ display: "block", marginBottom: "0.75rem" }}>
            <strong>Primary factor</strong>
            <select
              value={factorId}
              onChange={(e) => setFactorId(e.target.value as Factor["id"])}
              style={{ display: "block", marginTop: "0.35rem" }}
            >
              {FACTORS.map((factor) => (
                <option key={factor.id} value={factor.id}>
                  {factor.label}
                </option>
              ))}
            </select>
          </label>

          <p style={{ fontSize: "0.86rem", color: "var(--ink-dim)" }}>
            {activeFactor.blurb}
          </p>

          <label style={{ display: "block", margin: "0.65rem 0" }}>
            <input
              type="checkbox"
              checked={fallbackEnabled}
              onChange={(e) => setFallbackEnabled(e.target.checked)}
              style={{ width: "auto", marginRight: "0.45rem" }}
            />
            allow fallback to a weaker factor when the primary rail fails
          </label>

          <label style={{ display: "block", margin: "0.65rem 0" }}>
            <input
              type="checkbox"
              checked={helpdeskResetWeak}
              onChange={(e) => setHelpdeskResetWeak(e.target.checked)}
              style={{ width: "auto", marginRight: "0.45rem" }}
            />
            helpdesk can reset or re-enroll the factor with weak identity proofing
          </label>

          <label style={{ display: "block", margin: "0.65rem 0" }}>
            <input
              type="checkbox"
              checked={tokenBindingEnabled}
              onChange={(e) => setTokenBindingEnabled(e.target.checked)}
              style={{ width: "auto", marginRight: "0.45rem" }}
            />
            privileged session uses sender-constrained tokens / DPoP
          </label>

          <label style={{ display: "block", margin: "0.65rem 0" }}>
            <input
              type="checkbox"
              checked={numberMatchingEnabled}
              onChange={(e) => setNumberMatchingEnabled(e.target.checked)}
              style={{ width: "auto", marginRight: "0.45rem" }}
            />
            push approvals require number matching / user confirmation context
          </label>
        </section>

        <section
          style={{
            border: `1px solid ${
              result.outcome === "blocked"
                ? "#22c55e"
                : result.outcome === "degraded"
                  ? "#fbbf24"
                  : "#ef4444"
            }`,
            background:
              result.outcome === "blocked"
                ? "rgba(34, 197, 94, 0.06)"
                : result.outcome === "degraded"
                  ? "rgba(251, 191, 36, 0.06)"
                  : "rgba(239, 68, 68, 0.06)",
            padding: "0.9rem 1rem",
          }}
        >
          <h3 style={{ marginTop: 0 }}>Outcome</h3>
          <p style={{ margin: "0 0 0.5rem" }}>
            <strong>
              {result.outcome === "blocked"
                ? "Blocked"
                : result.outcome === "degraded"
                  ? "Degraded"
                  : "Compromised"}
            </strong>
          </p>
          <ol style={{ paddingLeft: "1.1rem", marginBottom: 0 }}>
            {result.trace.map((step) => (
              <li key={step.label} style={{ marginBottom: "0.45rem" }}>
                <strong>{step.label}</strong> — {step.detail}
              </li>
            ))}
          </ol>
        </section>
      </div>

      <h2 style={{ marginTop: "1.5rem" }}>Findings ({findings.length})</h2>
      <div className="findings">
        {findings.map((finding) => (
          <article key={finding.id} className={`finding ${finding.severity}`}>
            <div>
              <span className="sev">{finding.severity}</span>
              <strong>{finding.id}</strong> — {finding.title}
            </div>
            <p>{finding.detail}</p>
            <p style={{ fontSize: "0.88rem", color: "var(--ink-dim)" }}>
              <strong>fix:</strong> {finding.fix}
            </p>
          </article>
        ))}
      </div>
    </>
  );
}