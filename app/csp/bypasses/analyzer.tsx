"use client";

import { useMemo, useState } from "react";
import { analyzeBypass, BYPASS_SCENARIOS, type BypassScenario } from "@/lib/csp-bypasses";

const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;

export default function CspBypassAnalyzer() {
  const [scenarioId, setScenarioId] = useState<BypassScenario["id"]>("jsonp");
  const active = BYPASS_SCENARIOS.find((s) => s.id === scenarioId) ?? BYPASS_SCENARIOS[0];
  const [policy, setPolicy] = useState(active.policy);
  const [payload, setPayload] = useState(active.payload);

  const result = useMemo(
    () => analyzeBypass(scenarioId, policy, payload),
    [scenarioId, policy, payload],
  );

  const findings = [...result.findings].sort(
    (a, b) => sevOrder[a.severity] - sevOrder[b.severity] || a.id.localeCompare(b.id),
  );

  function loadScenario(next: BypassScenario) {
    setScenarioId(next.id);
    setPolicy(next.policy);
    setPayload(next.payload);
  }

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
        <strong>How this works.</strong> Pick a real bypass class, edit the
        CSP and the attacker payload, and the lab decides whether the bypass
        lands, is blocked, or is merely invisible to operations.
      </div>

      <h2 style={{ marginTop: "1.5rem" }}>Bypass catalog</h2>
      <div className="csp-scenarios">
        {BYPASS_SCENARIOS.map((scenario) => (
          <button
            key={scenario.id}
            type="button"
            className="csp-scenario-card"
            data-active={scenario.id === scenarioId}
            onClick={() => loadScenario(scenario)}
          >
            <span className="csp-scenario-cat">{scenario.category}</span>
            <span className="csp-scenario-title">{scenario.title}</span>
          </button>
        ))}
      </div>

      <div className="csp-scenario-detail">
        <p>{active.lesson}</p>
        <p style={{ fontSize: "0.78rem", color: "var(--ink-dim)" }}>
          Reference:{" "}
          <a href={active.reference.url} target="_blank" rel="noopener noreferrer">
            {active.reference.label}
          </a>
        </p>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "0.9rem",
          marginTop: "0.9rem",
        }}
      >
        <section>
          <label style={{ display: "block", marginBottom: "0.35rem" }}>
            <strong>Policy under test</strong>
          </label>
          <textarea value={policy} onChange={(e) => setPolicy(e.target.value)} spellCheck={false} />
        </section>
        <section>
          <label style={{ display: "block", marginBottom: "0.35rem" }}>
            <strong>Attacker payload</strong>
          </label>
          <textarea value={payload} onChange={(e) => setPayload(e.target.value)} spellCheck={false} />
        </section>
      </div>

      <div
        style={{
          marginTop: "1rem",
          padding: "0.85rem 1rem",
          border: `1px solid ${
            result.verdict === "lands"
              ? "#ef4444"
              : result.verdict === "degraded"
                ? "#fbbf24"
                : "#22c55e"
          }`,
          background:
            result.verdict === "lands"
              ? "rgba(239, 68, 68, 0.06)"
              : result.verdict === "degraded"
                ? "rgba(251, 191, 36, 0.06)"
                : "rgba(34, 197, 94, 0.06)",
        }}
      >
        <strong>
          {result.verdict === "lands"
            ? "Bypass lands"
            : result.verdict === "degraded"
              ? "Payload blocked, but ops is blind"
              : "Payload blocked"}
        </strong>
      </div>

      <h2 style={{ marginTop: "1.5rem" }}>Lab findings ({findings.length})</h2>
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

      <h2 style={{ marginTop: "1.5rem" }}>Baseline CSP analyzer findings</h2>
      <div className="findings">
        {result.cspFindings.map((finding) => (
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