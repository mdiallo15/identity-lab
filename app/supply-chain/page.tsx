"use client";

import { useMemo, useState } from "react";
import {
  INCIDENTS,
  SCENARIOS,
  TYPOSQUATS,
  analyzePackage,
  type ProvFinding,
  type ProvScenario,
  type SupplyChainIncident,
} from "@/lib/supply-chain";

export default function SupplyChainLab() {
  const [activeId, setActiveId] = useState<string>(SCENARIOS[0].id);
  const active: ProvScenario =
    SCENARIOS.find((s) => s.id === activeId) ?? SCENARIOS[0];

  const findings: ProvFinding[] = useMemo(
    () => analyzePackage(active.input),
    [active],
  );

  const matchedIncident: SupplyChainIncident | undefined = active.incidentId
    ? INCIDENTS.find((i) => i.id === active.incidentId)
    : undefined;

  return (
    <>
      <h1>Supply Chain</h1>
      <p className="lede">
        Real package-registry compromises, replayed against a live provenance
        analyzer. Every scenario reproduces a public incident — event-stream,
        ua-parser-js, node-ipc, 3CX, XZ, Ultralytics, LottieFiles,
        tj-actions — using the metadata signals that distinguished the
        poisoned version from the clean one.
      </p>

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
        <strong>How this works.</strong> Each scenario carries a plausibly-real{" "}
        <code>package.json</code> and a reconstructed registry response. The
        analyzer applies seven rules (PROV01–PROV07) covering install hooks,
        rapid republish bursts, publisher-IP drift, missing build provenance,
        unfamiliar builder identities, recent maintainer changes, and known
        typosquat patterns. Every signal is something you could collect from
        the registry alone, before the package ever runs on your machine.
      </div>

      {/* ------------------ Scenario catalog ------------------ */}
      <h2 style={{ marginTop: "1.6rem" }}>Real incident replicas</h2>
      <div className="csp-scenarios">
        {SCENARIOS.map((s) => (
          <button
            key={s.id}
            onClick={() => setActiveId(s.id)}
            data-active={s.id === activeId}
            className="csp-scenario-card"
            type="button"
          >
            <span className="csp-scenario-cat">
              {s.incidentId ? "incident" : "pattern"}
            </span>
            <span className="csp-scenario-title">{s.title}</span>
          </button>
        ))}
      </div>

      <div className="csp-scenario-detail">
        <p>
          <strong>What you&apos;re looking at.</strong> {active.blurb}
        </p>
        <p>
          <strong>Expected:</strong> {active.expected}
        </p>
        {matchedIncident && (
          <details style={{ marginTop: "0.4rem" }}>
            <summary
              style={{
                cursor: "pointer",
                fontSize: "0.82rem",
                color: "var(--accent)",
              }}
            >
              real-world details — {matchedIncident.pkg} ({matchedIncident.date}
              {matchedIncident.cve ? `, ${matchedIncident.cve}` : ""})
            </summary>
            <p style={{ marginTop: "0.5rem" }}>
              <strong>Vector.</strong> {matchedIncident.vector}
            </p>
            <p>
              <strong>Payload.</strong> {matchedIncident.payload}
            </p>
            <p>
              <strong>Blast radius.</strong> {matchedIncident.blastRadius}
            </p>
            <p style={{ fontSize: "0.78rem", color: "var(--ink-dim)" }}>
              <strong>refs:</strong>{" "}
              {matchedIncident.references.map((r, i) => (
                <span key={r}>
                  <a href={r} target="_blank" rel="noopener noreferrer">
                    {new URL(r).hostname}
                  </a>
                  {i < matchedIncident.references.length - 1 ? " · " : ""}
                </span>
              ))}
            </p>
          </details>
        )}
      </div>

      {/* ------------------ Inputs ------------------ */}
      <h2 style={{ marginTop: "1.6rem" }}>package.json + registry response</h2>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "0.8rem",
        }}
      >
        <div>
          <label
            style={{
              display: "block",
              fontSize: "0.78rem",
              color: "var(--ink-dim)",
            }}
          >
            package.json (read-only fixture)
          </label>
          <pre
            style={{
              background: "var(--bg-elev)",
              border: "1px solid var(--rule)",
              padding: "0.6rem 0.8rem",
              fontSize: "0.78rem",
              overflowX: "auto",
              marginTop: "0.3rem",
              whiteSpace: "pre-wrap",
            }}
          >
            {active.input.pkgJson}
          </pre>
        </div>
        <div>
          <label
            style={{
              display: "block",
              fontSize: "0.78rem",
              color: "var(--ink-dim)",
            }}
          >
            registry metadata
          </label>
          <pre
            style={{
              background: "var(--bg-elev)",
              border: "1px solid var(--rule)",
              padding: "0.6rem 0.8rem",
              fontSize: "0.78rem",
              overflowX: "auto",
              marginTop: "0.3rem",
              whiteSpace: "pre-wrap",
            }}
          >
            {JSON.stringify(active.input.registry, null, 2)}
          </pre>
        </div>
      </div>

      {/* ------------------ Findings ------------------ */}
      <h2 style={{ marginTop: "1.6rem" }}>
        Provenance findings ({findings.length})
      </h2>
      {findings.length === 0 && (
        <p>
          <span className="status ok">No findings.</span> The package looks
          clean against PROV01–PROV07 with the metadata available pre-install.
        </p>
      )}
      <div className="findings">
        {findings.map((f, i) => (
          <div key={`${f.id}-${i}`} className={`finding ${f.severity}`}>
            <div>
              <span className="sev">{f.severity}</span>
              <strong>{f.id}</strong> &mdash; {f.title}
            </div>
            <p style={{ margin: "0.4rem 0 0.3rem", color: "var(--ink-dim)" }}>
              {f.detail}
            </p>
            <p style={{ margin: 0, fontSize: "0.88rem" }}>
              <strong style={{ color: "var(--ok)" }}>fix:</strong> {f.fix}
            </p>
          </div>
        ))}
      </div>

      {/* ------------------ Typosquat reference ------------------ */}
      <h2 style={{ marginTop: "1.6rem" }}>Typosquat reference patterns</h2>
      <p style={{ color: "var(--ink-dim)", fontSize: "0.88rem" }}>
        Ten patterns the analyzer&apos;s PROV07 rule scores against. Drawn from
        documented real incidents where possible.
      </p>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr",
          gap: "0.4rem",
          marginTop: "0.5rem",
        }}
      >
        {TYPOSQUATS.map((t) => (
          <div
            key={t.squat}
            style={{
              border: "1px solid var(--rule)",
              padding: "0.5rem 0.7rem",
              fontSize: "0.85rem",
              display: "grid",
              gridTemplateColumns: "1fr 1fr 1fr",
              gap: "0.6rem",
              alignItems: "center",
            }}
          >
            <code>{t.legitimate}</code>
            <code style={{ color: "var(--high)" }}>{t.squat}</code>
            <span style={{ color: "var(--ink-dim)", fontSize: "0.78rem" }}>
              {t.technique}
              {t.realIncident && ` · ${t.realIncident}`}
            </span>
          </div>
        ))}
      </div>

      {/* ------------------ Reading list ------------------ */}
      <h2 style={{ marginTop: "1.6rem" }}>Incident reading list</h2>
      <ul style={{ paddingLeft: "1.2rem" }}>
        {INCIDENTS.map((i) => (
          <li key={i.id} style={{ margin: "0.4rem 0" }}>
            <strong>{i.title}</strong> ({i.date}
            {i.cve ? `, ${i.cve}` : ""}) ·{" "}
            <a href={i.references[0]} target="_blank" rel="noopener noreferrer">
              advisory
            </a>
          </li>
        ))}
      </ul>
    </>
  );
}
