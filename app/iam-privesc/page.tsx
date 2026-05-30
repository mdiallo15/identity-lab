"use client";

import { useMemo, useState } from "react";
import { LearnCallout } from "@/app/_components/learn-callout";
import {
  SCENARIOS,
  TECHNIQUES,
  enumerateAttackPaths,
  type AttackEdge,
  type AttackPath,
  type IamScenario,
  type Principal,
} from "@/lib/iam-privesc";

const ADMIN_NODE = "*admin*";

export default function IamPrivescLab() {
  const [activeId, setActiveId] = useState<string>(SCENARIOS[0].id);
  const active: IamScenario =
    SCENARIOS.find((s) => s.id === activeId) ?? SCENARIOS[0];

  // Editable copy of the principal list. JSON-encoded so users can flip
  // permissions, add/remove principals, and watch the path engine update.
  const [principalsJson, setPrincipalsJson] = useState<string>(
    JSON.stringify(active.principals, null, 2),
  );
  const [parseError, setParseError] = useState<string | null>(null);

  function loadScenario(id: string) {
    const s = SCENARIOS.find((x) => x.id === id) ?? SCENARIOS[0];
    setActiveId(s.id);
    setPrincipalsJson(JSON.stringify(s.principals, null, 2));
    setParseError(null);
  }

  const { principals, paths, edges } = useMemo(() => {
    let parsed: Principal[];
    try {
      parsed = JSON.parse(principalsJson);
      if (parseError) setParseError(null);
    } catch (e) {
      setParseError((e as Error).message);
      parsed = active.principals;
    }
    const result = enumerateAttackPaths({
      ...active,
      principals: parsed,
    });
    return { principals: parsed, ...result };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [principalsJson, active]);

  const adminPaths = paths.filter((p) => p.endsAtAdmin);

  const techIndex = new Map(TECHNIQUES.map((t) => [t.id, t]));

  return (
    <>
      <h1>IAM Privilege Escalation</h1>
      <LearnCallout href="/iam-privesc" />
      <p className="lede">
        A live cloud-IAM attack-path enumerator. Each scenario seeds a small
        directory of users, roles, groups, and service principals; the engine
        derives every attack edge from the permissions held, then enumerates
        every path from the starting principal to admin. Edit the principal
        list and watch paths appear and disappear.
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
        <strong>How this works.</strong> The engine knows {TECHNIQUES.length}{" "}
        published techniques across AWS, Azure, and GCP. For each principal it
        evaluates every technique&apos;s permission set against the
        principal&apos;s effective permissions (direct + group-inherited),
        derives outbound edges, then BFS&apos;s from the starting principal
        looking for paths to the admin sentinel. Path enumeration capped at
        depth 6 / 25 paths to keep the UI responsive on adversarial inputs.
      </div>

      {/* ------------------ Scenario picker ------------------ */}
      <h2 style={{ marginTop: "1.6rem" }}>Scenarios</h2>
      <div className="csp-scenarios">
        {SCENARIOS.map((s) => (
          <button
            key={s.id}
            onClick={() => loadScenario(s.id)}
            data-active={s.id === activeId}
            className="csp-scenario-card"
            type="button"
          >
            <span className="csp-scenario-cat">{s.provider}</span>
            <span className="csp-scenario-title">{s.title}</span>
          </button>
        ))}
      </div>

      <div className="csp-scenario-detail">
        <p>
          <strong>Setup.</strong> {active.blurb}
        </p>
        <p>
          <strong>Starting principal:</strong> <code>{active.startingPrincipal}</code>
        </p>
        {active.reference && (
          <p style={{ fontSize: "0.78rem", color: "var(--ink-dim)" }}>
            <strong>reference:</strong> {active.reference}
          </p>
        )}
      </div>

      {/* ------------------ Principal editor ------------------ */}
      <h2 style={{ marginTop: "1.6rem" }}>Principals (editable)</h2>
      <p style={{ color: "var(--ink-dim)", fontSize: "0.88rem" }}>
        Add, remove, or modify principals. Try removing{" "}
        <code>iam:PassRole</code> from the starting user to break the chain;
        try adding <code>iam:AttachUserPolicy</code> to enable a one-step
        path. Changes are reflected immediately in the path enumerator below.
      </p>
      {parseError && (
        <p style={{ color: "var(--high)", fontSize: "0.82rem" }}>
          parse error: {parseError}
        </p>
      )}
      <textarea
        value={principalsJson}
        onChange={(e) => setPrincipalsJson(e.target.value)}
        spellCheck={false}
        style={{
          width: "100%",
          minHeight: 280,
          fontFamily: "ui-monospace, monospace",
          fontSize: "0.78rem",
        }}
      />

      {/* ------------------ Path output ------------------ */}
      <h2 style={{ marginTop: "1.6rem" }}>
        Attack paths to admin ({adminPaths.length})
      </h2>
      {adminPaths.length === 0 && (
        <p>
          <span className="status ok">
            No path to admin found from{" "}
            <code>{active.startingPrincipal}</code>.
          </span>{" "}
          The current permission set doesn&apos;t enable any of the{" "}
          {TECHNIQUES.length} techniques in the catalog.
        </p>
      )}
      {adminPaths.map((p, i) => (
        <PathView
          key={i}
          index={i}
          path={p}
          start={active.startingPrincipal}
          techIndex={techIndex}
        />
      ))}

      {/* ------------------ All edges ------------------ */}
      <h2 style={{ marginTop: "1.6rem" }}>
        Derived attack edges ({edges.length})
      </h2>
      <p style={{ color: "var(--ink-dim)", fontSize: "0.88rem" }}>
        Every transition the engine derived, even ones not on a path to
        admin. Useful for spotting near-misses and lateral movement.
      </p>
      <div style={{ overflowX: "auto" }}>
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            fontSize: "0.82rem",
          }}
        >
          <thead>
            <tr style={{ textAlign: "left", color: "var(--ink-dim)" }}>
              <th style={{ padding: "0.3rem 0.5rem" }}>from</th>
              <th style={{ padding: "0.3rem 0.5rem" }}>to</th>
              <th style={{ padding: "0.3rem 0.5rem" }}>technique</th>
              <th style={{ padding: "0.3rem 0.5rem" }}>detail</th>
            </tr>
          </thead>
          <tbody>
            {edges.map((e, i) => (
              <tr
                key={i}
                style={{ borderTop: "1px solid var(--rule)" }}
              >
                <td style={{ padding: "0.3rem 0.5rem" }}>
                  <code>{e.from}</code>
                </td>
                <td style={{ padding: "0.3rem 0.5rem" }}>
                  <code>{e.to === ADMIN_NODE ? "admin" : e.to}</code>
                </td>
                <td style={{ padding: "0.3rem 0.5rem" }}>
                  <code>{e.techniqueId}</code>
                </td>
                <td style={{ padding: "0.3rem 0.5rem", color: "var(--ink-dim)" }}>
                  {e.detail}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* ------------------ Effective-permission view ------------------ */}
      <h2 style={{ marginTop: "1.6rem" }}>Principal directory</h2>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "0.6rem",
        }}
      >
        {principals.map((p) => (
          <div
            key={p.id}
            style={{
              border: "1px solid var(--rule)",
              padding: "0.5rem 0.7rem",
              fontSize: "0.82rem",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <code>{p.id}</code>
              <span style={{ color: "var(--ink-dim)", fontSize: "0.75rem" }}>
                {p.kind}
              </span>
            </div>
            {p.permissions.length > 0 && (
              <div style={{ marginTop: "0.3rem", color: "var(--ink-dim)" }}>
                {p.permissions.map((perm) => (
                  <code
                    key={perm}
                    style={{
                      display: "inline-block",
                      marginRight: "0.3rem",
                      marginBottom: "0.2rem",
                      padding: "0.05rem 0.3rem",
                      background: "var(--bg-elev)",
                      border: "1px solid var(--rule)",
                      fontSize: "0.72rem",
                    }}
                  >
                    {perm}
                  </code>
                ))}
              </div>
            )}
            {p.notes && (
              <p style={{ marginTop: "0.3rem", color: "var(--ink-dim)", fontSize: "0.75rem" }}>
                {p.notes}
              </p>
            )}
          </div>
        ))}
      </div>

      {/* ------------------ Technique catalog ------------------ */}
      <h2 style={{ marginTop: "1.6rem" }}>
        Technique catalog ({TECHNIQUES.length})
      </h2>
      <div className="findings">
        {TECHNIQUES.map((t) => (
          <div key={t.id} className={`finding ${t.severity}`}>
            <div>
              <span className="sev">{t.severity}</span>
              <code style={{ color: "var(--ink-dim)" }}>[{t.provider}]</code>{" "}
              <strong>{t.id}</strong> &mdash; {t.title}
            </div>
            <p style={{ margin: "0.4rem 0 0.3rem", color: "var(--ink-dim)" }}>
              {t.summary}
            </p>
            <p style={{ margin: 0, fontSize: "0.82rem" }}>
              <strong>requires:</strong>{" "}
              {t.requires.map((r) => (
                <code
                  key={r}
                  style={{
                    marginRight: "0.3rem",
                    fontSize: "0.78rem",
                  }}
                >
                  {r}
                </code>
              ))}
            </p>
            <p style={{ margin: "0.3rem 0 0", fontSize: "0.82rem" }}>
              <strong>outcome:</strong> {t.outcome}
            </p>
            <p style={{ margin: "0.3rem 0 0", fontSize: "0.82rem" }}>
              <strong style={{ color: "var(--ok)" }}>mitigation:</strong>{" "}
              {t.mitigation}
            </p>
            <p style={{ marginTop: "0.3rem", fontSize: "0.78rem", color: "var(--ink-dim)" }}>
              <a href={t.reference} target="_blank" rel="noopener noreferrer">
                {(() => {
                  try {
                    return new URL(t.reference).hostname;
                  } catch {
                    return t.reference;
                  }
                })()}
              </a>
            </p>
          </div>
        ))}
      </div>
    </>
  );
}

function PathView({
  index,
  path,
  start,
  techIndex,
}: {
  index: number;
  path: AttackPath;
  start: string;
  techIndex: Map<string, { title: string; severity: string }>;
}) {
  return (
    <div
      style={{
        border: "1px solid var(--high)",
        padding: "0.6rem 0.8rem",
        marginBottom: "0.6rem",
      }}
    >
      <div
        style={{
          fontSize: "0.78rem",
          color: "var(--high)",
          textTransform: "uppercase",
          letterSpacing: "0.05em",
          marginBottom: "0.4rem",
        }}
      >
        path #{index + 1} — {path.steps.length} hop{path.steps.length === 1 ? "" : "s"}
      </div>
      <ol style={{ margin: 0, paddingLeft: "1.2rem", fontSize: "0.85rem" }}>
        <li style={{ marginBottom: "0.35rem", color: "var(--ink-dim)" }}>
          start: <code>{start}</code>
        </li>
        {path.steps.map((step: AttackEdge, i) => {
          const tech = techIndex.get(step.techniqueId);
          return (
            <li key={i} style={{ marginBottom: "0.45rem" }}>
              <strong>
                {tech?.title ?? step.techniqueId}
              </strong>{" "}
              <span style={{ color: "var(--ink-dim)", fontSize: "0.78rem" }}>
                ({step.techniqueId})
              </span>
              <div style={{ color: "var(--ink-dim)", fontSize: "0.78rem", marginTop: "0.15rem" }}>
                → <code>{step.to === ADMIN_NODE ? "admin" : step.to}</code>:{" "}
                {step.detail}
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
