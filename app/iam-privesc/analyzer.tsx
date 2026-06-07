"use client";

import { useEffect, useMemo, useState } from "react";
import { LearnCallout } from "@/app/_components/learn-callout";
import { ThreatModelCard } from "@/app/_components/threat-model";
import type { ThreatEntry } from "@/lib/labs";
import {
  SCENARIOS,
  TECHNIQUES,
  enumerateAttackPaths,
  type AttackPath,
  type IamScenario,
  type Principal,
} from "@/lib/iam-privesc";

const THREATS: readonly ThreatEntry[] = [
  {
    stride: "E",
    threat: "`iam:PassRole` + `lambda:CreateFunction` on `*` = admin (Rhino).",
    demo: { label: "AWS chain", href: "/iam-privesc" },
  },
  {
    stride: "E",
    threat: "`Application.ReadWrite.All` mints a Graph admin via service principal.",
    demo: { label: "Azure chain", href: "/iam-privesc" },
  },
  {
    stride: "E",
    threat: "`iam.serviceAccounts.actAs` impersonates a privileged SA on GCP.",
    demo: { label: "GCP chain", href: "/iam-privesc" },
  },
  {
    stride: "T",
    threat: "`UpdateAssumeRolePolicy` rewrites trust to attacker principal.",
    demo: { label: "AWS chain", href: "/iam-privesc" },
  },
];

const ADMIN_NODE = "*admin*";

export default function IamPrivescAnalyzer() {
  const [activeId, setActiveId] = useState<string>(SCENARIOS[0].id);
  const active: IamScenario =
    SCENARIOS.find((s) => s.id === activeId) ?? SCENARIOS[0];
  const [principalsJson, setPrincipalsJson] = useState<string>(
    JSON.stringify(active.principals, null, 2),
  );
  const [parseError, setParseError] = useState<string | null>(null);

  function loadScenario(id: string) {
    const s = SCENARIOS.find((x) => x.id === id) ?? SCENARIOS[0];
    setActiveId(s.id);
    setPrincipalsJson(JSON.stringify(s.principals, null, 2));
    setParseError(null);
    if (typeof window !== "undefined") {
      const nextUrl = new URL(window.location.href);
      nextUrl.searchParams.set("scenario", s.id);
      window.history.replaceState({}, "", nextUrl.toString());
    }
  }

  useEffect(() => {
    if (typeof window === "undefined") return;
    const deepLinkedScenario = new URLSearchParams(window.location.search).get(
      "scenario",
    );
    if (!deepLinkedScenario) return;
    const matchedScenario = SCENARIOS.find(
      (scenario) => scenario.id === deepLinkedScenario,
    );
    if (!matchedScenario) return;
    setActiveId(matchedScenario.id);
    setPrincipalsJson(JSON.stringify(matchedScenario.principals, null, 2));
    setParseError(null);
  }, []);

  const { principals, paths, edges } = useMemo(() => {
    let parsed: Principal[];
    try {
      parsed = JSON.parse(principalsJson);
      if (parseError) setParseError(null);
    } catch (e) {
      setParseError((e as Error).message);
      parsed = active.principals;
    }
    const result = enumerateAttackPaths({ ...active, principals: parsed });
    return { principals: parsed, ...result };
  }, [principalsJson, active, parseError]);

  const adminPaths = paths.filter((p) => p.endsAtAdmin);
  const techIndex = new Map(TECHNIQUES.map((t) => [t.id, t]));

  return (
    <>
      <h1>IAM Privilege Escalation</h1>
      <LearnCallout href="/iam-privesc" />
      <ThreatModelCard entries={THREATS} />
      <p className="lede">
        A live cloud-IAM attack-path enumerator. Each scenario seeds a small
        directory of users, roles, groups, and service principals; the engine
        derives every attack edge from the permissions held, then enumerates
        every path from the starting principal to admin.
      </p>
      <div style={{ marginTop: "0.4rem", padding: "0.6rem 0.8rem", border: "1px dashed var(--rule)", fontSize: "0.78rem", color: "var(--ink-dim)", background: "var(--bg-elev)" }}>
        <strong>How this works.</strong> The engine knows {TECHNIQUES.length} published techniques across AWS, Azure, and GCP and BFSes the derived edges looking for paths to the admin sentinel.
      </div>
      <h2 style={{ marginTop: "1.6rem" }}>Scenarios</h2>
      <div className="csp-scenarios">
        {SCENARIOS.map((s) => (
          <button key={s.id} onClick={() => loadScenario(s.id)} data-active={s.id === activeId} className="csp-scenario-card" type="button">
            <span className="csp-scenario-cat">{s.provider}</span>
            <span className="csp-scenario-title">{s.title}</span>
          </button>
        ))}
      </div>
      <div className="csp-scenario-detail">
        <p><strong>Setup.</strong> {active.blurb}</p>
        <p><strong>Starting principal:</strong> <code>{active.startingPrincipal}</code></p>
        {active.reference && <p style={{ fontSize: "0.78rem", color: "var(--ink-dim)" }}><strong>reference:</strong> {active.reference}</p>}
      </div>
      <h2 style={{ marginTop: "1.6rem" }}>Principals (editable)</h2>
      {parseError && <p style={{ color: "var(--high)", fontSize: "0.82rem" }}>parse error: {parseError}</p>}
      <textarea value={principalsJson} onChange={(e) => setPrincipalsJson(e.target.value)} spellCheck={false} style={{ width: "100%", minHeight: 280, fontFamily: "ui-monospace, monospace", fontSize: "0.78rem" }} />
      <h2 style={{ marginTop: "1.6rem" }}>Attack paths to admin ({adminPaths.length})</h2>
      {adminPaths.map((p, i) => <PathView key={i} index={i} path={p} start={active.startingPrincipal} techIndex={techIndex} />)}
      <h2 style={{ marginTop: "1.6rem" }}>Derived attack edges ({edges.length})</h2>
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.82rem" }}>
          <thead><tr style={{ textAlign: "left", color: "var(--ink-dim)" }}><th style={{ padding: "0.3rem 0.5rem" }}>from</th><th style={{ padding: "0.3rem 0.5rem" }}>to</th><th style={{ padding: "0.3rem 0.5rem" }}>technique</th><th style={{ padding: "0.3rem 0.5rem" }}>detail</th></tr></thead>
          <tbody>
            {edges.map((e, i) => (
              <tr key={i} style={{ borderTop: "1px solid var(--rule)" }}>
                <td style={{ padding: "0.3rem 0.5rem" }}><code>{e.from}</code></td>
                <td style={{ padding: "0.3rem 0.5rem" }}><code>{e.to === ADMIN_NODE ? "admin" : e.to}</code></td>
                <td style={{ padding: "0.3rem 0.5rem" }}><code>{e.techniqueId}</code></td>
                <td style={{ padding: "0.3rem 0.5rem", color: "var(--ink-dim)" }}>{e.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function PathView({ index, path, start, techIndex }: { index: number; path: AttackPath; start: string; techIndex: Map<string, { title: string }> }) {
  return (
    <div style={{ border: "1px solid var(--high)", padding: "0.6rem 0.8rem", marginBottom: "0.6rem" }}>
      <div style={{ fontSize: "0.78rem", color: "var(--high)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "0.4rem" }}>path #{index + 1}</div>
      <ol style={{ margin: 0, paddingLeft: "1.2rem", fontSize: "0.85rem" }}>
        <li style={{ marginBottom: "0.35rem", color: "var(--ink-dim)" }}><code>{start}</code></li>
        {path.steps.map((step, i) => <li key={i} style={{ marginBottom: "0.35rem" }}><strong>{techIndex.get(step.techniqueId)?.title ?? step.techniqueId}</strong> → <code>{step.to === ADMIN_NODE ? "admin" : step.to}</code><div style={{ color: "var(--ink-dim)", fontSize: "0.8rem" }}>{step.detail}</div></li>)}
      </ol>
    </div>
  );
}