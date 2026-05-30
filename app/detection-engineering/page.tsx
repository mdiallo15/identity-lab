"use client";

import { useMemo, useState } from "react";
import {
  SCENARIOS,
  runRule,
  evalMatch,
  LAB_RULES,
  type Event,
  type LabKey,
  type LabRule,
  type Match,
  type Rule,
  type Scenario,
} from "@/lib/detection";

export default function DetectionLab() {
  const [activeId, setActiveId] = useState<string>(SCENARIOS[0].id);
  const active: Scenario =
    SCENARIOS.find((s) => s.id === activeId) ?? SCENARIOS[0];

  // Editable rule JSON — both naive and tuned. Users can twist either rule
  // and watch precision/recall change in real time.
  const [naiveJson, setNaiveJson] = useState(
    JSON.stringify(active.naiveRule.match, null, 2),
  );
  const [tunedJson, setTunedJson] = useState(
    JSON.stringify(active.tunedRule.match, null, 2),
  );

  function loadScenario(id: string) {
    const s = SCENARIOS.find((x) => x.id === id) ?? SCENARIOS[0];
    setActiveId(s.id);
    setNaiveJson(JSON.stringify(s.naiveRule.match, null, 2));
    setTunedJson(JSON.stringify(s.tunedRule.match, null, 2));
  }

  const naiveResult = useMemo(() => {
    let m: Match;
    try {
      m = JSON.parse(naiveJson);
    } catch {
      m = active.naiveRule.match;
    }
    return runRule({ ...active.naiveRule, match: m }, active.events);
  }, [naiveJson, active]);

  const tunedResult = useMemo(() => {
    let m: Match;
    try {
      m = JSON.parse(tunedJson);
    } catch {
      m = active.tunedRule.match;
    }
    return runRule({ ...active.tunedRule, match: m }, active.events);
  }, [tunedJson, active]);

  return (
    <>
      <h1>Detection Engineering</h1>
      <p className="lede">
        Real telemetry from real incidents, two detection rules per scenario, a
        ground-truth labeled event stream. Watch the naive rule fire on every
        helpdesk PowerShell session while the tuned rule catches the macro
        loader. Edit either rule&apos;s match tree as JSON and see precision /
        recall update live.
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
        <strong>How this works.</strong> Each scenario ships a Sysmon /
        CloudTrail / Entra event stream with a labeled ground truth: which
        events are part of the attack and which are benign. The runner
        evaluates a Sigma-style condition tree (eq / contains / regex / in /
        gte / and / or / not) against every event and reports true positives,
        false positives, false negatives, precision, recall, and F1. Edit the
        JSON to bias either rule and watch the metrics move.
      </div>

      {/* Scenario picker */}
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
            <span className="csp-scenario-cat">scenario</span>
            <span className="csp-scenario-title">{s.title}</span>
          </button>
        ))}
      </div>

      <div className="csp-scenario-detail">
        <p>
          <strong>Setup.</strong> {active.blurb}
        </p>
        <p style={{ fontSize: "0.78rem", color: "var(--ink-dim)" }}>
          <strong>reference:</strong> {active.reference}
        </p>
      </div>

      {/* Rule comparison */}
      <h2 style={{ marginTop: "1.6rem" }}>Rules side by side</h2>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "0.8rem",
        }}
      >
        <RuleColumn
          label="naive"
          rule={active.naiveRule}
          json={naiveJson}
          setJson={setNaiveJson}
          result={naiveResult}
        />
        <RuleColumn
          label="tuned"
          rule={active.tunedRule}
          json={tunedJson}
          setJson={setTunedJson}
          result={tunedResult}
        />
      </div>

      {/* Event stream */}
      <h2 style={{ marginTop: "1.6rem" }}>
        Event stream ({active.events.length} events,{" "}
        {active.events.filter((e) => e.malicious).length} malicious)
      </h2>
      <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem" }}>
        {active.events.map((ev) => (
          <EventRow
            key={ev.id}
            ev={ev}
            naiveMatch={naiveResult.matchedIds.includes(ev.id)}
            tunedMatch={tunedResult.matchedIds.includes(ev.id)}
          />
        ))}
      </div>

      <h2 style={{ marginTop: "1.8rem" }}>Detection rules by lab</h2>
      <p style={{ fontSize: "0.85rem", color: "var(--ink-dim)" }}>
        One Sigma-equivalent starting point per lab domain. Each rule lists
        the data source it needs, the ATT&amp;CK / OWASP / CVE handle it
        targets, the known false-positive shape, and a published reference.
        Lift the body into a real Sigma file, tune the allowlists for your
        environment, and ship.
      </p>
      <LabRuleCatalog />
    </>
  );
}

const LAB_LABEL: Record<LabKey, string> = {
  csp: "CSP",
  jwt: "JWT",
  ssrf: "SSRF",
  iam: "IAM PrivEsc",
  "supply-chain": "Supply Chain",
  rag: "RAG",
  "prompt-injection": "Prompt Injection",
  "agent-identity": "Agent Identity",
};

const LAB_HREF: Record<LabKey, string> = {
  csp: "/csp",
  jwt: "/identity/jwt",
  ssrf: "/ssrf",
  iam: "/iam-privesc",
  "supply-chain": "/supply-chain",
  rag: "/rag",
  "prompt-injection": "/prompt-injection",
  "agent-identity": "/agent-identity",
};

const SEVERITY_TONE: Record<LabRule["severity"], string> = {
  critical: "var(--high)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  info: "var(--ink-dim)",
};

function LabRuleCatalog() {
  const grouped = useMemo(() => {
    const m = new Map<LabKey, LabRule[]>();
    for (const r of LAB_RULES) {
      const arr = m.get(r.lab) ?? [];
      arr.push(r);
      m.set(r.lab, arr);
    }
    return m;
  }, []);
  const order: LabKey[] = [
    "csp",
    "jwt",
    "ssrf",
    "iam",
    "supply-chain",
    "rag",
    "prompt-injection",
    "agent-identity",
  ];
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "0.8rem" }}>
      {order.map((lab) => {
        const rules = grouped.get(lab) ?? [];
        if (rules.length === 0) return null;
        return (
          <section
            key={lab}
            style={{
              border: "1px solid var(--rule)",
              padding: "0.7rem 0.9rem",
              background: "var(--bg-elev)",
            }}
          >
            <header
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "baseline",
                marginBottom: "0.4rem",
              }}
            >
              <strong style={{ fontSize: "0.9rem" }}>{LAB_LABEL[lab]}</strong>
              <a
                href={LAB_HREF[lab]}
                style={{ fontSize: "0.78rem", color: "var(--accent)" }}
              >
                open lab →
              </a>
            </header>
            {rules.map((r) => (
              <LabRuleCard key={r.id} rule={r} />
            ))}
          </section>
        );
      })}
    </div>
  );
}

function LabRuleCard({ rule }: { rule: LabRule }) {
  return (
    <article
      style={{
        borderTop: "1px solid var(--rule)",
        marginTop: "0.5rem",
        paddingTop: "0.5rem",
        display: "flex",
        flexDirection: "column",
        gap: "0.35rem",
      }}
    >
      <div
        style={{
          display: "flex",
          gap: "0.5rem",
          alignItems: "baseline",
          flexWrap: "wrap",
        }}
      >
        <code style={{ fontSize: "0.78rem", color: SEVERITY_TONE[rule.severity] }}>
          {rule.id}
        </code>
        <span style={{ fontSize: "0.85rem" }}>{rule.title}</span>
        <span
          style={{
            fontSize: "0.68rem",
            textTransform: "uppercase",
            letterSpacing: "0.05em",
            color: SEVERITY_TONE[rule.severity],
            border: `1px solid ${SEVERITY_TONE[rule.severity]}`,
            padding: "0.05rem 0.4rem",
          }}
        >
          {rule.severity}
        </span>
      </div>
      <p style={{ margin: 0, fontSize: "0.8rem", color: "var(--ink-dim)" }}>
        {rule.rationale}
      </p>
      <dl
        style={{
          margin: 0,
          fontSize: "0.76rem",
          display: "grid",
          gridTemplateColumns: "max-content 1fr",
          rowGap: "0.2rem",
          columnGap: "0.6rem",
        }}
      >
        <dt style={{ color: "var(--ink-dim)" }}>data source</dt>
        <dd style={{ margin: 0 }}>{rule.dataSource}</dd>
        <dt style={{ color: "var(--ink-dim)" }}>maps to</dt>
        <dd style={{ margin: 0 }}>{rule.attack}</dd>
        {rule.knownFp && (
          <>
            <dt style={{ color: "var(--ink-dim)" }}>known FP</dt>
            <dd style={{ margin: 0 }}>{rule.knownFp}</dd>
          </>
        )}
        <dt style={{ color: "var(--ink-dim)" }}>reference</dt>
        <dd style={{ margin: 0, wordBreak: "break-all" }}>{rule.reference}</dd>
      </dl>
      <pre
        style={{
          margin: 0,
          padding: "0.5rem 0.6rem",
          background: "var(--bg)",
          border: "1px solid var(--rule)",
          fontSize: "0.72rem",
          whiteSpace: "pre",
          overflow: "auto",
        }}
      >
        {rule.sigma}
      </pre>
    </article>
  );
}

function RuleColumn({
  label,
  rule,
  json,
  setJson,
  result,
}: {
  label: "naive" | "tuned";
  rule: Rule;
  json: string;
  setJson: (s: string) => void;
  result: ReturnType<typeof runRule>;
}) {
  const isNaive = label === "naive";
  const accent = isNaive ? "var(--medium)" : "var(--ok)";
  return (
    <div
      style={{
        border: `1px solid ${accent}`,
        padding: "0.6rem 0.8rem",
      }}
    >
      <div
        style={{
          textTransform: "uppercase",
          fontSize: "0.72rem",
          letterSpacing: "0.05em",
          color: accent,
          marginBottom: "0.3rem",
        }}
      >
        {label} — <code>{rule.id}</code>
      </div>
      <div style={{ fontWeight: 600, marginBottom: "0.3rem" }}>{rule.title}</div>
      <p style={{ color: "var(--ink-dim)", fontSize: "0.82rem", margin: "0 0 0.5rem" }}>
        {rule.description}
      </p>
      <div style={{ fontSize: "0.78rem", color: "var(--ink-dim)", marginBottom: "0.4rem" }}>
        ATT&CK: {rule.attack.join(", ")}
      </div>
      <textarea
        value={json}
        onChange={(e) => setJson(e.target.value)}
        spellCheck={false}
        style={{
          width: "100%",
          minHeight: 180,
          fontFamily: "ui-monospace, monospace",
          fontSize: "0.74rem",
        }}
      />
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "0.3rem",
          marginTop: "0.5rem",
          fontSize: "0.82rem",
        }}
      >
        <Stat label="TP" value={result.truePositive} color="var(--ok)" />
        <Stat label="FP" value={result.falsePositive} color="var(--high)" />
        <Stat label="FN" value={result.falseNegative} color="var(--high)" />
        <Stat label="TN" value={result.trueNegative} color="var(--ink-dim)" />
        <Stat
          label="precision"
          value={result.precision.toFixed(2)}
          color="var(--accent)"
        />
        <Stat
          label="recall"
          value={result.recall.toFixed(2)}
          color="var(--accent)"
        />
        <Stat label="F1" value={result.f1.toFixed(2)} color="var(--accent)" />
      </div>
      {rule.knownFp && (
        <p style={{ fontSize: "0.75rem", color: "var(--ink-dim)", marginTop: "0.4rem" }}>
          <strong>known FP:</strong> {rule.knownFp}
        </p>
      )}
      <p style={{ fontSize: "0.72rem", marginTop: "0.3rem" }}>
        <a href={rule.reference} target="_blank" rel="noopener noreferrer">
          {(() => {
            try {
              return new URL(rule.reference).hostname;
            } catch {
              return rule.reference;
            }
          })()}
        </a>
      </p>
    </div>
  );
}

function Stat({ label, value, color }: { label: string; value: number | string; color: string }) {
  return (
    <div
      style={{
        border: "1px solid var(--rule)",
        padding: "0.2rem 0.4rem",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "baseline",
      }}
    >
      <span style={{ fontSize: "0.72rem", color: "var(--ink-dim)" }}>{label}</span>
      <code style={{ color }}>{value}</code>
    </div>
  );
}

function EventRow({
  ev,
  naiveMatch,
  tunedMatch,
}: {
  ev: Event;
  naiveMatch: boolean;
  tunedMatch: boolean;
}) {
  const border =
    ev.malicious && tunedMatch
      ? "var(--ok)"
      : ev.malicious && !tunedMatch
        ? "var(--high)"
        : !ev.malicious && naiveMatch
          ? "var(--medium)"
          : "var(--rule)";
  return (
    <div
      style={{
        border: `1px solid ${border}`,
        padding: "0.45rem 0.6rem",
        fontSize: "0.78rem",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.2rem" }}>
        <code>
          {new Date(ev.ts).toISOString()} · {ev.source}
          {ev.eventId !== undefined ? ` · id=${ev.eventId}` : ""}
        </code>
        <div style={{ display: "flex", gap: "0.3rem", alignItems: "center" }}>
          {ev.malicious ? (
            <span style={{ color: "var(--high)", fontSize: "0.7rem", textTransform: "uppercase" }}>
              malicious
            </span>
          ) : (
            <span style={{ color: "var(--ok)", fontSize: "0.7rem", textTransform: "uppercase" }}>
              benign
            </span>
          )}
          <span style={{ fontSize: "0.7rem", color: naiveMatch ? "var(--medium)" : "var(--ink-dim)" }}>
            naive {naiveMatch ? "✓" : "·"}
          </span>
          <span style={{ fontSize: "0.7rem", color: tunedMatch ? "var(--ok)" : "var(--ink-dim)" }}>
            tuned {tunedMatch ? "✓" : "·"}
          </span>
        </div>
      </div>
      <pre
        style={{
          margin: 0,
          fontSize: "0.72rem",
          color: "var(--ink-dim)",
          overflow: "auto",
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
        }}
      >
        {Object.entries(ev.fields)
          .filter(([, v]) => v !== undefined)
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n")}
      </pre>
      {ev.note && (
        <p style={{ marginTop: "0.3rem", fontSize: "0.72rem", color: "var(--ink-dim)", fontStyle: "italic" }}>
          // {ev.note}
        </p>
      )}
    </div>
  );
}
