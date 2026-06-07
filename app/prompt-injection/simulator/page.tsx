"use client";

import { useEffect, useMemo, useState } from "react";
import {
  AGENT_SCENARIOS,
  DEFAULT_HARDENED_POLICY,
  TOOLS,
  runScenario,
  summariseTrace,
  type AgentScenario,
  type HardenedPolicy,
  type TraceStep,
} from "../../../lib/prompt-injection";

export default function Simulator() {
  const [selectedId, setSelectedId] = useState<string>(AGENT_SCENARIOS[0].id);
  const [policy, setPolicy] = useState<HardenedPolicy>(DEFAULT_HARDENED_POLICY);

  function selectScenario(nextScenarioId: string) {
    setSelectedId(nextScenarioId);
    if (typeof window !== "undefined") {
      const nextUrl = new URL(window.location.href);
      nextUrl.searchParams.set("scenario", nextScenarioId);
      window.history.replaceState({}, "", nextUrl.toString());
    }
  }

  useEffect(() => {
    if (typeof window === "undefined") return;
    const deepLinkedScenario = new URLSearchParams(window.location.search).get(
      "scenario",
    );
    if (!deepLinkedScenario) return;
    const matchedScenario = AGENT_SCENARIOS.find(
      (scenario) => scenario.id === deepLinkedScenario,
    );
    if (!matchedScenario) return;
    setSelectedId(matchedScenario.id);
  }, []);

  const scenario: AgentScenario = useMemo(
    () =>
      AGENT_SCENARIOS.find((s) => s.id === selectedId) ?? AGENT_SCENARIOS[0],
    [selectedId],
  );

  const naive = useMemo(
    () => runScenario(scenario, "naive", policy),
    [scenario, policy],
  );
  const hardened = useMemo(
    () => runScenario(scenario, "hardened", policy),
    [scenario, policy],
  );
  const naiveSummary = summariseTrace(naive);
  const hardenedSummary = summariseTrace(hardened);

  function exportTelemetry() {
    const payload = {
      scenarioId: scenario.id,
      scenarioTitle: scenario.title,
      goal: scenario.goal,
      policy,
      naive: { trace: naive, summary: naiveSummary },
      hardened: { trace: hardened, summary: hardenedSummary },
      generatedAt: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `prompt-injection-${scenario.id}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  return (
    <>
      <h1>Prompt-injection simulator — live agent loop</h1>
      <p className="lede">
        Two agents share the same five-tool surface (<code>read_file</code>,{" "}
        <code>kb_search</code>, <code>web_fetch</code>, <code>send_email</code>,{" "}
        <code>update_calendar</code>) and execute the same operator-issued
        plan. The naive agent obeys instructions found in tool outputs; the
        hardened agent spotlights tool outputs as data, gates outbound sinks
        behind an operator allowlist, and refuses tool calls whose provenance
        traces to data. Pick a scenario and watch the traces diverge.
      </p>

      <h2>Tool surface</h2>
      <ul style={{ fontSize: "0.85rem", color: "var(--ink-dim)" }}>
        {TOOLS.map((t) => (
          <li key={t.name}>
            <code>
              {t.name}({t.args.join(", ")})
            </code>{" "}
            — {t.description}
            {t.outboundSink ? (
              <span
                style={{
                  marginLeft: "0.4rem",
                  padding: "0.05rem 0.35rem",
                  border: "1px solid var(--high)",
                  color: "var(--high)",
                  fontSize: "0.7rem",
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                }}
              >
                outbound sink
              </span>
            ) : null}
          </li>
        ))}
      </ul>

      <h2>Scenario ({AGENT_SCENARIOS.length} total)</h2>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
          gap: "0.5rem",
          margin: "0.6rem 0 0.8rem",
        }}
      >
        {AGENT_SCENARIOS.map((s) => (
          <button
            key={s.id}
            type="button"
            onClick={() => selectScenario(s.id)}
            style={{
              textAlign: "left",
              padding: "0.55rem 0.7rem",
              background:
                s.id === scenario.id ? "var(--bg-elev)" : "transparent",
              border: `1px solid ${s.id === scenario.id ? "var(--accent)" : "var(--rule)"}`,
              color: "var(--ink)",
              cursor: "pointer",
              borderRadius: 6,
            }}
          >
            <div
              style={{
                fontSize: "0.7rem",
                color: "var(--ink-dim)",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
              }}
            >
              {s.category}
            </div>
            <div style={{ fontSize: "0.85rem", fontWeight: 600 }}>
              {s.title}
            </div>
          </button>
        ))}
      </div>

      <div className="pi-task">
        <span className="pi-task__label">Operator&apos;s goal</span>
        <span className="pi-task__text">{scenario.goal}</span>
      </div>

      <p style={{ fontSize: "0.88rem", color: "var(--ink-dim)" }}>
        {scenario.blurb}
      </p>
      <p style={{ fontSize: "0.78rem" }}>
        Reference:{" "}
        <a
          href={scenario.reference.url}
          target="_blank"
          rel="noopener noreferrer"
        >
          {scenario.reference.label}
        </a>
      </p>

      <h2>Hardened-agent policy (editable)</h2>
      <PolicyEditor policy={policy} onChange={setPolicy} />

      <h2>Trace — naive vs hardened</h2>
      <div className="pi-agents" style={{ alignItems: "stretch" }}>
        <section className="pi-agent pi-agent--naive">
          <h2>Naive agent</h2>
          <SummaryStrip
            tool={naiveSummary.toolCalls}
            refused={naiveSummary.refusals}
            leak={naiveSummary.leaks}
            mode="naive"
          />
          <Trace steps={naive} />
        </section>
        <section className="pi-agent pi-agent--hardened">
          <h2>Hardened agent</h2>
          <SummaryStrip
            tool={hardenedSummary.toolCalls}
            refused={hardenedSummary.refusals}
            leak={hardenedSummary.leaks}
            mode="hardened"
          />
          <Trace steps={hardened} />
        </section>
      </div>

      <div style={{ display: "flex", gap: "0.5rem", margin: "1rem 0" }}>
        <button
          type="button"
          onClick={exportTelemetry}
          style={{
            background: "transparent",
            color: "var(--ink-dim)",
            border: "1px solid var(--rule)",
            padding: "0.4rem 0.85rem",
            fontSize: "0.78rem",
            fontWeight: 500,
          }}
        >
          Download telemetry (JSON)
        </button>
      </div>

      <h2>What this proves</h2>
      <ul style={{ fontSize: "0.88rem" }}>
        <li>
          Identical operator-issued plans produce opposite outcomes depending
          on how the agent treats tool output. Spotlighting +
          provenance-tracking is the pivot.
        </li>
        <li>
          Hardened policy is enforced at the runtime, not the model. Editing
          the allowlist above changes which calls survive; flipping{" "}
          <code>refuseToolCallsFromToolOutput</code> off makes the hardened
          agent regress to the naive agent.
        </li>
        <li>
          Every scenario maps to a published incident or technique (Greshake
          2023, Bargury / embracethered Copilot disclosures 2024, OWASP LLM
          Top 10, FBI IC3 BEC). The telemetry export is suitable for replaying
          into a SIEM or for unit tests around your agent runtime.
        </li>
      </ul>
    </>
  );
}

function PolicyEditor({
  policy,
  onChange,
}: {
  policy: HardenedPolicy;
  onChange: (p: HardenedPolicy) => void;
}) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "1fr 1fr",
        gap: "0.6rem",
        margin: "0.5rem 0 1rem",
      }}
    >
      <div
        style={{ border: "1px solid var(--rule)", padding: "0.45rem 0.6rem" }}
      >
        <label
          style={{
            fontSize: "0.7rem",
            textTransform: "uppercase",
            letterSpacing: "0.05em",
            color: "var(--ink-dim)",
          }}
        >
          email allowlist (comma-separated, suffix match)
        </label>
        <input
          type="text"
          value={policy.emailAllowlist.join(", ")}
          onChange={(e) =>
            onChange({
              ...policy,
              emailAllowlist: e.target.value
                .split(/\s*,\s*/)
                .filter(Boolean),
            })
          }
          style={{ marginTop: "0.2rem", fontSize: "0.78rem" }}
        />
      </div>
      <div
        style={{ border: "1px solid var(--rule)", padding: "0.45rem 0.6rem" }}
      >
        <label
          style={{
            fontSize: "0.7rem",
            textTransform: "uppercase",
            letterSpacing: "0.05em",
            color: "var(--ink-dim)",
          }}
        >
          web fetch allowlist (host substring)
        </label>
        <input
          type="text"
          value={policy.webAllowlist.join(", ")}
          onChange={(e) =>
            onChange({
              ...policy,
              webAllowlist: e.target.value
                .split(/\s*,\s*/)
                .filter(Boolean),
            })
          }
          style={{ marginTop: "0.2rem", fontSize: "0.78rem" }}
        />
      </div>
      <label
        style={{
          gridColumn: "1 / -1",
          border: "1px solid var(--rule)",
          padding: "0.45rem 0.6rem",
          display: "flex",
          gap: "0.5rem",
          alignItems: "center",
          cursor: "pointer",
          fontSize: "0.85rem",
        }}
      >
        <input
          type="checkbox"
          checked={policy.refuseToolCallsFromToolOutput}
          onChange={(e) =>
            onChange({
              ...policy,
              refuseToolCallsFromToolOutput: e.target.checked,
            })
          }
        />
        <code>refuseToolCallsFromToolOutput</code>
        <span style={{ color: "var(--ink-dim)", fontSize: "0.78rem" }}>
          spotlighting + provenance gate. Off = hardened agent collapses to
          naive.
        </span>
      </label>
    </div>
  );
}

function SummaryStrip({
  tool,
  refused,
  leak,
  mode,
}: {
  tool: number;
  refused: number;
  leak: number;
  mode: "naive" | "hardened";
}) {
  return (
    <div
      style={{
        display: "flex",
        gap: "0.4rem",
        marginBottom: "0.6rem",
        fontSize: "0.72rem",
        flexWrap: "wrap",
      }}
    >
      <span
        style={{
          padding: "0.15rem 0.45rem",
          border: "1px solid var(--rule)",
          color: "var(--ink-dim)",
        }}
      >
        {tool} tool call{tool === 1 ? "" : "s"}
      </span>
      <span
        style={{
          padding: "0.15rem 0.45rem",
          border: `1px solid ${refused ? "var(--ok)" : "var(--rule)"}`,
          color: refused ? "var(--ok)" : "var(--ink-dim)",
        }}
      >
        {refused} refused
      </span>
      <span
        style={{
          padding: "0.15rem 0.45rem",
          border: `1px solid ${leak ? "var(--high)" : "var(--rule)"}`,
          color: leak ? "var(--high)" : "var(--ink-dim)",
          fontWeight: leak ? 700 : 400,
        }}
      >
        {leak} leak{leak === 1 ? "" : "s"}
        {mode === "naive" && leak === 0 ? " (clean)" : ""}
      </span>
    </div>
  );
}

function Trace({ steps }: { steps: TraceStep[] }) {
  return (
    <ol
      style={{
        listStyle: "none",
        padding: 0,
        margin: 0,
        fontSize: "0.78rem",
        fontFamily: "ui-monospace, Menlo, monospace",
      }}
    >
      {steps.map((s, i) => (
        <li
          key={i}
          style={{
            borderLeft: `2px solid ${stepColor(s)}`,
            padding: "0.3rem 0.55rem",
            margin: "0.2rem 0",
            background: "var(--bg)",
            color: "var(--ink)",
          }}
        >
          {renderStep(s)}
        </li>
      ))}
    </ol>
  );
}

function stepColor(s: TraceStep): string {
  switch (s.kind) {
    case "plan":
      return "var(--rule)";
    case "tool_call":
      return s.provenance === "tool_output"
        ? "var(--high)"
        : "var(--accent)";
    case "tool_result":
      return "var(--rule)";
    case "refusal":
      return "var(--ok)";
    case "leak":
      return "var(--high)";
    case "final":
      return s.ok ? "var(--ok)" : "var(--high)";
  }
}

function renderStep(s: TraceStep) {
  switch (s.kind) {
    case "plan":
      return (
        <>
          <Tag label="plan" color="var(--ink-dim)" />
          <span style={{ color: "var(--ink-dim)" }}>{s.text}</span>
        </>
      );
    case "tool_call":
      return (
        <>
          <Tag
            label={
              s.provenance === "tool_output" ? "call (from data!)" : "call"
            }
            color={
              s.provenance === "tool_output" ? "var(--high)" : "var(--accent)"
            }
          />
          <code>
            {s.call.tool}({renderArgs(s.call.args)})
          </code>
        </>
      );
    case "tool_result":
      return (
        <>
          <Tag label="result" color="var(--ink-dim)" />
          <span style={{ whiteSpace: "pre-wrap" }}>
            {truncate(s.result.content, 320)}
          </span>
        </>
      );
    case "refusal":
      return (
        <>
          <Tag label="refused" color="var(--ok)" />
          <div style={{ color: "var(--ok)", fontWeight: 600 }}>{s.rule}</div>
          <div
            style={{
              color: "var(--ink-dim)",
              whiteSpace: "pre-wrap",
              marginTop: "0.15rem",
            }}
          >
            {s.rationale}
          </div>
          {s.excerpt ? (
            <div
              style={{
                marginTop: "0.2rem",
                padding: "0.2rem 0.4rem",
                background: "var(--bg-elev)",
                color: "var(--ink-dim)",
                fontSize: "0.72rem",
              }}
            >
              evidence: {truncate(s.excerpt, 200)}
            </div>
          ) : null}
        </>
      );
    case "leak":
      return (
        <>
          <Tag label="LEAK" color="var(--high)" />
          <div style={{ color: "var(--high)", fontWeight: 700 }}>
            {s.sink} — {s.channel}
          </div>
          <div style={{ color: "var(--ink-dim)" }}>data: {s.data}</div>
        </>
      );
    case "final":
      return (
        <>
          <Tag label="final" color={s.ok ? "var(--ok)" : "var(--high)"} />
          <span style={{ color: s.ok ? "var(--ok)" : "var(--high)" }}>
            {s.text}
          </span>
        </>
      );
  }
}

function Tag({ label, color }: { label: string; color: string }) {
  return (
    <span
      style={{
        display: "inline-block",
        marginRight: "0.4rem",
        padding: "0.05rem 0.35rem",
        border: `1px solid ${color}`,
        color,
        fontSize: "0.65rem",
        textTransform: "uppercase",
        letterSpacing: "0.05em",
      }}
    >
      {label}
    </span>
  );
}

function renderArgs(args: Record<string, string>): string {
  return Object.entries(args)
    .map(([k, v]) => `${k}="${truncate(v, 80)}"`)
    .join(", ");
}

function truncate(v: string, n: number): string {
  if (v.length <= n) return v;
  return v.slice(0, n - 1) + "…";
}
