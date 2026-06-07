"use client";

import { useEffect, useMemo, useState } from "react";
import {
  analyze,
  sevRank,
  SSRF_SAMPLES,
  SSRF_CATALOG,
  runFetcher,
  type Severity,
  type Finding,
  type SsrfScenarioId,
  type FetcherStep,
} from "../../../lib/ssrf";
import { standardsFor } from "../../../lib/standards";
import { ExportButtons } from "../../_components/export-buttons";

type Stage = {
  name: string;
  status: "pass" | "fail" | "skipped";
  detail: string;
  data?: unknown;
};
type RuntimeResult = { stages: Stage[]; findings: Finding[] };

export default function SsrfAnalyzer() {
  const [url, setUrl] = useState<string>(SSRF_SAMPLES[1].value);
  const [running, setRunning] = useState(false);
  const [runtime, setRuntime] = useState<RuntimeResult | null>(null);
  const [runtimeError, setRuntimeError] = useState<string | null>(null);
  const [scenarioId, setScenarioId] = useState<SsrfScenarioId>(
    SSRF_CATALOG[0].id,
  );

  function selectScenario(nextScenarioId: SsrfScenarioId) {
    const nextScenario =
      SSRF_CATALOG.find((scenario) => scenario.id === nextScenarioId) ??
      SSRF_CATALOG[0];
    setScenarioId(nextScenario.id);
    setUrl(nextScenario.request.url);
    if (typeof window !== "undefined") {
      const nextUrl = new URL(window.location.href);
      nextUrl.searchParams.set("scenario", nextScenario.id);
      window.history.replaceState({}, "", nextUrl.toString());
    }
  }

  useEffect(() => {
    if (typeof window === "undefined") return;
    const deepLinkedScenario = new URLSearchParams(window.location.search).get(
      "scenario",
    ) as SsrfScenarioId | null;
    if (!deepLinkedScenario) return;
    const matchedScenario = SSRF_CATALOG.find(
      (scenario) => scenario.id === deepLinkedScenario,
    );
    if (!matchedScenario) return;
    setScenarioId(matchedScenario.id);
    setUrl(matchedScenario.request.url);
  }, []);

  const scenario = useMemo(
    () => SSRF_CATALOG.find((s) => s.id === scenarioId) ?? SSRF_CATALOG[0],
    [scenarioId],
  );
  const naiveRun = useMemo(() => runFetcher(scenario, "naive"), [scenario]);
  const hardenedRun = useMemo(
    () => runFetcher(scenario, "hardened"),
    [scenario],
  );

  const { parsed, findings } = useMemo(() => analyze(url), [url]);

  async function runRuntimeTest() {
    setRunning(true);
    setRuntime(null);
    setRuntimeError(null);
    try {
      const r = await fetch("/api/ssrf-test", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await r.json();
      if (!r.ok) {
        setRuntimeError(data.error ?? `HTTP ${r.status}`);
      } else {
        setRuntime(data);
      }
    } catch (err) {
      setRuntimeError(err instanceof Error ? err.message : "Network error");
    } finally {
      setRunning(false);
    }
  }

  const counts = findings.reduce<Record<Severity, number>>(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] ?? 0) + 1;
      return acc;
    },
    { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
  );

  return (
    <>
      <h1>SSRF URL analyzer</h1>
      <p className="lede">
        Paste a URL the agent or backend is about to fetch. The analyzer decodes
        the host (decimal, hex, octal, alias), checks against cloud metadata
        IPs, RFC 1918, link-local, loopback, and unusual URL schemes, and
        surfaces eight SSRF-relevant findings.
      </p>

      <div className="row" style={{ marginBottom: "0.75rem" }}>
        <label>
          <strong>Sample:</strong>{" "}
          <select value={url} onChange={(e) => setUrl(e.target.value)}>
            {SSRF_SAMPLES.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      <input
        className="pi-input"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        spellCheck={false}
        placeholder="https://example.com/path"
      />

      <div className="row" style={{ gap: "0.5rem", marginTop: "0.6rem" }}>
        <button
          onClick={runRuntimeTest}
          disabled={running || !url.trim()}
          style={{
            background: "var(--ink)",
            color: "var(--bg)",
            border: "1px solid var(--ink)",
            padding: "0.45rem 0.9rem",
            fontWeight: 600,
            opacity: running ? 0.6 : 1,
          }}
        >
          {running ? "Running\u2026" : "Run server-side validate-then-fetch"}
        </button>
      </div>
      <p
        style={{
          fontSize: "0.78rem",
          color: "var(--ink-dim)",
          margin: "0.5rem 0 0",
        }}
      >
        Runs the canonical 4-stage hardening flow on the server: parse →
        pre-flight rule check → DNS resolve + re-check every IP (DNS-rebinding
        defence) → bounded fetch. Each stage's pass/fail is shown below.
      </p>

      {runtimeError && (
        <div
          role="alert"
          style={{
            marginTop: "0.8rem",
            padding: "0.7rem 0.9rem",
            border: "1px solid #ef4444",
            background: "rgba(239, 68, 68, 0.06)",
            fontSize: "0.88rem",
          }}
        >
          <strong>Runtime test failed:</strong> {runtimeError}
        </div>
      )}

      {runtime && (
        <div className="ssrf-stages" style={{ marginTop: "1rem" }}>
          <h2 style={{ marginTop: 0 }}>Runtime trace</h2>
          <ol style={{ paddingLeft: "1.1rem", margin: 0 }}>
            {runtime.stages.map((s, i) => (
              <li
                key={i}
                style={{
                  marginBottom: "0.5rem",
                  paddingLeft: "0.4rem",
                  borderLeft: `3px solid ${
                    s.status === "pass"
                      ? "#22c55e"
                      : s.status === "fail"
                        ? "#ef4444"
                        : "#94a3b8"
                  }`,
                }}
              >
                <strong>{s.name}</strong>{" "}
                <span
                  style={{
                    color:
                      s.status === "pass"
                        ? "#22c55e"
                        : s.status === "fail"
                          ? "#ef4444"
                          : "#94a3b8",
                    fontFamily: "var(--mono)",
                    fontSize: "0.78rem",
                  }}
                >
                  [{s.status.toUpperCase()}]
                </span>
                <div style={{ fontSize: "0.85rem", color: "var(--ink-dim)" }}>
                  {s.detail}
                </div>
                {s.data !== undefined && (
                  <pre
                    style={{
                      fontSize: "0.72rem",
                      marginTop: "0.3rem",
                      padding: "0.5rem",
                      background: "rgba(148, 163, 184, 0.08)",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-all",
                    }}
                  >
                    {JSON.stringify(s.data, null, 2)}
                  </pre>
                )}
              </li>
            ))}
          </ol>
        </div>
      )}

      <div className="ssrf-parsed">
        <strong>Resolved:</strong>{" "}
        <span className="csp-counts">
          {parsed.protocol ?? "?"}://{parsed.hostname ?? "?"}
          {parsed.port ? ":" + parsed.port : ""}
          {parsed.pathname && parsed.pathname !== "/" ? parsed.pathname : ""}
        </span>
        {parsed.decoded && (
          <div className="ssrf-decoded">
            ↳ canonical: <code>{parsed.decoded}</code>
          </div>
        )}
        <div className="ssrf-flags">
          {parsed.isMetadata && (
            <span className="ssrf-flag ssrf-flag--bad">cloud metadata</span>
          )}
          {parsed.isLinkLocal && (
            <span className="ssrf-flag ssrf-flag--bad">link-local</span>
          )}
          {parsed.isLoopback && (
            <span className="ssrf-flag ssrf-flag--bad">loopback</span>
          )}
          {parsed.isPrivate && !parsed.isLoopback && !parsed.isLinkLocal && (
            <span className="ssrf-flag ssrf-flag--bad">RFC1918</span>
          )}
          {parsed.isUnusualScheme && (
            <span className="ssrf-flag ssrf-flag--bad">unusual scheme</span>
          )}
          {!parsed.isPrivate &&
            !parsed.isMetadata &&
            !parsed.isUnusualScheme &&
            parsed.hostname && (
              <span className="ssrf-flag ssrf-flag--ok">public</span>
            )}
        </div>
      </div>

      <div className="csp-summary">
        <strong>{findings.length}</strong> finding
        {findings.length === 1 ? "" : "s"}
        <span className="csp-counts">
          {" — "}
          {counts.critical ? `${counts.critical} critical, ` : ""}
          {counts.high ? `${counts.high} high, ` : ""}
          {counts.medium ? `${counts.medium} medium, ` : ""}
          {counts.low ? `${counts.low} low` : ""}
          {!findings.length && "no SSRF risk indicators"}
        </span>
      </div>

      <ExportButtons
        findings={findings}
        toolName="lab.marwandiallo.com/ssrf"
        target={url}
        payload={{ url, parsed, findings }}
        filenamePrefix="ssrf-scan"
      />

      <div className="findings">
        {findings
          .sort((a, b) => sevRank[b.severity] - sevRank[a.severity])
          .map((f, i) => (
            <article
              key={`${f.id}-${i}`}
              className={`finding finding--${f.severity}`}
            >
              <header>
                <span className={`sev sev--${f.severity}`}>
                  {f.severity.toUpperCase()}
                </span>
                <span className="finding__id">{f.id}</span>
                <h3>{f.title}</h3>
              </header>
              <p>{f.detail}</p>
              {f.excerpt && <pre className="finding__excerpt">{f.excerpt}</pre>}
              {standardsFor(f.id) && (
                <p
                  style={{
                    marginTop: "0.4rem",
                    fontSize: "0.8rem",
                    color: "var(--ink-dim, #888)",
                  }}
                >
                  <strong>standards:</strong> {standardsFor(f.id)!.join(" · ")}
                </p>
              )}
            </article>
          ))}
      </div>

      {/* ============================================================ */}
      {/* SSRF v2 — live fetcher sandbox (T-01c).                       */}
      {/* ============================================================ */}
      <h2 style={{ marginTop: "2.5rem" }}>
        Fetcher sandbox — naive vs hardened
      </h2>
      <p style={{ color: "var(--ink-dim)", fontSize: "0.9rem" }}>
        Pick one of {SSRF_CATALOG.length} catalog payloads. Two fetchers
        receive the same request: a naive one (substring blocklist on the raw
        URL) and a hardened one (scheme allowlist → CRLF check → header strip
        → host canonicalisation → IP blocklist → IP-pinned fetch). The
        deterministic transcripts show what each would put on the wire and
        which hardened rule blocks the call. Reproduce any scenario over the
        wire with{" "}
        <code>POST /api/ssrf-fetch {`{ "scenarioId": "...", "mode": "..." }`}</code>
        .
      </p>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
          gap: "0.5rem",
          margin: "0.6rem 0 0.8rem",
        }}
      >
        {SSRF_CATALOG.map((s) => (
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

      <div
        style={{
          padding: "0.6rem 0.8rem",
          border: "1px dashed var(--rule)",
          background: "var(--bg-elev)",
          fontSize: "0.85rem",
          color: "var(--ink-dim)",
          marginBottom: "0.8rem",
        }}
      >
        <div>
          <strong style={{ color: "var(--ink)" }}>{scenario.title}</strong> ·{" "}
          <a
            href={scenario.reference.url}
            target="_blank"
            rel="noopener noreferrer"
          >
            {scenario.reference.label}
          </a>
        </div>
        <p style={{ margin: "0.4rem 0 0.4rem" }}>{scenario.blurb}</p>
        <pre
          style={{
            margin: 0,
            padding: "0.45rem 0.6rem",
            fontSize: "0.78rem",
            whiteSpace: "pre-wrap",
            wordBreak: "break-all",
            background: "var(--bg)",
            border: "1px solid var(--rule)",
          }}
        >
          {`${scenario.request.method ?? "GET"} ${scenario.request.url}${
            scenario.request.headers
              ? "\n" +
                Object.entries(scenario.request.headers)
                  .map(([k, v]) => `${k}: ${v}`)
                  .join("\n")
              : ""
          }`}
        </pre>
        <button
          type="button"
          onClick={() => copyAsCurl(scenario)}
          style={{
            marginTop: "0.5rem",
            background: "transparent",
            color: "var(--ink-dim)",
            border: "1px solid var(--rule)",
            padding: "0.3rem 0.7rem",
            fontSize: "0.75rem",
            fontWeight: 500,
          }}
        >
          Copy as curl (against /api/ssrf-fetch)
        </button>
      </div>

      <div className="pi-agents" style={{ alignItems: "stretch" }}>
        <section className="pi-agent pi-agent--naive">
          <h2>Naive fetcher</h2>
          <FetcherTrace steps={naiveRun.steps} />
        </section>
        <section className="pi-agent pi-agent--hardened">
          <h2>Hardened fetcher</h2>
          <FetcherTrace steps={hardenedRun.steps} />
        </section>
      </div>

      <h2 style={{ marginTop: "1.5rem" }}>What this proves</h2>
      <ul style={{ fontSize: "0.88rem" }}>
        <li>
          Substring blocklists on the raw URL fail against every encoded-host,
          IPv6, header-smuggle, and DNS-rebinding scenario in the catalog. The
          naive fetcher would put the malicious bytes on the wire in all 10.
        </li>
        <li>
          The hardened rule chain (scheme → CRLF → strip-headers → canonicalise
          → blocklist → pin-IP) refuses every catalog request before any
          socket open. Each block is tagged with the rule id (H-SCHEME,
          H-CRLF, H-HEADERS, H-CANON, H-IPRANGE, H-IPV6, H-PINIP) so you can
          map it back to the implementation in <code>lib/ssrf.ts</code>.
        </li>
        <li>
          Both fetchers are deterministic transcripts. The hardened-rule
          implementation is the same code a real backend would ship; only the
          wire transmission is faked, because emitting real metadata-IP /
          gopher:// / Redis-CRLF traffic from a public service would be both
          irresponsible and blocked by every modern hosting platform&apos;s
          egress firewall.
        </li>
      </ul>
    </>
  );
}

function FetcherTrace({ steps }: { steps: FetcherStep[] }) {
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
          }}
        >
          <div
            style={{
              display: "inline-block",
              marginRight: "0.4rem",
              padding: "0.05rem 0.35rem",
              border: `1px solid ${stepColor(s)}`,
              color: stepColor(s),
              fontSize: "0.65rem",
              textTransform: "uppercase",
              letterSpacing: "0.05em",
            }}
          >
            {s.label}
          </div>
          <span
            style={{
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
              color: "var(--ink-dim)",
            }}
          >
            {s.detail}
          </span>
        </li>
      ))}
    </ol>
  );
}

function stepColor(s: FetcherStep): string {
  if (s.kind === "block") return "var(--ok)";
  if (s.kind === "leak") return "var(--high)";
  if (s.kind === "wire") return "var(--accent)";
  if (s.kind === "response") return "var(--ink-dim)";
  if (s.kind === "final") return s.status === "block" ? "var(--ok)" : "var(--high)";
  return "var(--rule)";
}

function copyAsCurl(s: { id: string; request: { url: string } }) {
  const cmd = `curl -X POST '${typeof window !== "undefined" ? window.location.origin : "https://lab.marwandiallo.com"}/api/ssrf-fetch' \\\n  -H 'content-type: application/json' \\\n  -d '${JSON.stringify({ scenarioId: s.id, mode: "naive" })}'`;
  if (typeof navigator !== "undefined" && navigator.clipboard) {
    navigator.clipboard.writeText(cmd).catch(() => {
      /* clipboard refused; fall back to prompt below */
      window.prompt("Copy:", cmd);
    });
  } else {
    window.prompt("Copy:", cmd);
  }
}
