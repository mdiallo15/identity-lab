"use client";

import { useMemo, useState } from "react";
import {
  analyze,
  sevRank,
  SSRF_SAMPLES,
  type Severity,
  type Finding,
} from "../../../lib/ssrf";
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
      <p style={{ fontSize: "0.78rem", color: "var(--ink-dim)", margin: "0.5rem 0 0" }}>
        Runs the canonical 4-stage hardening flow on the server:
        parse → pre-flight rule check → DNS resolve + re-check every IP
        (DNS-rebinding defence) → bounded fetch. Each stage's pass/fail
        is shown below.
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
            </article>
          ))}
      </div>
    </>
  );
}
