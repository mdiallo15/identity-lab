"use client";

import { useMemo, useState } from "react";
import {
  analyze,
  sevRank,
  SSRF_SAMPLES,
  type Severity,
} from "../../../lib/ssrf";
import { ExportButtons } from "../../_components/export-buttons";

export default function SsrfAnalyzer() {
  const [url, setUrl] = useState<string>(SSRF_SAMPLES[1].value);

  const { parsed, findings } = useMemo(() => analyze(url), [url]);

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
