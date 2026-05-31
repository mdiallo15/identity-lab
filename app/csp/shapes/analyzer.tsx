"use client";

import { useMemo, useState } from "react";
import { recommendShape } from "@/lib/csp-shapes";

export default function CspShapesAnalyzer() {
  const [serverRendered, setServerRendered] = useState(true);
  const [staticHosted, setStaticHosted] = useState(false);
  const [thirdPartyScripts, setThirdPartyScripts] = useState(true);
  const [inlineScripts, setInlineScripts] = useState(false);
  const [reportOnlyRollout, setReportOnlyRollout] = useState(false);

  const recommendation = useMemo(
    () =>
      recommendShape({
        serverRendered,
        staticHosted,
        thirdPartyScripts,
        inlineScripts,
        reportOnlyRollout,
      }),
    [
      serverRendered,
      staticHosted,
      thirdPartyScripts,
      inlineScripts,
      reportOnlyRollout,
    ],
  );

  return (
    <>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "0.9rem",
          marginTop: "1rem",
        }}
      >
        <section className="card">
          <h2 style={{ marginTop: 0 }}>App constraints</h2>
          <label style={{ display: "block", margin: "0.55rem 0" }}>
            <input type="checkbox" checked={serverRendered} onChange={(e) => setServerRendered(e.target.checked)} style={{ width: "auto", marginRight: "0.4rem" }} />
            server-rendered app with request-time header control
          </label>
          <label style={{ display: "block", margin: "0.55rem 0" }}>
            <input type="checkbox" checked={staticHosted} onChange={(e) => setStaticHosted(e.target.checked)} style={{ width: "auto", marginRight: "0.4rem" }} />
            static hosting / CDN-only deployment
          </label>
          <label style={{ display: "block", margin: "0.55rem 0" }}>
            <input type="checkbox" checked={thirdPartyScripts} onChange={(e) => setThirdPartyScripts(e.target.checked)} style={{ width: "auto", marginRight: "0.4rem" }} />
            third-party runtime scripts are unavoidable
          </label>
          <label style={{ display: "block", margin: "0.55rem 0" }}>
            <input type="checkbox" checked={inlineScripts} onChange={(e) => setInlineScripts(e.target.checked)} style={{ width: "auto", marginRight: "0.4rem" }} />
            the app still has inline scripts that have not been migrated
          </label>
          <label style={{ display: "block", margin: "0.55rem 0" }}>
            <input type="checkbox" checked={reportOnlyRollout} onChange={(e) => setReportOnlyRollout(e.target.checked)} style={{ width: "auto", marginRight: "0.4rem" }} />
            the team is still in a short-lived report-only rollout window
          </label>
        </section>

        <section className="card">
          <h2 style={{ marginTop: 0 }}>Recommended shape</h2>
          <p>
            <strong>{recommendation.recommended.title}</strong>
          </p>
          <p style={{ color: "var(--ink-dim)", fontSize: "0.88rem" }}>
            {recommendation.recommended.rationale}
          </p>
          <pre>{recommendation.recommended.policy}</pre>
        </section>
      </div>

      <h2>Migration notes</h2>
      <ul>
        {recommendation.migration.map((step) => (
          <li key={step}>{step}</li>
        ))}
      </ul>

      <h2>What the baseline analyzer still flags</h2>
      <div className="findings">
        {recommendation.findings.map((finding) => (
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