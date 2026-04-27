"use client";

import { useState } from "react";
import { analyze, type Finding } from "@/lib/csp";

const SAMPLES: Record<string, string> = {
  "Strict (nonce + strict-dynamic)":
    "default-src 'self'; script-src 'nonce-RANDOM' 'strict-dynamic'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; report-to csp-endpoint",
  "Common — too loose":
    "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline'",
  "Allowlist with CDN":
    "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://*.cloudfront.net; img-src 'self' data: https:",
  "Wildcard everything (don't ship)":
    "default-src *; script-src * 'unsafe-inline' 'unsafe-eval'",
};

export default function Analyzer() {
  const [input, setInput] = useState(SAMPLES["Common — too loose"]);
  const findings: Finding[] = analyze(input);

  return (
    <>
      <h1>CSP Analyzer</h1>
      <p className="lede">
        Paste a Content-Security-Policy header value. The analyzer checks 12
        rules, ranked by severity, with fixes. Pure client-side; nothing leaves
        your browser.
      </p>

      <div className="row" style={{ flexWrap: "wrap", gap: "0.4rem" }}>
        {Object.keys(SAMPLES).map((name) => (
          <button
            key={name}
            onClick={() => setInput(SAMPLES[name])}
            style={{
              background: "transparent",
              color: "var(--ink-dim)",
              border: "1px solid var(--rule)",
              padding: "0.35rem 0.7rem",
              fontSize: "0.78rem",
              fontWeight: 500,
            }}
          >
            {name}
          </button>
        ))}
      </div>

      <textarea
        value={input}
        onChange={(e) => setInput(e.target.value)}
        spellCheck={false}
        style={{ marginTop: "1rem", minHeight: 130 }}
        aria-label="Content Security Policy input"
      />

      <div className="csp-summary">
        {findings.length === 0 ? (
          <span className="status ok">
            No findings. Paste a real-world CSP — most fail.
          </span>
        ) : (
          <span className="csp-counts">
            {countAt(findings, "high")} high &middot;{" "}
            {countAt(findings, "medium")} medium &middot;{" "}
            {countAt(findings, "low")} low &middot; {countAt(findings, "info")}{" "}
            info
          </span>
        )}
      </div>

      <div className="findings">
        {findings.map((f) => (
          <div key={f.id} className={`finding ${f.severity}`}>
            <div>
              <span className="sev">{f.severity}</span>
              <strong>{f.id}</strong> &mdash; {f.title}
              {f.directive && (
                <span className="csp-dir">
                  {" "}
                  &middot; <code>{f.directive}</code>
                </span>
              )}
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

      <h2>What this checks</h2>
      <p>
        The rule list intentionally mirrors what I look for in client
        engagements. It is opinionated — for example, <code>object-src</code>{" "}
        not locked to <code>'none'</code> is flagged even when modern apps don't
        use plugins, because the cost of locking it is zero and the upside is
        removing a historical XSS surface entirely.
      </p>
      <p>
        Out of scope (for now): <code>require-trusted-types-for</code>,{" "}
        <code>trusted-types</code>, <code>sandbox</code>, and per-element
        directives like <code>script-src-attr</code>. Those are next.
      </p>
    </>
  );
}

function countAt(findings: Finding[], sev: string) {
  return findings.filter((f) => f.severity === sev).length;
}
