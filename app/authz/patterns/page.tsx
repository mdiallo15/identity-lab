"use client";

import { RULES, type Severity } from "../../../lib/authz";
import { ExportButtons } from "../../_components/export-buttons";

const sevRank: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export default function AuthzPatterns() {
  const findings = [...RULES].sort(
    (a, b) => sevRank[b.severity] - sevRank[a.severity],
  );

  return (
    <>
      <h1>BOLA / IDOR patterns</h1>
      <p className="lede">
        Eight patterns I look for in API code reviews and Burp traces. Each
        is paired with the actual fix — not "add authz", but the specific
        line of code or query change that closes the gap.
      </p>

      <ExportButtons
        findings={findings}
        toolName="lab.marwandiallo.com/authz"
        target="ruleset"
        payload={{ rules: findings }}
        filenamePrefix="bola-rules"
      />

      <div className="findings">
        {findings.map((f) => (
          <article
            key={f.id}
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
            {f.fix && (
              <p style={{ marginTop: "0.5rem", fontSize: "0.9rem" }}>
                <strong style={{ color: "var(--ok, #22c55e)" }}>fix:</strong>{" "}
                {f.fix}
              </p>
            )}
          </article>
        ))}
      </div>

      <h2>The two questions to ask any list-or-fetch endpoint</h2>
      <ol>
        <li>
          <strong>Whose data does this query return?</strong> If the answer
          isn't "the authenticated principal's", the next question matters.
        </li>
        <li>
          <strong>Where is ownership enforced?</strong> "In the route
          handler" is a yellow flag. "In the data layer, in the same query
          that does the fetch" is what you want.
        </li>
      </ol>
    </>
  );
}
