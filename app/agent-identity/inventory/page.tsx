"use client";

import {
  INVENTORY,
  analyzeInventory,
  severityRank,
} from "../../../lib/agent-identity";
import { standardsFor } from "../../../lib/standards";
import { ExportButtons } from "../../_components/export-buttons";

export default function InventoryPage() {
  const findings = analyzeInventory().sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity),
  );

  return (
    <>
      <h1>Agent inventory + drift detector</h1>
      <p className="lede">
        A fixture inventory of seven agents across four attestation surfaces.
        Eight drift rules (AGT01–AGT08) flag the failure modes that come up
        most often in consulting engagements: long-lived secrets, missing
        attestation, scope drift since baseline, dormant agents, audit gaps,
        and shared workload identities.
      </p>

      <h2>Inventory</h2>
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={th}>Agent</th>
              <th style={th}>Owner</th>
              <th style={th}>Attestation</th>
              <th style={th}>Scopes</th>
              <th style={th}>Last seen</th>
              <th style={th}>Long-lived secret</th>
              <th style={th}>Emits act</th>
            </tr>
          </thead>
          <tbody>
            {INVENTORY.map((a) => (
              <tr key={a.id} style={{ borderTop: "1px solid #2a2a2a" }}>
                <td style={td}>
                  <strong>{a.label}</strong>
                  <br />
                  <code style={{ fontSize: "0.75rem" }}>{a.workload}</code>
                </td>
                <td style={td}>{a.owner}</td>
                <td style={td}>{a.attestation}</td>
                <td style={td}>
                  <code style={{ fontSize: "0.78rem" }}>
                    {a.scopes.join(" ")}
                  </code>
                </td>
                <td style={td}>{a.lastSeen}</td>
                <td style={td}>{a.longLivedSecret ? "yes" : "no"}</td>
                <td style={td}>{a.emitsActClaim ? "yes" : "no"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2 style={{ marginTop: "2rem" }}>Drift findings ({findings.length})</h2>

      <ExportButtons
        findings={findings}
        toolName="lab.marwandiallo.com/agent-identity"
        target="agent-inventory"
        payload={{ inventory: INVENTORY, findings }}
        filenamePrefix="agent-drift"
      />

      <div className="findings">
        {findings.map((f, i) => (
          <article
            key={`${f.agentId}-${f.id}-${i}`}
            className={`finding finding--${f.severity}`}
          >
            <header>
              <span className={`sev sev--${f.severity}`}>
                {f.severity.toUpperCase()}
              </span>
              <span className="finding__id">{f.id}</span>
              <h3>{f.title}</h3>
            </header>
            <p style={{ fontSize: "0.78rem", color: "var(--ink-dim, #888)" }}>
              <strong>agent:</strong> <code>{f.agentId}</code>
            </p>
            <p>{f.detail}</p>
            {f.fix && (
              <p style={{ marginTop: "0.5rem", fontSize: "0.9rem" }}>
                <strong style={{ color: "var(--ok, #22c55e)" }}>fix:</strong>{" "}
                {f.fix}
              </p>
            )}
            {standardsFor(f.id) && (
              <p
                style={{
                  marginTop: "0.4rem",
                  fontSize: "0.8rem",
                  color: "var(--ink-dim, #888)",
                }}
              >
                <strong>standards:</strong>{" "}
                {standardsFor(f.id)!.join(" · ")}
              </p>
            )}
          </article>
        ))}
      </div>

      <h2>Two questions to ask any agent in your environment</h2>
      <ol>
        <li>
          <strong>Whose authority does this agent hold, and how is that
          recorded in the audit log?</strong> If the answer is "the user's,
          and the log doesn't say it was the agent" — that's AGT07.
        </li>
        <li>
          <strong>What stops the credential from being reused if the
          container is compromised?</strong> If the answer is "nothing, it's a
          long-lived API key" — that's AGT01, and it's the single most common
          finding.
        </li>
      </ol>
    </>
  );
}

const th: React.CSSProperties = {
  textAlign: "left",
  padding: "0.5rem 0.6rem",
  fontSize: "0.78rem",
  fontWeight: 600,
  color: "var(--ink-dim, #888)",
  borderBottom: "1px solid #2a2a2a",
};

const td: React.CSSProperties = {
  padding: "0.55rem 0.6rem",
  fontSize: "0.85rem",
  verticalAlign: "top",
};
