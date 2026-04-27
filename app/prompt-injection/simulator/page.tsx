"use client";

import { useMemo, useState } from "react";
import {
  SAMPLES,
  analyze,
  naiveAgent,
  hardenedAgent,
  sevRank,
  type SampleDoc,
  type Severity,
} from "../../../lib/prompt-injection";
import { ExportButtons } from "../../_components/export-buttons";

export default function Simulator() {
  const [selectedId, setSelectedId] = useState<string>(SAMPLES[1].id);
  const [customMode, setCustomMode] = useState(false);
  const [customBody, setCustomBody] = useState("");
  const [customContext, setCustomContext] = useState(
    "Summarize this document for the user.",
  );

  const doc: SampleDoc = useMemo(() => {
    if (customMode) {
      return {
        id: "custom",
        label: "Your input",
        context: customContext,
        body: customBody,
        attackerNote: "",
      };
    }
    return SAMPLES.find((s) => s.id === selectedId) ?? SAMPLES[0];
  }, [selectedId, customMode, customBody, customContext]);

  const findings = useMemo(() => analyze(doc.body), [doc.body]);
  const naive = useMemo(() => naiveAgent(doc), [doc]);
  const hardened = useMemo(() => hardenedAgent(doc), [doc]);

  const counts = findings.reduce<Record<Severity, number>>(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] ?? 0) + 1;
      return acc;
    },
    { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
  );

  return (
    <>
      <h1>Prompt-injection simulator</h1>
      <p className="lede">
        Pick an attacker-crafted document below. Two simulated agents read it: a{" "}
        <strong>naive</strong> one that treats the document as instructions, and
        a <strong>hardened</strong> one that wraps the document in a data
        boundary. Their outputs diverge sharply once an injection is present.
      </p>

      <div className="row" style={{ marginBottom: "1rem" }}>
        <label>
          <strong>Sample:</strong>{" "}
          <select
            value={customMode ? "custom" : selectedId}
            onChange={(e) => {
              if (e.target.value === "custom") {
                setCustomMode(true);
                if (!customBody) setCustomBody(SAMPLES[1].body);
              } else {
                setCustomMode(false);
                setSelectedId(e.target.value);
              }
            }}
          >
            {SAMPLES.map((s) => (
              <option key={s.id} value={s.id}>
                {s.label}
              </option>
            ))}
            <option value="custom">— Paste your own —</option>
          </select>
        </label>
      </div>

      <div className="pi-task">
        <span className="pi-task__label">Operator's task</span>
        <span className="pi-task__text">{doc.context}</span>
      </div>

      {customMode ? (
        <>
          <label className="pi-label">Operator's task</label>
          <input
            className="pi-input"
            value={customContext}
            onChange={(e) => setCustomContext(e.target.value)}
          />
          <label className="pi-label">Untrusted document</label>
          <textarea
            className="pi-textarea"
            value={customBody}
            onChange={(e) => setCustomBody(e.target.value)}
            rows={14}
          />
        </>
      ) : (
        <>
          <pre className="pi-doc">{doc.body}</pre>
          {doc.attackerNote && (
            <div className="pi-note">
              <strong>What's happening:</strong> {doc.attackerNote}
            </div>
          )}
        </>
      )}

      <div className="csp-summary">
        <strong>{findings.length}</strong> injection pattern
        {findings.length === 1 ? "" : "s"} detected
        <span className="csp-counts">
          {" — "}
          {counts.critical ? `${counts.critical} critical, ` : ""}
          {counts.high ? `${counts.high} high, ` : ""}
          {counts.medium ? `${counts.medium} medium, ` : ""}
          {counts.low ? `${counts.low} low` : ""}
          {!findings.length && "clean"}
        </span>
      </div>

      <div className="pi-agents">
        <section className="pi-agent pi-agent--naive">
          <h2>Naive agent</h2>
          <p className="pi-agent__action">{naive.action}</p>
          <p>
            <strong>Output:</strong> {naive.output}
          </p>
          {naive.followed.length > 0 && (
            <>
              <p className="pi-agent__heading">Instructions followed:</p>
              <ul className="pi-list pi-list--bad">
                {naive.followed.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
            </>
          )}
        </section>

        <section className="pi-agent pi-agent--hardened">
          <h2>Hardened agent</h2>
          <p className="pi-agent__action">{hardened.action}</p>
          <p>
            <strong>Output:</strong> {hardened.output}
          </p>
          {hardened.refused.length > 0 && (
            <>
              <p className="pi-agent__heading">Instructions refused:</p>
              <ul className="pi-list pi-list--good">
                {hardened.refused.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
            </>
          )}
        </section>
      </div>

      {findings.length > 0 && (
        <>
          <h2>Detector findings</h2>
          <ExportButtons
            findings={findings}
            toolName="lab.marwandiallo.com/prompt-injection"
            target={doc.id}
            payload={{ doc, findings, naive, hardened }}
            filenamePrefix="prompt-injection"
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
                  {f.excerpt && (
                    <pre className="finding__excerpt">{f.excerpt}</pre>
                  )}
                </article>
              ))}
          </div>
        </>
      )}
    </>
  );
}
