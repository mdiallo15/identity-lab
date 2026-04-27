"use client";

import { findingsToSarif, type SarifFinding } from "@/lib/sarif";

interface Props {
  findings: SarifFinding[];
  toolName: string; // e.g. "lab.marwandiallo.com/prompt-injection"
  target?: string; // e.g. URL scanned, "user-input", or sample id
  payload?: unknown; // optional richer JSON (defaults to {findings})
  filenamePrefix?: string; // default "scan"
}

// Renders two small download buttons (SARIF + JSON). Lab pages use this
// so the export UX is consistent across the platform.
export function ExportButtons({
  findings,
  toolName,
  target,
  payload,
  filenamePrefix = "scan",
}: Props) {
  if (findings.length === 0) return null;

  function downloadSarif() {
    const sarif = findingsToSarif(findings, { toolName, target });
    download(
      JSON.stringify(sarif, null, 2),
      `${filenamePrefix}.sarif.json`,
      "application/sarif+json",
    );
  }

  function downloadJson() {
    const body = payload ?? { findings };
    download(
      JSON.stringify(body, null, 2),
      `${filenamePrefix}.json`,
      "application/json",
    );
  }

  return (
    <div className="row" style={{ gap: "0.5rem", marginTop: "0.6rem" }}>
      <button
        onClick={downloadSarif}
        style={{
          background: "transparent",
          color: "var(--ink-dim)",
          border: "1px solid var(--rule)",
          padding: "0.35rem 0.8rem",
          fontSize: "0.78rem",
          fontWeight: 500,
        }}
      >
        Download SARIF
      </button>
      <button
        onClick={downloadJson}
        style={{
          background: "transparent",
          color: "var(--ink-dim)",
          border: "1px solid var(--rule)",
          padding: "0.35rem 0.8rem",
          fontSize: "0.78rem",
          fontWeight: 500,
        }}
      >
        Download JSON
      </button>
    </div>
  );
}

function download(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}
