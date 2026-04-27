"use client";

import { useState } from "react";
import { analyze, type Finding } from "@/lib/csp";
import { findingsToSarif } from "@/lib/sarif";

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

type ScanResult = {
  target: string;
  status: number;
  headers: Record<string, string>;
  csp: string | null;
  findings: Finding[];
  counts: { high: number; medium: number; low: number; info: number };
};

type Mode = "paste" | "scan";

export default function Analyzer() {
  const [mode, setMode] = useState<Mode>("paste");
  const [input, setInput] = useState(SAMPLES["Common — too loose"]);
  const [url, setUrl] = useState("https://marwandiallo.com");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const pasteFindings: Finding[] = analyze(input);
  const findings = mode === "scan" ? (scanResult?.findings ?? []) : pasteFindings;

  async function runScan() {
    setScanning(true);
    setScanError(null);
    setScanResult(null);
    try {
      const r = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await r.json();
      if (!r.ok) {
        setScanError(data.error ?? `HTTP ${r.status}`);
      } else {
        setScanResult(data);
      }
    } catch (err) {
      setScanError(err instanceof Error ? err.message : "Network error");
    } finally {
      setScanning(false);
    }
  }

  function downloadSarif() {
    const target =
      mode === "scan" ? (scanResult?.target ?? "scanned-url") : "user-input";
    const sarif = findingsToSarif(findings, {
      toolName: "lab.marwandiallo.com/csp",
      target,
    });
    const blob = new Blob([JSON.stringify(sarif, null, 2)], {
      type: "application/sarif+json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "scan.sarif.json";
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function downloadJson() {
    const payload =
      mode === "scan" ? scanResult : { input, findings: pasteFindings };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "scan.json";
    a.click();
    URL.revokeObjectURL(a.href);
  }

  return (
    <>
      <h1>CSP & Headers Analyzer</h1>
      <p className="lede">
        Two modes: paste a CSP string for a 12-rule audit, or scan a live URL
        to fetch its real response headers and run the full headers + SRI
        ruleset. Export to SARIF for GitHub Code Scanning.
      </p>

      <div className="row" style={{ gap: "0.4rem", marginBottom: "0.8rem" }}>
        <button
          onClick={() => setMode("paste")}
          aria-pressed={mode === "paste"}
          style={{
            background: mode === "paste" ? "var(--ink)" : "transparent",
            color: mode === "paste" ? "var(--bg)" : "var(--ink-dim)",
            border: "1px solid var(--rule)",
            padding: "0.4rem 0.8rem",
            fontWeight: 500,
          }}
        >
          Paste CSP
        </button>
        <button
          onClick={() => setMode("scan")}
          aria-pressed={mode === "scan"}
          style={{
            background: mode === "scan" ? "var(--ink)" : "transparent",
            color: mode === "scan" ? "var(--bg)" : "var(--ink-dim)",
            border: "1px solid var(--rule)",
            padding: "0.4rem 0.8rem",
            fontWeight: 500,
          }}
        >
          Scan a URL
        </button>
      </div>

      {mode === "paste" && (
        <>
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
        </>
      )}

      {mode === "scan" && (
        <>
          <div className="row" style={{ gap: "0.5rem", alignItems: "stretch" }}>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              spellCheck={false}
              style={{
                flex: 1,
                padding: "0.6rem 0.8rem",
                fontFamily: "var(--mono)",
                fontSize: "0.9rem",
                border: "1px solid var(--rule)",
                background: "var(--bg)",
                color: "var(--ink)",
              }}
              aria-label="URL to scan"
            />
            <button
              onClick={runScan}
              disabled={scanning || !url.trim()}
              style={{
                background: "var(--ink)",
                color: "var(--bg)",
                padding: "0.6rem 1.1rem",
                fontWeight: 600,
                opacity: scanning ? 0.6 : 1,
              }}
            >
              {scanning ? "Scanning…" : "Scan"}
            </button>
          </div>
          <p
            style={{
              fontSize: "0.78rem",
              color: "var(--ink-dim)",
              margin: "0.5rem 0 0",
            }}
          >
            Public URLs only. Loopback, RFC1918, link-local, and cloud-metadata
            addresses are blocked at the SSRF guard. Rate-limited to 1 request
            per 10 seconds per IP.
          </p>

          {scanError && (
            <div
              role="alert"
              style={{
                marginTop: "1rem",
                padding: "0.7rem 0.9rem",
                border: "1px solid #ef4444",
                background: "rgba(239, 68, 68, 0.06)",
                fontSize: "0.88rem",
              }}
            >
              <strong>Scan failed:</strong> {scanError}
            </div>
          )}

          {scanResult && (
            <div
              style={{
                marginTop: "1rem",
                padding: "0.8rem 1rem",
                border: "1px solid var(--rule)",
              }}
            >
              <div style={{ fontSize: "0.85rem", color: "var(--ink-dim)" }}>
                <code>{scanResult.target}</code> — HTTP {scanResult.status}
              </div>
              {scanResult.csp ? (
                <pre
                  style={{
                    marginTop: "0.6rem",
                    fontSize: "0.78rem",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-all",
                  }}
                >
                  {scanResult.csp}
                </pre>
              ) : (
                <p style={{ fontSize: "0.85rem" }}>
                  No Content-Security-Policy header on this response.
                </p>
              )}
            </div>
          )}
        </>
      )}

      <div className="csp-summary">
        {findings.length === 0 ? (
          <span className="status ok">
            {mode === "scan" && !scanResult
              ? "Run a scan to populate findings."
              : "No findings."}
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

      {findings.length > 0 && (
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
      )}

      <div className="findings">
        {findings.map((f, i) => (
          <div key={`${f.id}-${i}`} className={`finding ${f.severity}`}>
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
        <strong>Paste mode</strong> runs 12 CSP rules (CSP01–CSP12) against any
        policy string. <strong>Scan mode</strong> fetches a live URL and runs
        the same CSP rules plus 12 security-headers rules (HDR01–HDR12: HSTS,
        X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
        Permissions-Policy, COOP/COEP, version banners) and a Subresource
        Integrity check on cross-origin <code>&lt;script&gt;</code> tags.
      </p>
      <p>
        Both modes export to SARIF v2.1.0 — paste the file into a GitHub
        Code Scanning workflow and findings show up in the Security tab.
      </p>
      <p>
        Out of scope (for now): <code>require-trusted-types-for</code>,{" "}
        <code>trusted-types</code>, <code>sandbox</code>, per-element
        directives like <code>script-src-attr</code>, and DNS-rebinding-aware
        IP re-resolution. Those need a Node runtime; the scanner runs on Edge.
      </p>
    </>
  );
}

function countAt(findings: Finding[], sev: string) {
  return findings.filter((f) => f.severity === sev).length;
}
