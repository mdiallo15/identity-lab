"use client";

import { useState } from "react";
import { decodeJwt, analyzeJwt, type JwtFinding } from "@/lib/jwt";

const SAMPLE =
  "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
  "eyJzdWIiOiJqYW5lLmRvZUBleGFtcGxlLmNvbSIsImlzcyI6Imh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbSIsImV4cCI6MTAwMDAwMDAwMH0." +
  "";

export default function JwtPage() {
  const [token, setToken] = useState("");
  const [decoded, setDecoded] = useState<{
    header: unknown;
    payload: unknown;
  } | null>(null);
  const [findings, setFindings] = useState<JwtFinding[]>([]);
  const [error, setError] = useState<string | null>(null);

  function inspect(value: string) {
    setError(null);
    setDecoded(null);
    setFindings([]);
    if (!value.trim()) return;
    try {
      const parts = decodeJwt(value);
      setDecoded({ header: parts.header, payload: parts.payload });
      setFindings(analyzeJwt(parts));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to decode");
    }
  }

  return (
    <>
      <h1>JWT inspector</h1>
      <p className="lede">
        Paste any JWT. We never send it to a server — decoding happens entirely
        in your browser.
      </p>

      <textarea
        placeholder="eyJhbGciOi…"
        value={token}
        onChange={(e) => {
          setToken(e.target.value);
          inspect(e.target.value);
        }}
      />
      <p>
        <button
          type="button"
          onClick={() => {
            setToken(SAMPLE);
            inspect(SAMPLE);
          }}
        >
          Load alg=none sample
        </button>
      </p>

      {error ? <div className="status err">{error}</div> : null}

      {decoded ? (
        <>
          <h2>Header</h2>
          <pre>{JSON.stringify(decoded.header, null, 2)}</pre>
          <h2>Payload</h2>
          <pre>{JSON.stringify(decoded.payload, null, 2)}</pre>
          <h2>Findings</h2>
          <div className="findings">
            {findings.map((f, i) => (
              <div key={i} className={`finding ${f.severity}`}>
                <span className="sev">{f.severity}</span>
                <strong>{f.title}</strong>
                <div style={{ marginTop: 4, color: "var(--ink-dim)" }}>
                  {f.detail}
                </div>
              </div>
            ))}
          </div>
        </>
      ) : null}
    </>
  );
}
