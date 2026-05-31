"use client";

import { useMemo, useState } from "react";
import {
  INCIDENTS,
  SCENARIOS,
  analyzePackage,
  type PackageInput,
  type ProvFinding,
  type ProvScenario,
  type SupplyChainIncident,
} from "@/lib/supply-chain";

/* Build the levenshtein distance between two short strings — used for the
 * interactive typosquat checker so users can paste any package name and see
 * the closest known-good neighbours. Iterative O(m*n), capped at 32 chars
 * each side to keep it cheap. */
function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const ax = a.slice(0, 32);
  const bx = b.slice(0, 32);
  const m = ax.length;
  const n = bx.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const dp: number[] = Array(n + 1)
    .fill(0)
    .map((_, i) => i);
  for (let i = 1; i <= m; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const tmp = dp[j];
      dp[j] =
        ax[i - 1] === bx[j - 1]
          ? prev
          : Math.min(prev, dp[j], dp[j - 1]) + 1;
      prev = tmp;
    }
  }
  return dp[n];
}

const POPULAR_PACKAGES = [
  // npm
  "lodash","react","react-dom","express","axios","webpack","typescript","next",
  "vite","jest","eslint","prettier","tailwindcss","zod","yargs","chalk",
  "moment","ua-parser-js","ws","uuid","commander","node-fetch","cross-env",
  "request","discord.js","puppeteer",
  // pypi
  "requests","numpy","pandas","scipy","matplotlib","tensorflow","torch",
  "pyyaml","django","flask","fastapi","pillow","cryptography","sqlalchemy",
  "pytest","colorama","ultralytics","typing-extensions","beautifulsoup4",
];

interface SquatHit {
  name: string;
  distance: number;
  reason: string;
}

function checkSquat(candidate: string): SquatHit[] {
  const c = candidate.trim().toLowerCase();
  if (!c) return [];
  const hits: SquatHit[] = [];
  for (const p of POPULAR_PACKAGES) {
    if (p === c) continue;
    const d = levenshtein(c, p);
    if (d > 0 && d <= 2) {
      let reason = `Levenshtein distance ${d} from '${p}'`;
      if (c.length === p.length && d <= 2) reason += " — possible transposition / homoglyph";
      else if (c.length === p.length + 1) reason += " — single-letter insertion";
      else if (c.length === p.length - 1) reason += " — single-letter omission";
      if (
        c.replace(/[-_]/g, "") === p.replace(/[-_]/g, "") &&
        c !== p
      ) {
        reason = `dash/underscore ambiguity vs '${p}' (different package on PyPI/npm)`;
      }
      hits.push({ name: p, distance: d, reason });
    }
  }
  return hits.sort((a, b) => a.distance - b.distance).slice(0, 5);
}

export default function SupplyChainAnalyzer() {
  const [activeId, setActiveId] = useState<string>(SCENARIOS[0].id);
  const active: ProvScenario =
    SCENARIOS.find((s) => s.id === activeId) ?? SCENARIOS[0];

  const [pkgJson, setPkgJson] = useState<string>(active.input.pkgJson);
  const [registryJson, setRegistryJson] = useState<string>(
    JSON.stringify(active.input.registry, null, 2),
  );
  const [squatInput, setSquatInput] = useState<string>("");

  function loadScenario(id: string) {
    const s = SCENARIOS.find((x) => x.id === id) ?? SCENARIOS[0];
    setActiveId(s.id);
    setPkgJson(s.input.pkgJson);
    setRegistryJson(JSON.stringify(s.input.registry, null, 2));
  }

  const { registry, registryError } = useMemo(() => {
    try {
      return {
        registry: JSON.parse(registryJson) as PackageInput["registry"],
        registryError: null as string | null,
      };
    } catch (e) {
      return {
        registry: active.input.registry,
        registryError: (e as Error).message,
      };
    }
  }, [registryJson, active]);

  const findings: ProvFinding[] = useMemo(
    () => analyzePackage({ pkgJson, registry }),
    [pkgJson, registry],
  );

  const squatHits = useMemo(() => checkSquat(squatInput), [squatInput]);

  const matchedIncident: SupplyChainIncident | undefined = active.incidentId
    ? INCIDENTS.find((i) => i.id === active.incidentId)
    : undefined;

  return (
    <>
      <div
        style={{
          marginTop: "0.4rem",
          padding: "0.6rem 0.8rem",
          border: "1px dashed var(--rule)",
          fontSize: "0.78rem",
          color: "var(--ink-dim)",
          background: "var(--bg-elev)",
        }}
      >
        <strong>How this works.</strong> Each scenario seeds a plausibly-real{" "}
        <code>package.json</code> and registry response into the editors below.{" "}
        <strong>Edit either field</strong> and the analyzer re-runs live: add
        an <code>install</code> script with a <code>curl</code>, change the
        publisher IP between versions, drop the <code>attestations</code>{" "}
        array, mark a maintainer&apos;s 2FA off. Watch the seven rules
        (PROV01–PROV07) light up in real time. Use the typosquat checker at
        the bottom to test any package name against a list of 40+ popular
        names.
      </div>

      <h2 style={{ marginTop: "1.6rem" }}>Real incident replicas</h2>
      <p style={{ color: "var(--ink-dim)", fontSize: "0.88rem" }}>
        Click a card to load that incident&apos;s metadata into the editors.
        The fields are editable from there — try fixing the malicious one or
        breaking a clean one.
      </p>
      <div className="csp-scenarios">
        {SCENARIOS.map((s) => (
          <button
            key={s.id}
            onClick={() => loadScenario(s.id)}
            data-active={s.id === activeId}
            className="csp-scenario-card"
            type="button"
          >
            <span className="csp-scenario-cat">
              {s.incidentId ? "incident" : "pattern"}
            </span>
            <span className="csp-scenario-title">{s.title}</span>
          </button>
        ))}
      </div>

      <div className="csp-scenario-detail">
        <p>
          <strong>What you&apos;re looking at.</strong> {active.blurb}
        </p>
        <p>
          <strong>Expected:</strong> {active.expected}
        </p>
        {matchedIncident && (
          <details style={{ marginTop: "0.4rem" }}>
            <summary
              style={{
                cursor: "pointer",
                fontSize: "0.82rem",
                color: "var(--accent)",
              }}
            >
              real-world details — {matchedIncident.pkg} ({matchedIncident.date}
              {matchedIncident.cve ? `, ${matchedIncident.cve}` : ""})
            </summary>
            <p style={{ marginTop: "0.5rem" }}>
              <strong>Vector.</strong> {matchedIncident.vector}
            </p>
            <p>
              <strong>Payload.</strong> {matchedIncident.payload}
            </p>
            <p>
              <strong>Blast radius.</strong> {matchedIncident.blastRadius}
            </p>
            <p style={{ fontSize: "0.78rem", color: "var(--ink-dim)" }}>
              <strong>refs:</strong>{" "}
              {matchedIncident.references.map((r, i) => (
                <span key={r}>
                  <a href={r} target="_blank" rel="noopener noreferrer">
                    {new URL(r).hostname}
                  </a>
                  {i < matchedIncident.references.length - 1 ? " · " : ""}
                </span>
              ))}
            </p>
          </details>
        )}
      </div>

      <h2 style={{ marginTop: "1.6rem" }}>package.json + registry response (editable)</h2>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "0.8rem",
        }}
      >
        <div>
          <label
            htmlFor="sc-pkgjson"
            style={{
              display: "block",
              fontSize: "0.78rem",
              color: "var(--ink-dim)",
            }}
          >
            package.json
          </label>
          <textarea
            id="sc-pkgjson"
            value={pkgJson}
            onChange={(e) => setPkgJson(e.target.value)}
            spellCheck={false}
            style={{
              minHeight: 220,
              marginTop: "0.3rem",
              fontFamily: "ui-monospace, monospace",
              fontSize: "0.78rem",
            }}
          />
        </div>
        <div>
          <label
            htmlFor="sc-registry"
            style={{
              display: "block",
              fontSize: "0.78rem",
              color: "var(--ink-dim)",
            }}
          >
            registry metadata (JSON){" "}
            {registryError && (
              <span style={{ color: "var(--high)" }}>— parse error: {registryError}</span>
            )}
          </label>
          <textarea
            id="sc-registry"
            value={registryJson}
            onChange={(e) => setRegistryJson(e.target.value)}
            spellCheck={false}
            style={{
              minHeight: 220,
              marginTop: "0.3rem",
              fontFamily: "ui-monospace, monospace",
              fontSize: "0.78rem",
            }}
          />
        </div>
      </div>
      <p style={{ color: "var(--ink-dim)", fontSize: "0.78rem", marginTop: "0.4rem" }}>
        Try editing fields to see rules fire/clear: add a <code>preinstall</code> script with <code>curl</code> → PROV01. Change one version&apos;s <code>publisherIp</code> → PROV03. Delete an <code>attestations</code> array → PROV04. Set <code>twoFactor</code> to false on a recent maintainer → PROV06.
      </p>

      <h2 style={{ marginTop: "1.6rem" }}>
        Provenance findings ({findings.length})
      </h2>
      {findings.length === 0 && (
        <p>
          <span className="status ok">No findings.</span> The package looks
          clean against PROV01–PROV07 with the metadata available pre-install.
        </p>
      )}
      <div className="findings">
        {findings.map((f, i) => (
          <div key={`${f.id}-${i}`} className={`finding ${f.severity}`}>
            <div>
              <span className="sev">{f.severity}</span>
              <strong>{f.id}</strong> &mdash; {f.title}
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

      <h2 style={{ marginTop: "1.6rem" }}>Typosquat checker</h2>
      <p style={{ color: "var(--ink-dim)", fontSize: "0.88rem" }}>
        Paste any npm or PyPI package name. The checker computes Levenshtein
        distance against 40+ popular packages and flags any neighbour within
        edit-distance 2 — the same heuristic used by registry abuse-detection
        teams.
      </p>
      <input
        type="text"
        value={squatInput}
        onChange={(e) => setSquatInput(e.target.value)}
        placeholder="e.g. loadash, requets, colourama, pyyaml_"
        spellCheck={false}
        style={{
          width: "100%",
          padding: "0.6rem 0.8rem",
          fontFamily: "ui-monospace, monospace",
          fontSize: "0.85rem",
          background: "var(--bg-elev)",
          border: "1px solid var(--rule)",
          color: "var(--ink)",
        }}
      />
      {squatInput.trim() && (
        <div style={{ marginTop: "0.5rem" }}>
          {squatHits.length === 0 && (
            <span className="status ok">
              No popular package within edit-distance 2. Likely original.
            </span>
          )}
          {squatHits.map((h) => (
            <div
              key={h.name}
              style={{
                border: "1px solid var(--high)",
                padding: "0.5rem 0.7rem",
                fontSize: "0.82rem",
                marginBottom: "0.4rem",
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: "0.6rem",
              }}
            >
              <div>
                <code>{squatInput.trim()}</code> → <code>{h.name}</code>
              </div>
              <div style={{ color: "var(--ink-dim)", fontSize: "0.78rem" }}>
                {h.reason}
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}
