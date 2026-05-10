"use client";

import { useEffect, useState } from "react";
import {
  ATTACKS,
  forge,
  getDemoKeys,
  mintLegitimate,
  verifyToken,
  type Alg,
  type AttackEntry,
  type ForgeAttack,
  type VerifierConfig,
  type VerifyResult,
} from "@/lib/jwt-forge";

const DEFAULT_PAYLOAD = {
  sub: "alice@example.com",
  iss: "https://idp.example/",
  aud: "https://api.example/",
  role: "user",
  exp: Math.floor(Date.now() / 1000) + 3600,
};

const DEFAULT_TAMPER = { role: "admin" };

export default function ForgePage() {
  const [keys, setKeys] = useState<{
    publicPem: string;
    privatePem: string;
  } | null>(null);
  const [legitToken, setLegitToken] = useState<string>("");
  const [attack, setAttack] = useState<ForgeAttack>("alg-confusion");
  const [tamperJson, setTamperJson] = useState<string>(
    JSON.stringify(DEFAULT_TAMPER, null, 2),
  );
  const [forgedToken, setForgedToken] = useState<string>("");
  const [forgedSteps, setForgedSteps] = useState<string[]>([]);
  const [forgedTechnique, setForgedTechnique] = useState<string>("");
  const [forgedReference, setForgedReference] = useState<string>("");

  const [config, setConfig] = useState<Omit<VerifierConfig, "publicPem">>({
    expectedIssuer: "https://idp.example/",
    expectedAudience: "https://api.example/",
    allowedAlgorithms: ["RS256"],
    trustHeaderAlg: false,
    acceptAlgNone: false,
  });

  const [legitResult, setLegitResult] = useState<VerifyResult | null>(null);
  const [forgedResult, setForgedResult] = useState<VerifyResult | null>(null);

  // Generate keys + a legit token on mount.
  useEffect(() => {
    (async () => {
      const k = await getDemoKeys();
      setKeys(k);
      const t = await mintLegitimate(k.privatePem, DEFAULT_PAYLOAD);
      setLegitToken(t);
    })();
  }, []);

  // Re-verify both tokens whenever inputs change.
  useEffect(() => {
    (async () => {
      if (!keys || !legitToken) return;
      const fullConfig: VerifierConfig = {
        ...config,
        publicPem: keys.publicPem,
      };
      const r1 = await verifyToken(legitToken, fullConfig);
      setLegitResult(r1);
      if (forgedToken) {
        const r2 = await verifyToken(forgedToken, fullConfig);
        setForgedResult(r2);
      } else {
        setForgedResult(null);
      }
    })();
  }, [keys, legitToken, forgedToken, config]);

  async function runForge() {
    if (!keys || !legitToken) return;
    let overrides: Record<string, unknown> = {};
    try {
      overrides = JSON.parse(tamperJson);
    } catch {
      // ignore parse errors; use empty overrides
    }
    const result = await forge(attack, legitToken, keys.publicPem, overrides);
    setForgedToken(result.token);
    setForgedSteps(result.steps);
    setForgedTechnique(result.technique);
    setForgedReference(result.reference);
  }

  const activeAttack: AttackEntry =
    ATTACKS.find((a) => a.id === attack) ?? ATTACKS[0];

  return (
    <>
      <h1>JWT forging workbench</h1>
      <p className="lede">
        A live attacker workbench paired with a real (intentionally
        misconfigurable) JWT verifier. Generate a legitimate RS256 token, run an
        attack to produce a forged one, then watch the verifier accept or reject
        each as you toggle defenses.
      </p>

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
        <strong>How this works.</strong> A 2048-bit RSA keypair is generated in
        your browser via WebCrypto on page load. The verifier below is the same
        code you&apos;d ship in production, with two configuration knobs that
        mirror the real footguns: <code>trustHeaderAlg</code> (turning it on
        enables RS-vs-HS confusion), and <code>acceptAlgNone</code> (turning it
        on enables CVE-2015-9235). Tokens are minted and verified with no server
        round-trip.
      </div>

      <div
        style={{
          marginTop: "0.6rem",
          padding: "0.6rem 0.8rem",
          border: "1px solid var(--rule)",
          fontSize: "0.8rem",
          background: "var(--bg-elev)",
        }}
      >
        <strong>What this proves.</strong> Four CVE-class verifier bugs that
        have shipped in real libraries and SaaS SDKs:
        <ul style={{ margin: "0.4rem 0 0", paddingLeft: "1.1rem" }}>
          <li>
            <code>alg=none</code> bypass (CVE-2015-9235) — verifier accepts
            unsigned tokens. Defense: pin <code>allowedAlgorithms</code>,
            never honour <code>none</code>.
          </li>
          <li>
            RS256 → HS256 alg confusion (CVE-2016-10555) — attacker HMACs
            the signing input with the verifier&apos;s public key as the
            secret. Defense: ignore the token header&apos;s <code>alg</code>;
            select the algorithm from your key material.
          </li>
          <li>
            <code>kid</code> header path traversal — attacker points
            <code>kid</code> at a known-bytes file and HMACs with those bytes.
            Defense: sanitize <code>kid</code>, resolve it through an allowlist
            of named keys, never as a filesystem path.
          </li>
          <li>
            Tamper claims, keep the signature — “decode-then-trust” code
            paths that read the payload before verifying. Defense: verify
            first, read claims from the verified output, never from the raw
            token.
          </li>
        </ul>
        <p style={{ margin: "0.5rem 0 0", color: "var(--ink-dim)" }}>
          Cross-reference: paste any token you generate here into the{" "}
          <a href="/identity/jwt">JWT inspector</a> for a static decode + Bearer
          health-check.
        </p>
      </div>

      {!keys && <p>Generating RSA keypair…</p>}

      {keys && (
        <>
          {/* ------------------ Legitimate token ------------------ */}
          <h2 style={{ marginTop: "1.6rem" }}>1. Legitimate RS256 token</h2>
          <p style={{ color: "var(--ink-dim)", fontSize: "0.88rem" }}>
            Signed with the demo private key. The verifier below holds the
            matching public key. Edit and re-mint to change claims.
          </p>
          <textarea
            value={legitToken}
            onChange={(e) => setLegitToken(e.target.value)}
            spellCheck={false}
            style={{
              width: "100%",
              minHeight: 90,
              fontFamily: "ui-monospace, monospace",
              fontSize: "0.74rem",
              wordBreak: "break-all",
            }}
          />

          {/* ------------------ Attack picker ------------------ */}
          <h2 style={{ marginTop: "1.6rem" }}>2. Pick a forgery attack</h2>
          <div className="csp-scenarios">
            {ATTACKS.map((a) => (
              <button
                key={a.id}
                onClick={() => setAttack(a.id)}
                data-active={a.id === attack}
                className="csp-scenario-card"
                type="button"
              >
                <span className="csp-scenario-cat">{a.cve ?? "technique"}</span>
                <span className="csp-scenario-title">{a.title}</span>
              </button>
            ))}
          </div>

          <div className="csp-scenario-detail">
            <p>{activeAttack.blurb}</p>
            <p style={{ fontSize: "0.78rem", color: "var(--ink-dim)" }}>
              <strong>defended by:</strong>{" "}
              <code>{activeAttack.defenseLabel}</code> ·{" "}
              <a
                href={activeAttack.reference}
                target="_blank"
                rel="noopener noreferrer"
              >
                reference
              </a>
            </p>
          </div>

          <div style={{ marginTop: "0.8rem" }}>
            <label
              style={{
                display: "block",
                fontSize: "0.78rem",
                color: "var(--ink-dim)",
                marginBottom: "0.2rem",
              }}
            >
              tamper-with overrides (merged into the original payload)
            </label>
            <textarea
              value={tamperJson}
              onChange={(e) => setTamperJson(e.target.value)}
              spellCheck={false}
              style={{
                width: "100%",
                minHeight: 70,
                fontFamily: "ui-monospace, monospace",
                fontSize: "0.78rem",
              }}
            />
          </div>

          <button
            type="button"
            onClick={runForge}
            style={{
              marginTop: "0.6rem",
              padding: "0.5rem 0.9rem",
              background: "var(--high)",
              color: "var(--bg)",
              border: "none",
              fontWeight: 600,
              fontSize: "0.85rem",
              cursor: "pointer",
            }}
          >
            Forge token
          </button>

          {forgedToken && (
            <>
              <h2 style={{ marginTop: "1.6rem" }}>3. Forged token</h2>
              <p
                style={{
                  color: "var(--ink-dim)",
                  fontSize: "0.88rem",
                  margin: "0 0 0.4rem",
                }}
              >
                <strong>{forgedTechnique}</strong>
              </p>
              <textarea
                value={forgedToken}
                onChange={(e) => setForgedToken(e.target.value)}
                spellCheck={false}
                style={{
                  width: "100%",
                  minHeight: 90,
                  fontFamily: "ui-monospace, monospace",
                  fontSize: "0.74rem",
                  wordBreak: "break-all",
                  border: "1px solid var(--high)",
                }}
              />
              <ol
                style={{
                  fontSize: "0.82rem",
                  color: "var(--ink-dim)",
                  marginTop: "0.4rem",
                }}
              >
                {forgedSteps.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ol>
              {forgedReference && (
                <p style={{ fontSize: "0.78rem", marginTop: "0.3rem" }}>
                  <a
                    href={forgedReference}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    {forgedReference}
                  </a>
                </p>
              )}
            </>
          )}

          {/* ------------------ Verifier config ------------------ */}
          <h2 style={{ marginTop: "1.6rem" }}>4. Verifier configuration</h2>
          <p style={{ color: "var(--ink-dim)", fontSize: "0.88rem" }}>
            Toggle the defenses to see when each forgery wins. Default is
            production-correct (algorithms pinned, alg=none rejected, header alg
            ignored).
          </p>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "0.6rem",
              fontSize: "0.85rem",
            }}
          >
            <ConfigToggle
              label="trustHeaderAlg"
              value={config.trustHeaderAlg}
              onChange={(v) => setConfig({ ...config, trustHeaderAlg: v })}
              hint="Pick verification algorithm from the token's own header. The footgun behind RS\u2192HS confusion."
            />
            <ConfigToggle
              label="acceptAlgNone"
              value={config.acceptAlgNone}
              onChange={(v) => setConfig({ ...config, acceptAlgNone: v })}
              hint="Treat alg=none as a valid algorithm. Default off."
            />
            <AlgList
              value={config.allowedAlgorithms}
              onChange={(v) => setConfig({ ...config, allowedAlgorithms: v })}
            />
            <div
              style={{
                border: "1px solid var(--rule)",
                padding: "0.4rem 0.6rem",
              }}
            >
              <label style={{ fontSize: "0.78rem", color: "var(--ink-dim)" }}>
                expectedIssuer
              </label>
              <input
                type="text"
                value={config.expectedIssuer ?? ""}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    expectedIssuer: e.target.value || null,
                  })
                }
                style={{
                  width: "100%",
                  fontFamily: "ui-monospace, monospace",
                  fontSize: "0.78rem",
                  marginTop: "0.2rem",
                }}
              />
            </div>
            <div
              style={{
                border: "1px solid var(--rule)",
                padding: "0.4rem 0.6rem",
              }}
            >
              <label style={{ fontSize: "0.78rem", color: "var(--ink-dim)" }}>
                expectedAudience
              </label>
              <input
                type="text"
                value={config.expectedAudience ?? ""}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    expectedAudience: e.target.value || null,
                  })
                }
                style={{
                  width: "100%",
                  fontFamily: "ui-monospace, monospace",
                  fontSize: "0.78rem",
                  marginTop: "0.2rem",
                }}
              />
            </div>
          </div>

          {/* ------------------ Verifier results ------------------ */}
          <h2 style={{ marginTop: "1.6rem" }}>5. Verifier results</h2>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "0.6rem",
            }}
          >
            <VerifyColumn label="legitimate token" result={legitResult} />
            <VerifyColumn label="forged token" result={forgedResult} />
          </div>

          {/* ------------------ Public key ------------------ */}
          <h2 style={{ marginTop: "1.6rem" }}>Demo public key</h2>
          <p style={{ color: "var(--ink-dim)", fontSize: "0.88rem" }}>
            The verifier holds this. The alg-confusion attack uses the bytes of
            this PEM as an HMAC secret.
          </p>
          <pre
            style={{
              fontSize: "0.7rem",
              padding: "0.5rem",
              background: "var(--bg-elev)",
              border: "1px solid var(--rule)",
              overflow: "auto",
            }}
          >
            {keys.publicPem}
          </pre>
        </>
      )}
    </>
  );
}

function ConfigToggle({
  label,
  value,
  onChange,
  hint,
}: {
  label: string;
  value: boolean;
  onChange: (v: boolean) => void;
  hint: string;
}) {
  return (
    <label
      style={{
        border: "1px solid var(--rule)",
        padding: "0.4rem 0.6rem",
        cursor: "pointer",
        display: "block",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <code>{label}</code>
        <input
          type="checkbox"
          checked={value}
          onChange={(e) => onChange(e.target.checked)}
        />
      </div>
      <p
        style={{
          fontSize: "0.72rem",
          color: "var(--ink-dim)",
          margin: "0.2rem 0 0",
        }}
      >
        {hint}
      </p>
    </label>
  );
}

function AlgList({
  value,
  onChange,
}: {
  value: Alg[];
  onChange: (v: Alg[]) => void;
}) {
  function toggle(a: Alg) {
    if (value.includes(a)) onChange(value.filter((x) => x !== a));
    else onChange([...value, a]);
  }
  return (
    <div style={{ border: "1px solid var(--rule)", padding: "0.4rem 0.6rem" }}>
      <label style={{ fontSize: "0.78rem", color: "var(--ink-dim)" }}>
        allowedAlgorithms
      </label>
      <div style={{ display: "flex", gap: "0.4rem", marginTop: "0.3rem" }}>
        {(["RS256", "HS256", "none"] as Alg[]).map((a) => (
          <label key={a} style={{ fontSize: "0.78rem" }}>
            <input
              type="checkbox"
              checked={value.includes(a)}
              onChange={() => toggle(a)}
            />{" "}
            <code>{a}</code>
          </label>
        ))}
      </div>
    </div>
  );
}

function VerifyColumn({
  label,
  result,
}: {
  label: string;
  result: VerifyResult | null;
}) {
  if (!result) {
    return (
      <div
        style={{
          border: "1px solid var(--rule)",
          padding: "0.6rem 0.8rem",
          color: "var(--ink-dim)",
          fontSize: "0.85rem",
        }}
      >
        {label}: (no token yet)
      </div>
    );
  }
  const accent = result.valid ? "var(--ok)" : "var(--high)";
  return (
    <div
      style={{
        border: `1px solid ${accent}`,
        padding: "0.6rem 0.8rem",
      }}
    >
      <div
        style={{
          textTransform: "uppercase",
          fontSize: "0.7rem",
          letterSpacing: "0.05em",
          color: accent,
          marginBottom: "0.3rem",
        }}
      >
        {label} — {result.valid ? "ACCEPTED" : "REJECTED"}
      </div>
      <p style={{ margin: "0 0 0.4rem", fontSize: "0.85rem" }}>
        {result.reason}
      </p>
      <ol
        style={{
          fontSize: "0.78rem",
          color: "var(--ink-dim)",
          margin: 0,
          paddingLeft: "1.1rem",
        }}
      >
        {result.steps.map((s, i) => (
          <li key={i}>{s}</li>
        ))}
      </ol>
    </div>
  );
}
