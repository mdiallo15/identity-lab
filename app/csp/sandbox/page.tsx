"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  SCENARIOS,
  HARDENED_STARTER,
  type Scenario,
} from "@/lib/csp-scenarios";
import { analyze, type Finding } from "@/lib/csp";

/* ---------------------------------------------------------------------- */
/*  Sandbox iframe srcdoc builder                                         */
/* ---------------------------------------------------------------------- */

/**
 * Build a complete HTML document for the sandbox iframe. Embeds the user's
 * CSP via <meta http-equiv> and wires a SecurityPolicyViolationEvent listener
 * that postMessages every violation back to the parent window.
 *
 * Caveats: <meta http-equiv> CSP cannot enforce frame-ancestors, sandbox, or
 * report-uri/report-to (per spec). The console mirror is our substitute for
 * report-uri.
 */
function buildSrcDoc(csp: string, payload: string): string {
  const safeCsp = csp.replace(/[\r\n]+/g, " ");
  // The reporter script must run before any other script so it can catch
  // violations from later scripts in the same document. It uses the nonce
  // 'SANDBOX' which the user's CSP must allow if they want their own scripts
  // to coexist with the reporter.
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="${escapeHtml(safeCsp)}">
  <style>
    body { font: 14px/1.55 ui-sans-serif, system-ui, sans-serif; color: #ededed; background: #0a0a0a; padding: 1rem; margin: 0; }
    h2 { font-size: 0.95rem; font-weight: 600; margin: 0 0 0.7rem; color: #ededed; }
    p { margin: 0.45rem 0; color: #c8c8c8; }
    code, pre { font-family: ui-monospace, monospace; font-size: 0.82rem; color: #ededed; background: #161616; padding: 0.1rem 0.3rem; border-radius: 2px; }
    pre { padding: 0.6rem 0.8rem; overflow-x: auto; }
    img { max-width: 100%; }
    a { color: #66d9ef; }
  </style>
  <script>
    (function () {
      function send(type, detail) {
        try {
          parent.postMessage({ __cspsandbox: true, type: type, detail: detail, t: Date.now() }, '*');
        } catch (e) { /* swallow */ }
      }
      document.addEventListener('securitypolicyviolation', function (e) {
        send('violation', {
          violatedDirective: e.violatedDirective,
          effectiveDirective: e.effectiveDirective,
          blockedURI: e.blockedURI,
          sourceFile: e.sourceFile,
          lineNumber: e.lineNumber,
          sample: (e.sample || '').slice(0, 200)
        });
      });
      window.addEventListener('error', function (e) {
        send('error', { message: e.message, source: e.filename, line: e.lineno });
      });
      send('boot', { ua: navigator.userAgent.slice(0, 80) });
    })();
  </script>
</head>
<body>
${payload}
</body>
</html>`;
}

function escapeHtml(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

/* ---------------------------------------------------------------------- */
/*  Console mirror message types                                          */
/* ---------------------------------------------------------------------- */

interface SandboxMessage {
  __cspsandbox: true;
  type: "boot" | "violation" | "error";
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  detail: any;
  t: number;
}

interface ConsoleEntry {
  id: number;
  type: "boot" | "violation" | "error";
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  detail: any;
  t: number;
}

/* ---------------------------------------------------------------------- */
/*  Main page                                                             */
/* ---------------------------------------------------------------------- */

export default function Sandbox() {
  const [csp, setCsp] = useState<string>(HARDENED_STARTER);
  const [payload, setPayload] = useState<string>(SCENARIOS[0].payload);
  const [activeScenarioId, setActiveScenarioId] = useState<string>(
    SCENARIOS[0].id,
  );
  const [iframeKey, setIframeKey] = useState(0);
  const [consoleLog, setConsoleLog] = useState<ConsoleEntry[]>([]);
  const counterRef = useRef(0);
  const sandboxRef = useRef<HTMLDivElement | null>(null);

  const findings: Finding[] = useMemo(() => analyze(csp), [csp]);

  // Listen for violation messages from the sandbox iframe
  useEffect(() => {
    function onMessage(ev: MessageEvent) {
      const data = ev.data as SandboxMessage | undefined;
      if (!data || data.__cspsandbox !== true) return;
      counterRef.current += 1;
      setConsoleLog((prev) =>
        [
          ...prev,
          {
            id: counterRef.current,
            type: data.type,
            detail: data.detail,
            t: data.t,
          },
        ].slice(-100),
      );
    }
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, []);

  function loadScenario(s: Scenario) {
    setActiveScenarioId(s.id);
    setCsp(s.csp);
    setPayload(s.payload);
    setConsoleLog([]);
    setIframeKey((k) => k + 1);
    // Scroll the live iframe into view so the user sees the result
    // immediately rather than scrolling down to find it.
    requestAnimationFrame(() => {
      sandboxRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    });
  }

  function rerun() {
    setConsoleLog([]);
    setIframeKey((k) => k + 1);
  }

  function clearConsole() {
    setConsoleLog([]);
  }

  function loadHardened() {
    setCsp(HARDENED_STARTER);
    setActiveScenarioId("");
  }

  const srcDoc = useMemo(() => buildSrcDoc(csp, payload), [csp, payload]);
  const activeScenario = SCENARIOS.find((s) => s.id === activeScenarioId);

  return (
    <>
      <h1>Sandbox</h1>
      <p className="lede">
        A real iframe enforcing the CSP you write, with every violation piped
        back into the console mirror. Pick a scenario from the catalog to load a
        preset, or paste your own header and payload.
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
        <strong>How this works.</strong> The iframe document carries your CSP
        via <code>&lt;meta http-equiv&gt;</code>, plus a tiny reporter that
        forwards every <code>SecurityPolicyViolationEvent</code> into the
        console mirror below. Limitations of meta-CSP:{" "}
        <code>frame-ancestors</code>, <code>sandbox</code>, and{" "}
        <code>report-to</code> are header-only and won&apos;t fire here.
        Everything else does.
      </div>

      {/* ------------------ Scenario catalog ------------------ */}
      <h2 style={{ marginTop: "1.6rem" }}>Scenario catalog</h2>
      <p style={{ color: "var(--ink-dim)", fontSize: "0.88rem" }}>
        Ten paired CSP + payload demos. Each loads its own header into the
        editor and re-renders the iframe. Watch the console for violations and
        compare against the &quot;expected&quot; line.
      </p>
      <div className="csp-scenarios">
        {SCENARIOS.map((s) => (
          <button
            key={s.id}
            onClick={() => loadScenario(s)}
            data-active={s.id === activeScenarioId}
            className="csp-scenario-card"
            type="button"
          >
            <span className="csp-scenario-cat">{s.category}</span>
            <span className="csp-scenario-title">{s.title}</span>
          </button>
        ))}
      </div>

      {activeScenario && (
        <div className="csp-scenario-detail">
          <p>
            <strong>Expected:</strong> {activeScenario.expected}
          </p>
          <p>
            <strong>Lesson:</strong> {activeScenario.lesson}
          </p>
          {activeScenario.standards && (
            <p style={{ fontSize: "0.78rem", color: "var(--ink-dim)" }}>
              <strong>standards:</strong> {activeScenario.standards.join(" · ")}
            </p>
          )}
        </div>
      )}

      {/* ------------------ Live sandbox + console (moved up) ------ */}
      <h2 ref={sandboxRef} style={{ marginTop: "1.6rem", scrollMarginTop: "0.8rem" }}>
        Live sandbox
      </h2>
      <div className="csp-sandbox-grid">
        <div className="csp-sandbox-frame">
          <div className="csp-sandbox-frame-bar">
            <span style={{ fontSize: "0.72rem", color: "var(--ink-dim)" }}>
              iframe — meta-CSP enforced
            </span>
            <button
              type="button"
              onClick={rerun}
              style={{
                background: "transparent",
                color: "var(--accent)",
                border: "1px solid var(--rule)",
                padding: "0.2rem 0.55rem",
                fontSize: "0.72rem",
              }}
            >
              ↻ reload
            </button>
          </div>
          <iframe
            key={iframeKey}
            title="CSP sandbox"
            srcDoc={srcDoc}
            // sandbox attribute deliberately permissive: we want scripts to
            // run so the CSP itself can be observed enforcing or not.
            sandbox="allow-scripts allow-forms"
            style={{
              width: "100%",
              height: 360,
              border: "0",
              background: "#0a0a0a",
            }}
          />
        </div>

        <div className="csp-sandbox-console">
          <div className="csp-sandbox-frame-bar">
            <span style={{ fontSize: "0.72rem", color: "var(--ink-dim)" }}>
              violations &amp; errors ({consoleLog.length})
            </span>
            <button
              type="button"
              onClick={clearConsole}
              style={{
                background: "transparent",
                color: "var(--accent)",
                border: "1px solid var(--rule)",
                padding: "0.2rem 0.55rem",
                fontSize: "0.72rem",
              }}
            >
              clear
            </button>
          </div>
          <div className="csp-sandbox-console-body">
            {consoleLog.length === 0 && (
              <div
                style={{
                  fontSize: "0.78rem",
                  color: "var(--ink-dim)",
                  padding: "0.6rem",
                }}
              >
                No events yet. Re-run or load a scenario.
              </div>
            )}
            {consoleLog.map((entry) => (
              <ConsoleLine key={entry.id} entry={entry} />
            ))}
          </div>
        </div>
      </div>

      {/* ------------------ Editor (moved below sandbox) ----------- */}
      <h2 style={{ marginTop: "1.6rem" }}>Editor</h2>
      <p style={{ color: "var(--ink-dim)", fontSize: "0.88rem", marginTop: 0 }}>
        Edit the policy or the payload, then hit <strong>Re-run</strong> to
        reload the iframe above.
      </p>
      <div className="row" style={{ gap: "0.4rem", marginBottom: "0.5rem" }}>
        <button
          type="button"
          onClick={loadHardened}
          style={{
            background: "transparent",
            color: "var(--ink-dim)",
            border: "1px solid var(--rule)",
            padding: "0.35rem 0.7rem",
            fontSize: "0.78rem",
          }}
        >
          Reset to hardened CSP
        </button>
        <button
          type="button"
          onClick={rerun}
          style={{
            background: "var(--ink)",
            color: "var(--bg)",
            border: "1px solid var(--ink)",
            padding: "0.35rem 0.9rem",
            fontSize: "0.78rem",
            fontWeight: 600,
          }}
        >
          Re-run
        </button>
      </div>

      <label
        htmlFor="csp-input"
        style={{
          display: "block",
          fontSize: "0.78rem",
          color: "var(--ink-dim)",
          marginTop: "0.6rem",
        }}
      >
        Content-Security-Policy header
      </label>
      <textarea
        id="csp-input"
        value={csp}
        onChange={(e) => setCsp(e.target.value)}
        spellCheck={false}
        style={{ minHeight: 80, marginTop: "0.3rem" }}
      />

      <label
        htmlFor="payload-input"
        style={{
          display: "block",
          fontSize: "0.78rem",
          color: "var(--ink-dim)",
          marginTop: "0.8rem",
        }}
      >
        HTML payload (rendered in the sandbox iframe)
      </label>
      <textarea
        id="payload-input"
        value={payload}
        onChange={(e) => setPayload(e.target.value)}
        spellCheck={false}
        style={{ minHeight: 140, marginTop: "0.3rem" }}
      />

      {/* ------------------ Static-analysis findings ------------------ */}
      <h2 style={{ marginTop: "1.6rem" }}>
        Static analysis ({findings.length})
      </h2>
      <p style={{ color: "var(--ink-dim)", fontSize: "0.88rem" }}>
        Same 12-rule grader as the analyzer page, run live against the policy in
        the editor.
      </p>
      <div className="findings">
        {findings.length === 0 && (
          <span className="status ok">No findings.</span>
        )}
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
    </>
  );
}

/* ---------------------------------------------------------------------- */

function ConsoleLine({ entry }: { entry: ConsoleEntry }) {
  if (entry.type === "boot") {
    return (
      <div className="csp-console-line boot">
        <span className="csp-console-tag">boot</span>
        <span>iframe loaded</span>
      </div>
    );
  }
  if (entry.type === "violation") {
    const d = entry.detail;
    return (
      <div className="csp-console-line violation">
        <span className="csp-console-tag violation">violation</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <code>{d.violatedDirective || d.effectiveDirective}</code> blocked{" "}
          <code style={{ wordBreak: "break-all" }}>
            {d.blockedURI || "inline"}
          </code>
          {d.sample && (
            <div
              style={{
                marginTop: "0.2rem",
                fontSize: "0.72rem",
                color: "var(--ink-dim)",
                wordBreak: "break-all",
              }}
            >
              sample: <code>{d.sample}</code>
            </div>
          )}
        </div>
      </div>
    );
  }
  // error
  return (
    <div className="csp-console-line error">
      <span className="csp-console-tag error">error</span>
      <code>{entry.detail.message}</code>
    </div>
  );
}
