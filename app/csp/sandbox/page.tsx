"use client";

import { useMemo, useRef, useState } from "react";
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
 * CSP via <meta http-equiv>. Note: we deliberately do NOT inject the
 * violation reporter or theme styles inside this document, because a strict
 * CSP (nonce-only, no 'unsafe-inline') would block them and the user would
 * see a blank iframe with no events — the very thing this sandbox is
 * supposed to demonstrate. Instead, the parent attaches a
 * securitypolicyviolation listener directly on the iframe's contentDocument
 * (requires sandbox="... allow-same-origin") and applies a dark theme via
 * adoptedStyleSheets, which is exempt from style-src per CSP3 spec.
 *
 * Caveats: <meta http-equiv> CSP cannot enforce frame-ancestors, sandbox, or
 * report-uri/report-to (per spec). The console mirror is our substitute for
 * report-uri.
 */
function buildSrcDoc(csp: string, payload: string): string {
  const safeCsp = csp.replace(/[\r\n]+/g, " ");
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="${escapeHtml(safeCsp)}">
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
  const iframeRef = useRef<HTMLIFrameElement | null>(null);

  const findings: Finding[] = useMemo(() => analyze(csp), [csp]);

  function pushEntry(type: ConsoleEntry["type"], detail: unknown) {
    counterRef.current += 1;
    setConsoleLog((prev) =>
      [
        ...prev,
        {
          id: counterRef.current,
          type,
          detail,
          t: Date.now(),
        },
      ].slice(-100),
    );
  }

  // Attach SecurityPolicyViolationEvent + error listeners directly on the
  // iframe's contentDocument from the parent. This bypasses the iframe's own
  // CSP for the observer code, so even a 'default-src none' policy won't
  // silence the violation feed. Requires the iframe sandbox to include
  // allow-same-origin.
  function onIframeLoad() {
    const iframe = iframeRef.current;
    if (!iframe) return;
    const doc = iframe.contentDocument;
    const win = iframe.contentWindow;
    if (!doc || !win) return;

    pushEntry("boot", { ua: win.navigator.userAgent.slice(0, 80) });

    doc.addEventListener(
      "securitypolicyviolation",
      (e: SecurityPolicyViolationEvent) => {
        pushEntry("violation", {
          violatedDirective: e.violatedDirective,
          effectiveDirective: e.effectiveDirective,
          blockedURI: e.blockedURI,
          sourceFile: e.sourceFile,
          lineNumber: e.lineNumber,
          sample: (e.sample || "").slice(0, 200),
        });
      },
    );

    win.addEventListener("error", (e: ErrorEvent) => {
      pushEntry("error", {
        message: e.message,
        source: e.filename,
        line: e.lineno,
      });
    });

    // Apply a dark theme via adoptedStyleSheets — exempt from style-src per
    // CSP3 spec, so it works even under a nonce-only policy. Falls back to a
    // <link> attempt would defeat the purpose; if adoptedStyleSheets isn't
    // supported (very old browsers) the iframe will just render with default
    // browser colors, which is acceptable.
    try {
      type DocWithSheets = Document & {
        adoptedStyleSheets: CSSStyleSheet[];
      };
      const SheetCtor = (
        win as Window & {
          CSSStyleSheet?: typeof CSSStyleSheet;
        }
      ).CSSStyleSheet;
      if (SheetCtor && "replaceSync" in SheetCtor.prototype) {
        const sheet = new SheetCtor();
        sheet.replaceSync(`
          body { font: 14px/1.55 ui-sans-serif, system-ui, sans-serif; color: #ededed; background: #0a0a0a; padding: 1rem; margin: 0; }
          h1, h2, h3 { font-weight: 600; margin: 0 0 0.7rem; color: #ededed; }
          h2 { font-size: 0.95rem; }
          p { margin: 0.45rem 0; color: #c8c8c8; }
          code, pre { font-family: ui-monospace, monospace; font-size: 0.82rem; color: #ededed; background: #161616; padding: 0.1rem 0.3rem; border-radius: 2px; }
          pre { padding: 0.6rem 0.8rem; overflow-x: auto; }
          img { max-width: 100%; }
          a { color: #66d9ef; }
        `);
        (doc as DocWithSheets).adoptedStyleSheets = [sheet];
      }
    } catch {
      /* fall back to default styling */
    }
  }

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
      <h2
        ref={sandboxRef}
        style={{ marginTop: "1.6rem", scrollMarginTop: "0.8rem" }}
      >
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
            ref={iframeRef}
            key={iframeKey}
            title="CSP sandbox"
            srcDoc={srcDoc}
            // allow-same-origin lets the parent attach the violation listener
            // directly on contentDocument, bypassing the user's CSP for the
            // reporter (we don't want a strict CSP to silence the very tool
            // observing it). The iframe still cannot reach the parent because
            // it's sandboxed and meta-CSP keeps payload-loaded resources
            // confined.
            sandbox="allow-scripts allow-forms allow-same-origin"
            onLoad={onIframeLoad}
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
