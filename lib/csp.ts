// audit-ignore-file
// This module describes dangerous CSP patterns (eval, unsafe-inline, etc.) in
// rule text. The audit tool flags occurrences of those keywords; that's the
// whole point of this file. Suppression is intentional and scoped.
//
// Pure CSP parser + rule engine. No deps. Runs client-side.

export type Severity = "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  fix: string;
  directive?: string;
}

export interface ParsedCsp {
  directives: Record<string, string[]>;
  raw: string;
}

const FETCH_DIRECTIVES = new Set([
  "default-src",
  "script-src",
  "script-src-elem",
  "script-src-attr",
  "style-src",
  "style-src-elem",
  "style-src-attr",
  "img-src",
  "connect-src",
  "font-src",
  "media-src",
  "object-src",
  "frame-src",
  "child-src",
  "worker-src",
  "manifest-src",
  "prefetch-src",
]);

export function parseCsp(input: string): ParsedCsp {
  const directives: Record<string, string[]> = {};
  for (const piece of input.split(";")) {
    const trimmed = piece.trim();
    if (!trimmed) continue;
    const tokens = trimmed.split(/\s+/);
    const name = (tokens.shift() ?? "").toLowerCase();
    if (!name) continue;
    directives[name] = tokens;
  }
  return { directives, raw: input };
}

function effectiveScriptSrc(d: Record<string, string[]>): string[] | undefined {
  return d["script-src"] ?? d["default-src"];
}
function effectiveStyleSrc(d: Record<string, string[]>): string[] | undefined {
  return d["style-src"] ?? d["default-src"];
}

function hasNonceOrHash(values: string[]): boolean {
  return values.some(
    (v) =>
      v.startsWith("'nonce-") ||
      v.startsWith("'sha256-") ||
      v.startsWith("'sha384-") ||
      v.startsWith("'sha512-"),
  );
}

function hasStrictDynamic(values: string[]): boolean {
  return values.includes("'strict-dynamic'");
}

export function analyze(csp: string): Finding[] {
  const findings: Finding[] = [];
  const { directives: d } = parseCsp(csp);

  if (!csp.trim()) return findings;

  // CSP01: missing default-src and missing script-src
  if (!d["script-src"] && !d["default-src"]) {
    findings.push({
      id: "CSP01",
      severity: "high",
      title: "No script-src or default-src",
      directive: "script-src",
      detail:
        "With no script-src and no default-src, browsers fall back to allowing all scripts.",
      fix: "Add at minimum default-src 'self', or an explicit script-src.",
    });
  }

  // CSP02: 'unsafe-inline' on script-src (without nonce/hash AND strict-dynamic)
  const scriptSrc = effectiveScriptSrc(d);
  if (scriptSrc?.includes("'unsafe-inline'")) {
    const safeguarded =
      hasStrictDynamic(scriptSrc) && hasNonceOrHash(scriptSrc);
    if (!safeguarded) {
      findings.push({
        id: "CSP02",
        severity: "high",
        title: "'unsafe-inline' on script-src",
        directive: "script-src",
        detail:
          "'unsafe-inline' allows inline <script> blocks and event-handler attributes — the vast majority of XSS payloads. It defeats most of CSP's purpose.",
        fix: "Replace inline scripts with nonce-CSP (nonce-* + 'strict-dynamic') or hashes. The nonce approach is what frameworks like Next.js generate at request time.",
      });
    }
  }

  // CSP03: 'unsafe-eval' on script-src
  if (scriptSrc?.includes("'unsafe-eval'")) {
    findings.push({
      id: "CSP03",
      severity: "medium",
      title: "'unsafe-eval' on script-src",
      directive: "script-src",
      detail:
        "Allows eval(), new Function(), and similar string-to-code primitives. Some bundlers and AngularJS still rely on this; modern frameworks do not.",
      fix: "Audit whether your build still emits eval (Webpack devtool, AngularJS templates). For prod, switch to source maps that don't require eval and remove this token.",
    });
  }

  // CSP04: wildcard host in script-src
  if (
    scriptSrc?.some((v) => v === "*" || /^https?:\/\/\*$/.test(v) || v === "https:" || v === "http:")
  ) {
    findings.push({
      id: "CSP04",
      severity: "high",
      title: "Wildcard or scheme-only source in script-src",
      directive: "script-src",
      detail:
        "* and bare scheme sources (https:, http:) defeat CSP's allowlist by trusting the entire web.",
      fix: "Use 'self', explicit hosts, or a nonce-based policy with 'strict-dynamic'.",
    });
  }

  // CSP05: data: in script-src
  if (scriptSrc?.includes("data:")) {
    findings.push({
      id: "CSP05",
      severity: "high",
      title: "data: scheme in script-src",
      directive: "script-src",
      detail:
        "data: URIs let an attacker inline arbitrary script via base64. Direct XSS bypass.",
      fix: "Remove data: from script-src. Use a nonce-based policy.",
    });
  }

  // CSP06: object-src not locked down
  if (!d["object-src"]) {
    const def = d["default-src"];
    if (!def || !def.includes("'none'")) {
      findings.push({
        id: "CSP06",
        severity: "medium",
        title: "object-src not set to 'none'",
        directive: "object-src",
        detail:
          "<object>, <embed>, and <applet> can load Flash and PDF plugins that historically have been XSS surfaces. Modern apps almost never need them.",
        fix: "Add object-src 'none' explicitly.",
      });
    }
  } else if (!d["object-src"].includes("'none'")) {
    findings.push({
      id: "CSP06",
      severity: "low",
      title: "object-src is set but allows sources",
      directive: "object-src",
      detail: "Unless you actually need <object>/<embed>, lock this down.",
      fix: "object-src 'none'",
    });
  }

  // CSP07: base-uri not locked down (dangling-markup mitigation)
  if (!d["base-uri"]) {
    findings.push({
      id: "CSP07",
      severity: "medium",
      title: "base-uri not set",
      directive: "base-uri",
      detail:
        "Without base-uri, an XSS that injects <base href> can rewrite all relative URLs on the page to attacker-controlled origins (the dangling-markup attack).",
      fix: "Add base-uri 'self' or base-uri 'none'.",
    });
  }

  // CSP08: frame-ancestors not set (clickjacking)
  if (!d["frame-ancestors"]) {
    findings.push({
      id: "CSP08",
      severity: "medium",
      title: "frame-ancestors not set",
      directive: "frame-ancestors",
      detail:
        "frame-ancestors is the modern replacement for X-Frame-Options. Without it, anyone can embed your app in an iframe and clickjack.",
      fix: "Add frame-ancestors 'none' (or 'self' if you self-frame).",
    });
  }

  // CSP09: form-action not set
  if (!d["form-action"]) {
    findings.push({
      id: "CSP09",
      severity: "low",
      title: "form-action not set",
      directive: "form-action",
      detail:
        "Without form-action, an injected <form> can post credentials to attacker-controlled origins.",
      fix: "Add form-action 'self' to restrict where forms can submit.",
    });
  }

  // CSP10: 'unsafe-inline' on style-src (without nonce/hash)
  const styleSrc = effectiveStyleSrc(d);
  if (styleSrc?.includes("'unsafe-inline'") && !hasNonceOrHash(styleSrc)) {
    findings.push({
      id: "CSP10",
      severity: "low",
      title: "'unsafe-inline' on style-src",
      directive: "style-src",
      detail:
        "Less dangerous than on scripts but still enables CSS-based data exfiltration (font ligatures, attribute selectors, scrollbar tricks).",
      fix: "Use nonces for style as well, or move to a CSS-in-JS solution that emits with the same nonce.",
    });
  }

  // CSP11: no reporting
  if (!d["report-uri"] && !d["report-to"]) {
    findings.push({
      id: "CSP11",
      severity: "low",
      title: "No CSP reporting configured",
      detail:
        "Without report-uri or report-to, CSP violations happen silently. You won't see in-the-wild XSS attempts or accidental policy breakage.",
      fix: "Add a report-to endpoint (modern) or report-uri (legacy). Even logging to your own server is a huge upgrade.",
    });
  }

  // CSP12: upgrade-insecure-requests not set on http+https mixed contexts
  if (!d["upgrade-insecure-requests"]) {
    findings.push({
      id: "CSP12",
      severity: "info",
      title: "upgrade-insecure-requests not set",
      detail:
        "Optional. If your app may load from a mix of http:// and https:// origins, this directive auto-upgrades requests, blocking mixed content.",
      fix: "Add upgrade-insecure-requests if you serve over HTTPS and may have legacy http:// references.",
    });
  }

  return findings.sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
}

function sevRank(s: Severity): number {
  return s === "high" ? 0 : s === "medium" ? 1 : s === "low" ? 2 : 3;
}
