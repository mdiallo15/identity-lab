// audit-ignore-file
// Security-headers rule engine. Extends the CSP analyzer with rules for
// the surrounding security headers (HSTS, X-CTO, X-Frame-Options,
// Referrer-Policy, Permissions-Policy, COOP/COEP/CORP). Pure parser,
// no network. Findings share the same shape as lib/csp.ts so the UI
// and SARIF emitter can render both lists uniformly.
//
// Refs:
//   https://owasp.org/www-project-secure-headers/
//   https://web.dev/articles/coop-coep
//   RFC 6797 (HSTS), RFC 7034 (X-Frame-Options legacy)

import type { Finding, Severity } from "./csp";

export type { Finding, Severity };

export interface HeaderInput {
  // Lowercased header name -> raw value (single line). Multiple values
  // for the same header should be comma-joined by the caller.
  headers: Record<string, string>;
}

const has = (h: Record<string, string>, name: string) => h[name.toLowerCase()];

export function analyzeHeaders({ headers }: HeaderInput): Finding[] {
  const out: Finding[] = [];
  const h: Record<string, string> = {};
  for (const k of Object.keys(headers)) h[k.toLowerCase()] = headers[k];

  // HDR01: HSTS missing or weak
  const hsts = has(h, "strict-transport-security");
  if (!hsts) {
    out.push({
      id: "HDR01",
      severity: "high",
      title: "HSTS not set",
      detail:
        "Without Strict-Transport-Security, a single first request over HTTP exposes the user to SSL-strip downgrade attacks. HSTS pins the browser to HTTPS for max-age seconds.",
      fix: "Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload (and submit to hstspreload.org once you've validated all subdomains run HTTPS).",
    });
  } else {
    const maxAge = /max-age=(\d+)/i.exec(hsts)?.[1];
    if (!maxAge || Number(maxAge) < 15552000) {
      out.push({
        id: "HDR02",
        severity: "medium",
        title: "HSTS max-age too short",
        detail:
          "max-age below 6 months (15552000s) is below the HSTS preload list requirement. Browsers will accept it but you can't preload, so first-visit users remain exposed.",
        fix: "Set max-age to at least 31536000 (1 year); 63072000 (2 years) is standard for preload.",
      });
    }
    if (!/includesubdomains/i.test(hsts)) {
      out.push({
        id: "HDR03",
        severity: "medium",
        title: "HSTS missing includeSubDomains",
        detail:
          "Without includeSubDomains, a malicious http://anything.example.com that responds before HTTPS can poison cookies for the parent domain.",
        fix: "Append ; includeSubDomains to the HSTS header. Verify every subdomain serves HTTPS first.",
      });
    }
  }

  // HDR04: X-Content-Type-Options
  const xcto = has(h, "x-content-type-options");
  if (!xcto || xcto.trim().toLowerCase() !== "nosniff") {
    out.push({
      id: "HDR04",
      severity: "medium",
      title: "X-Content-Type-Options not nosniff",
      detail:
        "Without nosniff, browsers may MIME-sniff a response and execute it as a script even if Content-Type says otherwise. Classic uploads-folder XSS.",
      fix: "Add X-Content-Type-Options: nosniff to all responses.",
    });
  }

  // HDR05: X-Frame-Options OR CSP frame-ancestors
  const xfo = has(h, "x-frame-options");
  const csp = has(h, "content-security-policy") ?? "";
  const hasFA = /frame-ancestors\s/i.test(csp);
  if (!xfo && !hasFA) {
    out.push({
      id: "HDR05",
      severity: "medium",
      title: "No clickjacking protection",
      detail:
        "Neither X-Frame-Options nor CSP frame-ancestors is set. Any site can iframe yours and clickjack a logged-in session.",
      fix: "Set CSP frame-ancestors 'none' (modern) and optionally X-Frame-Options: DENY for legacy UAs.",
    });
  }

  // HDR06: Referrer-Policy
  const rp = has(h, "referrer-policy");
  if (!rp) {
    out.push({
      id: "HDR06",
      severity: "low",
      title: "Referrer-Policy not set",
      detail:
        "Without an explicit Referrer-Policy, browsers default to no-referrer-when-downgrade in most cases — full URLs (incl. paths and tokens in query strings) leak to outbound links.",
      fix: "Set Referrer-Policy: strict-origin-when-cross-origin (sane default) or no-referrer for high-privacy apps.",
    });
  } else {
    const v = rp.trim().toLowerCase();
    if (v === "unsafe-url" || v === "no-referrer-when-downgrade") {
      out.push({
        id: "HDR07",
        severity: "low",
        title: `Weak Referrer-Policy: ${v}`,
        detail:
          "This policy still leaks the full URL on cross-origin navigations. Tokens or PII in query strings will land in third-party logs.",
        fix: "Use strict-origin-when-cross-origin (recommended) or no-referrer.",
      });
    }
  }

  // HDR08: Permissions-Policy
  const pp = has(h, "permissions-policy");
  if (!pp) {
    out.push({
      id: "HDR08",
      severity: "low",
      title: "Permissions-Policy not set",
      detail:
        "Without Permissions-Policy, every iframe inherits access to camera, microphone, geolocation, payment, etc. Scope-of-blast-radius issue when you embed third-party widgets.",
      fix: "Set Permissions-Policy disabling everything you don't use, e.g. camera=(), microphone=(), geolocation=(), payment=(), usb=().",
    });
  }

  // HDR09: COOP — protects from cross-origin window references
  const coop = has(h, "cross-origin-opener-policy");
  if (!coop) {
    out.push({
      id: "HDR09",
      severity: "low",
      title: "Cross-Origin-Opener-Policy not set",
      detail:
        "Without COOP, a cross-origin window.opener or popup can reference your global object, defeating Spectre-class isolation and enabling some tabnabbing variants.",
      fix: "Set Cross-Origin-Opener-Policy: same-origin (or same-origin-allow-popups if you need OAuth popups).",
    });
  }

  // HDR10: COEP — only enforce if COOP is set (it's the gateway to crossOriginIsolated)
  const coep = has(h, "cross-origin-embedder-policy");
  if (coop && coop.includes("same-origin") && !coep) {
    out.push({
      id: "HDR10",
      severity: "info",
      title: "COOP set but COEP missing — no crossOriginIsolated context",
      detail:
        "You've set COOP but not COEP, so the page never enters a crossOriginIsolated context. SharedArrayBuffer and high-resolution timers stay disabled.",
      fix: "If you need SharedArrayBuffer/Wasm threads/precise timers, add Cross-Origin-Embedder-Policy: require-corp and ensure all subresources serve CORP or CORS.",
    });
  }

  // HDR11: Server / X-Powered-By fingerprinting
  const server = has(h, "server");
  const xpb = has(h, "x-powered-by");
  if (server && /[\d.]/.test(server)) {
    out.push({
      id: "HDR11",
      severity: "info",
      title: `Server header leaks version: ${server}`,
      detail:
        "Version banners help attackers map vulnerabilities to your stack. Low impact on its own; combine with HTTPS and you've helped them skip recon.",
      fix: "Strip or generic-ize the Server header at the proxy/CDN layer.",
    });
  }
  if (xpb) {
    out.push({
      id: "HDR12",
      severity: "info",
      title: `X-Powered-By header present: ${xpb}`,
      detail:
        "Tells attackers exactly which framework version is running. Should be off in production.",
      fix: "Remove X-Powered-By. In Next.js: poweredByHeader: false in next.config.",
    });
  }

  return out.sort(
    (a, b) =>
      sevRank(a.severity) - sevRank(b.severity) || a.id.localeCompare(b.id),
  );
}

function sevRank(s: Severity): number {
  return s === "high" ? 0 : s === "medium" ? 1 : s === "low" ? 2 : 3;
}

// Subresource Integrity check — given an HTML body, look for cross-origin
// <script src="..."> tags without integrity= attribute. Pure regex-based,
// not a full HTML parser, but accurate enough for portfolio scanning.
export function analyzeSri(html: string, pageOrigin: string): Finding[] {
  const out: Finding[] = [];
  const tagRe = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let m: RegExpExecArray | null;
  let pageHost = "";
  try {
    pageHost = new URL(pageOrigin).host;
  } catch {
    return out;
  }
  while ((m = tagRe.exec(html)) !== null) {
    const src = m[1];
    let abs: URL;
    try {
      abs = new URL(src, pageOrigin);
    } catch {
      continue;
    }
    if (abs.host === pageHost) continue; // same-origin scripts don't need SRI
    if (!/integrity\s*=/i.test(m[0])) {
      out.push({
        id: "SRI01",
        severity: "low",
        title: `Cross-origin <script> without integrity: ${abs.host}`,
        detail:
          "If a third-party CDN is compromised (or replaces a versioned file), it can inject arbitrary JS into your page. Subresource Integrity locks the response to a known hash.",
        fix: `Add an integrity="sha384-..." attribute (and crossorigin="anonymous") to the <script> tag for ${abs.href}. Most CDN docs publish ready-made SRI hashes.`,
      });
    }
  }
  return out;
}
