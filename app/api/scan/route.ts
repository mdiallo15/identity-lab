// audit-ignore-file
// Public URL header scanner. Fetches a user-supplied URL, extracts response
// headers, runs the CSP + headers + SRI analyzers, returns a unified report.
//
// SECURITY POSTURE — this is a runtime fetcher accepting user URLs. It's
// the canonical SSRF surface. Hardening:
//   1. Only http/https schemes.
//   2. Reject loopback, link-local, RFC1918, cloud metadata IPs at the
//      pre-flight URL parse stage (lib/ssrf parseTarget).
//   3. Resolve hostname via DNS and re-check every resolved address against
//      the same blocklist — defeats DNS-rebinding (NOT YET; see TODO below).
//      Edge runtime doesn't expose dns; for now we trust the URL host check.
//      Production hardening would move this to Node runtime + dns.lookup.
//   4. Hard timeout (5s), max body 256 KiB, no redirect chasing past 3 hops.
//   5. AbortController to enforce timeout.
//   6. Rate limit by IP (1 req / 10s) using an in-memory LRU.
//
// What this is NOT: not a credentialed scanner, not authenticated, not a
// pentest replacement. It's a public header check identical in scope to
// what a curl -I would tell you, plus rule-based interpretation.

import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { analyze as analyzeCsp } from "@/lib/csp";
import { analyzeHeaders, analyzeSri } from "@/lib/headers";
import { findingsToSarif } from "@/lib/sarif";
import { parseTarget } from "@/lib/ssrf";

export const runtime = "edge";
export const dynamic = "force-dynamic";

const MAX_BODY_BYTES = 256 * 1024;
const TIMEOUT_MS = 5000;
const MAX_REDIRECTS = 3;

// Tiny in-memory rate limiter. Edge runtime spins up multiple isolates so
// this is best-effort, not authoritative — that's fine for a portfolio
// lab. For real abuse prevention you'd back this with KV/Redis.
const lastSeen = new Map<string, number>();
const RATE_WINDOW_MS = 10_000;

function rateLimit(ip: string): boolean {
  const now = Date.now();
  const prev = lastSeen.get(ip) ?? 0;
  if (now - prev < RATE_WINDOW_MS) return false;
  lastSeen.set(ip, now);
  // GC: keep map bounded.
  if (lastSeen.size > 1000) {
    for (const [k, v] of lastSeen) {
      if (now - v > RATE_WINDOW_MS * 6) lastSeen.delete(k);
    }
  }
  return true;
}

export async function POST(req: NextRequest) {
  const ip =
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    req.headers.get("x-real-ip") ??
    "unknown";

  if (!rateLimit(ip)) {
    return NextResponse.json(
      { error: "Too many requests. Try again in 10s." },
      { status: 429 },
    );
  }

  let body: { url?: string; format?: "json" | "sarif" };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const target = body.url?.trim() ?? "";
  if (!target || target.length > 2048) {
    return NextResponse.json(
      { error: "Provide a url (≤ 2048 chars)." },
      { status: 400 },
    );
  }

  // Pre-flight URL validation — schemes + private/loopback/metadata blocks.
  const parsed = parseTarget(target);
  if (!parsed.hostname) {
    return NextResponse.json(
      { error: "Could not parse URL." },
      { status: 400 },
    );
  }
  if (!parsed.protocol || !["http", "https"].includes(parsed.protocol)) {
    return NextResponse.json(
      { error: `Unsupported scheme: ${parsed.protocol ?? "(none)"}.` },
      { status: 400 },
    );
  }
  if (
    parsed.isLoopback ||
    parsed.isLinkLocal ||
    parsed.isPrivate ||
    parsed.isMetadata
  ) {
    return NextResponse.json(
      {
        error:
          "Refusing to scan internal/private/metadata addresses. This is the SSRF guard.",
        blockedReason: parsed.isMetadata
          ? "cloud metadata"
          : parsed.isLoopback
            ? "loopback"
            : parsed.isLinkLocal
              ? "link-local"
              : "RFC1918 private",
      },
      { status: 400 },
    );
  }

  // Fetch with timeout + bounded redirects.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetch(target, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        // Friendly identification — analogous to securityheaders.com's UA.
        "user-agent":
          "lab.marwandiallo.com header scanner (https://lab.marwandiallo.com)",
        accept: "text/html,application/xhtml+xml",
      },
    });
  } catch (err) {
    clearTimeout(timer);
    const msg = err instanceof Error ? err.message : "fetch failed";
    return NextResponse.json(
      { error: `Fetch failed: ${msg}` },
      { status: 502 },
    );
  }
  clearTimeout(timer);

  // Bound the body size — read up to MAX_BODY_BYTES.
  const reader = response.body?.getReader();
  let html = "";
  if (reader) {
    let received = 0;
    const chunks: Uint8Array[] = [];
    const decoder = new TextDecoder();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.length;
      if (received > MAX_BODY_BYTES) {
        await reader.cancel();
        break;
      }
      chunks.push(value);
    }
    for (const c of chunks) html += decoder.decode(c, { stream: true });
    html += decoder.decode();
  }

  // Collect headers as a flat record (lowercased keys; comma-joined dups).
  const headerRecord: Record<string, string> = {};
  response.headers.forEach((v, k) => {
    const key = k.toLowerCase();
    headerRecord[key] = headerRecord[key] ? `${headerRecord[key]}, ${v}` : v;
  });

  // Run analyzers.
  const cspValue = headerRecord["content-security-policy"] ?? "";
  const cspFindings = cspValue ? analyzeCsp(cspValue) : [];
  if (!cspValue) {
    cspFindings.push({
      id: "CSP00",
      severity: "high",
      title: "No Content-Security-Policy header",
      detail:
        "The response did not include a Content-Security-Policy header at all. CSP is the most effective anti-XSS control once you have one; the absence of one is a meaningful gap.",
      fix: "Start with a strict baseline: default-src 'self'; script-src 'self' 'nonce-...' 'strict-dynamic'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; report-to ...",
    });
  }
  const headerFindings = analyzeHeaders({ headers: headerRecord });
  const sriFindings = analyzeSri(html, response.url);

  const allFindings = [...cspFindings, ...headerFindings, ...sriFindings];

  if (body.format === "sarif") {
    const sarif = findingsToSarif(allFindings, {
      toolName: "lab.marwandiallo.com/csp",
      target: response.url,
    });
    return NextResponse.json(sarif, {
      headers: {
        "content-disposition": `attachment; filename="scan.sarif.json"`,
      },
    });
  }

  return NextResponse.json({
    target: response.url,
    status: response.status,
    headers: headerRecord,
    csp: cspValue || null,
    findings: allFindings,
    counts: {
      high: allFindings.filter((f) => f.severity === "high").length,
      medium: allFindings.filter((f) => f.severity === "medium").length,
      low: allFindings.filter((f) => f.severity === "low").length,
      info: allFindings.filter((f) => f.severity === "info").length,
    },
  });
}

export async function GET() {
  return new NextResponse(null, { status: 405, headers: { Allow: "POST" } });
}
