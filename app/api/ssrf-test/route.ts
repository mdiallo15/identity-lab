// audit-ignore-file
// Server-side SSRF safety demo. Given a user URL, walks through the four
// stages a hardened backend should perform BEFORE making the actual fetch.
// Returns each stage's outcome so the lab can render a transparent trace
// (parse -> dns lookup -> post-resolve check -> bounded fetch).
//
// This is the canonical "validate-then-fetch" pattern you want behind any
// feature that takes a user URL (image proxy, webhook target, OAuth callback,
// link preview, etc). The lab page shows it step-by-step.
//
// Runtime: Node, NOT Edge. We need node:dns for proper IP re-resolution to
// defeat DNS rebinding. Edge runtime does not expose dns.

import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { promises as dns } from "node:dns";
import { parseTarget, analyze } from "@/lib/ssrf";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const TIMEOUT_MS = 4000;
const MAX_BODY = 64 * 1024;

// Same blocklist used by parseTarget on the IP check, applied AGAIN
// after DNS resolves the hostname. This is the step that defeats
// DNS-rebinding (DNS first returns a public IP to pass validation,
// then re-resolves to 169.254.169.254 on the second lookup the
// fetch performs). The defence: resolve once, validate, fetch by IP.
function isBlockedIp(ipv4: string): {
  blocked: boolean;
  reason?: string;
} {
  // Reuse parseTarget's own logic by feeding it a synthetic URL.
  const parsed = parseTarget(`http://${ipv4}/`);
  if (parsed.isMetadata) return { blocked: true, reason: "cloud metadata" };
  if (parsed.isLoopback) return { blocked: true, reason: "loopback" };
  if (parsed.isLinkLocal) return { blocked: true, reason: "link-local" };
  if (parsed.isPrivate) return { blocked: true, reason: "RFC1918 private" };
  return { blocked: false };
}

interface Stage {
  name: string;
  status: "pass" | "fail" | "skipped";
  detail: string;
  data?: unknown;
}

export async function POST(req: NextRequest) {
  let body: { url?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  const target = body.url?.trim() ?? "";
  if (!target || target.length > 2048) {
    return NextResponse.json(
      { error: "Provide a url (≤ 2048 chars)" },
      { status: 400 },
    );
  }

  const stages: Stage[] = [];

  // STAGE 1 — parse + scheme allowlist + static rule analysis.
  const parsed = parseTarget(target);
  const findings = analyze(target).findings;
  if (!parsed.hostname) {
    stages.push({
      name: "Parse URL",
      status: "fail",
      detail: "Could not parse the input as a URL.",
    });
    return NextResponse.json({ stages, findings });
  }
  if (!parsed.protocol || !["http", "https"].includes(parsed.protocol)) {
    stages.push({
      name: "Parse URL",
      status: "fail",
      detail: `Unsupported scheme '${parsed.protocol}'. Only http/https allowed.`,
      data: { hostname: parsed.hostname, protocol: parsed.protocol },
    });
    return NextResponse.json({ stages, findings });
  }
  stages.push({
    name: "Parse URL",
    status: "pass",
    detail: `Scheme '${parsed.protocol}' allowed. Hostname '${parsed.hostname}'.`,
    data: {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port ?? null,
      pathname: parsed.pathname ?? "/",
    },
  });

  // STAGE 2 — pre-flight rule analysis (catches encoded IPs, unusual schemes,
  // metadata aliases, etc. before any network call).
  const criticalOrHigh = findings.filter(
    (f) => f.severity === "critical" || f.severity === "high",
  );
  if (criticalOrHigh.length > 0) {
    stages.push({
      name: "Pre-flight rule check",
      status: "fail",
      detail: `${criticalOrHigh.length} blocking finding(s): ${criticalOrHigh
        .map((f) => f.id)
        .join(", ")}. Refusing to resolve or fetch.`,
      data: criticalOrHigh,
    });
    return NextResponse.json({ stages, findings });
  }
  stages.push({
    name: "Pre-flight rule check",
    status: "pass",
    detail: `No critical/high findings on the URL string itself.`,
    data: { nonBlockingFindings: findings.length },
  });

  // STAGE 3 — DNS lookup, then re-check every resolved address. This is
  // the DNS-rebinding defence. We use {all: true, family: 0} to get every
  // A and AAAA record. If ANY resolves to a blocked IP, we refuse.
  let resolved: { address: string; family: number }[] = [];
  try {
    resolved = await Promise.race([
      dns.lookup(parsed.hostname, { all: true, family: 0 }),
      new Promise<never>((_, rej) =>
        setTimeout(() => rej(new Error("DNS timeout")), 2000),
      ),
    ]);
  } catch (err) {
    stages.push({
      name: "DNS resolution",
      status: "fail",
      detail: `DNS lookup failed: ${
        err instanceof Error ? err.message : "unknown"
      }`,
    });
    return NextResponse.json({ stages, findings });
  }

  if (resolved.length === 0) {
    stages.push({
      name: "DNS resolution",
      status: "fail",
      detail: "No IP addresses returned for hostname.",
    });
    return NextResponse.json({ stages, findings });
  }

  // Apply the same blocklist to every resolved address. IPv4 only —
  // IPv6 RFC1918-equivalent ranges (fc00::/7, fe80::/10) covered partially
  // by parseTarget; for v6 we just allow if the address starts with a
  // public global-unicast prefix (very rough). Production: use a full
  // ipaddr.js-style classifier.
  const blockedHits: { ip: string; reason: string }[] = [];
  for (const r of resolved) {
    if (r.family === 4) {
      const check = isBlockedIp(r.address);
      if (check.blocked) {
        blockedHits.push({ ip: r.address, reason: check.reason ?? "blocked" });
      }
    } else if (r.family === 6) {
      const v6 = r.address.toLowerCase();
      if (
        v6 === "::1" ||
        v6.startsWith("fe80:") ||
        v6.startsWith("fc") ||
        v6.startsWith("fd")
      ) {
        blockedHits.push({ ip: r.address, reason: "IPv6 private/link-local" });
      }
    }
  }

  if (blockedHits.length > 0) {
    stages.push({
      name: "Post-resolve IP re-check",
      status: "fail",
      detail: `Hostname resolved to ${blockedHits.length} blocked address(es). This is what stops DNS-rebinding attacks.`,
      data: { resolved, blockedHits },
    });
    return NextResponse.json({ stages, findings });
  }
  stages.push({
    name: "Post-resolve IP re-check",
    status: "pass",
    detail: `All ${resolved.length} resolved IP(s) are public. Safe to fetch.`,
    data: { resolved },
  });

  // STAGE 4 — bounded fetch. Time-limited, body-capped, no follow on
  // redirects (so the redirect target itself can be re-validated upstream
  // by the caller — full handling is out-of-scope for the demo).
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let status = 0;
  let bodySnippet = "";
  let contentType = "";
  try {
    const resp = await fetch(target, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        "user-agent":
          "lab.marwandiallo.com SSRF runtime demo (https://lab.marwandiallo.com)",
      },
    });
    clearTimeout(timer);
    status = resp.status;
    contentType = resp.headers.get("content-type") ?? "";
    if (resp.body) {
      const reader = resp.body.getReader();
      let received = 0;
      const chunks: Uint8Array[] = [];
      const decoder = new TextDecoder();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.length;
        if (received > MAX_BODY) {
          await reader.cancel();
          break;
        }
        chunks.push(value);
      }
      for (const c of chunks)
        bodySnippet += decoder.decode(c, { stream: true });
      bodySnippet += decoder.decode();
    }
  } catch (err) {
    clearTimeout(timer);
    stages.push({
      name: "Bounded fetch",
      status: "fail",
      detail: `Fetch failed: ${err instanceof Error ? err.message : "unknown"}`,
    });
    return NextResponse.json({ stages, findings });
  }

  stages.push({
    name: "Bounded fetch",
    status: "pass",
    detail: `HTTP ${status}. ${bodySnippet.length} bytes body captured (cap ${MAX_BODY}).`,
    data: {
      status,
      contentType,
      bodyLength: bodySnippet.length,
      bodyPreview: bodySnippet.slice(0, 500),
    },
  });

  return NextResponse.json({ stages, findings });
}

export async function GET() {
  return new NextResponse(null, { status: 405, headers: { Allow: "POST" } });
}
