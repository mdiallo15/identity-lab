// audit-ignore-file
// Server-side mirror of the deterministic SSRF v2 fetcher sandbox.
// Takes { scenarioId, mode } and returns the same trace the client renders.
// Exposed as an endpoint so users can curl it (copy-as-curl from the UI),
// replay scenarios from CI, or wire scenarios into a SIEM as test fixtures.
//
// Crucially, this route does NOT perform real outbound fetches against the
// catalog URLs. The catalog targets cloud metadata services and internal
// IPs that production hosting blocks at egress; emitting them from a public
// service would also be irresponsible. The fetchers are deterministic
// transcripts. The hardened-rule logic is the same code a real backend
// ships; only the wire transmission is faked.

import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { SSRF_CATALOG, runFetcher, type FetcherMode } from "@/lib/ssrf";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

interface Body {
  scenarioId?: string;
  mode?: FetcherMode;
}

export async function POST(req: NextRequest) {
  let body: Body;
  try {
    body = (await req.json()) as Body;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  const scenario = SSRF_CATALOG.find((s) => s.id === body.scenarioId);
  if (!scenario) {
    return NextResponse.json(
      {
        error: "Unknown scenarioId",
        validIds: SSRF_CATALOG.map((s) => s.id),
      },
      { status: 400 },
    );
  }
  const mode: FetcherMode =
    body.mode === "naive" || body.mode === "hardened" ? body.mode : "hardened";

  const result = runFetcher(scenario, mode);

  return NextResponse.json({
    scenario: {
      id: scenario.id,
      title: scenario.title,
      category: scenario.category,
      blurb: scenario.blurb,
      reference: scenario.reference,
      request: scenario.request,
    },
    result,
  });
}

export async function GET() {
  // Convenience: list the catalog so users can `curl /api/ssrf-fetch` to
  // discover scenario ids before POST'ing.
  return NextResponse.json({
    scenarios: SSRF_CATALOG.map((s) => ({
      id: s.id,
      category: s.category,
      title: s.title,
    })),
  });
}
