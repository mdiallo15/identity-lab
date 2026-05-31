import { analyze as analyzeCsp, type Finding } from "./csp";

export interface ShapeChoice {
  id: "open" | "allowlist" | "nonce" | "hash";
  title: string;
  policy: string;
  rationale: string;
  tradeoffs: string[];
}

export interface ShapeInput {
  serverRendered: boolean;
  staticHosted: boolean;
  thirdPartyScripts: boolean;
  inlineScripts: boolean;
  reportOnlyRollout: boolean;
}

export const SHAPES: readonly ShapeChoice[] = [
  {
    id: "open",
    title: "Fully open / transitional",
    policy: "default-src 'self' 'unsafe-inline' 'unsafe-eval' https:;",
    rationale:
      "Only acceptable as a temporary report-only measurement phase. This is not a production shape.",
    tradeoffs: [
      "fastest migration",
      "worst exploit resistance",
      "high false confidence risk",
    ],
  },
  {
    id: "allowlist",
    title: "Host allowlist",
    policy:
      "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://www.googletagmanager.com; style-src 'self' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; report-to csp-endpoint;",
    rationale:
      "Operationally simple when the app truly has a fixed script supplier set, but it degrades badly as third-party JS grows.",
    tradeoffs: [
      "good for fixed script hosts",
      "poor against JSONP/CDN drift",
      "operationally noisy at scale",
    ],
  },
  {
    id: "nonce",
    title: "Nonce + strict-dynamic",
    policy:
      "default-src 'self'; script-src 'nonce-RANDOM' 'strict-dynamic'; style-src 'self' 'nonce-RANDOM'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; report-to csp-endpoint;",
    rationale:
      "Best default for server-rendered apps. Execution is tied to request-time trusted markup instead of a host allowlist.",
    tradeoffs: [
      "strongest default for SSR",
      "needs request-time header control",
      "works well with dynamic script trees",
    ],
  },
  {
    id: "hash",
    title: "Hash-based static policy",
    policy:
      "default-src 'self'; script-src 'sha256-AbC123...' 'sha256-XyZ789...' 'strict-dynamic'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; report-to csp-endpoint;",
    rationale:
      "Best fit for static hosting where request-time nonce minting is impossible but inline scripts are few and stable.",
    tradeoffs: [
      "good for CDN/static hosting",
      "every inline-script change rotates hashes",
      "less flexible for frequent script churn",
    ],
  },
] as const;

export function recommendShape(input: ShapeInput): {
  recommended: ShapeChoice;
  migration: string[];
  findings: Finding[];
} {
  let recommended: ShapeChoice;

  if (input.reportOnlyRollout && !input.serverRendered && !input.staticHosted) {
    recommended = SHAPES[0];
  } else if (input.staticHosted) {
    recommended = SHAPES[3];
  } else if (input.serverRendered) {
    recommended = SHAPES[2];
  } else {
    recommended = SHAPES[1];
  }

  const migration: string[] = [];
  if (recommended.id === "nonce") {
    migration.push("Mint a fresh nonce per response and stamp it onto every trusted inline script/style tag.");
    migration.push("Delete host-level script allowlists once strict-dynamic is live, unless a browser support requirement says otherwise.");
  }
  if (recommended.id === "hash") {
    migration.push("Hash every intentional inline script at build time and regenerate hashes on each content change.");
    migration.push("Keep the inline-script set small. Hash sprawl is the operational tax of static hosting.");
  }
  if (recommended.id === "allowlist") {
    migration.push("Inventory every third-party script host and review JSONP / script-reflection risk before adding it to script-src.");
    migration.push("Treat this as a migration waypoint if third-party JS is expanding or if inline scripts still exist.");
  }
  if (recommended.id === "open") {
    migration.push("Use report-only only long enough to measure breakage; do not ship this shape enforced.");
    migration.push("Pick a target enforced shape before rollout so the temporary policy does not become permanent.");
  }

  if (input.thirdPartyScripts && recommended.id === "allowlist") {
    migration.push("Watch for allowlist drift. The more third-party JS you load, the faster allowlist CSP collapses into broad trust.");
  }
  if (input.inlineScripts && recommended.id === "allowlist") {
    migration.push("If inline scripts must stay temporarily, keep them behind a short-lived migration plan; unsafe-inline is not the end state.");
  }

  return {
    recommended,
    migration,
    findings: analyzeCsp(recommended.policy),
  };
}