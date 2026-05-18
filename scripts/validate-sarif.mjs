// scripts/validate-sarif.mjs
//
// Exercises lib/sarif.ts against representative findings from every lab
// surface that exports SARIF, then runs validateSarif() to confirm the
// emitted document is structurally valid against SARIF 2.1.0 (the subset
// GitHub Code Scanning and the SARIF Multitool enforce).
//
// Run: `npm run validate-sarif`
//
// Implementation note: lib/sarif.ts is TypeScript, so we use the
// TypeScript compiler (already a devDependency) to transpile it in-memory
// to ESM, then import via a data: URL. Zero runtime dependencies beyond
// `typescript`, which is already pinned in package.json.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import ts from "typescript";

const here = dirname(fileURLToPath(import.meta.url));
const sarifTsPath = resolve(here, "../lib/sarif.ts");
const src = readFileSync(sarifTsPath, "utf-8");
const js = ts.transpileModule(src, {
  compilerOptions: {
    module: ts.ModuleKind.ESNext,
    target: ts.ScriptTarget.ES2022,
  },
}).outputText;
const mod = await import(
  "data:text/javascript;base64," + Buffer.from(js).toString("base64")
);
const { findingsToSarif, validateSarif } = mod;

// --- Fixture findings representing every lab surface ----------------------

const CSP_FINDINGS = [
  {
    id: "CSP-001",
    severity: "high",
    title: "script-src allows 'unsafe-inline'",
    detail: "Inline scripts execute against current document context.",
    fix: "Replace 'unsafe-inline' with nonce or hash.",
    directive: "script-src",
  },
  {
    id: "HDR-XFO",
    severity: "medium",
    title: "Missing X-Frame-Options",
    detail: "Frame ancestors not bounded.",
  },
  {
    id: "SRI-MISSING",
    severity: "low",
    title: "Third-party script without integrity",
    detail: "<script src=//cdn> lacks integrity= attribute.",
    excerpt: "<script src='https://cdn.example/x.js'></script>",
  },
];

const AUTHZ_FINDINGS = [
  {
    id: "AZ-001",
    severity: "critical",
    title: "Wildcard role assignment",
    detail: "Role '*' grants all permissions; violates least privilege.",
    fix: "Replace * with explicit verb list.",
  },
];

const SSRF_FINDINGS = [
  {
    id: "SSRF-001",
    severity: "critical",
    title: "AWS IMDSv1 reachable",
    detail: "169.254.169.254 not in deny list.",
    fix: "Pin egress to allowlisted CIDRs; require IMDSv2 token.",
  },
  {
    id: "SSRF-CRLF",
    severity: "high",
    title: "CRLF injection via URL fragment",
    detail: "Newlines in path smuggle into Host header.",
  },
];

const AGENT_FINDINGS = [
  {
    id: "AGT01",
    severity: "high",
    title: "Long-lived secret",
    detail: "Agent uses static API key with no expiry.",
    fix: "Replace with attested workload identity (RFC 8693).",
  },
  {
    id: "AGT02",
    severity: "info",
    title: "Acceptable hygiene",
    detail: "Agent emits act claim and rotates daily.",
  },
];

const SURFACES = [
  {
    name: "csp/analyzer (in-browser CSP)",
    findings: CSP_FINDINGS,
    opts: { toolName: "lab.marwandiallo.com/csp", target: "user-input" },
  },
  {
    name: "api/scan (server-side CSP+HDR+SRI scan)",
    findings: CSP_FINDINGS,
    opts: {
      toolName: "lab.marwandiallo.com/csp",
      target: "https://example.com",
    },
  },
  {
    name: "authz/patterns",
    findings: AUTHZ_FINDINGS,
    opts: { toolName: "lab.marwandiallo.com/authz", target: "user-input" },
  },
  {
    name: "ssrf/analyzer",
    findings: SSRF_FINDINGS,
    opts: { toolName: "lab.marwandiallo.com/ssrf", target: "user-input" },
  },
  {
    name: "agent-identity/inventory",
    findings: AGENT_FINDINGS,
    opts: {
      toolName: "lab.marwandiallo.com/agent-identity",
      target: "user-input",
    },
  },
  {
    name: "(edge case) empty findings, no target",
    findings: [],
    opts: { toolName: "lab.marwandiallo.com/empty" },
  },
];

let failed = 0;
for (const s of SURFACES) {
  const sarif = findingsToSarif(s.findings, s.opts);
  const errs = validateSarif(sarif);
  if (errs.length === 0) {
    console.log(`✓ ${s.name} (${s.findings.length} findings)`);
  } else {
    failed++;
    console.error(`✗ ${s.name}`);
    for (const e of errs) console.error("  - " + e);
  }
}

if (failed > 0) {
  console.error(`\n${failed} surface(s) failed SARIF validation.`);
  process.exit(1);
}
console.log("\nAll SARIF exports validate against SARIF 2.1.0.");
