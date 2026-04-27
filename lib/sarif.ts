// SARIF v2.1.0 emitter. Converts Finding[] to a SARIF run that GitHub
// Code Scanning, Sonar, Azure DevOps, and other tools can ingest.
//
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
//
// We emit the smallest valid SARIF document that GitHub Advanced Security
// will accept: $schema + version + runs[].tool.driver.{name,version,rules}
// and runs[].results[]. Severity maps from our 4-level model to SARIF's
// security-severity (CVSS 0-10) so GitHub renders the right pill color.

import type { Finding, Severity } from "./csp";

const VERSION = "1.0.0";
const SCHEMA =
  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json";

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  defaultConfiguration: { level: "error" | "warning" | "note" };
  properties: { "security-severity": string; tags: string[] };
}

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations?: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
    };
  }>;
}

export interface SarifOptions {
  toolName: string; // e.g. "lab.marwandiallo.com/csp"
  target?: string; // URL or "user-input" — shown in artifact location
}

export function findingsToSarif(
  findings: Finding[],
  opts: SarifOptions,
): unknown {
  // Deduplicate rules — multiple findings can share an id (rare but possible).
  const ruleMap = new Map<string, SarifRule>();
  for (const f of findings) {
    if (ruleMap.has(f.id)) continue;
    ruleMap.set(f.id, {
      id: f.id,
      name: f.title,
      shortDescription: { text: f.title },
      fullDescription: { text: f.detail },
      defaultConfiguration: { level: severityToLevel(f.severity) },
      properties: {
        "security-severity": severityToCvss(f.severity),
        tags: ["security", deriveTag(f.id)],
      },
    });
  }

  const results: SarifResult[] = findings.map((f) => ({
    ruleId: f.id,
    level: severityToLevel(f.severity),
    message: {
      text: `${f.title}\n\n${f.detail}\n\nFix: ${f.fix}`,
    },
    locations: opts.target
      ? [
          {
            physicalLocation: {
              artifactLocation: { uri: opts.target },
            },
          },
        ]
      : undefined,
  }));

  return {
    $schema: SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: opts.toolName,
            version: VERSION,
            informationUri: "https://lab.marwandiallo.com",
            rules: Array.from(ruleMap.values()),
          },
        },
        results,
      },
    ],
  };
}

function severityToLevel(s: Severity): "error" | "warning" | "note" {
  if (s === "high") return "error";
  if (s === "medium") return "warning";
  return "note"; // low, info
}

// security-severity is GitHub's signal for sort order on the
// Code Scanning UI. Mapping: high=8.5, medium=5.5, low=3.0, info=0.0.
function severityToCvss(s: Severity): string {
  if (s === "high") return "8.5";
  if (s === "medium") return "5.5";
  if (s === "low") return "3.0";
  return "0.0";
}

function deriveTag(id: string): string {
  if (id.startsWith("CSP")) return "content-security-policy";
  if (id.startsWith("HDR")) return "security-headers";
  if (id.startsWith("SRI")) return "subresource-integrity";
  if (id.startsWith("PI")) return "prompt-injection";
  if (id.startsWith("SSRF")) return "ssrf";
  return "general";
}
