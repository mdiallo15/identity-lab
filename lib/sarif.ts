// SARIF v2.1.0 emitter. Converts Finding[] to a SARIF run that GitHub
// Code Scanning, Sonar, Azure DevOps, and other tools can ingest.
//
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
//
// We emit the smallest valid SARIF document that GitHub Advanced Security
// will accept: $schema + version + runs[].tool.driver.{name,version,rules}
// and runs[].results[]. Severity maps from our 4-level model to SARIF's
// security-severity (CVSS 0-10) so GitHub renders the right pill color.

// Permissive Finding shape — matches lib/csp.ts, lib/headers.ts,
// lib/prompt-injection.ts, and lib/ssrf.ts. Each lab's Finding has
// slightly different optional fields (fix vs excerpt vs directive)
// and PI/SSRF add 'critical' to the severity union. We accept all of
// them and map appropriately.
export type SarifSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface SarifFinding {
  id: string;
  severity: SarifSeverity;
  title: string;
  detail: string;
  fix?: string;
  excerpt?: string;
  directive?: string;
}

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

// Re-export legacy alias so existing /csp/analyzer import keeps working.
export type { SarifFinding as Finding };

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
  findings: SarifFinding[],
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

  const results: SarifResult[] = findings.map((f) => {
    const fixLine = f.fix ? `\n\nFix: ${f.fix}` : "";
    const excerptLine = f.excerpt ? `\n\nExcerpt:\n${f.excerpt}` : "";
    return {
      ruleId: f.id,
      level: severityToLevel(f.severity),
      message: {
        text: `${f.title}\n\n${f.detail}${fixLine}${excerptLine}`,
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
    };
  });

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

function severityToLevel(s: SarifSeverity): "error" | "warning" | "note" {
  if (s === "critical" || s === "high") return "error";
  if (s === "medium") return "warning";
  return "note"; // low, info
}

// security-severity is GitHub's signal for sort order on the
// Code Scanning UI. CVSS bands: critical>=9, high>=7, medium>=4, low>=0.1.
function severityToCvss(s: SarifSeverity): string {
  if (s === "critical") return "9.5";
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
