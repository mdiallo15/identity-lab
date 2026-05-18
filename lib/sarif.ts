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

// Lightweight SARIF 2.1.0 structural validator. Runs in the browser and in
// Node with no dependencies. Returns a list of human-readable error
// strings; an empty list means the document is structurally well-formed
// against the subset of the schema that GitHub Code Scanning and the
// SARIF Multitool actually enforce.
//
// What is checked:
//   - $schema and version pinned to SARIF 2.1.0
//   - runs is a non-empty array
//   - tool.driver.name and rules[] present
//   - each rule has id + valid level + numeric security-severity in [0,10]
//   - each result has ruleId that resolves to a known rule, valid level,
//     message.text, and (if present) a well-formed location
//
// What is NOT checked (out of scope for a structural pass): URI scheme
// restrictions imposed by GitHub Code Scanning (file:// only) and CVSS
// vector validation. The SARIF spec itself permits https URIs.
export function validateSarif(doc: unknown): string[] {
  const errors: string[] = [];
  const push = (m: string) => errors.push(m);
  if (typeof doc !== "object" || doc === null) {
    push("root: not an object");
    return errors;
  }
  const d = doc as Record<string, unknown>;
  if (d.$schema !== SCHEMA) push(`$schema: expected ${SCHEMA}, got ${d.$schema}`);
  if (d.version !== "2.1.0") push(`version: expected "2.1.0", got ${d.version}`);
  if (!Array.isArray(d.runs) || d.runs.length === 0) {
    push("runs: expected non-empty array");
    return errors;
  }
  const validLevels = new Set(["error", "warning", "note", "none"]);
  d.runs.forEach((run, ri) => {
    if (typeof run !== "object" || run === null) {
      push(`runs[${ri}]: not an object`);
      return;
    }
    const r = run as Record<string, unknown>;
    const tool = r.tool as Record<string, unknown> | undefined;
    const driver = tool?.driver as Record<string, unknown> | undefined;
    if (!driver) {
      push(`runs[${ri}].tool.driver: missing`);
    } else {
      if (typeof driver.name !== "string" || driver.name.length === 0) {
        push(`runs[${ri}].tool.driver.name: missing or empty`);
      }
      if (driver.rules !== undefined && !Array.isArray(driver.rules)) {
        push(`runs[${ri}].tool.driver.rules: expected array`);
      }
    }
    const ruleIds = new Set<string>();
    const rules = (driver?.rules as unknown[] | undefined) ?? [];
    rules.forEach((rule, idx) => {
      if (typeof rule !== "object" || rule === null) {
        push(`runs[${ri}].rules[${idx}]: not an object`);
        return;
      }
      const ru = rule as Record<string, unknown>;
      if (typeof ru.id !== "string" || ru.id.length === 0) {
        push(`runs[${ri}].rules[${idx}].id: missing`);
      } else {
        ruleIds.add(ru.id);
      }
      const cfg = ru.defaultConfiguration as
        | Record<string, unknown>
        | undefined;
      if (cfg && typeof cfg.level === "string" && !validLevels.has(cfg.level)) {
        push(
          `runs[${ri}].rules[${idx}].defaultConfiguration.level: invalid (${cfg.level})`,
        );
      }
      const props = ru.properties as Record<string, unknown> | undefined;
      if (props && "security-severity" in props) {
        const v = props["security-severity"];
        const n = typeof v === "string" ? Number(v) : NaN;
        if (Number.isNaN(n) || n < 0 || n > 10) {
          push(
            `runs[${ri}].rules[${idx}].properties.security-severity: out of range (${String(v)})`,
          );
        }
      }
      const sd = ru.shortDescription as Record<string, unknown> | undefined;
      if (sd && typeof sd.text !== "string") {
        push(`runs[${ri}].rules[${idx}].shortDescription.text: not a string`);
      }
    });
    const results = r.results;
    if (results !== undefined && !Array.isArray(results)) {
      push(`runs[${ri}].results: expected array`);
    } else if (Array.isArray(results)) {
      results.forEach((res, idx) => {
        if (typeof res !== "object" || res === null) {
          push(`runs[${ri}].results[${idx}]: not an object`);
          return;
        }
        const re = res as Record<string, unknown>;
        if (typeof re.ruleId !== "string" || re.ruleId.length === 0) {
          push(`runs[${ri}].results[${idx}].ruleId: missing`);
        } else if (ruleIds.size > 0 && !ruleIds.has(re.ruleId)) {
          push(
            `runs[${ri}].results[${idx}].ruleId: "${re.ruleId}" not in tool.driver.rules`,
          );
        }
        if (typeof re.level === "string" && !validLevels.has(re.level)) {
          push(`runs[${ri}].results[${idx}].level: invalid (${re.level})`);
        }
        const msg = re.message as Record<string, unknown> | undefined;
        if (!msg || typeof msg.text !== "string" || msg.text.length === 0) {
          push(`runs[${ri}].results[${idx}].message.text: missing or empty`);
        }
        if (re.locations !== undefined) {
          if (!Array.isArray(re.locations) || re.locations.length === 0) {
            push(
              `runs[${ri}].results[${idx}].locations: must be a non-empty array when present`,
            );
          } else {
            re.locations.forEach((loc, li) => {
              const l = loc as Record<string, unknown>;
              const pl = l?.physicalLocation as
                | Record<string, unknown>
                | undefined;
              const al = pl?.artifactLocation as
                | Record<string, unknown>
                | undefined;
              if (typeof al?.uri !== "string" || al.uri.length === 0) {
                push(
                  `runs[${ri}].results[${idx}].locations[${li}].physicalLocation.artifactLocation.uri: missing`,
                );
              }
            });
          }
        }
      });
    }
  });
  return errors;
}
