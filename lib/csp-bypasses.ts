import { analyze as analyzeCsp, parseCsp, type Finding as CspFinding } from "./csp";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface LabFinding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  fix: string;
}

export interface BypassScenario {
  id:
    | "jsonp"
    | "base-uri"
    | "unsafe-inline"
    | "strict-dynamic"
    | "reporting";
  title: string;
  category: string;
  policy: string;
  payload: string;
  lesson: string;
  reference: { label: string; url: string };
}

export const BYPASS_SCENARIOS: readonly BypassScenario[] = [
  {
    id: "jsonp",
    category: "allowlist",
    title: "JSONP on an allowlisted host",
    policy:
      "default-src 'self'; script-src 'self' https://ajax.googleapis.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    payload:
      '<script src="https://ajax.googleapis.com/ajax/services/search/web?v=1.0&callback=alert(1)"></script>',
    lesson:
      "Host allowlists trust the entire origin. If that origin serves attacker-controlled JS, the bypass lands.",
    reference: {
      label: "PortSwigger, 'Bypassing CSP with JSONP endpoints'",
      url: "https://portswigger.net/research/bypassing-csp-with-jsonp-endpoints",
    },
  },
  {
    id: "base-uri",
    category: "dangling markup",
    title: "Missing base-uri enables base tag rewrite",
    policy:
      "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; object-src 'none'; frame-ancestors 'none'; form-action 'self'",
    payload: '<base href="https://attacker.example/">',
    lesson:
      "One injected <base> rewrites every relative URL on the page unless base-uri is locked down.",
    reference: {
      label: "PortSwigger, 'Dangling markup injection'",
      url: "https://portswigger.net/web-security/cross-site-scripting/dangling-markup",
    },
  },
  {
    id: "unsafe-inline",
    category: "legacy inline",
    title: "'unsafe-inline' lets the payload execute directly",
    policy:
      "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    payload: '<script>alert(document.domain)</script>',
    lesson:
      "Once unsafe-inline is back in script-src, most classic reflected and stored XSS payloads are alive again.",
    reference: {
      label: "Google CSP Evaluator guidance",
      url: "https://csp-evaluator.withgoogle.com/",
    },
  },
  {
    id: "strict-dynamic",
    category: "misconfiguration",
    title: "'strict-dynamic' without nonce or hash",
    policy:
      "default-src 'self'; script-src 'strict-dynamic' https://cdn.jsdelivr.net; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    payload: '<script src="https://cdn.jsdelivr.net/npm/evil/payload.js"></script>',
    lesson:
      "Teams copy strict-dynamic from a blog post but forget the nonce/hash that gives it meaning.",
    reference: {
      label: "MDN, 'strict-dynamic' semantics",
      url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#strict-dynamic",
    },
  },
  {
    id: "reporting",
    category: "operations",
    title: "No reporting creates silent breakage",
    policy:
      "default-src 'self'; script-src 'nonce-RANDOM' 'strict-dynamic'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    payload: '<script src="https://tag-manager.example/new.js"></script>',
    lesson:
      "The policy blocks the new script, but you have no telemetry and only discover it when analytics quietly disappear.",
    reference: {
      label: "OWASP Content Security Policy Cheat Sheet",
      url: "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
    },
  },
] as const;

function has(values: string[] | undefined, token: string): boolean {
  return !!values?.includes(token);
}

export function analyzeBypass(
  scenarioId: BypassScenario["id"],
  policy: string,
  payload: string,
): {
  verdict: "blocked" | "lands" | "degraded";
  findings: LabFinding[];
  cspFindings: CspFinding[];
} {
  const findings: LabFinding[] = [];
  const cspFindings = analyzeCsp(policy);
  const { directives } = parseCsp(policy);
  const scriptSrc = directives["script-src"] ?? directives["default-src"];

  if (scenarioId === "jsonp") {
    const allowsHost =
      has(scriptSrc, "https://ajax.googleapis.com") ||
      has(scriptSrc, "https:") ||
      has(scriptSrc, "*");
    if (allowsHost && !has(scriptSrc, "'strict-dynamic'")) {
      findings.push({
        id: "BYP01",
        severity: "critical",
        title: "JSONP endpoint trusted by host allowlist",
        detail:
          "The payload host is explicitly or implicitly trusted, so CSP sees it as legitimate script even though the endpoint returns attacker-controlled JavaScript.",
        fix: "Move away from host allowlists for script execution. Prefer nonce + strict-dynamic and remove JSONP-capable hosts.",
      });
      return { verdict: "lands", findings, cspFindings };
    }
    findings.push({
      id: "BYP02",
      severity: "info",
      title: "Host allowlist no longer grants script execution",
      detail:
        "The payload is blocked because the policy does not trust that origin, or the script rail is nonce-governed instead of host-governed.",
      fix: "Keep script execution on a nonce/hash rail and avoid JSONP-capable hosts.",
    });
    return { verdict: "blocked", findings, cspFindings };
  }

  if (scenarioId === "base-uri") {
    if (!directives["base-uri"]) {
      findings.push({
        id: "BYP03",
        severity: "critical",
        title: "Missing base-uri allows attacker base tag",
        detail:
          "The payload rewrites relative script, image, and link URLs to the attacker origin before the rest of the page resolves them.",
        fix: "Set base-uri 'self' or 'none' on every production policy.",
      });
      return { verdict: "lands", findings, cspFindings };
    }
    findings.push({
      id: "BYP04",
      severity: "info",
      title: "base-uri closes the dangling-markup path",
      detail: "The injected base tag is inert because the policy constrains who may become the document base.",
      fix: "Keep base-uri in the enforced policy, not just report-only mode.",
    });
    return { verdict: "blocked", findings, cspFindings };
  }

  if (scenarioId === "unsafe-inline") {
    if (has(scriptSrc, "'unsafe-inline'") && !scriptSrc?.some((v) => v.startsWith("'nonce-") || v.startsWith("'sha"))) {
      findings.push({
        id: "BYP05",
        severity: "critical",
        title: "Inline script executes under unsafe-inline",
        detail:
          "The payload is a textbook stored/reflected XSS and the policy explicitly allows it to run.",
        fix: "Remove unsafe-inline from script-src and migrate to nonce- or hash-based execution.",
      });
      return { verdict: "lands", findings, cspFindings };
    }
    findings.push({
      id: "BYP06",
      severity: "info",
      title: "Inline script blocked",
      detail: "The policy does not expose the unsafe-inline rail, so a plain inline payload does not execute.",
      fix: "Keep inline execution behind nonces or hashes only.",
    });
    return { verdict: "blocked", findings, cspFindings };
  }

  if (scenarioId === "strict-dynamic") {
    const hasStrictDynamic = has(scriptSrc, "'strict-dynamic'");
    const hasNonceOrHash =
      scriptSrc?.some((v) => v.startsWith("'nonce-") || v.startsWith("'sha")) ?? false;
    if (hasStrictDynamic && !hasNonceOrHash) {
      findings.push({
        id: "BYP07",
        severity: "high",
        title: "strict-dynamic copied without nonce/hash",
        detail:
          "The team believes they are on a nonce-governed policy, but the directive is incomplete and the fallback behavior is weaker than intended.",
        fix: "Pair strict-dynamic with a real nonce/hash source, or remove it and use an explicit allowlist until the app can mint nonces.",
      });
      return { verdict: "lands", findings, cspFindings };
    }
    findings.push({
      id: "BYP08",
      severity: "info",
      title: "strict-dynamic is anchored correctly",
      detail: "The policy only works because the execution rail is tied to a nonce/hash and not just the keyword itself.",
      fix: "Keep the nonce/hash in the same directive whenever strict-dynamic is present.",
    });
    return { verdict: "blocked", findings, cspFindings };
  }

  const hasReporting =
    directives["report-uri"] || directives["report-to"] || directives["Reporting-Endpoints"];
  if (!hasReporting) {
    findings.push({
      id: "BYP09",
      severity: "medium",
      title: "No reporting endpoint for blocked script drift",
      detail:
        "The payload is blocked, but nobody learns about it. Operations discovers the breakage later through missing telemetry or user complaints.",
      fix: "Add report-to or report-uri and route CSP violation data into logs or SIEM.",
    });
    return { verdict: "degraded", findings, cspFindings };
  }
  findings.push({
    id: "BYP10",
    severity: "info",
    title: "Blocked and observable",
    detail: "The payload is blocked and the policy includes a reporting path, so operations gets a signal instead of silent drift.",
    fix: "Keep enforcement and reporting together during tag-manager and third-party JS changes.",
  });
  return { verdict: "blocked", findings, cspFindings };
}