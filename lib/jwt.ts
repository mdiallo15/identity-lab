// JWT decoder with security analysis.
//
// Pure client-side: no key, no signature verification — this is a
// teaching tool, not a verifier. We pull the structural pieces out and
// flag the patterns that bite real applications:
//   - alg: 'none' or HS-vs-RS confusion
//   - missing/expired exp, missing iss/aud
//   - obvious PII in the payload
//
// Inspired by jwt.io but with explicit security highlights.

export interface JwtParts {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
}

export interface JwtFinding {
  severity: "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
}

function b64urlDecode(str: string): string {
  const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
  const b64 = (str + pad).replace(/-/g, "+").replace(/_/g, "/");
  if (typeof atob === "function") return atob(b64);
  // Node fallback
  return Buffer.from(b64, "base64").toString("utf8");
}

export function decodeJwt(token: string): JwtParts {
  const parts = token.trim().split(".");
  if (parts.length !== 3) {
    throw new Error("Not a JWT — expected three dot-separated segments.");
  }
  const headerJson = b64urlDecode(parts[0]!);
  const payloadJson = b64urlDecode(parts[1]!);
  return {
    header: JSON.parse(headerJson),
    payload: JSON.parse(payloadJson),
    signature: parts[2]!,
  };
}

export function analyzeJwt(parts: JwtParts): JwtFinding[] {
  const findings: JwtFinding[] = [];
  const { header, payload, signature } = parts;

  // alg checks
  const alg = String(header.alg ?? "");
  if (alg === "" || alg.toLowerCase() === "none") {
    findings.push({
      severity: "high",
      title: "alg=none",
      detail:
        "Token claims no algorithm. Verifiers that don't pin algorithms accept this as valid — full impersonation.",
    });
  }
  if (signature === "") {
    findings.push({
      severity: "high",
      title: "Empty signature",
      detail: "No signature segment present. Identical risk to alg=none.",
    });
  }

  // Expiry
  if (typeof payload.exp !== "number") {
    findings.push({
      severity: "medium",
      title: "Missing exp claim",
      detail: "Tokens without expiry live forever in stolen-cookie scenarios.",
    });
  } else {
    const expMs = (payload.exp as number) * 1000;
    if (expMs < Date.now()) {
      findings.push({
        severity: "medium",
        title: "Token is expired",
        detail: `exp = ${new Date(expMs).toISOString()} — verifiers should reject.`,
      });
    }
  }

  if (typeof payload.iat === "number") {
    const iatMs = (payload.iat as number) * 1000;
    if (iatMs > Date.now() + 60_000) {
      findings.push({
        severity: "medium",
        title: "iat in the future",
        detail: "Clock-skew or forged issuance time.",
      });
    }
  }

  // Audience / issuer
  if (!payload.iss) {
    findings.push({
      severity: "low",
      title: "Missing iss claim",
      detail:
        "Always pin issuer when verifying — prevents cross-tenant token reuse.",
    });
  }
  if (!payload.aud) {
    findings.push({
      severity: "low",
      title: "Missing aud claim",
      detail: "Without audience, tokens issued for service A can be replayed at service B.",
    });
  }

  // PII heuristics
  const payloadStr = JSON.stringify(payload).toLowerCase();
  if (/\bssn\b|social.security/.test(payloadStr)) {
    findings.push({
      severity: "high",
      title: "PII in token claims",
      detail:
        "JWT payloads are base64-encoded, not encrypted. Treat anything inside as public.",
    });
  }
  if (/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/.test(payloadStr) && !payload.email_verified) {
    findings.push({
      severity: "low",
      title: "Email present but unverified",
      detail:
        "If you trust 'email' for authorization, also require email_verified === true.",
    });
  }

  // OIDC ID token heuristics
  if (payload.nonce && header.typ !== "JWT" && header.typ !== "id+jwt" && header.typ !== undefined) {
    findings.push({
      severity: "info",
      title: "Unusual typ for ID token",
      detail: `typ='${header.typ}' — common values: 'JWT', 'id+jwt'.`,
    });
  }

  if (alg.startsWith("HS") && payload.iss && /accounts\.google|login\.microsoftonline|auth0|okta/.test(String(payload.iss))) {
    findings.push({
      severity: "high",
      title: "HMAC alg with public IdP issuer",
      detail:
        "Public IdPs sign with RSA/EC. HS-* claims here suggest alg-confusion attack — verifier may treat the public key as an HMAC secret.",
    });
  }

  if (findings.length === 0) {
    findings.push({
      severity: "info",
      title: "No structural issues found",
      detail:
        "This tool only checks the visible structure. Always verify the signature against the issuer's JWKS in production.",
    });
  }
  return findings;
}
