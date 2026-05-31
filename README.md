# marwandiallo-labs

Hands-on security labs. Live at **[lab.marwandiallo.com](https://lab.marwandiallo.com)**.

> Built by [Marwan Diallo](https://marwandiallo.com) — security architect at
> Microsoft, founder of Diallo Group. Each lab pairs a working demo with the
> failure modes I've actually seen in production.

## Labs

| Lab | Routes | What ships |
| --- | --- | --- |
| Identity | `/identity`, `/identity/passkey`, `/identity/jwt`, `/identity/forge`, `/identity/phishing-resistant`, `/identity/agent-identity` | WebAuthn passkey demo, JWT inspector, forging workbench, phishing-resistant MFA attack simulator, and agent-identity labs. |
| Agent Identity | `/agent-identity`, `/agent-identity/attestation`, `/agent-identity/inventory`, `/agent-identity/token-exchange` | Attestation comparison, inventory drift detector, and RFC 8693 token-exchange playground. |
| CSP | `/csp`, `/csp/analyzer`, `/csp/sandbox`, `/csp/bypasses`, `/csp/shapes` | CSP/header analyzer, sandbox, live bypass lab, and CSP-shape decision lab. |
| AuthZ | `/authz`, `/authz/patterns`, `/authz/simulator` | BOLA / IDOR query-scoping lab and naive-vs-hardened endpoint simulator. |
| SSRF | `/ssrf`, `/ssrf/analyzer`, `/ssrf/targets`, `/ssrf/hardening` | Live SSRF analyzer, target catalog, and hardening guidance. |
| Prompt Injection | `/prompt-injection`, `/prompt-injection/patterns`, `/prompt-injection/defenses`, `/prompt-injection/simulator` | Five-tool agent-loop simulator, pattern catalog, and defense guidance. |
| Supply Chain | `/supply-chain` | Provenance analyzer, typosquat checker, and incident replay catalog. |
| IAM PrivEsc | `/iam-privesc` | Multi-cloud privilege-escalation path enumerator with editable graph. |
| Detection Engineering | `/detection-engineering` | Ground-truth-labeled detections with live precision/recall/F1. |
| RAG Security | `/rag` | Deterministic retrieval-augmented-generation attack simulator. |

## Architecture

Single Next.js app, route-grouped by lab. Routes:

```
/                       hub index
/identity/*             Identity Lab
/agent-identity/*       Agent Identity Lab
/csp/*                  CSP Playground
/authz/*                Authorization Lab
/ssrf/*                 SSRF Lab
/prompt-injection/*     Prompt Injection Lab
/supply-chain           Supply Chain Lab
/iam-privesc            IAM PrivEsc Lab
/detection-engineering  Detection Engineering Lab
/rag                    RAG Security Lab
/api/identity/passkey/* WebAuthn API (in-memory store)
/api/scan               Public CSP/header scanner
/api/ssrf-test          Validate-then-fetch SSRF demo
```

WebAuthn RP ID is `lab.marwandiallo.com`. Passkeys registered here are
scoped to that origin only — they cannot sign assertions for the main site
or any other subdomain. That isolation is intentional; it's the first thing
the Identity Lab teaches.

## Run it

```bash
npm install
npm run dev   # http://localhost:3000
npm run build
npm test      # node:test
```

## Production hardening checklist

Before deploying any of this with real users:

- Replace the in-memory passkey store with a database. Persist
  `credentialID`, `publicKey`, `counter`, `transports`. Encrypt at rest.
- Origin-bind sessions. The lab does not currently issue session cookies
  after sign-in — that's a deliberate omission for the demo.
- Add rate limiting on `/api/identity/passkey/*`. The starter at
  [secure-next-starter](https://github.com/mdiallo15/secure-next-starter)
  shows one approach.
- Set `userVerification: "required"` (the lab uses `"preferred"` so it
  works on more devices).
- Pin attestation (`attestationType: "direct"`) and validate against the
  FIDO Metadata Service if you need attestation guarantees.
- Implement passkey-rotation and recovery flows. The lab has neither.

## License

MIT. See LICENSE.
