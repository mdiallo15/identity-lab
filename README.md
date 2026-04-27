# marwandiallo-labs

Hands-on security labs. Live at **[lab.marwandiallo.com](https://lab.marwandiallo.com)**.

> Built by [Marwan Diallo](https://marwandiallo.com) — security architect at
> Microsoft, founder of Diallo Group. Each lab pairs a working demo with the
> failure modes I've actually seen in production.

## Labs

### Identity Lab — `/identity`

- **Passkey demo** (`/identity/passkey`) — working WebAuthn registration +
  sign-in via `@simplewebauthn`. In-memory store. Resets on deploy.
- **JWT inspector** (`/identity/jwt`) — client-side decoder that flags
  `alg=none`, alg-confusion, missing `exp`/`iss`/`aud`, PII leakage.
- **Phishing-resistant MFA** (`/identity/phishing-resistant`) — the four MFA
  archetypes ranked, deployment patterns, and the failure modes that defeat
  even well-deployed FIDO2 (helpdesk bypass, soft fallback).
- **Agent identity** (`/identity/agent-identity`) — workload identity,
  SPIFFE/SPIRE, attestation, RFC 8693 token exchange, and the broken models
  most agent platforms ship today.

### CSP Playground — `/csp`

- **Analyzer** (`/csp/analyzer`) — paste a Content-Security-Policy, get 12
  rules of findings ranked by severity, with fixes. Pure client-side.
- **Four shapes** (`/csp/shapes`) — fully open / allowlist / nonce /
  hash, with the actual headers and when to use each.
- **Bypasses** (`/csp/bypasses`) — JSONP, dangling-markup, "unsafe-inline
  just for legacy," and the three other patterns I see most often.

### Planned

- **Prompt Injection Lab** — indirect injection, tool-call hijacking,
  agent-on-behalf-of confusion.
- **SSRF / Cloud Metadata Lab** — IMDSv2, link-local hardening, egress
  policy.

## Architecture

Single Next.js app, route-grouped by lab. Routes:

```
/                       hub index
/identity/*             Identity Lab
/csp/*                  CSP Playground
/api/identity/passkey/* WebAuthn API (in-memory store)
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
