# identity-lab

Interactive playground for the identity primitives most teams misuse.

> Built by [Marwan Diallo](https://marwandiallo.com) — security architect at
> Microsoft, founder of Diallo Group. Companion to writing on identity at
> marwandiallo.com.

## Two tools (v0.1)

### JWT inspector — `/jwt`

Pure client-side JWT decoder with security findings:

- `alg=none` / empty signature
- Missing or expired `exp`
- Missing `iss` / `aud`
- HMAC algorithm with a public-IdP `iss` (alg-confusion smell)
- PII in payload (email without `email_verified`, SSN-like keys)

The token never leaves your browser.

### Passkey demo — `/passkey`

Working WebAuthn registration + authentication using
[@simplewebauthn](https://simplewebauthn.dev). Stores credentials in memory
keyed by username — perfect for kicking the tires, terrible for production.
Resets every server restart.

## Run it

```bash
git clone https://github.com/mdiallo15/identity-lab
cd identity-lab
npm install
npm run dev
# open http://localhost:3000
```

Passkeys require an HTTPS origin or `localhost`. Both work out of the box.

## Roadmap

- [ ] OIDC ID token "what your IdP actually signed" diff view (Google,
      Microsoft, Okta, Auth0)
- [ ] SAML AuthnResponse inspector (XML signature + assertion claims)
- [ ] Persisted credentials via SQLite (so the demo survives restarts)
- [ ] Conditional-UI passkey ceremony (auto-fill from password manager)
- [ ] mTLS client cert inspector

## License

MIT — see [LICENSE](./LICENSE).
