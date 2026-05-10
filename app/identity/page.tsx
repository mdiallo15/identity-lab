import Link from "next/link";

export const metadata = {
  title: "Identity Lab — Phishing-resistant authentication, hands-on",
  description:
    "Interactive playground for passwordless auth, WebAuthn passkeys, JWT analysis, and agent / workload identity. Built by Marwan Diallo.",
};

export default function Home() {
  return (
    <>
      <h1>Identity Lab</h1>
      <p className="lede">
        A hands-on playground for the auth model that's replacing passwords:
        passkeys, phishing-resistant MFA, and the workload-identity primitives
        that extend the same guarantees to AI agents.
      </p>

      <section className="hero-stat">
        <div>
          <strong>0</strong>
          <span>
            FIDO2 passkey logins have been successfully phished in the wild at
            scale. The origin binding makes it impossible.
          </span>
        </div>
        <div>
          <strong>~80%</strong>
          <span>
            of breaches still start with a stolen or phished credential (Verizon
            DBIR).
          </span>
        </div>
        <div>
          <strong>1 origin</strong>
          <span>
            is all a passkey will ever sign for. That's the whole trick.
          </span>
        </div>
      </section>

      <h2>Try it</h2>
      <div className="cards">
        <div className="card">
          <h3>Passwordless sign-in</h3>
          <p>
            Register a passkey on your device, then sign back in with no
            password and no OTP. Walks through every byte of the WebAuthn
            ceremony — including the origin binding that makes it phishing-
            resistant.
          </p>
          <Link href="/identity/passkey">Open demo →</Link>
        </div>
        <div className="card">
          <h3>JWT inspector</h3>
          <p>
            Paste a real token, see what's inside, and watch the analyzer flag
            <code> alg=none</code>, alg-confusion, missing <code>exp</code>, and
            PII leakage in real time.
          </p>
          <Link href="/identity/jwt">Open inspector →</Link>
        </div>
        <div className="card">
          <h3>JWT forging workbench</h3>
          <p>
            A live attacker workbench against a real WebCrypto verifier.
            Generate an RS256 token, forge a copy via alg=none (CVE-2015-9235),
            RS→HS confusion (CVE-2016-10555), kid path traversal, or claim
            tampering, then toggle verifier defenses and watch each forgery
            accepted or rejected.
          </p>
          <Link href="/identity/forge">Open workbench →</Link>
        </div>
        <div className="card">
          <h3>Phishing-resistant MFA, explained</h3>
          <p>
            Why FIDO2 / WebAuthn is the only mainstream MFA factor that survives
            a real-time AitM phishing kit. With diagrams of what actually
            happens on the wire.
          </p>
          <Link href="/identity/phishing-resistant">Read →</Link>
        </div>
        <div className="card">
          <h3>Agent identity</h3>
          <p>
            What a passkey is to a human, a workload credential is to an AI
            agent. Covers OIDC, SPIFFE/SPIRE, attestation, and the new problem:
            how do you authenticate an agent that{" "}
            <em>acts on a user's behalf</em>?
          </p>
          <Link href="/identity/agent-identity">Read →</Link>
        </div>
      </div>

      <h2>Why this exists</h2>
      <p>
        I spend my days auditing identity systems at Microsoft. The same bugs
        keep showing up: tokens accepted with{" "}
        <code>jwt.verify(token, secret)</code> {/* audit-ignore JS008 */}
        without an algorithm pinned, MFA prompts that any reverse-proxy phishing
        kit can replay, and now — agents handed long-lived API keys because
        nobody designed an identity model for them.
      </p>
      <p>
        This lab lets you touch the alternative: phishing-resistant
        authentication for humans, the same primitives extended to workloads,
        and the failure modes that cause both to be deployed insecurely.
      </p>

      <h2>Modeled on real guidance</h2>
      <ul className="standards">
        <li>
          <strong>NIST SP 800-63B-4 (draft)</strong> — phishing-resistant AAL3
        </li>
        <li>
          <strong>CISA Zero Trust Maturity Model</strong> — "phishing-resistant
          MFA" as the identity pillar baseline
        </li>
        <li>
          <strong>FIDO2 / WebAuthn Level 3</strong> — the protocol the demo
          implements
        </li>
        <li>
          <strong>OMB M-22-09</strong> — federal civilian agencies required to
          deploy phishing-resistant MFA
        </li>
        <li>
          <strong>SPIFFE / SPIRE</strong> — the de-facto workload-identity
          standard for agents and services
        </li>
      </ul>
    </>
  );
}
