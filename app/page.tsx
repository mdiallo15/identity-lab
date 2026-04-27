import Link from "next/link";

export const metadata = {
  title: "Labs — Marwan Diallo",
  description:
    "Hands-on security labs by Marwan Diallo. Phishing-resistant identity, content security policy, and other topics that don't survive PowerPoint.",
};

export default function LabsIndex() {
  return (
    <>
      <h1>Labs</h1>
      <p className="lede">
        Hands-on, opinionated security playgrounds. Each lab pairs a working
        demo with the failure modes I've actually seen in production. Built
        because the topics here don't survive PowerPoint.
      </p>

      <div className="lab-grid">
        <Link href="/identity" className="lab-tile" data-tag="identity">
          <span className="lab-tile__chip">Live</span>
          <h2>Identity Lab</h2>
          <p>
            Phishing-resistant authentication, end to end. Register a passkey in
            your browser, decode real JWTs and see what makes them forgeable,
            and learn how the same primitives apply to AI agents acting on a
            user's behalf.
          </p>
          <ul className="lab-tile__bullets">
            <li>WebAuthn / passkey registration + sign-in</li>
            <li>JWT inspector with 8 alg-confusion / PII findings</li>
            <li>Phishing-resistant MFA explainer</li>
            <li>Agent identity (OIDC, SPIFFE, RFC 8693)</li>
          </ul>
          <span className="lab-tile__cta">Open lab →</span>
        </Link>

        <Link href="/csp" className="lab-tile" data-tag="csp">
          <span className="lab-tile__chip">Live</span>
          <h2>CSP Playground</h2>
          <p>
            Paste a Content-Security-Policy header, watch the analyzer flag the
            same patterns I flag in client engagements: unsafe-inline,
            wildcards, missing object-src, no nonce, no report-uri. Then see the
            four canonical CSP shapes side by side.
          </p>
          <ul className="lab-tile__bullets">
            <li>Live CSP header analyzer (12 rules)</li>
            <li>Four canonical policy shapes compared</li>
            <li>Common bypass patterns (JSONP, base-uri, dangling markup)</li>
            <li>Migration path from unsafe-inline to nonces</li>
          </ul>
          <span className="lab-tile__cta">Open lab →</span>
        </Link>

        <Link href="/prompt-injection" className="lab-tile" data-tag="ai">
          <span className="lab-tile__chip">Live</span>
          <h2>Prompt Injection Lab</h2>
          <p>
            Indirect prompt injection, tool-call hijacking, exfiltration via
            markdown images. A deterministic side-by-side simulator of a naive
            vs hardened agent on identical attacker-crafted documents. No LLM
            API key required.
          </p>
          <ul className="lab-tile__bullets">
            <li>Naive vs hardened agent simulator (6 samples)</li>
            <li>10-rule injection detector (PI01–PI10)</li>
            <li>Defense playbook ranked by impact</li>
            <li>Pairs with the agent identity work in Identity Lab</li>
          </ul>
          <span className="lab-tile__cta">Open lab →</span>
        </Link>

        <Link href="/ssrf" className="lab-tile" data-tag="net">
          <span className="lab-tile__chip">Live</span>
          <h2>SSRF / Cloud Metadata</h2>
          <p>
            Why <code>169.254.169.254</code> is the most-attacked IP on the
            internet. URL analyzer that decodes decimal, hex, octal, and
            alias-hostname bypasses; a tour of the five canonical SSRF
            targets; and the four hardening layers ranked by impact.
          </p>
          <ul className="lab-tile__bullets">
            <li>URL bypass analyzer (8 sample payloads)</li>
            <li>AWS IMDS, GCP, Azure, Redis, Kubernetes targets</li>
            <li>IMDSv2, egress firewall, SSRF-safe URL validation</li>
            <li>Identity-layer scoping for blast-radius control</li>
          </ul>
          <span className="lab-tile__cta">Open lab →</span>
        </Link>
      </div>

      <h2>Why labs</h2>
      <p>
        Every security finding I've ever written has been more convincing when
        the reader could touch the bug. Slide decks let people nod along; a
        working demo, with the actual headers on the actual wire, is what
        changes architecture decisions.
      </p>
      <p>
        These labs cost nothing to run, are linkable in a code review, and each
        one is a complete teaching artifact in under five minutes. If you're an
        engineer trying to convince a leader, or a leader trying to understand
        an engineer, that's what they're for.
      </p>

      <h2>Source</h2>
      <p>
        Everything is open source under MIT.{" "}
        <a
          href="https://github.com/mdiallo15/identity-lab"
          target="_blank"
          rel="noopener noreferrer"
        >
          github.com/mdiallo15/identity-lab
        </a>
        . Issues and PRs welcome.
      </p>
    </>
  );
}
