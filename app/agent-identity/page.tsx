import Link from "next/link";
import { LearnCallout } from "@/app/_components/learn-callout";
import { ThreatModelCard } from "@/app/_components/threat-model";
import type { ThreatEntry } from "@/lib/labs";

const THREATS: readonly ThreatEntry[] = [
  {
    stride: "S",
    threat: "Agent presents user JWT directly \u2014 no `act` claim, no attribution.",
    demo: { label: "token-exchange", href: "/agent-identity/token-exchange" },
  },
  {
    stride: "R",
    threat: "Long-lived API key with no `exp` \u2014 cannot revoke or audit.",
    demo: { label: "inventory", href: "/agent-identity/inventory" },
  },
  {
    stride: "E",
    threat: "Scope drift: agent inherits user scopes wholesale at STS.",
    demo: { label: "token-exchange", href: "/agent-identity/token-exchange" },
  },
  {
    stride: "T",
    threat: "Missing workload attestation \u2014 anyone with the secret is the agent.",
    demo: { label: "attestation", href: "/agent-identity/attestation" },
  },
];

export const metadata = {
  title: "Agent Identity Lab — labs.marwandiallo.com",
  description:
    "Hands-on workload identity for AI agents: RFC 8693 token exchange, attested workload primitives, and a live drift detector on a fixture agent inventory.",
  openGraph: {
    title: "Agent Identity Lab — Marwan Diallo",
    description:
      "RFC 8693 token exchange, workload attestation, and live agent-identity drift detection.",
    type: "website",
    url: "https://lab.marwandiallo.com/agent-identity",
  },
  twitter: {
    card: "summary_large_image",
    title: "Agent Identity Lab — Marwan Diallo",
    description:
      "RFC 8693 token exchange, workload attestation, and live agent-identity drift detection.",
  },
};

export default function AgentIdentityLab() {
  return (
    <>
      <h1>Agent Identity Lab</h1>
      <LearnCallout href="/agent-identity" />
      <ThreatModelCard entries={THREATS} />
      <p className="lede">
        Most agents in production today authenticate with a long-lived API key
        in a config file. The fix is the same family of primitives that put
        passkeys in front of human users — short-lived credentials, hardware
        attestation, sender-constraint, and a delegation claim that makes
        user-on-behalf-of-agent calls attributable in audit logs. This lab is
        three working demos of those primitives, no IdP required.
      </p>

      <section className="hero-stat">
        <div>
          <strong>RFC 8693</strong>
          <span>
            OAuth 2.0 Token Exchange — the standards-track mechanism for
            user→agent delegation, anchored on the <code>act</code> claim.
          </span>
        </div>
        <div>
          <strong>4 attestation surfaces</strong>
          <span>
            GitHub Actions OIDC, AWS Nitro, Azure managed identity, GCP WIF —
            all four eliminate long-lived secrets if you wire them up.
          </span>
        </div>
        <div>
          <strong>8 drift rules</strong>
          <span>
            AGT01–AGT08: long-lived secrets, missing attestation, scope drift,
            dormant agents, audit gaps, shared identities.
          </span>
        </div>
      </section>

      <h2>Three things in this lab</h2>
      <div className="cards">
        <div className="card">
          <h3>Token-exchange playground</h3>
          <p>
            Pick a user (passkey-authenticated, current or offboarded), pick an
            agent (with or without attestation), pick scopes and a TTL, and see
            the RFC 8693 request, the resulting delegated token claims, the
            audit-log line, and the warnings the IdP would flag.
          </p>
          <Link href="/agent-identity/token-exchange">Open playground →</Link>
        </div>
        <div className="card">
          <h3>Inventory + drift detector</h3>
          <p>
            Seven-agent fixture inventory across four attestation surfaces.
            Eight drift rules flag long-lived secrets, scope drift since
            baseline, dormant agents, missing <code>act</code> claims, and
            shared workload identities. SARIF export.
          </p>
          <Link href="/agent-identity/inventory">Run analysis →</Link>
        </div>
        <div className="card">
          <h3>Attestation primer</h3>
          <p>
            Side-by-side comparison of the six attestation surfaces a builder
            is most likely to wire up first: GitHub OIDC, AWS Nitro, Azure
            managed identity, GCP WIF, TPM 2.0, Apple App Attest. Pick by
            operational lift vs trust-root strength.
          </p>
          <Link href="/agent-identity/attestation">Compare options →</Link>
        </div>
      </div>

      <h2>Why this lab</h2>
      <p>
        The companion essay to this lab —{" "}
        <a
          href="https://marwandiallo.com/writing/agent-identity-front"
          target="_blank"
          rel="noopener noreferrer"
        >
          The Agent Identity Front
        </a>{" "}
        — argues that AI agent identity is the next major vulnerability vector
        and that the gap between adoption velocity and governance velocity is
        widening. This lab is the working demo of the primitives that close the
        gap.
      </p>
      <p>
        The drift rules are the patterns I see in consulting engagements
        repeatedly: long-lived secrets in config files, agents authenticating
        without attestation, scope drift over months, dormant agents that
        nobody has retired, audit logs that record the human as the actor when
        the agent is the one running the call.
      </p>

      <h2>Pairs with</h2>
      <ul>
        <li>
          <Link href="/identity">Identity Lab</Link> — passkey registration,
          JWT inspector, and the three-identities explainer this lab builds on.
        </li>
        <li>
          <Link href="/prompt-injection">Prompt Injection Lab</Link> — the
          attack surface a delegated agent token is supposed to bound.
        </li>
        <li>
          <Link href="/authz">AuthZ Lab</Link> — what the agent's downscoped
          token meets when it lands on the resource server.
        </li>
      </ul>
    </>
  );
}
