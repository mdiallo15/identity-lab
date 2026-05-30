import Link from "next/link";
import { LearnCallout } from "@/app/_components/learn-callout";
import { ThreatModelCard } from "@/app/_components/threat-model";
import type { ThreatEntry } from "@/lib/labs";

const THREATS: readonly ThreatEntry[] = [
  {
    stride: "I",
    threat: "App fetches 169.254.169.254 \u2192 leaks instance credentials.",
    demo: { label: "analyzer (IMDSv1)", href: "/ssrf/analyzer" },
  },
  {
    stride: "T",
    threat: "Decimal / hex / octal IPv4 bypasses naive allowlist.",
    demo: { label: "analyzer", href: "/ssrf/analyzer" },
  },
  {
    stride: "T",
    threat: "DNS rebinding flips A-record between resolve and fetch.",
    demo: { label: "analyzer", href: "/ssrf/analyzer" },
  },
  {
    stride: "E",
    threat: "`gopher://` to Redis \u2192 unauth RCE on cache tier.",
    demo: { label: "analyzer", href: "/ssrf/analyzer" },
  },
];

export const metadata = {
  title: "SSRF / Cloud Metadata Lab — Labs",
  description:
    "Why 169.254.169.254 is the most-attacked IP on the internet. Validate URLs against the SSRF analyzer, see the canonical target endpoints, and learn the four hardening layers that actually contain blast radius.",
};

export default function SsrfOverview() {
  return (
    <>
      <h1>SSRF / Cloud Metadata Lab</h1>
      <LearnCallout href="/ssrf" />
      <ThreatModelCard entries={THREATS} />
      <p className="lede">
        Server-Side Request Forgery has been a top-10 web vulnerability since
        OWASP added it in 2021. The reason it stays there: every cloud platform
        exposes a metadata service at <code>169.254.169.254</code> that, until
        you harden the chain end-to-end, hands out IAM credentials to anything
        that asks.
      </p>

      <div className="hero-stat">
        <strong>Capital One, 2019.</strong> 100 million records. The finding
        chain: a misconfigured WAF allowed an outbound request, the request hit
        IMDSv1, the response carried IAM credentials, and the attacker walked
        the perms across the account. Every link of that chain is fixable. Most
        production environments still haven't fixed all of them.
      </div>

      <div className="cards">
        <Link href="/ssrf/analyzer" className="card">
          <h2>URL analyzer →</h2>
          <p>
            Paste any URL — or one of 8 attacker-crafted samples (decimal, hex,
            octal IPs, gopher://, alias hostnames). The analyzer decodes the
            canonical destination and flags 8 SSRF-relevant properties
            (SSRF01–SSRF08).
          </p>
        </Link>

        <Link href="/ssrf/targets" className="card">
          <h2>Targets →</h2>
          <p>
            The five endpoints attackers point SSRF at: AWS IMDS, GCP metadata,
            Azure IMDS, internal Redis, Kubernetes API. Real request/response
            pairs for each.
          </p>
        </Link>

        <Link href="/ssrf/hardening" className="card">
          <h2>Hardening →</h2>
          <p>
            Four layers that work together: IMDSv2 (or platform equivalent),
            egress firewall, URL validation that resolves before checking, and
            identity-layer scoping. Ranked by impact.
          </p>
        </Link>
      </div>

      <h2>Why this matters more in 2026 than 2019</h2>
      <p>
        Every AI agent that fetches URLs on a user's behalf is one misvalidated
        input away from being an SSRF tool. Browser-using agents, RAG pipelines
        that pull URLs from documents, summarize- this-link bots — all of them
        ship with the same primitive that Capital One's WAF had: "fetch what the
        input says, return the body."
      </p>
      <p>
        That's why this lab pairs with{" "}
        <Link href="/prompt-injection">Prompt Injection</Link>. A successful
        prompt-injection that gets the agent to fetch{" "}
        <code>http://169.254.169.254/latest/meta-data/iam/...</code> is the same
        Capital One attack chain — just routed through an LLM instead of a WAF
        rule.
      </p>

      <h2>Read in order</h2>
      <ol>
        <li>
          <Link href="/ssrf/analyzer">Analyzer</Link> — get a feel for what
          bypasses look like.
        </li>
        <li>
          <Link href="/ssrf/targets">Targets</Link> — what's actually at the
          other end.
        </li>
        <li>
          <Link href="/ssrf/hardening">Hardening</Link> — what to ship.
        </li>
      </ol>
    </>
  );
}
