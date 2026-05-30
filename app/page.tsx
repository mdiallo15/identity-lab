import Link from "next/link";
import { isNewLab } from "@/lib/labs";

export const metadata = {
  title: "Labs — Marwan Diallo",
  description:
    "Hands-on security labs by Marwan Diallo. Phishing-resistant identity, content security policy, and other topics that don't survive PowerPoint.",
};

// Render a small "new" chip next to Live for labs flagged in lib/labs.ts.
// Auto-clears after NEW_WINDOW_DAYS so the page never carries stale flags.
function NewPill({ href }: { href: string }) {
  if (!isNewLab(href)) return null;
  return <span className="lab-tile__chip lab-tile__chip--new">new</span>;
}

export default function LabsIndex() {
  return (
    <>
      <h1>Labs</h1>
      <p className="lede">
        Hands-on, opinionated security playgrounds. Each lab pairs a working
        demo with the failure modes I&apos;ve actually seen in production.
        Built because the topics here don&apos;t survive PowerPoint.
      </p>

      <div className="lab-grid">
        {/* --- Newest first ------------------------------------------------ */}

        <Link
          href="/detection-engineering"
          className="lab-tile"
          data-tag="defense"
        >
          <span className="lab-tile__chip">Live</span>
          <NewPill href="/detection-engineering" />
          <h2>Detection Engineering</h2>
          <p>
            Real Sysmon, CloudTrail, and Entra sign-in telemetry from real
            incidents (Midnight Blizzard 2024, Volt Typhoon, Storm-0558),
            ground-truth labeled, with a naive and a tuned Sigma-style rule
            for each. Edit either rule&apos;s match tree as JSON and watch
            precision, recall, and F1 update live. Plus one Sigma-equivalent
            starter rule per lab domain.
          </p>
          <ul className="lab-tile__bullets">
            <li>Five attack scenarios, ground-truth labeled</li>
            <li>Sigma-equivalent match engine (eq/regex/and/or/not)</li>
            <li>Live precision / recall / F1 metrics</li>
            <li>Per-lab Sigma starter rules (CSP / JWT / SSRF / IAM / …)</li>
          </ul>
          <span className="lab-tile__cta">Open lab →</span>
        </Link>

        <Link href="/agent-identity" className="lab-tile" data-tag="ai">
          <span className="lab-tile__chip">Live</span>
          <NewPill href="/agent-identity" />
          <h2>Agent Identity Lab</h2>
          <p>
            RFC 8693 token exchange in motion: pick a user, an agent, scopes,
            a TTL, and watch all three JWTs decoded side-by-side with a claims
            diff explaining what came from <code>subject_token</code>, what
            came from <code>actor_token</code>, and what the STS narrowed.
            Run the eight-rule drift detector against a fixture inventory of
            seven agents.
          </p>
          <ul className="lab-tile__bullets">
            <li>RFC 8693 token-exchange playground with claims diff</li>
            <li>8-rule drift detector (AGT01–AGT08)</li>
            <li>Six attestation surfaces compared</li>
            <li>Companion to the Agent Identity Front essay</li>
          </ul>
          <span className="lab-tile__cta">Open lab →</span>
        </Link>

        <Link href="/iam-privesc" className="lab-tile" data-tag="cloud">
          <span className="lab-tile__chip">Live</span>
          <NewPill href="/iam-privesc" />
          <h2>IAM Privilege Escalation</h2>
          <p>
            A live attack-path enumerator across AWS, Azure, and GCP. Edit a
            principal directory and watch the engine derive every transition
            from the {`{12}`}-technique catalog (PassRole+RunInstances,
            UpdateAssumeRolePolicy, Application.ReadWrite.All,
            iam.serviceAccounts.actAs) and BFS to admin. Modeled on Pacu,
            CloudGoat, and AzureHound.
          </p>
          <ul className="lab-tile__bullets">
            <li>12 published privesc techniques across three clouds</li>
            <li>Editable principal graph with live path enumeration</li>
            <li>Multi-hop chains through groups and roles</li>
            <li>Citations to Rhino, SpecterOps, hackingthe.cloud</li>
          </ul>
          <span className="lab-tile__cta">Open lab →</span>
        </Link>

        <Link href="/supply-chain" className="lab-tile" data-tag="supply-chain">
          <span className="lab-tile__chip">Live</span>
          <NewPill href="/supply-chain" />
          <h2>Supply Chain Lab</h2>
          <p>
            Real registry compromises, replayed against a live provenance
            analyzer. Replicas of event-stream (2018), ua-parser-js (2021),
            node-ipc (2022), 3CX (2023), XZ Utils (2024), Ultralytics (2024),
            LottieFiles (2024), and tj-actions (2025). Seven detection rules
            covering install hooks, rapid republish, publisher-IP drift,
            missing build provenance, and known typosquat patterns.
          </p>
          <ul className="lab-tile__bullets">
            <li>Eight real-incident replicas with citations</li>
            <li>7-rule provenance analyzer (PROV01–PROV07)</li>
            <li>Ten typosquat patterns drawn from real campaigns</li>
            <li>Sigstore / npm-provenance verification flow</li>
          </ul>
          <span className="lab-tile__cta">Open lab →</span>
        </Link>

        <Link href="/rag" className="lab-tile" data-tag="ai">
          <span className="lab-tile__chip">Live</span>
          <NewPill href="/rag" />
          <h2>RAG Security Lab</h2>
          <p>
            Real attacks against retrieval-augmented generation, replayed with
            a deterministic in-browser vector store. Indirect prompt injection
            (Greshake 2023), PoisonedRAG ranking attacks (Zou 2024), markdown
            image canary exfil, citation forgery, training-data extraction
            (Carlini 2023). Naive vs four-defense hardened agent side by side.
          </p>
          <ul className="lab-tile__bullets">
            <li>Six published attacks reproduced with full traces</li>
            <li>Spotlighting + URL allowlist + grounding + dedup</li>
            <li>Live retrievals with cosine-similarity scores</li>
            <li>Four-rule corpus analyzer (RAG01–RAG04)</li>
          </ul>
          <span className="lab-tile__cta">Open lab →</span>
        </Link>

        <Link href="/prompt-injection" className="lab-tile" data-tag="ai">
          <span className="lab-tile__chip">Live</span>
          <NewPill href="/prompt-injection" />
          <h2>Prompt Injection Lab</h2>
          <p>
            Indirect prompt injection, tool-call hijacking, exfiltration via
            markdown images. A deterministic side-by-side simulator of a
            naive vs hardened agent on identical attacker-crafted documents,
            now with a five-tool agent loop, 12 scenarios, and exportable
            telemetry. No LLM API key required.
          </p>
          <ul className="lab-tile__bullets">
            <li>Live five-tool agent loop, 12 scenarios</li>
            <li>10-rule injection detector (PI01–PI10)</li>
            <li>Hardened-policy editor with live re-runs</li>
            <li>JSON telemetry export</li>
          </ul>
          <span className="lab-tile__cta">Open lab →</span>
        </Link>

        <Link href="/ssrf" className="lab-tile" data-tag="net">
          <span className="lab-tile__chip">Live</span>
          <NewPill href="/ssrf" />
          <h2>SSRF / Cloud Metadata</h2>
          <p>
            Why <code>169.254.169.254</code> is the most-attacked IP on the
            internet. Live fetcher sandbox replaying 10 payloads (decimal /
            hex / octal IPv4, IPv6 loopback, DNS rebinding, AWS IMDSv1,
            GCP-via-Host-smuggle, Redis CRLF, K8s API ServiceAccount, gopher
            → Redis RCE) through a naive fetcher and a hardened one
            side-by-side.
          </p>
          <ul className="lab-tile__bullets">
            <li>Live fetcher sandbox with 10-scenario catalog</li>
            <li>Naive vs hardened (H-SCHEME / H-CRLF / H-IPRANGE / …)</li>
            <li>Sandboxed /api/ssrf-fetch for curl + SIEM replay</li>
            <li>Capital One IMDS, Orange Tsai 2017, OWASP cheat sheet</li>
          </ul>
          <span className="lab-tile__cta">Open lab →</span>
        </Link>

        {/* --- Long-running tiles below the fold --------------------------- */}

        <Link href="/identity" className="lab-tile" data-tag="identity">
          <span className="lab-tile__chip">Live</span>
          <NewPill href="/identity/forge" />
          <h2>Identity Lab</h2>
          <p>
            Phishing-resistant authentication, end to end. Register a passkey
            in your browser, decode real JWTs and see what makes them
            forgeable, and learn how the same primitives apply to AI agents
            acting on a user&apos;s behalf. Now with a JWT forging workbench
            against an intentionally-misconfigurable verifier.
          </p>
          <ul className="lab-tile__bullets">
            <li>WebAuthn / passkey registration + sign-in</li>
            <li>JWT inspector + forging workbench (4 CVE-class attacks)</li>
            <li>Phishing-resistant MFA explainer</li>
            <li>Agent identity (OIDC, SPIFFE, RFC 8693)</li>
          </ul>
          <span className="lab-tile__cta">Open lab →</span>
        </Link>

        <Link href="/csp" className="lab-tile" data-tag="csp">
          <span className="lab-tile__chip">Live</span>
          <h2>CSP Playground</h2>
          <p>
            Paste a Content-Security-Policy header, watch the analyzer flag
            the same patterns I flag in client engagements: unsafe-inline,
            wildcards, missing object-src, no nonce, no report-uri. Then see
            the four canonical CSP shapes side by side.
          </p>
          <ul className="lab-tile__bullets">
            <li>Live CSP header analyzer (12 rules)</li>
            <li>Four canonical policy shapes compared</li>
            <li>Common bypass patterns (JSONP, base-uri, dangling markup)</li>
            <li>Migration path from unsafe-inline to nonces</li>
          </ul>
          <span className="lab-tile__cta">Open lab →</span>
        </Link>

        <Link href="/authz" className="lab-tile" data-tag="api">
          <span className="lab-tile__chip">Live</span>
          <h2>AuthZ Lab — IDOR / BOLA</h2>
          <p>
            Broken Object Level Authorization is OWASP API Top 10 #1. Pick a
            user, ask for someone else&apos;s order ID, and watch the naive
            endpoint hand it over while the hardened endpoint returns 404.
            Eight detection rules covering missing owner scope, 403-vs-404
            leakage, sequential IDs, and mass-assignment.
          </p>
          <ul className="lab-tile__bullets">
            <li>Naive vs hardened endpoint simulator</li>
            <li>8-rule pattern catalog (BOLA01–BOLA08)</li>
            <li>SARIF/JSON export of the ruleset</li>
            <li>Pairs with the AuthN work in Identity Lab</li>
          </ul>
          <span className="lab-tile__cta">Open lab →</span>
        </Link>
      </div>

      <h2>Why labs</h2>
      <p>
        Every security finding I&apos;ve ever written has been more
        convincing when the reader could touch the bug. Slide decks let
        people nod along; a working demo, with the actual headers on the
        actual wire, is what changes architecture decisions.
      </p>
      <p>
        These labs cost nothing to run, are linkable in a code review, and
        each one is a complete teaching artifact in under five minutes. If
        you&apos;re an engineer trying to convince a leader, or a leader
        trying to understand an engineer, that&apos;s what they&apos;re for.
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
