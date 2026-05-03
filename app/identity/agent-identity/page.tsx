import Link from "next/link";

export const metadata = {
  title: "Agent identity — Identity Lab",
  description:
    "What a passkey is to a human, a workload credential is to an AI agent. OIDC, SPIFFE, attestation, and the hard problem of agents acting on a user's behalf.",
};

export default function AgentIdentityPage() {
  return (
    <>
      <h1>Agent identity</h1>
      <p className="lede">
        Every conversation about passkeys ends with the same question:{" "}
        <em>
          great, but my AI agent has an OpenAI API key in a config file — how is
          that any better than a password?
        </em>{" "}
        It's not. The fix uses the same building blocks as WebAuthn, applied to
        workloads.
      </p>

      <h2>Three identities, not one</h2>
      <p>
        When an agent runs a task on your behalf, three identities are in play.
        Most platforms collapse them and that's where the security model breaks.
      </p>
      <ul className="triple">
        <li>
          <strong>User identity.</strong> Who you are. Authenticated with a
          passkey, ideally. Bounded by your AAL (NIST 800-63).
        </li>
        <li>
          <strong>Agent identity.</strong> Which agent — which model deployment,
          which container, which version — is running. This is a workload
          identity, not a human one.
        </li>
        <li>
          <strong>Delegation.</strong> The signed claim that says "this user
          authorized this agent to do these specific actions for this much
          time." The piece almost everyone is missing today.
        </li>
      </ul>

      <h2>Workload identity primitives</h2>
      <dl>
        <dt>OIDC for workloads (federated tokens)</dt>
        <dd>
          GitHub Actions, AWS, Azure, GCP, Kubernetes — they all issue OIDC
          tokens to running workloads. The token is short-lived, attested by the
          platform, and the relying party verifies it the same way it verifies a
          human's ID token. No long-lived API key needed.
          <br />
          <em>Real example:</em> the GitHub Actions runner on this lab's CI
          could authenticate to Vercel with no stored secret — just an OIDC
          token Vercel verifies against GitHub's JWKS.
        </dd>

        <dt>SPIFFE / SPIRE</dt>
        <dd>
          The CNCF standard. Every workload gets an X.509 SVID — a short-lived
          cert with a SPIFFE ID like{" "}
          <code>spiffe://prod/agent/code-reviewer/v3</code>. The SPIRE agent
          mints them on demand based on attested workload selectors (process
          UID, k8s service account, hardware TPM). Used by Bloomberg, Spotify,
          and most large platforms running mTLS at scale.
        </dd>

        <dt>Hardware attestation</dt>
        <dd>
          The agent doesn't <em>say</em> it's running on a trusted node, it{" "}
          <em>proves</em> it via TPM quote, AWS Nitro attestation, Azure
          Confidential Compute, or Apple App Attest. The same property that
          makes a passkey unphishable (non-exportable, hardware-bound) extends
          to the workload credential.
        </dd>

        <dt>Token-bound delegation</dt>
        <dd>
          OAuth 2.0 token exchange (RFC 8693) lets a user's passkey-issued token
          be downgraded into a narrower, time-boxed token for the agent. The
          agent's token is bound to its workload identity via DPoP (RFC 9449),
          so a stolen token can't be used elsewhere.
        </dd>
      </dl>

      <h2>The unsolved problem: agent-on-behalf-of-user</h2>
      <p>Today, most agent platforms ship one of these two broken models:</p>
      <ol className="bad-models">
        <li>
          <strong>Shared secret model.</strong> The agent has a long-lived API
          key for the LLM provider, plus another long-lived token for every tool
          it calls (GitHub PAT, calendar token, Stripe key). Steal the agent's
          container, get keys to everything. This is most agents in production
          right now.
        </li>
        <li>
          <strong>Impersonation model.</strong> The agent uses <em>your</em>{" "}
          credentials directly. Whatever you can do, the agent can do, with no
          audit distinction. Your access logs say "user did X" when the agent
          did X.
        </li>
      </ol>

      <h2>What a clean model looks like</h2>
      <ol className="action">
        <li>
          User authenticates with a passkey → receives a session token at AAL2 /
          AAL3.
        </li>
        <li>
          User invokes agent → token-exchange (RFC 8693) downgrades the session
          into a narrower agent token: scope ={" "}
          <code>read:repo write:issues</code>, audience ={" "}
          <code>github.com</code>, ttl = 5 minutes, actor claim ={" "}
          <code>spiffe://prod/agent/code-reviewer/v3</code>.
        </li>
        <li>
          Agent calls GitHub. GitHub sees both <code>sub</code> (the user) and{" "}
          <code>act</code> (the agent), logs the agent identity in the audit
          trail, enforces scope.
        </li>
        <li>
          Token expires in 5 minutes. Agent that needs to keep working
          re-requests, which the user can revoke at any time without changing
          their own credentials.
        </li>
      </ol>
      <p>
        This is what OIDC's <code>act</code> claim and OAuth 2.0 Token Exchange
        were designed for. Almost nobody uses them yet for agents. That's the
        gap.
      </p>

      <h2>Practical guidance for builders</h2>
      <ul className="gotchas">
        <li>
          <strong>Never give an agent a long-lived secret.</strong> Use
          short-lived OIDC tokens, federated from your platform's identity
          provider.
        </li>
        <li>
          <strong>Identify the agent, not just the user.</strong> Your audit
          logs need to say "Claude code-reviewer v3 acting on behalf of
          marwan@..." — not just the user.
        </li>
        <li>
          <strong>Bound scopes per task.</strong> The agent doing a code review
          doesn't need <code>repo:write</code>. Token-exchange every tool call
          to the minimum scope required.
        </li>
        <li>
          <strong>Revoke independently.</strong> Compromising an agent should
          not require rotating the user's passkey.
        </li>
        <li>
          <strong>Attest where you can.</strong> If your agent runs on
          Confidential Compute or a TEE, use platform attestation instead of
          shared secrets to bootstrap identity.
        </li>
      </ul>

      <h2>Read next</h2>
      <p>
        <Link href="/agent-identity">
          Open the Agent Identity Lab (RFC 8693 playground + drift detector +
          attestation primer) →
        </Link>
        <br />
        <Link href="/identity/phishing-resistant">
          Phishing-resistant MFA, on the wire →
        </Link>
        <br />
        <Link href="/identity/passkey">Try a passkey registration →</Link>
        <br />
        <Link href="/identity/jwt">
          Inspect a token (try one with an <code>act</code> claim) →
        </Link>
      </p>
    </>
  );
}
