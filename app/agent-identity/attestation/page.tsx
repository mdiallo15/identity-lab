import { ATTESTATION_OPTIONS } from "../../../lib/agent-identity";

export const metadata = {
  title: "Attestation primer — Agent Identity Lab",
  description:
    "Side-by-side comparison of the six workload-attestation surfaces a builder is most likely to wire up: GitHub Actions OIDC, AWS Nitro, Azure managed identity, GCP WIF, TPM 2.0, Apple App Attest.",
};

export default function AttestationPrimer() {
  return (
    <>
      <h1>Attestation primer</h1>
      <p className="lede">
        An agent's identity is only as strong as the platform that vouches for
        it. Attestation is the mechanism by which a workload <em>proves</em>{" "}
        what it is, rather than asserting it. The six options below are the
        ones a builder is most likely to wire up first, ranked by operational
        lift relative to the trust-root strength they provide.
      </p>

      <div style={{ overflowX: "auto", marginBlock: "1.5rem" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={th}>Surface</th>
              <th style={th}>Best for</th>
              <th style={th}>Binds to</th>
              <th style={th}>TTL</th>
              <th style={th}>Trust root</th>
            </tr>
          </thead>
          <tbody>
            {ATTESTATION_OPTIONS.map((o) => (
              <tr key={o.kind} style={{ borderTop: "1px solid #2a2a2a" }}>
                <td style={td}>
                  <strong>{o.label}</strong>
                </td>
                <td style={td}>{o.bestFor}</td>
                <td style={td}>{o.bindsTo}</td>
                <td style={td}>{o.ttl}</td>
                <td style={td}>{o.trustRoot}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2>Notes per surface</h2>
      <div className="cards">
        {ATTESTATION_OPTIONS.map((o) => (
          <article key={o.kind} className="card">
            <h3>{o.label}</h3>
            <p>
              <strong>Rotation:</strong> {o.rotation}
            </p>
            <p>{o.notes}</p>
          </article>
        ))}
      </div>

      <h2>How to pick</h2>
      <ul>
        <li>
          <strong>Most agents in CI today:</strong> GitHub Actions OIDC.
          Lowest-friction path off long-lived API keys; AWS, Azure, GCP all
          accept GitHub's OIDC tokens directly via federation.
        </li>
        <li>
          <strong>Agents on cloud compute:</strong> use the platform-native
          identity (Azure managed identity, AWS IAM Roles Anywhere or
          IRSA/Pod Identity, GCP WIF).
        </li>
        <li>
          <strong>Agents that touch sensitive data:</strong> AWS Nitro Enclave
          attestation or Azure Confidential Compute. The PCR measurement
          binds to the exact runtime image.
        </li>
        <li>
          <strong>On-prem or edge agents:</strong> TPM 2.0. Highest lift,
          highest trust-root strength.
        </li>
        <li>
          <strong>Endpoint-resident agents:</strong> Apple App Attest on
          Apple platforms; Play Integrity on Android.
        </li>
      </ul>

      <h2>Anti-pattern to avoid</h2>
      <p>
        A long-lived API key in a config file with no platform attestation, no
        sender-constraint, and no <code>act</code> claim on the issued token.
        This is the modal agent identity setup in 2026 and the one that shows
        up in incident reports first. The fix is not "rotate the key more
        often" — the fix is to retire the long-lived key class entirely and
        federate against one of the surfaces above.
      </p>

      <h2>References</h2>
      <ul>
        <li>
          <a
            href="https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect"
            target="_blank"
            rel="noopener noreferrer"
          >
            GitHub Actions OIDC documentation
          </a>
        </li>
        <li>
          <a
            href="https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html"
            target="_blank"
            rel="noopener noreferrer"
          >
            AWS Nitro Enclaves attestation concepts
          </a>
        </li>
        <li>
          <a
            href="https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview"
            target="_blank"
            rel="noopener noreferrer"
          >
            Azure managed identities overview
          </a>
        </li>
        <li>
          <a
            href="https://cloud.google.com/iam/docs/workload-identity-federation"
            target="_blank"
            rel="noopener noreferrer"
          >
            GCP Workload Identity Federation
          </a>
        </li>
        <li>
          <a
            href="https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/"
            target="_blank"
            rel="noopener noreferrer"
          >
            SPIFFE concepts
          </a>
        </li>
      </ul>
    </>
  );
}

const th: React.CSSProperties = {
  textAlign: "left",
  padding: "0.55rem 0.6rem",
  fontSize: "0.78rem",
  fontWeight: 600,
  color: "var(--ink-dim, #888)",
  borderBottom: "1px solid #2a2a2a",
};

const td: React.CSSProperties = {
  padding: "0.55rem 0.6rem",
  fontSize: "0.85rem",
  verticalAlign: "top",
};
