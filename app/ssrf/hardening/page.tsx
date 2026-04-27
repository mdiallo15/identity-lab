import Link from "next/link";

export const metadata = {
  title: "SSRF hardening — Labs",
};

export default function Hardening() {
  return (
    <>
      <h1>Hardening that actually contains it</h1>
      <p className="lede">
        SSRF is rarely fixable in one place. The application has to pass
        the request, the network has to route it, and the destination has
        to honor it. Break any of those and the chain dies. Break all
        four below and you've contained the blast radius even if the
        next bug lands.
      </p>

      <article className="shape">
        <h2>1. Make IMDSv2 required (or platform equivalent)</h2>
        <p>
          On AWS:
        </p>
        <pre>{`# Per launch template
HttpTokens: required
HttpPutResponseHopLimit: 1

# Or audit existing instances
aws ec2 describe-instances \\
  --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions.HttpTokens]' \\
  --output table`}</pre>
        <p>
          On GCP and Azure, the platform requires a header on every read.
          That's already analogous to IMDSv2's session-token model — but
          only against header-stripping SSRF primitives. The next layer
          is what catches the rest.
        </p>
      </article>

      <article className="shape">
        <h2>2. Egress firewall: link-local is non-egressable</h2>
        <p>
          Application processes have no business reaching{" "}
          <code>169.254.169.254</code>. The metadata service is for the{" "}
          <em>host</em>, not for application code. Block at the host
          firewall:
        </p>
        <pre>{`# nftables on Linux — drop link-local egress from app uid
nft add rule ip filter OUTPUT \\
  meta skuid != 0 ip daddr 169.254.0.0/16 drop

# Or via iptables
iptables -A OUTPUT -m owner --uid-owner app \\
  -d 169.254.0.0/16 -j DROP`}</pre>
        <p>
          On Kubernetes, do it at the NetworkPolicy / Calico /
          Cilium layer:
        </p>
        <pre>{`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: deny-link-local }
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
      - ipBlock:
          cidr: 0.0.0.0/0
          except: ["169.254.0.0/16", "127.0.0.0/8", "10.0.0.0/8"]`}</pre>
      </article>

      <article className="shape">
        <h2>3. URL validation: resolve before checking</h2>
        <p>
          The mistake that ships in 80% of homegrown URL validators is
          this:
        </p>
        <pre>{`// BROKEN
function isAllowed(rawUrl: string) {
  const u = new URL(rawUrl);
  if (u.hostname === "169.254.169.254") return false;
  return true;
}`}</pre>
        <p>
          That misses every encoding the{" "}
          <Link href="/ssrf/analyzer">analyzer</Link> covers: decimal,
          hex, octal, alias hostnames, DNS rebinding. The fix is to{" "}
          <em>resolve</em> the hostname to an IP, validate the IP
          against your blocklist, and then make the actual request to
          that resolved IP (with the original Host header for SNI).
          That last part — pinning the IP after validation — is what
          defeats DNS rebinding.
        </p>
        <pre>{`// Slightly better (still simplified)
async function safeFetch(rawUrl: string) {
  const u = new URL(rawUrl);
  if (!["http:", "https:"].includes(u.protocol)) throw "scheme";
  const ips = await dns.resolve(u.hostname);
  for (const ip of ips) {
    if (isPrivateOrMetadata(ip)) throw "blocked";
  }
  // Pin to first resolved IP and pass Host header for SNI
  return fetch("https://" + ips[0] + u.pathname + u.search, {
    headers: { host: u.hostname },
  });
}`}</pre>
        <p>
          In practice: don't roll this. Use a battle-tested library
          (Python <code>urllib3</code> with the SSRF protection patch,
          Go <code>net/http.DefaultTransport</code> with a custom dialer,
          a fronting proxy like Stripe's{" "}
          <a
            href="https://github.com/stripe/smokescreen"
            target="_blank"
            rel="noopener noreferrer"
          >
            Smokescreen
          </a>
          ).
        </p>
      </article>

      <article className="shape">
        <h2>4. Identity-layer scoping</h2>
        <p>
          The reason IMDS theft is catastrophic is that the IAM role
          attached to the instance is usually over-privileged. Even if
          layers 1–3 fail, a tightly-scoped instance role limits the
          blast radius:
        </p>
        <ul>
          <li>
            One role per instance type / per application. No shared
            "general-app" role.
          </li>
          <li>
            <em>No</em> wildcard <code>Resource: "*"</code> on
            sensitive actions (S3 GetObject, Secrets Manager, KMS).
          </li>
          <li>
            Use IAM <em>session tags</em> + <em>request conditions</em>{" "}
            to scope role usage by request context where possible.
          </li>
          <li>
            Detective controls: CloudTrail alerts on any IMDS-derived
            credential used from outside the instance's expected egress
            range — Capital One would have been caught here.
          </li>
        </ul>
      </article>

      <h2>The ranking that matters</h2>
      <p>If you can only ship three things this quarter:</p>
      <ol>
        <li>
          <strong>Egress-block link-local from app processes.</strong>{" "}
          One firewall rule. Kills the highest-impact attack class
          regardless of validator quality.
        </li>
        <li>
          <strong>Set IMDSv2 required</strong> on every AWS instance.
          One config flag. Gigantic upgrade against header-stripping
          SSRF primitives.
        </li>
        <li>
          <strong>Stop hand-rolling URL validators.</strong> Use a
          fronting proxy or a battle-tested library. The bypasses are
          too many to maintain in-house.
        </li>
      </ol>

      <h2>The agent angle</h2>
      <p>
        Every URL-fetching AI agent inherits this entire threat model.
        If the agent can be{" "}
        <Link href="/prompt-injection">prompt-injected</Link> into
        fetching a URL, your validation chain has to be at least as
        strict as if the user had submitted it. In most agent
        deployments today, it isn't.
      </p>
    </>
  );
}
