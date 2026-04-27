export const metadata = {
  title: "SSRF targets — Labs",
};

export default function Targets() {
  return (
    <>
      <h1>What's actually at the other end</h1>
      <p className="lede">
        Five endpoints attackers point SSRF at. Knowing what each one
        returns tells you exactly what's at risk if a fetch slips through
        validation.
      </p>

      <article className="shape">
        <h2>1. AWS Instance Metadata Service (IMDS)</h2>
        <p>
          <code>http://169.254.169.254/latest/meta-data/</code>
        </p>
        <pre>{`# IMDSv1 — vulnerable, still default on legacy AMIs
$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
my-app-role

$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/my-app-role
{
  "AccessKeyId":"ASIA...",
  "SecretAccessKey":"...",
  "Token":"...",
  "Expiration":"..."
}

# IMDSv2 — same endpoint, but token-required
$ curl -X PUT "http://169.254.169.254/latest/api/token" \\
       -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
AQAEA...

$ curl -H "X-aws-ec2-metadata-token: AQAEA..." \\
       http://169.254.169.254/latest/meta-data/iam/security-credentials/`}</pre>
        <p>
          IMDSv2 is a session-token model: the requester does a{" "}
          <code>PUT</code> first to acquire a short-lived token, then
          must include it in the metadata read. SSRF primitives that
          can only do <code>GET</code> can't do the PUT, which kills the
          most common bypass. Make IMDSv2 <em>required</em>{" "}
          (HttpTokens=required) on every instance and launch template.
        </p>
      </article>

      <article className="shape">
        <h2>2. GCP metadata server</h2>
        <p>
          <code>http://metadata.google.internal/computeMetadata/v1/</code>
        </p>
        <pre>{`$ curl -H "Metadata-Flavor: Google" \\
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
{ "access_token": "ya29....", "token_type": "Bearer", "expires_in": 3599 }`}</pre>
        <p>
          GCP requires the <code>Metadata-Flavor: Google</code> header on
          every read. SSRF primitives that can't set arbitrary headers
          (e.g., a backend that hardcodes <code>User-Agent</code> only)
          can't reach it. URL-fetcher SSRF that controls headers — most
          of them — sails through. Egress-block link-local from app
          processes; that's the durable fix here.
        </p>
      </article>

      <article className="shape">
        <h2>3. Azure IMDS</h2>
        <p>
          <code>http://169.254.169.254/metadata/instance?api-version=...</code>
        </p>
        <pre>{`$ curl -H "Metadata: true" \\
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"`}</pre>
        <p>
          Same shape as GCP — header-required, link-local IP. Same
          bypass class, same defense. <em>Managed Identity</em> on Azure
          gives away tokens for whatever Azure resources the VM's
          identity has been granted.
        </p>
      </article>

      <article className="shape">
        <h2>4. Internal Redis on loopback</h2>
        <p>
          <code>http://127.0.0.1:6379/</code>
        </p>
        <pre>{`# Plain HTTP fetch on Redis port — Redis ignores the malformed
# header and treats lines as commands. With gopher://, the bypass
# is even cleaner:

$ curl "gopher://127.0.0.1:6379/_FLUSHALL%0d%0aSET%20pwn%20rce%0d%0aSAVE"`}</pre>
        <p>
          Redis-via-SSRF was the high-impact bug-bounty pattern of 2017–2020.
          Modern Redis defaults (protected mode, requirepass) help; many
          deployments override or disable both. Defense: bind Redis to a
          Unix socket or a non-loopback address with a strict allowlist;
          block all gopher/file/dict/ftp schemes at the URL fetcher.
        </p>
      </article>

      <article className="shape">
        <h2>5. Kubernetes API server</h2>
        <p>
          <code>https://10.96.0.1:443/api/v1/...</code>
        </p>
        <pre>{`$ curl -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \\
       https://10.96.0.1:443/api/v1/namespaces/default/secrets`}</pre>
        <p>
          If your application pod has SSRF and a service-account token
          mounted (<em>which is the default</em>), the attacker can
          enumerate secrets, list pods, exec into them. The default
          service-account token is the most over-privileged credential
          in many clusters.
        </p>
        <p>
          Defense: <code>automountServiceAccountToken: false</code> on
          every pod that doesn't need it. <em>Pod Security Standards</em>{" "}
          plus a <em>NetworkPolicy</em> that denies pod-to-API-server
          traffic by default also work.
        </p>
      </article>

      <h2>The pattern</h2>
      <p>
        All five share a single property: they are services that{" "}
        <strong>trust the network</strong>. They authenticate by IP, by
        header presence, or by the simple fact that "you got a packet to
        me, you must be authorized." That assumption is what SSRF
        violates. The fix is at the layer that makes the assumption — not
        usually at the layer of the application that has the bug.
      </p>
    </>
  );
}
