export const metadata = {
  title: "Four CSP shapes — Labs",
};

export default function Shapes() {
  return (
    <>
      <h1>The four CSP shapes</h1>
      <p className="lede">
        Almost every CSP I see in the wild is a variant of one of four
        shapes. Pick the right starting point and you save yourself the
        migration.
      </p>

      <article className="shape">
        <h2>1. Fully open (default state, also{" "}
          <code>'unsafe-inline'</code>)</h2>
        <pre>{`default-src 'self' 'unsafe-inline' 'unsafe-eval' https:;`}</pre>
        <p>
          What you get if you "added a CSP" without thinking. Inline scripts
          run, eval runs, any HTTPS host is trusted, no XSS protection
          beyond what the browser already gives you. <strong>Worse than
          no CSP</strong> in some ways because it gives a false sense of
          security.
        </p>
        <p className="when">
          <strong>When to use:</strong> never on production. Acceptable for
          5 minutes during initial rollout while you measure with{" "}
          <code>Content-Security-Policy-Report-Only</code>.
        </p>
      </article>

      <article className="shape">
        <h2>2. Allowlist (the most common)</h2>
        <pre>{`default-src 'self';
script-src 'self' https://cdn.jsdelivr.net https://www.googletagmanager.com;
style-src 'self' https://fonts.googleapis.com;
img-src 'self' data: https://images.example.com;
font-src 'self' https://fonts.gstatic.com;
object-src 'none';
base-uri 'self';
frame-ancestors 'none';
form-action 'self';
report-to csp-endpoint;`}</pre>
        <p>
          What 90% of teams ship. Works fine until your marketing team adds
          a sixth analytics vendor and someone adds <code>https:</code> to
          shut up the violations. Then it slowly degenerates into shape #1.
        </p>
        <p>
          <strong>Hidden risk:</strong> any allowlisted CDN that hosts JSONP
          endpoints (cdn.jsdelivr.net, ajax.googleapis.com historically)
          gives an attacker an XSS bypass. See the{" "}
          <a href="/csp/bypasses">bypasses</a> page.
        </p>
        <p className="when">
          <strong>When to use:</strong> mature server-rendered sites where
          you control every script you load. Not great for SPAs that pull
          in a lot of third-party JS at runtime.
        </p>
      </article>

      <article className="shape">
        <h2>3. Nonce-based (recommended for most)</h2>
        <pre>{`default-src 'self';
script-src 'nonce-{RANDOM}' 'strict-dynamic';
style-src 'self' 'nonce-{RANDOM}';
object-src 'none';
base-uri 'self';
frame-ancestors 'none';
form-action 'self';
report-to csp-endpoint;`}</pre>
        <p>
          The server generates a fresh random nonce per request, includes
          it in the CSP header, and stamps it on every legitimate{" "}
          <code>&lt;script&gt;</code> tag. Inline scripts work (because
          they have the right nonce); injected scripts don't (because the
          attacker doesn't know it). <code>'strict-dynamic'</code> means
          any script that runs with a valid nonce can pull in further
          scripts dynamically — no need to allowlist every CDN.
        </p>
        <p>
          <strong>This is what marwandiallo.com runs.</strong> Generated
          fresh per request via Next.js middleware.
        </p>
        <p className="when">
          <strong>When to use:</strong> server-rendered apps (Next.js,
          Rails, Django, ASP.NET). You need request-time control over the
          response.
        </p>
      </article>

      <article className="shape">
        <h2>4. Hash-based / pure 'strict-dynamic'</h2>
        <pre>{`default-src 'self';
script-src 'sha256-AbC123...' 'sha256-XyZ789...' 'strict-dynamic';
object-src 'none';
base-uri 'self';
frame-ancestors 'none';
form-action 'self';`}</pre>
        <p>
          For static sites where you can't generate per-request nonces.
          You hash the SHA-256 of every legitimate inline script at build
          time and embed the digests in the policy. Brittle (every script
          change rotates the hash) but works on a CDN-only static site.
        </p>
        <p className="when">
          <strong>When to use:</strong> static / CDN-served sites where
          you can't run server middleware. Or when you have a small,
          controlled set of inline scripts that rarely change.
        </p>
      </article>

      <h2>Picking the shape for you</h2>
      <ol className="action">
        <li>
          Server-rendered with a small number of routes? <strong>Nonce</strong>.
        </li>
        <li>
          Static site on a CDN? <strong>Hash</strong>, or move to a host
          that lets you set per-request headers.
        </li>
        <li>
          Existing app you can't rewrite? Start <strong>allowlist</strong>{" "}
          in <em>report-only mode</em>, watch the violations for a week,
          then switch to enforce. Plan migration to nonce as the next step.
        </li>
        <li>
          New app, no existing constraints? <strong>Nonce</strong> from
          day one.
        </li>
      </ol>
    </>
  );
}
