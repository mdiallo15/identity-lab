export const metadata = {
  title: "CSP bypasses — Labs",
};

export default function Bypasses() {
  return (
    <>
      <h1>How CSPs get bypassed</h1>
      <p className="lede">
        A policy is only as strong as its weakest source. These are the
        five bypass patterns I see most often in real engagements.
      </p>

      <section>
        <h2>1. JSONP endpoints on allowlisted CDNs</h2>
        <p>
          You allowlist <code>https://ajax.googleapis.com</code> for
          jQuery. Attacker injects an <code>&lt;script src&gt;</code> to{" "}
          <code>https://ajax.googleapis.com/.../jsonp?callback=alert(1)</code>{" "}
          — a JSONP endpoint on the same allowlisted host that returns
          attacker-controlled JavaScript. The CDN's origin is in your
          allowlist, so CSP is happy. XSS lands.
        </p>
        <p>
          <strong>Defense:</strong> avoid CDNs that host JSONP-like
          endpoints. Move to <code>'strict-dynamic'</code> + nonce so the
          allowlist becomes irrelevant.
        </p>
      </section>

      <section>
        <h2>2. base-uri + dangling markup</h2>
        <p>
          You forget <code>base-uri</code>. An XSS that can inject a single
          tag (not a full <code>&lt;script&gt;</code>) injects{" "}
          <code>&lt;base href="https://attacker.com"&gt;</code>. Now every
          relative URL on your page — script-src, link-href, image-src —
          loads from the attacker's domain. The attacker doesn't even need
          script execution; image and link loads happen automatically.
        </p>
        <p>
          <strong>Defense:</strong> always set <code>base-uri 'self'</code>{" "}
          or <code>base-uri 'none'</code>. There's no reason not to.
        </p>
      </section>

      <section>
        <h2>3. 'unsafe-inline' "just for the legacy page"</h2>
        <p>
          One ten-year-old admin page can't be migrated, so the team adds{" "}
          <code>'unsafe-inline'</code> "just for that route." A year later
          nobody remembers, and it's site-wide. The whole CSP is now
          theater.
        </p>
        <p>
          <strong>Defense:</strong> if you must, use a route-specific CSP
          via middleware, not a global <code>'unsafe-inline'</code>.
          Better: pay the migration cost; it's smaller than you think.
        </p>
      </section>

      <section>
        <h2>4. 'strict-dynamic' without a nonce or hash</h2>
        <p>
          A team copies <code>'strict-dynamic'</code> from a blog post but
          forgets the accompanying nonce. <code>'strict-dynamic'</code>{" "}
          alone <em>disables</em> the host allowlist without enforcing
          script integrity. Some browsers ignore this misconfiguration;
          others quietly accept it.
        </p>
        <p>
          <strong>Defense:</strong> never use <code>'strict-dynamic'</code>{" "}
          without <code>'nonce-X'</code> or <code>'sha256-X'</code> in the
          same directive.
        </p>
      </section>

      <section>
        <h2>5. No reporting → silent breakage</h2>
        <p>
          You ship a strict CSP. Three weeks later marketing pushes a new
          tag manager script that breaks. Nobody sees errors in the JS
          console because the page renders fine — only that one tracking
          pixel doesn't fire. By the time you find out, you have a month
          of missing analytics.
        </p>
        <p>
          <strong>Defense:</strong> always set <code>report-to</code>.
          Even logging to your own server (one route handler that accepts
          the report and writes to logs) is a 10x improvement over silent
          breakage.
        </p>
      </section>

      <h2>The pattern</h2>
      <p>
        All five of these have one thing in common: <strong>CSP rewards
        thinking about adversaries up front and punishes deferred
        decisions.</strong> The teams that ship clean policies are the
        teams that decided what they trusted before they started writing
        the header.
      </p>
    </>
  );
}
