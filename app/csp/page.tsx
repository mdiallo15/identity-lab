import Link from "next/link";

export default function CspOverview() {
  return (
    <>
      <h1>CSP Playground</h1>
      <p className="lede">
        Content-Security-Policy is the single most effective XSS mitigation
        we've ever shipped, and it's the one most teams either skip, deploy
        with <code>'unsafe-inline'</code>, or copy-paste from the internet
        without understanding. This lab fixes that.
      </p>

      <section className="hero-stat">
        <div>
          <strong>~90%</strong>
          <span>
            of CSP deployments in the wild include <code>'unsafe-inline'</code>
            on script-src, neutralizing most of the XSS protection.
          </span>
        </div>
        <div>
          <strong>2 lines</strong>
          <span>
            is all a strict, nonce-based CSP needs. The rest is migration
            work.
          </span>
        </div>
        <div>
          <strong>0 reports</strong>
          <span>
            is what you get without <code>report-uri</code> /{" "}
            <code>report-to</code>. Most policies break silently.
          </span>
        </div>
      </section>

      <h2>Three things in this lab</h2>
      <div className="cards">
        <div className="card">
          <h3>Analyzer</h3>
          <p>
            Paste any CSP string. The analyzer flags the patterns I flag in
            client engagements: <code>'unsafe-inline'</code>,{" "}
            <code>'unsafe-eval'</code>, wildcards, missing{" "}
            <code>object-src</code>, missing <code>base-uri</code>, no nonce,
            no report endpoint. Twelve rules, severity-ranked, with fixes.
          </p>
          <Link href="/csp/analyzer">Open analyzer →</Link>
        </div>
        <div className="card">
          <h3>Four shapes</h3>
          <p>
            The four canonical CSP shapes I see in practice — fully open,
            allowlist, nonce, strict-dynamic — with the actual headers and
            what each one actually blocks. Use it to pick the right starting
            point.
          </p>
          <Link href="/csp/shapes">Compare →</Link>
        </div>
        <div className="card">
          <h3>Bypasses</h3>
          <p>
            Why CDN allowlists fail (JSONP endpoints), why{" "}
            <code>base-uri</code> matters more than people think, the
            dangling-markup attack, and what you give up when you ship{" "}
            <code>'unsafe-inline'</code> "just for now."
          </p>
          <Link href="/csp/bypasses">Read →</Link>
        </div>
      </div>

      <h2>Read in order if you're new</h2>
      <ol className="action">
        <li>
          Read <Link href="/csp/shapes">Four shapes</Link> to understand the
          design space.
        </li>
        <li>
          Drop your real prod CSP into the{" "}
          <Link href="/csp/analyzer">analyzer</Link>. Most people are
          surprised.
        </li>
        <li>
          Skim <Link href="/csp/bypasses">Bypasses</Link> to know what your
          policy is and isn't actually defending against.
        </li>
      </ol>
    </>
  );
}
