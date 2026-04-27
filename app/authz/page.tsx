import Link from "next/link";

export default function AuthzOverview() {
  return (
    <>
      <h1>AuthZ Lab — IDOR / BOLA</h1>
      <p className="lede">
        Broken Object Level Authorization is the #1 entry on the OWASP API
        Security Top 10 and has been the root cause of more bug-bounty
        payouts than any other class. The bug is almost always the same:{" "}
        <em>the endpoint trusts the ID in the URL.</em> This lab makes that
        bug click in 30 seconds.
      </p>

      <section className="hero-stat">
        <div>
          <strong>API #1</strong>
          <span>OWASP API Security Top 10 ranks BOLA first by impact.</span>
        </div>
        <div>
          <strong>1 line</strong>
          <span>
            is the difference between a hardened query and the bug:
            <code> AND owner_id = ?</code>.
          </span>
        </div>
        <div>
          <strong>404 not 403</strong>
          <span>
            Returning 403 for cross-owner access leaks existence — let it 404.
          </span>
        </div>
      </section>

      <h2>Three things in this lab</h2>
      <div className="cards">
        <div className="card">
          <h3>Simulator</h3>
          <p>
            Switch between Alice, Bob, and an admin. Try to read order IDs
            that belong to other users. The naive endpoint hands them over;
            the hardened endpoint returns the same 404 it returns for IDs
            that don't exist. Watch the difference live.
          </p>
          <Link href="/authz/simulator">Open simulator →</Link>
        </div>
        <div className="card">
          <h3>Patterns</h3>
          <p>
            Eight detection rules (BOLA01–BOLA08) covering the patterns I look
            for in code reviews and Burp traces: missing owner scope,
            403-vs-404 leakage, sequential IDs, mass-assignment on update,
            client-supplied admin flags, GraphQL resolver gaps.
          </p>
          <Link href="/authz/patterns">See patterns →</Link>
        </div>
        <div className="card">
          <h3>Where this fits</h3>
          <p>
            BOLA is the AuthZ failure that survives a perfect AuthN
            deployment. Even with passkeys (
            <Link href="/identity">Identity Lab</Link>) and a strict CSP
            (<Link href="/csp">CSP Playground</Link>), a single broken
            <code>WHERE</code> clause leaks customer data.
          </p>
          <Link href="/authz/simulator">Try the attack →</Link>
        </div>
      </div>

      <h2>Why this lab matters</h2>
      <p>
        AuthZ bugs are different from AuthN bugs in one crucial way:{" "}
        <strong>
          the user is correctly authenticated when the breach happens.
        </strong>{" "}
        Every log line says "valid session, valid token, 200 OK". The
        request looks legitimate to every monitoring tool you have. The
        only signal is at the data layer — and most teams don't instrument
        that layer for ownership-mismatch alerts.
      </p>
      <p>
        I include some version of this in almost every API audit. Run the
        simulator first; the patterns page makes much more sense once
        you've felt the bug.
      </p>
    </>
  );
}
