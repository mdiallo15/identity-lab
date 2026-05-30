import Link from "next/link";
import { LearnCallout } from "@/app/_components/learn-callout";
import { ThreatModelCard } from "@/app/_components/threat-model";
import type { ThreatEntry } from "@/lib/labs";

const THREATS: readonly ThreatEntry[] = [
  {
    stride: "I",
    threat: "BOLA: GET /orders/{id} returns another tenant's order.",
    demo: { label: "simulator", href: "/authz/simulator" },
  },
  {
    stride: "E",
    threat: "Mass-assignment promotes role on PATCH /users/me.",
    demo: { label: "patterns", href: "/authz/patterns" },
  },
  {
    stride: "I",
    threat: "403-vs-404 leakage enumerates valid IDs.",
    demo: { label: "patterns", href: "/authz/patterns" },
  },
  {
    stride: "R",
    threat: "Missing audit on resource access \u2014 cannot prove who saw what.",
    demo: { label: "patterns", href: "/authz/patterns" },
  },
];

export default function AuthzOverview() {
  return (
    <>
      <h1>AuthZ Lab — IDOR / BOLA</h1>
      <LearnCallout href="/authz" />
      <ThreatModelCard entries={THREATS} />
      <p className="lede">
        Broken Object Level Authorization sits at the top of the OWASP API
        Security Top 10. The bug pattern, in almost every case I have reviewed,
        is the same: the endpoint authenticates the caller, then trusts the
        object ID in the URL without checking who owns it. This lab is built
        around feeling that bug rather than reading about it.
      </p>

      <section className="hero-stat">
        <div>
          <strong>OWASP API #1</strong>
          <span>
            Broken Object Level Authorization is the highest-ranked entry by
            impact across reviewed cases.
          </span>
        </div>
        <div>
          <strong>One missing predicate</strong>
          <span>
            The fix is usually a single <code>AND owner_id = ?</code> on the
            query. The bug is its absence.
          </span>
        </div>
        <div>
          <strong>404, not 403</strong>
          <span>
            Returning 403 on cross-owner access leaks object existence. Match
            the not-found response.
          </span>
        </div>
      </section>

      <h2>Three things in this lab</h2>
      <div className="cards">
        <div className="card">
          <h3>Simulator</h3>
          <p>
            Switch between Alice, Bob, and an admin. Try to read order IDs that
            belong to other users. The naive endpoint hands them over; the
            hardened endpoint returns the same 404 it returns for IDs that don't
            exist. Watch the difference live.
          </p>
          <Link href="/authz/simulator">Open simulator →</Link>
        </div>
        <div className="card">
          <h3>Patterns</h3>
          <p>
            Eight detection rules (BOLA01–BOLA08) covering the patterns I look
            for in code reviews and Burp traces: missing owner scope, 403-vs-404
            leakage, sequential IDs, mass-assignment on update, client-supplied
            admin flags, GraphQL resolver gaps.
          </p>
          <Link href="/authz/patterns">See patterns →</Link>
        </div>
        <div className="card">
          <h3>Where this fits</h3>
          <p>
            BOLA is the AuthZ failure that survives a perfect AuthN deployment.
            Even with passkeys (<Link href="/identity">Identity Lab</Link>) and
            a strict CSP (<Link href="/csp">CSP Playground</Link>), a single
            broken
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
        Every log line says "valid session, valid token, 200 OK". The request
        looks legitimate to every monitoring tool you have. The only signal is
        at the data layer — and most teams don't instrument that layer for
        ownership-mismatch alerts.
      </p>
      <p>
        On a recent API review, the same pattern came up on the third endpoint
        I tested: a numeric order ID in the path, a valid bearer token, a clean
        200 response, and someone else's invoice in the body. Run the simulator
        first; the patterns page reads better once you have felt the bug rather
        than just read about it.
      </p>
    </>
  );
}
