"use client";

import { useMemo, useState } from "react";
import {
  RULES,
  USERS,
  ORDERS,
  naiveGetOrder,
  hardenedGetOrder,
  type Severity,
} from "../../../lib/authz";
import { standardsFor } from "../../../lib/standards";
import { ExportButtons } from "../../_components/export-buttons";

const sevRank: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export default function AuthzPatterns() {
  const [authedUserId, setAuthedUserId] = useState(USERS[0].id);
  const [orderId, setOrderId] = useState(ORDERS[2].id);
  const [pattern, setPattern] = useState<
    "naive-by-id" | "fetch-then-403" | "scoped-query" | "client-admin-flag"
  >("naive-by-id");
  const [useOpaqueIds, setUseOpaqueIds] = useState(false);

  const findings = useMemo(() => {
    const base = [...RULES];
    const target = ORDERS.find((o) => o.id === orderId);
    const actor = USERS.find((u) => u.id === authedUserId);
    const crossOwner =
      !!target && !!actor && actor.role !== "admin" && target.ownerId !== actor.id;

    if (crossOwner && pattern === "naive-by-id") {
      base.unshift({
        id: "LIVE01",
        severity: "critical",
        title: "Cross-owner read succeeds under by-id lookup",
        detail:
          "The request authenticates the actor but never scopes the resource query by owner. Alice can read Bob's order just by changing the URL identifier.",
        fix: "Bind resource lookup to the authenticated principal in the same query: WHERE id = ? AND owner_id = ?.",
      });
    }
    if (crossOwner && pattern === "fetch-then-403") {
      base.unshift({
        id: "LIVE02",
        severity: "high",
        title: "Fetch-then-check leaks existence",
        detail:
          "The server first proves the record exists, then rejects access. That 403 is enough for an attacker to map valid order IDs before finding a second bug.",
        fix: "Do not fetch cross-owner records at all. Scope the query and return the same 404 for not-found and not-yours.",
      });
    }
    if (pattern === "client-admin-flag") {
      base.unshift({
        id: "LIVE03",
        severity: "high",
        title: "Client-controlled admin override",
        detail:
          "If the route trusts ?admin=true or X-Admin: 1 from the client, the authorization decision has already been lost before the data layer runs.",
        fix: "Derive privilege from validated server-side claims only. Strip request-level admin flags entirely.",
      });
    }
    if (!useOpaqueIds) {
      base.unshift({
        id: "LIVE04",
        severity: "medium",
        title: "Guessable identifiers amplify enumeration",
        detail:
          "The core bug is authorization, but short sequential IDs make discovery faster and make 403/404 side channels far more useful.",
        fix: "Use opaque identifiers and still fix owner scoping in the query. Opaque IDs are friction, not authorization.",
      });
    }

    return base.sort((a, b) => sevRank[b.severity] - sevRank[a.severity]);
  }, [authedUserId, orderId, pattern, useOpaqueIds]);

  const preview = useMemo(() => {
    if (pattern === "naive-by-id") return naiveGetOrder(authedUserId, orderId);
    if (pattern === "scoped-query") return hardenedGetOrder(authedUserId, orderId);
    if (pattern === "fetch-then-403") {
      const fetched = naiveGetOrder(authedUserId, orderId);
      if (fetched.status !== 200) return fetched;
      const actor = USERS.find((u) => u.id === authedUserId);
      if (actor?.role === "admin" || fetched.body.ownerId === authedUserId) {
        return fetched;
      }
      return { status: 403 as const, body: { error: "Forbidden" } };
    }
    return naiveGetOrder("u_carol", orderId);
  }, [authedUserId, orderId, pattern]);

  const actor = USERS.find((u) => u.id === authedUserId);
  const target = ORDERS.find((o) => o.id === orderId);
  const targetOwner = USERS.find((u) => u.id === target?.ownerId);

  return (
    <>
      <h1>BOLA / IDOR patterns</h1>
      <p className="lede">
        This route is now a live query-scoping lab. Pick an authenticated user,
        a target order, and a server-side query pattern. The findings rerun live
        based on whether the route trusts the URL, fetches then rejects, scopes
        the query correctly, or relies on a client-controlled admin escape hatch.
      </p>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "0.8rem",
          margin: "1rem 0",
        }}
      >
        <section className="card">
          <label style={{ display: "block", marginBottom: "0.6rem" }}>
            <strong>Authenticated user</strong>
            <select
              value={authedUserId}
              onChange={(e) => setAuthedUserId(e.target.value)}
              style={{ display: "block", marginTop: "0.3rem" }}
            >
              {USERS.map((user) => (
                <option key={user.id} value={user.id}>
                  {user.name}
                </option>
              ))}
            </select>
          </label>

          <label style={{ display: "block", marginBottom: "0.6rem" }}>
            <strong>Requested order</strong>
            <select
              value={orderId}
              onChange={(e) => setOrderId(e.target.value)}
              style={{ display: "block", marginTop: "0.3rem" }}
            >
              {ORDERS.map((order) => {
                const owner = USERS.find((u) => u.id === order.ownerId);
                return (
                  <option key={order.id} value={order.id}>
                    {order.id} (owner: {owner?.name ?? "?"})
                  </option>
                );
              })}
            </select>
          </label>

          <label style={{ display: "block", marginBottom: "0.6rem" }}>
            <strong>Route / query pattern</strong>
            <select
              value={pattern}
              onChange={(e) =>
                setPattern(
                  e.target.value as
                    | "naive-by-id"
                    | "fetch-then-403"
                    | "scoped-query"
                    | "client-admin-flag",
                )
              }
              style={{ display: "block", marginTop: "0.3rem" }}
            >
              <option value="naive-by-id">naive by-id lookup</option>
              <option value="fetch-then-403">fetch then 403</option>
              <option value="scoped-query">owner-scoped query</option>
              <option value="client-admin-flag">client admin override</option>
            </select>
          </label>

          <label style={{ display: "block", marginTop: "0.75rem" }}>
            <input
              type="checkbox"
              checked={useOpaqueIds}
              onChange={(e) => setUseOpaqueIds(e.target.checked)}
              style={{ width: "auto", marginRight: "0.4rem" }}
            />
            use opaque IDs instead of guessable order identifiers
          </label>
        </section>

        <section className="card">
          <h3 style={{ marginTop: 0 }}>Live request preview</h3>
          <p style={{ fontSize: "0.85rem", color: "var(--ink-dim)" }}>
            Actor: <strong>{actor?.name}</strong> · Resource owner:{" "}
            <strong>{targetOwner?.name}</strong>
          </p>
          <pre style={{ marginTop: "0.6rem" }}>{`GET /api/orders/${orderId}${pattern === "client-admin-flag" ? "?admin=true" : ""}
session.sub = ${authedUserId}

${pattern === "naive-by-id" ? "SELECT * FROM orders WHERE id = ?" : pattern === "fetch-then-403" ? "SELECT * FROM orders WHERE id = ?; then if owner mismatch return 403" : pattern === "scoped-query" ? "SELECT * FROM orders WHERE id = ? AND owner_id = ?" : "if req.query.admin === true skip owner check"}`}</pre>
          <p style={{ fontSize: "0.85rem", color: "var(--ink-dim)" }}>
            Result: <strong>HTTP {preview.status}</strong>
          </p>
          <pre>{JSON.stringify(preview.body, null, 2)}</pre>
        </section>
      </div>

      <ExportButtons
        findings={findings}
        toolName="lab.marwandiallo.com/authz"
        target="ruleset"
        payload={{ rules: findings }}
        filenamePrefix="bola-rules"
      />

      <div className="findings">
        {findings.map((f) => (
          <article key={f.id} className={`finding finding--${f.severity}`}>
            <header>
              <span className={`sev sev--${f.severity}`}>
                {f.severity.toUpperCase()}
              </span>
              <span className="finding__id">{f.id}</span>
              <h3>{f.title}</h3>
            </header>
            <p>{f.detail}</p>
            {f.fix && (
              <p style={{ marginTop: "0.5rem", fontSize: "0.9rem" }}>
                <strong style={{ color: "var(--ok, #22c55e)" }}>fix:</strong>{" "}
                {f.fix}
              </p>
            )}
            {standardsFor(f.id) && (
              <p
                style={{
                  marginTop: "0.4rem",
                  fontSize: "0.8rem",
                  color: "var(--ink-dim, #888)",
                }}
              >
                <strong>standards:</strong> {standardsFor(f.id)!.join(" · ")}
              </p>
            )}
          </article>
        ))}
      </div>

      <h2>The two questions to ask any list-or-fetch endpoint</h2>
      <ol>
        <li>
          <strong>Whose data does this query return?</strong> If the answer
          isn't "the authenticated principal's", the next question matters.
        </li>
        <li>
          <strong>Where is ownership enforced?</strong> "In the route handler"
          is a yellow flag. "In the data layer, in the same query that does the
          fetch" is what you want.
        </li>
      </ol>
    </>
  );
}
