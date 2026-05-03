"use client";

import { useMemo, useState } from "react";
import {
  USERS,
  ORDERS,
  naiveGetOrder,
  hardenedGetOrder,
  type EndpointResponse,
} from "../../../lib/authz";

export default function AuthzSimulator() {
  const [authedUserId, setAuthedUserId] = useState<string>(USERS[0].id);
  const [orderId, setOrderId] = useState<string>(ORDERS[0].id);

  const naive = useMemo(
    () => naiveGetOrder(authedUserId, orderId),
    [authedUserId, orderId],
  );
  const hardened = useMemo(
    () => hardenedGetOrder(authedUserId, orderId),
    [authedUserId, orderId],
  );

  const authedUser = USERS.find((u) => u.id === authedUserId);
  const targetOrder = ORDERS.find((o) => o.id === orderId);
  const isCrossOwner =
    !!targetOrder &&
    !!authedUser &&
    authedUser.role !== "admin" &&
    targetOrder.ownerId !== authedUser.id;

  return (
    <>
      <h1>BOLA simulator</h1>
      <p className="lede">
        Pick a logged-in user and a target order ID. The same request goes to
        two endpoint implementations: a naive <code>GET /orders/:id</code> and a
        hardened one. The hardened endpoint scopes the lookup by owner; the
        naive one trusts the URL. Try Alice reading Bob's order.
      </p>

      <div className="row" style={{ gap: "1.5rem", flexWrap: "wrap" }}>
        <label>
          <strong>Logged in as:</strong>{" "}
          <select
            value={authedUserId}
            onChange={(e) => setAuthedUserId(e.target.value)}
          >
            {USERS.map((u) => (
              <option key={u.id} value={u.id}>
                {u.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          <strong>Order ID requested:</strong>{" "}
          <select value={orderId} onChange={(e) => setOrderId(e.target.value)}>
            {ORDERS.map((o) => {
              const owner = USERS.find((u) => u.id === o.ownerId);
              return (
                <option key={o.id} value={o.id}>
                  {o.id} (owner: {owner?.name ?? "?"})
                </option>
              );
            })}
          </select>
        </label>
      </div>

      {isCrossOwner && (
        <div
          role="status"
          style={{
            marginTop: "0.8rem",
            padding: "0.6rem 0.9rem",
            border: "1px solid #fbbf24",
            background: "rgba(251, 191, 36, 0.06)",
            fontSize: "0.88rem",
          }}
        >
          <strong>Cross-owner request.</strong> {authedUser?.name} is asking for
          an order owned by{" "}
          {USERS.find((u) => u.id === targetOrder?.ownerId)?.name}. Watch the
          two endpoints diverge.
        </div>
      )}

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "1rem",
          marginTop: "1rem",
        }}
      >
        <EndpointPanel
          title="Naive endpoint"
          subtitle="GET /orders/:id  →  WHERE id = ?"
          tone="bad"
          response={naive}
          isLeak={isCrossOwner && naive.status === 200}
        />
        <EndpointPanel
          title="Hardened endpoint"
          subtitle="GET /orders/:id  →  WHERE id = ? AND owner_id = ?"
          tone="good"
          response={hardened}
          isLeak={false}
        />
      </div>

      <h2>What just happened</h2>
      <p>
        The naive endpoint authenticates the request, then does{" "}
        <code>SELECT * FROM orders WHERE id = ?</code> — that's BOLA01. The
        hardened endpoint adds <code>AND owner_id = ?</code> in the same query
        (not a separate post-fetch check), and returns 404 — not 403 — for
        cross-owner access so existence isn't leaked (BOLA02).
      </p>
      <p>
        Try every combination of (user, order) and watch the table fill in. The
        naive column shows other people's shipping addresses, payment last-4,
        and notes. The hardened column shows the same 404 it returns for an
        order that doesn't exist at all.
      </p>
    </>
  );
}

function EndpointPanel({
  title,
  subtitle,
  tone,
  response,
  isLeak,
}: {
  title: string;
  subtitle: string;
  tone: "bad" | "good";
  response: EndpointResponse;
  isLeak: boolean;
}) {
  const borderColor = tone === "bad" ? "#ef4444" : "#22c55e";
  const tintBg =
    tone === "bad" ? "rgba(239, 68, 68, 0.04)" : "rgba(34, 197, 94, 0.04)";
  return (
    <section
      style={{
        border: `1px solid ${borderColor}`,
        background: tintBg,
        padding: "0.9rem 1rem",
      }}
    >
      <h3 style={{ marginTop: 0 }}>{title}</h3>
      <code style={{ fontSize: "0.78rem", color: "var(--ink-dim)" }}>
        {subtitle}
      </code>

      <div
        style={{
          marginTop: "0.8rem",
          display: "flex",
          alignItems: "center",
          gap: "0.5rem",
        }}
      >
        <span
          style={{
            padding: "0.15rem 0.5rem",
            background: response.status === 200 ? "#22c55e" : "#475569",
            color: "#fff",
            fontFamily: "var(--mono)",
            fontSize: "0.78rem",
            fontWeight: 700,
          }}
        >
          HTTP {response.status}
        </span>
        {isLeak && (
          <span
            style={{
              padding: "0.15rem 0.5rem",
              background: "#ef4444",
              color: "#fff",
              fontSize: "0.72rem",
              fontWeight: 700,
              letterSpacing: "0.06em",
            }}
          >
            DATA LEAK
          </span>
        )}
      </div>

      <pre
        style={{
          marginTop: "0.6rem",
          padding: "0.7rem",
          background: "rgba(15, 23, 42, 0.04)",
          fontSize: "0.78rem",
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
        }}
      >
        {JSON.stringify(response.body, null, 2)}
      </pre>
    </section>
  );
}
