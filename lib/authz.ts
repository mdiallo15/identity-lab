// audit-ignore-file
// Authorization (IDOR / BOLA) lab logic. Pure in-memory fixture data
// plus two endpoint implementations: a naive one ("trust the ID in
// the URL") and a hardened one ("scope by the authenticated principal,
// reject if the resource doesn't belong to them"). Eight detection
// rules (BOLA01-BOLA08) describe the patterns I look for in client
// API audits.
//
// Refs:
//   OWASP API Security Top 10 (2023) — API1: Broken Object Level Auth
//   PortSwigger — IDOR research collection
//   Shopify, Uber, Lyft — historical BOLA disclosures with similar shapes

import type { SarifFinding } from "./sarif";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface User {
  id: string;
  name: string;
  email: string;
  role: "user" | "admin";
}

export interface Order {
  id: string;
  ownerId: string;
  total: number;
  shippingAddress: string;
  paymentLast4: string;
  notes: string;
}

export const USERS: User[] = [
  { id: "u_alice", name: "Alice", email: "alice@example.com", role: "user" },
  { id: "u_bob", name: "Bob", email: "bob@example.com", role: "user" },
  {
    id: "u_carol",
    name: "Carol (admin)",
    email: "carol@example.com",
    role: "admin",
  },
];

export const ORDERS: Order[] = [
  {
    id: "ord_1001",
    ownerId: "u_alice",
    total: 84.5,
    shippingAddress: "123 Maple St, Austin TX",
    paymentLast4: "4242",
    notes: "Leave at door.",
  },
  {
    id: "ord_1002",
    ownerId: "u_alice",
    total: 19.99,
    shippingAddress: "123 Maple St, Austin TX",
    paymentLast4: "4242",
    notes: "Birthday gift — wrap.",
  },
  {
    id: "ord_1003",
    ownerId: "u_bob",
    total: 312.0,
    shippingAddress: "9 Oak Ave, Brooklyn NY",
    paymentLast4: "0007",
    notes: "Replacement for damaged item.",
  },
  {
    id: "ord_1004",
    ownerId: "u_bob",
    total: 41.25,
    shippingAddress: "9 Oak Ave, Brooklyn NY",
    paymentLast4: "0007",
    notes: "",
  },
];

export type EndpointResponse =
  | { status: 200; body: Order }
  | { status: 401; body: { error: string } }
  | { status: 403; body: { error: string } }
  | { status: 404; body: { error: string } };

// NAIVE — looks up by ID, returns whatever it finds. Classic BOLA.
// "It's behind login so it's safe" — no, the auth check verified WHO
// you are, not WHICH RESOURCES you can see.
export function naiveGetOrder(
  authedUserId: string | null,
  orderId: string,
): EndpointResponse {
  if (!authedUserId) {
    return { status: 401, body: { error: "Not authenticated" } };
  }
  const order = ORDERS.find((o) => o.id === orderId);
  if (!order) return { status: 404, body: { error: "Order not found" } };
  return { status: 200, body: order };
}

// HARDENED — scopes the lookup to the authenticated principal. Returns
// 404 (not 403) for cross-owner access so we don't leak the existence
// of other people's resources. Admins get a separate code path.
export function hardenedGetOrder(
  authedUserId: string | null,
  orderId: string,
): EndpointResponse {
  if (!authedUserId) {
    return { status: 401, body: { error: "Not authenticated" } };
  }
  const user = USERS.find((u) => u.id === authedUserId);
  if (!user) return { status: 401, body: { error: "Unknown principal" } };

  if (user.role === "admin") {
    const order = ORDERS.find((o) => o.id === orderId);
    if (!order) return { status: 404, body: { error: "Order not found" } };
    return { status: 200, body: order };
  }

  // Normal users: scope-by-owner. Note we look up by (id AND ownerId)
  // in a single query — not "fetch then check". That pattern is the
  // one place BOLA bugs hide most often.
  const order = ORDERS.find(
    (o) => o.id === orderId && o.ownerId === authedUserId,
  );
  if (!order) return { status: 404, body: { error: "Order not found" } };
  return { status: 200, body: order };
}

// Detection rules — what I look for in a code review or burp trace.
export const RULES: SarifFinding[] = [
  {
    id: "BOLA01",
    severity: "critical",
    title: "Resource fetched by ID without owner scope",
    detail:
      "The endpoint queries for the resource by primary key and returns whatever it finds. Any authenticated user can change the ID in the URL and read other users' data. This is OWASP API #1 and accounts for the largest share of bug-bounty payouts.",
    fix: "Scope the query by the authenticated principal: WHERE id = ? AND owner_id = ?. Do not 'fetch then check'.",
  },
  {
    id: "BOLA02",
    severity: "high",
    title: "403 Forbidden returned for cross-owner access",
    detail:
      "Returning 403 confirms the resource exists; an attacker can enumerate IDs to map other users' inventory. Real outcome: confirmed which order IDs are valid before they steal them.",
    fix: "Return 404 Not Found for both 'does not exist' and 'not yours'. Indistinguishable.",
  },
  {
    id: "BOLA03",
    severity: "high",
    title: "Sequential / guessable resource IDs",
    detail:
      "Auto-incrementing IDs make BOLA discovery trivial — change ord_1001 to ord_1002 and try again. UUIDs don't fix the underlying authorization bug but raise the cost of mass enumeration significantly.",
    fix: "Use UUIDv4 or another opaque identifier. Combine with the BOLA01 fix; UUIDs alone are not authorization.",
  },
  {
    id: "BOLA04",
    severity: "high",
    title: "Authorization in middleware only, not in the query",
    detail:
      "Middleware checks 'is the user logged in', then the route fetches by ID. This separation of concerns is correct for AuthN, dangerous for AuthZ — the route still needs to verify ownership.",
    fix: "Push owner-scope into the data layer: a repository method that takes (id, principal) and refuses to return cross-tenant rows.",
  },
  {
    id: "BOLA05",
    severity: "high",
    title: "Mass-assignment on update endpoint",
    detail:
      "An update endpoint accepts the full order object including ownerId, allowing an attacker to reassign their own order to another user, or to escalate via role= fields.",
    fix: "Whitelist updatable fields. Never trust client-supplied id/owner/role/createdBy on writes.",
  },
  {
    id: "BOLA06",
    severity: "medium",
    title: "Admin override flag in client request",
    detail:
      "Endpoint accepts ?admin=true or X-Admin: 1 and skips the owner check. Frequently used by internal tools and never removed before launch.",
    fix: "Trust only server-side claims (session, JWT validated server-side). Strip request-level admin flags at the edge.",
  },
  {
    id: "BOLA07",
    severity: "medium",
    title: "GraphQL by-ID query without owner scope",
    detail:
      "GraphQL resolvers commonly expose order(id: ID!) that resolves any record. Same bug as REST; harder to spot because of the schema layer.",
    fix: "Pass the principal into the resolver context. Apply ownership in the data loader, not the resolver. Consider Relay-style global IDs that encode owner.",
  },
  {
    id: "BOLA08",
    severity: "low",
    title: "Verbose error messages leak resource shape",
    detail:
      "Errors like 'order not found in tenant t_acme' confirm tenant existence and naming. Useful for an attacker building a cross-tenant attack chain.",
    fix: "Return generic errors to clients. Log the detail server-side with a correlation ID.",
  },
];

// Lookup helpers used by the UI.
export function getUserById(id: string | null): User | null {
  if (!id) return null;
  return USERS.find((u) => u.id === id) ?? null;
}
export function getAllOrders(): Order[] {
  return ORDERS;
}
