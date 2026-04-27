"use client";

import { useState } from "react";
import {
  startRegistration,
  startAuthentication,
} from "@simplewebauthn/browser";

export default function PasskeyPage() {
  const [username, setUsername] = useState("alice");
  const [status, setStatus] = useState<{
    kind: "ok" | "err";
    msg: string;
  } | null>(null);

  async function register() {
    setStatus(null);
    try {
      const optsRes = await fetch(`/api/identity/passkey/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ step: "options", username }),
      });
      if (!optsRes.ok) throw new Error(await optsRes.text());
      const opts = await optsRes.json();

      const attestation = await startRegistration({ optionsJSON: opts });

      const verifyRes = await fetch(`/api/identity/passkey/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          step: "verify",
          username,
          attestation,
        }),
      });
      if (!verifyRes.ok) throw new Error(await verifyRes.text());
      setStatus({ kind: "ok", msg: "Passkey registered. Try signing in." });
    } catch (e) {
      setStatus({ kind: "err", msg: errorMessage(e) });
    }
  }

  async function signIn() {
    setStatus(null);
    try {
      const optsRes = await fetch(`/api/identity/passkey/authenticate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ step: "options", username }),
      });
      if (!optsRes.ok) throw new Error(await optsRes.text());
      const opts = await optsRes.json();

      const assertion = await startAuthentication({ optionsJSON: opts });

      const verifyRes = await fetch(`/api/identity/passkey/authenticate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          step: "verify",
          username,
          assertion,
        }),
      });
      if (!verifyRes.ok) throw new Error(await verifyRes.text());
      setStatus({ kind: "ok", msg: "Authenticated." });
    } catch (e) {
      setStatus({ kind: "err", msg: errorMessage(e) });
    }
  }

  return (
    <>
      <h1>Passkey demo</h1>
      <p className="lede">
        WebAuthn registration + authentication against an in-memory user store.
        The server is{" "}
        <a href="https://simplewebauthn.dev">@simplewebauthn/server</a>; the
        store resets on every server restart.
      </p>

      <h2>Username</h2>
      <div className="row">
        <input
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete="username webauthn"
        />
      </div>

      <h2>Actions</h2>
      <div className="row">
        <button type="button" onClick={register}>
          Register passkey
        </button>
        <button type="button" onClick={signIn}>
          Sign in
        </button>
      </div>

      {status ? (
        <div className={`status ${status.kind}`}>{status.msg}</div>
      ) : null}

      <h2>What happens during registration</h2>
      <ol>
        <li>Server generates a random challenge bound to your username.</li>
        <li>
          Browser passes the challenge to your authenticator (Touch ID, security
          key, phone). Authenticator generates a fresh keypair.
        </li>
        <li>
          Authenticator returns a signed attestation including the public key.
          The private key never leaves the device.
        </li>
        <li>
          Server verifies the attestation, stores the public key, and binds it
          to the user.
        </li>
      </ol>
    </>
  );
}

function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  return "Unknown error";
}
