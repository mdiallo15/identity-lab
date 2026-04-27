import Link from "next/link";

export const metadata = {
  title: "Phishing-resistant MFA — Identity Lab",
  description:
    "Why FIDO2 / WebAuthn is the only mainstream factor that survives real-time AitM phishing kits, and what makes everything else replayable.",
};

export default function PhishingResistantPage() {
  return (
    <>
      <h1>Phishing-resistant MFA, on the wire</h1>
      <p className="lede">
        Most "MFA" is replayable. A modern reverse-proxy phishing kit (Evilginx,
        EvilProxy, Tycoon 2FA) is just a pipe — it takes whatever your user
        types, including the OTP and the session cookie, and hands it to the
        attacker. FIDO2 / WebAuthn is the one factor it cannot forward.
      </p>

      <h2>The four MFA archetypes, ranked</h2>
      <table className="rank">
        <thead>
          <tr>
            <th>Factor</th>
            <th>Phishable?</th>
            <th>Why</th>
          </tr>
        </thead>
        <tbody>
          <tr className="bad">
            <td>SMS / voice OTP</td>
            <td>Yes, trivially</td>
            <td>
              SIM swap, SS7, plain interception. NIST has been deprecating this
              since 2016.
            </td>
          </tr>
          <tr className="bad">
            <td>TOTP (Google Authenticator, Authy)</td>
            <td>Yes — replayed in real time</td>
            <td>
              The 6 digits are valid for 30 seconds. The proxy types them into
              the real site faster than the user does.
            </td>
          </tr>
          <tr className="meh">
            <td>Push notifications</td>
            <td>
              Yes — push fatigue / number matching helps but doesn't solve
            </td>
            <td>
              If the user approves the push, the attacker is in. Number-
              matching reduces but doesn't eliminate.
            </td>
          </tr>
          <tr className="good">
            <td>FIDO2 / WebAuthn passkey</td>
            <td>
              <strong>No</strong>
            </td>
            <td>
              The signed assertion is bound to the origin the browser is
              actually talking to. The phishing site has the wrong origin, so
              the signature is invalid for the real site. Period.
            </td>
          </tr>
        </tbody>
      </table>

      <h2>What makes WebAuthn unphishable</h2>
      <p>Three properties, in order of importance:</p>
      <ol>
        <li>
          <strong>Origin binding.</strong> The authenticator signs over the
          origin the browser sees (<code>login.example.com</code>), not what the
          user thinks they're on. A reverse-proxy at{" "}
          <code>login-examp1e.com</code> will produce a signature for{" "}
          <em>that</em> domain, which the real server rejects.
        </li>
        <li>
          <strong>No shared secret.</strong> The server stores only the public
          key. There is nothing to steal from the database, nothing to
          exfiltrate from a memory dump, nothing to forward.
        </li>
        <li>
          <strong>User presence + verification.</strong> The signature is only
          produced after a local gesture (Touch ID, Face ID, PIN, button press).
          The credential is non-exportable from the secure enclave on
          single-device passkeys, and end-to-end encrypted for synced passkeys.
        </li>
      </ol>

      <h2>What "passwordless" actually means</h2>
      <p>Three deployment patterns, ordered by maturity:</p>
      <dl>
        <dt>Passkey + password fallback</dt>
        <dd>
          Cheapest way to add phishing-resistance, but the password remains as a
          phishable backdoor. Most consumer rollouts (Apple, Google) started
          here.
        </dd>
        <dt>Passwordless primary, recovery via secondary device</dt>
        <dd>
          The password is removed from the account. Recovery is another passkey
          on a backup device, an admin-recovery flow, or attested re-enrollment
          from a trusted endpoint.
        </dd>
        <dt>Phishing-resistant only, no exceptions</dt>
        <dd>
          AAL3 / OMB M-22-09 territory. No SMS recovery, no helpdesk reset
          without identity-proofing. The bar U.S. federal agencies have to meet
          by mandate, and what mature enterprises are heading toward.
        </dd>
      </dl>

      <h2>Where it goes wrong in the wild</h2>
      <ul className="gotchas">
        <li>
          <strong>Soft fallback.</strong> "If passkey fails, send an OTP" — the
          attacker just triggers the fallback. Defeats the point. Don't.
        </li>
        <li>
          <strong>Helpdesk bypass.</strong> Caller IDs themselves, says they
          lost their device, helpdesk re-enrolls a passkey on the attacker's
          device. This was the MGM and Caesars pattern in 2023.
        </li>
        <li>
          <strong>Account-takeover via session token theft post-auth.</strong> A
          passkey stops phishing but doesn't stop infostealer malware that lifts
          an already-issued session cookie. Token-binding (or token- binding's
          modern cousin, DPoP) is the answer.
        </li>
        <li>
          <strong>Mixed RP IDs.</strong> Registering a passkey for{" "}
          <code>example.com</code> and trying to use it on{" "}
          <code>app.example.com</code> without a proper RP ID hierarchy breaks.
          Plan the relying-party-ID tree before rollout.
        </li>
      </ul>

      <h2>What you can do today</h2>
      <ol className="action">
        <li>
          Walk through the <Link href="/identity/passkey">passkey demo</Link>. It's the
          same WebAuthn ceremony enterprise IdPs run.
        </li>
        <li>
          Read about <Link href="/identity/agent-identity">agent identity</Link> — the
          same primitives, applied to AI agents instead of humans.
        </li>
        <li>
          For your own org: enable passkeys on the IdP, gate sensitive admin
          roles to passkey-only (no fallback), and add token-binding / DPoP on
          the highest-risk APIs.
        </li>
      </ol>
    </>
  );
}
