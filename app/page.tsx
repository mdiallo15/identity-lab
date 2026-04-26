import Link from "next/link";

export default function Home() {
  return (
    <>
      <h1>Identity Lab</h1>
      <p className="lede">
        Two interactive tools for the auth-curious. Paste a real token, see
        what's actually inside; register a passkey, watch the WebAuthn
        ceremony in your browser.
      </p>

      <div className="cards">
        <div className="card">
          <h3>JWT inspector</h3>
          <p>
            Decodes the header and payload, then highlights the patterns that
            make verifiers fail open: <code>alg=none</code>, missing
            <code> exp</code>, HMAC vs RSA confusion, PII leakage.
          </p>
          <Link href="/jwt">Open inspector →</Link>
        </div>
        <div className="card">
          <h3>Passkey demo</h3>
          <p>
            Register a passkey on your device with WebAuthn, then sign back in.
            Walks through every byte the browser sends to the server.
          </p>
          <Link href="/passkey">Try it →</Link>
        </div>
      </div>

      <h2>Why this exists</h2>
      <p>
        Most identity bugs are structural. A teammate writes{" "}
        <code>jwt.verify(token, secret)</code> without pinning the algorithm,{/* audit-ignore JS008 */}
        ships, and doesn't think about it again. This lab lets you see those
        bugs the way I see them when I audit code.
      </p>
    </>
  );
}
