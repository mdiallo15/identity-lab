import Link from "next/link";

export const metadata = {
  title: "Identity Lab — Phishing-resistant authentication, hands-on",
  description:
    "Interactive playground for passwordless auth, WebAuthn passkeys, JWT analysis, and agent / workload identity.",
};

export default function IdentityLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="lab-shell">
      <nav className="sub-nav" aria-label="Identity Lab sections">
        <Link href="/identity">Overview</Link>
        <Link href="/identity/passkey">Passkey</Link>
        <Link href="/identity/jwt">JWT</Link>
        <Link href="/identity/phishing-resistant">Phishing-resistant</Link>
        <Link href="/identity/agent-identity">Agent identity</Link>
      </nav>
      {children}
    </div>
  );
}
