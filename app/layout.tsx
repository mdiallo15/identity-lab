import "./globals.css";
import Link from "next/link";

export const metadata = {
  title: "Identity Lab — Phishing-resistant authentication, hands-on",
  description:
    "Interactive playground for passwordless auth, WebAuthn passkeys, JWT analysis, and agent / workload identity.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <header className="topbar">
          <Link href="/" className="brand">
            Identity Lab
          </Link>
          <nav>
            <Link href="/passkey">Passkey</Link>
            <Link href="/jwt">JWT</Link>
            <Link href="/phishing-resistant">Phishing-resistant</Link>
            <Link href="/agent-identity">Agent identity</Link>
            <a
              href="https://github.com/mdiallo15/identity-lab"
              target="_blank"
              rel="noopener noreferrer"
            >
              GitHub
            </a>
          </nav>
        </header>
        <main>{children}</main>
        <footer>
          <span>
            Built by <a href="https://marwandiallo.com">Marwan Diallo</a> · MIT
          </span>
        </footer>
      </body>
    </html>
  );
}
