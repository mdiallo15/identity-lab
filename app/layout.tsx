import "./globals.css";
import Link from "next/link";

export const metadata = {
  title: "Identity Lab",
  description:
    "Interactive playground for JWTs, OIDC ID tokens, and WebAuthn passkeys.",
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
            <Link href="/jwt">JWT inspector</Link>
            <Link href="/passkey">Passkey demo</Link>
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
            Built by{" "}
            <a href="https://marwandiallo.com">Marwan Diallo</a> · MIT
          </span>
        </footer>
      </body>
    </html>
  );
}
