import "./globals.css";
import Link from "next/link";

export const metadata = {
  title: "marwandiallo.com / labs",
  description:
    "Hands-on security labs by Marwan Diallo. Phishing-resistant identity, content security policy, and other topics that don't survive PowerPoint.",
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
          <div className="topbar-left">
            <a href="https://marwandiallo.com" className="back-link">
              ← marwandiallo.com
            </a>
            <Link href="/" className="brand">
              labs
            </Link>
          </div>
          <nav>
            <Link href="/identity">Identity</Link>
            <Link href="/csp">CSP</Link>
            <Link href="/prompt-injection">Prompt Injection</Link>
            <Link href="/ssrf">SSRF</Link>
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
