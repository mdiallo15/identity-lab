import Link from "next/link";

export default function SsrfLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="lab-shell">
      <nav className="sub-nav">
        <Link href="/ssrf">Overview</Link>
        <Link href="/ssrf/analyzer">Analyzer</Link>
        <Link href="/ssrf/targets">Targets</Link>
        <Link href="/ssrf/hardening">Hardening</Link>
      </nav>
      {children}
    </div>
  );
}
