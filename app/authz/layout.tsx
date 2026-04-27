import Link from "next/link";

export const metadata = {
  title: "AuthZ Lab — Labs",
  description:
    "Broken Object Level Authorization (BOLA / IDOR) is the OWASP API Top 10 #1. Side-by-side simulator: naive vs hardened endpoint, eight detection rules, the patterns I look for in API audits.",
};

export default function AuthzLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="lab-shell">
      <nav className="sub-nav" aria-label="AuthZ lab sections">
        <Link href="/authz">Overview</Link>
        <Link href="/authz/simulator">Simulator</Link>
        <Link href="/authz/patterns">Patterns</Link>
      </nav>
      {children}
    </div>
  );
}
