import Link from "next/link";

export const metadata = {
  title: "CSP Playground — Labs",
  description:
    "Paste a Content-Security-Policy, see what's actually being blocked. Side-by-side comparison of the four canonical policy shapes and the bypasses that defeat the loose ones.",
};

export default function CspLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="lab-shell">
      <nav className="sub-nav" aria-label="CSP Playground sections">
        <Link href="/csp">Overview</Link>
        <Link href="/csp/analyzer">Analyzer</Link>
        <Link href="/csp/shapes">Four shapes</Link>
        <Link href="/csp/bypasses">Bypasses</Link>
      </nav>
      {children}
    </div>
  );
}
