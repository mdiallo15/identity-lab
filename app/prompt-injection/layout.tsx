import Link from "next/link";

export default function PromptInjectionLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="lab-shell">
      <nav className="sub-nav">
        <Link href="/prompt-injection">Overview</Link>
        <Link href="/prompt-injection/simulator">Simulator</Link>
        <Link href="/prompt-injection/patterns">Patterns</Link>
        <Link href="/prompt-injection/defenses">Defenses</Link>
      </nav>
      {children}
    </div>
  );
}
