import Link from "next/link";

export interface LabFrameLink {
  href: string;
  label: string;
}

export function LabFrame({
  children,
  navLabel,
  links,
}: {
  children: React.ReactNode;
  navLabel: string;
  links: readonly LabFrameLink[];
}) {
  return (
    <div className="lab-shell">
      <nav className="sub-nav" aria-label={navLabel}>
        {links.map((link) => (
          <Link key={link.href} href={link.href}>
            {link.label}
          </Link>
        ))}
      </nav>
      {children}
    </div>
  );
}