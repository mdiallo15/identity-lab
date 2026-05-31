import { LabFrame } from "@/app/_components/lab-frame";

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
    <LabFrame
      navLabel="AuthZ lab sections"
      links={[
        { href: "/authz", label: "Overview" },
        { href: "/authz/simulator", label: "Simulator" },
        { href: "/authz/patterns", label: "Patterns" },
      ]}
    >
      {children}
    </LabFrame>
  );
}
