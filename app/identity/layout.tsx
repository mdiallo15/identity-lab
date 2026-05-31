import { LabFrame } from "@/app/_components/lab-frame";

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
    <LabFrame
      navLabel="Identity Lab sections"
      links={[
        { href: "/identity", label: "Overview" },
        { href: "/identity/passkey", label: "Passkey" },
        { href: "/identity/jwt", label: "JWT" },
        { href: "/identity/phishing-resistant", label: "Phishing-resistant" },
        { href: "/identity/agent-identity", label: "Agent identity" },
      ]}
    >
      {children}
    </LabFrame>
  );
}
