import { LabFrame } from "@/app/_components/lab-frame";

export const metadata = {
  title: "CSP Playground — Labs",
  description:
    "Paste a Content-Security-Policy, see what's actually being blocked. Side-by-side comparison of the four canonical policy shapes and the bypasses that defeat the loose ones.",
};

export default function CspLayout({ children }: { children: React.ReactNode }) {
  return (
    <LabFrame
      navLabel="CSP Playground sections"
      links={[
        { href: "/csp", label: "Overview" },
        { href: "/csp/analyzer", label: "Analyzer" },
        { href: "/csp/sandbox", label: "Sandbox" },
        { href: "/csp/shapes", label: "Four shapes" },
        { href: "/csp/bypasses", label: "Bypasses" },
      ]}
    >
      {children}
    </LabFrame>
  );
}
