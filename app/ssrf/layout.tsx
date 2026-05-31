import { LabFrame } from "@/app/_components/lab-frame";

export default function SsrfLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <LabFrame
      navLabel="SSRF lab sections"
      links={[
        { href: "/ssrf", label: "Overview" },
        { href: "/ssrf/analyzer", label: "Analyzer" },
        { href: "/ssrf/targets", label: "Targets" },
        { href: "/ssrf/hardening", label: "Hardening" },
      ]}
    >
      {children}
    </LabFrame>
  );
}
