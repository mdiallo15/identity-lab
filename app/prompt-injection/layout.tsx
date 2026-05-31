import { LabFrame } from "@/app/_components/lab-frame";

export default function PromptInjectionLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <LabFrame
      navLabel="Prompt injection lab sections"
      links={[
        { href: "/prompt-injection", label: "Overview" },
        { href: "/prompt-injection/simulator", label: "Simulator" },
        { href: "/prompt-injection/patterns", label: "Patterns" },
        { href: "/prompt-injection/defenses", label: "Defenses" },
      ]}
    >
      {children}
    </LabFrame>
  );
}
