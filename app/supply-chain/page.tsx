import { LearnCallout } from "@/app/_components/learn-callout";
import { ThreatModelCard } from "@/app/_components/threat-model";
import type { ThreatEntry } from "@/lib/labs";
import { INCIDENTS, TYPOSQUATS } from "@/lib/supply-chain";
import SupplyChainAnalyzer from "./analyzer";

export const metadata = {
  title: "Supply Chain — Identity Lab",
};

const THREATS: readonly ThreatEntry[] = [
  {
    stride: "T",
    threat: "Postinstall hook stages payload (event-stream 2018, xz 2024).",
    demo: { label: "Scenarios", href: "/supply-chain" },
  },
  {
    stride: "S",
    threat: "Typosquat package impersonates a popular dep.",
    demo: { label: "Scenarios", href: "/supply-chain" },
  },
  {
    stride: "E",
    threat: "Account takeover republishes signed package (tj-actions 2025).",
    demo: { label: "Scenarios", href: "/supply-chain" },
  },
  {
    stride: "R",
    threat: "No build provenance \u2014 cannot prove which commit produced the artifact.",
    demo: { label: "Scenarios", href: "/supply-chain" },
  },
];

export default function SupplyChainLab() {
  return (
    <>
      <h1>Supply Chain</h1>
      <LearnCallout href="/supply-chain" />
      <ThreatModelCard entries={THREATS} />
      <p className="lede">
        Real package-registry compromises, replayed against a live provenance
        analyzer. Every scenario reproduces a public incident — event-stream,
        ua-parser-js, node-ipc, 3CX, XZ, Ultralytics, LottieFiles, tj-actions —
        using the metadata signals that distinguished the poisoned version from
        the clean one.
      </p>

      <SupplyChainAnalyzer />

      {/* ------------------ Static typosquat reference (server-rendered) */}
      <h2 style={{ marginTop: "1.6rem" }}>Documented typosquat patterns</h2>
      <p style={{ color: "var(--ink-dim)", fontSize: "0.88rem" }}>
        Patterns the analyzer&apos;s PROV07 rule scores against. Drawn from
        documented real incidents where possible.
      </p>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr",
          gap: "0.4rem",
          marginTop: "0.5rem",
        }}
      >
        {TYPOSQUATS.map((t) => (
          <div
            key={t.squat}
            style={{
              border: "1px solid var(--rule)",
              padding: "0.5rem 0.7rem",
              fontSize: "0.85rem",
              display: "grid",
              gridTemplateColumns: "1fr 1fr 1fr",
              gap: "0.6rem",
              alignItems: "center",
            }}
          >
            <code>{t.legitimate}</code>
            <code style={{ color: "var(--high)" }}>{t.squat}</code>
            <span style={{ color: "var(--ink-dim)", fontSize: "0.78rem" }}>
              {t.technique}
              {t.realIncident && ` · ${t.realIncident}`}
            </span>
          </div>
        ))}
      </div>

      {/* ------------------ Reading list (server-rendered) */}
      <h2 style={{ marginTop: "1.6rem" }}>Incident reading list</h2>
      <ul style={{ paddingLeft: "1.2rem" }}>
        {INCIDENTS.map((i) => (
          <li key={i.id} style={{ margin: "0.4rem 0" }}>
            <strong>{i.title}</strong> ({i.date}
            {i.cve ? `, ${i.cve}` : ""}) ·{" "}
            <a href={i.references[0]} target="_blank" rel="noopener noreferrer">
              advisory
            </a>
          </li>
        ))}
      </ul>
    </>
  );
}
