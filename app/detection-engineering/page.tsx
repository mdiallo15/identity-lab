import { LearnCallout } from "@/app/_components/learn-callout";
import { ThreatModelCard } from "@/app/_components/threat-model";
import type { ThreatEntry } from "@/lib/labs";
import { LAB_RULES, type LabKey, type LabRule } from "@/lib/detection-lab-rules";
import ScenarioRunner from "./scenario-runner";

export const metadata = {
  title: "Detection Engineering — Identity Lab",
  description:
    "Ground-truth-labeled detection lab with naive vs tuned rules, live precision/recall, and per-lab Sigma-equivalent starters.",
  openGraph: {
    title: "Detection Engineering Lab — Marwan Diallo",
    description:
      "Ground-truth-labeled detections, live precision/recall, and editable naive-vs-tuned rules.",
    type: "website",
    url: "https://lab.marwandiallo.com/detection-engineering",
  },
  twitter: {
    card: "summary_large_image",
    title: "Detection Engineering Lab — Marwan Diallo",
    description:
      "Ground-truth-labeled detections, live precision/recall, and editable naive-vs-tuned rules.",
  },
};
const THREATS: readonly ThreatEntry[] = [
  {
    stride: "T",
    threat: "Naive rule tuned by attacker's noise floor (helpdesk PowerShell).",
    demo: { label: "Phishing macro", href: "/detection-engineering" },
  },
  {
    stride: "R",
    threat: "Missing data source \u2014 rule cannot fire because field is absent.",
    demo: { label: "Scenarios", href: "/detection-engineering" },
  },
  {
    stride: "D",
    threat: "Over-broad rule alerts at 10\u00d7 baseline \u2014 SOC mutes the signal.",
    demo: { label: "Scenarios", href: "/detection-engineering" },
  },
  {
    stride: "I",
    threat: "TTP detection misses pre-stage (recon, ingress tool transfer).",
    demo: { label: "Volt Typhoon", href: "/detection-engineering" },
  },
];
const LAB_LABEL: Record<LabKey, string> = {
  csp: "CSP",
  jwt: "JWT",
  ssrf: "SSRF",
  iam: "IAM PrivEsc",
  "supply-chain": "Supply Chain",
  rag: "RAG",
  "prompt-injection": "Prompt Injection",
  "agent-identity": "Agent Identity",
};

const LAB_HREF: Record<LabKey, string> = {
  csp: "/csp",
  jwt: "/identity/jwt",
  ssrf: "/ssrf",
  iam: "/iam-privesc",
  "supply-chain": "/supply-chain",
  rag: "/rag",
  "prompt-injection": "/prompt-injection",
  "agent-identity": "/agent-identity",
};

const SEVERITY_TONE: Record<LabRule["severity"], string> = {
  critical: "var(--high)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  info: "var(--ink-dim)",
};

const LAB_ORDER: LabKey[] = [
  "csp",
  "jwt",
  "ssrf",
  "iam",
  "supply-chain",
  "rag",
  "prompt-injection",
  "agent-identity",
];

// Pre-group at module scope so the server renders this with no work at
// request time.
const GROUPED: Array<[LabKey, LabRule[]]> = LAB_ORDER.map((lab) => [
  lab,
  LAB_RULES.filter((r) => r.lab === lab),
]);

export default function DetectionLab() {
  return (
    <>
      <h1>Detection Engineering</h1>
      <LearnCallout href="/detection-engineering" />
      <ThreatModelCard entries={THREATS} />
      <p className="lede">
        Real telemetry from real incidents, two detection rules per scenario, a
        ground-truth labeled event stream. Watch the naive rule fire on every
        helpdesk PowerShell session while the tuned rule catches the macro
        loader. Edit either rule&apos;s match tree as JSON and see precision /
        recall update live.
      </p>

      <ScenarioRunner />

      <h2 style={{ marginTop: "1.8rem" }}>Detection rules by lab</h2>
      <p style={{ fontSize: "0.85rem", color: "var(--ink-dim)" }}>
        One Sigma-equivalent starting point per lab domain. Each rule lists
        the data source it needs, the ATT&amp;CK / OWASP / CVE handle it
        targets, the known false-positive shape, and a published reference.
        Lift the body into a real Sigma file, tune the allowlists for your
        environment, and ship. This catalog is rendered server-side so it
        does not ship to your browser as JavaScript.
      </p>
      <div style={{ display: "flex", flexDirection: "column", gap: "0.8rem" }}>
        {GROUPED.map(([lab, rules]) =>
          rules.length === 0 ? null : (
            <section
              key={lab}
              style={{
                border: "1px solid var(--rule)",
                padding: "0.7rem 0.9rem",
                background: "var(--bg-elev)",
              }}
            >
              <header
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "baseline",
                  marginBottom: "0.4rem",
                }}
              >
                <strong style={{ fontSize: "0.9rem" }}>{LAB_LABEL[lab]}</strong>
                <a
                  href={LAB_HREF[lab]}
                  style={{ fontSize: "0.78rem", color: "var(--accent)" }}
                >
                  open lab →
                </a>
              </header>
              {rules.map((r) => (
                <LabRuleCard key={r.id} rule={r} />
              ))}
            </section>
          ),
        )}
      </div>
    </>
  );
}

function LabRuleCard({ rule }: { rule: LabRule }) {
  return (
    <article
      style={{
        borderTop: "1px solid var(--rule)",
        marginTop: "0.5rem",
        paddingTop: "0.5rem",
        display: "flex",
        flexDirection: "column",
        gap: "0.35rem",
      }}
    >
      <div
        style={{
          display: "flex",
          gap: "0.5rem",
          alignItems: "baseline",
          flexWrap: "wrap",
        }}
      >
        <code style={{ fontSize: "0.78rem", color: SEVERITY_TONE[rule.severity] }}>
          {rule.id}
        </code>
        <span style={{ fontSize: "0.85rem" }}>{rule.title}</span>
        <span
          style={{
            fontSize: "0.68rem",
            textTransform: "uppercase",
            letterSpacing: "0.05em",
            color: SEVERITY_TONE[rule.severity],
            border: `1px solid ${SEVERITY_TONE[rule.severity]}`,
            padding: "0.05rem 0.4rem",
          }}
        >
          {rule.severity}
        </span>
      </div>
      <p style={{ margin: 0, fontSize: "0.8rem", color: "var(--ink-dim)" }}>
        {rule.rationale}
      </p>
      <dl
        style={{
          margin: 0,
          fontSize: "0.76rem",
          display: "grid",
          gridTemplateColumns: "max-content 1fr",
          rowGap: "0.2rem",
          columnGap: "0.6rem",
        }}
      >
        <dt style={{ color: "var(--ink-dim)" }}>data source</dt>
        <dd style={{ margin: 0 }}>{rule.dataSource}</dd>
        <dt style={{ color: "var(--ink-dim)" }}>maps to</dt>
        <dd style={{ margin: 0 }}>{rule.attack}</dd>
        {rule.knownFp && (
          <>
            <dt style={{ color: "var(--ink-dim)" }}>known FP</dt>
            <dd style={{ margin: 0 }}>{rule.knownFp}</dd>
          </>
        )}
        <dt style={{ color: "var(--ink-dim)" }}>reference</dt>
        <dd style={{ margin: 0, wordBreak: "break-all" }}>{rule.reference}</dd>
      </dl>
      <pre
        style={{
          margin: 0,
          padding: "0.5rem 0.6rem",
          background: "var(--bg)",
          border: "1px solid var(--rule)",
          fontSize: "0.72rem",
          whiteSpace: "pre",
          overflow: "auto",
        }}
      >
        {rule.sigma}
      </pre>
    </article>
  );
}
