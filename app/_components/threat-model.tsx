import Link from "next/link";
import type { ThreatEntry } from "@/lib/labs";

const STRIDE_LABEL: Record<ThreatEntry["stride"], string> = {
  S: "Spoofing",
  T: "Tampering",
  R: "Repudiation",
  I: "Info disclosure",
  D: "Denial of service",
  E: "Elevation of privilege",
};

const STRIDE_TONE: Record<ThreatEntry["stride"], string> = {
  S: "var(--medium)",
  T: "var(--high)",
  R: "var(--low)",
  I: "var(--high)",
  D: "var(--medium)",
  E: "var(--high)",
};

// Compact STRIDE-style threat-model card.
// Entries are passed as a prop (rather than looked up from a global map)
// so that client lab pages only ship the rows they actually render —
// not the entire workspace's threat corpus.
export function ThreatModelCard({
  entries,
}: {
  entries: readonly ThreatEntry[];
}) {
  if (!entries || entries.length === 0) return null;
  return (
    <aside className="threat-model" aria-label="Threats covered">
      <h2 className="threat-model__title">Threats covered</h2>
      <ul className="threat-model__list">
        {entries.map((e, i) => (
          <li key={`${e.stride}-${i}`}>
            <span
              className="threat-model__tag"
              style={{
                color: STRIDE_TONE[e.stride],
                borderColor: STRIDE_TONE[e.stride],
              }}
              title={STRIDE_LABEL[e.stride]}
            >
              {e.stride}
            </span>
            <span className="threat-model__text">{e.threat}</span>
            {e.demo && (
              <Link href={e.demo.href} className="threat-model__demo">
                {e.demo.label} →
              </Link>
            )}
          </li>
        ))}
      </ul>
      <p className="threat-model__legend">
        S spoofing · T tampering · R repudiation · I info disclosure · D denial
        of service · E elevation of privilege
      </p>
    </aside>
  );
}
