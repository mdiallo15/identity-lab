import { LAB_LEARN } from "@/lib/labs";

// Render the "what you'll learn" callout for a lab, given its route key
// (the same key used in lib/labs.ts LAB_LEARN). Returns null if no
// bullets are configured for the route, so it's safe to drop into any
// lab page without tripping a build.
export function LearnCallout({ href }: { href: string }) {
  const bullets = LAB_LEARN[href];
  if (!bullets || bullets.length === 0) return null;
  return (
    <aside className="learn-callout" aria-label="What you'll learn">
      <h2 className="learn-callout__title">What you&apos;ll learn</h2>
      <ul className="learn-callout__list">
        {bullets.map((b) => (
          <li key={b}>{b}</li>
        ))}
      </ul>
    </aside>
  );
}
