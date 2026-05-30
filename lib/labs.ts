// Lab metadata. Today the only field used is "since" (ISO date), which
// drives the "new" pill on the home page. Pills auto-clear after the
// NEW_WINDOW_DAYS threshold so the page never carries stale flags.

export const NEW_WINDOW_DAYS = 60;

// Per-route launch / major-revision dates. Update these when a lab ships
// a v2 — the "new" pill will rehang for NEW_WINDOW_DAYS.
export const LAB_SINCE: Record<string, string> = {
  "/identity/forge": "2026-05-03",
  "/agent-identity": "2026-05-03",
  "/agent-identity/token-exchange": "2026-05-17",
  "/iam-privesc": "2026-05-03",
  "/detection-engineering": "2026-05-30",
  "/supply-chain": "2026-05-03",
  "/rag": "2026-04-26",
  "/prompt-injection": "2026-05-10",
  "/ssrf": "2026-05-10",
};

export function isNewLab(href: string, now: Date = new Date()): boolean {
  const since = LAB_SINCE[href];
  if (!since) return false;
  const t = Date.parse(since);
  if (Number.isNaN(t)) return false;
  const ageMs = now.getTime() - t;
  return ageMs >= 0 && ageMs <= NEW_WINDOW_DAYS * 24 * 60 * 60 * 1000;
}
