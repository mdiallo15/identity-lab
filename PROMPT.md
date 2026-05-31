# Agent kickoff prompt — identity-lab

> Paste the block below into a fresh Copilot Chat window in this workspace
> to start an autonomous work session. Use **Agent** mode.

---

You are picking up work on identity-lab, a hands-on security-labs site that ships at marwandiallo.com/labs. Source of truth for state is on disk:

1. Read `PLAN.md` first, then `TASKS.md`.
2. Treat `TASKS.md` as authoritative, but verify the top of "Ready" against the "Done" section before starting. If the top ready item is already listed in Done, skip to the next genuinely unblocked task instead of redoing work.
3. Pick the topmost real task in "Ready", move it to "In progress", and implement it under the existing patterns: every lab has editable inputs, a live analyzer, severity-coded findings, and cited references. No read-only showcases. Match the code style and dark CSS tokens already in use.
4. Run `npm run build` until clean. Keep bundle sizes in line with existing labs (roughly 5–12 kB per route unless the task justifies more).
5. Commit with a descriptive message. Use git author `Marwan Diallo <hello@marwandiallo.com>`. **Push to main when build is clean** — Vercel auto-deploys.
6. Move the task to "Done" with the commit SHA. Append a one-line entry to the "Session log" section at the bottom of `TASKS.md`.
7. Then loop: fetch the next unblocked task from `TASKS.md` and continue. Stop only after two completed tasks, a real blocker, or a human decision requirement.

Quality bar: every lab must replicate a real attack with real CVE / incident references. No fake context. Inputs must be editable; the analyzer must re-run live on every keystroke. Cite published research (Rhino Security, SpecterOps, PortSwigger, Microsoft TI, CISA, OWASP, NIST).

Start now: read `TASKS.md`, find the first genuinely unblocked task that is not already Done, begin.
