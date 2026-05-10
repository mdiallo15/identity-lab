# Agent kickoff prompt — identity-lab

> Paste the block below into a fresh Copilot Chat window in this workspace
> to start an autonomous work session. Use **Agent** mode.

---

You are picking up work on identity-lab, a hands-on security-labs site that ships at marwandiallo.com/labs. Source of truth for state is on disk:

1. Read `PLAN.md` first, then `TASKS.md`. The "Ready" section lists the next unblocked tasks in priority order (T-00, T-01b, T-01c, T-01, T-02 …). The "Done" section shows recent commits and what was just shipped.
2. Pick the topmost unchecked task in "Ready" and move it to "In progress".
3. Implement it under the existing patterns: every lab has editable inputs, a live analyzer, severity-coded findings, and cited references. No read-only showcases. Match the code style and dark CSS tokens already in use.
4. Run `npm run build` until clean. Keep bundle sizes in line with existing labs (5–12 kB per route).
5. Commit with a descriptive message (multi-paragraph if non-trivial). Use git author `Marwan Diallo <hello@marwandiallo.com>`. **Push to main when build is clean** — Vercel auto-deploys.
6. Move the task to "Done" with the commit SHA. Append a one-line entry to the "Session log" section at the bottom of `TASKS.md`.
7. Move on to the next "Ready" task. Two complete tasks per session is the established cadence; stop after that and summarize.

Quality bar: every lab must replicate a real attack with real CVE / incident references. No fake context. Inputs must be editable; the analyzer must re-run live on every keystroke. Cite published research (Rhino Security, SpecterOps, PortSwigger, Microsoft TI, CISA, OWASP, NIST).

Start now: read `TASKS.md`, pick T-00, begin.
