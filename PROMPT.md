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
7. Then loop: fetch the next unblocked task from `TASKS.md` and continue. **Do not stop after two tasks anymore.** Keep going autonomously until the Ready queue is empty, a real blocker is hit, CI/build is red in a way you cannot resolve, or the user explicitly tells you to stop.

Autonomy mode:

- Do not wait for approval between tasks. If the next Ready item is clear, start it.
- Keep commits small and task-scoped, but continue shipping task after task in the same session.
- After each shipped task: update `TASKS.md`, append the session log entry, push to `main`, then immediately fetch the next Ready item.
- If you encounter a blocker, write it down precisely in `TASKS.md` and pivot to the next genuinely unblocked task if one exists.

Current backlog snapshot (June 2026):

- The Ready queue may be empty. Always re-read `TASKS.md` before starting instead of trusting this paragraph.
- If `TASKS.md` shows `Ready` is empty, stop and report that the autonomous backlog is exhausted.
- If new tasks have been added since this prompt was last edited, follow `TASKS.md` rather than this snapshot.

Execution preference:

- Prefer the top Ready item in `TASKS.md`.
- If multiple low-risk infrastructure/documentation items are adjacent, batching them is fine as long as they share the same validation surface.

Quality bar: every lab must replicate a real attack with real CVE / incident references. No fake context. Inputs must be editable; the analyzer must re-run live on every keystroke. Cite published research (Rhino Security, SpecterOps, PortSwigger, Microsoft TI, CISA, OWASP, NIST).

Start now: read `TASKS.md`, find the first genuinely unblocked task that is not already Done, begin.
