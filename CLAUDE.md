# identity-lab — operating contract

**Status: ACTIVE — continuous autonomous mode, push to `main` authorized.**
The Ready queue may be empty at session start — that is NOT a stop signal:
replenish from `PLAN.md`, production signals, and lint/type debt first (see
Loop). Hands-on security-labs site shipping at marwandiallo.com/labs.
Stack: Next.js App Router, dark CSS tokens already in use.

## Source of truth

`TASKS.md` is the backlog; `PLAN.md` is strategy. No snapshots exist anywhere
else by design. Session start: read `TASKS.md` + `git log --oneline -15`.

## Loop

Pick top unblocked Ready item → implement matching existing patterns (every lab
has editable inputs, a live analyzer, severity-coded findings, cited
references — no read-only showcases) → validation gate (use the
`verify-before-commit` skill) → `/code-review` the diff → commit as
`Marwan Diallo <hello@marwandiallo.com>` → **push to `main`** (authorized;
Vercel auto-deploys) → mark Done in `TASKS.md` with the SHA + session-log line
→ next item.

**Replenishment (when Ready is empty):** derive new atomic tasks from `PLAN.md`
goals not yet in Done, production signals (failed Vercel builds/deploys), and
lint/type debt; append them to Ready with sequential IDs, commit the tracker
update, and continue. If every PLAN goal is in Done and replenishment yields
nothing genuinely useful, mark the tracker `## Project status: shipped` with
date + last SHA, report, and stop — never invent busywork.

## Validation gate

- `npx tsc --noEmit`
- `npx eslint <touched files>`
- `npm run build` — keep route bundles roughly 5–12 kB unless the task justifies more

## Hard rules

- Don't fabricate CVE/incident context; cite references in labs.
- No destructive/irreversible git ops without surfacing first.
- Never mark a task Done without its commit SHA.
- Never invent busywork or re-churn correct code just to commit.

## Stop conditions

- Every PLAN goal is Done and replenishment yields nothing genuinely useful.
- The only remaining work is human-gated (taste/branding, real content,
  credentials).

## Kickoff

```
/goal Work TASKS.md top-down, replenishing Ready from PLAN.md when it empties:
every Done item has a commit SHA and a green tsc + lint + build. Stop when
every PLAN goal is Done or only human-gated work remains. Stop after 40 turns.
```
