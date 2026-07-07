# identity-lab — kickoff

> **Superseded 2026-07-06.** The operating contract now lives in
> [`CLAUDE.md`](CLAUDE.md), which Claude Code loads automatically — nothing to
> paste. The work-queue snapshot that used to live here was removed
> deliberately: `TASKS.md` is the single source of truth.

**Status: ACTIVE** — Ready may be empty, but the loop replenishes from
`PLAN.md`, production signals, and lint/type debt before stopping.

Start a work session:

```bash
claude
/goal Work TASKS.md top-down, replenishing Ready from PLAN.md when it empties:
every Done item has a commit SHA and a green tsc + lint + build. Stop when
every PLAN goal is Done or only human-gated work remains. Stop after 40 turns.
```

(Legacy Copilot fallback: paste `CLAUDE.md` into Agent-mode chat.)
