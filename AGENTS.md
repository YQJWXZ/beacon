# AGENTS.md

Project conventions for humans and AI agents working in this repo.

## Language

- **Code**: Go. Identifiers and comments in English.
- **Docs** (`*.md`): Chinese, except this file and code comments.
- **Commits / PR titles / PR bodies**: English only.

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/), written in English.

```
<type>(<scope>): <subject>

<body: why this change, wrapped at 72 cols>

<footer: BREAKING CHANGE / Refs>
```

Rules:

- `type` ∈ `feat` `fix` `docs` `refactor` `perf` `test` `build` `ci` `chore`
- `scope` is optional but preferred: `agent` `collector` `detector` `flow` `fw` `port` `alert` `api` `docs` `deps`
- Subject: imperative mood, lowercase, no trailing period, ≤ 72 chars
- Body explains **why**, not what; the diff already says what
- Reference issues in the footer, e.g. `Refs: #12`

Examples:

```
feat(fw): detect ruleset changes via nft -j snapshot diff
fix(agent): keep wall-clock timestamps when replaying WAL
docs: add OSS landscape research and implementation spec
refactor(flow): bound conntrack sampling to 4096 entries
```

Do not mix unrelated changes in one commit. Docs-only changes use `docs:`.

## Engineering constraints

- Single static binary per component; no CGO unless there is no alternative.
- Agent never listens on a network port.
- Metrics use Prometheus naming (`beacon_<domain>_<name>_<unit>`); counters end with `_total`.
- No unbounded label values (remote IPs, raw destinations) in metric labels.
- Every alert must carry machine-readable `evidence`.
