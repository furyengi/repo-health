# repo-health

A daily audit of every non-fork repo on [@furyengi](https://github.com/furyengi).

[**Latest report →**](latest.md) · [all reports](reports/)

## What it checks

For each repo, via the GitHub API plus a shallow clone:

- **Dependency vulnerabilities** — `npm audit` on anything with a `package.json`
  (a lockfile is generated on the fly if the repo doesn't ship one)
- **Hygiene** — README, LICENSE, `.gitignore`, and a CI workflow present or not
- **Size and debt** — source files, lines, `TODO`/`FIXME`/`HACK`/`XXX` markers,
  longest files
- **Staleness** — days since last push, open issues and PRs
- **Stack detection** — npm, pip, cargo, go, maven, composer, bundler, …

The report opens with a table, then a *Needs attention* list ranked by how many
flags a repo trips, then per-repo detail. Raw results land in
`reports/YYYY-MM-DD.json` if you want to chart them over time.

## Schedule

`.github/workflows/health.yml` runs at 06:15 UTC daily, and on demand via
**Actions → repo health → Run workflow**. It commits only when the output
actually changed, so a quiet day produces no commit.

## Running it locally

```bash
gh auth login
node scripts/health.mjs
```

Needs `gh`, `git`, and Node 18+ (npm ships with it). No dependencies to install
— the script is stdlib only. Set `TARGET_OWNER` to audit a different account.
