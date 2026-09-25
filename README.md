# code-review-agent

A [GAP](https://github.com/gitagent-protocol) (gitagent protocol) agent **purely for code analysis and review**: adversarial pull-request reviews, repository audits, and patch/snippet reviews — with a mandatory security pass on every review.

Driven via [gitagent](https://github.com/gitagent/gitagent) / gitclaw and invoked from `@computeragent` infrastructure — the Slack review bot, or the `/run`, `/tasks`, `/sandboxes` endpoints of a ComputerAgent harness server. The harness clones this repo **fresh for every run**, so merging to `main` is the deploy.

## What it does

- **PR reviews** — fetches the diff (and checks out the branch for context), reviews for correctness, security, performance, tests, API/contract breakage, and posts the review to GitHub with inline comments and an honest approve / request-changes / comment verdict.
- **Repo audits** — clones a repo and runs the same analysis tree-wide.
- **Security pass on every review** (`skills/security-review`):
  - leftover debug artifacts — stray `print`/`console.log`/debugger hooks, commented-out code, added TODO/FIXMEs, debug flags, focused/skipped tests, log-hygiene issues
  - hard-coded secrets/keys/tokens in the diff (blocking + rotation advice)
  - known CVEs in added/bumped dependencies via the bundled OSV.dev scanner (`osv_scan.py`)
- **Project-convention aware** — the first thing it does after cloning a repo for review is read that project's `CLAUDE.md` (plus `AGENTS.md`/`CONTRIBUTING.md`), and it judges changes against the project's own rules.

## Files

- `agent.yaml` — GAP manifest (model, runtime, skills)
- `SOUL.md` — system prompt: review standards, workflow, approval bar, security guardrails
- `skills/security-review/` — the security pass method + `osv_scan.py` CVE scanner
- `skills/log-review/` — graded log-leak audit (prints/loggers/raises/responses → `<repo>-print-audit.md`); runs **only** when explicitly asked to "review log leaks"
- `skills/exa-research/` — web research for CVEs/advisories/framework behaviour
- `skills/pdf-export/`, `skills/read-document/` — report delivery and document ingestion

## GitHub integration — auto-review every PR

`.github/workflows/pr-review.yml` is a **reusable workflow**: on every PR (opened / reopened / synchronize / ready-for-review, drafts skipped) it calls the deployed harness, the agent reviews the PR and posts the review directly on GitHub, and the job fails if no review lands. Fork PRs skip gracefully (secrets aren't exposed to forks).

To adopt it in **any repo**, add `.github/workflows/code-review.yml`:

```yaml
name: code-review
on:
  pull_request:
    types: [opened, reopened, synchronize, ready_for_review]
jobs:
  review:
    uses: shreyas-lyzr/code-review-agent/.github/workflows/pr-review.yml@main
    secrets:
      CLAWAGENT_BASIC: ${{ secrets.CLAWAGENT_BASIC }}
```

…and set the `CLAWAGENT_BASIC` secret (`user:password` for `api.clawagent.sh`) on the repo — or once at the org level so every repo inherits it. Optionally make the `review` check required in branch protection to gate merges on the agent's review landing.

## CI/CD

`.github/workflows/agent-ci.yml` runs on every push:

1. **validate** — `agent.yaml` parses; `SOUL.md` + `AGENT_BUILD` marker present.
2. **live-verify** (`main` only) — asks the deployed harness to run this agent and echo its `AGENT_BUILD`; the build fails unless the live agent serves that exact commit.

## Usage

```bash
# As a one-shot task via the ComputerAgent SDK
runTask({
  source: { kind: "github", repo: "shreyas-lyzr/code-review-agent" },
  harness: "gitagent",
  envs: { ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY },
  message: "Review this PR: https://github.com/<owner>/<repo>/pull/<n>",
});
```
