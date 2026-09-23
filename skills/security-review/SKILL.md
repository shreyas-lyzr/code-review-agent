---
name: security-review
description: "Security + hygiene pass for code reviews: sweep for leftover debug artifacts (print/console.log statements, stray logging, commented-out code, TODO/FIXME, debug flags, focused/skipped tests), hard-coded secrets, and known CVEs in changed dependencies (bundled OSV.dev scanner). Triggers on every PR/repo review as the mandatory security pass, and whenever the user asks for a 'security review', 'security pass', or 'check for leftover debug code'."
allowed-tools: "Bash, Read, Grep"
---

# Security review pass

Run this on **every** review (PR, repo, or patch). Three sweeps: **debug leftovers**, **secrets**, **dependency CVEs**. Report findings with file:line evidence; never write exploits — this is defensive analysis only.

Scope: for a PR, run the sweeps over the **changed files/diff** (flag pre-existing issues only when severe). For a whole-repo audit, run them tree-wide, excluding vendored/generated dirs (`node_modules`, `dist`, `build`, `vendor`, `.git`).

## 1. Debug-leftovers sweep

Things developers leave behind and shouldn't ship. Grep the changed files:

```bash
# Print/debug statements by language (tune the file globs to the diff)
grep -rnE '(^|[^a-zA-Z_.])print\(' --include='*.py' <paths>            # Python print()
grep -rnE 'console\.(log|debug|trace|warn|info)\(' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' <paths>
grep -rnE 'System\.out\.print|System\.err\.print' --include='*.java' <paths>
grep -rnE 'fmt\.Print(ln|f)?\(' --include='*.go' <paths>               # Go fmt prints (vs log/slog)
grep -rnE '\bdbg!|println!\(' --include='*.rs' <paths>
grep -rnE 'var_dump|print_r\(' --include='*.php' <paths>

# Debugger hooks — always blocking if shipped
grep -rnE 'debugger;|pdb\.set_trace|breakpoint\(\)|binding\.pry|byebug|import ipdb' <paths>

# Focused / skipped tests left behind — silently disables CI coverage
grep -rnE '\b(it|describe|test)\.only\(|\bf(describe|it)\(|@pytest\.mark\.skip|\.skip\(|xit\(|xdescribe\(' <paths>

# Commented-out code blocks & fresh task markers added by this change
grep -rnE '^\s*(//|#)\s*(TODO|FIXME|HACK|XXX)\b' <paths>
# For PRs: only count markers the diff ADDS →  gh pr diff <url> | grep -nE '^\+.*(TODO|FIXME|HACK|XXX)'

# Debug flags / verbose modes flipped on
grep -rniE 'DEBUG\s*=\s*(True|true|1)|LOG_LEVEL\s*=\s*.?(debug|trace)|verbose\s*[:=]\s*(true|True|1)' <paths>
```

How to judge:

- **Blocking:** debugger hooks (`pdb.set_trace`, `debugger;`), `.only`/focused tests, `DEBUG=true` defaults in production config, prints/logs that emit **sensitive values** (tokens, passwords, PII, full request bodies).
- **Should fix:** stray `print`/`console.log` in production paths (dev scripts and CLIs whose *purpose* is printing are fine — judge intent), large commented-out code blocks (delete; git remembers), TODO/FIXME added without a tracking issue.
- **Fine:** deliberate structured logging at appropriate levels; prints in examples/tests where output is the point. Don't flag the project's own logger usage — check `CLAUDE.md`/lint config for the project's logging conventions first.

Also check **log hygiene** in changed logging calls: no secrets/PII interpolated, level appropriate (`error` for errors, not `info`), no unbounded object dumps.

## 2. Secrets sweep

```bash
grep -rnE '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|sk-ant-[A-Za-z0-9-]{20,}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)' <paths>
grep -rniE '(password|passwd|secret|api_key|apikey|auth_token|access_key)\s*[:=]\s*["'"'"'][^"'"'"']{8,}' <paths> | grep -viE '(example|sample|test|dummy|placeholder|changeme|your[-_])'
```

A real credential in the diff is **always blocking**: request changes, and tell the author to **rotate it** — removing it in a follow-up commit does not un-leak it from git history. Also check "public" frontend env vars (`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `EXPO_PUBLIC_*`) — anything secret behind those ships to every visitor.

## 3. Dependency CVE scan — bundled OSV.dev client

For any added or version-bumped dependency, query OSV.dev with the bundled zero-dependency script:

```bash
SCAN="$(find . -name osv_scan.py -path '*security-review*' 2>/dev/null | head -1)"
python3 "$SCAN" package.json           # npm manifest
python3 "$SCAN" requirements.txt       # PyPI requirements
python3 "$SCAN" --eco Go go.mod        # Go modules (best-effort parse)
python3 "$SCAN" --pkg lodash --version 4.17.20 --eco npm   # single package
```

It prints any known vulnerability IDs (CVE/GHSA) with summary + severity per package. Then:

- Cite the exact advisory ID in the review comment; **never fabricate CVE numbers**.
- "No known advisory" ≠ "safe" — still reputation-check **brand-new** dependencies: age, maintainers, weekly downloads, name-distance from popular packages (typosquats like `requets`, `lodahs`).
- Version pinned by a lockfile? Scan the resolved version, not the range.

## 4. Reporting

Fold findings into the main review (inline comments at file:line). Severity language: "Blocking:", "Should fix:", "Question:". If every sweep is clean, say so explicitly:

> Security pass: no CVEs in changed deps, no secrets, no debug leftovers, no obvious injection/authz gaps.

Never weaken a security control, write exploit code, or add a bypass "to demonstrate" — describe the class of problem and the fix instead.
