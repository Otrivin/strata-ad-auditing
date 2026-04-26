# CLAUDE.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.
## 5. Rules

- All scripts must be idempotent (safe to run more than once)
- Never make destructive changes without a -WhatIf guard
- Always require -Confirm for anything that modifies ACLs or group membership
- Scripts must work without internet access (no web downloads)

---

# strata — Active Directory Auditing

Read-only Active Directory auditor. Connects via Kerberos GSSAPI, runs 87
security checks across every domain in the forest, and produces an
interactive Textual TUI, a self-contained HTML report with a prioritised
Remediation Roadmap, a grep-able plain-text scan log, and per-finding
PowerShell remediation scripts.

No changes are ever made to Active Directory.

## References

- MS AD DS Security Best Practices:
  https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory
- CIS Microsoft Windows Server 2022 v4.0.0 L1 DC — integration deferred
  (see `strata_hardening_cis_todo.md` memory for the plan and ID mapping)

## Tech stack

Python 3.11+. Defense-only library set, zero offensive tooling deps:

- `ldap3` — Kerberos SASL read-only LDAP client
- `gssapi` — Kerberos credential loading for ldap3
- `winacl` — pure-Python `nTSecurityDescriptor` parser (skelsec)
- `smbprotocol` + `pyspnego` + `krb5` — pure-Python SMB2/3 client for
  reading SYSVOL Registry.pol files using the existing Kerberos ccache
  (jborean93)
- `textual` + `rich` — TUI + console rendering (Textualize)
- `jinja2` — HTML report templating (Pallets)
- `click` — CLI (Pallets)

`impacket` was removed 2026-04-26 — see `strata_hardening_impacket_strip.md`
memory for the migration record and revert procedure.

## Project layout

```
strata/
  cli.py                 # click: scan | tui | compare  (binary: `strata`)
  models.py              # Severity, Category, Complexity, CheckResult, Snapshot
  scoring.py             # weighted-percentage score + bands + colors
  trend.py               # load / save / diff JSON snapshots
  log_capture.py         # in-memory `strata` logger handler used during scan
  collector/
    connection.py        # Kerberos LDAP bind + BER-encoded paged search
    forest.py            # forest / domain discovery
    sysvol.py            # SYSVOL Registry.pol reader (smbprotocol + krb5)
    checks/
      accounts.py        # ACCT-001..024  (24 checks)
      delegation.py      # DELEG-001..007 (7 checks)
      passwords.py       # PWD-001..008   (8 checks)
      trusts.py          # TRUST-001..004 (4 checks)
      acls.py            # ACL-001..006   (6 checks)
      gpo.py             # GPO-001..020   (20 checks — many via SYSVOL Registry.pol)
      infrastructure.py  # INFRA-001..013 (13 checks)
      certificates.py    # CERT-001..005  (5 checks — ADCS ESC1/2/3/4/6)
  reporter/
    html.py              # Tokyo Night dashboard renderer
    log.py               # plain-text scan log + live trace section
    ps.py                # per-finding PowerShell remediation scripts
    templates/report.html.j2
  tui/
    app.py               # HardeningApp + AppHeader/Footer + LoadingScreen +
                         #   ConnectScreen + ErrorScreen + RoadmapScreen +
                         #   TopologyScreen + CheckDetailScreen + ExportScreen
                         #   + render_logo() / render_compact_logo() helpers
    app.tcss             # Catppuccin Mocha stylesheet
    screens/
      dashboard.py       # 40/60 split: score panel + Quick Wins + clickable category tiles
      checks.py          # filterable two-pane list + Rich Syntax PS preview
      compare.py         # snapshot diff
results/                 # auto-created per scan, .gitignored
```

## Check categories (87 total)

| Category       | IDs            | Coverage                                                      |
| -------------- | -------------- | ------------------------------------------------------------- |
| Accounts       | ACCT-001..024  | Stale priv, AS-REP / Kerberoast, Protected Users, krbtgt rotation, Pre-Win2000 group, FSPs, non-expiring passwords (broad + privileged) |
| Delegation     | DELEG-001..007 | Unconstrained / constrained / RBCD, MachineAccountQuota, delegatable privileged accounts |
| Passwords      | PWD-001..008   | Domain policy, fine-grained PSO for service accounts, NTLMv2, anonymous LDAP, WDigest |
| Trusts         | TRUST-001..004 | SID filtering, transitive trusts, MIT trusts, directions      |
| ACLs           | ACL-001..006   | DCSync, AdminSDHolder, dangerous ACEs on privileged groups, OU protection, DNS zone CreateChild |
| Group Policy   | GPO-001..020   | LLMNR, hardened UNC paths, Kerberos armoring (FAST), PowerShell logging, RDP/NLA, Defender ASR, RestrictRemoteSAM, audit policy, LDAP signing & channel binding (CVE-2021-42291) |
| Infrastructure | INFRA-001..013 | Functional levels, LAPS, Recycle Bin, RC4/DES on DCs, dsHeuristics, DC count, AD backup status |
| Certificates   | CERT-001..005  | ADCS ESC1 / ESC2 / ESC3 / ESC4 / ESC6                         |

GPO content checks (GPO-007 onward) read SYSVOL Registry.pol via SMB; they
gracefully degrade to advisory PASS if SYSVOL is unreachable.

## Scoring model

Weighted percentage (NOT deduction):

```
score = passing_weight / total_weight × 100
```

Bands: 90+ Excellent | 75-89 Good | 50-74 Fair | 25-49 Poor | <25 Critical.

Each check has `weight` (1-10), `severity` (CRITICAL/HIGH/MEDIUM/LOW/INFO),
and `complexity` (TRIVIAL/EASY/MODERATE/HARD/SURGICAL — defaults per category,
overridable per check).

Priority order in the Remediation Roadmap:

```
priority_score = (severity_multiplier × weight) ÷ complexity
```

Severity multipliers: CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1, INFO=0.
Complexity scores: TRIVIAL=1, EASY=2, MODERATE=3, HARD=4, SURGICAL=5.

Quick Wins surface = TRIVIAL/EASY × high impact. Floats e.g. krbtgt
rotation (CRITICAL × weight 10 ÷ EASY 2 = 50) to the very top.

## Trend / comparison

Each scan saves `results/<forest>_<ts>/snapshot.json`. The `compare` command
(and Compare TUI screen) shows: score delta, newly introduced failures,
mitigated issues, still-failing, still-passing.

## Output artifacts per scan

Written to `results/<forest>_<ts>/`:

- `snapshot.json` — full structured result (Snapshot dataclass)
- `scan.log` — plain-text per-check log + **SCAN TRACE section**
  (every LDAP query + level-tagged events captured via
  `log_capture.capture_scan_log()` — useful for debugging)
- `report.html` — self-contained Tokyo Night dashboard (no CDN, no fonts,
  no analytics)
- `ps/` — per-finding PowerShell remediation scripts

## HTML report structure

1. Hero: animated SVG score gauge, letter grade A+/A/.../F, severity-count chips
2. **⚡ Remediation Roadmap (the headline)** — Quick Wins carousel + sortable
   full backlog ordered by `priority_score`
3. Category heatmap (8-tile grid)
4. Findings explorer — filterable, click-to-expand PS with copy button
5. Topology / inventory
6. Footer with generation timestamp + tool version

Single self-contained file. STRATA wordmark uses the same horizontal
`mauve → pink → blue → sky` brand gradient as the TUI logo.

## TUI

Catppuccin Mocha aesthetic, all panels `border: round`. Bindings shown in
the footer hint bar with mauve keys.

Screens:

- `AppHeader` (compact STRATA brand left, score/forest right)
- `AppFooter` (mauve-keyed binding hints)
- `LoadingScreen` — gradient ANSI Shadow logo + braille spinner + scrolling log
- `ConnectScreen` — form with inline validation (rejects `@` in hostname etc.)
- `ErrorScreen` — retry button
- `DashboardScreen` — 40/60 split: score panel + Quick Wins + clickable
  4×2 category grid
- `RoadmapScreen` — DataTable sorted by priority, Enter for detail
- `ChecksScreen` — filterable two-pane (filter input + Passed/Failed +
  active category pill); `Ctrl+X` (priority binding) clears category filter
- `TopologyScreen` — Tree of forest → domains → DCs/trusts
- `CompareScreen` — pick two snapshots, side-by-side diff
- `CheckDetailScreen` (modal) — full detail + Rich `Syntax`-highlighted PS
- `ExportScreen` (modal) — open report in browser, regen artifacts from
  in-memory snapshot

Bindings from anywhere: `d/r/c/t/v/e/R/q`. Per-screen extras: `/` filter,
`Enter` open detail, `Ctrl+X` clear category filter, `Esc` back.

Important: `_silence_console_logging()` runs before `app.run()` to strip
stderr-bound StreamHandlers — otherwise the parent CLI's `basicConfig()`
handler bleeds through Textual's render and corrupts the screen.

## Security non-negotiables

- Kerberos GSSAPI only; `read_only=True` on every LDAP connection
- LDAPS port 636 by default; `--no-ssl` for lab only
- SMB reads use `GENERIC_READ` only; never request write/delete access
- Never store credentials — use existing kinit ticket cache (`KRB5CCNAME` /
  `/tmp/krb5cc_<uid>`)
- No writes to Active Directory under any circumstances
- BER-encode LDAP paging controls manually (ldap3 does not accept tuples)
- Zero offensive-tooling dependencies in the venv — winacl + smbprotocol
  replaced impacket so `pip install` does not put `secretsdump`, `psexec`,
  `wmiexec`, etc. into `<venv>/bin/`
- All scan output stays local to `results/`; no telemetry, no off-host calls
