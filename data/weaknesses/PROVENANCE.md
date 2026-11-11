# Weakness card provenance

`cards.json` is the only weakness definition in this repository. It is embedded into `betsy`
at build time, and its hash is part of every analysis run's configuration, so editing a card
never silently reuses old decisions. The format is described in the
[README](../../README.md#weakness-cards) and the cards' status in
[docs/DETECTION_CARDS.md](../../docs/DETECTION_CARDS.md).

| File | Content | Cards | SHA-256 |
|---|---|---:|---|
| `cards.json` | weakness cards | 1,088 | `f0c07893e45dbc3274d3b5237243703738ffcaa9db10cb0ba35a870d8f64bc65` |

| IDs | Catalog | Cards | Origin |
|---|---|---:|---|
| `CWE-` | security | 754 | MITRE CWE 4.20 (released 2026-04-30) |
| `REL-001` to `REL-213` | reliability | 213 | scorpius-cli reliability catalog |
| `PERF-001` to `PERF-010` | performance | 10 | scorpius-cli performance catalog |
| `REL-214` to `REL-306` | reliability | 93 | written for BETSY |
| `PERF-011` to `PERF-028` | performance | 18 | written for BETSY |

## History

The cards were first written as an overlay on catalog files copied byte for byte from
`taylorelley/scorpius-cli` at commit `501fdb9de233fe9d541f3c6091f121059284b04d`, path
`src/scorpius_cli/knowledge/data/` (`cwe_database.json`, `reliability_weaknesses.json`,
`performance_weaknesses.json`, `cwe_metadata.json`), and on two BETSY-owned extension files in
the same schema. Those files have been removed from the repository and remain in its git
history. Each card took from its entry the ID, name, abstraction, applicable languages and
position in the hierarchy; descriptions and other prose were not carried over.

## MITRE CWE content

Cards with `CWE-` IDs use MITRE's identifiers, names and CWE-1000 hierarchy, and their
questions and patterns are new wording derived from MITRE CWE 4.20. A check, run while the
source files were still present, rejected any ten consecutive words copied from an entry's
description. The CWE terms appear to permit derived works when the notice in `CWE_NOTICE.txt`
is kept; this has not yet been confirmed with Legal and must be before the cards ship.

`CWE_NOTICE.txt` (SHA-256 `e3f34d4d13a81749d965bdad2e4159fdbe750ce19dcaea474a66584ed486e6c1`)
reproduces MITRE's copyright designation and license. It is the notice as copied from
scorpius-cli, so its opening and closing lines name that project.

The `REL-` and `PERF-` cards are not derived from MITRE content.
