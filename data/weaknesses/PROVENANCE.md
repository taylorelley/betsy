# Weakness card provenance

The files under `cards/` are the only weakness definitions in this repository. They are
embedded into `betsy` at build time, and their combined hash is part of every analysis run's
configuration, so editing a card never silently reuses old decisions. The format is described
in the [README](../../README.md#weakness-cards) and the cards' status in
[docs/DETECTION_CARDS.md](../../docs/DETECTION_CARDS.md).

| Content | Cards | Catalog hash (SHA-256 over every file's path and content) |
|---|---:|---|
| `cards/` | 1,149 | `896241aed1b6324ce03f2099fe4305ae69ac113a0737242a39beca0a15fc675b` |

`betsy weaknesses audit` prints the same hash as `catalog_hash`.

| IDs | Catalog | Cards | Origin |
|---|---|---:|---|
| `CWE-` | security | 755 | MITRE CWE 4.20 (released 2026-04-30) |
| `REL-001` to `REL-213` | reliability | 213 | scorpius-cli reliability catalog |
| `PERF-001` to `PERF-010` | performance | 10 | scorpius-cli performance catalog |
| `REL-214` to `REL-359` | reliability | 146 | written for BETSY |
| `PERF-011` to `PERF-035` | performance | 25 | written for BETSY |

`REL-` and `PERF-` cards name the published rules they were written from in `sources`, by
standard and rule number. For `REL-312` onwards and `PERF-029` onwards the sources are lint
rule names recalled while drafting, not yet checked against the tools' current releases. The earlier catalog files recorded none for `REL-001` to `REL-025`.

## History

The cards were first written as an overlay on catalog files copied byte for byte from
`taylorelley/scorpius-cli` at commit `501fdb9de233fe9d541f3c6091f121059284b04d`, path
`src/scorpius_cli/knowledge/data/` (`cwe_database.json`, `reliability_weaknesses.json`,
`performance_weaknesses.json`, `cwe_metadata.json`), and on two BETSY-owned extension files in
the same schema. Those files have been removed from the repository and remain in its git
history. Each card took from its entry the ID, name, abstraction, applicable languages,
position in the hierarchy and, for `REL-` and `PERF-` cards, the standard and rule numbers it
maps to; descriptions and other prose were not carried over. The cards were then moved from
one `cards.json` into the family files under `cards/`.

## MITRE CWE content

Cards with `CWE-` IDs use MITRE's identifiers, names and CWE-1000 hierarchy, and their
questions and patterns are new wording derived from MITRE CWE 4.20. `CWE-1426` was added later by ID and name; confirm both against
the MITRE release before the cards ship. A check, run while the
source files were still present, rejected any ten consecutive words copied from an entry's
description. The CWE terms appear to permit derived works when the notice in `CWE_NOTICE.txt`
is kept; this has not yet been confirmed with Legal and must be before the cards ship.

`CWE_NOTICE.txt` (SHA-256 `e3f34d4d13a81749d965bdad2e4159fdbe750ce19dcaea474a66584ed486e6c1`)
reproduces MITRE's copyright designation and license. It is the notice as copied from
scorpius-cli, so its opening and closing lines name that project.

The `REL-` and `PERF-` cards are not derived from MITRE content. Many `REL-` cards are derived
from MISRA C:2012 and the SEI CERT coding standards, in new wording; whether that derivation
may be distributed has not been confirmed with Legal.
