# Weakness catalog provenance

Copied byte for byte from `taylorelley/scorpius-cli` at commit
`501fdb9de233fe9d541f3c6091f121059284b04d`, path `src/scorpius_cli/knowledge/data/`.

| File | Catalog | Entries | SHA-256 |
|---|---|---:|---|
| `cwe_database.json` | security (MITRE CWE 4.20) | 969 | `98cdb4808a4e3cdf102470887b4f6f7e47c3e5a9ac7fd1730c5f9580534cf55d` |
| `reliability_weaknesses.json` | reliability (`REL-`) | 213 | `35866f2432b8fbb2242d8c6e0b6f69cc54b5e40b7baf0f74d95299560418be0a` |
| `performance_weaknesses.json` | performance (`PERF-`) | 10 | `e8e0a62fb37c25c69d57f55e9cf7a1bac11e51762dd3c55e98b321278de78a1d` |
| `cwe_metadata.json` | MITRE release metadata | | `fd4053b11464384cc146c9e114f502e88b9887eb3f041844cb76cd10340049f4` |
| `CWE_NOTICE.txt` | MITRE copyright and license notice | | `e3f34d4d13a81749d965bdad2e4159fdbe750ce19dcaea474a66584ed486e6c1` |

The files are embedded into `betsy` at build time. Their combined hash is part of every
analysis run's configuration, so editing a catalog never silently reuses old decisions.
CWE content is subject to the MITRE terms reproduced in `CWE_NOTICE.txt`.

## BETSY-owned extensions

These files are not copied from scorpius-cli. They add reliability and performance entries
written for BETSY, in the same schema and continuing the same ID sequences; see
[docs/DETECTION_CARDS.md](../../docs/DETECTION_CARDS.md#extension-catalogs). Each entry's
`mapping_usage` starts with "BETSY-authored". They are not derived from MITRE content.

| File | Catalog | Entries | SHA-256 |
|---|---|---:|---|
| `betsy_reliability_weaknesses.json` | reliability (`REL-214` to `REL-271`) | 58 | `69ae777df801308e3e43921f8b7ac06ab61a47f1b8ab814c23d02cd69f463b70` |
| `betsy_performance_weaknesses.json` | performance (`PERF-011` to `PERF-024`) | 14 | `4de254b9e27eab2f8c4421aa7d831afab95ae74646e3fd24d975ba5b2603ba40` |

## Detection cards

`cards.json` is not copied from scorpius-cli. It is an overlay written for BETSY that rewrites
the question for selected entries; see [docs/DETECTION_CARDS.md](../../docs/DETECTION_CARDS.md).

| File | Content | Cards | SHA-256 |
|---|---|---:|---|
| `cards.json` | detection cards | 1,043 | `ca2039db499bd74d2aeadd52ced263e4c16dac3b8defd85a9b55ecfca3caee83` |

Sources, per card, are the catalog entry it is keyed by and the entries named in its
`distinguish_from`, as they appear in the files above (MITRE CWE 4.20 for `CWE-` IDs). The
wording is new (a check rejects any ten consecutive words copied from an entry's description),
but cards for `CWE-` entries are derived from MITRE content. The CWE terms
appear to permit derived works when the notice in `CWE_NOTICE.txt` is kept; this has not yet
been confirmed with Legal and must be before the cards ship.

The cards' hash is part of the catalog hash, so it is part of every analysis run's configuration.
