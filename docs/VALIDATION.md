# Validation, 2026-10-30 (v0.2.0)

Executed in the supplied Linux x86_64 workspace, using rustc 1.99.1 and cargo 1.99.1,
with the checked-in Cargo.lock and pinned Tree-sitter grammars.

| Command | Result |
|---|---|
| `cargo fmt --check` | Passed |
| `cargo clippy --locked --offline --all-targets -- -D warnings` | Passed, no warnings |
| `cargo test --locked --offline` | Passed: 81 tests (27 unit, 16 integration, 32 analysis, 6 external analyzer), 0 failures; re-run 2026-11-11 after the cards were restructured. Run as root, `unreadable_source_is_a_gap` needs `USER=root` set, as before this change |
| `cargo test --locked --offline --release` | Not re-run since the weakness cards were added |
| `cargo +1.90 test --locked --offline` (minimum supported Rust version) | Not re-run since the weakness cards were added |
| `cargo deny check licenses bans sources` (cargo-deny 0.20.2, all target platforms) | bans ok, licenses ok, sources ok |
| `strace -f -e trace=network -o <scratch>/net.trace cargo test --locked --offline` | Passed: 61 tests; every connect was to 127.0.0.1, the local HTTP test server; no external addresses |
| `./target/release/betsy scan tests/fixtures --db <scratch>/smoke.sqlite --strict` | Sealed, source_complete=true, 37 occurrences |
| `./target/release/betsy verify --db <scratch>/smoke.sqlite --snapshot <returned-id> --format json` | valid=true; 37 occurrences |
| `./target/release/betsy weaknesses plan --db <scratch>/smoke.sqlite --snapshot <returned-id>` | 40,441 naive questions (1,093 cards for each of 37 functions); 28,179 after prefilter; hierarchical lower bound 1,239, before syntax traits |
| `./target/release/betsy analyze --snapshot <returned-id> --provider mock --mock-file <script>` with `{"default":0.0}` | Finished; 37 completed, 0 positives, 37 requests (one root round per function), 1,071 questions asked and 168 subtrees ruled out by the parser |
| `./target/release/betsy run create --db <scratch>/smoke.sqlite --snapshot <returned-id> --analyzer echo-v1` | Created a dispatch run; returned a run ID |
| `./target/release/betsy run exec --db <scratch>/smoke.sqlite --run <returned-run-id> --profile echo-v1 -- cat` | Finished; 37 completed, each result equal to its request; nested callables and syntax traits present where expected |
| `./target/debug/betsy weaknesses audit --strict` | Exit 0; `errors` empty |
| `cargo audit --version` | Not installed locally; audit not run. Separate CI job installs and runs cargo-audit. |

Per-language plans for the fixtures (planned questions per function, after the prefilter):
C 895, C++ 938, JavaScript 709, Python 715, Rust 733, TypeScript 713, each at most six
rounds deep.

## v0.1 inventory and dispatch

The 37 starter occurrences match every independent byte span, exact snippet, kind,
parent label, additional grammar-specific node type and independently computed SHA-256.
Per-file counts also match the untouched supplied count oracle. The 47 extended literal
oracles pass for JSX, TSX, Python, Rust, C headers and C++.

Integration tests exercise grammar/version contracts, syntax/encoding/resource failures,
unreadable files (checked only where the test user cannot read a mode-000 file, since root can), strict CLI rejection and partial
persistence, ignored/glob-excluded files, empty inventory, non-callable files, identical
source in separate paths, symlink exclusion, unsafe path normalization rejection,
three-location/traversal-order reproducibility, concurrent source edits using atomic
file replacement, retrieval after source deletion, immutable SQL triggers, deterministic
range/order/ID properties, concurrent unique claims, persistent interrupted claims,
explicit recovery/retry, migration of v3 dispatch queues to canonical ordinals, fault history, final failures, state validation and idempotent
completion with rejection of conflicting results.

Full release starter report, manifest and verification JSON are in `artifacts/`.
Original starter fixture bytes and original oracle JSON were compared to the supplied
pack and remain unchanged. No extraction result was used to generate an acceptance oracle.

## v0.2 weakness decisions

Analysis tests use the offline mock provider and a loopback HTTP server. They exercise
that the cards are the only weakness definitions, ID normalisation, plan accounting against a golden, REL/PERF
attachment under listed parent CWEs and only-child splicing, flat explicit selection, hierarchical
gating and subtree opening, `--max-rounds`, provider chunk limits, decision cache reuse
across runs and duplicate bodies, determinism under concurrency, interrupted claims,
retryable provider failures, Jev and OpenAI request/response wire shapes, HTTP retry on
rate limits and halving of oversized requests, trait catalog validity, syntax-only proof
of trait presence, trait pruning, recall attribution to traits and gated ancestors, and
schema migration from v1, v2 and v3 databases to v4. They also check that rejected
credentials or an unknown model stop the run and leave every function pending, even when an
earlier chunk of the same round failed for an ordinary reason, that answers
paid for before a failure are cached and reused by the retry, that `--recover-claimed`
requeues interrupted claims, that `run findings --threshold` reports at another threshold,
that resuming rejects options differing from the run's configuration, that `--no-cache`
replaces stale cached answers, and that a failed run creation leaves no orphan run.

## Scale

Measured on synthetic Python repositories (50 three-line functions per file) with the release
build in a cloud container, before and after the v0.2 scaling fixes. The analysis used the
offline mock provider and one question per function, so it measures BETSY's own overhead.

| Functions | Scan before | Scan after | Analysis before | Analysis after |
|---|---|---|---|---|
| 10,000 | 1.1 s | 0.5 s | 219 s | 6.2 s |
| 20,000 | 4.8 s | 1.0 s | over 14 min, stopped | 13.0 s |
| 40,000 | 18.1 s | 2.1 s | not attempted | 26.0 s |

The causes were a claim query that sorted the whole run for every claim, a parent search that
compared every function with every other, line positions recomputed from the start of the
file, whole-file reads for each function's source, and a rollback journal created and deleted
on every commit. A single file of 20,000 functions now scans in 0.8 s. Timings depend on the
disk; these are indicative only.

## Question wording and weakness cards

Unit tests check that cards are rejected for unknown IDs, catalog prefixes, languages or fields,
missing names or parts, unknown or self-referencing parents and `distinguish_from` IDs, and
duplicate IDs; that a card's catalog and planning order come from its ID; that `languages`
restricts a card only when listed; that parents are tried in order; that card criteria read
per-language patterns (C++ reads C) and stay within 1,500 characters for every card and
language; that uncheckable cards are skipped by the prefilter and refused when named
explicitly; that only `gate` cards are planned as gates; and that REL and PERF cards with
parents are gated rather than asked as roots; that card files merge, that a catalog directory
holds only its catalog's cards and that the catalog hash covers file paths; that `requires`
becomes a trait mask and unknown traits are rejected; that `sources` and `status` are
validated; that a `detached` card has no parents; that traits are validated; and that the
parser settles syntax traits as absent only for a clean parse and only for languages that list
node kinds. All 1,093 cards load, and the 1,013 checkable ones render within the limit for all
seven languages. They have not been run against a provider or
labelled code.

When the catalog files the cards were first laid over were removed, the plan for each of the
seven languages (roles, parents, splicing, rounds, trait tags and skips) and all 5,393 planned
questions (wording and hashes) were compared before and after. They were identical apart from
the order of entries, which now follows catalog and ID number.

When the cards were split into family files and trait requirements moved onto them, the same
comparison was repeated before any behaviour changed: plans and questions were byte-identical.
The later changes (syntax traits, new trait requirements, the language fixes and the five new
cards) do change plans, so the profile is now `function-v7`. An analysis test checks that the
audit reports no defects and that the findings asked of every function match
`tests/expected/always_asked.json`; two others check that a gated run asks exactly the planned
nodes the parser does not rule out. The effect of syntax traits on recall has not been measured
against a provider: it rests on the argument that a construct absent from a cleanly parsed
function cannot be shown by that function's code.

## Unit tests

Unit tests cover the pure helpers without a database: HTTP status classification and
`Retry-After` parsing (including a non-finite value, which previously panicked), request
splitting and answer-count checks, probability bounds and refusals, usage accounting, state
rendering, every accepted OpenAI response container, Jev refusals and range checks, weakness
ID normalisation, the language prefilter, parent selection, question keys and hashes, and
trait masks.

## External analyzers and request contract

External tests check that features are deterministic, that byte and line counts match the
stored source, and that nested callable counts, taken from stored spans, agree with the
independent `parent_id` hierarchy across all 37 fixtures. `run exec` is tested end to end:
the request contract reaches stdin intact; results complete items; invalid output and non-zero
exits fail finally with the stderr tail; timeouts kill the process and fail retryably within
the deadline; a program that cannot start leaves the claim pending with a `recovered` event;
analysis runs are refused; and the CLI runs the program without a shell.

## Scope limits

No semantic resolution, macro expansion, dynamic function discovery, UI or server is
included. C++ qualified free functions cannot always be distinguished from out-of-line
members without semantic context; qualified names and flags are syntactic.
The file size limit applies before parsing, while the AST node limit applies after parsing;
there is no parser wall-clock timeout. Huge files retain a bounded prefix and an explicit
resource gap. Directory traversal failures stop the command explicitly. Symlink exclusion
is a default scan policy, not protection against malicious concurrent filesystem mutation.
Source completeness applies only to successfully parsed supported syntax under the pinned
adapters. It is not a claim about all runtime callable code or all future grammar constructs.

Not yet validated against live providers: no Jev or OpenAI Decisions request has been made.
The wire shapes are tested against recorded expectations only, and the Decisions response
container is parsed permissively because it was not fully documented. The default
`--gate-threshold` and the trait filter have not been tuned for recall on labelled code;
`--traits` remains off by default. Model probabilities are leads to verify, never proof.
