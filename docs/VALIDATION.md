# Validation, 2026-10-30 (v0.2.0)

Executed in the supplied Linux x86_64 workspace, using rustc 1.99.1 and cargo 1.99.1,
with the checked-in Cargo.lock and pinned Tree-sitter grammars.

| Command | Result |
|---|---|
| `cargo fmt --check` | Passed |
| `cargo clippy --locked --offline --all-targets -- -D warnings` | Passed, no warnings |
| `cargo test --locked --offline` | Passed: 66 tests (23 unit, 16 integration, 21 analysis, 6 external analyzer), 0 failures. Run as root, `unreadable_source_is_a_gap` needs `USER=root` set, as before this change |
| `cargo test --locked --offline --release` | Not re-run for detection cards |
| `cargo +1.90 test --locked --offline` (minimum supported Rust version) | Not re-run for detection cards |
| `cargo deny check licenses bans sources` (cargo-deny 0.20.2, all target platforms) | bans ok, licenses ok, sources ok |
| `strace -f -e trace=network -o <scratch>/net.trace cargo test --locked --offline` | Passed: 61 tests; every connect was to 127.0.0.1, the local HTTP test server; no external addresses |
| `./target/release/betsy scan tests/fixtures --db <scratch>/smoke.sqlite --strict` | Sealed, source_complete=true, 37 occurrences |
| `./target/release/betsy verify --db <scratch>/smoke.sqlite --snapshot <returned-id> --format json` | valid=true; 37 occurrences |
| `./target/release/betsy weaknesses plan --db <scratch>/smoke.sqlite --snapshot <returned-id>` | 45,695 naive questions; 26,968 after prefilter; hierarchical lower bound 1,321 |
| `./target/release/betsy analyze --snapshot <returned-id> --provider mock --mock-file <script>` with `{"default":0.0}` | Finished; 37 completed, 0 positives, 37 requests (one root round per function) |
| `./target/release/betsy run create --db <scratch>/smoke.sqlite --snapshot <returned-id> --analyzer echo-v1` | Created a dispatch run; returned a run ID |
| `./target/release/betsy run exec --db <scratch>/smoke.sqlite --run <returned-run-id> --profile echo-v1 -- cat` | Finished; 37 completed, each result equal to its request; nested callables and syntax traits present where expected |
| `cargo audit --version` | Not installed locally; audit not run. Separate CI job installs and runs cargo-audit. |

Per-language plans for the fixtures (planned questions per function, after the prefilter):
C 869, C++ 887, JavaScript 683, Python 676, Rust 706, TypeScript 684, each at most six
rounds deep.

## v0.1 inventory and dispatch

The 37 starter occurrences match every independent byte span, exact snippet, kind,
parent label, additional grammar-specific node type and independently computed SHA-256.
Per-file counts also match the untouched supplied count oracle. The 47 extended literal
oracles pass for JSX, TSX, Python, Rust, C headers and C++.

Integration tests exercise grammar/version contracts, syntax/encoding/resource failures,
unreadable files under the ordinary workspace user, strict CLI rejection and partial
persistence, ignored/glob-excluded files, empty inventory, non-callable files, identical
source in separate paths, symlink exclusion, unsafe path normalization rejection,
three-location/traversal-order reproducibility, concurrent source edits using atomic
file replacement, retrieval after source deletion, immutable SQL triggers, deterministic
range/order/ID properties, concurrent unique claims, persistent interrupted claims,
explicit recovery/retry, fault history, final failures, state validation and idempotent
completion with rejection of conflicting results.

Full release starter report, manifest and verification JSON are in `artifacts/`.
Original starter fixture bytes and original oracle JSON were compared to the supplied
pack and remain unchanged. No extraction result was used to generate an acceptance oracle.

## v0.2 weakness decisions

Analysis tests use the offline mock provider and a loopback HTTP server. They exercise
catalog integrity and ID normalisation, plan accounting against a golden, REL/PERF
attachment under peer CWEs and only-child splicing, flat explicit selection, hierarchical
gating and subtree opening, `--max-rounds`, provider chunk limits, decision cache reuse
across runs and duplicate bodies, determinism under concurrency, interrupted claims,
retryable provider failures, Jev and OpenAI request/response wire shapes, HTTP retry on
rate limits and halving of oversized requests, trait catalog validity, syntax-only proof
of trait presence, trait pruning, recall attribution to traits and gated ancestors, and
schema migration from v1 and v2 databases to v3.

## Question wording and detection cards

Unit tests check that sentences ruling cases out are moved from the true criterion to the false
one, while abbreviations, "acceptable for ..." and sentences that point back at earlier ones
stay put; that cards are rejected for unknown IDs, languages or fields, missing parts,
self-references and duplicate IDs; that card criteria read per-language patterns (C++ reads C)
and stay within 1,500 characters for every card and language; and that uncheckable cards are
skipped by the prefilter but still asked when named explicitly; that every planned entry has a
card; that BETSY-authored entries are gated under a planned peer CWE; and that no card copies ten
consecutive words of its entry's description. All 1,014 cards load and render within the limit
for all seven languages. They have not been run against a provider or labelled
code.

## Unit tests

Unit tests cover the pure helpers without a database: HTTP status classification and
`Retry-After` parsing (including a non-finite value, which previously panicked), request
splitting and answer-count checks, probability bounds and refusals, usage accounting, state
rendering, every accepted OpenAI response container, Jev refusals and range checks, weakness
ID normalisation, language, hardware and mode-of-introduction prefilters, CWE-1000 parent
selection, text compaction, question keys and hashes, and trait masks.

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
