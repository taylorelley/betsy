# BETSY

**Bug Evaluation Through Simple Yes/No**, initial build v0.1.0.

BETSY inventories source functions deterministically and dispatches them individually
for later analysis. This milestone implements the attached [build specification](docs/BUILD_SPEC.md).
The executable is `funh`, preserving the build pack's command interface.
v0.2 adds weakness decisions: `funh analyze` asks a decision model (Jev or OpenAI
Decisions) whether each catalog weakness is present in each function, one weakness per
question. Scanning and every test stay offline. Model probabilities are stored apart from
parser facts and are leads to verify, never proof.

## Build and try it

Install stable Rust with the rustfmt and clippy components, plus a C compiler (the
Tree-sitter grammars and bundled SQLite compile locally). Initial dependency fetching
requires Internet access. Scanning requires no language server, source-project setup,
model credentials or network access.

```sh
cargo build --locked --release
./target/release/funh scan tests/fixtures --db .funh/index.sqlite --strict
```

The scan returns JSON with a `snapshot_id`, `source_complete`, `sealed`, function count,
per-file coverage and explicit exclusions. The supplied fixtures produce **37 functions**.
Use the returned identifiers in subsequent commands:

```sh
funh list --db .funh/index.sqlite --snapshot <snapshot-id> --format json
funh list --db .funh/index.sqlite --snapshot <snapshot-id> --format jsonl --source
funh get --db .funh/index.sqlite --snapshot <snapshot-id> --id <function-id> --format json
funh verify --db .funh/index.sqlite --snapshot <snapshot-id> --format json
funh run create --db .funh/index.sqlite --snapshot <snapshot-id> --analyzer dummy-v1
funh run next --db .funh/index.sqlite --run <run-id> --format json
funh run complete --db .funh/index.sqlite --run <run-id> --id <function-id> --result-file result.json
funh run status --db .funh/index.sqlite --run <run-id> --format json
```

Install the executable onto your PATH with `cargo install --path . --locked`, or use
`./target/release/funh` in each command above. `result.json` can contain any valid JSON,
for example `{"answer":true}`. The analyzer name identifies configuration; it does not
execute an analyzer. `next` returns one stored-source record, or JSON `null` if no pending
item remains. Claimed or failed items can still exist when it returns null.

## Coverage and extraction

Supported extensions: JS/JSX (`js`, `jsx`, `mjs`, `cjs`), TypeScript (`ts`, `mts`, `cts`),
TSX, Python, Rust, C (`c`, `h`), and C++ (`cc`, `cpp`, `cxx`, `hpp`, `hh`, `hxx`).
UTF-8 is required. Header interpretation can be overridden:

```sh
funh scan ./repo --language h=cpp --include 'src/**' --exclude '**/generated/**'
funh scan ./repo --allow-partial --no-ignore --max-file-bytes 8388608 --max-nodes 1000000
```

Include/exclude globs match relative paths; exclude wins. The ignore crate applies
`.gitignore`, `.ignore`, repository excludes and configured global git ignores, including
parent rules, without requiring a `.git` directory. Hidden source files are eligible.
`--no-ignore` bypasses these rules for reproducible scans independent of local ignore
configuration. Excluded regular files are listed with reasons; symlinks are listed and
never followed. Non-UTF-8 paths and traversal failures cause explicit command failure.
Directories themselves are not counted as excluded files. Original project contents are
never executed. Avoid concurrently renaming directories while walking a repository;
the default symlink policy is not a hardened filesystem sandbox against a hostile process.

Discovery is a full Tree-sitter AST walk with pinned grammar versions. All anonymous and
nested functions are retained. Types and declaration-only signatures supply no executable
body and are excluded. Candidate signature nodes are accounted for separately. Prototypes
and function types in C/C++ are not callable-definition candidates. Decorators, Rust
attributes and C++ template wrappers belong to the associated definition span.
[Grammar details and node mismatches](docs/GRAMMARS.md) document these decisions.

Kinds: `function`, `method`, `constructor`, `destructor`, `getter`, `setter`, `arrow`,
`lambda`, `closure`, `generator`. A generator method remains `method` with a generator
flag. Flags also record syntactically available async/static/unsafe/export/decorator/
template/inline properties. These are syntax facts, not resolved symbol visibility.
Python `__init__` remains a method. Anonymous names may be null; simple assignment names
are inferred from AST fields. Qualified names are syntactic and may be absent or incomplete.
C++ qualified definitions are classified as methods without semantic namespace resolution.

Strict mode is the default. Any parse ERROR/MISSING, encoding/I/O/resource failure or
unresolved candidate prevents sealing and exits nonzero. Its full coverage report is
written to stdout; the error goes to stderr. A rejected strict scan does not persist an
inventory. `--allow-partial` seals an inspectable snapshot whose `source_complete=false`
is permanent and visible in manifests and run creation. Partial snapshots may be dispatched
explicitly through the same run API; their evidence must not be mistaken for full coverage.

Each file reports parse status, coverage status, candidate/extraction/declaration/unresolved
counts, error ranges, gap details and macro sites. Successful files satisfy:

```
candidates = extracted + excluded declarations + unresolved
```

Macro expansion and preprocessor uncertainty are reported separately and do not prevent
source-level completeness. Both visible preprocessor alternatives remain distinct source
occurrences. Rust macro token trees are not parsed as generated functions. Runtime-generated
functions, template instantiations, imports, compiler semantics and macro expansion are
outside v0.1. A clean parse alone is not a proof of conceptual completeness: the independent
oracles and pinned grammar contract remain essential.

## Snapshot format and identity

Schema version 1 uses JSON records with `snapshot_id`, occurrence `id`, `language`, normalized
relative `path`, `kind`, optional `name`/`qualified_name`/`parent_id`, definition and body byte
bounds, display positions, `source_hash`, `file_hash`, flags and original `node_kind`.
`get`, `next` and `list --source` additionally include UTF-8 `source`. Plain list omits source.
Offsets are zero-based, half-open bytes; lines are one-based and columns zero-based UTF-8
bytes. Outer source deliberately includes inner callable text.

SQLite stores whole original files as content-addressed BLOBs. A file is read once into a
bounded buffer, and that same buffer supplies parsing, hashing and storage. Files may change
between reads; this is a collection of exact per-file reads, not an atomic filesystem-wide
transaction. Oversized files retain only a bounded prefix with an explicit resource gap and
cannot certify completeness. The default limit is 16 MiB per file and 2,000,000 AST nodes.
The AST limit is checked during traversal after parsing; there is no wall-clock parser timeout.

Snapshot hashes use structured JSON arrays over schema, exact grammar/parser/adapter versions,
inclusion policy and sorted path/file-hash/parse-status entries. Read-failure statuses distinguish
unavailable source from a successfully read empty file. Exclusion reports and informational creation
times do not affect identity. Occurrence hashes use structured arrays over snapshot/path/span/
node kind/canonical lexical ordinal. All hashes are SHA-256 with a `sha256:` prefix. Identical
source in different paths remains distinct. Queue order compares UTF-8 path bytes, start, end,
node kind and ID. IDs identify one snapshot, not an enduring symbol across edits.

Foreign keys, transactions and immutable inventory triggers protect sealed inventory records.
Dispatch state is separate. `verify` checks stored byte hashes, exact source slices, ranges,
record consistency, re-parsed coverage, IDs, nesting and canonical manifest order. Stored
source is returned after the working files change or disappear. SQLite is local storage,
not a security boundary against a user with write access to the database.

## Dispatch recovery

Claims are atomic `BEGIN IMMEDIATE` transactions. Repeated `next` calls claim distinct pending
items in canonical order. The intended integration is one synchronous worker. There are no leases,
background recovery or automatic retries. Completion is idempotent for the same parsed JSON
result and rejects conflicting second results.

```sh
funh run fail --run <run-id> --id <id> --code timeout --message 'Analyzer timed out' --retryable
funh run retry --run <run-id> --id <id>
funh run recover --run <run-id> --id <claimed-id>
```

Use the same `--db` as your run, or accept `.funh/index.sqlite`. Without `--retryable`, a failure
is final. `retry` only requeues a retryable failure. After a worker stops, `recover` explicitly
requeues a claimed item; first ensure the original worker is stopped. Every claim increments
attempt count. An append-only event history preserves fault, retry, recovery and completion
evidence; the latest error remains on the item even after success. This guarantees durable
queue transitions, not exactly-once external side effects. External analyzers should use
occurrence IDs as their own idempotency keys. Run status is derived from persisted item states.

## Weakness decisions

`data/weaknesses/` embeds the scorpius-cli catalogs: 969 MITRE CWEs, 213 reliability (`REL-`)
and 10 performance (`PERF-`) weaknesses. Provenance and hashes are in its `PROVENANCE.md`.

```sh
funh weaknesses list --language rust            # deterministic plan: nodes, roots, skips with reasons
funh weaknesses plan --snapshot <snapshot-id>   # dry-run question/request budget, no network
JEV_API_KEY=... funh analyze --snapshot <snapshot-id> --provider jev
OPENAI_API_KEY=... funh analyze --snapshot <snapshot-id> --provider openai
funh analyze --run <run-id> --provider jev --retry-failed   # resume; same provider flags required
funh run findings --run <run-id> --format jsonl
funh run recall --run <pruned-run> --baseline <exhaustive-run>   # what pruning missed, and why
```

Each question asks about exactly one weakness and gets an independent probability: a Jev
`noul` (`POST /v1/systemone`) or an OpenAI `predicate` (`POST /v1/decisions`). The function
record (language, path, kind, name, exact stored source) is the shared state. `--provider
mock --mock-file script.json` is a deterministic offline provider for tests.

To keep this fast and cheap, BETSY layers six measures:

1. **Deterministic prefilter** (profile `function-v2`). Entries are skipped, each with a
   recorded reason, when:
   - their explicit language platforms don't match the function's language;
   - they are hardware-only;
   - every mode of introduction lies outside source code.

   MITRE `Prohibited`/`Discouraged` entries and Pillars are asked only as hierarchy gates and
   are never reported. Fixtures go from 1,192 questions per function to 706–939, depending on
   the language.
2. **Hierarchical early exit.** CWEs form a forest over their primary `ChildOf` edges in view
   CWE-1000. REL and PERF entries hang under the first planned CWE they name as `PeerOf`;
   the rest are roots. Round 1 asks the roots. Children are asked only when the parent's
   probability reaches `--gate-threshold` (default 0.15, set low for recall); a refusal also
   descends. Unasked subtrees are recorded as `gated` with the parent's probability.
   - An only child is *spliced*: it is asked in its parent's round, since gating it alone
     would save one question at the cost of a round. It still gates its own children, and
     they open only if both it and its parent pass.
   - `--max-rounds N` asks every remaining descendant in round N and stops, trading
     questions for latency. The C plan is six rounds deep.
   - `--exhaustive` turns gating off. Comparing it with a gated run using `funh run recall`
     is how to tune the threshold.
3. **Trait filter** (`--traits`, off by default until tuned). `data/weaknesses/traits.json`
   defines observable function traits (buffer access, pointers, concurrency, file system,
   network, crypto, iteration and so on) and tags weaknesses with the traits of which at least
   one must be present.
   - Tags are inherited down the hierarchy, and untagged entries are always asked, so a
     missing tag can only cost questions, never a finding.
   - Each node carries its own requirement and the union over its subtree, as bitmasks.
   - An extra first round asks every trait. Syntax nodes listed under `present_if` prove a
     trait present without asking; absence is never concluded from syntax, since macros,
     callees and aliases can hide anything.
   - A trait counts as present at or above `--gate-threshold`, or when refused. A subtree
     with none of its traits present is recorded once with origin `trait`. A node whose own
     traits are absent but whose descendants' are present is skipped, and its children are
     considered in the same round.
   - The trait round counts towards `--max-rounds`. Trait answers are cached like any other,
     and the run identity includes the trait catalog hash.
4. **Batching.** All of a round's questions go into one request, or `ceil(n/limit)` requests
   (`--max-questions`; default 100 for Jev, 400 for OpenAI, its documented maximum). A 413 or
   422 halves the chunk and retries.
5. **Prefix reuse and concurrency.**
   - The function is the shared prefix of every request, and OpenAI requests carry
     `prompt_cache_key=<source_hash>`. The first chunk of a round is sent alone to warm the
     cache, then the rest run concurrently.
   - `--concurrency` functions are evaluated in parallel, and `--max-inflight` caps the
     requests in flight.
   - Only the coordinator thread writes SQLite and claims work through the existing
     dispatcher.
   - Requests retry with backoff on 408, 429 and 5xx, honouring `Retry-After`. A provider
     failure marks the function `failed_retryable`, which is retried only with
     `--retry-failed`.
6. **Decision cache.** Answers are keyed by provider and model, language, `source_hash` and
   question hash. Duplicate function bodies and re-runs after edits reuse earlier answers
   without a request.

Run configuration (provider, model, catalog hash, profile, selection, thresholds, gating)
determines the run identity and is checked on resume. `--weakness CWE-89,REL-001` asks only the
listed weaknesses, flat and ungated; `--exclude-weakness` removes entries. SQLite tables:
`analysis_runs`, `weakness_plan` (per-language dispositions), `weakness_decisions` (per
function, weakness: role, round, origin `provider|cache|refused|gated|trait`, probability) and
`decision_cache`. Each dispatch item's result is a summary: questions asked, cached, gated,
trait-filtered, rounds, plan depth, trait answers, usage, and positives at or above
`--threshold`. The schema is now `user_version=3`: v1 databases are upgraded in place by
adding these tables, and v2 databases by rebuilding `weakness_decisions` to admit the `trait`
origin.

`funh run recall` compares a run with a baseline over the same snapshot. It reports the
share of the baseline's findings the run also reported, plus question and round totals for
both. Each missed finding is attributed to its cause: a `trait` filter, a `gated` ancestor
(named with its probability), or a probability `below_threshold`. Run it on labelled or
representative code before turning on `--traits` or raising `--gate-threshold`.

The Decisions response container was not fully documented when this was written. The parser
accepts an `answers`, `output`, `decisions` or `results` array of `{name, probability}`.

## Development and validation

```sh
cargo fmt --check
cargo clippy --locked --offline --all-targets -- -D warnings
cargo test --locked --offline
cargo test --locked --offline --release
cargo audit # if installed; needs an advisory database
```

See [validation results](docs/VALIDATION.md). CI runs formatting, linting, debug and release
checks with offline dependency resolution after `cargo fetch --locked`; a separate job runs
`cargo audit`. The dependency graph and production code contain no model or HTTP client.
Oracles are checked-in literal snippets and independently specified spans, not regenerated
from extractor output. Starter fixture inputs and their original oracle are preserved unchanged.
Grammar-specific expectations add node types and independently computed snippet hashes.

To extend a language, inspect its pinned `node-types.json`, add explicit candidate/classification
rules in `languages.rs`, extend the literal oracle with executable definitions and declaration
exclusions, and run all checks. Grammar or adapter contract changes must update snapshot version
metadata and rerun every golden. Keep future analyzer features outside the deterministic
extraction and queue modules.

Licensed under MIT OR Apache-2.0. Dependency licensing is summarized in
[third-party notices](docs/THIRD_PARTY.md).
