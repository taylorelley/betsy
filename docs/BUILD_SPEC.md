# Deterministic Function Extraction Harness
## Version 0.1: build specification and acceptance contract

**Status:** Ready for implementation  
**Implementation language:** Rust  
**Scope:** Source-level function extraction from JavaScript, JSX, TypeScript, TSX, Python, Rust, C and C++  
**Primary parser:** Tree-sitter with pinned language grammars  
**Storage:** SQLite, containing immutable source snapshots  
**License target:** MIT or Apache-2.0 (check upstream components before bundling)

## 1. Objective

Build a single-command, deterministic function enumerator that scans a mixed-language repository, discovers every supported callable *definition*, captures each exact source range, and produces a stable manifest. A separate, single-item dispatcher must make those functions available one at a time to an external analyzer, including a future Jev adapter.

No AI, prompts, text generation, LLM, or decision model is involved in discovery, parsing, classification, extraction, deduplication, sorting, identifier generation, or queue scheduling. Do not use regex as the primary discovery mechanism. LSP is optional enrichment, never a prerequisite to enumeration.

**Source-level coverage guarantee:** For all included files that successfully parse under the pinned language grammar and supported syntax, every node corresponding to a supported callable definition is recorded exactly once. Invalid syntax, unhandled nodes, excluded files, macro-generation uncertainty, unsupported encodings, and parser failures must be visible in a coverage report. Never silently treat these as zero functions.

Not guaranteed by v0.1: all possible C preprocessor variants, Rust macro expansions, generated files not present in the scan, Python runtime monkey-patching, JS `eval`/`new Function`, template instantiations, actual runtime dispatch, semantic call graphs.

## 2. Non-goals

- Do not implement Jev inference, LLM orchestration, model-generated analysis, an agent workflow planner, web UI, or network server in v0.1.
- Do not implement a bespoke parser for each language.
- Do not require language servers, network access, compiler toolchains, a working build, or package installation merely to inventory supplied source files.
- Do not claim MISRA/DO-178 or proof-level verification from syntax extraction.
- Do not rewrite/normalise source or expand macros during the first pass.

## 3. Architecture (one repository, one CLI)

```
source tree
  -> deterministic file walker (include/exclude policy, path normalisation)
  -> Tree-sitter grammar selected by extension
  -> depth-first AST walker
  -> language adapter: callable classification + exact byte ranges
  -> validator: parsing gaps + candidate accounting
  -> immutable SQLite snapshot and canonical manifest
  -> transactional one-at-a-time dispatcher
  -> JSON record / future external analyzer
```

Use Tree-sitter as the common parsing library. **Language adapters are rules on AST nodes, not independent parsers.** The first pass is syntactic only. Optional semantic enrichers (TypeScript compiler, rust-analyzer, Clang, pyright) will be separate modules in later releases.

### 3.1 Minimal repository structure

```
Cargo.toml
Cargo.lock
src/
  main.rs              # CLI
  scan.rs              # deterministic traversal, file filters, snapshots
  parse.rs             # parser versions, tree traversal, error detection
  model.rs             # serializable common records and enums
  languages.rs         # adapter trait + JS/TS/Python/Rust/C/C++ rules
  manifest.rs          # stable IDs, ordering, validation
  store.rs             # SQLite migration and transactions
  dispatch.rs          # one-at-a-time queue lifecycle
  report.rs            # JSON/human-readable coverage report
tests/
  fixtures/            # copy the supplied fixtures here
  expected/            # oracle expectations
  integration.rs       # golden manifests, round trips, resume, negative cases
README.md
```

Keep this as one crate until splitting modules provides a measurable benefit. Use `tree-sitter`, pinned grammar crates, `rusqlite`, `serde`, `serde_json`, `sha2`, `clap`, and `ignore` or equivalent mature small dependencies. Keep `Cargo.lock` checked in. No distributed queue, broker, service framework, or plugin loader is needed.

## 4. Exact callable taxonomy

A *callable definition* is a syntax node that supplies an executable function body, even if anonymous or nested. Do not confuse *call sites* with definitions. Record each callable node once, even when its byte range is contained in another callable.

Canonical `kind` values:

| Kind | Definition | Examples |
|---|---|---|
| `function` | Named/unnamed ordinary function | JS `function f(){}`, Python `def f`, Rust `fn f`, C/C++ definition |
| `method` | Member/associated function definition | JS object/class method, Python class method, Rust `impl`/trait default, C++ member method |
| `constructor` | Class constructor body | JS/TS/C++ constructors, Python `__init__` as method *with optional role constructor* |
| `destructor` | C++ destructor body | `~T(){}` |
| `getter` | JS/TS getter definition | `get name(){}` |
| `setter` | JS/TS setter definition | `set name(v){}` |
| `arrow` | JS/TS arrow-function expression | `(x) => x`, including implicit-expression body |
| `lambda` | Python lambda or C++ lambda | `lambda x: x`, `[](int x){...}` |
| `closure` | Rust closure expression | `|x| x+1`, `move || { ... }` |
| `generator` | Generator definition | JS `function*` and generator methods |

Use independent flags for `async`, `generator`, `static`, `unsafe`, `exported`, `decorated`, `template`, `inline`, and `macro_origin` where syntactically knowable. A generator method has `kind=method` with `generator=true`; a plain generator has `kind=generator`. `qualified_name` can be null: anonymous functions are never excluded for lacking names.

### 4.1 Required grammar coverage (verify against pinned `node-types.json`)

| Source | Included | Excluded or caveated |
|---|---|---|
| JavaScript/JSX | `function_declaration`, `function_expression`, generator counterparts, `arrow_function`, `method_definition` | Invocations; class static blocks (not a function); `new Function` created at runtime |
| TypeScript/TSX | All JS forms plus typed function implementations and methods | Function overload signatures, interface/abstract-only methods, call signatures and type aliases without bodies |
| Python | `function_definition`, including async, nested and class methods; `lambda` | `decorated_definition` is a wrapper around the same function, *not* a second function; generator expressions and comprehensions are not function definitions |
| Rust | `function_item` in modules, `impl`s, and traits when body exists; `closure_expression` | Trait-required signatures, extern declarations, and functions generated only by macros are not inventoriable before expansion |
| C | `function_definition` | Prototypes, function pointer types, function-like macros without a visible function definition |
| C++ | `function_definition` including constructors/destructors/operators/templates, and `lambda_expression` | Declarations without bodies, semantic template instantiations, invisible macro-generated definitions |

Inspect the **actual pinned grammar** rather than assuming an upstream name is stable. Add explicit tests for aliases and wrappers. Where a function definition is represented by a qualified grammar node different from the table above, update the adapter and golden fixtures; do not skip it. Treat grammar upgrades as potentially breaking contract changes.

The adapters must properly distinguish a syntactic definition from a declaration by inspecting the corresponding AST shape/body, rather than relying exclusively on a node name where that name is ambiguous.

### 4.2 Source range rules

1. `start_byte` and `end_byte` are offsets into the *original stored file bytes*, zero-based and half-open: `[start_byte, end_byte)`.
2. `source_bytes` must equal `original_file[start_byte:end_byte]` byte-for-byte. Use byte slicing. Do not pretty-print or reformat.
3. Define `definition_range`: full syntactic definition, including signature, body and modifiers. For a Python decorator, include the outer `decorated_definition` range while accounting for only one callable. For C++ template definitions, include the enclosing `template_declaration` wrapper; for other wrappers/attributes, include them when they syntactically belong to the definition.
4. Define `body_range`: the executable body expression or block, where syntactically available; null otherwise.
5. Use a nested callable's own range, not its enclosing function's range. Overlapping ranges are valid and required.
6. Display lines are one-based; display columns are documented as UTF-8 byte columns, not user-perceived character counts. Source offsets remain authoritative.
7. For syntax nodes that Tree-sitter recovers with `ERROR` or `MISSING`, retain available evidence but mark file/affected extraction unresolved and do not certify complete coverage for that file.
8. v0.1 supports UTF-8 source; unsupported byte encodings produce an explicit gap, not a successful zero-function result.

## 5. Rust interface contracts

Language adapters should be deterministic pure functions over the parsed tree and original bytes. Names and parent classifications must come from syntax, not heuristics that involve AI.

```rust
pub trait LanguageAdapter: Send + Sync {
    fn language(&self) -> Language;
    fn candidate_types(&self) -> &'static [&'static str];
    fn classify(&self, node: tree_sitter::Node<'_>, source: &[u8])
        -> Option<CallableDraft>;
}

pub struct CallableDraft {
    pub kind: FunctionKind,
    pub name: Option<String>,
    pub qualified_name: Option<String>,
    pub definition: std::ops::Range<usize>,
    pub body: Option<std::ops::Range<usize>>,
    pub flags: FunctionFlags,
    pub node_kind: String,
}
```

The common persisted record is versioned, language-neutral, and JSON-serializable:

```json
{
  "schema_version": 1,
  "snapshot_id": "sha256:<snapshot-hash>",
  "id": "sha256:<occurrence-hash>",
  "language": "typescript",
  "path": "src/example.ts",
  "kind": "arrow",
  "name": "compute",
  "qualified_name": "compute",
  "parent_id": null,
  "start_byte": 15,
  "end_byte": 38,
  "body_start_byte": 30,
  "body_end_byte": 38,
  "source_hash": "sha256:<exact-extracted-bytes-hash>",
  "file_hash": "sha256:<entire-file-hash>",
  "flags": {"async": false, "generator": false},
  "node_kind": "arrow_function",
  "source": "(x: number) => x * 2"
}
```

The values above are illustrative, **not** byte-offset test fixtures. Store original source bytes as a BLOB; JSON `source` is only supplied when valid UTF-8 and when requested. Do not conflate exact source with human-readable text.

### 5.1 Identity rules

- `snapshot_id = sha256(schema_version | parser/grammar_versions | inclusion_policy | sorted(path, file_hash))`. Use unambiguous length-prefixed/structured byte encoding, not delimiter-concatenated strings. Exclude timestamps, absolute paths, worker IDs and machine hostname.
- `id = sha256(snapshot_id | normalised_relative_path | start_byte | end_byte | AST_node_kind | lexical_ordinal)`. This is a unique *occurrence ID within one snapshot*. It is not a promise of stability after edits.
- `source_hash = sha256(extracted bytes)` enables content comparison; it does **not** identify an occurrence.
- Identical source in two different files yields two occurrences. Do not accidentally drop one with content-hash deduplication.
- A separate optional `analysis_key` may later hash source + semantic context + analyzer version + question schema, allowing safe reuse when appropriate.
- `parent_id` refers to the closest enclosing callable. Parent-child relationships are created only after all occurrences are collected.

### 5.2 Sorting rules

Canonical queue order: `(path with '/' separators, start_byte, end_byte, node_kind, id)` using a documented bytewise comparison. Sorting is independent of directory traversal order, operating system and SQLite row order. For nested functions, outer start offsets normally precede inner ones; all nested callable occurrences still appear individually.

## 6. File discovery and reproducibility

- Scan only explicitly supported extensions by default: `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts`, `.py`, `.rs`, `.c`, `.h`, `.cc`, `.cpp`, `.cxx`, `.hpp`, `.hh`, `.hxx`. For ambiguous `.h`, default to C but allow override; always record the selected language.
- Allow explicit include/exclude globs, ignored file policy, and language override. Document ignore semantics. Exclusions must appear in the report with counts and reasons.
- Do not follow symlinks by default. Never traverse outside repository root unless expressly authorised. Handle duplicate/hardlinked files as separate paths if included.
- Use relative forward-slash paths and deterministic ordering. Reject unsafe path traversal.
- Store a snapshot of the exact source bytes in SQLite (content-addressed by file hash) so `get` works even if files change after scan. Incremental and retention controls are later work.
- Detect file changes during scanning by reading each file once into memory, then parsing/storing that exact byte buffer. Produce `snapshot_id` from those bytes, not filesystem modification times.
- Do not execute untrusted project build scripts, macros, imports, npm hooks, Python imports, or binaries.

## 7. Validation and coverage report

For every included file, report:

- `parse_status`: `ok`, `errors`, `unsupported_encoding`, `unsupported_language`, `io_error`, `timeout`, `resource_limit`.
- `candidate_nodes_seen`: all known callable candidate node types encountered in a full AST walk.
- `extracted_occurrences`: accepted records.
- `unresolved_candidates`: nodes detected but not classified/extracted.
- `parse_errors`: count and byte ranges of `ERROR`/`MISSING` regions.
- `macro_sites`: count/locations for code-generation forms whose generated functions are not visible in the source parse.
- `coverage_status`: `source_complete`, `partial`, or `unverified`.

Core accounting invariant on a well-parsed file:

`candidate_nodes_seen = extracted_occurrences + explicitly_excluded_declarations + unresolved_candidates`

Important: Python `decorated_definition` wrappers and other structural wrappers are not counted as independent candidates. Language adapters must document exact candidate definitions. Use a second AST walk or a separately implemented fixture oracle to detect missed candidates. A parser reporting no `ERROR` is *necessary but not sufficient* to prove every conceptual function is identified.

The CLI defaults to **strict mode**: any unexplained candidate, parse error, unreadable included file, unsupported encoding, or otherwise uncertified included file prevents sealing a snapshot for dispatch. A `--allow-partial` flag permits inspection, with `source_complete=false` recorded permanently. Macro-expansion uncertainty is reported separately from source-level coverage and does not block a `source_complete` scan.

## 8. SQLite data model

Create tables (normalised names indicative, migrations versioned):

- `snapshots(id PRIMARY KEY, schema_version, parser_versions_json, inclusion_policy_json, status, created_at)`; `created_at` informational only, not part of hash.
- `file_blobs(sha256 PRIMARY KEY, bytes BLOB)`.
- `files(snapshot_id, path, language, blob_hash, parse_status, coverage_json, PRIMARY KEY(snapshot_id, path))`.
- `functions(id PRIMARY KEY, snapshot_id, path, parent_id, kind, name, qualified_name, start_byte, end_byte, body_start_byte, body_end_byte, source_hash, flags_json, node_kind)` with unique occurrence constraints and canonical-order index.
- `gaps(snapshot_id, path, kind, start_byte, end_byte, details_json)`.
- `dispatch_runs(id PRIMARY KEY, snapshot_id, analyzer_config_hash, status)`.
- `dispatch_items(run_id, function_id, status, attempt, result_json, error_json, PRIMARY KEY(run_id, function_id))`.

Enable foreign keys and SQLite transactions. A sealed snapshot is immutable. The dispatch run is stateful and separate from the extraction snapshot.

## 9. One-function-at-a-time dispatch

Implement a synchronous, single-worker queue for v0.1. State machine:

```
pending -> claimed -> completed
                  \-> failed_retryable -> pending (after explicit retry)
                  \-> failed_final
```

- `next(run_id)`: inside a SQLite transaction, atomically claim the earliest eligible pending function in canonical order. Return exactly one record.
- `complete(run_id, function_id, result_json)`: record output once with idempotent retry semantics.
- `fail(run_id, function_id, code, message)`: persist fault, keep audit trail. Retries never silently discard errors.
- On restart, recovery of a `claimed` item must be explicit and safe (e.g., single-worker recovery command with attempt count), not hidden.
- Dispatcher must return original-source bytes and metadata from the immutable snapshot, not reread current source on disk.
- `run --analyzer-command ...` (optional v0.1 feature) may invoke a test subprocess once per item with JSON on stdin and result JSON on stdout; keep this disabled by default. Never execute the repository itself as part of extraction.
- Jev integration should be a subsequent provider adapter consuming the same record interface. Jev should take typed, bounded questions and structured context, not be asked to generate a missing function inventory.

## 10. Required CLI

```bash
betsy scan ./repo --db .betsy/index.sqlite --strict
betsy scan ./repo --db .betsy/index.sqlite --allow-partial
betsy list --db .betsy/index.sqlite --snapshot <id> --format json
betsy get --db .betsy/index.sqlite --snapshot <id> --id <function-id> --format json
betsy verify --db .betsy/index.sqlite --snapshot <id> --format json
betsy run create --db .betsy/index.sqlite --snapshot <id> --analyzer dummy-v1
betsy run next --db .betsy/index.sqlite --run <run-id> --format json
betsy run complete --db .betsy/index.sqlite --run <run-id> --id <function-id> --result-file result.json
betsy run status --db .betsy/index.sqlite --run <run-id> --format json
```

Implement JSONL streaming in `list` as a small optional convenience. All commands should have stable JSON outputs, explicit errors and nonzero exit codes on failure.

## 11. Golden fixtures and exact test oracle

Use the supplied `fixtures/` directory, `expected/expected_counts.json` and `expected/expected_occurrences.json`. Treat these as independent *acceptance targets*. The latter contains 37 hand-selected callable snippets, exact byte offsets, expected generic kinds and lexical parent labels. The coding agent must correct grammar-specific implementation details without weakening a fixture target. Note that the offsets were derived by exact literal matching from fixture source, **not from any parser output**.

| Fixture | Expected callable definitions | Major cases |
|---|---:|---|
| `example.js` | 12 | named/nested, arrows/callbacks, expression, generator, object getter/setter, class methods, async arrow |
| `example.ts` | 5 | overload signature filtering, type-only declarations, class accessor bodies, arrow and callback |
| `example.py` | 6 | nested def, lambda, decorated class method, async method, nested lambda |
| `example.rs` | 6 | free fn, closures, trait default, trait-only declaration excluded, impl methods |
| `example.c` | 2 | ordinary inline function, function returning function pointer |
| `example.cpp` | 6 | ordinary function, lambda, ctor, dtor, method, function template |
| **Total** | **37** | Source-level callable definitions |

Additional mandatory fixtures to implement, with explicit expected source snippets:

- JS: async generators, concise arrows, parenthesised expression arrows, object shorthand methods, optional chaining call sites (not functions), private class methods, JSX callback, chained callbacks, class-field arrows.
- TS/TSX: generic arrow ambiguity in TSX, overload implementation, `declare`, ambient classes, interface signatures, namespace function, decorated methods, nested generic functions.
- Python: multi-decorator function, multiline signature, Unicode identifiers, class/nested class method, generator `def` with `yield`, lambda in defaults, multiline lambda body limits, `async def` nested in `def`.
- Rust: associated function, `pub async fn`, `unsafe fn`, `const fn`, trait default, required signature, closure inside closure, macro invocation (expansion reported as unknown), `cfg` attributes.
- C: prototypes, preprocessor branches (both source definitions counted if visible), header static inline, old-style function definition if grammar supports it, function pointers.
- C++: namespaces, class inline/out-of-line methods, operator overloads, conversion operators, function-try-block, templates, lambdas nested within lambdas, attributes, preprocessor alternatives.
- Failure cases: invalid syntax, truncated file, non-UTF-8 file, unreadable file, symlink escape, duplicate source contents in two paths, empty repo, no functions, deleted files after scan, intentional file change during scan, huge file/resource limits.

### 11.1 Acceptance tests

1. **Fixture inventory:** all six starter files extract exactly 37 callable occurrences, with no false declarations and all expected positions/snippets verified.
2. **Byte fidelity:** for every record, `source_bytes == stored_file_bytes[start_byte..end_byte]`; matching SHA-256; all body ranges inside definition ranges.
3. **Reproducibility:** scan the same fixture directory three times with changed traversal order, absolute root location and process startup conditions; compare canonical JSON manifests excluding informational times/DB IDs; snapshot and occurrence hashes must match.
4. **Nesting:** every inner callable is present and has the closest enclosing callable as `parent_id`; the outer source still contains the nested code.
5. **Failure visibility:** malformed included files cause strict scan failure and explicit gap coordinates; partial mode still marks gaps and does not claim complete coverage.
6. **Header/config preservation:** identical functions in different paths/configuration-sensitive branches remain separate occurrences; any future semantic deduplication must not delete source occurrences.
7. **Queue exactly once in ordinary operation:** repeated `next` yields one distinct pending function per claim in fixed order, then empty. Completion/resume preserves results. Atomic transaction guards duplicate claims.
8. **Interrupted queue:** after abrupt termination with a claimed function, restart reports it as claimed until explicit recovery; it is never silently completed or lost.
9. **Snapshot immutability:** change/delete original source after scan; retrieval returns original stored exact bytes and IDs unchanged.
10. **Grammar-version test:** upgrades of grammar crates must rerun goldens and explicitly update parser version in snapshot identity.
11. **No AI/network:** run all extraction and tests offline with no model credentials or network requests; instrument or inspect dependencies to verify no AI invoked.
12. **Security:** exclude symlink traversal by default; reject unsafe path escapes; do not execute repository contents as scan side effects.

Test both debug and release builds; use deterministic fuzz/property tests for byte-range containment, stable ordering and duplicate IDs. Do not infer completeness from the harness's own reported counts alone; checked-in golden oracle data is required.

## 12. Build phases and done criteria

### Phase A: Parser and taxonomy

- Pin grammars, implement all language adapters, AST traversal and normalised spans.
- Include every named, anonymous and nested callable in the starter golden fixtures.
- Done: 37/37 starter fixture callable definitions and exact spans verified against the checked-in independent occurrence oracle.

### Phase B: Inventory and coverage

- Build deterministic file scan, immutable byte snapshots, SQLite manifest, strict/partial coverage reporting.
- Done: reproducible manifests and all failure-path coverage tests passing.

### Phase C: Sequential dispatch

- Implement run creation, `next`, `complete`, `fail`, explicit resume and JSON result persistence.
- Done: single-worker stable processing; interruption/retry tests pass without duplicates/loss.

### Phase D: Project hygiene

- README with quickstart, taxonomy, limits, JSON schema, extension instructions and test results.
- CI `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `cargo audit` if available; offline golden test job.
- Done: clean build, tests green, no silent coverage gaps, reproducibility documented.

**Ship v0.1 after D.** Do not add Jev, LSP orchestration, distributed workers, a frontend, or richer semantic analysis to this milestone.

## 13. Future milestone v0.2 (not part of acceptance)

Add an analyzer interface with typed requests and outputs. Jev receives one extracted function record plus *deterministically generated* bounded features and optionally semantic context from LSP/compiler tools. Queue is still controlled by the harness. Typed decision outputs and confidence are logged separately from proven parser facts. Never promote a model score into a correctness proof.

Potential provider contract:

```json
{
  "schema_version": 1,
  "occurrence_id": "sha256:...",
  "snapshot_id": "sha256:...",
  "source_hash": "sha256:...",
  "analysis_profile": "risk-triage-v1",
  "features": {"lines": 42, "nested_callables": 2, "language": "rust"},
  "source": "..."
}
```

Also consider native semantic passes for TypeScript, Rust, C/C++ and Python, generated-code scanning, macro expansion and incremental manifests. These are separate from source-level enumeration.

## 14. Agent instructions

Implement this specification inside one Rust repository. Do not weaken a fixture or coverage rule to make tests pass. Before coding, inspect installed/pinned Tree-sitter grammar node types and record any taxonomy mismatches. Prefer a simple AST DFS with explicit language-node classification over a query-only approach that could truncate matches; if queries are used, detect any match-limit overflow and fail as incomplete. Keep extraction free of AI and network calls. Make deterministic output and explicit coverage gaps more important than speed. Run tests and provide the exact command/results and any remaining unsupported constructs. Do not claim full coverage unless the strict coverage report and checked-in oracle both pass.

## 15. Reference documentation

- Tree-sitter Rust QueryCursor: https://docs.rs/tree-sitter/latest/tree_sitter/struct.QueryCursor.html
- Tree-sitter CLI query docs: https://tree-sitter.github.io/tree-sitter/cli/query.html
- JavaScript grammar: https://github.com/tree-sitter/tree-sitter-javascript
- TypeScript/TSX grammars: https://github.com/tree-sitter/tree-sitter-typescript
- Python grammar: https://github.com/tree-sitter/tree-sitter-python
- Rust grammar: https://github.com/tree-sitter/tree-sitter-rust
- C grammar: https://github.com/tree-sitter/tree-sitter-c
- C++ grammar: https://github.com/tree-sitter/tree-sitter-cpp
- rust-analyzer macro expansion architecture (later work): https://rust-analyzer.github.io/book/contributing/guide.html
