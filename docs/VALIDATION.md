# Validation — 2026-10-25

Executed in the supplied Linux x86_64 workspace, using rustc 1.99.1 and cargo 1.99.1,
with the checked-in Cargo.lock and pinned Tree-sitter grammars.

| Command | Result |
|---|---|
| `cargo fmt --check` | Passed |
| `cargo clippy --locked --offline --all-targets -- -D warnings` | Passed, no warnings |
| `cargo test --locked --offline` | Passed: 16 integration tests, 0 failures |
| `cargo test --locked --offline --release` | Passed: 16 integration tests, 0 failures |
| `strace -f -e trace=network -o /workspace/scratch/betsy-network.trace cargo test --locked --offline` | Passed: 16 tests; no socket, connect, sendto, bind or listen calls |
| `./target/release/betsy scan tests/fixtures --db .betsy/index.sqlite --strict` | Sealed, source_complete=true, 37 occurrences |
| `./target/release/betsy verify --db .betsy/index.sqlite --snapshot <returned-id> --format json` | valid=true; 37 occurrences |
| CLI smoke: scan, list, get, verify, run create, next, complete, status, repeat scan | Passed; 1 completed, 36 pending; repeated snapshot ID identical |
| `cargo audit --version` | Not installed locally; audit not run. Separate CI job installs and runs cargo-audit. |

The 37 starter occurrences match every independent byte span, exact snippet, kind,
parent label, additional grammar-specific node type and independently computed SHA-256.
Per-file counts also match the untouched supplied count oracle. The 47 extended literal
oracles pass for JSX, TSX, Python, Rust, C headers and C++.

Additional tests exercise grammar/version contracts, syntax/encoding/resource failures,
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

## Scope limits

No semantic resolution, macro expansion, dynamic function discovery, Jev/LLM integration,
UI or server is included. C++ qualified free functions cannot always be distinguished
from out-of-line members without semantic context; qualified names and flags are syntactic.
The file size limit applies before parsing, while the AST node limit applies after parsing;
there is no parser wall-clock timeout. Huge files retain a bounded prefix and an explicit
resource gap. Directory traversal failures stop the command explicitly. Symlink exclusion
is a default scan policy, not protection against malicious concurrent filesystem mutation.
Source completeness applies only to successfully parsed supported syntax under the pinned
adapters. It is not a claim about all runtime callable code or all future grammar constructs.
