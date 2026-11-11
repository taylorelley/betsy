# Weakness cards

BETSY asks a decision model one yes/no question per weakness about one function's code.
Published weakness catalogues are written for people, and their prose is a poor fit for that:
exclusions sit at the end of long descriptions, broad product-level entries cannot be decided
from one function, and sibling CWEs describe the same code pattern. So each weakness BETSY
knows is a card under `data/weaknesses/cards/`, and those files are the only weakness
definitions in the repository. The format is described in the [README](../README.md#weakness-cards).

The cards began as an overlay on catalog files copied from scorpius-cli (MITRE CWE 4.20 plus
`REL-` and `PERF-` entries) and on BETSY's own extension files. Those files have been removed.
Each card now carries what the plan needed from them: the name, the abstraction, whether it
is a gate, the languages it applies to and its parents. Plans and question wording for every
language were compared before and after the removal and are unchanged, apart from the order of
entries. The earlier files remain in the git history.

## Status

**Complete in coverage, not yet validated and not cleared to ship.**

- There are 1,093 cards. 1,013 are checkable; 80 are marked not function-checkable and listed
  below. Six of those 80 (CWE-382, CWE-564, CWE-609, CWE-690, CWE-1051 and CWE-1106) exist only
  because another card's `distinguish_from` names them; they were never planned.
- Every card has `status` `draft`. No card has been marked `reviewed` or `validated`.
- The 215 other entries of the earlier catalog files that had no card were never planned for
  any language (hardware-only, introduced outside code, wrong language, or a gate with nothing
  below it). They are no longer known to BETSY, so naming one with `--weakness` is an error.
- 116 cards are BETSY's own weaknesses (REL-214 to REL-311 and PERF-011 to PERF-028); see
  "BETSY's own weaknesses" below.
- The cards for `CWE-` entries are new wording derived from MITRE content. Legal must confirm
  that the CWE terms of use allow this, with the notice in `data/weaknesses/CWE_NOTICE.txt`
  kept, before the cards ship. Provenance is recorded in `data/weaknesses/PROVENANCE.md`.
- No card has been checked against a model or labelled code. Treat them as drafts.

Each card was drafted from its catalog entry, its parent, children and siblings in the plan, and
the brief summarised in "Writing a card" below. Each card was then checked mechanically: every
planned language receives at least one present and one not-present pattern; rendered criteria
stay within 1,500 characters; distinguish IDs exist; gates stay checkable; and no ten consecutive
words are copied from the entry's description or extended description. The length and ID checks
are unit tests. The copying check was a unit test until the catalog files were removed; it
passed on the last commit that had them, and the card wording has not changed since. A human
has read only a sample.

Skipping the uncheckable cards saves 51 to 72 questions per function, depending on the
language; the fixtures now plan 709 to 938.

## Structure and audit

The cards were restructured so that each one is self-contained and gaps are visible:

- **One card, one place.** Trait requirements moved from `traits.json` onto each card
  (`requires`), and the two hard-coded root exceptions became a `detached` reason on CWE-617
  and REL-026. The single 32,000-line file became 22 files under
  `data/weaknesses/cards/<catalog>/`, grouped by top-level CWE or by source standard. Plans
  and all 5,393 questions were byte-identical before and after this step.
- **Sources and status.** `REL-` and `PERF-` cards carry `sources`, recovered from the rule
  mappings in the removed catalog files (MISRA C:2012, Goldberg 1991, SEI CERT C, C++ and
  Java, and the references named below); rule titles were not carried over. 81 cards have
  none: REL-001 to REL-025, whose origin the earlier files did not record, and the cards
  written for BETSY without a published rule. `status` records how far a card has been
  checked.
- **Audit.** `betsy weaknesses audit` reports coverage and defects; see the
  [README](../README.md#auditing-the-cards). Its first run found the following, now fixed:
  - CWE-94, CWE-96 and CWE-470 (code injection and unsafe reflection) were planned for
    JavaScript but not TypeScript or TSX. They now reach all three.
  - CWE-362 (race condition) was limited to C and C++ although its patterns are
    language-neutral, so races were never asked about in the other languages and its
    children CWE-367 and CWE-368 were asked of every function there. It now applies to every
    language.
  - Five `distinguish_from` links named cards that are never planned for the same language;
    they were removed.
- **Fewer questions in round 1.** 32 cards about one syntactic construct now require a
  syntax trait, which the parser settles for free, and 13 other root cards gained trait
  requirements that `--traits` can use. For C and C++, the findings asked of every function
  whatever its content fell from 24 to 12; for Rust from 33 to 6; for the other languages
  from between 8 and 11 to 3 or 4. The
  remaining ones are pinned in `tests/expected/always_asked.json`. No model-asked gate cards
  were added, since their effect on recall cannot be measured without provider runs.

What the audit still shows, for a person to decide:

- CWE-364 (signal handler race) has only C and C++ patterns, so its children CWE-432, CWE-828
  and CWE-831 are roots in the other languages; CWE-97 is a root in C, C++ and Rust because
  CWE-96 is not planned there.
- 11 cards are limited to some languages although every pattern is language-neutral (CWE-96,
  CWE-543 and nine `REL-` cards from MISRA C), so the limit may be narrower than the weakness.
  Separately, CWE-248 (uncaught exception) is limited to C++ and has only C++ patterns,
  although exceptions go uncaught in other languages too.
- 744 of 1,444 `distinguish_from` links are one-way, and 134 checkable cards have none.
- 428 to 483 of the cards planned for each language have no pattern specific to it.

## BETSY's own weaknesses

The scorpius-cli catalogs had no reliability entries for JavaScript, TypeScript, Python or C++,
and only ten performance entries (REL-001 to REL-213 and PERF-001 to PERF-010). BETSY added its
own, continuing the same ID sequences:

- REL-307 to REL-311, added after the first audit, each checked against the existing cards by
  keyword: a global or sticky regular expression reused across calls, a promise returned
  without `await` from inside a `try` block, and framework state mutated in place (JavaScript,
  TypeScript and TSX); a `str` sliced at a byte offset that may split a character (Rust); and
  a coroutine or future that is created but never awaited (Python and Rust).
- REL-214 to REL-242: JavaScript (floating promises, async
  callbacks in `forEach`, unchecked `NaN` from parsing, `for...in` over arrays, `typeof null`,
  implicit globals, comparator-less `sort`, `return` followed by a line break), TypeScript only
  (`as any` and double assertions, non-null `!`, `@ts-ignore`, unvalidated external data cast to a
  type), Python (mutable defaults, `assert` as validation, also for C), Python and JavaScript
  (late-binding closures, mutation while iterating, falsy values taken as missing, iterators
  consumed twice, naive and aware date-times), C++ (exceptions leaving destructors, iterator
  invalidation, views of temporaries, use after `std::move`, manual `lock`/`unlock`, slicing,
  virtual calls in constructors, dangling reference captures, unjoined `std::thread`) and Rust
  (guards or `RefCell` borrows held across `.await`).
- PERF-011 to PERF-024: front removal from arrays in a loop,
  sequential `await` of independent calls, growth without reserving capacity, large by-value
  copies, deep copy by serialisation, exceptions for routine cases in loops, unbuffered small I/O,
  costly disabled log messages, fetching rows to count them, locks held across slow I/O,
  busy-waiting, unmemoised overlapping recursion, materialising a sequence to scan it once, and
  DOM layout thrashing.

Each card lists as a parent a CWE planned for all of its languages, so it is gated under that
CWE rather than asked as a root; a unit test checks this. Where a candidate was already covered by a planned card (for example loose `==` under
CWE-1024, `is` with literals under CWE-595, bare `except` under CWE-396, regex compilation in a
loop under PERF-006), the entry was not added. Language-specific cards list their `languages`
(a TypeScript weakness lists `typescript` and `tsx`; a C one usually lists `cpp` too).

### Entries from coding standards and references

A second round compared the cards with published coding standards and reference material, and
added an entry wherever a function-level defect had no card. The wording is BETSY's own. The
sources are recorded here by ID range; the rule-by-rule mapping was in the removed extension
files and remains in the git history.

- **SEI CERT C and C++ (REL-243 to REL-271).** Of 205 rules, 119 were already covered, 10 cannot
  be decided from one function, and 32 were closer to an existing card than to a new entry.
  The new entries cover struct padding copied out or compared with `memcmp`, C23
  `[[unsequenced]]` functions with side effects, writes through and stale pointers from
  `getenv`/`strerror`/`localeconv`, exit and fault-signal handlers that do not end the program,
  `errno` tested without being reset, update streams switched without a flush or seek, mutexes
  destroyed while held, condition waits and weak compare-exchange outside a loop, single notifies
  for mixed predicates, asynchronous thread termination, unnamed C++ guards, polymorphic arrays,
  mixed iterator ranges, stateful predicates, raw storage without construction, misaligned
  placement new, replacement `operator new` and handlers that break their contract,
  function-try-block handlers using members, handler order (also for Python), catching by value,
  deleting through a base without a virtual destructor, initialiser order, self-assignment,
  pointer-to-member misuse, copies that change their source, and `noreturn` functions that return.
- **QuantifiedCode Python anti-patterns, W3Schools JavaScript mistakes and the SEI CERT Oracle
  Java standard (REL-272 to REL-299).** BETSY does not scan Java, so only Java rules whose defect
  also occurs in a supported language were used, and pure style items were left out. Five
  Java-only CWEs (CWE-395, CWE-486, CWE-572, CWE-581, CWE-609) are never planned; their
  transferable forms are REL-293, REL-279, REL-295 and REL-288. The new entries cover `+` on
  values that may be strings, arrays used as maps, shadowed built-ins, wrong `super()` arguments,
  loop `else` without `break`, wrong special-method signatures, mixed return types, type tests by
  exact class or name, discarded results of non-mutating methods, assertions with side effects,
  changes to loop-variable copies, `Decimal` from a float, floats compared as strings, binary data
  decoded as text, default text encodings, `this` escaping a constructor, inconsistent equality
  and hashing, broken comparators, mutated hash keys, cleanup left to finalisers, cleanup errors
  masking the original, catching null-dereference errors, libraries calling `exit`, `Thread.run`
  instead of `start`, pool tasks waiting on their own pool, lost background-task errors,
  thread-local state left in pooled threads, and undrained child-process pipes.
- **"Every programmer should know" and the Machinery bug taxonomy (REL-300 to REL-306).** Most
  of the linked material (floating point, Unicode, regex, crypto, latency, naive date-times) was
  already carded. The new entries cover listeners, timers and subscriptions with no cleanup, wall
  clocks used for durations, fixed-length calendar arithmetic, digit-string identifiers parsed as
  numbers, rigid name and address formats, unbounded retries without backoff, and locale-sensitive
  case conversion for comparison. Architecture-level fallacies, such as changing topology or
  clocks ordered across machines, cannot be decided from one function and were left out.
- **Drepper, "What Every Programmer Should Know About Memory" (PERF-025 to PERF-028).** Arrays
  walked against their storage order (including naive matrix products), false sharing between
  per-thread slots, one shared atomic counter updated per item by every thread, and linked lists
  used only for sequential scans. They hang directly under the CWE-400 gate rather than under
  CWE-1176 or CWE-1050, whose questions (avoidable work, resources acquired per iteration) a
  cache-hostile loop does not answer yes to; a test checks this. Struct layout, prefetch hints,
  non-temporal stores, TLB and NUMA placement depend on type declarations, hardware or
  deployment and were left out.

Where a CERT C or C++ rule was a form of an entry that already had a card, the card gained a
pattern instead of a new entry being added: REL-034, REL-039, REL-096, REL-113, REL-132, REL-135,
REL-145, REL-146, REL-165, REL-172, REL-235, CWE-191, CWE-364, CWE-366, CWE-475, CWE-476,
CWE-687, CWE-754, CWE-758, CWE-762, CWE-772 and CWE-1341. REL-174 (`<tgmath.h>`) stays
uncheckable, since its reason still holds. The POSIX side of FIO32-C (opening a FIFO or device as
if it were a file) was not added to CWE-67, whose card is about Windows device names; it has no
card yet.

## Language-specific patterns

C++ reads `c` patterns and TypeScript and TSX read `javascript` ones, so those languages mostly
saw C and JavaScript idioms. Cards now carry `cpp` patterns where C++ code looks different (STL
containers and `at()`, iterators, smart pointers and RAII, `new`/`delete`, `std::thread` and
`std::mutex`, casts, `string_view`, streams), `typescript` patterns where types change the
picture (type assertions, `any`, non-null `!`, typed but unvalidated request bodies, schema
validators as guards), and `tsx` patterns for React and JSX sinks (`dangerouslySetInnerHTML`,
`href` from data, `target="_blank"`). Keys were added only where the language changes what to
look for.

## Known weak spots

These came up while drafting and are the first places to look when reviewing results:

- **Product-level and design entries turned into code questions** (for example password ageing,
  single-factor authentication, UI entries CWE-446 to CWE-451 and CWE-1007, malicious-code entries
  CWE-506 to CWE-512, covert channels CWE-385, CWE-514, CWE-515 and CWE-1229, and SQL cost entries
  CWE-1049 and CWE-1067). Their cards ask the closest code-level question and may be noisy. These
  are the main candidates for gate-only treatment.
- **File-level C rules narrowed to declarations inside a function body** (REL-044, REL-045,
  REL-062, REL-063, REL-072, REL-078, REL-079, REL-086, REL-146, REL-150 to REL-154, REL-156,
  REL-159, REL-160, REL-162, REL-164, and the macro-definition rules REL-019, REL-021, REL-034 and
  REL-161). They will rarely fire; switch them to uncheckable if they never do.
- **Rust macro rules REL-022, REL-023 and REL-025** flag any macro use, so they will be true for
  almost every Rust function. That follows the guideline, but the guideline itself is likely to
  need excluding for most projects.
- **Firmware-level hardware entries kept checkable** (CWE-1220, CWE-1232, CWE-1234, CWE-1282,
  CWE-1420): could be made uncheckable like the other hardware entries.
- **BETSY-authored entries** have no external source to check against and have not been run
  against a model. The likeliest to be noisy are PERF-014 (large by-value copies), PERF-018
  (log message cost), REL-219 (implicit globals, which TypeScript rejects anyway), REL-227
  (late-binding closures) and REL-230 (truthiness tests). 14 of the 29 reliability entries sit under
  gates (CWE-755, CWE-697, CWE-710, CWE-664, CWE-20); the rest, and 13 of the 14 performance
  entries, sit under findings such as CWE-754, CWE-825, CWE-407, CWE-1176 and CWE-1050, whose
  low answers may hide them. If `betsy run recall` shows
  gating misses, mark them `detached` or give them a broader parent such as CWE-400.
- **Entries from the second round (REL-243 to REL-306, PERF-025 to PERF-028)** have not been
  run against a model either. The likeliest to be noisy are REL-304 (rigid name and address
  formats) and REL-306 (locale-sensitive case conversion), which depend on what the data is;
  PERF-028 (linked lists), which is often a reasonable design choice; REL-244 (C23 attributes),
  which will rarely apply; and REL-278 (mixed return types), which overlaps documented `Optional`
  returns. REL-289 (comparator contract) overlaps the JavaScript comparator pattern of CWE-475.
- **Narrow sibling distinctions** (CWE-152 to CWE-154, CWE-796 and CWE-797, CWE-32 to CWE-35)
  depend on fine wording and may still be confused.

## Writing or changing a card

- Ask about the function's own code, not the product. "Can this function write past the end
  of a buffer it writes to?" rather than "Does the product write past the end of a buffer?".
- `present_when` lists patterns a reader could point at in the source. Put language-specific
  APIs under the language key, and keep `any` for patterns that hold everywhere.
- `not_present_when` lists what rules the weakness out: guards on every path, constants, safe
  APIs, and language guarantees (Python indexing cannot read outside memory).
- `distinguish_from` names siblings that a model would otherwise also report for the same code,
  and says what the code would show instead. Prefer the more precise sibling.
- Put the card in the file for its family, or start a new file in the catalog's directory.
- Give every card a `name`. List `languages` only when the weakness cannot occur in some of
  them, and `parents` in order of preference; a card with no planned parent is asked of every
  function as a root.
- Add `requires` when the card cannot apply without a trait. Prefer a syntax trait when the
  card is about one construct the parser can see; add a new one to `traits.json` if needed. A
  finding with neither a parent nor a `requires` is asked of every function, and a test fails
  until it is added to `tests/expected/always_asked.json`.
- Give `REL-` and `PERF-` cards their `sources`. Leave `status` out until a person has
  reviewed the card.
- Run `betsy weaknesses audit --strict`.
- Mark as `gate` a category that should route the hierarchy but never be reported (for CWEs:
  Pillars and entries MITRE marks Prohibited or Discouraged for mapping). Write a broad,
  recall-oriented question covering the subtree. Gates must stay checkable.
- Mark `function_checkable: false` only when no single function could show the weakness, and
  give the reason. When in doubt, leave the entry checkable: a skipped entry can never be found.
- Write new wording. Do not paste sentences from MITRE or any other published catalogue into
  cards.

Each rendered criterion must stay within 1,500 characters for every language; a unit test checks
this.

## Validating cards

The existing pair benchmark was written from the same catalog definitions the cards were written
from, so tuning cards against it would overfit. For each evaluation round:

- write new vulnerable/fixed pairs from the published definitions (MITRE CWE for `CWE-` IDs, the
  coding standards named above for the rest), not from the cards;
- add new SQLite functions not used before;
- judge them the same way as the existing benchmark;
- compare a run with the changed cards against the same run with the previous revision of
  the card files, using `betsy run findings` and `betsy run recall`;
- compare a default run with an `--exhaustive` one using `betsy run recall`, to confirm that
  no finding is attributed to a syntax trait;
- set `status` to `validated` on the cards the round covered.

Start with the round-1 roots and gates (asked of every function) and the entries that produce the
most false positives. Budget roughly 1 to 2 million tokens per round. Live-provider runs that
become routine or automated, or that feed any decision process, should be raised with IT&SM first.

## Entries marked not function-checkable

| ID | Name | Reason |
|---|---|---|
| CWE-382 | J2EE Bad Practices: Use of System.exit() | It occurs only in Java, which BETSY does not analyse. |
| CWE-500 | Public Static Field Not Marked Final | A public static data member is declared at class scope, outside any function body. |
| CWE-520 | .NET Misconfiguration: Use of Impersonation | Concerns impersonation settings in a .NET application's configuration, which no function in the planned languages contains. |
| CWE-541 | Inclusion of Sensitive Information in an Include File | Concerns the contents and accessibility of an include file as a whole, not a function body. |
| CWE-544 | Missing Standardized Error Handling Mechanism | Concerns whether error handling is consistent across the whole codebase, which a single function cannot show. |
| CWE-564 | SQL Injection: Hibernate | It is specific to Hibernate query APIs, which are used from Java, a language BETSY does not analyse. |
| CWE-609 | Double-Checked Locking | It is catalogued for Java only, which BETSY does not analyse. |
| CWE-651 | Exposure of WSDL File Containing Sensitive Information | Concerns the content and publication of a web service description file, not a function's code. |
| CWE-655 | Insufficient Psychological Acceptability | Concerns how acceptable users find a protection mechanism, a human and design matter that no function's source can show. |
| CWE-690 | Unchecked Return Value to NULL Pointer Dereference | It is a chain of an unchecked return value and a null dereference, each of which has its own card and is asked separately. |
| CWE-766 | Critical Data Element Declared Public | Concerns access specifiers in a class or struct declaration, which lies outside any function body. |
| CWE-926 | Improper Export of Android Application Components | Component export is declared in the Android manifest, not in function code in the planned languages. |
| CWE-1045 | Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor | Whether a parent and child class declare virtual destructors is fixed in the class declarations of the hierarchy, not in any one function body. |
| CWE-1051 | Initialization with Hard-Coded Network Resource Configuration Data | It is a quality indicator that findings may not be mapped to, and no checkable weakness hangs under it. |
| CWE-1079 | Parent Class without Virtual Destructor Method | Whether a base class with subclasses lacks a virtual destructor is decided by the class declarations, which no single function body contains. |
| CWE-1087 | Class with Virtual Method without a Virtual Destructor | Whether a class with virtual methods also declares a virtual destructor is a property of the class declaration, not of any one function body. |
| CWE-1089 | Large Data Table with Excessive Number of Indices | Depends on a database table's row count and index definitions, which are schema properties not visible in function code. |
| CWE-1098 | Data Element containing Pointer Item without Proper Copy Control Element | Whether a type with pointer members defines copy and assignment control is set by the type's declaration, not by one function's code. |
| CWE-1104 | Use of Unmaintained Third Party Components | Whether a third-party component is still maintained is a fact about its upstream project, not visible in a function's source. |
| CWE-1106 | Insufficient Use of Symbolic Constants | It is a quality indicator that findings may not be mapped to, and no checkable weakness hangs under it. |
| CWE-1191 | On-Chip Debug and Test Interface With Improper Access Control | Concerns access control on a chip's physical JTAG or test interface, which is hardware, not function code. |
| CWE-1231 | Improper Prevention of Lock Bit Modification | Concerns whether hardware lets a lock bit be changed after being set, which is decided by hardware design, not function code. |
| CWE-1233 | Security-Sensitive Hardware Controls with Missing Lock Bit Protection | Concerns which hardware registers a lock bit covers, which is decided by hardware design, not function code. |
| CWE-1242 | Inclusion of Undocumented Features or Chicken Bits | Concerns undocumented hardware configuration bits designed into a device, which function source code cannot show. |
| CWE-1243 | Sensitive Non-Volatile Information Not Protected During Debug | Concerns hardware gating of fuse contents during debug modes, not function code. |
| CWE-1253 | Incorrect Selection of Fuse Values | Concerns the logic level chosen for hardware fuses, which is a hardware design property rather than function source code. |
| CWE-1255 | Comparison Logic is Vulnerable to Power Side-Channel Attacks | Concerns a device's power consumption during hardware token comparison, which function source cannot show. |
| CWE-1258 | Exposure of Sensitive System Information Due to Uncleared Debug Information | It concerns hardware failing to clear registers and keys when a debug mode is entered, which no software function's source shows. |
| CWE-1261 | Improper Handling of Single Event Upsets | Concerns hardware logic resilience to single event upsets, a hardware design property rather than function source code. |
| CWE-1262 | Improper Access Control for Register Interface | Concerns hardware enforcement of access to memory-mapped registers, which lies outside function code. |
| CWE-1263 | Improper Physical Access Control | Concerns physical protection of a device against someone with hands-on access, which no function's code can show. |
| CWE-1264 | Hardware Logic with Insecure De-Synchronization between Control and Data Channels | Concerns hardware logic forwarding data on separate bus or datapath channels, not software function code. |
| CWE-1267 | Policy Uses Obsolete Encoding | Concerns how on-chip access-control policies encode agent identities, a hardware design matter outside function code. |
| CWE-1268 | Policy Privileges are not Assigned Consistently Between Control and Data Agents | Concerns hardware access-control policy registers on a system-on-chip, not software function code. |
| CWE-1270 | Generation of Incorrect Security Tokens | Concerns security tokens generated by system-on-chip hardware for bus transactions, not function code. |
| CWE-1271 | Uninitialized Value on Reset for Registers Holding Security Settings | Concerns hardware register values on device reset, which no software function body shows. |
| CWE-1274 | Improper Access Control for Volatile Memory Containing Boot Code | Concerns hardware protection of volatile memory holding boot code during secure boot, not function code. |
| CWE-1276 | Hardware Child Block Incorrectly Connected to Parent System | Concerns how signals between hardware blocks are wired, which no software function can show. |
| CWE-1277 | Firmware Not Updateable | Whether firmware can be updated is a product capability, not something one function's source can show. |
| CWE-1278 | Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Imaging Techniques | Concerns physical chip protection against imaging attacks, which no software function can show. |
| CWE-1283 | Mutable Attestation or Measurement Reporting Data | Concerns whether hardware attestation registers can be written by an adversary, a hardware design matter. |
| CWE-1291 | Public Key Re-Use for Signing both Debug and Production Code | Concerns key management practice for signing builds, a process and deployment matter not visible in one function. |
| CWE-1300 | Improper Protection of Physical Side Channels | Concerns physical side channels such as power and electromagnetic emissions of a device, not function source code. |
| CWE-1301 | Insufficient or Incomplete Data Removal within Hardware Component | Concerns physical data remanence in hardware components such as media or RAM, which function code cannot show. |
| CWE-1302 | Missing Source Identifier in Entity Transactions on a System-On-Chip (SOC) | Concerns hardware bus transactions on a system-on-chip, not software function code. |
| CWE-1303 | Non-Transparent Sharing of Microarchitectural Resources | Concerns shared microarchitectural hardware such as caches and branch predictors, not function code. |
| CWE-1304 | Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation | Concerns hardware IP saving and restoring its configuration across power states, not function code. |
| CWE-1312 | Missing Protection for Mirrored Regions in On-Chip Fabric Firewall | Concerns on-chip fabric firewall coverage of mirrored address regions, which is hardware. |
| CWE-1313 | Hardware Allows Activation of Test or Debug Logic at Runtime | Concerns hardware letting test or debug logic be activated at run time, not function code. |
| CWE-1315 | Improper Setting of Bus Controlling Capability in Fabric End-point | Concerns bus-controller bits in on-chip fabric end-points, a hardware design matter. |
| CWE-1329 | Reliance on Component That is Not Updateable | Whether a component can be updated or patched depends on product packaging and deployment, not on one function's code. |
| CWE-1334 | Unauthorized Error Injection Can Degrade Hardware Redundancy | Concerns hardware redundancy blocks accepting injected errors, not function code. |
| CWE-1338 | Improper Protections Against Hardware Overheating | Concerns hardware thermal protection features rather than software function code. |
| CWE-1357 | Reliance on Insufficiently Trustworthy Component | Whether a component is trustworthy enough is a supply chain and design property that no single function's source can show. |
| CWE-1395 | Dependency on Vulnerable Third-Party Component | Known vulnerabilities in a dependency depend on its version and advisories, recorded in manifests rather than in a function's code. |
| CWE-1421 | Exposure of Sensitive Information in Shared Microarchitectural Structures during Transient Execution | It describes processor microarchitecture leaking restricted data from shared structures during transient execution, which no single function's source shows. |
| CWE-1422 | Exposure of Sensitive Information caused by Incorrect Data Forwarding during Transient Execution | It describes processor forwarding of stale or incorrect data to transient operations, a hardware behaviour not visible in any function's source. |
| CWE-1429 | Missing Security-Relevant Feedback for Unexecuted Operations in Hardware Interface | Concerns a hardware interface silently discarding operations, which is hardware behaviour rather than function code. |
| REL-005 | Example guideline with bibliography (gui_Bib7x9KmPq2nL) | Placeholder guideline about review process with no technical requirement; nothing in code can show it. |
| REL-006 | Example guideline with bibliography (gui_Bob7x9KmPq2nL) | Placeholder guideline about review process with no technical requirement; nothing in code can show it. |
| REL-033 | Exposed Structure Layout Where Opaque Handle Suffices | Whether a struct definition is exposed more widely than needed depends on header contents and on which files use the type, not on one function body. |
| REL-035 | Header File Without Effective Include Guard | Concerns a header file's include guard, which lies outside any function body. |
| REL-046 | Macro Defined but Never Expanded or Tested | Whether a macro is ever expanded, tested or undefined anywhere depends on the whole program and its build, not on one function body. |
| REL-053 | External Identifiers Indistinguishable Within Linker Significance Limit | Needs every external identifier in the program to compare names. |
| REL-056 | Macro Names or Parameters Not Distinct Within Significant Length | Whether macro names are distinct depends on all macros defined across headers and translation units, not on one function's code. |
| REL-057 | Ordinary Identifier Sharing a Name With a Macro | Whether an identifier clashes with a macro depends on macros defined across headers and the whole program, which one function cannot show. |
| REL-058 | Typedef Name Reused for Another Declaration | Reuse of a typedef name is a program-wide naming question spanning headers and files, not visible in a single function. |
| REL-059 | Struct, Union or Enum Tag Reused for Another Declaration | Reuse of a struct, union or enum tag is a program-wide naming question spanning files, not visible in a single function. |
| REL-060 | Global Symbol Name Reused for Another Identifier | Needs the program's external symbols to know whether a name is reused. |
| REL-061 | File-Local Static Name Reused Across the Program | Needs every identifier in the program to know whether a static name is reused. |
| REL-070 | Inconsistent Declarations of the Same Object or Function | Requires comparing several declarations of the same name across the file or program, which a single function body does not show. |
| REL-071 | External Definition Without Visible Prior Declaration | Depends on which declarations are in scope at file level before the definition, outside the function's own code. |
| REL-073 | External Identifier With Missing or Duplicate Definition | Whether an externally linked identifier has exactly one definition depends on every translation unit and the link, not on one function's code. |
| REL-074 | Externally Visible Definition Used in Only One File | Whether an externally visible function or object is referenced only in its own file depends on the whole program, not one function body. |
| REL-075 | Internal Linkage Implied Without Static Keyword | Inherited internal linkage depends on an earlier static declaration elsewhere in the file, which the function's own definition does not show. |
| REL-076 | File-Scope Object Used by a Single Function | Knowing that only one function refers to a file-scope object requires seeing every other function in the file. |
| REL-134 | Call to Function With No Visible Declaration | Whether a declaration is visible depends on headers and earlier file-level declarations, not on the calling function's own code. |
| REL-163 | Conditional Compilation Block Split Across Files | Concerns preprocessor blocks that span files, outside any function body. |
| REL-174 | Type-Generic Math Macros From tgmath.h | It depends on a file-level #include of <tgmath.h>; a function body calling sqrt or pow looks the same with or without it. |
| PERF-003 | Missing Database Index on Filtered Column | Depends on the database schema's indexes, which are not in the function's code. |
