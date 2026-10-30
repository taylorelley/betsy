# Detection cards

The weakness catalogs were written for people reading a catalogue. BETSY asks a decision model
one yes/no question per weakness about one function's code, and catalog prose is a poor fit for
that: exclusions sit at the end of long descriptions, broad product-level entries cannot be
decided from one function, and sibling CWEs describe the same code pattern. Detection cards in
`data/weaknesses/cards.json` rewrite the question for selected entries without editing the
source catalogs. The format is described in the [README](../README.md#detection-cards).

## Status

**Seed set, not yet validated and not cleared to ship.**

- The cards for `CWE-` entries are new wording derived from MITRE content. Legal must confirm
  that the CWE terms of use allow this, with the notice in `data/weaknesses/CWE_NOTICE.txt`
  kept, before the cards ship. Provenance is recorded in `data/weaknesses/PROVENANCE.md`.
- No card has been checked against a model or labelled code. Treat them as drafts.

The seed set has 19 cards:

- 9 full cards: CWE-125, CWE-787 and CWE-476 (the common memory-safety findings and their
  siblings), CWE-617 and REL-026 (both asked in round 1, and broad enough to produce false
  positives), CWE-777, CWE-367, PERF-004 and PERF-007.
- 10 entries marked not function-checkable: REL-005 and REL-006 (placeholder guidelines with no
  technical content), REL-035, REL-053, REL-060, REL-061 and REL-163 (file- or program-level C
  rules), PERF-003 (database schema) and CWE-1302 and CWE-1303 (hardware entries that the
  hardware-only prefilter misses, so they were asked in round 1 for every language).

Each uncheckable mark removes one question per function from every C and C++ plan, and fewer
from other languages: C now plans 920 questions instead of 928, and Python 706 instead of 709.

## Writing a card

- Ask about the function's own code, not the product. "Can this function write past the end
  of a buffer it writes to?" rather than "Does the product write past the end of a buffer?".
- `present_when` lists patterns a reader could point at in the source. Put language-specific
  APIs under the language key, and keep `any` for patterns that hold everywhere.
- `not_present_when` lists what rules the weakness out: guards on every path, constants, safe
  APIs, and language guarantees (Python indexing cannot read outside memory).
- `distinguish_from` names siblings that a model would otherwise also report for the same code,
  and says what the code would show instead. Prefer the more precise sibling.
- Mark `function_checkable: false` only when no single function could show the weakness, and
  give the reason. When in doubt, leave the entry checkable: a skipped entry can never be found.
- Write new wording. Do not paste catalog sentences into cards.

Each rendered criterion must stay within 1,500 characters for every language; a unit test checks
this.

## What to write next

Prioritise rather than rewrite all 1,192 entries. Start with about 80 to 100:

1. **Round-1 roots and gates.** They are asked of every function, so their wording affects
   every run. There are 128 across the six languages, listed below, though many REL entries in
   the list are narrow C or Rust rules that need only a short card.
2. **The top false-positive producers.** Rank entries by findings judged not genuine in the
   SQLite review and the unrelated-weakness positives in the pair benchmark. That ranking is not
   in this repository and should be regenerated from the stored run data.
3. **Broad product-level CWEs.** These may work better as gates only, never reported. Cards do
   not yet support forcing an entry to gate; add a `gate_only` field when the first such case is
   validated.

Further entries that look file-level rather than function-level, and should be checked for
`function_checkable: false`: REL-058, REL-059, REL-078, REL-079 and REL-146 (declarations
usually at file scope).

## Validating cards

The existing pair benchmark was written from the same catalog definitions the cards are written
from, so tuning cards against it would overfit. For each evaluation round:

- write new vulnerable/fixed pairs from the original catalog definitions, not from the cards;
- add new SQLite functions not used before;
- judge them the same way as the existing benchmark;
- compare a run with cards against the same run with `cards.json` reduced to `{"cards": {}}`,
  using `betsy run findings` and `betsy run recall`.

Budget roughly 1 to 2 million tokens per round. Live-provider runs that become routine or
automated, or that feed any decision process, should be raised with IT&SM first.

## Round-1 roots and gates

Planned before the seed cards, across C, C++, JavaScript, TypeScript, Python and Rust.

| ID | Name | Role | Round 1 in | Card |
|---|---|---|---|---|
| CWE-14 | Compiler Removal of Code to Clear Buffers | finding | c, cpp |  |
| CWE-20 | Improper Input Validation | gate |  |  |
| CWE-74 | Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') | gate |  |  |
| CWE-75 | Failure to Sanitize Special Elements into a Different Plane (Special Element Injection) | gate |  |  |
| CWE-95 | Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection') | finding | typescript |  |
| CWE-97 | Improper Neutralization of Server-Side Includes (SSI) Within a Web Page | finding | c, cpp, typescript, rust |  |
| CWE-118 | Incorrect Access of Indexable Resource ('Range Error') | gate |  |  |
| CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | gate |  |  |
| CWE-138 | Improper Neutralization of Special Elements | gate |  |  |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | gate |  |  |
| CWE-269 | Improper Privilege Management | gate |  |  |
| CWE-284 | Improper Access Control | gate | all |  |
| CWE-285 | Improper Authorization | gate |  |  |
| CWE-287 | Improper Authentication | gate |  |  |
| CWE-311 | Missing Encryption of Sensitive Data | gate |  |  |
| CWE-325 | Missing Cryptographic Step | finding | all |  |
| CWE-330 | Use of Insufficiently Random Values | gate |  |  |
| CWE-345 | Insufficient Verification of Data Authenticity | gate |  |  |
| CWE-363 | Race Condition Enabling Link Following | finding | javascript, typescript, python, rust |  |
| CWE-367 | Time-of-check Time-of-use (TOCTOU) Race Condition | finding | javascript, typescript, python, rust | yes |
| CWE-368 | Context Switching Race Condition | finding | javascript, typescript, python, rust |  |
| CWE-400 | Uncontrolled Resource Consumption | gate |  |  |
| CWE-432 | Dangerous Signal Handler not Disabled During Sensitive Operations | finding | javascript, typescript, python, rust |  |
| CWE-435 | Improper Interaction Between Multiple Correctly-Behaving Entities | gate | all |  |
| CWE-610 | Externally Controlled Reference to a Resource in Another Sphere | gate |  |  |
| CWE-617 | Reachable Assertion | finding | all | yes |
| CWE-657 | Violation of Secure Design Principles | gate |  |  |
| CWE-662 | Improper Synchronization | gate |  |  |
| CWE-664 | Improper Control of a Resource Through its Lifetime | gate | all |  |
| CWE-665 | Improper Initialization | gate |  |  |
| CWE-666 | Operation on Resource in Wrong Phase of Lifetime | gate |  |  |
| CWE-668 | Exposure of Resource to Wrong Sphere | gate |  |  |
| CWE-682 | Incorrect Calculation | gate | all |  |
| CWE-691 | Insufficient Control Flow Management | gate | all |  |
| CWE-693 | Protection Mechanism Failure | gate | all |  |
| CWE-697 | Incorrect Comparison | gate | all |  |
| CWE-703 | Improper Check or Handling of Exceptional Conditions | gate | all |  |
| CWE-707 | Improper Neutralization | gate | all |  |
| CWE-710 | Improper Adherence to Coding Standards | gate | all |  |
| CWE-755 | Improper Handling of Exceptional Conditions | gate |  |  |
| CWE-777 | Regular Expression without Anchors | finding | all | yes |
| CWE-786 | Access of Memory Location Before Start of Buffer | gate |  |  |
| CWE-788 | Access of Memory Location After End of Buffer | gate |  |  |
| CWE-828 | Signal Handler with Functionality that is not Asynchronous-Safe | finding | javascript, typescript, python, rust |  |
| CWE-831 | Signal Handler Function Associated with Multiple Signals | finding | javascript, typescript, python, rust |  |
| CWE-834 | Excessive Iteration | gate |  |  |
| CWE-1041 | Use of Redundant Code | gate |  |  |
| CWE-1076 | Insufficient Adherence to Expected Conventions | gate |  |  |
| CWE-1078 | Inappropriate Source Code Style or Formatting | gate |  |  |
| CWE-1095 | Loop Condition Value Update within the Loop | gate |  |  |
| CWE-1099 | Inconsistent Naming Conventions for Identifiers | gate |  |  |
| CWE-1105 | Insufficient Encapsulation of Machine-Dependent Functionality | gate |  |  |
| CWE-1113 | Inappropriate Comment Style | gate |  |  |
| CWE-1119 | Excessive Use of Unconditional Branching | gate |  |  |
| CWE-1302 | Missing Source Identifier in Entity Transactions on a System-On-Chip (SOC) | finding | all | not checkable |
| CWE-1303 | Non-Transparent Sharing of Microarchitectural Resources | finding | all | not checkable |
| CWE-1336 | Improper Neutralization of Special Elements Used in a Template Engine | finding | typescript |  |
| PERF-001 | N+1 Query Pattern | finding | all |  |
| PERF-002 | Unbounded Data Loading | finding | all |  |
| PERF-003 | Missing Database Index on Filtered Column | finding | all | not checkable |
| PERF-004 | Inefficient String Concatenation in Loop | finding | all | yes |
| PERF-005 | Blocking I/O in Hot Path | finding | all |  |
| PERF-006 | Redundant Repeated Computation | finding | all |  |
| PERF-007 | Inefficient Membership Test on Sequence | finding | all | yes |
| PERF-008 | Missing Cache on Expensive Repeated Request | finding | all |  |
| REL-001 | Ensure reads of union fields produce valid values for the field's type | finding | rust |  |
| REL-002 | Use strong types to differentiate between logically distinct values | finding | rust |  |
| REL-003 | Do not use an integer type as a divisor during integer division | finding | rust |  |
| REL-004 | The 'as' operator should not be used with numeric operands | finding | rust |  |
| REL-005 | Example guideline with bibliography (gui_Bib7x9KmPq2nL) | finding | rust | not checkable |
| REL-006 | Example guideline with bibliography (gui_Bob7x9KmPq2nL) | finding | rust | not checkable |
| REL-007 | Avoid as underscore pointer casts | finding | rust |  |
| REL-008 | Avoid out-or-range shifts | finding | rust |  |
| REL-009 | An integer shall not be converted to a pointer | finding | rust |  |
| REL-010 | Do not shift an expression by a negative number of bits or by greater than or equal to the bitwidth of the operand | finding | rust |  |
| REL-011 | Ensure that integer operations do not result in arithmetic overflow | finding | rust |  |
| REL-012 | An integer shall not be converted to an invalid pointer | finding | rust |  |
| REL-013 | Do not divide by 0 | finding | rust |  |
| REL-014 | Recursive function are not allowed | finding | rust |  |
| REL-015 | Assure visibility of unsafe keyword in unsafe code | finding | rust |  |
| REL-016 | Attribute macros shall not be used | finding | rust |  |
| REL-017 | A macro should not be used in place of a function | finding | rust |  |
| REL-018 | Procedural macros should not be used | finding | rust |  |
| REL-019 | Shall ensure complete hygiene of macros | finding | rust |  |
| REL-020 | Do not hide unsafe blocks within macro expansions | finding | rust |  |
| REL-021 | Names in a macro definition shall use a fully qualified path | finding | rust |  |
| REL-022 | Shall not use Function-like Macros | finding | rust |  |
| REL-023 | Shall not invoke macros | finding | rust |  |
| REL-024 | Shall not use Declarative Macros | finding | rust |  |
| REL-025 | Shall not write code that expands macros | finding | rust |  |
| REL-026 | Missing Run-Time Guards Before Hazardous Operations | finding | c, cpp | yes |
| REL-034 | Function-Like Macro Used Where a Function Would Work | finding | c, cpp |  |
| REL-035 | Header File Without Effective Include Guard | finding | c, cpp | not checkable |
| REL-039 | Non-Conforming C Syntax or Constraint Violations | finding | c, cpp |  |
| REL-051 | Unterminated Numeric Escape Followed by Literal Characters | finding | c, cpp |  |
| REL-052 | Trigraph Sequence in Source Text | finding | c, cpp |  |
| REL-053 | External Identifiers Indistinguishable Within Linker Significance Limit | finding | c, cpp | not checkable |
| REL-054 | Same-Scope Identifiers Differing Only Beyond Significant Characters | finding | c, cpp |  |
| REL-055 | Inner Declaration Shadowing an Outer Identifier | finding | c, cpp |  |
| REL-056 | Macro Names or Parameters Not Distinct Within Significant Length | finding | c, cpp |  |
| REL-057 | Ordinary Identifier Sharing a Name With a Macro | finding | c, cpp |  |
| REL-058 | Typedef Name Reused for Another Declaration | finding | c, cpp |  |
| REL-059 | Struct, Union or Enum Tag Reused for Another Declaration | finding | c, cpp |  |
| REL-060 | Global Symbol Name Reused for Another Identifier | finding | c, cpp | not checkable |
| REL-061 | File-Local Static Name Reused Across the Program | finding | c, cpp | not checkable |
| REL-078 | External Array Declared Without Explicit Size | finding | c, cpp |  |
| REL-079 | Implicitly Numbered Enumerator Duplicating Another Value | finding | c, cpp |  |
| REL-086 | Array Length Inferred From Designated Initialiser | finding | c, cpp |  |
| REL-103 | Literal Zero Used as Null Pointer | finding | c, cpp |  |
| REL-106 | Use of the Comma Operator | finding | c, cpp |  |
| REL-110 | Increment or Decrement Mixed with Other Side Effects | finding | c, cpp |  |
| REL-113 | Side Effect Placed Inside sizeof Operand | finding | c, cpp |  |
| REL-117 | Non-Boolean Value Used as Branch or Loop Condition | finding | c, cpp |  |
| REL-121 | Loop with Multiple break or goto Exits | finding | c, cpp |  |
| REL-122 | Function with Early or Multiple Return Points | finding | c, cpp |  |
| REL-125 | Switch Statement With Irregular Body Structure | finding | c, cpp |  |
| REL-126 | Case Label Nested Inside Inner Block of Switch | finding | c, cpp |  |
| REL-129 | Default Label Placed in Middle of Switch | finding | c, cpp |  |
| REL-130 | Degenerate Switch With Single Clause | finding | c, cpp |  |
| REL-131 | Switch Controlled by Boolean Expression | finding | c, cpp |  |
| REL-132 | Use of Variadic Argument Facilities from stdarg.h | finding | c, cpp |  |
| REL-139 | Assignment to Function Parameter Inside Function Body | finding | c, cpp |  |
| REL-144 | Excessive Levels of Pointer Indirection in Declarations | finding | c, cpp |  |
| REL-146 | Struct Declared With Flexible Array Member | finding | c, cpp |  |
| REL-157 | Non-Boolean Conditional Compilation Expression | finding | c, cpp |  |
| REL-158 | Undefined Macro Evaluated in Conditional Compilation | finding | c, cpp |  |
| REL-161 | Macro Parameter Both Expanded and Pasted or Stringised | finding | c, cpp |  |
| REL-163 | Conditional Compilation Block Split Across Files | finding | c, cpp | not checkable |
