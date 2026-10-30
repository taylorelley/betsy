# Detection cards

The weakness catalogs were written for people reading a catalogue. BETSY asks a decision model
one yes/no question per weakness about one function's code, and catalog prose is a poor fit for
that: exclusions sit at the end of long descriptions, broad product-level entries cannot be
decided from one function, and sibling CWEs describe the same code pattern. Detection cards in
`data/weaknesses/cards.json` rewrite the question for each entry without editing the source
catalogs. The format is described in the [README](../README.md#detection-cards).

## Status

**Complete in coverage, not yet validated and not cleared to ship.**

- There are 971 cards: one for every entry that at least one language plans (961) plus 10 entries
  that are no longer planned because their card marks them uncheckable. 897 are checkable; 74 are
  marked not function-checkable and listed below. The 221 catalog entries without a card are
  never planned for any language (hardware-only, introduced outside code, wrong language, or a
  gate with nothing below it).
- The cards for `CWE-` entries are new wording derived from MITRE content. Legal must confirm
  that the CWE terms of use allow this, with the notice in `data/weaknesses/CWE_NOTICE.txt`
  kept, before the cards ship. Provenance is recorded in `data/weaknesses/PROVENANCE.md`.
- No card has been checked against a model or labelled code. Treat them as drafts.

Each card was drafted from its catalog entry, its parent, children and siblings in the plan, and
the brief summarised in "Writing a card" below. Each card was then checked mechanically: every
planned language receives at least one present and one not-present pattern; rendered criteria
stay within 1,500 characters; distinguish IDs exist; gates stay checkable; and no ten consecutive
words are copied from the entry's description. A human has read only a sample.

Removing the 74 uncheckable entries takes the fixtures from 706 to 939 questions per function
down to 655 to 867, depending on the language.

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
- For gates (Pillars and Prohibited or Discouraged entries), write a broad, recall-oriented
  question covering the subtree. Gates must stay checkable.
- Mark `function_checkable: false` only when no single function could show the weakness, and
  give the reason. When in doubt, leave the entry checkable: a skipped entry can never be found.
- Write new wording. Do not paste catalog sentences into cards.

Each rendered criterion must stay within 1,500 characters for every language; a unit test checks
this.

## Validating cards

The existing pair benchmark was written from the same catalog definitions the cards are written
from, so tuning cards against it would overfit. For each evaluation round:

- write new vulnerable/fixed pairs from the original catalog definitions, not from the cards;
- add new SQLite functions not used before;
- judge them the same way as the existing benchmark;
- compare a run with cards against the same run with `cards.json` reduced to `{"cards": {}}`,
  using `betsy run findings` and `betsy run recall`.

Start with the round-1 roots and gates (asked of every function) and the entries that produce the
most false positives. Budget roughly 1 to 2 million tokens per round. Live-provider runs that
become routine or automated, or that feed any decision process, should be raised with IT&SM first.

## Entries marked not function-checkable

| ID | Name | Reason |
|---|---|---|
| CWE-500 | Public Static Field Not Marked Final | A public static data member is declared at class scope, outside any function body. |
| CWE-520 | .NET Misconfiguration: Use of Impersonation | Concerns impersonation settings in a .NET application's configuration, which no function in the planned languages contains. |
| CWE-541 | Inclusion of Sensitive Information in an Include File | Concerns the contents and accessibility of an include file as a whole, not a function body. |
| CWE-544 | Missing Standardized Error Handling Mechanism | Concerns whether error handling is consistent across the whole codebase, which a single function cannot show. |
| CWE-651 | Exposure of WSDL File Containing Sensitive Information | Concerns the content and publication of a web service description file, not a function's code. |
| CWE-655 | Insufficient Psychological Acceptability | Concerns how acceptable users find a protection mechanism, a human and design matter that no function's source can show. |
| CWE-766 | Critical Data Element Declared Public | Concerns access specifiers in a class or struct declaration, which lies outside any function body. |
| CWE-926 | Improper Export of Android Application Components | Component export is declared in the Android manifest, not in function code in the planned languages. |
| CWE-1045 | Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor | Whether a parent and child class declare virtual destructors is fixed in the class declarations of the hierarchy, not in any one function body. |
| CWE-1079 | Parent Class without Virtual Destructor Method | Whether a base class with subclasses lacks a virtual destructor is decided by the class declarations, which no single function body contains. |
| CWE-1087 | Class with Virtual Method without a Virtual Destructor | Whether a class with virtual methods also declares a virtual destructor is a property of the class declaration, not of any one function body. |
| CWE-1089 | Large Data Table with Excessive Number of Indices | Depends on a database table's row count and index definitions, which are schema properties not visible in function code. |
| CWE-1098 | Data Element containing Pointer Item without Proper Copy Control Element | Whether a type with pointer members defines copy and assignment control is set by the type's declaration, not by one function's code. |
| CWE-1104 | Use of Unmaintained Third Party Components | Whether a third-party component is still maintained is a fact about its upstream project, not visible in a function's source. |
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
