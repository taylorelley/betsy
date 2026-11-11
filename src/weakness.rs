//! Weakness cards and the deterministic per-language selection and hierarchy used to plan
//! per-function decision questions. The files under `data/weaknesses/cards/` are the only
//! weakness definitions: one card names a weakness, places it in the hierarchy, says which
//! functions it can apply to and how to decide it.
//! Nothing here calls a model: selection is a pure function of the cards and the language.
use crate::model::{hash, identity};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::OnceLock;

/// Bumped whenever plan shape or question wording changes, so cached run identities differ.
pub const PROFILE: &str = "function-v7";
const TRAITS_FILE: &[u8] = include_bytes!("../data/weaknesses/traits.json");
// `CARD_FILES`: every file under `data/weaknesses/cards/`, by relative path; see `build.rs`.
include!(concat!(env!("OUT_DIR"), "/card_files.rs"));
/// Languages a card may name in `languages` and, with `any`, as a pattern key.
pub const LANGUAGES: [&str; 7] = [
    "c",
    "cpp",
    "javascript",
    "typescript",
    "tsx",
    "python",
    "rust",
];
/// ID prefixes and the catalog each names, in planning order.
const CATALOGS: [(&str, &str); 3] = [
    ("CWE", "security"),
    ("REL", "reliability"),
    ("PERF", "performance"),
];

/// Code patterns keyed by `any` or a betsy language; see [`card_languages`].
pub type Patterns = BTreeMap<String, Vec<String>>;
/// A weakness card: what one weakness is called, where it sits in the hierarchy and how to
/// decide it from one function's own code.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Card {
    /// The card's key in `cards.json`, in the spelling used everywhere in output.
    #[serde(skip)]
    pub id: String,
    /// `security`, `reliability` or `performance`, from the ID prefix.
    #[serde(skip)]
    pub catalog: String,
    pub name: String,
    #[serde(default)]
    pub abstraction: String,
    /// Asked only to route the hierarchy, never reported as a finding.
    #[serde(default)]
    pub gate: bool,
    /// Languages the weakness can occur in; empty means every language.
    #[serde(default)]
    pub languages: Vec<String>,
    /// Cards this one hangs under, in order of preference: the first that is planned for the
    /// language becomes its parent.
    #[serde(default)]
    pub parents: Vec<String>,
    /// Why the card deliberately has no parent although a related card exists. A card with
    /// this set is asked as a root.
    #[serde(default)]
    pub detached: String,
    /// Trait keys of which at least one must be present for the card to be asked; inherited
    /// by descendants that name none. Empty means no restriction of its own.
    #[serde(default)]
    pub requires: Vec<String>,
    /// `requires` as a trait bitmask.
    #[serde(skip)]
    pub requires_mask: Option<u64>,
    /// Published rules the card was written from, for cards outside MITRE CWE.
    #[serde(default)]
    pub sources: Vec<Source>,
    #[serde(default)]
    pub status: Status,
    /// False when the weakness cannot be seen in a single function; the prefilter skips it.
    pub function_checkable: bool,
    /// Why a card is not function-checkable.
    #[serde(default)]
    pub reason: String,
    /// One yes/no question about the function's own code.
    #[serde(default)]
    pub question: String,
    #[serde(default)]
    pub present_when: Patterns,
    /// Guards, constants and safe APIs that rule the weakness out.
    #[serde(default)]
    pub not_present_when: Patterns,
    /// Sibling weakness IDs, each with what tells it apart from this one.
    #[serde(default)]
    pub distinguish_from: BTreeMap<String, String>,
}
/// A rule in a published standard that a card was written from.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub standard: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rule: String,
}
/// How far a card has been checked. Every card starts as a draft.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Written and mechanically checked only.
    #[default]
    Draft,
    /// Read and accepted by a person.
    Reviewed,
    /// Measured against labelled code with a decision provider.
    Validated,
}
impl Card {
    fn language_applies(&self, language: &str) -> bool {
        self.languages.is_empty() || self.languages.iter().any(|l| l == language)
    }
}

#[derive(Deserialize)]
struct CardFile {
    cards: BTreeMap<String, Card>,
}
pub struct Catalog {
    /// Ordered by catalog, then by ID number.
    pub entries: Vec<Card>,
    /// Identity of every card file's path and content.
    pub hash: String,
    index: HashMap<String, usize>,
}
impl Catalog {
    /// Loads card files given as (path relative to the cards directory, content). A file in
    /// a directory may hold only cards of the catalog the directory is named after.
    fn load(files: &[(&str, &[u8])], traits: &Traits) -> Result<Self> {
        let mut keyed = vec![];
        let mut hashes = vec![];
        for (path, bytes) in files {
            let file: CardFile =
                serde_json::from_slice(bytes).with_context(|| format!("parsing {path}"))?;
            hashes.push((*path, hash(bytes)));
            let directory = path.split_once('/').map(|(d, _)| d);
            for (raw, mut card) in file.cards {
                let key = normalize_id(&raw).with_context(|| format!("invalid id {raw}"))?;
                let (prefix, number) = key.split_once('-').expect("normalized ids have a prefix");
                let rank = CATALOGS
                    .iter()
                    .position(|(p, _)| *p == prefix)
                    .with_context(|| format!("{raw}: unknown catalog prefix {prefix}"))?;
                let number: u64 = number.parse().expect("normalized ids end in a number");
                card.catalog = CATALOGS[rank].1.into();
                anyhow::ensure!(
                    directory.is_none_or(|d| d == card.catalog),
                    "{raw}: a {} card in {path}",
                    card.catalog
                );
                card.id = raw;
                keyed.push(((rank, number), key, card));
            }
        }
        keyed.sort_by_key(|(order, ..)| *order);
        let mut index = HashMap::new();
        let mut entries = vec![];
        for (i, (_, key, card)) in keyed.into_iter().enumerate() {
            anyhow::ensure!(index.insert(key, i).is_none(), "duplicate card {}", card.id);
            entries.push(card);
        }
        let resolve = |from: &str, what: &str, raw: &str| -> Result<String> {
            let i = normalize_id(raw)
                .and_then(|k| index.get(&k))
                .with_context(|| format!("{from} {what} unknown weakness {raw}"))?;
            let id = &entries[*i].id;
            anyhow::ensure!(id != from, "{from} {what} itself");
            Ok(id.clone())
        };
        let mut resolved = vec![];
        for card in &entries {
            let id = &card.id;
            anyhow::ensure!(!card.name.trim().is_empty(), "{id}: a card needs a name");
            if card.function_checkable {
                anyhow::ensure!(
                    !card.question.trim().is_empty()
                        && !card.present_when.is_empty()
                        && !card.not_present_when.is_empty(),
                    "{id}: a checkable card needs a question, present_when and not_present_when"
                );
            } else {
                anyhow::ensure!(
                    !card.reason.trim().is_empty(),
                    "{id}: an uncheckable card needs a reason"
                );
            }
            for (k, v) in card.present_when.iter().chain(&card.not_present_when) {
                anyhow::ensure!(
                    k == "any" || LANGUAGES.contains(&k.as_str()),
                    "{id}: unknown language {k}"
                );
                anyhow::ensure!(
                    v.iter().all(|p| !p.trim().is_empty()),
                    "{id}: empty pattern"
                );
            }
            for l in &card.languages {
                anyhow::ensure!(
                    LANGUAGES.contains(&l.as_str()),
                    "{id}: unknown language {l}"
                );
            }
            anyhow::ensure!(
                card.detached.trim().is_empty() || card.parents.is_empty(),
                "{id}: a detached card has no parents"
            );
            for source in &card.sources {
                anyhow::ensure!(
                    !source.standard.trim().is_empty(),
                    "{id}: a source needs a standard"
                );
            }
            let mut mask = 0;
            for k in &card.requires {
                mask |= traits
                    .bit(k)
                    .with_context(|| format!("{id} requires unknown trait {k}"))?;
            }
            let parents = card
                .parents
                .iter()
                .map(|p| resolve(id, "hangs under", p))
                .collect::<Result<Vec<_>>>()?;
            let distinguish = card
                .distinguish_from
                .iter()
                .map(|(other, note)| Ok((resolve(id, "distinguishes", other)?, note.clone())))
                .collect::<Result<BTreeMap<_, _>>>()?;
            resolved.push((parents, distinguish, mask));
        }
        for (card, (parents, distinguish, mask)) in entries.iter_mut().zip(resolved) {
            card.parents = parents;
            card.distinguish_from = distinguish;
            card.requires_mask = (mask != 0).then_some(mask);
        }
        Ok(Self {
            entries,
            hash: identity(&hashes),
            index,
        })
    }
    pub fn get(&self, raw: &str) -> Option<&Card> {
        normalize_id(raw).and_then(|k| self.index.get(&k).map(|&i| &self.entries[i]))
    }
}
pub fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        Catalog::load(CARD_FILES, traits()).expect("embedded weakness cards are valid")
    })
}

/// An observable property of a function, settled once before any weakness so that weaknesses
/// which cannot apply without it are never asked.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trait {
    pub key: String,
    /// True when the parser alone settles the trait: present when a `present_if` node kind
    /// occurs in the function, absent when none does and the function parses cleanly. Such a
    /// trait is never asked, is not shown to the provider, and applies without `--traits`.
    #[serde(default)]
    pub syntax: bool,
    #[serde(default)]
    pub question: String,
    #[serde(default, rename = "true")]
    pub criteria_true: String,
    #[serde(default, rename = "false")]
    pub criteria_false: String,
    /// Per language, syntax node kinds (named or anonymous) whose presence proves the trait.
    /// For an asked trait absence proves nothing: macros, callees and aliases can hide it.
    /// A syntax trait is undecided, and so counts as present, in a language it does not list.
    #[serde(default)]
    pub present_if: BTreeMap<String, Vec<String>>,
    /// Per language, identifiers whose use proves the trait, for constructs that are spelled
    /// as a call rather than as syntax, such as `div_euclid` for division.
    #[serde(default)]
    pub present_if_names: BTreeMap<String, Vec<String>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TraitFile {
    traits: Vec<Trait>,
}
pub struct Traits {
    pub traits: Vec<Trait>,
    pub hash: String,
}
impl Traits {
    fn load(bytes: &[u8]) -> Result<Self> {
        let file: TraitFile = serde_json::from_slice(bytes).context("parsing traits.json")?;
        anyhow::ensure!(file.traits.len() <= 64, "at most 64 traits fit a mask");
        let keys: BTreeSet<&str> = file.traits.iter().map(|t| t.key.as_str()).collect();
        anyhow::ensure!(keys.len() == file.traits.len(), "duplicate trait key");
        for t in &file.traits {
            let key = &t.key;
            for (language, kinds) in t.present_if.iter().chain(&t.present_if_names) {
                anyhow::ensure!(
                    LANGUAGES.contains(&language.as_str()) && !kinds.is_empty(),
                    "trait {key}: bad present_if for {language}"
                );
            }
            // Names only add to what node kinds find; alone they could not settle absence.
            for language in t.present_if_names.keys() {
                anyhow::ensure!(
                    t.present_if.contains_key(language),
                    "trait {key}: present_if_names for {language} needs present_if too"
                );
            }
            if t.syntax {
                anyhow::ensure!(
                    !t.present_if.is_empty(),
                    "syntax trait {key} needs present_if"
                );
            } else {
                anyhow::ensure!(
                    [&t.question, &t.criteria_true, &t.criteria_false]
                        .iter()
                        .all(|s| !s.trim().is_empty()),
                    "asked trait {key} needs a question and both criteria"
                );
            }
        }
        Ok(Self {
            traits: file.traits,
            hash: hash(bytes),
        })
    }
    fn bit(&self, key: &str) -> Option<u64> {
        self.traits
            .iter()
            .position(|t| t.key == key)
            .map(|i| 1 << i)
    }
    /// Mask of the traits the parser settles on its own.
    pub fn syntax_mask(&self) -> u64 {
        self.traits
            .iter()
            .enumerate()
            .filter(|(_, t)| t.syntax)
            .fold(0, |m, (i, _)| m | 1 << i)
    }
    /// Mask of the named trait keys; unknown names are ignored.
    pub fn mask(&self, names: &[String]) -> u64 {
        self.traits
            .iter()
            .enumerate()
            .filter(|(_, t)| names.contains(&t.key))
            .fold(0, |m, (i, _)| m | 1 << i)
    }
    /// Trait keys named by a mask, in declaration order.
    pub fn names(&self, mask: u64) -> Vec<&str> {
        self.traits
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, t)| t.key.as_str())
            .collect()
    }
}
/// What the parser can say about one function's traits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Syntax {
    /// Traits one of whose `present_if` node kinds occurs in the function.
    pub found: u64,
    /// Syntax traits the parser has settled as absent: the language lists node kinds for
    /// them, none occurs, and the function parsed without error.
    pub absent: u64,
}
/// Scans the function's own syntax tree for trait node kinds. A snippet that does not parse
/// cleanly can still prove presence, but never absence.
pub fn scan_traits(language: &str, source: &str) -> Syntax {
    let t = traits();
    const NONE: &[String] = &[];
    let wanted: Vec<(u64, &[String], &[String])> = t
        .traits
        .iter()
        .enumerate()
        .filter_map(|(i, tr)| {
            let names = tr
                .present_if_names
                .get(language)
                .map_or(NONE, Vec::as_slice);
            tr.present_if
                .get(language)
                .map(|k| (1u64 << i, k.as_slice(), names))
        })
        .collect();
    if wanted.is_empty() {
        return Syntax::default();
    }
    let mut parser = tree_sitter::Parser::new();
    let Ok(grammar) = crate::languages::grammar(language) else {
        return Syntax::default();
    };
    if parser.set_language(&grammar).is_err() {
        return Syntax::default();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Syntax::default();
    };
    let mut found = 0;
    let mut cursor = tree.walk();
    'walk: loop {
        let node = cursor.node();
        let kind = node.kind();
        // Identifier-like leaves only: a name inside a string or comment proves nothing. Any
        // use counts, not only a call, since a function can be passed by name and then called;
        // an unrelated identifier of the same name only costs a question. A Rust raw
        // identifier such as `r#div` names the same item as `div`.
        let name = (node.child_count() == 0 && kind.ends_with("identifier"))
            .then(|| node.utf8_text(source.as_bytes()).ok())
            .flatten()
            .map(|n| n.strip_prefix("r#").unwrap_or(n));
        for (bit, kinds, names) in &wanted {
            if kinds.iter().any(|k| k == kind) || name.is_some_and(|n| names.iter().any(|x| x == n))
            {
                found |= bit;
            }
        }
        if cursor.goto_first_child() || cursor.goto_next_sibling() {
            continue;
        }
        loop {
            if !cursor.goto_parent() {
                break 'walk;
            }
            if cursor.goto_next_sibling() {
                break;
            }
        }
    }
    let decidable = wanted.iter().fold(0, |m, (bit, ..)| m | bit) & t.syntax_mask();
    let absent = if tree.root_node().has_error() {
        0
    } else {
        decidable & !found
    };
    Syntax { found, absent }
}
/// Asked traits whose syntax occurs in the function: the parser facts shown to the provider.
/// Syntax traits are left out, since they only steer which cards are asked.
pub fn proven_traits(language: &str, source: &str) -> u64 {
    scan_traits(language, source).found & !traits().syntax_mask()
}
pub fn traits() -> &'static Traits {
    static TRAITS: OnceLock<Traits> = OnceLock::new();
    TRAITS.get_or_init(|| Traits::load(TRAITS_FILE).expect("embedded traits are valid"))
}

/// Card pattern keys a language reads, broadest first: C++ code also shows C patterns, and
/// TypeScript code JavaScript ones.
fn card_languages(language: &str) -> &'static [&'static str] {
    match language {
        "c" => &["any", "c"],
        "cpp" => &["any", "c", "cpp"],
        "javascript" => &["any", "javascript"],
        "typescript" => &["any", "javascript", "typescript"],
        "tsx" => &["any", "javascript", "typescript", "tsx"],
        "python" => &["any", "python"],
        "rust" => &["any", "rust"],
        _ => &["any"],
    }
}
pub fn patterns_for<'a>(p: &'a Patterns, language: &str) -> Vec<&'a str> {
    card_languages(language)
        .iter()
        .filter_map(|k| p.get(*k))
        .flatten()
        .map(String::as_str)
        .collect()
}

/// Normalizes `CWE-89`, `cwe_89`, `89`, `REL-001` and `rel 1` to `PREFIX-N` without zero padding.
/// Output always uses the catalog's own spelling via [`Catalog::get`].
pub fn normalize_id(raw: &str) -> Option<String> {
    let s = raw.trim().to_ascii_uppercase();
    let split = s.find(|c: char| c.is_ascii_digit())?;
    let (prefix, digits) = s.split_at(split);
    let prefix = prefix.trim_end_matches(['-', '_', ' ']);
    if !prefix.chars().all(|c| c.is_ascii_uppercase())
        || !digits.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    (n > 0).then(|| format!("{}-{n}", if prefix.is_empty() { "CWE" } else { prefix }))
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Asked, and reported as a finding when above threshold.
    Finding,
    /// Asked only to route the hierarchy (cards marked `gate`).
    Gate,
}
#[derive(Debug, Clone, Serialize)]
pub struct Node {
    pub id: String,
    pub role: Role,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    /// Number of nodes in this subtree, including itself.
    pub subtree: usize,
    /// The only child of its parent: asked in the parent's round, since gating it separately
    /// would save one question at the cost of a whole round.
    pub spliced: bool,
    /// Round in which this node is asked when every ancestor passes.
    pub wave: u32,
    /// Traits of which one must be present to ask this node, inherited from the nearest
    /// tagged ancestor; `None` means always asked.
    pub requires: Option<u64>,
    /// Union of `requires` over the subtree; `None` when any node in it is always asked.
    /// When no trait in `reach` is present, the whole subtree is skipped.
    pub reach: Option<u64>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Skip {
    pub id: String,
    pub reason: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Selection {
    /// Explicit weakness IDs; when set, only these are asked, flat and ungated.
    pub only: Vec<String>,
    pub exclude: Vec<String>,
}
/// The deterministic question plan for one language.
#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub profile: &'static str,
    pub language: String,
    pub nodes: Vec<Node>,
    pub roots: Vec<usize>,
    pub skipped: Vec<Skip>,
}
impl Plan {
    pub fn findings(&self) -> usize {
        self.nodes
            .iter()
            .filter(|n| n.role == Role::Finding)
            .count()
    }
    /// Sequential rounds needed when every gate passes.
    pub fn depth(&self) -> u32 {
        self.nodes.iter().map(|n| n.wave).max().unwrap_or(0)
    }
    /// Mask of every trait some node requires; other traits never change what is asked.
    pub fn traits_used(&self) -> u64 {
        self.nodes
            .iter()
            .fold(0, |m, n| m | n.requires.unwrap_or(0))
    }
    /// Questions asked in round 1 whatever the answers.
    pub fn first_wave(&self) -> usize {
        self.nodes.iter().filter(|n| n.wave == 1).count()
    }
}

pub fn resolve_ids(raw: &[String]) -> Result<BTreeSet<String>> {
    raw.iter()
        .flat_map(|s| s.split(','))
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            catalog()
                .get(s)
                .map(|w| w.id.clone())
                .with_context(|| format!("unknown weakness id {s:?}"))
        })
        .collect()
}
/// Resolves an explicit selection. A card that is not function-checkable has no question to
/// ask, so naming one is an error rather than a silent skip.
pub fn resolve_only(raw: &[String]) -> Result<BTreeSet<String>> {
    let only = resolve_ids(raw)?;
    for id in &only {
        let card = catalog().get(id).expect("resolved id exists");
        anyhow::ensure!(
            card.function_checkable,
            "{id} cannot be checked within one function: {}",
            card.reason.trim()
        );
    }
    Ok(only)
}

pub fn plan(language: &str, selection: &Selection) -> Result<Plan> {
    let cat = catalog();
    let exclude = resolve_ids(&selection.exclude)?;
    let only = resolve_only(&selection.only)?;
    let mut skipped = vec![];
    let mut kept: BTreeMap<&str, Role> = BTreeMap::new();
    for w in &cat.entries {
        let reason = if exclude.contains(&w.id) {
            Some("excluded by selection")
        } else if !only.is_empty() {
            (!only.contains(&w.id)).then_some("not in explicit selection")
        } else if !w.language_applies(language) {
            Some("language not applicable")
        } else if !w.function_checkable {
            Some("not checkable within one function")
        } else {
            None
        };
        match reason {
            Some(r) => skipped.push(Skip {
                id: w.id.clone(),
                reason: r.into(),
            }),
            None => {
                let gate = only.is_empty() && w.gate;
                kept.insert(&w.id, if gate { Role::Gate } else { Role::Finding });
            }
        }
    }
    // First parent among kept entries; an entry whose parents were all skipped is a root.
    let parent_of = |id: &str| -> Option<&str> {
        if !only.is_empty() {
            return None;
        }
        cat.get(id).and_then(|w| {
            w.parents
                .iter()
                .map(String::as_str)
                .find(|p| kept.contains_key(p))
        })
    };
    // Gates with no finding below them are never worth asking.
    let mut useful: BTreeSet<&str> = BTreeSet::new();
    for (id, role) in &kept {
        if *role == Role::Finding {
            let mut cur = Some(*id);
            let mut seen = BTreeSet::new();
            while let Some(c) = cur {
                if !seen.insert(c) || (!useful.insert(c) && c != *id) {
                    break;
                }
                cur = parent_of(c);
            }
        }
    }
    for (id, role) in &kept {
        if *role == Role::Gate && !useful.contains(id) {
            skipped.push(Skip {
                id: (*id).into(),
                reason: "gate without applicable descendants".into(),
            });
        }
    }
    let ordered: Vec<&str> = cat
        .entries
        .iter()
        .map(|w| w.id.as_str())
        .filter(|id| useful.contains(id))
        .collect();
    let pos: HashMap<&str, usize> = ordered.iter().enumerate().map(|(i, id)| (*id, i)).collect();
    let mut nodes: Vec<Node> = ordered
        .iter()
        .map(|id| Node {
            id: (*id).into(),
            role: kept[id].clone(),
            parent: parent_of(id).map(|p| pos[p]),
            children: vec![],
            subtree: 1,
            spliced: false,
            wave: 1,
            requires: None,
            reach: None,
        })
        .collect();
    // Break any cycle defensively so the forest is always finite.
    for i in 0..nodes.len() {
        let mut seen = BTreeSet::from([i]);
        let mut cur = nodes[i].parent;
        while let Some(p) = cur {
            if !seen.insert(p) {
                nodes[i].parent = None;
                break;
            }
            cur = nodes[p].parent;
        }
    }
    for i in 0..nodes.len() {
        if let Some(p) = nodes[i].parent {
            nodes[p].children.push(i);
        }
    }
    let roots: Vec<usize> = (0..nodes.len())
        .filter(|&i| nodes[i].parent.is_none())
        .collect();
    // An explicit selection is asked flat and unconditionally.
    let tag = |id: &str| cat.get(id).and_then(|w| w.requires_mask);
    if only.is_empty() {
        for n in &mut nodes {
            n.requires = tag(&n.id);
        }
    }
    // Parents precede children only within a tree, so assign waves and inherit tags top-down.
    let mut stack = roots.clone();
    while let Some(i) = stack.pop() {
        let (wave, requires, children) =
            (nodes[i].wave, nodes[i].requires, nodes[i].children.clone());
        let only_child = children.len() == 1;
        for c in children {
            nodes[c].spliced = only_child;
            nodes[c].wave = if only_child { wave } else { wave + 1 };
            if nodes[c].requires.is_none() {
                nodes[c].requires = requires;
            }
            stack.push(c);
        }
    }
    fn size(nodes: &mut [Node], i: usize) -> (usize, Option<u64>) {
        let children = nodes[i].children.clone();
        let (mut s, mut reach) = (1, nodes[i].requires);
        for c in children {
            let (cs, cr) = size(nodes, c);
            s += cs;
            reach = reach.zip(cr).map(|(a, b)| a | b);
        }
        nodes[i].subtree = s;
        nodes[i].reach = reach;
        (s, reach)
    }
    for &r in &roots {
        size(&mut nodes, r);
    }
    skipped.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(Plan {
        profile: PROFILE,
        language: language.into(),
        nodes,
        roots,
        skipped,
    })
}

/// One deterministic yes/no question about one weakness.
#[derive(Debug, Clone, Serialize)]
pub struct Question {
    pub weakness_id: String,
    /// Provider-safe question name.
    pub key: String,
    pub instructions: String,
    pub criteria_true: String,
    pub criteria_false: String,
    pub hash: String,
}
/// The question for one trait; its `weakness_id` is `trait:<key>`, outside any catalog.
pub fn trait_question(t: &Trait) -> Question {
    let hash = identity(&(&t.question, &t.criteria_true, &t.criteria_false));
    Question {
        weakness_id: format!("trait:{}", t.key),
        key: format!("TRAIT_{}", t.key),
        instructions: t.question.clone(),
        criteria_true: t.criteria_true.clone(),
        criteria_false: t.criteria_false.clone(),
        hash,
    }
}
fn sentence_list(items: &[&str]) -> String {
    items
        .iter()
        .map(|s| s.trim().trim_end_matches('.'))
        .collect::<Vec<_>>()
        .join("; ")
}
const OUTSIDE: &str = "it would only arise outside this function";
/// Question text from a card; gates keep their recall-oriented framing.
fn card_question(card: &Card, role: &Role, language: &str) -> (String, String, String) {
    let w = card;
    let present = sentence_list(&patterns_for(&card.present_when, language));
    match role {
        Role::Finding => {
            let mut criteria_false = format!(
                "No when: {}.",
                sentence_list(&patterns_for(&card.not_present_when, language))
            );
            for (other, note) in &card.distinguish_from {
                let name = catalog().get(other).map_or("", |o| o.name.as_str());
                criteria_false.push_str(&format!(
                    " Also no when {}; that is {other} \"{name}\", not this weakness.",
                    note.trim().trim_end_matches('.')
                ));
            }
            criteria_false.push_str(&format!(" Also no when {OUTSIDE}."));
            (
                format!("{} (weakness {} \"{}\")", card.question.trim(), w.id, w.name),
                format!("Yes when the function's own code shows: {present}."),
                criteria_false,
            )
        }
        Role::Gate => (
            format!(
                "Is it plausible that this function's code contains any weakness in the category {} \"{}\"? {}",
                w.id,
                w.name,
                card.question.trim()
            ),
            format!("The function plausibly involves {}, for example: {present}.", w.name),
            "The function clearly does nothing related to this category.".to_string(),
        ),
    }
}
/// The question for one planned weakness in one language. Only function-checkable cards are
/// ever planned; asking about any other is a caller bug.
pub fn question(id: &str, role: &Role, language: &str) -> Question {
    let w = catalog().get(id).expect("planned weakness exists");
    assert!(w.function_checkable, "{} has no question", w.id);
    let (instructions, criteria_true, criteria_false) = card_question(w, role, language);
    let hash = identity(&(&instructions, &criteria_true, &criteria_false));
    Question {
        weakness_id: w.id.clone(),
        key: w.id.replace('-', "_"),
        instructions,
        criteria_true,
        criteria_false,
        hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_normalize_without_padding() {
        for (raw, want) in [
            ("CWE-89", "CWE-89"),
            ("cwe_89", "CWE-89"),
            (" 89 ", "CWE-89"),
            ("REL-001", "REL-1"),
            ("rel 1", "REL-1"),
            ("perf-010", "PERF-10"),
        ] {
            assert_eq!(normalize_id(raw).as_deref(), Some(want), "{raw}");
        }
        for raw in ["", "CWE-", "CWE-0", "CWE-89a", "C3PO", "CWE/89", "1-2"] {
            assert_eq!(normalize_id(raw), None, "{raw}");
        }
    }

    fn load(cards: &str) -> Result<Catalog> {
        load_in("cards.json", cards)
    }
    fn load_in(path: &str, cards: &str) -> Result<Catalog> {
        let file = format!(r#"{{"cards":{{{cards}}}}}"#);
        Catalog::load(&[(path, file.as_bytes())], traits())
    }
    const OK: &str = r#""function_checkable":true,"question":"q?","present_when":{"c":["p"]},"not_present_when":{"any":["n"]}"#;

    #[test]
    fn catalog_and_order_come_from_the_id() {
        let c = load(&format!(
            r#""PERF-002":{{"name":"p",{OK}}},"REL-010":{{"name":"r",{OK}}},
            "REL-9":{{"name":"r",{OK}}},"cwe-787":{{"name":"w",{OK}}}"#
        ))
        .unwrap();
        let got: Vec<(&str, &str)> = c
            .entries
            .iter()
            .map(|w| (w.id.as_str(), w.catalog.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("cwe-787", "security"),
                ("REL-9", "reliability"),
                ("REL-010", "reliability"),
                ("PERF-002", "performance")
            ]
        );
        assert!(load(&format!(r#""XYZ-1":{{"name":"x",{OK}}}"#)).is_err());
    }

    #[test]
    fn languages_restrict_a_card_only_when_listed() {
        let c = load(&format!(
            r#""CWE-1":{{"name":"a",{OK}}},"CWE-2":{{"name":"b","languages":["c","cpp"],{OK}}}"#
        ))
        .unwrap();
        let (all, some) = (c.get("CWE-1").unwrap(), c.get("CWE-2").unwrap());
        assert!(all.language_applies("python") && all.language_applies("go"));
        assert!(some.language_applies("c") && some.language_applies("cpp"));
        assert!(!some.language_applies("python") && !some.language_applies("go"));
    }

    #[test]
    fn files_merge_and_a_catalog_directory_holds_only_its_catalog() {
        let card = |id: &str| format!(r#"{{"cards":{{"{id}":{{"name":"n",{OK}}}}}}}"#);
        let (a, b, c) = (card("CWE-1"), card("REL-1"), card("CWE-1"));
        let two = Catalog::load(
            &[
                ("security/a.json", a.as_bytes()),
                ("reliability/b.json", b.as_bytes()),
            ],
            traits(),
        )
        .unwrap();
        assert_eq!(two.entries.len(), 2);
        let moved = Catalog::load(
            &[
                ("security/z.json", a.as_bytes()),
                ("reliability/b.json", b.as_bytes()),
            ],
            traits(),
        )
        .unwrap();
        assert_ne!(two.hash, moved.hash, "the hash covers file paths");
        assert!(load_in(
            "reliability/a.json",
            &format!(r#""CWE-1":{{"name":"n",{OK}}}"#)
        )
        .is_err());
        let duplicate = [
            ("security/a.json", a.as_bytes()),
            ("security/c.json", c.as_bytes()),
        ];
        assert!(Catalog::load(&duplicate, traits()).is_err());
    }

    #[test]
    fn parents_keep_their_order_and_detached_cards_have_none() {
        let c = load(&format!(
            r#""CWE-1":{{"name":"a",{OK}}},"CWE-2":{{"name":"b",{OK}}},
            "REL-5":{{"name":"c","parents":["2","cwe_1"],{OK}}},
            "REL-026":{{"name":"d","detached":"broader than CWE-1",{OK}}}"#
        ))
        .unwrap();
        assert_eq!(c.get("REL-5").unwrap().parents, ["CWE-2", "CWE-1"]);
        assert!(load(&format!(
            r#""CWE-1":{{"name":"a",{OK}}},
            "REL-026":{{"name":"d","detached":"why","parents":["CWE-1"],{OK}}}"#
        ))
        .is_err());
    }

    #[test]
    fn requires_become_a_trait_mask() {
        let key = |i: usize| traits().traits[i].key.clone();
        let c = load(&format!(
            r#""CWE-1":{{"name":"a","requires":["{}","{}"],{OK}}},"CWE-2":{{"name":"b",{OK}}}"#,
            key(0),
            key(2)
        ))
        .unwrap();
        assert_eq!(c.get("CWE-1").unwrap().requires_mask, Some(0b101));
        assert_eq!(c.get("CWE-2").unwrap().requires_mask, None);
        assert!(load(&format!(
            r#""CWE-1":{{"name":"a","requires":["nope"],{OK}}}"#
        ))
        .is_err());
    }

    #[test]
    fn sources_and_status_are_validated() {
        let c = load(&format!(
            r#""REL-1":{{"name":"a","status":"reviewed",
            "sources":[{{"standard":"MISRA C:2012","rule":"Rule 1.3"}},{{"standard":"S"}}],{OK}}},
            "REL-2":{{"name":"b",{OK}}}"#
        ))
        .unwrap();
        let card = c.get("REL-1").unwrap();
        assert_eq!(card.status, Status::Reviewed);
        assert_eq!(card.sources[0].rule, "Rule 1.3");
        assert!(card.sources[1].rule.is_empty());
        assert_eq!(c.get("REL-2").unwrap().status, Status::Draft);
        for bad in [
            r#""status":"done""#,
            r#""sources":[{"rule":"1"}]"#,
            r#""sources":[{"standard":" "}]"#,
            r#""sources":[{"standard":"S","url":"x"}]"#,
        ] {
            assert!(
                load(&format!(r#""REL-1":{{"name":"a",{bad},{OK}}}"#)).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn traits_are_validated() {
        let ok = r#"{"traits":[{"key":"a","question":"q","true":"t","false":"f"},
            {"key":"b","syntax":true,"present_if":{"c":["switch_statement"]}}]}"#;
        let t = Traits::load(ok.as_bytes()).unwrap();
        assert_eq!(
            (t.syntax_mask(), t.bit("a"), t.bit("z")),
            (0b10, Some(1), None)
        );
        for bad in [
            r#"{"traits":[{"key":"a"}]}"#,
            r#"{"traits":[{"key":"a","syntax":true}]}"#,
            r#"{"traits":[{"key":"a","syntax":true,"present_if":{"go":["x"]}}]}"#,
            r#"{"traits":[{"key":"a","syntax":true,"present_if":{"c":[]}}]}"#,
            r#"{"traits":[{"key":"a","syntax":true,"present_if":{"c":["x"]},"present_if_names":{"rust":["n"]}}]}"#,
            r#"{"traits":[{"key":"a","syntax":true,"present_if":{"c":["x"]}},{"key":"a","syntax":true,"present_if":{"c":["x"]}}]}"#,
            r#"{"traits":[],"requires":{}}"#,
        ] {
            assert!(Traits::load(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_first_planned_parent_is_used() {
        // REL-001 lists parents that do not apply to Rust before one that does.
        let rel = catalog().get("REL-001").unwrap();
        let p = plan("rust", &Selection::default()).unwrap();
        let n = p.nodes.iter().find(|n| n.id == rel.id).unwrap();
        let planned = |id: &String| p.nodes.iter().any(|n| n.id == *id);
        let want = rel.parents.iter().find(|id| planned(id));
        assert_eq!(n.parent.map(|i| &p.nodes[i].id), want);
    }

    #[test]
    fn detached_entries_are_planned_as_roots() {
        let plan = plan("c", &Selection::default()).unwrap();
        let detached: Vec<&Card> = catalog()
            .entries
            .iter()
            .filter(|w| !w.detached.is_empty())
            .collect();
        assert!(!detached.is_empty());
        for w in detached {
            if let Some(node) = plan.nodes.iter().find(|n| n.id == w.id) {
                assert!(node.parent.is_none(), "{} has a parent", w.id);
            }
        }
    }

    #[test]
    fn gates_are_never_findings_and_reliability_and_performance_cards_are_gated() {
        for language in LANGUAGES {
            let p = plan(language, &Selection::default()).unwrap();
            for n in &p.nodes {
                let card = catalog().get(&n.id).unwrap();
                assert_eq!(n.role == Role::Gate, card.gate, "{language}: {}", n.id);
                if card.catalog != "security" && !card.parents.is_empty() {
                    assert!(n.parent.is_some(), "{language}: {} is a root", n.id);
                }
            }
        }
    }

    #[test]
    fn questions_use_provider_safe_keys_and_stable_hashes() {
        let q = question("cwe-89", &Role::Finding, "python");
        assert_eq!(
            (q.weakness_id.as_str(), q.key.as_str()),
            ("CWE-89", "CWE_89")
        );
        assert_eq!(q.hash, question("CWE-89", &Role::Finding, "python").hash);
        let gate = question("CWE-89", &Role::Gate, "python");
        assert_ne!(q.hash, gate.hash);
        assert!(gate.instructions.starts_with("Is it plausible"));
        let t = trait_question(&traits().traits[0]);
        assert!(t.weakness_id.starts_with("trait:") && t.key.starts_with("TRAIT_"));
    }

    #[test]
    fn cards_validate_ids_fields_and_languages() {
        let c = load(&format!(
            r#""cwe-787":{{"name":"w","distinguish_from":{{"125":"reads"}},{OK}}},
            "CWE-125":{{"name":"r","function_checkable":false,"reason":"r"}}"#
        ))
        .unwrap();
        assert_eq!(
            c.get("CWE-787")
                .unwrap()
                .distinguish_from
                .keys()
                .collect::<Vec<_>>(),
            ["CWE-125"]
        );
        for bad in [
            r#""CWE-0":{"name":"w","function_checkable":false,"reason":"r"}"#,
            r#""CWE-787":{"name":"w","function_checkable":false}"#,
            r#""CWE-787":{"function_checkable":false,"reason":"r"}"#,
            r#""CWE-787":{"name":" ","function_checkable":false,"reason":"r"}"#,
            r#""CWE-787":{"name":"w","function_checkable":true,"question":"q?","present_when":{"c":["p"]}}"#,
            r#""CWE-787":{"name":"w","function_checkable":true,"question":"q?","present_when":{"go":["p"]},"not_present_when":{"any":["n"]}}"#,
            r#""CWE-787":{"name":"w","function_checkable":false,"reason":"r","languages":["go"]}"#,
            r#""CWE-787":{"name":"w","function_checkable":false,"reason":"r","languages":["any"]}"#,
            r#""CWE-787":{"name":"w","function_checkable":false,"reason":"r","distinguish_from":{"CWE-787":"x"}}"#,
            r#""CWE-787":{"name":"w","function_checkable":false,"reason":"r","distinguish_from":{"CWE-1":"x"}}"#,
            r#""CWE-787":{"name":"w","function_checkable":false,"reason":"r","parents":["787"]}"#,
            r#""CWE-787":{"name":"w","function_checkable":false,"reason":"r","parents":["CWE-1"]}"#,
            r#""CWE-787":{"name":"w","function_checkable":false,"reason":"r","typo":1}"#,
            r#""CWE-787":{"name":"w","function_checkable":false,"reason":"r"},"787":{"name":"w","function_checkable":false,"reason":"r"}"#,
        ] {
            assert!(load(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn cards_render_per_language_and_bound_their_criteria() {
        let q = question("CWE-787", &Role::Finding, "cpp");
        assert!(q
            .instructions
            .ends_with("(weakness CWE-787 \"Out-of-bounds Write\")"));
        assert!(q.criteria_true.contains("strcpy"), "C++ reads C patterns");
        assert!(q.criteria_false.contains("CWE-125 \"Out-of-bounds Read\""));
        assert!(q.criteria_false.ends_with("outside this function."));
        let py = question("CWE-787", &Role::Finding, "python");
        assert!(!py.criteria_true.contains("strcpy") && py.hash != q.hash);
        for card in catalog().entries.iter().filter(|c| c.function_checkable) {
            let id = &card.id;
            for language in LANGUAGES {
                let q = question(id, &Role::Finding, language);
                for text in [&q.instructions, &q.criteria_true, &q.criteria_false] {
                    assert!(text.chars().count() <= 1500, "{id} {language}: {text}");
                }
            }
        }
    }

    #[test]
    fn uncheckable_cards_are_skipped_and_cannot_be_selected() {
        let plan = plan("c", &Selection::default()).unwrap();
        let skip = plan.skipped.iter().find(|s| s.id == "REL-035").unwrap();
        assert!(skip.reason.contains("not checkable"));
        let only = Selection {
            only: vec!["REL-035".into()],
            exclude: vec![],
        };
        let err = super::plan("c", &only).unwrap_err().to_string();
        assert!(err.contains("REL-035 cannot be checked"), "{err}");
        let exclude = Selection {
            only: vec![],
            exclude: vec!["REL-035".into()],
        };
        assert!(super::plan("c", &exclude).is_ok());
    }

    #[test]
    fn the_parser_settles_syntax_traits_only_for_clean_parses() {
        let t = traits();
        let bit = |k: &str| t.bit(k).unwrap();
        let (switch, comma) = (bit("switch_construct"), bit("increment"));
        let with = scan_traits("c", "int f(int x) { switch (x) { default: return 1; } }");
        assert!(with.found & switch != 0 && with.absent & switch == 0);
        assert!(with.absent & comma != 0);
        let without = scan_traits("c", "int f(int x) { return x++; }");
        assert!(without.absent & switch != 0);
        assert!(without.found & comma != 0 && without.absent & comma == 0);
        // A snippet that does not parse can hide anything, so nothing is settled as absent.
        let broken = scan_traits("c", "int f(int x) { return x");
        assert_eq!(broken.absent, 0);
        // A language a syntax trait lists no node kinds for leaves it unsettled.
        let py = scan_traits("python", "def f(x):\n    return x\n");
        assert!(py.absent & switch != 0 && py.absent & comma == 0);
        // Asked traits are never settled as absent, and syntax traits are not shown to the
        // provider.
        assert_eq!(with.absent & !t.syntax_mask(), 0);
        assert_eq!(
            proven_traits("c", "int f(int x) { switch (x) { default: return 1; } }") & switch,
            0
        );
        assert!(
            scan_traits("rust", "fn f(a: u32, b: u32) -> u32 { a / b }").found & bit("division")
                != 0
        );
        assert!(scan_traits("rust", "fn f(a: u32) -> u32 { a + 1 }").absent & bit("division") != 0);
        // Division and shifts spelled as method calls count, but not a name in a string.
        for call in [
            "a.div_euclid(b)",
            "a.rem_euclid(b)",
            "std::ops::Div::div(a, b)",
            "a.wrapping_rem(b)",
            "a.checked_div(b).unwrap()",
            "a.strict_rem_euclid(b)",
            "a.checked_next_multiple_of(b).unwrap()",
            "a.r#div_euclid(b)",
            // Passed by name rather than called here.
            "[b].into_iter().fold(a, i32::div_euclid)",
        ] {
            let s = scan_traits("rust", &format!("fn f(a: i32, b: i32) -> i32 {{ {call} }}"));
            assert!(
                s.found & bit("division") != 0 && s.absent & bit("division") == 0,
                "{call}"
            );
        }
        for call in ["a.wrapping_shl(b)", "a.strict_shr(b)"] {
            let s = scan_traits("rust", &format!("fn f(a: u32, b: u32) -> u32 {{ {call} }}"));
            assert!(s.found & bit("shift") != 0, "{call}");
        }
        let text = scan_traits("rust", "fn f() -> &'static str { \"div_euclid\" }");
        assert!(text.absent & bit("division") != 0);
    }

    #[test]
    fn trait_names_follow_mask_bits() {
        let t = traits();
        assert!(t.names(0).is_empty());
        assert_eq!(
            t.names(0b101),
            [t.traits[0].key.as_str(), t.traits[2].key.as_str()]
        );
        let names: Vec<String> = t.names(0b101).into_iter().map(String::from).collect();
        assert_eq!(t.mask(&names), 0b101);
        assert_eq!(t.mask(&["no-such-trait".into()]), 0);
    }
}
