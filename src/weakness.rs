//! Weakness cards and the deterministic per-language selection and hierarchy used to plan
//! per-function decision questions. `data/weaknesses/cards.json` is the only weakness
//! definition: one card names a weakness, places it in the hierarchy and says how to decide it.
//! Nothing here calls a model: selection is a pure function of the cards and the language.
use crate::model::{hash, identity};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::OnceLock;

/// Bumped whenever plan shape or question wording changes, so cached run identities differ.
pub const PROFILE: &str = "function-v6";
const TRAITS_FILE: &[u8] = include_bytes!("../data/weaknesses/traits.json");
const CARDS_FILE: &[u8] = include_bytes!("../data/weaknesses/cards.json");
/// Languages a card may name in `languages` and, with `any`, as a pattern key.
const LANGUAGES: [&str; 7] = [
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
impl Card {
    /// Parents to try, in order. Cards in [`DETACHED`] have none and are asked as roots.
    fn parent_candidates(&self) -> &[String] {
        if DETACHED.iter().any(|(id, _)| *id == self.id) {
            return &[];
        }
        &self.parents
    }
    fn language_applies(&self, language: &str) -> bool {
        self.languages.is_empty() || self.languages.iter().any(|l| l == language)
    }
}

/// Entries planned as roots because a low answer for their parent says little about them;
/// measured with `betsy run recall` against exhaustive runs on SQLite functions.
pub const DETACHED: &[(&str, &str)] = &[
    (
        "CWE-617",
        "assertions are common in C, while its parent CWE-705 (control flow scoping) rarely applies",
    ),
    (
        "REL-026",
        "missing guards before any hazardous operation is broader than its parent CWE-369 (divide by zero)",
    ),
];

#[derive(Deserialize)]
struct CardFile {
    cards: BTreeMap<String, Card>,
}
pub struct Catalog {
    /// Ordered by catalog, then by ID number.
    pub entries: Vec<Card>,
    pub hash: String,
    index: HashMap<String, usize>,
}
impl Catalog {
    fn load(bytes: &[u8]) -> Result<Self> {
        let file: CardFile = serde_json::from_slice(bytes).context("parsing cards.json")?;
        let mut keyed = vec![];
        for (raw, mut card) in file.cards {
            let key = normalize_id(&raw).with_context(|| format!("invalid id {raw}"))?;
            let (prefix, number) = key.split_once('-').expect("normalized ids have a prefix");
            let rank = CATALOGS
                .iter()
                .position(|(p, _)| *p == prefix)
                .with_context(|| format!("{raw}: unknown catalog prefix {prefix}"))?;
            let number: u64 = number.parse().expect("normalized ids end in a number");
            card.catalog = CATALOGS[rank].1.into();
            card.id = raw;
            keyed.push(((rank, number), key, card));
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
            resolved.push((parents, distinguish));
        }
        for (card, (parents, distinguish)) in entries.iter_mut().zip(resolved) {
            card.parents = parents;
            card.distinguish_from = distinguish;
        }
        Ok(Self {
            entries,
            hash: identity(&[("cards.json", hash(bytes))]),
            index,
        })
    }
    pub fn get(&self, raw: &str) -> Option<&Card> {
        normalize_id(raw).and_then(|k| self.index.get(&k).map(|&i| &self.entries[i]))
    }
}
pub fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| Catalog::load(CARDS_FILE).expect("embedded weakness cards are valid"))
}

/// An observable property of a function, asked once before any weakness so that weaknesses
/// which cannot apply without it are never asked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trait {
    pub key: String,
    pub question: String,
    #[serde(rename = "true")]
    pub criteria_true: String,
    #[serde(rename = "false")]
    pub criteria_false: String,
    /// Per language, syntax node kinds whose presence proves the trait without asking.
    /// Absence proves nothing: macros, callees and aliases can hide any construct.
    #[serde(default)]
    pub present_if: BTreeMap<String, Vec<String>>,
}
#[derive(Deserialize)]
struct TraitFile {
    traits: Vec<Trait>,
    requires: BTreeMap<String, Vec<String>>,
}
pub struct Traits {
    pub traits: Vec<Trait>,
    /// Weakness ID to the traits, as a bitmask, of which at least one must be present.
    pub requires: HashMap<String, u64>,
    pub hash: String,
}
impl Traits {
    fn load() -> Result<Self> {
        let file: TraitFile = serde_json::from_slice(TRAITS_FILE).context("parsing traits.json")?;
        anyhow::ensure!(file.traits.len() <= 64, "at most 64 traits fit a mask");
        let bit: HashMap<&str, u64> = file
            .traits
            .iter()
            .enumerate()
            .map(|(i, t)| (t.key.as_str(), 1u64 << i))
            .collect();
        anyhow::ensure!(bit.len() == file.traits.len(), "duplicate trait key");
        let mut requires = HashMap::new();
        for (id, keys) in &file.requires {
            let w = catalog()
                .get(id)
                .with_context(|| format!("traits.json tags unknown weakness {id}"))?;
            anyhow::ensure!(!keys.is_empty(), "{id} requires no traits");
            let mut mask = 0;
            for k in keys {
                mask |= bit
                    .get(k.as_str())
                    .with_context(|| format!("{id} requires unknown trait {k}"))?;
            }
            requires.insert(w.id.clone(), mask);
        }
        Ok(Self {
            traits: file.traits,
            requires,
            hash: hash(TRAITS_FILE),
        })
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
/// Traits whose `present_if` node kinds occur in the function's own syntax tree. A snippet that
/// does not parse cleanly can still prove presence, since only presence is ever concluded.
pub fn proven_traits(language: &str, source: &str) -> u64 {
    let t = traits();
    let wanted: Vec<(u64, &[String])> = t
        .traits
        .iter()
        .enumerate()
        .filter_map(|(i, tr)| {
            tr.present_if
                .get(language)
                .map(|k| (1u64 << i, k.as_slice()))
        })
        .collect();
    if wanted.is_empty() {
        return 0;
    }
    let mut parser = tree_sitter::Parser::new();
    let Ok(grammar) = crate::languages::grammar(language) else {
        return 0;
    };
    if parser.set_language(&grammar).is_err() {
        return 0;
    }
    let Some(tree) = parser.parse(source, None) else {
        return 0;
    };
    let mut found = 0;
    let mut cursor = tree.walk();
    'walk: loop {
        let kind = cursor.node().kind();
        for (bit, kinds) in &wanted {
            if kinds.iter().any(|k| k == kind) {
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
    found
}
pub fn traits() -> &'static Traits {
    static TRAITS: OnceLock<Traits> = OnceLock::new();
    TRAITS.get_or_init(|| Traits::load().expect("embedded traits are valid"))
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
fn patterns_for<'a>(p: &'a Patterns, language: &str) -> Vec<&'a str> {
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
            w.parent_candidates()
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
    let tags = &traits().requires;
    if only.is_empty() {
        for n in &mut nodes {
            n.requires = tags.get(&n.id).copied();
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
            if nodes[c].requires.is_none() && !tags.contains_key(&nodes[c].id) {
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
        Catalog::load(format!(r#"{{"cards":{{{cards}}}}}"#).as_bytes())
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
    fn parents_keep_their_order_and_detached_cards_have_none() {
        let c = load(&format!(
            r#""CWE-1":{{"name":"a",{OK}}},"CWE-2":{{"name":"b",{OK}}},
            "REL-5":{{"name":"c","parents":["2","cwe_1"],{OK}}},
            "REL-026":{{"name":"d","parents":["CWE-1"],{OK}}}"#
        ))
        .unwrap();
        assert_eq!(
            c.get("REL-5").unwrap().parent_candidates(),
            ["CWE-2", "CWE-1"]
        );
        assert!(c.get("REL-026").unwrap().parent_candidates().is_empty());
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
        for (id, _) in DETACHED {
            let node = plan
                .nodes
                .iter()
                .find(|n| n.id == *id)
                .expect("planned for C");
            assert!(node.parent.is_none(), "{id} has a parent");
        }
    }

    #[test]
    fn gates_are_never_findings_and_reliability_and_performance_cards_are_gated() {
        for language in LANGUAGES {
            let p = plan(language, &Selection::default()).unwrap();
            for n in &p.nodes {
                let card = catalog().get(&n.id).unwrap();
                assert_eq!(n.role == Role::Gate, card.gate, "{language}: {}", n.id);
                let detached = DETACHED.iter().any(|(id, _)| *id == n.id);
                if card.catalog != "security" && !card.parents.is_empty() && !detached {
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
