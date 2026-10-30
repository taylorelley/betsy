//! Weakness catalogs copied from scorpius-cli, plus the deterministic per-language
//! selection and CWE-1000 hierarchy used to plan per-function decision questions.
//! Nothing here calls a model: selection is a pure function of catalog and language.
use crate::model::{hash, identity};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::OnceLock;

const CATALOG_FILES: [(&str, &str, &[u8]); 3] = [
    (
        "security",
        "cwe_database.json",
        include_bytes!("../data/weaknesses/cwe_database.json"),
    ),
    (
        "reliability",
        "reliability_weaknesses.json",
        include_bytes!("../data/weaknesses/reliability_weaknesses.json"),
    ),
    (
        "performance",
        "performance_weaknesses.json",
        include_bytes!("../data/weaknesses/performance_weaknesses.json"),
    ),
];
/// Bumped whenever plan shape or question wording changes, so cached run identities differ.
pub const PROFILE: &str = "function-v4";
const HIERARCHY_VIEW: &str = "CWE-1000";
const TRAITS_FILE: &[u8] = include_bytes!("../data/weaknesses/traits.json");
/// Detection cards: an overlay that rewrites questions without touching the source catalogs.
const CARDS_FILE: &[u8] = include_bytes!("../data/weaknesses/cards.json");

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Platform {
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub class: String,
    #[serde(default)]
    pub name: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Related {
    pub nature: String,
    pub cwe_id: String,
    #[serde(default)]
    pub view_id: String,
    #[serde(default)]
    pub ordinal: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Weakness {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub extended_description: String,
    #[serde(default)]
    pub abstraction: String,
    #[serde(default)]
    pub mapping_usage: String,
    #[serde(default)]
    pub applicable_platforms: Vec<Platform>,
    #[serde(default)]
    pub related_weaknesses: Vec<Related>,
    #[serde(default)]
    pub modes_of_introduction: Vec<String>,
    #[serde(skip_deserializing)]
    pub catalog: String,
}
impl Weakness {
    /// Gated on the ID prefix, as in scorpius `is_mitre_cwe()`: other catalogs reuse the fields.
    pub fn is_mitre_cwe(&self) -> bool {
        self.id.starts_with("CWE-")
    }
    /// Primary CWE-1000 parent; non-MITRE entries hang under their `PeerOf` CWEs instead,
    /// tried in catalog order, so reliability and performance entries are gated too.
    /// Entries in [`DETACHED`] have no parent and are asked as roots.
    fn parent_candidates(&self) -> Vec<&str> {
        if DETACHED.iter().any(|(id, _)| *id == self.id) {
            return vec![];
        }
        if !self.is_mitre_cwe() {
            return self
                .related_weaknesses
                .iter()
                .filter(|r| r.nature == "PeerOf")
                .map(|r| r.cwe_id.as_str())
                .collect();
        }
        let parents: Vec<&Related> = self
            .related_weaknesses
            .iter()
            .filter(|r| r.nature == "ChildOf" && r.view_id == HIERARCHY_VIEW)
            .collect();
        parents
            .iter()
            .find(|r| r.ordinal == "Primary")
            .or(parents.first())
            .map(|r| r.cwe_id.as_str())
            .into_iter()
            .collect()
    }
}

/// Entries planned as roots because a low answer for their catalog parent says little about
/// them; measured with `betsy run recall` against exhaustive runs on SQLite functions.
pub const DETACHED: &[(&str, &str)] = &[
    (
        "CWE-617",
        "assertions are common in C, while its parent CWE-705 (control flow scoping) rarely applies",
    ),
    (
        "REL-026",
        "missing guards before any hazardous operation is broader than its PeerOf CWE-369 (divide by zero)",
    ),
];

pub struct Catalog {
    pub entries: Vec<Weakness>,
    pub hash: String,
    index: HashMap<String, usize>,
}
impl Catalog {
    fn load() -> Result<Self> {
        let mut entries = vec![];
        let mut hashes = vec![];
        for (catalog, file, bytes) in CATALOG_FILES {
            let mut list: Vec<Weakness> =
                serde_json::from_slice(bytes).with_context(|| format!("parsing {file}"))?;
            for w in &mut list {
                w.catalog = catalog.into();
            }
            entries.extend(list);
            hashes.push((file, hash(bytes)));
        }
        // Cards change questions and the plan, so they belong to the catalog's identity.
        hashes.push(("cards.json", hash(CARDS_FILE)));
        let mut index = HashMap::new();
        for (i, w) in entries.iter().enumerate() {
            let key = normalize_id(&w.id).with_context(|| format!("invalid id {}", w.id))?;
            anyhow::ensure!(
                index.insert(key, i).is_none(),
                "duplicate weakness {}",
                w.id
            );
        }
        Ok(Self {
            entries,
            hash: identity(&hashes),
            index,
        })
    }
    pub fn get(&self, raw: &str) -> Option<&Weakness> {
        normalize_id(raw).and_then(|k| self.index.get(&k).map(|&i| &self.entries[i]))
    }
}
pub fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| Catalog::load().expect("embedded weakness catalogs are valid"))
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

/// Code patterns keyed by `any` or a betsy language; see [`card_languages`].
pub type Patterns = BTreeMap<String, Vec<String>>;
/// A detection card: how to decide one weakness from one function's own code. It replaces the
/// catalog prose in the question, which was written for people reading a catalogue.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Card {
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
#[derive(Deserialize)]
struct CardFile {
    cards: BTreeMap<String, Card>,
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
pub struct Cards {
    /// Keyed by the catalog's own spelling of the weakness ID.
    pub cards: HashMap<String, Card>,
}
impl Cards {
    fn load(bytes: &[u8]) -> Result<Self> {
        const KEYS: [&str; 8] = [
            "any",
            "c",
            "cpp",
            "javascript",
            "typescript",
            "tsx",
            "python",
            "rust",
        ];
        let file: CardFile = serde_json::from_slice(bytes).context("parsing cards.json")?;
        let mut cards = HashMap::new();
        for (raw, mut card) in file.cards {
            let id = catalog()
                .get(&raw)
                .with_context(|| format!("card for unknown weakness {raw}"))?
                .id
                .clone();
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
                anyhow::ensure!(KEYS.contains(&k.as_str()), "{id}: unknown language {k}");
                anyhow::ensure!(
                    v.iter().all(|p| !p.trim().is_empty()),
                    "{id}: empty pattern"
                );
            }
            card.distinguish_from = card
                .distinguish_from
                .into_iter()
                .map(|(other, note)| {
                    let w = catalog()
                        .get(&other)
                        .with_context(|| format!("{id} distinguishes unknown weakness {other}"))?;
                    anyhow::ensure!(w.id != id, "{id} distinguishes itself");
                    Ok((w.id.clone(), note))
                })
                .collect::<Result<_>>()?;
            anyhow::ensure!(
                cards.insert(id.clone(), card).is_none(),
                "duplicate card {id}"
            );
        }
        Ok(Self { cards })
    }
    pub fn get(&self, id: &str) -> Option<&Card> {
        self.cards.get(id)
    }
}
pub fn cards() -> &'static Cards {
    static CARDS: OnceLock<Cards> = OnceLock::new();
    CARDS.get_or_init(|| Cards::load(CARDS_FILE).expect("embedded detection cards are valid"))
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

/// Platform names a betsy language satisfies in catalog `applicable_platforms`.
fn platform_names(language: &str) -> &'static [&'static str] {
    match language {
        "c" => &["C", "Memory-Unsafe"],
        "cpp" => &["C++", "C", "Memory-Unsafe", "Object-Oriented"],
        "javascript" => &["JavaScript", "Object-Oriented", "Interpreted"],
        "typescript" | "tsx" => &["TypeScript", "JavaScript", "Object-Oriented"],
        "python" => &["Python", "Object-Oriented", "Interpreted"],
        "rust" => &["Rust", "Memory-Unsafe"],
        _ => &[],
    }
}
fn hardware_only(w: &Weakness) -> bool {
    let hw = |p: &Platform| {
        matches!(p.name.as_str(), "Verilog" | "VHDL" | "System on Chip")
            || p.name.ends_with("Hardware")
            || matches!(
                p.class.as_str(),
                "System on Chip" | "Hardware Description Language"
            )
            || p.class.ends_with("Hardware")
    };
    let specific: Vec<&Platform> = w
        .applicable_platforms
        .iter()
        .filter(|p| matches!(p.kind.as_str(), "Language" | "Technology"))
        .filter(|p| !p.class.starts_with("Not "))
        .collect();
    !specific.is_empty() && specific.iter().all(|p| hw(p))
}
/// True when every listed mode of introduction lies outside source code.
fn introduced_outside_code(w: &Weakness) -> bool {
    const CODE: [&str; 5] = [
        "Implementation",
        "Architecture and Design",
        "Design",
        "Integration",
        "Porting",
    ];
    !w.modes_of_introduction.is_empty()
        && !w
            .modes_of_introduction
            .iter()
            .any(|m| CODE.contains(&m.as_str()))
}
fn language_applies(w: &Weakness, language: &str) -> bool {
    let langs: Vec<&Platform> = w
        .applicable_platforms
        .iter()
        .filter(|p| p.kind == "Language" || p.kind.is_empty())
        .collect();
    if langs.is_empty() || langs.iter().any(|p| p.class == "Not Language-Specific") {
        return true;
    }
    let names = platform_names(language);
    langs
        .iter()
        .any(|p| names.contains(&p.name.as_str()) || names.contains(&p.class.as_str()))
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Asked, and reported as a finding when above threshold.
    Finding,
    /// Asked only to route the hierarchy (MITRE Prohibited/Discouraged/Pillar entries).
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

pub fn plan(language: &str, selection: &Selection) -> Result<Plan> {
    let cat = catalog();
    let exclude = resolve_ids(&selection.exclude)?;
    let only = resolve_ids(&selection.only)?;
    let mut skipped = vec![];
    let mut kept: BTreeMap<&str, Role> = BTreeMap::new();
    for w in &cat.entries {
        let reason = if exclude.contains(&w.id) {
            Some("excluded by selection")
        } else if !only.is_empty() {
            (!only.contains(&w.id)).then_some("not in explicit selection")
        } else if hardware_only(w) {
            Some("hardware-only platform")
        } else if introduced_outside_code(w) {
            Some("introduced outside source code")
        } else if !language_applies(w, language) {
            Some("language not applicable")
        } else if cards().get(&w.id).is_some_and(|c| !c.function_checkable) {
            Some("not checkable within one function (detection card)")
        } else {
            None
        };
        match reason {
            Some(r) => skipped.push(Skip {
                id: w.id.clone(),
                reason: r.into(),
            }),
            None => {
                let gate = only.is_empty()
                    && w.is_mitre_cwe()
                    && (matches!(w.mapping_usage.as_str(), "Prohibited" | "Discouraged")
                        || w.abstraction == "Pillar");
                kept.insert(&w.id, if gate { Role::Gate } else { Role::Finding });
            }
        }
    }
    // Primary CWE-1000 parent among kept entries; an entry whose parent was skipped is a root.
    let parent_of = |id: &str| -> Option<&str> {
        if !only.is_empty() {
            return None;
        }
        cat.get(id).and_then(|w| {
            w.parent_candidates()
                .into_iter()
                .filter_map(|p| cat.get(p))
                .map(|p| p.id.as_str())
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

fn compact(text: &str, max: usize) -> String {
    let s = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() <= max {
        return s;
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
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
/// Phrases that mark a catalog sentence as ruling cases out rather than describing the weakness.
const EXCLUDING: [&str; 9] = [
    "do not count",
    "does not count",
    "not counted",
    "not this weakness",
    "not a defect",
    "not defects",
    "not findings",
    "is not about",
    "does not cover",
];
/// Verdicts that rule a case out only when they end a clause: "is acceptable." but not
/// "is acceptable for a handful of rows", nor "not affected by the HTML encoding".
const EXCLUDING_VERDICTS: [&str; 13] = [
    "not affected",
    "is fine",
    "are fine",
    "is acceptable",
    "are acceptable",
    "is permitted",
    "are permitted",
    "is allowed",
    "are allowed",
    "is compliant",
    "are compliant",
    "is out of scope",
    "are out of scope",
];
fn excludes(sentence: &str) -> bool {
    let s = sentence.to_lowercase();
    if s.starts_with("of these") || s.starts_with("of those") {
        // Points back at an earlier sentence, so it means nothing on its own.
        return false;
    }
    EXCLUDING.iter().any(|p| s.contains(p))
        || EXCLUDING_VERDICTS.iter().any(|p| {
            s.match_indices(p).any(|(i, _)| {
                let rest = &s[i + p.len()..];
                rest.is_empty()
                    || rest.starts_with(['.', ',', ';', ':'])
                    || [" as ", " here", " too", " and ", " nor", " when", " since"]
                        .iter()
                        .any(|t| rest.starts_with(t))
            })
        })
}
/// Splits whitespace-collapsed prose into sentences at `.`, `?` or `!` followed by a space and an
/// upper-case letter, keeping common abbreviations whole.
fn sentences(text: &str) -> Vec<&str> {
    let mut out = vec![];
    let mut start = 0;
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if !matches!(b, b'.' | b'?' | b'!') || bytes.get(i + 1) != Some(&b' ') {
            continue;
        }
        if !bytes.get(i + 2).is_some_and(|c| c.is_ascii_uppercase()) {
            continue;
        }
        let head = &text[start..=i];
        if ["e.g.", "i.e.", "vs.", "cf."]
            .iter()
            .any(|a| head.to_lowercase().ends_with(a))
        {
            continue;
        }
        out.push(head);
        start = i + 2;
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}
/// Separates the sentences that rule cases out ("... do not count", "... are fine") from the rest
/// of an entry's prose, so they reach the false criterion instead of falling after the cut.
pub fn split_exclusions(text: &str) -> (String, String) {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let (excluded, kept): (Vec<&str>, Vec<&str>) =
        sentences(&text).into_iter().partition(|s| excludes(s));
    (kept.join(" "), excluded.join(" "))
}
fn sentence_list(items: &[&str]) -> String {
    items
        .iter()
        .map(|s| s.trim().trim_end_matches('.'))
        .collect::<Vec<_>>()
        .join("; ")
}
const OUTSIDE: &str = "it would only arise outside this function";
/// Question text from a detection card; gates keep their recall-oriented framing.
fn card_question(
    w: &Weakness,
    card: &Card,
    role: &Role,
    language: &str,
) -> (String, String, String) {
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
/// Question text from catalog prose, for entries without a detection card.
fn prose_question(w: &Weakness, role: &Role) -> (String, String, String) {
    let detail = if w.extended_description.is_empty() {
        &w.description
    } else {
        &w.extended_description
    };
    match role {
        Role::Finding => {
            let (detail, exclusions) = split_exclusions(detail);
            let criteria_false = if exclusions.is_empty() {
                format!("The function's code does not exhibit this weakness, or {OUTSIDE}.")
            } else {
                format!(
                    "{} Also no when the function's code does not exhibit this weakness, or {OUTSIDE}.",
                    compact(&exclusions, 600)
                )
            };
            (
                format!(
                    "Does this function's own code contain the weakness {} \"{}\"? {}",
                    w.id,
                    w.name,
                    compact(&w.description, 400)
                ),
                format!(
                    "The function's code exhibits {}: {}",
                    w.name,
                    compact(&detail, 600)
                ),
                criteria_false,
            )
        }
        Role::Gate => (
            format!(
                "Is it plausible that this function's code contains any weakness in the category {} \"{}\"? {}",
                w.id,
                w.name,
                compact(&w.description, 400)
            ),
            format!("The function plausibly involves {}.", w.name),
            "The function clearly does nothing related to this category.".to_string(),
        ),
    }
}
/// The question for one planned weakness in one language: from its detection card when it has
/// one, otherwise from the catalog prose.
pub fn question(id: &str, role: &Role, language: &str) -> Question {
    let w = catalog().get(id).expect("planned weakness exists");
    let (instructions, criteria_true, criteria_false) =
        match cards().get(&w.id).filter(|c| c.function_checkable) {
            Some(card) => card_question(w, card, role, language),
            None => prose_question(w, role),
        };
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

    fn weakness(id: &str) -> Weakness {
        Weakness {
            id: id.into(),
            name: "w".into(),
            description: String::new(),
            extended_description: String::new(),
            abstraction: String::new(),
            mapping_usage: String::new(),
            applicable_platforms: vec![],
            related_weaknesses: vec![],
            modes_of_introduction: vec![],
            catalog: String::new(),
        }
    }
    fn platform(kind: &str, class: &str, name: &str) -> Platform {
        Platform {
            kind: kind.into(),
            class: class.into(),
            name: name.into(),
        }
    }
    fn related(nature: &str, id: &str, view: &str, ordinal: &str) -> Related {
        Related {
            nature: nature.into(),
            cwe_id: id.into(),
            view_id: view.into(),
            ordinal: ordinal.into(),
        }
    }

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

    #[test]
    fn language_platforms_filter_only_named_languages() {
        let mut w = weakness("CWE-1");
        assert!(language_applies(&w, "python"));
        w.applicable_platforms = vec![platform("Language", "", "C")];
        assert!(language_applies(&w, "c") && language_applies(&w, "cpp"));
        assert!(!language_applies(&w, "python") && !language_applies(&w, "rust"));
        w.applicable_platforms = vec![platform("Language", "Memory-Unsafe", "")];
        assert!(language_applies(&w, "rust") && !language_applies(&w, "javascript"));
        w.applicable_platforms
            .push(platform("Language", "Not Language-Specific", ""));
        assert!(language_applies(&w, "javascript"));
        w.applicable_platforms = vec![platform("Technology", "Web Based", "")];
        assert!(
            language_applies(&w, "python"),
            "technology platforms do not restrict language"
        );
    }

    #[test]
    fn hardware_only_needs_every_specific_platform_to_be_hardware() {
        let mut w = weakness("CWE-1");
        assert!(!hardware_only(&w));
        w.applicable_platforms = vec![
            platform("Language", "", "Verilog"),
            platform("Technology", "System on Chip", ""),
            platform("Language", "Not Language-Specific", ""),
        ];
        assert!(hardware_only(&w));
        w.applicable_platforms.push(platform("Language", "", "C"));
        assert!(!hardware_only(&w));
    }

    #[test]
    fn modes_outside_code_skip_only_when_none_touch_code() {
        let mut w = weakness("CWE-1");
        assert!(!introduced_outside_code(&w));
        w.modes_of_introduction = vec!["Operation".into(), "Build and Compilation".into()];
        assert!(introduced_outside_code(&w));
        w.modes_of_introduction.push("Implementation".into());
        assert!(!introduced_outside_code(&w));
    }

    #[test]
    fn parents_prefer_primary_cwe_1000_edge_and_peers_for_other_catalogs() {
        let mut w = weakness("CWE-5");
        w.related_weaknesses = vec![
            related("ChildOf", "CWE-1", "CWE-699", "Primary"),
            related("ChildOf", "CWE-2", HIERARCHY_VIEW, ""),
            related("ChildOf", "CWE-3", HIERARCHY_VIEW, "Primary"),
            related("PeerOf", "CWE-4", HIERARCHY_VIEW, ""),
        ];
        assert_eq!(w.parent_candidates(), ["CWE-3"]);
        w.related_weaknesses.remove(2);
        assert_eq!(w.parent_candidates(), ["CWE-2"]);
        w.id = "REL-5".into();
        assert_eq!(w.parent_candidates(), ["CWE-4"]);
        w.id = "REL-026".into();
        assert!(w.parent_candidates().is_empty());
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
    fn compact_collapses_whitespace_and_truncates_by_character() {
        assert_eq!(compact(" a \n\t b ", 10), "a b");
        assert_eq!(compact("ééééé", 5), "ééééé");
        assert_eq!(compact("ééééé", 4), "ééé…");
        assert_eq!(compact("abc", 0), "…");
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
    fn exclusions_are_lifted_out_of_the_cut() {
        let (kept, excluded) = split_exclusions(
            "A divisor from input is used. Its sign, e.g. a negative, is not checked. Code where \
             the range is proven locally does not count. Latency that is acceptable for a few \
             rows grows. Of these, only the last is acceptable. Plain -O2 is fine.",
        );
        assert_eq!(
            excluded,
            "Code where the range is proven locally does not count. Plain -O2 is fine."
        );
        assert!(kept.contains("e.g. a negative") && kept.contains("acceptable for a few"));
        assert!(kept.ends_with("only the last is acceptable."));
        let q = question("REL-026", &Role::Finding, "c");
        assert!(!q.criteria_true.contains("does not count"));
        let q = question("REL-105", &Role::Finding, "c");
        assert!(q.criteria_false.starts_with("Constant shift counts"));
        assert!(q.criteria_false.contains("outside this function"));
        let q = question("CWE-89", &Role::Finding, "c");
        assert!(q
            .criteria_false
            .starts_with("The function's code does not exhibit"));
    }

    #[test]
    fn cards_validate_ids_fields_and_languages() {
        let ok = r#"{"cards":{"cwe-787":{"function_checkable":true,"question":"q?",
            "present_when":{"c":["p"]},"not_present_when":{"any":["n"]},
            "distinguish_from":{"125":"reads"}}}}"#;
        let c = Cards::load(ok.as_bytes()).unwrap();
        assert_eq!(
            c.get("CWE-787")
                .unwrap()
                .distinguish_from
                .keys()
                .collect::<Vec<_>>(),
            ["CWE-125"]
        );
        for bad in [
            r#"{"cards":{"CWE-0":{"function_checkable":false,"reason":"r"}}}"#,
            r#"{"cards":{"CWE-787":{"function_checkable":false}}}"#,
            r#"{"cards":{"CWE-787":{"function_checkable":true,"question":"q?","present_when":{"c":["p"]}}}}"#,
            r#"{"cards":{"CWE-787":{"function_checkable":true,"question":"q?","present_when":{"go":["p"]},"not_present_when":{"any":["n"]}}}}"#,
            r#"{"cards":{"CWE-787":{"function_checkable":true,"question":"q?","present_when":{"c":["p"]},"not_present_when":{"any":["n"]},"distinguish_from":{"CWE-787":"x"}}}}"#,
            r#"{"cards":{"CWE-787":{"function_checkable":false,"reason":"r","typo":1}}}"#,
            r#"{"cards":{"CWE-787":{"function_checkable":false,"reason":"r"},"787":{"function_checkable":false,"reason":"r"}}}"#,
        ] {
            assert!(Cards::load(bad.as_bytes()).is_err(), "{bad}");
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
        for (id, card) in &cards().cards {
            if !card.function_checkable {
                continue;
            }
            for language in [
                "c",
                "cpp",
                "javascript",
                "typescript",
                "tsx",
                "python",
                "rust",
            ] {
                let q = question(id, &Role::Finding, language);
                for text in [&q.instructions, &q.criteria_true, &q.criteria_false] {
                    assert!(text.chars().count() <= 1500, "{id} {language}: {text}");
                }
            }
        }
    }

    #[test]
    fn uncheckable_cards_are_skipped_unless_selected() {
        let plan = plan("c", &Selection::default()).unwrap();
        let skip = plan.skipped.iter().find(|s| s.id == "REL-035").unwrap();
        assert!(skip.reason.contains("detection card"));
        let only = Selection {
            only: vec!["REL-035".into()],
            exclude: vec![],
        };
        assert_eq!(super::plan("c", &only).unwrap().nodes.len(), 1);
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
