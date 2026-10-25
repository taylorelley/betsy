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
pub const PROFILE: &str = "function-v1";
const HIERARCHY_VIEW: &str = "CWE-1000";

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
    fn primary_parent(&self) -> Option<&str> {
        if !self.is_mitre_cwe() {
            return None;
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
    }
}

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
        cat.get(id)
            .and_then(Weakness::primary_parent)
            .filter(|p| kept.contains_key(p))
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
    fn size(nodes: &mut [Node], i: usize) -> usize {
        let children = nodes[i].children.clone();
        let s = 1 + children.into_iter().map(|c| size(nodes, c)).sum::<usize>();
        nodes[i].subtree = s;
        s
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
pub fn question(id: &str, role: &Role) -> Question {
    let w = catalog().get(id).expect("planned weakness exists");
    let detail = if w.extended_description.is_empty() {
        &w.description
    } else {
        &w.extended_description
    };
    let (instructions, criteria_true, criteria_false) = match role {
        Role::Finding => (
            format!(
                "Does this function's own code contain the weakness {} \"{}\"? {}",
                w.id,
                w.name,
                compact(&w.description, 400)
            ),
            format!(
                "The function's code exhibits {}: {}",
                w.name,
                compact(detail, 600)
            ),
            "The function's code does not exhibit this weakness, or it would only arise outside this function."
                .to_string(),
        ),
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
