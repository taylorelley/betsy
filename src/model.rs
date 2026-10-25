use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn hash(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
pub fn identity(value: &impl Serialize) -> String {
    hash(&serde_json::to_vec(value).expect("serializable identity"))
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct FunctionFlags {
    pub r#async: bool,
    pub generator: bool,
    pub r#static: bool,
    pub r#unsafe: bool,
    pub exported: bool,
    pub decorated: bool,
    pub template: bool,
    pub inline: bool,
    pub macro_origin: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Function {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub id: String,
    pub language: String,
    pub path: String,
    pub kind: String,
    pub name: Option<String>,
    pub qualified_name: Option<String>,
    pub parent_id: Option<String>,
    pub start_byte: usize,
    pub end_byte: usize,
    pub body_start_byte: Option<usize>,
    pub body_end_byte: Option<usize>,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub source_hash: String,
    pub file_hash: String,
    pub flags: FunctionFlags,
    pub node_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Gap {
    pub kind: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub detail: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coverage {
    pub path: String,
    pub language: String,
    pub parse_status: String,
    pub coverage_status: String,
    pub candidate_nodes_seen: usize,
    pub extracted_occurrences: usize,
    pub explicitly_excluded_declarations: usize,
    pub unresolved_candidates: usize,
    pub parse_errors: Vec<Gap>,
    pub macro_sites: Vec<Gap>,
    pub gaps: Vec<Gap>,
}
impl Coverage {
    pub fn new(path: &str, language: &str) -> Self {
        Self {
            path: path.into(),
            language: language.into(),
            parse_status: "ok".into(),
            coverage_status: "source_complete".into(),
            candidate_nodes_seen: 0,
            extracted_occurrences: 0,
            explicitly_excluded_declarations: 0,
            unresolved_candidates: 0,
            parse_errors: vec![],
            macro_sites: vec![],
            gaps: vec![],
        }
    }
    pub fn fail(&mut self, kind: &str, detail: String, end: usize) {
        self.parse_status = kind.into();
        self.coverage_status = "unverified".into();
        self.gaps.push(Gap {
            kind: kind.into(),
            start_byte: 0,
            end_byte: end,
            detail,
        });
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub includes: Vec<String>,
    pub excludes: Vec<String>,
    pub respect_ignores: bool,
    pub overrides: std::collections::BTreeMap<String, String>,
    pub max_file_bytes: u64,
    pub max_nodes: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exclusion {
    pub path: String,
    pub reason: String,
}
#[derive(Debug, Clone)]
pub struct FileSnapshot {
    pub path: String,
    pub language: String,
    pub bytes: Vec<u8>,
    pub hash: String,
    pub coverage: Coverage,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub parser_versions: serde_json::Value,
    pub inclusion_policy: Policy,
    pub source_complete: bool,
    pub sealed: bool,
    pub files: Vec<Coverage>,
    pub exclusions: Vec<Exclusion>,
    pub functions: Vec<Function>,
}
