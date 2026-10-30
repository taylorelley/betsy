//! The typed record handed to analyzers: one stored function plus deterministic, bounded
//! features derived only from its own source, so they never change for the same `source_hash`.
//! Parser facts only; nothing here calls a model.
use crate::{model::Function, weakness};
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

/// Bumped whenever the request or feature shape changes.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Features {
    pub lines: usize,
    pub bytes: usize,
    /// Callables extracted inside this one at any depth.
    pub nested_callables: usize,
    /// Traits whose syntax occurs in the function. Absence is never implied.
    pub syntax_traits: Vec<String>,
}
pub fn features(db: &Connection, f: &Function) -> Result<Features> {
    let nested: usize = db.query_row(
        "SELECT count(*) FROM functions WHERE snapshot_id=? AND path=? AND start_byte>=? AND start_byte<? AND end_byte<=? AND id<>?",
        params![f.snapshot_id, f.path, f.start_byte, f.end_byte, f.end_byte, f.id],
        |r| r.get(0),
    )?;
    let source = f
        .source
        .as_deref()
        .context("function record has no source")?;
    let traits = weakness::traits();
    Ok(Features {
        lines: f.end_line + 1 - f.start_line,
        bytes: f.end_byte - f.start_byte,
        nested_callables: nested,
        syntax_traits: traits
            .names(weakness::proven_traits(&f.language, source))
            .into_iter()
            .map(String::from)
            .collect(),
    })
}

/// One analyzer request; `occurrence_id` is the idempotency key for external side effects.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_profile: Option<String>,
    pub occurrence_id: String,
    pub snapshot_id: String,
    /// False for `--allow-partial` snapshots: findings cannot claim full coverage.
    pub source_complete: bool,
    pub source_hash: String,
    pub language: String,
    pub path: String,
    pub kind: String,
    pub name: Option<String>,
    pub qualified_name: Option<String>,
    pub features: Features,
    pub source: String,
}
pub fn request(db: &Connection, f: &Function, profile: Option<&str>) -> Result<Request> {
    let source_complete: bool = db.query_row(
        "SELECT source_complete FROM snapshots WHERE id=?",
        [&f.snapshot_id],
        |r| r.get(0),
    )?;
    Ok(Request {
        schema_version: SCHEMA_VERSION,
        analysis_profile: profile.map(String::from),
        occurrence_id: f.id.clone(),
        snapshot_id: f.snapshot_id.clone(),
        source_complete,
        source_hash: f.source_hash.clone(),
        language: f.language.clone(),
        path: f.path.clone(),
        kind: f.kind.clone(),
        name: f.name.clone(),
        qualified_name: f.qualified_name.clone(),
        features: features(db, f)?,
        source: f.source.clone().context("function record has no source")?,
    })
}
