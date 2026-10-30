use crate::{manifest, model::*};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
pub fn open(path: &Path) -> Result<Connection> {
    if let Some(p) = path.parent() {
        if !p.as_os_str().is_empty() {
            std::fs::create_dir_all(p)?;
        }
    }
    let db = Connection::open(path)?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    let version: u32 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
    anyhow::ensure!(
        version <= 3,
        "unsupported database schema version: {version}"
    );
    let partial_v2 = version < 2
        && db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='weakness_decisions')",
            [],
            |r| r.get::<_, bool>(0),
        )?;
    if version == 2 || partial_v2 {
        // v3 widens the `origin` CHECK on weakness_decisions; SQLite cannot alter a CHECK.
        db.execute_batch(&format!(
            "PRAGMA foreign_keys=OFF;BEGIN;DROP INDEX IF EXISTS weakness_findings;ALTER TABLE weakness_decisions RENAME TO weakness_decisions_v2;{}INSERT INTO weakness_decisions SELECT * FROM weakness_decisions_v2;DROP TABLE weakness_decisions_v2;COMMIT;",
            include_str!("schema.sql")
        ))?;
    }
    db.execute_batch(include_str!("schema.sql"))?;
    Ok(db)
}
pub fn save(db: &mut Connection, m: &Manifest, files: &[FileSnapshot]) -> Result<()> {
    let tx = db.transaction()?;
    if tx
        .query_row(
            "SELECT 1 FROM snapshots WHERE id=?",
            [&m.snapshot_id],
            |r| r.get::<_, i32>(0),
        )
        .optional()?
        .is_some()
    {
        return Ok(());
    }
    tx.execute("INSERT INTO snapshots(id,schema_version,parser_versions_json,inclusion_policy_json,status,source_complete,manifest_json) VALUES(?,1,?,?,?,?,?)",params![m.snapshot_id,serde_json::to_string(&m.parser_versions)?,serde_json::to_string(&m.inclusion_policy)?,if m.sealed {"sealed"}else{"rejected"},m.source_complete,serde_json::to_string(m)?])?;
    for f in files {
        tx.execute(
            "INSERT OR IGNORE INTO file_blobs VALUES(?,?)",
            params![f.hash, f.bytes],
        )?;
        tx.execute(
            "INSERT INTO files VALUES(?,?,?,?,?,?)",
            params![
                m.snapshot_id,
                f.path,
                f.language,
                f.hash,
                f.coverage.parse_status,
                serde_json::to_string(&f.coverage)?
            ],
        )?;
        for g in f
            .coverage
            .gaps
            .iter()
            .chain(&f.coverage.parse_errors)
            .chain(&f.coverage.macro_sites)
        {
            tx.execute("INSERT INTO gaps(snapshot_id,path,kind,start_byte,end_byte,details_json) VALUES(?,?,?,?,?,?)",params![m.snapshot_id,f.path,g.kind,g.start_byte,g.end_byte,serde_json::to_string(g)?])?;
        }
    }
    for f in &m.functions {
        tx.execute("INSERT INTO functions(id,snapshot_id,path,parent_id,kind,name,qualified_name,start_byte,end_byte,body_start_byte,body_end_byte,source_hash,flags_json,node_kind,record_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",params![f.id,f.snapshot_id,f.path,f.parent_id,f.kind,f.name,f.qualified_name,f.start_byte,f.end_byte,f.body_start_byte,f.body_end_byte,f.source_hash,serde_json::to_string(&f.flags)?,f.node_kind,serde_json::to_string(f)?])?;
    }
    tx.execute("UPDATE snapshots SET locked=1 WHERE id=?", [&m.snapshot_id])?;
    tx.commit()?;
    Ok(())
}
pub fn load(db: &Connection, snapshot: &str) -> Result<Manifest> {
    let s: String = db
        .query_row(
            "SELECT manifest_json FROM snapshots WHERE id=?",
            [snapshot],
            |r| r.get(0),
        )
        .context("snapshot not found")?;
    Ok(serde_json::from_str(&s)?)
}
pub fn get(db: &Connection, snapshot: &str, id: &str) -> Result<Function> {
    let s: String = db
        .query_row(
            "SELECT record_json FROM functions WHERE snapshot_id=? AND id=?",
            params![snapshot, id],
            |r| r.get(0),
        )
        .context("function not found in snapshot")?;
    let mut f: Function = serde_json::from_str(&s)?;
    let bytes:Vec<u8>=db.query_row("SELECT b.bytes FROM files f JOIN file_blobs b ON b.sha256=f.blob_hash WHERE f.snapshot_id=? AND f.path=?",params![snapshot,f.path],|r|r.get(0))?;
    f.source = Some(String::from_utf8(
        bytes
            .get(f.start_byte..f.end_byte)
            .context("invalid stored range")?
            .to_vec(),
    )?);
    Ok(f)
}
pub fn verify(db: &Connection, id: &str) -> Result<serde_json::Value> {
    let m = load(db, id)?;
    let mut files = vec![];
    for c in &m.files {
        let (bytes,h):(Vec<u8>,String)=db.query_row("SELECT b.bytes,f.blob_hash FROM files f JOIN file_blobs b ON b.sha256=f.blob_hash WHERE f.snapshot_id=? AND f.path=?",params![id,c.path],|r|Ok((r.get(0)?,r.get(1)?)))?;
        anyhow::ensure!(hash(&bytes) == h, "file hash mismatch: {}", c.path);
        files.push(FileSnapshot {
            path: c.path.clone(),
            language: c.language.clone(),
            bytes,
            hash: h,
            coverage: c.clone(),
        });
    }
    for f in &m.functions {
        let src = get(db, id, &f.id)?;
        anyhow::ensure!(
            hash(src.source.as_ref().unwrap().as_bytes()) == f.source_hash,
            "source hash mismatch"
        );
        if let (Some(a), Some(b)) = (f.body_start_byte, f.body_end_byte) {
            anyhow::ensure!(
                a >= f.start_byte && a <= b && b <= f.end_byte,
                "body outside definition"
            );
        }
        anyhow::ensure!(
            serde_json::to_value(get_without_source(src))? == serde_json::to_value(f)?,
            "record mismatch"
        );
    }
    let mut reparsed = vec![];
    for file in &files {
        if matches!(file.coverage.parse_status.as_str(), "ok" | "errors") {
            let (functions, coverage) = crate::parse::extract(
                &file.path,
                &file.language,
                &file.bytes,
                m.inclusion_policy.max_nodes,
            )?;
            anyhow::ensure!(
                serde_json::to_value(&coverage)? == serde_json::to_value(&file.coverage)?,
                "stored coverage does not match parser evidence"
            );
            reparsed.extend(functions);
        } else {
            reparsed.extend(m.functions.iter().filter(|f| f.path == file.path).cloned());
        }
    }
    anyhow::ensure!(
        m.source_complete
            == files
                .iter()
                .all(|f| f.coverage.coverage_status == "source_complete"),
        "inconsistent completeness flag"
    );
    let rebuilt = manifest::assemble(
        m.inclusion_policy.clone(),
        &files,
        reparsed,
        m.exclusions.clone(),
        m.source_complete,
        m.sealed,
    );
    anyhow::ensure!(
        serde_json::to_value(&rebuilt)? == serde_json::to_value(&m)?,
        "manifest identity/order/nesting mismatch"
    );
    for c in &m.files {
        anyhow::ensure!(
            c.candidate_nodes_seen
                == c.extracted_occurrences
                    + c.explicitly_excluded_declarations
                    + c.unresolved_candidates,
            "candidate accounting mismatch"
        );
    }
    Ok(
        serde_json::json!({"snapshot_id":id,"valid":true,"source_complete":m.source_complete,"function_count":m.functions.len()}),
    )
}
fn get_without_source(mut f: Function) -> Function {
    f.source = None;
    f
}
