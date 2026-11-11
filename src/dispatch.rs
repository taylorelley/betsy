use crate::{
    model::{identity, Function},
    store,
};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{json, Value};
fn run_snapshot(db: &Connection, run: &str) -> Result<String> {
    db.query_row(
        "SELECT snapshot_id FROM dispatch_runs WHERE id=?",
        [run],
        |r| r.get(0),
    )
    .context("run not found")
}
pub fn create(db: &mut Connection, snapshot: &str, analyzer: &str) -> Result<Value> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let created = create_in(&tx, snapshot, analyzer)?;
    tx.commit()?;
    Ok(created)
}
/// Creates a run inside the caller's transaction, so callers can attach more records to it
/// atomically. Items are numbered in canonical queue order once, so each claim is an index
/// lookup instead of a sort over the whole run.
pub fn create_in(tx: &Transaction, snapshot: &str, analyzer: &str) -> Result<Value> {
    let (status, source_complete): (String, bool) = tx
        .query_row(
            "SELECT status,source_complete FROM snapshots WHERE id=?",
            [snapshot],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .context("snapshot not found")?;
    anyhow::ensure!(status == "sealed", "snapshot is not sealed");
    let seq: i64 = tx.query_row("SELECT count(*) FROM dispatch_runs", [], |r| r.get(0))?;
    let config = identity(&(analyzer, 1));
    let run = identity(&(snapshot, &config, seq));
    tx.execute(
        "INSERT INTO dispatch_runs VALUES(?,?,?,'active')",
        params![run, snapshot, config],
    )?;
    tx.execute(
        &format!("INSERT INTO dispatch_items(run_id,function_id,status,ordinal) SELECT ?,id,'pending',row_number() OVER (ORDER BY {CANONICAL}) FROM functions WHERE snapshot_id=?"),
        params![run, snapshot],
    )?;
    Ok(
        json!({"run_id":run,"snapshot_id":snapshot,"analyzer_config_hash":config,"source_complete":source_complete}),
    )
}
/// Canonical queue order over `functions` columns: UTF-8 path bytes, span, node kind, ID.
pub const CANONICAL: &str =
    "path COLLATE BINARY,start_byte,end_byte,node_kind COLLATE BINARY,id COLLATE BINARY";
pub fn next(db: &mut Connection, run: &str) -> Result<Option<Function>> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let snapshot = run_snapshot(&tx, run)?;
    // Claims persist until explicit completion/failure/recovery, including after restart.
    let id: Option<String> = tx
        .query_row(
            "SELECT function_id FROM dispatch_items WHERE run_id=? AND status='pending' ORDER BY ordinal LIMIT 1",
            [run],
            |r| r.get(0),
        )
        .optional()?;
    let Some(id) = id else {
        tx.commit()?;
        return Ok(None);
    };
    tx.execute("UPDATE dispatch_items SET status='claimed',attempt=attempt+1 WHERE run_id=? AND function_id=? AND status='pending'",params![run,id])?;
    event(&tx, run, &id, "claimed", &Value::Null)?;
    let f = store::get(&tx, &snapshot, &id)?;
    tx.commit()?;
    Ok(Some(f))
}
fn event(db: &Connection, run: &str, id: &str, kind: &str, details: &Value) -> Result<()> {
    db.execute("INSERT INTO dispatch_events(run_id,function_id,event,attempt,details_json) SELECT run_id,function_id,?,attempt,? FROM dispatch_items WHERE run_id=? AND function_id=?",params![kind,serde_json::to_string(details)?,run,id])?;
    Ok(())
}
pub fn complete(db: &mut Connection, run: &str, id: &str, result: Value) -> Result<Value> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let out = complete_in(&tx, run, id, result)?;
    tx.commit()?;
    Ok(out)
}
/// Completes a claimed item inside the caller's transaction, so its result commits together
/// with any records derived from it.
pub fn complete_in(tx: &Transaction, run: &str, id: &str, result: Value) -> Result<Value> {
    let (status, old): (String, Option<String>) = tx
        .query_row(
            "SELECT status,result_json FROM dispatch_items WHERE run_id=? AND function_id=?",
            params![run, id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .context("dispatch item not found")?;
    if status == "completed" {
        anyhow::ensure!(
            old.as_ref()
                .map(|s| serde_json::from_str::<Value>(s))
                .transpose()?
                == Some(result),
            "completion conflicts with stored result"
        );
        return Ok(json!({"status":"completed","idempotent":true}));
    }
    anyhow::ensure!(status == "claimed", "completion requires a claimed item");
    tx.execute("UPDATE dispatch_items SET status='completed',result_json=? WHERE run_id=? AND function_id=?",params![serde_json::to_string(&result)?,run,id])?;
    event(tx, run, id, "completed", &result)?;
    Ok(json!({"status":"completed","idempotent":false}))
}
pub fn fail(
    db: &mut Connection,
    run: &str,
    id: &str,
    code: &str,
    message: &str,
    retryable: bool,
) -> Result<Value> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let error = json!({"code":code,"message":message});
    let status = if retryable {
        "failed_retryable"
    } else {
        "failed_final"
    };
    let count=tx.execute("UPDATE dispatch_items SET status=?,error_json=? WHERE run_id=? AND function_id=? AND status='claimed'",params![status,serde_json::to_string(&error)?,run,id])?;
    anyhow::ensure!(count == 1, "failure requires a claimed item");
    event(&tx, run, id, status, &error)?;
    tx.commit()?;
    Ok(json!({"status":status}))
}
pub fn requeue(db: &mut Connection, run: &str, id: &str, recover: bool) -> Result<Value> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let required = if recover {
        "claimed"
    } else {
        "failed_retryable"
    };
    let count = tx.execute(
        "UPDATE dispatch_items SET status='pending' WHERE run_id=? AND function_id=? AND status=?",
        params![run, id, required],
    )?;
    anyhow::ensure!(count == 1, "item is not {required}");
    event(
        &tx,
        run,
        id,
        if recover {
            "recovered"
        } else {
            "retry_requested"
        },
        &Value::Null,
    )?;
    tx.commit()?;
    Ok(json!({"status":"pending"}))
}
/// Requeues every claimed item of a run, for use after the only worker has stopped.
pub fn recover_all(db: &mut Connection, run: &str) -> Result<Value> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    run_snapshot(&tx, run)?;
    let ids: Vec<String> = tx
        .prepare("SELECT function_id FROM dispatch_items WHERE run_id=? AND status='claimed' ORDER BY ordinal")?
        .query_map([run], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    for id in &ids {
        tx.execute(
            "UPDATE dispatch_items SET status='pending' WHERE run_id=? AND function_id=?",
            params![run, id],
        )?;
        event(&tx, run, id, "recovered", &Value::Null)?;
    }
    tx.commit()?;
    Ok(json!({"run_id":run,"recovered":ids.len()}))
}
/// Run status and per-state counts, without the item and event listings of [`status`].
pub fn summary(db: &Connection, run: &str) -> Result<Value> {
    let snapshot = run_snapshot(db, run)?;
    let mut q = db.prepare_cached(
        "SELECT status,count(*) FROM dispatch_items WHERE run_id=? GROUP BY status",
    )?;
    let counts: std::collections::BTreeMap<String, usize> = q
        .query_map([run], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    Ok(json!({"run_id":run,"snapshot_id":snapshot,"status":run_state(&counts),"counts":counts}))
}
fn run_state(counts: &std::collections::BTreeMap<String, usize>) -> &'static str {
    let finished = !counts.contains_key("pending")
        && !counts.contains_key("claimed")
        && !counts.contains_key("failed_retryable");
    if finished {
        "finished"
    } else {
        "active"
    }
}
pub fn status(db: &Connection, run: &str) -> Result<Value> {
    let snapshot = run_snapshot(db, run)?;
    let mut q=db.prepare("SELECT function_id,status,attempt,result_json,error_json FROM dispatch_items WHERE run_id=? ORDER BY function_id")?;
    let items = q
        .query_map([run], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, usize>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    let mut records = vec![];
    for (id, s, a, result, error) in items {
        *counts.entry(s.clone()).or_default() += 1;
        records.push(json!({"function_id":id,"status":s,"attempt":a,"result":result.map(|s|serde_json::from_str::<Value>(&s)).transpose()?,"error":error.map(|s|serde_json::from_str::<Value>(&s)).transpose()?}));
    }
    let mut q=db.prepare("SELECT function_id,event,attempt,details_json FROM dispatch_events WHERE run_id=? ORDER BY sequence")?;
    let events=q.query_map([run],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,usize>(2)?,r.get::<_,String>(3)?)))?.collect::<Result<Vec<_>,_>>()?.into_iter().map(|(id,e,a,d)|Ok(json!({"function_id":id,"event":e,"attempt":a,"details":serde_json::from_str::<Value>(&d)?}))).collect::<Result<Vec<_>>>()?;
    Ok(
        json!({"run_id":run,"snapshot_id":snapshot,"status":run_state(&counts),"counts":counts,"items":records,"events":events}),
    )
}
