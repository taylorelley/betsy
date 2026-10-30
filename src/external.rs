//! Runs a local analyzer subprocess once per claimed function: the analyzer request JSON on
//! stdin, one JSON result on stdout. The program is run directly, never through a shell, and
//! nothing from the scanned repository is executed.
use crate::{contract, dispatch};
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Larger outputs fail the item rather than exhausting memory.
const MAX_OUTPUT: u64 = 16 * 1024 * 1024;

pub struct Analyzer {
    pub program: String,
    pub args: Vec<String>,
    pub timeout: Duration,
    pub profile: Option<String>,
}
/// Why one invocation failed; `retryable` follows the dispatcher's failure states.
#[derive(Debug)]
pub struct Failure {
    pub code: &'static str,
    pub message: String,
    pub retryable: bool,
}
fn failure(code: &'static str, message: String, retryable: bool) -> Failure {
    Failure {
        code,
        message,
        retryable,
    }
}

/// Code of a failure to start the analyzer at all; the item was never analyzed.
pub const SPAWN: &str = "analyzer_spawn";

/// Runs the analyzer once on one request.
pub fn invoke(a: &Analyzer, input: &[u8]) -> Result<Value, Failure> {
    let mut child = Command::new(&a.program)
        .args(&a.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| failure(SPAWN, format!("cannot start {:?}: {e}", a.program), true))?;
    let deadline = Instant::now() + a.timeout;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let input = input.to_vec();
    // An analyzer may exit without reading its input; the broken pipe is not an error.
    std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let (tx, rx) = mpsc::channel();
    let mut stdout = child.stdout.take().expect("piped stdout");
    let out_tx = tx.clone();
    std::thread::spawn(move || {
        let _ = out_tx.send((true, read_bounded(&mut stdout)));
    });
    let mut stderr = child.stderr.take().expect("piped stderr");
    std::thread::spawn(move || {
        let _ = tx.send((false, read_bounded(&mut stderr)));
    });
    let status = loop {
        if let Some(s) = child.try_wait().map_err(io)? {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(failure(
                "timeout",
                format!("analyzer exceeded {:?}", a.timeout),
                true,
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // Descendants that inherited the pipes could hold them open; never wait past the deadline.
    let (mut out, mut err) = (None, None);
    while out.is_none() || err.is_none() {
        let wait = deadline.saturating_duration_since(Instant::now());
        let Ok((is_out, r)) = rx.recv_timeout(wait) else {
            return Err(failure(
                "timeout",
                "analyzer output still open at the deadline".into(),
                true,
            ));
        };
        let bytes = r.map_err(io)?;
        *if is_out { &mut out } else { &mut err } = Some(bytes);
    }
    let (out, err) = (out.unwrap_or_default(), err.unwrap_or_default());
    if !status.success() {
        return Err(failure(
            "analyzer_exit",
            format!("analyzer {status}: {}", tail(&err)),
            false,
        ));
    }
    if out.len() as u64 > MAX_OUTPUT {
        return Err(failure(
            "analyzer_output",
            format!("analyzer output exceeds {MAX_OUTPUT} bytes"),
            false,
        ));
    }
    serde_json::from_slice(&out).map_err(|e| {
        failure(
            "analyzer_output",
            format!("analyzer stdout is not one JSON value: {e}"),
            false,
        )
    })
}
/// Keeps at most `MAX_OUTPUT + 1` bytes and discards the rest, so the writer never blocks.
fn read_bounded(r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![];
    r.take(MAX_OUTPUT + 1).read_to_end(&mut buf)?;
    std::io::copy(r, &mut std::io::sink())?;
    Ok(buf)
}
fn io(e: std::io::Error) -> Failure {
    failure("analyzer_io", e.to_string(), true)
}
/// The last 2000 characters of stderr, for the failure record.
fn tail(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let n = s.chars().count().saturating_sub(2000);
    s.chars().skip(n).collect::<String>().trim().to_string()
}

/// Claims and analyzes pending functions of `run` one at a time, up to `limit`.
pub fn drain(db: &mut Connection, run: &str, a: &Analyzer, limit: Option<usize>) -> Result<Value> {
    let owned: Option<i64> = db
        .query_row("SELECT 1 FROM analysis_runs WHERE run_id=?", [run], |r| {
            r.get(0)
        })
        .optional()?;
    anyhow::ensure!(
        owned.is_none(),
        "run belongs to `betsy analyze`; create a separate run for an external analyzer"
    );
    let mut totals = BTreeMap::<&str, u64>::new();
    while limit.is_none_or(|n| totals.values().sum::<u64>() < n as u64) {
        let Some(f) = dispatch::next(db, run)? else {
            break;
        };
        let request = contract::request(db, &f, a.profile.as_deref())?;
        match invoke(a, &serde_json::to_vec(&request)?) {
            Ok(result) => {
                dispatch::complete(db, run, &f.id, result)?;
                *totals.entry("completed").or_default() += 1;
            }
            Err(e) if e.code == SPAWN => {
                dispatch::requeue(db, run, &f.id, true)?;
                anyhow::bail!(e.message);
            }
            Err(e) => {
                dispatch::fail(db, run, &f.id, e.code, &e.message, e.retryable)?;
                *totals
                    .entry(if e.retryable {
                        "failed_retryable"
                    } else {
                        "failed_final"
                    })
                    .or_default() += 1;
            }
        }
    }
    let status = dispatch::status(db, run)?;
    Ok(
        json!({"run_id":run,"status":status["status"],"counts":status["counts"],"this_invocation":totals}),
    )
}
