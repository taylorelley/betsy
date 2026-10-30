use betsy::{
    analyze::{self, Config},
    contract,
    decide::mock::Mock,
    dispatch,
    external::{self, Analyzer},
    model::*,
    scan, store,
    weakness::Selection,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::Path,
    time::{Duration, Instant},
};

fn persisted() -> (tempfile::TempDir, rusqlite::Connection, Manifest) {
    let t = tempfile::tempdir().unwrap();
    let mut db = store::open(&t.path().join("db.sqlite")).unwrap();
    let (m, f) = scan::scan(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"),
        Policy {
            respect_ignores: false,
            ..Policy::default()
        },
        false,
    )
    .unwrap();
    store::save(&mut db, &m, &f).unwrap();
    (t, db, m)
}
fn run(db: &mut rusqlite::Connection, m: &Manifest) -> String {
    dispatch::create(db, &m.snapshot_id, "external-test").unwrap()["run_id"]
        .as_str()
        .unwrap()
        .into()
}
fn sh(script: &str, timeout: Duration) -> Analyzer {
    Analyzer {
        program: "sh".into(),
        args: vec!["-c".into(), script.into()],
        timeout,
        profile: None,
    }
}
fn items(db: &rusqlite::Connection, run: &str) -> Vec<Value> {
    dispatch::status(db, run).unwrap()["items"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn features_count_every_nested_callable_and_match_records() {
    let (_t, db, m) = persisted();
    let parents: HashMap<&str, Option<&str>> = m
        .functions
        .iter()
        .map(|f| (f.id.as_str(), f.parent_id.as_deref()))
        .collect();
    fn depth<'a>(parents: &HashMap<&'a str, Option<&'a str>>, mut id: &'a str) -> usize {
        let mut d = 0;
        while let Some(Some(p)) = parents.get(id) {
            d += 1;
            id = p;
        }
        d
    }
    let (mut nested, mut ancestors) = (0, 0);
    for listed in &m.functions {
        ancestors += depth(&parents, &listed.id);
        let f = store::get(&db, &m.snapshot_id, &listed.id).unwrap();
        let x = contract::features(&db, &f).unwrap();
        assert_eq!(x.bytes, f.source.as_ref().unwrap().len());
        assert_eq!(x.lines, f.source.as_ref().unwrap().lines().count());
        nested += x.nested_callables;
        assert_eq!(x, contract::features(&db, &f).unwrap(), "deterministic");
    }
    assert!(nested > 0);
    assert_eq!(nested, ancestors);
}

#[test]
fn exec_sends_the_request_contract_and_completes_items() {
    let (_t, mut db, m) = persisted();
    let run = run(&mut db, &m);
    let mut a = sh("cat", Duration::from_secs(30));
    a.profile = Some("echo-v1".into());
    let out = external::drain(&mut db, &run, &a, Some(3)).unwrap();
    assert_eq!(out["this_invocation"], json!({"completed":3}));
    assert_eq!(out["counts"], json!({"completed":3,"pending":34}));
    for item in items(&db, &run)
        .iter()
        .filter(|i| i["status"] == "completed")
    {
        let id = item["function_id"].as_str().unwrap();
        let f = store::get(&db, &m.snapshot_id, id).unwrap();
        let want = contract::request(&db, &f, Some("echo-v1")).unwrap();
        assert_eq!(item["result"], json!(want));
        assert_eq!(item["result"]["schema_version"], contract::SCHEMA_VERSION);
        assert_eq!(item["result"]["source_complete"], true);
    }
    let out = external::drain(&mut db, &run, &a, None).unwrap();
    assert_eq!(out["status"], "finished");
    assert_eq!(out["counts"], json!({"completed":37}));
}

#[test]
fn exec_records_bad_output_exit_codes_and_timeouts() {
    let (_t, mut db, m) = persisted();
    let error = |db: &rusqlite::Connection, run: &str| {
        let i = items(db, run);
        let i = i.iter().find(|i| i["status"] != "pending").unwrap();
        (i["status"].clone(), i["error"].clone())
    };
    let r = run(&mut db, &m);
    let a = sh("cat >/dev/null; echo not json", Duration::from_secs(30));
    external::drain(&mut db, &r, &a, Some(1)).unwrap();
    let (status, e) = error(&db, &r);
    assert_eq!(
        (status, e["code"].clone()),
        (json!("failed_final"), json!("analyzer_output"))
    );

    let r = run(&mut db, &m);
    let a = sh("echo broken >&2; exit 3", Duration::from_secs(30));
    external::drain(&mut db, &r, &a, Some(1)).unwrap();
    let (status, e) = error(&db, &r);
    assert_eq!(
        (status, e["code"].clone()),
        (json!("failed_final"), json!("analyzer_exit"))
    );
    assert!(e["message"].as_str().unwrap().ends_with(": broken"));

    let r = run(&mut db, &m);
    let a = sh("sleep 10", Duration::from_millis(300));
    let start = Instant::now();
    external::drain(&mut db, &r, &a, Some(1)).unwrap();
    assert!(start.elapsed() < Duration::from_secs(5));
    let (status, e) = error(&db, &r);
    assert_eq!(
        (status, e["code"].clone()),
        (json!("failed_retryable"), json!("timeout"))
    );
}

#[test]
fn exec_requeues_the_claim_when_the_analyzer_cannot_start() {
    let (_t, mut db, m) = persisted();
    let r = run(&mut db, &m);
    let a = Analyzer {
        program: "/nonexistent/betsy-analyzer".into(),
        args: vec![],
        timeout: Duration::from_secs(5),
        profile: None,
    };
    let e = external::drain(&mut db, &r, &a, None).unwrap_err();
    assert!(e.to_string().contains("cannot start"));
    let s = dispatch::status(&db, &r).unwrap();
    assert_eq!(s["counts"], json!({"pending":37}));
    let events: Vec<&str> = s["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    assert_eq!(events, ["claimed", "recovered"]);
}

#[test]
fn exec_refuses_analysis_runs() {
    let (_t, mut db, m) = persisted();
    let config = Config::new(
        &Mock::new(Default::default(), 100),
        Selection::default(),
        0.5,
        0.15,
        false,
    )
    .unwrap();
    let created = analyze::create(&mut db, &m.snapshot_id, &config).unwrap();
    let r = created["run_id"].as_str().unwrap();
    let e = external::drain(&mut db, r, &sh("cat", Duration::from_secs(5)), None).unwrap_err();
    assert!(e.to_string().contains("betsy analyze"));
    assert_eq!(
        dispatch::status(&db, r).unwrap()["counts"],
        json!({"pending":37})
    );
}

#[test]
fn cli_exec_runs_the_program_without_a_shell() {
    let (t, mut db, m) = persisted();
    let r = run(&mut db, &m);
    drop(db);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_betsy"))
        .args(["run", "exec", "--db"])
        .arg(t.path().join("db.sqlite"))
        .args([
            "--run",
            &r,
            "--limit",
            "2",
            "--",
            "sh",
            "-c",
            "cat >/dev/null; echo '{\"ok\":true}'",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["this_invocation"], json!({"completed":2}));
}
