use betsy::{dispatch, languages, model::*, scan, store};
use serde_json::{json, Value};
use std::{collections::BTreeSet, fs, path::Path};
fn fixtures() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}
fn inventory(root: &Path) -> (Manifest, Vec<FileSnapshot>) {
    scan::scan(
        root,
        Policy {
            respect_ignores: false,
            ..Policy::default()
        },
        false,
    )
    .unwrap()
}
fn persisted() -> (tempfile::TempDir, rusqlite::Connection, Manifest) {
    let t = tempfile::tempdir().unwrap();
    let mut db = store::open(&t.path().join("db.sqlite")).unwrap();
    let (m, f) = inventory(&fixtures());
    store::save(&mut db, &m, &f).unwrap();
    (t, db, m)
}
#[test]
fn starter_independent_oracle() {
    let (m, files) = inventory(&fixtures());
    assert!(m.source_complete, "{:?}", m.files);
    assert_eq!(m.functions.len(), 37);
    let oracle: Value =
        serde_json::from_str(include_str!("expected/expected_occurrences.json")).unwrap();
    let grammar_oracle: Value =
        serde_json::from_str(include_str!("expected/grammar_expectations.json")).unwrap();
    let counts: Value =
        serde_json::from_str(include_str!("expected/expected_counts.json")).unwrap();
    assert_eq!(m.functions.len() as u64, counts["total"].as_u64().unwrap());
    for (path, count) in counts["counts"].as_object().unwrap() {
        assert_eq!(
            m.functions.iter().filter(|f| &f.path == path).count() as u64,
            count.as_u64().unwrap()
        );
    }
    let mut labels = std::collections::BTreeMap::new();
    for expected in oracle["records"].as_array().unwrap() {
        let f = m
            .functions
            .iter()
            .find(|f| {
                f.path == expected["file"].as_str().unwrap()
                    && f.start_byte == expected["start_byte"].as_u64().unwrap() as usize
            })
            .unwrap_or_else(|| panic!("missing {}", expected["label"]));
        assert_eq!(f.end_byte, expected["end_byte"].as_u64().unwrap() as usize);
        assert_eq!(f.kind, expected["kind"]);
        let file = files.iter().find(|x| x.path == f.path).unwrap();
        assert_eq!(
            &file.bytes[f.start_byte..f.end_byte],
            expected["source"].as_str().unwrap().as_bytes()
        );
        let g = &grammar_oracle[expected["label"].as_str().unwrap()];
        assert_eq!(f.node_kind, g["node_kind"]);
        assert_eq!(f.source_hash, g["source_hash"]);
        labels.insert(expected["label"].as_str().unwrap(), f);
    }
    for expected in oracle["records"].as_array().unwrap() {
        let f = labels[expected["label"].as_str().unwrap()];
        let parent = expected["parent_label"]
            .as_str()
            .map(|p| labels[p].id.clone());
        assert_eq!(f.parent_id, parent);
    }
}
#[test]
fn grammar_contract() {
    for lang in [
        "javascript",
        "typescript",
        "tsx",
        "python",
        "rust",
        "c",
        "cpp",
    ] {
        let nodes: Value = serde_json::from_str(languages::node_types(lang)).unwrap();
        let a = languages::Adapter(lang.into());
        use languages::LanguageAdapter;
        for kind in a.candidate_types() {
            assert!(
                nodes
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|n| n["type"] == *kind && n["named"] == true),
                "missing {lang}/{kind}"
            );
        }
    }
}
#[test]
fn independent_extended_oracle() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/extended");
    let (m, files) = inventory(&root);
    assert!(m.source_complete, "{:?}", m.files);
    let expected: Value = serde_json::from_str(include_str!("expected/extended.json")).unwrap();
    let expected = expected.as_array().unwrap();
    assert_eq!(
        m.functions.len(),
        expected.len(),
        "{:?}",
        m.functions
            .iter()
            .map(|f| (&f.path, f.start_byte, f.end_byte, &f.kind))
            .collect::<Vec<_>>()
    );
    for e in expected {
        let matches = m
            .functions
            .iter()
            .filter(|f| {
                f.path == e["file"].as_str().unwrap()
                    && f.start_byte == e["start_byte"].as_u64().unwrap() as usize
            })
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "{e}");
        let f = matches[0];
        assert_eq!(f.end_byte, e["end_byte"].as_u64().unwrap() as usize, "{e}");
        assert_eq!(f.kind, e["kind"], "{e}");
        let b = &files.iter().find(|x| x.path == f.path).unwrap().bytes;
        assert_eq!(
            &b[f.start_byte..f.end_byte],
            e["source"].as_str().unwrap().as_bytes()
        );
    }
}
#[test]
fn reproducible_and_snapshot_fidelity() {
    let (t, db, m) = persisted();
    store::verify(&db, &m.snapshot_id).unwrap();
    for reverse in [false, true] {
        let copy = t.path().join(if reverse { "b" } else { "a" });
        fs::create_dir(&copy).unwrap();
        let mut entries = fs::read_dir(fixtures())
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        if reverse {
            entries.reverse();
        }
        for e in entries {
            fs::copy(e.path(), copy.join(e.file_name())).unwrap();
        }
        let (other, _) = inventory(&copy);
        assert_eq!(
            serde_json::to_value(&m).unwrap(),
            serde_json::to_value(other).unwrap()
        );
    }
    let temp = t.path().join("mutable");
    fs::create_dir(&temp).unwrap();
    fs::write(temp.join("f.py"), "def f(): return 1\n").unwrap();
    let (snap, files) = inventory(&temp);
    let mut db = store::open(&t.path().join("immutable.sqlite")).unwrap();
    store::save(&mut db, &snap, &files).unwrap();
    fs::write(temp.join("f.py"), "broken").unwrap();
    fs::remove_file(temp.join("f.py")).unwrap();
    let f = store::get(&db, &snap.snapshot_id, &snap.functions[0].id).unwrap();
    assert_eq!(f.source.as_deref(), Some("def f(): return 1"));
    store::verify(&db, &snap.snapshot_id).unwrap();
    assert!(db
        .execute("UPDATE functions SET name='changed'", [])
        .is_err());
    assert!(db.execute("DELETE FROM file_blobs", []).is_err());
}
#[test]
fn coverage_failures_and_limits() {
    for (name, bytes, status) in [
        ("invalid.js", b"function broken( {".as_slice(), "errors"),
        ("truncated.py", b"def broken(".as_slice(), "errors"),
        ("encoding.rs", b"\xff".as_slice(), "unsupported_encoding"),
    ] {
        let t = tempfile::tempdir().unwrap();
        fs::write(t.path().join(name), bytes).unwrap();
        let (m, _) = inventory(t.path());
        assert!(!m.sealed);
        assert!(!m.source_complete);
        assert_eq!(m.files[0].parse_status, status);
        let (partial, _) = scan::scan(
            t.path(),
            Policy {
                respect_ignores: false,
                ..Policy::default()
            },
            true,
        )
        .unwrap();
        assert!(partial.sealed);
        assert!(!partial.source_complete);
    }
    let t = tempfile::tempdir().unwrap();
    fs::write(t.path().join("huge.js"), "const f=()=>1;").unwrap();
    let (m, _) = scan::scan(
        t.path(),
        Policy {
            max_file_bytes: 5,
            ..Policy::default()
        },
        false,
    )
    .unwrap();
    assert_eq!(m.files[0].parse_status, "resource_limit");
    let (m, _) = scan::scan(
        t.path(),
        Policy {
            max_nodes: 1,
            ..Policy::default()
        },
        false,
    )
    .unwrap();
    assert_eq!(m.files[0].parse_status, "resource_limit");
    assert!(!m.sealed);
}
#[test]
fn exclusions_duplicates_empty_and_no_execution() {
    let t = tempfile::tempdir().unwrap();
    let (m, _) = inventory(t.path());
    assert!(m.source_complete);
    assert!(m.functions.is_empty());
    fs::write(t.path().join("a.js"), "const f=()=>1;").unwrap();
    fs::write(t.path().join("b.js"), "const f=()=>1;").unwrap();
    fs::write(t.path().join("empty.py"), "# no definitions\n").unwrap();
    fs::write(
        t.path().join("evil.py"),
        "open('SHOULD_NOT_EXIST','w').write('executed')\n",
    )
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/passwd", t.path().join("escape.py")).unwrap();
    let (m, _) = inventory(t.path());
    assert_eq!(m.functions.len(), 2);
    assert_eq!(m.functions[0].source_hash, m.functions[1].source_hash);
    assert_ne!(m.functions[0].id, m.functions[1].id);
    assert!(!t.path().join("SHOULD_NOT_EXIST").exists());
    #[cfg(unix)]
    assert!(m
        .exclusions
        .iter()
        .any(|e| e.reason == "symlink_not_followed"));
    fs::write(t.path().join(".gitignore"), "b.js\n").unwrap();
    let (m, _) = scan::scan(
        t.path(),
        Policy {
            excludes: vec!["evil.py".into()],
            ..Policy::default()
        },
        false,
    )
    .unwrap();
    assert_eq!(m.functions.len(), 1);
    assert!(m
        .exclusions
        .iter()
        .any(|e| e.path == "b.js" && e.reason == "ignored"));
}
#[test]
fn queue_persistence_retries_and_idempotence() {
    let (t, mut db, m) = persisted();
    let run = dispatch::create(&mut db, &m.snapshot_id, "dummy-v1").unwrap()["run_id"]
        .as_str()
        .unwrap()
        .to_string();
    let first = dispatch::next(&mut db, &run).unwrap().unwrap();
    assert_eq!(first.id, m.functions[0].id);
    drop(db);
    let mut db = store::open(&t.path().join("db.sqlite")).unwrap();
    assert_eq!(dispatch::status(&db, &run).unwrap()["counts"]["claimed"], 1);
    dispatch::requeue(&mut db, &run, &first.id, true).unwrap();
    let f = dispatch::next(&mut db, &run).unwrap().unwrap();
    assert_eq!(f.id, first.id);
    dispatch::fail(&mut db, &run, &f.id, "test", "retry fault", true).unwrap();
    dispatch::requeue(&mut db, &run, &f.id, false).unwrap();
    let f = dispatch::next(&mut db, &run).unwrap().unwrap();
    assert_eq!(f.id, first.id);
    dispatch::complete(&mut db, &run, &f.id, json!({"ok":true})).unwrap();
    assert_eq!(
        dispatch::complete(&mut db, &run, &f.id, json!({"ok":true})).unwrap()["idempotent"],
        true
    );
    assert!(dispatch::complete(&mut db, &run, &f.id, json!({"ok":false})).is_err());
    let mut ids = vec![f.id];
    while let Some(f) = dispatch::next(&mut db, &run).unwrap() {
        ids.push(f.id.clone());
        dispatch::complete(&mut db, &run, &f.id, json!({})).unwrap();
    }
    assert_eq!(
        ids,
        m.functions.iter().map(|f| f.id.clone()).collect::<Vec<_>>()
    );
    assert!(dispatch::next(&mut db, &run).unwrap().is_none());
    let status = dispatch::status(&db, &run).unwrap();
    assert_eq!(status["counts"]["completed"], 37);
    assert_eq!(
        status["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["function_id"] == first.id)
            .unwrap()["attempt"],
        3
    );
    assert!(status["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["event"] == "failed_retryable"));
}
#[test]
fn concurrent_claims_are_unique() {
    let (t, mut db, m) = persisted();
    let run = dispatch::create(&mut db, &m.snapshot_id, "concurrent").unwrap()["run_id"]
        .as_str()
        .unwrap()
        .to_string();
    let path = t.path().join("db.sqlite");
    let handles = (0..4)
        .map(|_| {
            let path = path.clone();
            let run = run.clone();
            std::thread::spawn(move || {
                let mut db = store::open(&path).unwrap();
                let mut ids = vec![];
                while let Some(f) = dispatch::next(&mut db, &run).unwrap() {
                    ids.push(f.id);
                }
                ids
            })
        })
        .collect::<Vec<_>>();
    let ids = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), 37);
    assert_eq!(ids.into_iter().collect::<BTreeSet<_>>().len(), 37);
}
#[test]
fn deterministic_range_properties() {
    for count in 0..32 {
        let t = tempfile::tempdir().unwrap();
        let source = (0..count)
            .map(|i| format!("function f{i}(){{return (x)=>()=>x+{i};}}\n"))
            .collect::<String>();
        fs::write(t.path().join("generated.js"), source.as_bytes()).unwrap();
        let (m, files) = inventory(t.path());
        assert!(m.source_complete);
        assert_eq!(m.functions.len(), count * 3);
        assert_eq!(
            m.functions
                .iter()
                .map(|f| &f.id)
                .collect::<BTreeSet<_>>()
                .len(),
            m.functions.len()
        );
        for f in &m.functions {
            assert!(f.end_byte <= files[0].bytes.len());
            assert_eq!(
                hash(&source.as_bytes()[f.start_byte..f.end_byte]),
                f.source_hash
            );
            if let Some(p) = &f.parent_id {
                let parent = m.functions.iter().find(|x| &x.id == p).unwrap();
                assert!(parent.start_byte <= f.start_byte && parent.end_byte >= f.end_byte);
            }
        }
    }
}
#[test]
fn cli_strict_failure_and_partial_persistence() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("repo");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("bad.js"), "function {").unwrap();
    let db = t.path().join("db.sqlite");
    let invoke = |partial: bool| {
        let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_funh"));
        c.arg("scan").arg(&root).arg("--db").arg(&db);
        if partial {
            c.arg("--allow-partial");
        }
        c.output().unwrap()
    };
    let strict = invoke(false);
    assert!(!strict.status.success());
    let report: Value = serde_json::from_slice(&strict.stdout).unwrap();
    assert_eq!(report["sealed"], false);
    let partial = invoke(true);
    assert!(partial.status.success());
    let report: Value = serde_json::from_slice(&partial.stdout).unwrap();
    assert_eq!(report["source_complete"], false);
    let db = store::open(&db).unwrap();
    store::verify(&db, report["snapshot_id"].as_str().unwrap()).unwrap();
}

#[test]
fn unreadable_source_is_a_gap() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("locked.py");
        fs::write(&path, "def f(): return 1\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o0)).unwrap();
        let (m, _) = inventory(t.path());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        // Root can read mode-000 files. This workspace runs as an ordinary user.
        if std::env::var("USER").as_deref() != Ok("root") {
            assert_eq!(m.files[0].parse_status, "io_error");
            assert!(!m.sealed);
        }
    }
}
#[test]
fn concurrent_file_edits_do_not_mix_parse_and_storage_buffers() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("f.js");
    fs::write(&path, "function first(){return 1;}\n").unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = stop.clone();
    let worker_path = path.clone();
    let writer = std::thread::spawn(move || {
        let mut i = 0;
        while !worker_stop.load(Ordering::SeqCst) {
            let tmp = worker_path.with_extension("tmp");
            fs::write(
                &tmp,
                if i % 2 == 0 {
                    "function first(){return 1;}\n"
                } else {
                    "function second(){return ()=>2;}\n"
                },
            )
            .unwrap();
            fs::rename(&tmp, &worker_path).unwrap();
            i += 1;
        }
    });
    for _ in 0..5 {
        let (m, files) = inventory(t.path());
        assert!(m.source_complete);
        let mut db = store::open(&t.path().join("db.sqlite")).unwrap();
        store::save(&mut db, &m, &files).unwrap();
        store::verify(&db, &m.snapshot_id).unwrap();
    }
    stop.store(true, Ordering::SeqCst);
    writer.join().unwrap();
}
#[test]
fn syntactic_flags_and_language_overrides() {
    let (m, _) = inventory(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/extended"));
    let by_name = |name: &str| {
        m.functions
            .iter()
            .find(|f| f.name.as_deref() == Some(name))
            .unwrap()
    };
    assert!(by_name("stream").flags.generator);
    assert!(by_name("stream").flags.r#async);
    assert!(by_name("public").flags.r#async);
    assert!(by_name("public").flags.exported);
    assert!(by_name("dangerous").flags.r#unsafe);
    assert!(by_name("gen").flags.generator);
    assert!(m
        .functions
        .iter()
        .any(|f| f.path == "edge.py" && f.flags.decorated));
    assert!(m
        .functions
        .iter()
        .any(|f| f.path == "edge.tsx" && f.flags.decorated));
    assert!(m.files.iter().any(|f| !f.macro_sites.is_empty()));
    let t = tempfile::tempdir().unwrap();
    fs::write(
        t.path().join("types.h"),
        "class C { int method(){return 1;} };\n",
    )
    .unwrap();
    let (m, _) = scan::scan(
        t.path(),
        Policy {
            overrides: std::collections::BTreeMap::from([("h".into(), "cpp".into())]),
            ..Policy::default()
        },
        false,
    )
    .unwrap();
    assert!(m.source_complete);
    assert_eq!(m.functions[0].language, "cpp");
    assert_eq!(m.functions[0].kind, "method");
}
#[test]
fn final_failure_and_completion_require_valid_state() {
    let (_t, mut db, m) = persisted();
    let run = dispatch::create(&mut db, &m.snapshot_id, "final-failure").unwrap()["run_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let id = &m.functions[0].id;
    assert!(dispatch::complete(&mut db, &run, id, json!({})).is_err());
    dispatch::next(&mut db, &run).unwrap();
    dispatch::fail(&mut db, &run, id, "permanent", "cannot process", false).unwrap();
    assert!(dispatch::requeue(&mut db, &run, id, false).is_err());
    assert!(dispatch::requeue(&mut db, &run, id, true).is_err());
    assert_eq!(
        dispatch::status(&db, &run).unwrap()["counts"]["failed_final"],
        1
    );
}

#[test]
fn version_metadata_matches_locked_grammars() {
    let lock = include_str!("../Cargo.lock");
    let versions = betsy::manifest::parser_versions();
    for (key, crate_name) in [
        ("tree-sitter", "tree-sitter"),
        ("javascript", "tree-sitter-javascript"),
        ("typescript", "tree-sitter-typescript"),
        ("tsx", "tree-sitter-typescript"),
        ("python", "tree-sitter-python"),
        ("rust", "tree-sitter-rust"),
        ("c", "tree-sitter-c"),
        ("cpp", "tree-sitter-cpp"),
    ] {
        let name = format!("name = \"{crate_name}\"");
        let package = lock
            .split("[[package]]")
            .find(|p| p.lines().any(|line| line == name))
            .unwrap();
        let expected = format!("version = \"{}\"", versions[key].as_str().unwrap());
        assert!(
            package.lines().any(|line| line == expected),
            "snapshot metadata must match locked {crate_name}"
        );
    }
}
#[cfg(unix)]
#[test]
fn ambiguous_unix_path_is_rejected() {
    let t = tempfile::tempdir().unwrap();
    fs::write(t.path().join("..\\escape.js"), "()=>1").unwrap();
    assert!(scan::scan(t.path(), Policy::default(), false).is_err());
}
