use betsy::{
    analyze::{self, Config, Exec},
    decide::{self, mock::Mock, Answer, Provider, ProviderError, State, Usage},
    dispatch,
    model::*,
    scan, store,
    weakness::{self, Selection},
};
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

const LANGUAGES: [&str; 7] = [
    "c",
    "cpp",
    "javascript",
    "typescript",
    "tsx",
    "python",
    "rust",
];

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
fn exec(concurrency: usize) -> Exec {
    Exec {
        concurrency,
        max_inflight: 16,
        retry_failed: false,
    }
}
fn run_with(
    db: &mut rusqlite::Connection,
    snapshot: &str,
    provider: Arc<dyn Provider>,
    exhaustive: bool,
    concurrency: usize,
) -> (String, Value) {
    let config = Config::new(
        provider.as_ref(),
        Selection::default(),
        0.5,
        0.15,
        exhaustive,
    )
    .unwrap();
    let run = analyze::create(db, snapshot, &config).unwrap()["run_id"]
        .as_str()
        .unwrap()
        .to_string();
    let out = analyze::drain(db, &run, provider, exec(concurrency)).unwrap();
    (run, out)
}
fn decisions(db: &rusqlite::Connection, run: &str) -> Vec<(String, String, String, Option<f64>)> {
    db.prepare("SELECT function_id,weakness_id,origin,probability FROM weakness_decisions WHERE run_id=? ORDER BY function_id,weakness_id")
        .unwrap()
        .query_map([run], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn catalogs_copied_intact_and_ids_normalize() {
    let c = weakness::catalog();
    let count = |cat: &str| c.entries.iter().filter(|w| w.catalog == cat).count();
    assert_eq!(
        (
            count("security"),
            count("reliability"),
            count("performance")
        ),
        (969, 213, 10)
    );
    assert_eq!(c.get("cwe_89").unwrap().id, "CWE-89");
    assert_eq!(c.get("89").unwrap().id, "CWE-89");
    assert_eq!(c.get("REL-1").unwrap().id, "REL-001");
    assert_eq!(c.get("perf 2").unwrap().id, "PERF-002");
    assert!(c.get("CWE-0").is_none() && c.get("nope").is_none());
    let metadata: Value =
        serde_json::from_str(include_str!("../data/weaknesses/cwe_metadata.json")).unwrap();
    assert_eq!(metadata["entry_count"], 969);
}

#[test]
fn plans_account_for_every_weakness_and_match_golden() {
    let total = weakness::catalog().entries.len();
    let golden: Value = serde_json::from_str(include_str!("expected/weakness_plans.json")).unwrap();
    for language in LANGUAGES {
        let p = weakness::plan(language, &Selection::default()).unwrap();
        assert_eq!(p.nodes.len() + p.skipped.len(), total, "{language}");
        for (i, n) in p.nodes.iter().enumerate() {
            if let Some(parent) = n.parent {
                assert!(p.nodes[parent].children.contains(&i));
            } else {
                assert!(p.roots.contains(&i));
            }
            if n.role == weakness::Role::Gate {
                assert!(!n.children.is_empty(), "useless gate {}", n.id);
            }
        }
        let sizes: usize = p.roots.iter().map(|&r| p.nodes[r].subtree).sum();
        assert_eq!(sizes, p.nodes.len(), "forest covers every node once");
        let g = &golden[language];
        assert_eq!(
            json!({"questions":p.nodes.len(),"findings":p.findings(),"roots":p.roots.len()}),
            *g,
            "{language}"
        );
    }
    let has = |l: &str, id: &str| {
        weakness::plan(l, &Selection::default())
            .unwrap()
            .nodes
            .iter()
            .any(|n| n.id == id)
    };
    assert!(has("c", "CWE-787") && !has("python", "CWE-787"));
    assert!(has("python", "CWE-89") && has("rust", "REL-001") && !has("c", "REL-001"));
    assert!(has("python", "PERF-001"));
}

#[test]
fn explicit_selection_is_flat_and_exclusive() {
    let sel = Selection {
        only: vec!["CWE-89,REL-1".into()],
        exclude: vec![],
    };
    let p = weakness::plan("rust", &sel).unwrap();
    let ids: Vec<&str> = p.nodes.iter().map(|n| n.id.as_str()).collect();
    assert_eq!(ids, ["CWE-89", "REL-001"]);
    assert_eq!(p.roots.len(), 2);
    assert!(weakness::plan(
        "rust",
        &Selection {
            only: vec!["CWE-999999".into()],
            exclude: vec![]
        }
    )
    .is_err());
}

#[test]
fn hierarchy_gates_children_of_negative_answers() {
    let (_t, mut db, m) = persisted();
    let none = Arc::new(Mock::new(
        decide::mock::Script {
            rules: vec![],
            default: Some(0.0),
        },
        100,
    ));
    let (run, out) = run_with(&mut db, &m.snapshot_id, none.clone(), false, 4);
    assert_eq!(out["counts"]["completed"], 37);
    let roots: usize = m
        .functions
        .iter()
        .map(|f| {
            weakness::plan(&f.language, &Selection::default())
                .unwrap()
                .roots
                .len()
        })
        .sum();
    assert_eq!(
        none.questions.load(Ordering::SeqCst),
        roots,
        "only roots asked"
    );
    let d = decisions(&db, &run);
    assert!(d.iter().any(|x| x.2 == "gated"));
    assert!(analyze::findings(&db, &run).unwrap()["findings"]
        .as_array()
        .unwrap()
        .is_empty());

    let (_t2, mut db2, m2) = persisted();
    let all = Arc::new(Mock::new(
        decide::mock::Script {
            rules: vec![],
            default: Some(0.0),
        },
        100,
    ));
    let (run2, _) = run_with(&mut db2, &m2.snapshot_id, all.clone(), true, 4);
    let planned: usize = m2
        .functions
        .iter()
        .map(|f| {
            weakness::plan(&f.language, &Selection::default())
                .unwrap()
                .nodes
                .len()
        })
        .sum();
    assert_eq!(
        all.questions.load(Ordering::SeqCst),
        planned,
        "exhaustive asks all"
    );
    assert!(decisions(&db2, &run2).iter().all(|x| x.2 == "provider"));
}

#[test]
fn positive_parent_opens_its_subtree_and_reports_findings() {
    let (_t, mut db, m) = persisted();
    // CWE-664 (Pillar) -> CWE-118 -> CWE-119 -> CWE-787 in CWE-1000.
    let rules = ["CWE-664", "CWE-118", "CWE-119", "CWE-787"]
        .iter()
        .map(|id| decide::mock::Rule {
            weakness: (*id).into(),
            contains: None,
            probability: 0.9,
        })
        .collect();
    let mock = Arc::new(Mock::new(
        decide::mock::Script {
            rules,
            default: Some(0.01),
        },
        100,
    ));
    let (run, _) = run_with(&mut db, &m.snapshot_id, mock, false, 2);
    let f = analyze::findings(&db, &run).unwrap();
    let found: Vec<(&str, &str)> = f["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["weakness_id"].as_str().unwrap(),
                x["path"].as_str().unwrap(),
            )
        })
        .collect();
    assert!(found.contains(&("CWE-787", "example.c")));
    assert!(
        !found.iter().any(|(w, _)| *w == "CWE-664"),
        "gates are not findings"
    );
    assert!(!found
        .iter()
        .any(|(w, p)| *w == "CWE-787" && p.ends_with(".py")));
}

#[test]
fn chunking_respects_provider_limit() {
    let (_t, mut db, m) = persisted();
    let mock = Arc::new(Mock::new(
        decide::mock::Script {
            rules: vec![],
            default: Some(0.5),
        },
        7,
    ));
    run_with(&mut db, &m.snapshot_id, mock.clone(), false, 3);
    assert_eq!(mock.largest_request.load(Ordering::SeqCst), 7);
}

#[test]
fn decision_cache_reuses_answers_across_runs_and_duplicates() {
    let (_t, mut db, m) = persisted();
    let mock = Arc::new(Mock::new(Default::default(), 100));
    let (r1, _) = run_with(&mut db, &m.snapshot_id, mock.clone(), false, 4);
    let asked = mock.questions.load(Ordering::SeqCst);
    let (r2, out) = run_with(&mut db, &m.snapshot_id, mock.clone(), false, 4);
    assert_eq!(
        mock.questions.load(Ordering::SeqCst),
        asked,
        "second run is free"
    );
    assert_eq!(out["usage"]["requests"], 0);
    let strip = |v: Vec<(String, String, String, Option<f64>)>| {
        v.into_iter()
            .map(|(f, w, o, p)| (f, w, if o == "cache" { "provider".into() } else { o }, p))
            .collect::<Vec<_>>()
    };
    assert_eq!(strip(decisions(&db, &r1)), strip(decisions(&db, &r2)));
}

#[test]
fn concurrency_does_not_change_decisions() {
    let script = || decide::mock::Script {
        rules: vec![],
        default: None,
    };
    let (_a, mut da, m) = persisted();
    let (ra, _) = run_with(
        &mut da,
        &m.snapshot_id,
        Arc::new(Mock::new(script(), 50)),
        false,
        1,
    );
    let (_b, mut dbb, _) = persisted();
    let (rb, _) = run_with(
        &mut dbb,
        &m.snapshot_id,
        Arc::new(Mock::new(script(), 50)),
        false,
        8,
    );
    assert_eq!(decisions(&da, &ra), decisions(&dbb, &rb));
    assert!(decisions(&da, &ra).iter().any(|x| x.2 == "gated"));
}

#[test]
fn interrupted_claims_stay_claimed_until_recovered() {
    let (_t, mut db, m) = persisted();
    let mock: Arc<dyn Provider> = Arc::new(Mock::new(Default::default(), 100));
    let config = Config::new(mock.as_ref(), Selection::default(), 0.5, 0.15, false).unwrap();
    let run = analyze::create(&mut db, &m.snapshot_id, &config).unwrap()["run_id"]
        .as_str()
        .unwrap()
        .to_string();
    let stranded = dispatch::next(&mut db, &run).unwrap().unwrap();
    let out = analyze::drain(&mut db, &run, mock.clone(), exec(4)).unwrap();
    assert_eq!(out["status"], "active");
    assert_eq!(out["counts"]["claimed"], 1);
    dispatch::requeue(&mut db, &run, &stranded.id, true).unwrap();
    let out = analyze::drain(&mut db, &run, mock.clone(), exec(4)).unwrap();
    assert_eq!(out["status"], "finished");
    assert_eq!(out["counts"]["completed"], 37);
    let other: Arc<dyn Provider> = Arc::new(Mock::new(
        decide::mock::Script {
            rules: vec![],
            default: Some(0.3),
        },
        100,
    ));
    assert!(analyze::drain(&mut db, &run, other, exec(1)).is_err());
}

struct Flaky {
    inner: Mock,
    fail: AtomicBool,
}
impl Provider for Flaky {
    fn config(&self) -> Value {
        self.inner.config()
    }
    fn max_questions(&self) -> usize {
        self.inner.max_questions()
    }
    fn decide(
        &self,
        s: &State,
        q: &[&weakness::Question],
    ) -> Result<(Vec<Answer>, Usage), ProviderError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(ProviderError {
                code: "provider_http",
                message: "HTTP 503".into(),
                retryable: true,
                split: false,
            });
        }
        self.inner.decide(s, q)
    }
}
#[test]
fn provider_failures_are_retryable_and_explicitly_retried() {
    let (_t, mut db, m) = persisted();
    let flaky = Arc::new(Flaky {
        inner: Mock::new(Default::default(), 100),
        fail: AtomicBool::new(true),
    });
    let (run, out) = run_with(&mut db, &m.snapshot_id, flaky.clone(), false, 4);
    assert_eq!(out["counts"]["failed_retryable"], 37);
    flaky.fail.store(false, Ordering::SeqCst);
    let out = analyze::drain(&mut db, &run, flaky.clone(), exec(4)).unwrap();
    assert_eq!(out["counts"]["failed_retryable"], 37, "no silent retry");
    let out = analyze::drain(
        &mut db,
        &run,
        flaky,
        Exec {
            retry_failed: true,
            ..exec(4)
        },
    )
    .unwrap();
    assert_eq!(out["status"], "finished");
}

fn function() -> Function {
    let (_t, db, m) = persisted();
    store::get(&db, &m.snapshot_id, &m.functions[0].id).unwrap()
}
fn questions() -> Vec<weakness::Question> {
    vec![
        weakness::question("CWE-89", &weakness::Role::Finding),
        weakness::question("REL-001", &weakness::Role::Finding),
    ]
}
#[test]
fn jev_and_openai_wire_shapes() {
    let f = function();
    let state = State { function: &f };
    let qs = questions();
    let refs: Vec<&weakness::Question> = qs.iter().collect();
    let r = decide::jev::request("jev-latest", &state, &refs);
    assert_eq!(r["model"], "jev-latest");
    assert_eq!(r["state"]["source"], json!(f.source));
    assert_eq!(r["questions"]["CWE_89"]["type"], "noul");
    assert!(r["questions"]["REL_001"]["criteria"]["true"].is_string());
    let resp = json!({"model":"jev-1.13.0","answers":{"CWE_89":{"type":"noul","noul":0.93},"REL_001":{"type":"noul","noul":0.01}},"usage":{"input_tokens":360,"output_tokens":39}});
    let (a, u) = decide::jev::parse(&resp, &refs).unwrap();
    assert_eq!(a, [Answer::Probability(0.93), Answer::Probability(0.01)]);
    assert_eq!(u.input_tokens, 360);
    assert!(decide::jev::parse(&json!({"answers":{}}), &refs).is_err());

    let r = decide::openai::request("gpt-6-luna", &state, &refs);
    assert_eq!(r["questions"][0]["type"], "predicate");
    assert_eq!(r["questions"][0]["name"], "CWE_89");
    assert!(r["input"]
        .as_str()
        .unwrap()
        .contains(f.source.as_deref().unwrap()));
    assert_eq!(r["prompt_cache_key"], json!(f.source_hash));
    let resp = json!({"answers":[{"type":"refusal","name":"REL_001"},{"type":"predicate","name":"CWE_89","probability":0.4}],"usage":{"input_tokens":2000,"input_tokens_details":{"cached_tokens":1500}}});
    let (a, u) = decide::openai::parse(&resp, &refs).unwrap();
    assert_eq!(a, [Answer::Probability(0.4), Answer::Refused]);
    assert_eq!(u.cached_tokens, 1500);
}

/// Serves canned HTTP responses in order and records request bodies.
fn stub(
    responses: Vec<(u16, &'static str, Value)>,
) -> (String, std::thread::JoinHandle<Vec<Value>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let h = std::thread::spawn(move || {
        let mut bodies = vec![];
        for (status, extra, body) in responses {
            let (mut s, _) = l.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut len = 0;
            let mut auth = false;
            loop {
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                let lower = line.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                auth |= lower.starts_with("authorization: bearer test-key");
                if line == "\r\n" {
                    break;
                }
            }
            assert!(auth, "bearer token sent");
            let mut buf = vec![0; len];
            r.read_exact(&mut buf).unwrap();
            bodies.push(serde_json::from_slice(&buf).unwrap());
            let text = body.to_string();
            write!(
                s,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{text}",
                text.len()
            )
            .unwrap();
        }
        bodies
    });
    (url, h)
}
#[test]
fn http_retries_rate_limits_and_splits_oversized_requests() {
    let f = function();
    let state = State { function: &f };
    let qs = questions();
    let refs: Vec<&weakness::Question> = qs.iter().collect();
    let ok = |names: &[&str]| {
        let answers: serde_json::Map<String, Value> = names
            .iter()
            .map(|n| ((*n).into(), json!({"type":"noul","noul":0.7})))
            .collect();
        json!({"answers":answers,"usage":{"input_tokens":10}})
    };
    let (url, h) = stub(vec![
        (429, "Retry-After: 0\r\n", json!({"error":"slow down"})),
        (422, "", json!({"detail":[]})),
        (200, "", ok(&["CWE_89"])),
        (200, "", ok(&["REL_001"])),
    ]);
    let jev = decide::jev::Jev::new(
        url,
        "jev-latest".into(),
        Some("test-key".into()),
        100,
        false,
        std::time::Duration::from_secs(10),
        2,
    );
    let (a, u) = decide::decide_splitting(&jev, &state, &refs).unwrap();
    assert_eq!(a, [Answer::Probability(0.7), Answer::Probability(0.7)]);
    assert_eq!(u.requests, 2);
    let bodies = h.join().unwrap();
    assert_eq!(bodies[0]["questions"].as_object().unwrap().len(), 2);
    assert_eq!(bodies[2]["questions"].as_object().unwrap().len(), 1);

    let (url, h) = stub(vec![(401, "", json!({"error":"bad key"}))]);
    let jev = decide::jev::Jev::new(
        url,
        "jev-latest".into(),
        Some("test-key".into()),
        100,
        false,
        std::time::Duration::from_secs(10),
        3,
    );
    let e = decide::decide_splitting(&jev, &state, &refs).unwrap_err();
    assert!(!e.retryable && !e.split);
    h.join().unwrap();
}
