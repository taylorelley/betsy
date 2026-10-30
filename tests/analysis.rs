use betsy::{
    analyze::{self, Config, Exec},
    contract,
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
        (969, 213 + 29, 10 + 14)
    );
    // The scorpius-cli copies stay byte for byte as recorded in PROVENANCE.md; BETSY's own
    // entries live in the betsy_ files.
    let provenance = include_str!("../data/weaknesses/PROVENANCE.md");
    for bytes in [
        &include_bytes!("../data/weaknesses/cwe_database.json")[..],
        include_bytes!("../data/weaknesses/reliability_weaknesses.json"),
        include_bytes!("../data/weaknesses/performance_weaknesses.json"),
    ] {
        let digest = hash(bytes);
        assert!(provenance.contains(&digest["sha256:".len()..]), "{digest}");
    }
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
    // BETSY-owned extensions: language-specific entries reach only their languages.
    assert!(has("python", "REL-226") && !has("javascript", "REL-226"));
    assert!(has("javascript", "REL-214") && has("tsx", "REL-214") && !has("python", "REL-214"));
    assert!(has("typescript", "REL-222") && has("tsx", "REL-222") && !has("javascript", "REL-222"));
    assert!(has("cpp", "REL-234") && !has("c", "REL-234"));
    assert!(has("rust", "REL-242") && !has("cpp", "REL-242"));
    assert!(has("cpp", "PERF-013") && has("rust", "PERF-013") && !has("python", "PERF-013"));
    assert!(has("javascript", "PERF-024") && !has("python", "PERF-024"));
    assert!(LANGUAGES.iter().all(|l| has(l, "PERF-022")));
}

#[test]
fn reliability_entries_hang_under_peer_cwes_and_only_children_are_spliced() {
    let c = weakness::catalog();
    let p = weakness::plan("c", &Selection::default()).unwrap();
    let rel = p.nodes.iter().filter(|n| n.id.starts_with("REL-"));
    let attached = rel.clone().filter(|n| n.parent.is_some()).count();
    assert!(attached > 100, "{attached} REL entries attached");
    for n in rel.filter(|n| n.parent.is_some()) {
        let parent = &p.nodes[n.parent.unwrap()].id;
        let peers: Vec<&str> = c
            .get(&n.id)
            .unwrap()
            .related_weaknesses
            .iter()
            .filter(|r| r.nature == "PeerOf")
            .map(|r| r.cwe_id.as_str())
            .collect();
        assert!(peers.contains(&parent.as_str()), "{} under {parent}", n.id);
    }
    for n in &p.nodes {
        let siblings = n.parent.map(|q| p.nodes[q].children.len());
        assert_eq!(n.spliced, siblings == Some(1), "{}", n.id);
        let expected = match n.parent {
            None => 1,
            Some(q) => p.nodes[q].wave + u32::from(!n.spliced),
        };
        assert_eq!(n.wave, expected, "{}", n.id);
    }
    assert!(p.depth() > 2 && p.first_wave() >= p.roots.len());
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
                .first_wave()
        })
        .sum();
    assert_eq!(
        none.questions.load(Ordering::SeqCst),
        roots,
        "only roots and their spliced chains asked"
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
fn max_rounds_asks_remaining_subtrees_at_once() {
    let (_t, mut db, m) = persisted();
    let mock = Arc::new(Mock::new(
        decide::mock::Script {
            rules: vec![],
            default: Some(0.9),
        },
        100,
    ));
    let config = Config::new(mock.as_ref(), Selection::default(), 0.5, 0.15, false)
        .unwrap()
        .with_max_rounds(Some(2))
        .unwrap();
    let run = analyze::create(&mut db, &m.snapshot_id, &config).unwrap()["run_id"]
        .as_str()
        .unwrap()
        .to_string();
    analyze::drain(&mut db, &run, mock.clone(), exec(4)).unwrap();
    let max_round: u32 = db
        .query_row(
            "SELECT MAX(round) FROM weakness_decisions WHERE run_id=?",
            [&run],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(max_round, 2);
    let planned: usize = m
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
        mock.questions.load(Ordering::SeqCst),
        planned,
        "all passed, all asked"
    );
    assert!(
        Config::new(mock.as_ref(), Selection::default(), 0.5, 0.15, false)
            .unwrap()
            .with_max_rounds(Some(0))
            .is_err()
    );
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

fn function() -> (Function, contract::Features) {
    let (_t, db, m) = persisted();
    let f = store::get(&db, &m.snapshot_id, &m.functions[0].id).unwrap();
    let x = contract::features(&db, &f).unwrap();
    (f, x)
}
fn questions() -> Vec<weakness::Question> {
    vec![
        weakness::question("CWE-89", &weakness::Role::Finding, "python"),
        weakness::question("REL-001", &weakness::Role::Finding, "python"),
    ]
}
#[test]
fn jev_and_openai_wire_shapes() {
    let (f, x) = function();
    let state = State {
        function: &f,
        features: &x,
    };
    let qs = questions();
    let refs: Vec<&weakness::Question> = qs.iter().collect();
    let r = decide::jev::request("jev-latest", &state, &refs, false, false);
    assert_eq!(r["model"], "jev-latest");
    assert_eq!(r["state"]["source"], json!(f.source));
    assert_eq!(r["state"]["features"], json!(x));
    let t = decide::jev::request("gliner2-decide", &state, &refs, true, false);
    assert_eq!(t["state"], json!(state.text()));
    assert_eq!(t["questions"], r["questions"]);
    let t = decide::jev::request("julia", &state, &refs, true, true);
    assert!(t["questions"]["CWE_89"].get("criteria").is_none());
    assert_eq!(
        t["questions"]["CWE_89"]["instructions"],
        r["questions"]["CWE_89"]["instructions"]
    );
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
    assert!(r["input"]
        .as_str()
        .unwrap()
        .contains(&format!("\nSize: {} lines, ", x.lines)));
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
    let (f, x) = function();
    let state = State {
        function: &f,
        features: &x,
    };
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

fn traits_run(
    db: &mut rusqlite::Connection,
    snapshot: &str,
    provider: Arc<dyn Provider>,
    traits: bool,
) -> String {
    let config = Config::new(provider.as_ref(), Selection::default(), 0.5, 0.15, false)
        .unwrap()
        .with_traits(traits);
    let run = analyze::create(db, snapshot, &config).unwrap()["run_id"]
        .as_str()
        .unwrap()
        .to_string();
    analyze::drain(db, &run, provider, exec(4)).unwrap();
    run
}
fn trait_rules(probability: f64) -> Vec<decide::mock::Rule> {
    weakness::traits()
        .traits
        .iter()
        .map(|t| decide::mock::Rule {
            weakness: format!("trait:{}", t.key),
            contains: None,
            probability,
        })
        .collect()
}

#[test]
fn trait_catalog_is_valid_against_grammars_and_catalog() {
    let t = weakness::traits();
    assert!(!t.traits.is_empty() && t.traits.len() <= 64);
    for tr in &t.traits {
        for (language, kinds) in &tr.present_if {
            let g = betsy::languages::grammar(language).unwrap();
            for k in kinds {
                assert_ne!(g.id_for_node_kind(k, true), 0, "{language} has no node {k}");
            }
        }
    }
    let p = weakness::plan("c", &Selection::default()).unwrap();
    for n in &p.nodes {
        if let Some(q) = n.parent {
            let tagged = t.requires.contains_key(&n.id);
            if !tagged {
                assert_eq!(n.requires, p.nodes[q].requires, "{} inherits", n.id);
            }
        }
        let union = n.children.iter().try_fold(n.requires, |acc, &c| {
            Some(acc.zip(p.nodes[c].reach).map(|(a, b)| a | b))
        });
        assert_eq!(Some(n.reach), union, "{} reach", n.id);
    }
    assert!(p.nodes.iter().any(|n| n.reach.is_some()));
    let flat = weakness::plan(
        "c",
        &Selection {
            only: vec!["CWE-787".into()],
            exclude: vec![],
        },
    )
    .unwrap();
    assert!(flat.nodes.iter().all(|n| n.requires.is_none()));
}

#[test]
fn parser_proves_trait_presence_only() {
    let t = weakness::traits();
    let bit = |k: &str| 1u64 << t.traits.iter().position(|x| x.key == k).unwrap();
    let c = weakness::proven_traits(
        "c",
        "int f(int *a, int n) { for (int i = 0; i < n; i++) a[i] = 0; return 0; }",
    );
    assert_ne!(c & bit("iteration"), 0);
    assert_ne!(c & bit("memory_buffers"), 0);
    assert_eq!(c & bit("switch"), 0);
    let py = weakness::proven_traits("python", "def f(xs):\n    # for x in xs\n    return 1\n");
    assert_eq!(py & bit("iteration"), 0, "comments prove nothing");
    assert_ne!(
        weakness::proven_traits("python", "def f(xs):\n    return [x for x in xs]\n")
            & bit("iteration"),
        0
    );
}

#[test]
fn traits_all_present_change_nothing_and_all_absent_prune() {
    let script = |p| decide::mock::Script {
        rules: trait_rules(p),
        default: None,
    };
    let weaknesses = |db: &rusqlite::Connection, run: &str| {
        decisions(db, run)
            .into_iter()
            .map(|(f, w, o, p)| (f, w, if o == "cache" { "provider".into() } else { o }, p))
            .collect::<Vec<_>>()
    };
    let (_a, mut da, m) = persisted();
    let plain = traits_run(
        &mut da,
        &m.snapshot_id,
        Arc::new(Mock::new(script(1.0), 100)),
        false,
    );
    let (_b, mut dbb, _) = persisted();
    let present = Arc::new(Mock::new(script(1.0), 100));
    let all = traits_run(&mut dbb, &m.snapshot_id, present.clone(), true);
    assert_eq!(weaknesses(&da, &plain), weaknesses(&dbb, &all));

    let (_c, mut dc, _) = persisted();
    let absent = Arc::new(Mock::new(script(0.0), 100));
    let none = traits_run(&mut dc, &m.snapshot_id, absent.clone(), true);
    assert!(absent.questions.load(Ordering::SeqCst) < present.questions.load(Ordering::SeqCst));
    let d = decisions(&dc, &none);
    assert!(d.iter().any(|x| x.2 == "trait"));
    let asked: std::collections::HashSet<String> = absent
        .log
        .lock()
        .unwrap()
        .iter()
        .map(|(_, w)| w.clone())
        .collect();
    assert!(
        !asked.contains("PERF-001"),
        "N+1 queries need a data store or network"
    );
    assert!(
        !asked.contains("CWE-662"),
        "synchronisation needs concurrency"
    );
    assert!(
        asked.contains("CWE-710"),
        "untagged categories are always asked"
    );
    let recall = analyze::recall(&dc, &none, &none).unwrap();
    assert_eq!(recall["recall"], 1.0);
}

#[test]
fn recall_attributes_missed_findings_to_traits() {
    let (_t, mut db, m) = persisted();
    let mut rules = trait_rules(0.0);
    rules.push(decide::mock::Rule {
        weakness: "CWE-362".into(),
        contains: None,
        probability: 0.9,
    });
    let base = traits_run(
        &mut db,
        &m.snapshot_id,
        Arc::new(Mock::new(
            decide::mock::Script {
                rules: rules.clone(),
                default: Some(0.9),
            },
            100,
        )),
        false,
    );
    let pruned = traits_run(
        &mut db,
        &m.snapshot_id,
        Arc::new(Mock::new(
            decide::mock::Script {
                rules,
                default: Some(0.9),
            },
            100,
        )),
        true,
    );
    let r = analyze::recall(&db, &base, &pruned).unwrap();
    assert!(r["recall"].as_f64().unwrap() < 1.0);
    assert!(r["missed_by_cause"]["trait"].as_u64().unwrap() > 0);
    assert_eq!(r["missed_by_cause"].as_object().unwrap().len(), 1);
    assert!(r["run"]["questions"].as_u64() < r["baseline"]["questions"].as_u64());
    let miss = r["missed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["weakness_id"] == "CWE-362")
        .unwrap();
    assert_eq!(
        miss["decided_at"], "CWE-662",
        "attributed to the pruned subtree root"
    );
}

#[test]
fn recall_attributes_spliced_subtrees_to_the_failing_ancestor() {
    let (_t, mut db, m) = persisted();
    let plan = weakness::plan("c", &Selection::default()).unwrap();
    // Splice CWE-664 -> CWE-118 -> CWE-119 into one round by excluding 118's siblings.
    let root = plan.nodes.iter().find(|n| n.id == "CWE-664").unwrap();
    let selection = Selection {
        only: vec![],
        exclude: root
            .children
            .iter()
            .map(|&i| plan.nodes[i].id.clone())
            .filter(|id| id != "CWE-118")
            .collect(),
    };
    let plan = weakness::plan("c", &selection).unwrap();
    for id in ["CWE-664", "CWE-118", "CWE-119"] {
        assert_eq!(plan.nodes.iter().find(|n| n.id == id).unwrap().wave, 1);
    }
    let provider = Arc::new(Mock::new(
        decide::mock::Script {
            rules: vec![decide::mock::Rule {
                weakness: "CWE-664".into(),
                contains: None,
                probability: 0.01,
            }],
            default: Some(0.9),
        },
        100,
    ));
    let mut config = Config::new(provider.as_ref(), selection, 0.5, 0.15, true).unwrap();
    let mut runs = vec![];
    for exhaustive in [true, false] {
        config.exhaustive = exhaustive;
        let run = analyze::create(&mut db, &m.snapshot_id, &config).unwrap()["run_id"]
            .as_str()
            .unwrap()
            .to_string();
        analyze::drain(&mut db, &run, provider.clone(), exec(4)).unwrap();
        runs.push(run);
    }
    let report = analyze::recall(&db, &runs[0], &runs[1]).unwrap();
    let function = m.functions.iter().find(|f| f.path == "example.c").unwrap();
    let miss = report["missed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["function_id"] == function.id && x["weakness_id"] == "CWE-787")
        .unwrap();
    assert_eq!(miss["cause"], "gated");
    assert_eq!(miss["decided_at"], "CWE-787");
    assert_eq!(
        miss["reason"],
        format!(
            "ancestor CWE-664 closed in round 1; subtree of {} not asked",
            plan.nodes
                .iter()
                .find(|n| n.id == "CWE-787")
                .unwrap()
                .subtree
        )
    );
}

#[test]
fn schema_v2_tables_migrate_to_v3_even_with_stale_version_metadata() {
    for old_version in [0, 1, 2] {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("old.sqlite");
        {
            let db = rusqlite::Connection::open(&path).unwrap();
            let v2 = include_str!("../src/schema.sql")
                .replace(",'trait'))", "))")
                .replace("user_version=3", &format!("user_version={old_version}"));
            db.execute_batch(&v2).unwrap();
            db.execute_batch("PRAGMA foreign_keys=OFF; INSERT INTO weakness_decisions VALUES('r','f','CWE-1','finding',2,'gated',0.1,'hash','original reason')").unwrap();
            assert!(db.execute("INSERT INTO weakness_decisions(run_id,function_id,weakness_id,role,round,origin) VALUES('r','f','CWE-2','finding',1,'trait')", []).is_err());
        }
        let db = store::open(&path).unwrap();
        let version: u32 = db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, 3);
        let foreign_keys: bool = db
            .pragma_query_value(None, "foreign_keys", |r| r.get(0))
            .unwrap();
        assert!(foreign_keys);
        let preserved: (u32, String, f64, String, String) = db
            .query_row("SELECT round,origin,probability,question_hash,reason FROM weakness_decisions WHERE run_id='r' AND function_id='f' AND weakness_id='CWE-1'", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
            .unwrap();
        assert_eq!(
            preserved,
            (
                2,
                "gated".into(),
                0.1,
                "hash".into(),
                "original reason".into()
            )
        );
        db.execute_batch("PRAGMA foreign_keys=OFF; INSERT INTO weakness_decisions(run_id,function_id,weakness_id,role,round,origin) VALUES('r','f','CWE-2','finding',1,'trait')").unwrap();
        let n: u32 = db
            .query_row("SELECT COUNT(*) FROM weakness_decisions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
        let indexed_table: String = db
            .query_row("SELECT tbl_name FROM sqlite_master WHERE type='index' AND name='weakness_findings'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(indexed_table, "weakness_decisions");
        drop(db);
        store::open(&path).unwrap();
    }
}

#[test]
fn legacy_databases_without_weakness_decisions_upgrade_to_v3() {
    for old_version in [0, 1] {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("legacy.sqlite");
        {
            let db = rusqlite::Connection::open(&path).unwrap();
            let inventory_schema = include_str!("../src/schema.sql")
                .split("CREATE TABLE IF NOT EXISTS analysis_runs")
                .next()
                .unwrap();
            db.execute_batch(inventory_schema).unwrap();
            db.pragma_update(None, "user_version", old_version).unwrap();
        }
        let db = store::open(&path).unwrap();
        let version: u32 = db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, 3);
        db.execute_batch("PRAGMA foreign_keys=OFF; INSERT INTO weakness_decisions(run_id,function_id,weakness_id,role,round,origin) VALUES('r','f','CWE-1','finding',1,'trait')").unwrap();
    }
}
