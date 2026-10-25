//! Drives a dispatch run through a decision provider: one function at a time from the
//! queue, one independent yes/no question per weakness, batched per hierarchy round.
//! Model probabilities are stored apart from parser facts and are never treated as proof.
use crate::{
    decide::{decide_splitting, Answer, Provider, ProviderError, State, Usage},
    dispatch,
    model::{identity, Function},
    weakness::{self, Plan, Question, Role, Selection},
};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::{mpsc, Arc, Condvar, Mutex};

/// Everything that changes which questions are asked or how answers are judged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    pub provider: Value,
    pub profile: String,
    pub catalog_hash: String,
    pub selection: Selection,
    pub threshold: f64,
    pub gate_threshold: f64,
    pub exhaustive: bool,
}
impl Config {
    pub fn new(
        provider: &dyn Provider,
        selection: Selection,
        threshold: f64,
        gate_threshold: f64,
        exhaustive: bool,
    ) -> Result<Self> {
        anyhow::ensure!(
            (0.0..=1.0).contains(&threshold) && (0.0..=1.0).contains(&gate_threshold),
            "thresholds must be within [0, 1]"
        );
        weakness::resolve_ids(&selection.only)?;
        weakness::resolve_ids(&selection.exclude)?;
        Ok(Self {
            provider: provider.config(),
            profile: weakness::PROFILE.into(),
            catalog_hash: weakness::catalog().hash.clone(),
            selection,
            threshold,
            gate_threshold,
            exhaustive,
        })
    }
    fn provider_key(&self) -> String {
        identity(&self.provider)
    }
}
/// Throughput controls; these do not affect results, so they are not part of the run identity.
#[derive(Debug, Clone, Copy)]
pub struct Exec {
    /// Functions evaluated at once.
    pub concurrency: usize,
    /// Provider requests in flight across all functions.
    pub max_inflight: usize,
    pub retry_failed: bool,
}

/// A language's plan with its questions rendered once.
struct Prepared {
    plan: Plan,
    questions: Vec<Question>,
}
fn prepare(language: &str, selection: &Selection) -> Result<Arc<Prepared>> {
    let plan = weakness::plan(language, selection)?;
    let questions = plan
        .nodes
        .iter()
        .map(|n| weakness::question(&n.id, &n.role))
        .collect();
    Ok(Arc::new(Prepared { plan, questions }))
}

pub fn create(db: &mut Connection, snapshot: &str, config: &Config) -> Result<Value> {
    let analyzer = serde_json::to_string(config)?;
    let created = dispatch::create(db, snapshot, &analyzer)?;
    let run = created["run_id"].as_str().context("run id")?.to_string();
    let tx = db.transaction()?;
    tx.execute(
        "INSERT INTO analysis_runs(run_id,config_json) VALUES(?,?)",
        params![run, analyzer],
    )?;
    let mut q = tx.prepare(
        "SELECT DISTINCT language FROM files WHERE snapshot_id=? ORDER BY language COLLATE BINARY",
    )?;
    let languages = q
        .query_map([snapshot], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(q);
    let mut plans = BTreeMap::new();
    for language in languages {
        let plan = weakness::plan(&language, &config.selection)?;
        for s in &plan.skipped {
            tx.execute(
                "INSERT INTO weakness_plan(run_id,language,weakness_id,disposition,reason) VALUES(?,?,?,'skipped',?)",
                params![run, language, s.id, s.reason],
            )?;
        }
        for n in &plan.nodes {
            tx.execute(
                "INSERT INTO weakness_plan(run_id,language,weakness_id,disposition,reason) VALUES(?,?,?,?,NULL)",
                params![run, language, n.id, if n.role == Role::Gate { "gate" } else { "finding" }],
            )?;
        }
        plans.insert(
            language,
            json!({"questions":plan.nodes.len(),"findings":plan.findings(),"roots":plan.roots.len(),"skipped":plan.skipped.len()}),
        );
    }
    tx.commit()?;
    let mut out = created;
    out["plans"] = json!(plans);
    Ok(out)
}
pub fn load_config(db: &Connection, run: &str) -> Result<Config> {
    let s: String = db
        .query_row(
            "SELECT config_json FROM analysis_runs WHERE run_id=?",
            [run],
            |r| r.get(0),
        )
        .optional()?
        .context("run has no analysis configuration (not created by `funh analyze`)")?;
    Ok(serde_json::from_str(&s)?)
}

#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub weakness_id: String,
    pub role: Role,
    pub round: u32,
    /// `provider`, `cache`, `refused`, or `gated` (children of a negative gate, not asked).
    pub origin: &'static str,
    pub probability: Option<f64>,
    pub question_hash: Option<String>,
    pub reason: Option<String>,
}
pub struct Outcome {
    pub decisions: Vec<Decision>,
    pub fresh: Vec<(String, f64)>,
    pub usage: Usage,
    pub summary: Value,
}

struct Semaphore {
    permits: Mutex<usize>,
    cv: Condvar,
}
impl Semaphore {
    fn new(n: usize) -> Self {
        Self {
            permits: Mutex::new(n.max(1)),
            cv: Condvar::new(),
        }
    }
    fn with<T>(&self, f: impl FnOnce() -> T) -> T {
        let mut p = self.permits.lock().expect("semaphore");
        while *p == 0 {
            p = self.cv.wait(p).expect("semaphore");
        }
        *p -= 1;
        drop(p);
        let out = f();
        *self.permits.lock().expect("semaphore") += 1;
        self.cv.notify_one();
        out
    }
}

type Batch = Result<(Vec<Answer>, Usage), ProviderError>;
/// Asks the uncached questions of one round. The first chunk goes alone so it can write the
/// provider's prefix cache for this function; the remaining chunks then run concurrently.
fn ask_round(
    provider: &dyn Provider,
    state: &State,
    questions: &[&Question],
    sem: &Semaphore,
) -> Batch {
    let size = provider.max_questions().max(1);
    let chunks: Vec<&[&Question]> = questions.chunks(size).collect();
    let Some((first, rest)) = chunks.split_first() else {
        return Ok((vec![], Usage::default()));
    };
    let (mut answers, mut usage) = sem.with(|| decide_splitting(provider, state, first))?;
    let results: Vec<Batch> = std::thread::scope(|s| {
        let handles: Vec<_> = rest
            .iter()
            .map(|c| s.spawn(|| sem.with(|| decide_splitting(provider, state, c))))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("provider thread"))
            .collect()
    });
    for r in results {
        let (a, u) = r?;
        answers.extend(a);
        usage.add(&u);
    }
    Ok((answers, usage))
}

fn evaluate(
    provider: &dyn Provider,
    prepared: &Prepared,
    function: &Function,
    cached: &HashMap<String, f64>,
    config: &Config,
    sem: &Semaphore,
) -> Result<Outcome, ProviderError> {
    let plan = &prepared.plan;
    let state = State { function };
    let mut frontier = plan.roots.clone();
    let mut decisions = vec![];
    let mut fresh = vec![];
    let mut usage = Usage::default();
    let (mut asked, mut from_cache, mut gated_subtrees, mut gated_total) = (0, 0, 0, 0);
    let mut round = 0;
    while !frontier.is_empty() {
        round += 1;
        let mut answers: HashMap<usize, (Answer, &'static str)> = HashMap::new();
        let mut pending = vec![];
        for &i in &frontier {
            match cached.get(&prepared.questions[i].hash) {
                Some(&p) => {
                    answers.insert(i, (Answer::Probability(p), "cache"));
                    from_cache += 1;
                }
                None => pending.push(i),
            }
        }
        let qs: Vec<&Question> = pending.iter().map(|&i| &prepared.questions[i]).collect();
        let (got, u) = ask_round(provider, &state, &qs, sem)?;
        usage.add(&u);
        asked += pending.len();
        for (&i, a) in pending.iter().zip(got) {
            if let Answer::Probability(p) = a {
                fresh.push((prepared.questions[i].hash.clone(), p));
            }
            answers.insert(i, (a, "provider"));
        }
        let mut next = vec![];
        for &i in &frontier {
            let node = &plan.nodes[i];
            let (answer, origin) = answers[&i];
            let probability = match answer {
                Answer::Probability(p) => Some(p),
                Answer::Refused => None,
            };
            decisions.push(Decision {
                weakness_id: node.id.clone(),
                role: node.role.clone(),
                round,
                origin: if probability.is_none() {
                    "refused"
                } else {
                    origin
                },
                probability,
                question_hash: Some(prepared.questions[i].hash.clone()),
                reason: None,
            });
            // A refusal descends: missing a weakness is worse than an extra question.
            if config.exhaustive || probability.is_none_or(|p| p >= config.gate_threshold) {
                next.extend(&node.children);
            } else {
                for &c in &node.children {
                    gated_subtrees += 1;
                    gated_total += plan.nodes[c].subtree;
                    decisions.push(Decision {
                        weakness_id: plan.nodes[c].id.clone(),
                        role: plan.nodes[c].role.clone(),
                        round: round + 1,
                        origin: "gated",
                        probability: None,
                        question_hash: None,
                        reason: Some(format!(
                            "parent {} p={:.4} < gate {}; subtree of {} not asked",
                            node.id,
                            probability.unwrap_or_default(),
                            config.gate_threshold,
                            plan.nodes[c].subtree
                        )),
                    });
                }
            }
        }
        frontier = next;
    }
    let mut positives: Vec<&Decision> = decisions
        .iter()
        .filter(|d| d.role == Role::Finding && d.probability.is_some_and(|p| p >= config.threshold))
        .collect();
    positives.sort_by(|a, b| {
        b.probability
            .partial_cmp(&a.probability)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.weakness_id.cmp(&b.weakness_id))
    });
    let summary = json!({
        "profile": plan.profile,
        "provider": config.provider,
        "planned": plan.nodes.len(),
        "asked": asked,
        "cached": from_cache,
        "gated_subtrees": gated_subtrees,
        "gated_weaknesses": gated_total,
        "rounds": round,
        "usage": usage,
        "positives": positives.iter().map(|d| json!({"weakness_id":d.weakness_id,"probability":d.probability})).collect::<Vec<_>>(),
    });
    Ok(Outcome {
        decisions,
        fresh,
        usage,
        summary,
    })
}

fn cached(db: &Connection, config: &Config, f: &Function) -> Result<HashMap<String, f64>> {
    let mut q = db.prepare_cached(
        "SELECT question_hash,probability FROM decision_cache WHERE provider_key=? AND language=? AND source_hash=?",
    )?;
    let rows = q
        .query_map(
            params![config.provider_key(), f.language, f.source_hash],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}
fn persist(
    db: &mut Connection,
    run: &str,
    config: &Config,
    f: &Function,
    outcome: &Outcome,
) -> Result<()> {
    let tx = db.transaction()?;
    for d in &outcome.decisions {
        tx.execute(
            "INSERT OR REPLACE INTO weakness_decisions(run_id,function_id,weakness_id,role,round,origin,probability,question_hash,reason) VALUES(?,?,?,?,?,?,?,?,?)",
            params![run, f.id, d.weakness_id, if d.role == Role::Gate { "gate" } else { "finding" }, d.round, d.origin, d.probability, d.question_hash, d.reason],
        )?;
    }
    let key = config.provider_key();
    for (h, p) in &outcome.fresh {
        tx.execute(
            "INSERT OR IGNORE INTO decision_cache(provider_key,language,source_hash,question_hash,probability) VALUES(?,?,?,?,?)",
            params![key, f.language, f.source_hash, h, p],
        )?;
    }
    tx.commit()?;
    Ok(())
}

struct Job {
    function: Function,
    prepared: Arc<Prepared>,
    cached: HashMap<String, f64>,
}

/// Claims and evaluates every pending function of `run`, then returns run counts.
pub fn drain(
    db: &mut Connection,
    run: &str,
    provider: Arc<dyn Provider>,
    exec: Exec,
) -> Result<Value> {
    let config = load_config(db, run)?;
    anyhow::ensure!(
        config.provider == provider.config(),
        "provider configuration differs from the run's; create a new run"
    );
    if exec.retry_failed {
        let ids: Vec<String> = db
            .prepare("SELECT function_id FROM dispatch_items WHERE run_id=? AND status='failed_retryable'")?
            .query_map([run], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        for id in ids {
            dispatch::requeue(db, run, &id, false)?;
        }
    }
    let sem = Semaphore::new(exec.max_inflight);
    let concurrency = exec.concurrency.max(1);
    let (job_tx, job_rx) = mpsc::channel::<Job>();
    let job_rx = Mutex::new(job_rx);
    let (res_tx, res_rx) = mpsc::channel::<(Function, Result<Outcome, ProviderError>)>();
    let mut totals = BTreeMap::<&str, u64>::new();
    let mut usage = Usage::default();
    std::thread::scope(|s| -> Result<()> {
        for _ in 0..concurrency {
            let (rx, tx, provider, config, sem) =
                (&job_rx, res_tx.clone(), &provider, &config, &sem);
            s.spawn(move || loop {
                let job = rx.lock().expect("job queue").recv();
                let Ok(job) = job else { break };
                let r = evaluate(
                    provider.as_ref(),
                    &job.prepared,
                    &job.function,
                    &job.cached,
                    config,
                    sem,
                );
                if tx.send((job.function, r)).is_err() {
                    break;
                }
            });
        }
        drop(res_tx);
        let mut coordinate = || -> Result<()> {
            let mut plans: HashMap<String, Arc<Prepared>> = HashMap::new();
            let (mut inflight, mut exhausted) = (0usize, false);
            loop {
                while !exhausted && inflight < concurrency {
                    match dispatch::next(db, run)? {
                        Some(function) => {
                            let prepared = match plans.get(&function.language) {
                                Some(p) => p.clone(),
                                None => {
                                    let p = prepare(&function.language, &config.selection)?;
                                    plans.insert(function.language.clone(), p.clone());
                                    p
                                }
                            };
                            let cached = cached(db, &config, &function)?;
                            job_tx
                                .send(Job {
                                    function,
                                    prepared,
                                    cached,
                                })
                                .map_err(|_| anyhow::anyhow!("worker pool stopped"))?;
                            inflight += 1;
                        }
                        None => exhausted = true,
                    }
                }
                if inflight == 0 {
                    return Ok(());
                }
                let (function, result) = res_rx.recv().context("worker pool stopped")?;
                inflight -= 1;
                match result {
                    Ok(outcome) => {
                        persist(db, run, &config, &function, &outcome)?;
                        usage.add(&outcome.usage);
                        *totals.entry("completed").or_default() += 1;
                        *totals.entry("positives").or_default() += outcome.summary["positives"]
                            .as_array()
                            .map_or(0, |a| a.len())
                            as u64;
                        dispatch::complete(db, run, &function.id, outcome.summary)?;
                    }
                    Err(e) => {
                        *totals.entry("failed").or_default() += 1;
                        dispatch::fail(db, run, &function.id, e.code, &e.message, e.retryable)?;
                    }
                }
            }
        };
        let r = coordinate();
        drop(job_tx);
        r
    })?;
    let status = dispatch::status(db, run)?;
    Ok(
        json!({"run_id":run,"status":status["status"],"counts":status["counts"],"this_invocation":totals,"usage":usage}),
    )
}
/// Above-threshold findings for a run, strongest first.
pub fn findings(db: &Connection, run: &str) -> Result<Value> {
    let config = load_config(db, run)?;
    let mut q = db.prepare(
        "SELECT d.function_id,d.weakness_id,d.probability,d.origin,f.path,f.kind,f.name,f.qualified_name,f.record_json FROM weakness_decisions d JOIN functions f ON f.id=d.function_id WHERE d.run_id=? AND d.role='finding' AND d.probability>=? ORDER BY d.probability DESC,f.path COLLATE BINARY,f.start_byte,d.weakness_id",
    )?;
    let rows = q
        .query_map(params![run, config.threshold], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, f64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, String>(8)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let cat = weakness::catalog();
    let mut out = vec![];
    for (fid, wid, p, origin, path, kind, name, qname, record) in rows {
        let rec: Value = serde_json::from_str(&record)?;
        let w = cat.get(&wid);
        out.push(json!({"function_id":fid,"path":path,"start_line":rec["start_line"],"end_line":rec["end_line"],"kind":kind,"name":name,"qualified_name":qname,"weakness_id":wid,"weakness_name":w.map(|w|&w.name),"catalog":w.map(|w|&w.catalog),"probability":p,"origin":origin}));
    }
    Ok(json!({"run_id":run,"threshold":config.threshold,"findings":out}))
}

/// Dry-run question budget for a snapshot, without contacting any provider.
pub fn estimate(
    db: &Connection,
    snapshot: &str,
    selection: &Selection,
    max_questions: usize,
) -> Result<Value> {
    let m = crate::store::load(db, snapshot)?;
    let mut by_language = BTreeMap::<String, usize>::new();
    for f in &m.functions {
        *by_language.entry(f.language.clone()).or_default() += 1;
    }
    let total = weakness::catalog().entries.len();
    let per = max_questions.max(1);
    let mut languages = vec![];
    let (mut naive, mut exhaustive, mut first_round) = (0usize, 0usize, 0usize);
    for (language, functions) in by_language {
        let plan = weakness::plan(&language, selection)?;
        naive += functions * total;
        exhaustive += functions * plan.nodes.len();
        first_round += functions * plan.roots.len();
        languages.push(json!({
            "language": language,
            "functions": functions,
            "catalog_weaknesses": total,
            "skipped": plan.skipped.len(),
            "planned_questions": plan.nodes.len(),
            "findings": plan.findings(),
            "gates": plan.nodes.len() - plan.findings(),
            "round1_questions": plan.roots.len(),
            "exhaustive_requests_per_function": plan.nodes.len().div_ceil(per),
            "round1_requests_per_function": plan.roots.len().div_ceil(per),
        }));
    }
    Ok(json!({
        "snapshot_id": snapshot,
        "profile": weakness::PROFILE,
        "max_questions_per_request": per,
        "questions": {"naive_all_weaknesses": naive, "after_prefilter_exhaustive": exhaustive, "hierarchical_lower_bound": first_round},
        "languages": languages,
    }))
}
