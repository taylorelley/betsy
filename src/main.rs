use anyhow::Result;
use betsy::{
    analyze,
    decide::{self, Provider},
    dispatch,
    model::Policy,
    report, scan, store,
    weakness::{self, Selection},
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
#[derive(Parser)]
#[command(
    name = "funh",
    version,
    about = "BETSY — Bug Evaluation Through Simple Yes/No: parser-only function inventory"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Args)]
struct Db {
    #[arg(long, default_value = ".funh/index.sqlite")]
    db: PathBuf,
}
#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Json,
    Jsonl,
}
#[derive(Args)]
struct Snapshot {
    #[command(flatten)]
    db: Db,
    #[arg(long)]
    snapshot: String,
    #[arg(long, value_enum, default_value = "json")]
    format: Format,
}
#[derive(Args)]
struct Run {
    #[command(flatten)]
    db: Db,
    #[arg(long)]
    run: String,
    #[arg(long, value_enum, default_value = "json")]
    format: Format,
}
#[derive(Args)]
struct SelectionArgs {
    /// Ask only these weakness IDs (repeatable or comma-separated); disables hierarchy gating.
    #[arg(long = "weakness")]
    only: Vec<String>,
    #[arg(long = "exclude-weakness")]
    exclude: Vec<String>,
}
impl SelectionArgs {
    fn selection(self) -> Selection {
        Selection {
            only: self.only,
            exclude: self.exclude,
        }
    }
}
#[derive(Clone, Copy, ValueEnum)]
enum ProviderKind {
    /// TypeSafe System One (`/v1/systemone`, Noul questions).
    Jev,
    /// OpenAI Decisions (`/v1/decisions`, predicate questions).
    Openai,
    /// Deterministic offline provider for tests.
    Mock,
}
#[derive(Args)]
struct ProviderArgs {
    #[arg(long, value_enum, default_value = "jev")]
    provider: ProviderKind,
    #[arg(long)]
    model: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
    /// Environment variable holding the API key (default JEV_API_KEY or OPENAI_API_KEY).
    #[arg(long)]
    api_key_env: Option<String>,
    /// Questions per request (default 100 for Jev, 400 for OpenAI).
    #[arg(long)]
    max_questions: Option<usize>,
    /// Send TypeSafe's long-context header for large functions.
    #[arg(long)]
    long_context: bool,
    #[arg(long, default_value_t = 120)]
    timeout_secs: u64,
    #[arg(long, default_value_t = 5)]
    max_retries: u32,
    /// JSON script for the mock provider: {"rules":[{"weakness","contains","probability"}],"default"}.
    #[arg(long)]
    mock_file: Option<PathBuf>,
}
impl ProviderArgs {
    fn build(self) -> Result<Arc<dyn Provider>> {
        let timeout = std::time::Duration::from_secs(self.timeout_secs);
        let key = |default: &str| -> Result<Option<String>> {
            let var = self.api_key_env.clone().unwrap_or_else(|| default.into());
            Ok(Some(std::env::var(&var).map_err(|_| {
                anyhow::anyhow!("API key environment variable {var} is not set")
            })?))
        };
        Ok(match self.provider {
            ProviderKind::Jev => Arc::new(decide::jev::Jev::new(
                self.base_url
                    .clone()
                    .unwrap_or_else(|| "https://api.typesafe.ai".into()),
                self.model.clone().unwrap_or_else(|| "jev-latest".into()),
                key("JEV_API_KEY")?,
                self.max_questions.unwrap_or(100),
                self.long_context,
                timeout,
                self.max_retries,
            )),
            ProviderKind::Openai => Arc::new(decide::openai::OpenAi::new(
                self.base_url
                    .clone()
                    .unwrap_or_else(|| "https://api.openai.com".into()),
                self.model.clone().unwrap_or_else(|| "gpt-6-luna".into()),
                key("OPENAI_API_KEY")?,
                self.max_questions.unwrap_or(decide::openai::MAX_QUESTIONS),
                timeout,
                self.max_retries,
            )),
            ProviderKind::Mock => {
                let script = match &self.mock_file {
                    Some(p) => serde_json::from_slice(&std::fs::read(p)?)?,
                    None => Default::default(),
                };
                Arc::new(decide::mock::Mock::new(
                    script,
                    self.max_questions.unwrap_or(100),
                ))
            }
        })
    }
}
#[derive(Subcommand)]
enum WeaknessCommand {
    /// List catalog entries, or a language's deterministic question plan.
    List {
        #[arg(long)]
        language: Option<String>,
        #[command(flatten)]
        selection: SelectionArgs,
    },
    /// Dry-run question and request budget for a snapshot; contacts no provider.
    Plan {
        #[command(flatten)]
        db: Db,
        #[arg(long)]
        snapshot: String,
        #[command(flatten)]
        selection: SelectionArgs,
        #[arg(long, default_value_t = 100)]
        max_questions: usize,
    },
}
#[derive(Subcommand)]
enum Command {
    Scan {
        root: PathBuf,
        #[command(flatten)]
        db: Db,
        #[arg(long, conflicts_with = "allow_partial")]
        strict: bool,
        #[arg(long)]
        allow_partial: bool,
        #[arg(long)]
        include: Vec<String>,
        #[arg(long)]
        exclude: Vec<String>,
        #[arg(long)]
        no_ignore: bool,
        #[arg(long, value_name = "EXT=LANGUAGE")]
        language: Vec<String>,
        #[arg(long,default_value_t=16*1024*1024)]
        max_file_bytes: u64,
        #[arg(long, default_value_t = 2_000_000)]
        max_nodes: usize,
    },
    List {
        #[command(flatten)]
        snapshot: Snapshot,
        #[arg(long)]
        source: bool,
    },
    Get {
        #[command(flatten)]
        snapshot: Snapshot,
        #[arg(long)]
        id: String,
    },
    Verify {
        #[command(flatten)]
        snapshot: Snapshot,
    },
    Run {
        #[command(subcommand)]
        command: RunCommand,
    },
    Weaknesses {
        #[command(subcommand)]
        command: WeaknessCommand,
    },
    /// Ask a decision model, one weakness per question, about every function in a snapshot.
    Analyze {
        #[command(flatten)]
        db: Db,
        /// Create a new run for this snapshot.
        #[arg(long, required_unless_present = "run", conflicts_with = "run")]
        snapshot: Option<String>,
        /// Resume an existing analysis run.
        #[arg(long)]
        run: Option<String>,
        #[command(flatten)]
        provider: ProviderArgs,
        #[command(flatten)]
        selection: SelectionArgs,
        /// Probability at or above which a weakness is reported.
        #[arg(long, default_value_t = 0.5)]
        threshold: f64,
        /// Children of a weakness are asked only when its probability reaches this value.
        #[arg(long, default_value_t = 0.15)]
        gate_threshold: f64,
        /// Ask every planned weakness, disabling hierarchical early exit.
        #[arg(long)]
        exhaustive: bool,
        /// Functions evaluated concurrently.
        #[arg(long, default_value_t = 8)]
        concurrency: usize,
        /// Provider requests in flight at once.
        #[arg(long, default_value_t = 32)]
        max_inflight: usize,
        /// Requeue retryable failures before draining.
        #[arg(long)]
        retry_failed: bool,
    },
}
#[derive(Subcommand)]
enum RunCommand {
    Create {
        #[command(flatten)]
        snapshot: Snapshot,
        #[arg(long)]
        analyzer: String,
    },
    Next {
        #[command(flatten)]
        run: Run,
    },
    Complete {
        #[command(flatten)]
        run: Run,
        #[arg(long)]
        id: String,
        #[arg(long)]
        result_file: PathBuf,
    },
    Fail {
        #[command(flatten)]
        run: Run,
        #[arg(long)]
        id: String,
        #[arg(long)]
        code: String,
        #[arg(long)]
        message: String,
        #[arg(long)]
        retryable: bool,
    },
    Retry {
        #[command(flatten)]
        run: Run,
        #[arg(long)]
        id: String,
    },
    Recover {
        #[command(flatten)]
        run: Run,
        #[arg(long)]
        id: String,
    },
    Status {
        #[command(flatten)]
        run: Run,
    },
    /// Above-threshold weakness decisions of an analysis run.
    Findings {
        #[command(flatten)]
        run: Run,
    },
}
fn output(v: &impl serde::Serialize) -> Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, v)?;
    writeln!(out)?;
    Ok(())
}
fn execute(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Scan {
            root,
            db,
            strict: _,
            allow_partial,
            include,
            exclude,
            no_ignore,
            language,
            max_file_bytes,
            max_nodes,
        } => {
            let mut policy = Policy {
                includes: include,
                excludes: exclude,
                respect_ignores: !no_ignore,
                max_file_bytes,
                max_nodes,
                ..Policy::default()
            };
            for s in language {
                let (ext, lang) = s
                    .split_once('=')
                    .ok_or_else(|| anyhow::anyhow!("language override requires EXT=LANGUAGE"))?;
                policy
                    .overrides
                    .insert(ext.trim_start_matches('.').into(), lang.into());
            }
            let mut db = store::open(&db.db)?;
            let (m, files) = scan::scan(&root, policy, allow_partial)?;
            if m.sealed {
                store::save(&mut db, &m, &files)?;
            }
            output(&report::summary(&m))?;
            anyhow::ensure!(m.sealed,"strict scan rejected: inspect coverage gaps; use --allow-partial to persist an incomplete snapshot");
        }
        Command::List { snapshot, source } => {
            let db = store::open(&snapshot.db.db)?;
            let mut m = store::load(&db, &snapshot.snapshot)?;
            if source {
                for f in &mut m.functions {
                    *f = store::get(&db, &snapshot.snapshot, &f.id)?;
                }
            }
            match snapshot.format {
                Format::Json => output(&m)?,
                Format::Jsonl => {
                    for f in m.functions {
                        output(&f)?;
                    }
                }
            }
        }
        Command::Get { snapshot, id } => {
            let db = store::open(&snapshot.db.db)?;
            output(&store::get(&db, &snapshot.snapshot, &id)?)?;
        }
        Command::Verify { snapshot } => {
            let db = store::open(&snapshot.db.db)?;
            output(&store::verify(&db, &snapshot.snapshot)?)?;
        }
        Command::Run { command } => match command {
            RunCommand::Create { snapshot, analyzer } => {
                let mut db = store::open(&snapshot.db.db)?;
                output(&dispatch::create(&mut db, &snapshot.snapshot, &analyzer)?)?;
            }
            RunCommand::Next { run } => {
                let mut db = store::open(&run.db.db)?;
                output(&dispatch::next(&mut db, &run.run)?)?;
            }
            RunCommand::Complete {
                run,
                id,
                result_file,
            } => {
                let result: Value = serde_json::from_slice(&std::fs::read(result_file)?)?;
                let mut db = store::open(&run.db.db)?;
                output(&dispatch::complete(&mut db, &run.run, &id, result)?)?;
            }
            RunCommand::Fail {
                run,
                id,
                code,
                message,
                retryable,
            } => {
                let mut db = store::open(&run.db.db)?;
                output(&dispatch::fail(
                    &mut db, &run.run, &id, &code, &message, retryable,
                )?)?;
            }
            RunCommand::Retry { run, id } => {
                let mut db = store::open(&run.db.db)?;
                output(&dispatch::requeue(&mut db, &run.run, &id, false)?)?;
            }
            RunCommand::Recover { run, id } => {
                let mut db = store::open(&run.db.db)?;
                output(&dispatch::requeue(&mut db, &run.run, &id, true)?)?;
            }
            RunCommand::Status { run } => {
                let db = store::open(&run.db.db)?;
                output(&dispatch::status(&db, &run.run)?)?;
            }
            RunCommand::Findings { run } => {
                let db = store::open(&run.db.db)?;
                let v = analyze::findings(&db, &run.run)?;
                match run.format {
                    Format::Json => output(&v)?,
                    Format::Jsonl => {
                        for f in v["findings"].as_array().into_iter().flatten() {
                            output(f)?;
                        }
                    }
                }
            }
        },
        Command::Weaknesses { command } => match command {
            WeaknessCommand::List {
                language,
                selection,
            } => match language {
                Some(language) => output(&weakness::plan(&language, &selection.selection())?)?,
                None => {
                    let c = weakness::catalog();
                    let entries: Vec<Value> = c
                        .entries
                        .iter()
                        .map(|w| json!({"id":w.id,"catalog":w.catalog,"name":w.name,"abstraction":w.abstraction}))
                        .collect();
                    output(&json!({"catalog_hash":c.hash,"count":entries.len(),"entries":entries}))?
                }
            },
            WeaknessCommand::Plan {
                db,
                snapshot,
                selection,
                max_questions,
            } => {
                let db = store::open(&db.db)?;
                output(&analyze::estimate(
                    &db,
                    &snapshot,
                    &selection.selection(),
                    max_questions,
                )?)?;
            }
        },
        Command::Analyze {
            db,
            snapshot,
            run,
            provider,
            selection,
            threshold,
            gate_threshold,
            exhaustive,
            concurrency,
            max_inflight,
            retry_failed,
        } => {
            let provider = provider.build()?;
            let mut db = store::open(&db.db)?;
            let run = match (snapshot, run) {
                (Some(snapshot), None) => {
                    let config = analyze::Config::new(
                        provider.as_ref(),
                        selection.selection(),
                        threshold,
                        gate_threshold,
                        exhaustive,
                    )?;
                    let created = analyze::create(&mut db, &snapshot, &config)?;
                    eprintln!("{created}");
                    created["run_id"].as_str().unwrap_or_default().to_string()
                }
                (None, Some(run)) => run,
                _ => anyhow::bail!("pass exactly one of --snapshot or --run"),
            };
            output(&analyze::drain(
                &mut db,
                &run,
                provider,
                analyze::Exec {
                    concurrency,
                    max_inflight,
                    retry_failed,
                },
            )?)?;
        }
    }
    Ok(())
}
fn main() {
    if let Err(e) = execute(Cli::parse()) {
        eprintln!("{}", json!({"error":format!("{e:#}")}));
        std::process::exit(1);
    }
}
