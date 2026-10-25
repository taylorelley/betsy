use anyhow::Result;
use betsy::{dispatch, model::Policy, report, scan, store};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};
use std::path::PathBuf;
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
        },
    }
    Ok(())
}
fn main() {
    if let Err(e) = execute(Cli::parse()) {
        eprintln!("{}", json!({"error":format!("{e:#}")}));
        std::process::exit(1);
    }
}
