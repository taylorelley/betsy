use crate::{languages, manifest, model::*, parse};
use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use std::{collections::BTreeMap, fs, io::Read, path::Path};

impl Default for Policy {
    fn default() -> Self {
        Self {
            includes: vec![],
            excludes: vec![],
            respect_ignores: true,
            overrides: BTreeMap::new(),
            max_file_bytes: 16 * 1024 * 1024,
            max_nodes: 2_000_000,
        }
    }
}
fn globs(patterns: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        b.add(Glob::new(p)?);
    }
    Ok(b.build()?)
}
pub fn scan(
    root: &Path,
    policy: Policy,
    allow_partial: bool,
) -> Result<(Manifest, Vec<FileSnapshot>)> {
    anyhow::ensure!(root.is_dir(), "scan root must be a directory");
    let root = root.canonicalize()?;
    let includes = globs(&policy.includes)?;
    let excludes = globs(&policy.excludes)?;
    for lang in policy.overrides.values() {
        languages::grammar(lang)?;
    }
    let mut files = vec![];
    let mut functions = vec![];
    let mut exclusions = vec![];
    // Enumerate ignored entries too, so exclusions remain visible. A separate ignore walker
    // computes inclusion using the mature ignore crate's gitignore semantics.
    let mut accepted = std::collections::BTreeSet::new();
    if policy.respect_ignores {
        for e in WalkBuilder::new(&root)
            .hidden(false)
            .require_git(false)
            .follow_links(false)
            .build()
        {
            match e {
                Ok(e) => {
                    accepted.insert(e.path().to_path_buf());
                }
                Err(e) => anyhow::bail!("ignore traversal failed: {e}"),
            }
        }
    }
    for entry in WalkBuilder::new(&root)
        .standard_filters(false)
        .follow_links(false)
        .sort_by_file_path(|a, b| a.cmp(b))
        .build()
    {
        let e = entry.context("file traversal failed")?;
        if e.path() == root {
            continue;
        }
        let rel = e.path().strip_prefix(&root)?;
        let raw = rel
            .to_str()
            .context("non-UTF-8 path cannot be normalized")?;
        #[cfg(unix)]
        anyhow::ensure!(
            !raw.contains('\\'),
            "backslash in Unix path cannot be normalized safely: {raw}"
        );
        let path = raw.replace('\\', "/");
        anyhow::ensure!(
            !rel.components()
                .any(|c| !matches!(c, std::path::Component::Normal(_))),
            "unsafe path"
        );
        let ty = e.file_type().context("unknown file type")?;
        if ty.is_symlink() {
            exclusions.push(Exclusion {
                path,
                reason: "symlink_not_followed".into(),
            });
            continue;
        }
        if ty.is_dir() {
            continue;
        }
        let ext = e.path().extension().and_then(|s| s.to_str()).unwrap_or("");
        let lang = policy
            .overrides
            .get(ext)
            .map(String::as_str)
            .or_else(|| languages::for_extension(ext));
        let reason = if excludes.is_match(rel) {
            Some("exclude_glob")
        } else if !policy.includes.is_empty() && !includes.is_match(rel) {
            Some("outside_include_globs")
        } else if policy.respect_ignores && !accepted.contains(e.path()) {
            Some("ignored")
        } else if lang.is_none() {
            Some("unsupported_extension")
        } else {
            None
        };
        if let Some(reason) = reason {
            exclusions.push(Exclusion {
                path,
                reason: reason.into(),
            });
            continue;
        }
        let lang = lang.unwrap();
        let mut coverage = Coverage::new(&path, lang);
        let mut bytes = vec![];
        match fs::File::open(e.path()).and_then(|f| {
            f.take(policy.max_file_bytes.saturating_add(1))
                .read_to_end(&mut bytes)
        }) {
            Err(err) => coverage.fail("io_error", err.to_string(), 0),
            Ok(_) => {
                if bytes.len() as u64 > policy.max_file_bytes {
                    coverage.fail(
                        "resource_limit",
                        "file exceeds max_file_bytes; bounded prefix retained".into(),
                        bytes.len(),
                    );
                } else if std::str::from_utf8(&bytes).is_err() {
                    coverage.fail("unsupported_encoding", "UTF-8 required".into(), bytes.len());
                } else {
                    let (found, c) = parse::extract(&path, lang, &bytes, policy.max_nodes)?;
                    functions.extend(found);
                    coverage = c;
                }
            }
        }
        files.push(FileSnapshot {
            path,
            language: lang.into(),
            hash: hash(&bytes),
            bytes,
            coverage,
        });
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    exclusions.sort_by(|a, b| a.path.cmp(&b.path));
    let complete = files
        .iter()
        .all(|f| f.coverage.coverage_status == "source_complete");
    let m = manifest::assemble(
        policy,
        files.as_slice(),
        functions,
        exclusions,
        complete,
        complete || allow_partial,
    );
    Ok((m, files))
}
