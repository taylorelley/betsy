use crate::{
    languages::{self, Adapter, LanguageAdapter},
    model::*,
};
use anyhow::Result;
use tree_sitter::Parser;
pub fn extract(
    path: &str,
    lang: &str,
    source: &[u8],
    max_nodes: usize,
) -> Result<(Vec<Function>, Coverage)> {
    let mut parser = Parser::new();
    parser.set_language(&languages::grammar(lang)?)?;
    let mut coverage = Coverage::new(path, lang);
    let mut out = vec![];
    let Some(tree) = parser.parse(source, None) else {
        coverage.fail("timeout", "parser returned no tree".into(), source.len());
        return Ok((out, coverage));
    };
    let adapter = Adapter(lang.into());
    let file_hash = hash(source);
    let mut stack = vec![tree.root_node()];
    let mut seen = 0;
    while let Some(n) = stack.pop() {
        seen += 1;
        if seen > max_nodes {
            coverage.fail(
                "resource_limit",
                "AST exceeds max_nodes".into(),
                source.len(),
            );
            break;
        }
        if n.is_error() || n.is_missing() {
            coverage.parse_errors.push(Gap {
                kind: if n.is_missing() { "missing" } else { "error" }.into(),
                start_byte: n.start_byte(),
                end_byte: n.end_byte(),
                detail: n.kind().into(),
            });
        }
        if matches!(
            n.kind(),
            "macro_invocation"
                | "macro_definition"
                | "preproc_function_def"
                | "preproc_call"
                | "preproc_if"
                | "preproc_ifdef"
        ) {
            coverage.macro_sites.push(Gap {
                kind: "macro_expansion_unknown".into(),
                start_byte: n.start_byte(),
                end_byte: n.end_byte(),
                detail: n.kind().into(),
            });
        }
        let candidate = n.is_named() && adapter.candidate_types().contains(&n.kind());
        if candidate {
            coverage.candidate_nodes_seen += 1;
            if let Some(d) = adapter.classify(n, source) {
                let start = d.definition.start;
                let end = d.definition.end;
                let before = &source[..start];
                let end_before = &source[..end];
                let line_col = |b: &[u8]| {
                    (
                        1 + b.iter().filter(|&&x| x == b'\n').count(),
                        b.iter()
                            .rposition(|&x| x == b'\n')
                            .map_or(b.len(), |i| b.len() - i - 1),
                    )
                };
                let (start_line, start_column) = line_col(before);
                let (end_line, end_column) = line_col(end_before);
                out.push(Function {
                    schema_version: 1,
                    snapshot_id: String::new(),
                    id: String::new(),
                    language: lang.into(),
                    path: path.into(),
                    kind: d.kind,
                    name: d.name,
                    qualified_name: d.qualified_name,
                    parent_id: None,
                    start_byte: start,
                    end_byte: end,
                    body_start_byte: d.body.as_ref().map(|r| r.start),
                    body_end_byte: d.body.map(|r| r.end),
                    start_line,
                    start_column,
                    end_line,
                    end_column,
                    source_hash: hash(&source[start..end]),
                    file_hash: file_hash.clone(),
                    flags: d.flags,
                    node_kind: d.node_kind,
                    source: None,
                });
                coverage.extracted_occurrences += 1;
            } else if languages::excluded_declaration(n) {
                coverage.explicitly_excluded_declarations += 1;
            } else {
                coverage.unresolved_candidates += 1;
                coverage.gaps.push(Gap {
                    kind: "unresolved_candidate".into(),
                    start_byte: n.start_byte(),
                    end_byte: n.end_byte(),
                    detail: n.kind().into(),
                });
            }
        } else if n.is_named()
            && (n.kind().ends_with("function_definition")
                || n.kind().ends_with("method_definition")
                || n.kind().ends_with("closure_expression")
                || n.kind().ends_with("lambda_expression"))
        {
            coverage.unresolved_candidates += 1;
            coverage.candidate_nodes_seen += 1;
            coverage.gaps.push(Gap {
                kind: "unknown_callable_node".into(),
                start_byte: n.start_byte(),
                end_byte: n.end_byte(),
                detail: n.kind().into(),
            });
        }
        for i in (0..n.child_count()).rev() {
            if let Some(c) = n.child(i) {
                stack.push(c);
            }
        }
    }
    if !coverage.parse_errors.is_empty() {
        coverage.parse_status = "errors".into();
        coverage.coverage_status = "partial".into();
    }
    if coverage.unresolved_candidates > 0 {
        coverage.coverage_status = "partial".into();
    }
    Ok((out, coverage))
}
