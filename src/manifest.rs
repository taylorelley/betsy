use crate::model::*;
use serde_json::json;
pub fn parser_versions() -> serde_json::Value {
    json!({"tree-sitter":"0.25.10", "javascript":"0.25.0","typescript":"0.23.2","tsx":"0.23.2","python":"0.25.0","rust":"0.24.0","c":"0.24.1","cpp":"0.23.4", "adapter_contract":1})
}
pub fn assemble(
    policy: Policy,
    files: &[FileSnapshot],
    mut functions: Vec<Function>,
    exclusions: Vec<Exclusion>,
    complete: bool,
    sealed: bool,
) -> Manifest {
    let versions = parser_versions();
    let snapshot = identity(&(
        1,
        &versions,
        &policy,
        files
            .iter()
            .map(|f| (&f.path, &f.hash, &f.coverage.parse_status))
            .collect::<Vec<_>>(),
    ));
    functions.sort_by(|a, b| {
        (&a.path, a.start_byte, a.end_byte, &a.node_kind).cmp(&(
            &b.path,
            b.start_byte,
            b.end_byte,
            &b.node_kind,
        ))
    });
    for (ordinal, f) in functions.iter_mut().enumerate() {
        f.snapshot_id = snapshot.clone();
        f.id = identity(&(
            &snapshot,
            &f.path,
            f.start_byte,
            f.end_byte,
            &f.node_kind,
            ordinal,
        ));
    }
    // The parent is the smallest enclosing callable in the same file. Syntax-tree spans nest
    // or are disjoint, so a stack of open spans finds it in one pass per file.
    let mut order: Vec<usize> = (0..functions.len()).collect();
    order.sort_by(|&a, &b| {
        let (x, y) = (&functions[a], &functions[b]);
        (&x.path, x.start_byte, std::cmp::Reverse(x.end_byte), a).cmp(&(
            &y.path,
            y.start_byte,
            std::cmp::Reverse(y.end_byte),
            b,
        ))
    });
    let mut open: Vec<usize> = vec![];
    for i in order {
        let f = &functions[i];
        while let Some(&p) = open.last() {
            let p = &functions[p];
            if p.path == f.path && p.end_byte >= f.end_byte {
                break;
            }
            open.pop();
        }
        let parent = open.last().map(|&p| functions[p].id.clone());
        functions[i].parent_id = parent;
        open.push(i);
    }
    Manifest {
        schema_version: 1,
        snapshot_id: snapshot,
        parser_versions: versions,
        inclusion_policy: policy,
        source_complete: complete,
        sealed,
        files: files.iter().map(|f| f.coverage.clone()).collect(),
        exclusions,
        functions,
    }
}
