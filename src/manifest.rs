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
    for i in 0..functions.len() {
        let f = &functions[i];
        let parent = functions
            .iter()
            .filter(|p| {
                p.path == f.path
                    && p.start_byte <= f.start_byte
                    && p.end_byte >= f.end_byte
                    && p.id != f.id
            })
            .min_by_key(|p| p.end_byte - p.start_byte)
            .map(|p| p.id.clone());
        functions[i].parent_id = parent;
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
