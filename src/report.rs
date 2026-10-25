use crate::model::Manifest;
use serde_json::{json, Value};
pub fn summary(m: &Manifest) -> Value {
    json!({"schema_version":1,"snapshot_id":m.snapshot_id,"source_complete":m.source_complete,"sealed":m.sealed,"function_count":m.functions.len(),"files":m.files,"excluded_count":m.exclusions.len(),"exclusions":m.exclusions})
}
