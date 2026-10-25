use crate::model::FunctionFlags;
use anyhow::{bail, Result};
use std::ops::Range;
use tree_sitter::{Language, Node};

pub fn for_extension(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "js" | "jsx" | "mjs" | "cjs" => "javascript",
        "ts" | "mts" | "cts" => "typescript",
        "tsx" => "tsx",
        "py" => "python",
        "rs" => "rust",
        "c" | "h" => "c",
        "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" => "cpp",
        _ => return None,
    })
}
pub fn grammar(lang: &str) -> Result<Language> {
    Ok(match lang {
        "javascript" => tree_sitter_javascript::LANGUAGE.into(),
        "typescript" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
        "python" => tree_sitter_python::LANGUAGE.into(),
        "rust" => tree_sitter_rust::LANGUAGE.into(),
        "c" => tree_sitter_c::LANGUAGE.into(),
        "cpp" => tree_sitter_cpp::LANGUAGE.into(),
        _ => bail!("unsupported language: {lang}"),
    })
}
pub fn node_types(lang: &str) -> &'static str {
    match lang {
        "javascript" => tree_sitter_javascript::NODE_TYPES,
        "typescript" => tree_sitter_typescript::TYPESCRIPT_NODE_TYPES,
        "tsx" => tree_sitter_typescript::TSX_NODE_TYPES,
        "python" => tree_sitter_python::NODE_TYPES,
        "rust" => tree_sitter_rust::NODE_TYPES,
        "c" => tree_sitter_c::NODE_TYPES,
        "cpp" => tree_sitter_cpp::NODE_TYPES,
        _ => "[]",
    }
}
pub struct CallableDraft {
    pub kind: String,
    pub name: Option<String>,
    pub qualified_name: Option<String>,
    pub definition: Range<usize>,
    pub body: Option<Range<usize>>,
    pub flags: FunctionFlags,
    pub node_kind: String,
}
pub trait LanguageAdapter: Send + Sync {
    fn language(&self) -> &str;
    fn candidate_types(&self) -> &'static [&'static str];
    fn classify(&self, node: Node<'_>, source: &[u8]) -> Option<CallableDraft>;
}
pub struct Adapter(pub String);
fn text<'a>(n: Node<'_>, s: &'a [u8]) -> &'a str {
    std::str::from_utf8(&s[n.byte_range()]).unwrap_or("")
}
fn has_token(n: Node<'_>, token: &str, s: &[u8]) -> bool {
    let mut c = n.walk();
    let found = n
        .children(&mut c)
        .any(|x| !x.is_named() && text(x, s) == token);
    found
}
fn ancestors(n: Node<'_>) -> Vec<Node<'_>> {
    let mut out = vec![];
    let mut p = n.parent();
    while let Some(a) = p {
        out.push(a);
        p = a.parent();
    }
    out
}
fn declarator_name(n: Node<'_>, s: &[u8]) -> Option<String> {
    if matches!(
        n.kind(),
        "identifier"
            | "field_identifier"
            | "qualified_identifier"
            | "destructor_name"
            | "operator_name"
            | "operator_cast"
    ) {
        return Some(text(n, s).to_string());
    }
    if let Some(d) = n.child_by_field_name("declarator") {
        return declarator_name(d, s);
    }
    let mut c = n.walk();
    for child in n.named_children(&mut c) {
        if child.kind() != "parameter_list" {
            if let Some(name) = declarator_name(child, s) {
                return Some(name);
            }
        }
    }
    None
}
impl LanguageAdapter for Adapter {
    fn language(&self) -> &str {
        &self.0
    }
    fn candidate_types(&self) -> &'static [&'static str] {
        match self.0.as_str() {
            "javascript" => &[
                "function_declaration",
                "function_expression",
                "generator_function",
                "generator_function_declaration",
                "arrow_function",
                "method_definition",
            ],
            "typescript" | "tsx" => &[
                "function_declaration",
                "function_expression",
                "generator_function",
                "generator_function_declaration",
                "arrow_function",
                "method_definition",
                "function_signature",
                "method_signature",
                "abstract_method_signature",
                "call_signature",
                "construct_signature",
            ],
            "python" => &["function_definition", "lambda"],
            "rust" => &[
                "function_item",
                "closure_expression",
                "function_signature_item",
            ],
            "c" => &["function_definition"],
            "cpp" => &["function_definition", "lambda_expression"],
            _ => &[],
        }
    }
    fn classify(&self, n: Node<'_>, s: &[u8]) -> Option<CallableDraft> {
        let body = n.child_by_field_name("body").or_else(|| {
            let mut c = n.walk();
            let found = n
                .named_children(&mut c)
                .find(|x| x.kind() == "try_statement");
            found
        })?;
        if matches!(
            body.kind(),
            "default_method_clause" | "delete_method_clause"
        ) {
            return None;
        }
        let a = ancestors(n);
        let lang = self.0.as_str();
        let nk = n.kind();
        let mut kind = match nk {
            "arrow_function" => "arrow",
            "lambda" | "lambda_expression" => "lambda",
            "closure_expression" => "closure",
            "generator_function" | "generator_function_declaration" => "generator",
            "method_definition" => "method",
            _ => "function",
        }
        .to_string();
        let mut name = n
            .child_by_field_name("name")
            .map(|x| text(x, s).to_string());
        if name.is_none() && matches!(lang, "c" | "cpp") {
            name = n
                .child_by_field_name("declarator")
                .and_then(|d| declarator_name(d, s));
        }
        if nk == "method_definition" {
            if has_token(n, "get", s) {
                kind = "getter".into();
            } else if has_token(n, "set", s) {
                kind = "setter".into();
            } else if name.as_deref() == Some("constructor")
                && n.parent().is_some_and(|x| x.kind() == "class_body")
            {
                kind = "constructor".into();
            }
        }
        if lang == "python" && nk == "function_definition" {
            // The first lexical scope decides: a def nested in a method is a function.
            if a.iter()
                .find(|x| {
                    matches!(
                        x.kind(),
                        "class_definition" | "function_definition" | "lambda"
                    )
                })
                .is_some_and(|x| x.kind() == "class_definition")
            {
                kind = "method".into();
            }
        }
        if lang == "rust"
            && nk == "function_item"
            && a.iter()
                .find(|x| {
                    matches!(
                        x.kind(),
                        "impl_item" | "trait_item" | "function_item" | "closure_expression"
                    )
                })
                .is_some_and(|x| matches!(x.kind(), "impl_item" | "trait_item"))
        {
            kind = "method".into();
        }
        if lang == "cpp" && nk == "function_definition" {
            let class = a.iter().find(|x| {
                matches!(
                    x.kind(),
                    "class_specifier" | "struct_specifier" | "union_specifier"
                )
            });
            let raw = name.as_deref().unwrap_or("");
            let pieces = raw.split("::").collect::<Vec<_>>();
            let last = pieces.last().copied().unwrap_or("");
            let cname = class
                .and_then(|c| c.child_by_field_name("name"))
                .map(|x| text(x, s));
            if last.starts_with('~') {
                kind = "destructor".into();
            } else if cname == Some(last) || pieces.len() > 1 && pieces[pieces.len() - 2] == last {
                kind = "constructor".into();
            } else if class.is_some()
                || pieces.len() > 1
                || n.child_by_field_name("declarator")
                    .is_some_and(|d| d.kind() == "operator_cast")
            {
                kind = "method".into();
            }
        }
        let mut definition = n.byte_range();
        let mut flags = FunctionFlags::default();
        if let Some(p) = n.parent() {
            if (lang == "python" && p.kind() == "decorated_definition")
                || (lang == "cpp" && p.kind() == "template_declaration")
            {
                definition = p.byte_range();
                flags.decorated = lang == "python";
                flags.template = lang == "cpp";
            }
        }
        // Rust attributes syntactically belong to the next item, but are siblings.
        if lang == "rust" || matches!(lang, "typescript" | "tsx") {
            let mut prev = n.prev_named_sibling();
            while let Some(p) = prev {
                if !(lang == "rust" && p.kind() == "attribute_item"
                    || matches!(lang, "typescript" | "tsx") && p.kind() == "decorator")
                {
                    break;
                }
                definition.start = p.start_byte();
                flags.decorated |= p.kind() == "decorator";
                prev = p.prev_named_sibling();
            }
        }
        flags.r#async = has_token(n, "async", s);
        flags.generator = nk.starts_with("generator_") || has_token(n, "*", s);
        flags.r#static = has_token(n, "static", s);
        flags.r#unsafe = has_token(n, "unsafe", s);
        flags.inline = has_token(n, "inline", s);
        let mut c = n.walk();
        for child in n.named_children(&mut c) {
            if matches!(
                child.kind(),
                "function_modifiers" | "storage_class_specifier" | "type_qualifier"
            ) {
                flags.r#async |= has_token(child, "async", s) || text(child, s) == "async";
                flags.r#unsafe |= has_token(child, "unsafe", s) || text(child, s) == "unsafe";
                flags.inline |= text(child, s) == "inline";
                flags.r#static |= text(child, s) == "static";
            }
            if child.kind() == "decorator" {
                flags.decorated = true;
            }
        }
        flags.exported = n.parent().is_some_and(|p| p.kind() == "export_statement") || {
            let mut c = n.walk();
            let found = n
                .named_children(&mut c)
                .any(|x| x.kind() == "visibility_modifier" && text(x, s).starts_with("pub"));
            found
        };
        if name.is_none() {
            if let Some(p) = n.parent() {
                if matches!(
                    p.kind(),
                    "variable_declarator"
                        | "let_declaration"
                        | "assignment"
                        | "field_definition"
                        | "public_field_definition"
                        | "pair"
                ) {
                    name = p
                        .child_by_field_name("name")
                        .or_else(|| p.child_by_field_name("pattern"))
                        .or_else(|| p.child_by_field_name("left"))
                        .or_else(|| p.child_by_field_name("property"))
                        .or_else(|| p.child_by_field_name("key"))
                        .filter(|x| {
                            matches!(
                                x.kind(),
                                "identifier"
                                    | "property_identifier"
                                    | "field_identifier"
                                    | "private_property_identifier"
                            )
                        })
                        .map(|x| text(x, s).to_string());
                }
            }
        }
        if lang == "python" && nk == "function_definition" {
            let mut pending = vec![body];
            while let Some(x) = pending.pop() {
                if matches!(x.kind(), "yield" | "yield_expression") {
                    flags.generator = true;
                }
                for i in 0..x.named_child_count() {
                    if let Some(child) = x.named_child(i) {
                        if !matches!(
                            child.kind(),
                            "function_definition" | "lambda" | "class_definition"
                        ) {
                            pending.push(child);
                        }
                    }
                }
            }
        }
        let qualified_name = name.as_ref().map(|name| {
            let mut scopes = a
                .iter()
                .rev()
                .filter(|x| {
                    matches!(
                        x.kind(),
                        "class_definition"
                            | "class_declaration"
                            | "function_definition"
                            | "function_declaration"
                            | "function_item"
                            | "method_definition"
                            | "namespace_definition"
                            | "mod_item"
                            | "class_specifier"
                            | "struct_specifier"
                    )
                })
                .filter_map(|x| x.child_by_field_name("name"))
                .map(|x| text(x, s).to_string())
                .collect::<Vec<_>>();
            scopes.push(name.clone());
            scopes.join("::")
        });
        Some(CallableDraft {
            kind,
            name,
            qualified_name,
            definition,
            body: Some(body.byte_range()),
            flags,
            node_kind: nk.into(),
        })
    }
}
pub fn excluded_declaration(n: Node<'_>) -> bool {
    matches!(
        n.kind(),
        "function_signature_item"
            | "function_signature"
            | "method_signature"
            | "abstract_method_signature"
            | "call_signature"
            | "construct_signature"
    ) || n
        .child_by_field_name("body")
        .is_some_and(|b| matches!(b.kind(), "default_method_clause" | "delete_method_clause"))
}
