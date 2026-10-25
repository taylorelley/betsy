# Pinned grammar inspection

Inspected the downloaded crates' actual `node-types.json` before writing adapters.
Runtime and grammar versions are pinned in Cargo.toml and recorded in snapshot identity.

* JS 0.25.0: anonymous generators are `generator_function`, not `generator_function_expression`. Function expressions are `function_expression`. Methods use `method_definition`.
* TS/TSX 0.23.2: implementations share JS kinds; `function_signature`, `method_signature`, `abstract_method_signature`, `call_signature`, and `construct_signature` have no executable body. Account for them as excluded declarations. Function types are types, not candidates. TS decorators can be class-body siblings of their method; they extend its definition span.
* Python 0.25.0: async functions share `function_definition`; `decorated_definition` wraps the `definition` field. It is not a candidate. Lambda has a body field.
* Rust 0.24.0: required trait/extern declarations use `function_signature_item`, excluded explicitly. `function_item` and `closure_expression` have body fields. Attributes are preceding sibling `attribute_item` nodes, so definition spans include them.
* C 0.24.1 / C++ 0.23.4: `function_definition` has declarator and body fields. Declarator nesting must be followed to recover function-pointer-returning names. C++ conversion functions use `operator_cast` under the declarator; the enclosing definition is still counted once. Templates wrap `function_definition`; lambdas use `lambda_expression`. Function-try-blocks have a direct `try_statement` child without a body field; use that entire executable region as body. Default/delete clauses are declarations without executable bodies.

No regex or query limits participate in discovery. The walker visits all AST children, including anonymous tokens, using an explicit stack and bounded node count. Unknown named nodes whose names indicate executable definitions become unresolved gaps. Macro invocations/definitions and preprocessor sites are reported separately; expansion is outside source completeness.
