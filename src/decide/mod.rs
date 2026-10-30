//! Decision-model providers. Each question asks about exactly one weakness; providers may
//! evaluate many independent questions against the same function state in one request.
use crate::{contract::Features, model::Function, weakness::Question};
use serde::Serialize;
use serde_json::{json, Value};

mod http;
pub mod jev;
pub mod mock;
pub mod openai;

/// Version of the state shown to providers. It is part of every provider's configuration, so
/// cached answers and resumed runs never mix states of different shapes.
pub const STATE_VERSION: u32 = 2;

/// The shared evidence for every question about one function.
pub struct State<'a> {
    pub function: &'a Function,
    pub features: &'a Features,
}
impl State<'_> {
    pub fn json(&self) -> Value {
        let f = self.function;
        json!({"language":f.language,"path":f.path,"kind":f.kind,"name":f.name,"qualified_name":f.qualified_name,"features":self.features,"source":f.source})
    }
    /// Text form; the function comes first so every question reuses the same cached prefix.
    pub fn text(&self) -> String {
        let f = self.function;
        let x = self.features;
        let traits = if x.syntax_traits.is_empty() {
            "none proven".to_string()
        } else {
            x.syntax_traits.join(", ")
        };
        format!(
            "Language: {}\nPath: {}\nKind: {}\nName: {}\nSize: {} lines, {} bytes, {} nested callables\nSyntax traits: {}\nSource:\n```\n{}\n```",
            f.language,
            f.path,
            f.kind,
            f.qualified_name
                .as_deref()
                .or(f.name.as_deref())
                .unwrap_or("<anonymous>"),
            x.lines,
            x.bytes,
            x.nested_callables,
            traits,
            f.source.as_deref().unwrap_or_default()
        )
    }
    pub fn cache_key(&self) -> &str {
        &self.function.source_hash
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "probability")]
pub enum Answer {
    Probability(f64),
    Refused,
}
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Usage {
    pub requests: u64,
    pub input_tokens: u64,
    pub cached_tokens: u64,
    pub output_tokens: u64,
}
impl Usage {
    pub fn add(&mut self, o: &Usage) {
        self.requests += o.requests;
        self.input_tokens += o.input_tokens;
        self.cached_tokens += o.cached_tokens;
        self.output_tokens += o.output_tokens;
    }
    fn from_json(u: &Value) -> Self {
        let n = |v: &Value| v.as_u64().unwrap_or(0);
        Usage {
            requests: 1,
            input_tokens: n(&u["input_tokens"]),
            cached_tokens: n(&u["input_tokens_details"]["cached_tokens"]),
            output_tokens: n(&u["output_tokens"]),
        }
    }
}
#[derive(Debug, Clone)]
pub struct ProviderError {
    pub code: &'static str,
    pub message: String,
    pub retryable: bool,
    /// The request was rejected as too large; retrying with fewer questions may succeed.
    pub split: bool,
}
impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

pub trait Provider: Send + Sync {
    /// Stable identity used in run configuration and the decision cache.
    fn config(&self) -> Value;
    fn max_questions(&self) -> usize;
    /// Answers, in question order, for one request.
    fn decide(
        &self,
        state: &State,
        questions: &[&Question],
    ) -> Result<(Vec<Answer>, Usage), ProviderError>;
}

/// Asks one chunk, halving it when the provider rejects the payload size.
pub fn decide_splitting(
    p: &dyn Provider,
    state: &State,
    questions: &[&Question],
) -> Result<(Vec<Answer>, Usage), ProviderError> {
    match p.decide(state, questions) {
        Err(e) if e.split && questions.len() > 1 => {
            let (a, b) = questions.split_at(questions.len() / 2);
            let (mut answers, mut usage) = decide_splitting(p, state, a)?;
            let (rest, u) = decide_splitting(p, state, b)?;
            answers.extend(rest);
            usage.add(&u);
            Ok((answers, usage))
        }
        r => {
            let (answers, usage) = r?;
            if answers.len() != questions.len() {
                return Err(ProviderError {
                    code: "provider_protocol",
                    message: format!(
                        "expected {} answers, got {}",
                        questions.len(),
                        answers.len()
                    ),
                    retryable: true,
                    split: false,
                });
            }
            Ok((answers, usage))
        }
    }
}

/// Reads one probability-like field, rejecting values outside [0, 1].
fn probability(v: &Value, field: &str) -> Option<Answer> {
    if v["type"] == "refusal" {
        return Some(Answer::Refused);
    }
    v[field]
        .as_f64()
        .filter(|p| (0.0..=1.0).contains(p))
        .map(Answer::Probability)
}
fn protocol(message: String) -> ProviderError {
    ProviderError {
        code: "provider_protocol",
        message,
        retryable: true,
        split: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{model::FunctionFlags, weakness::Role};
    use std::sync::Mutex;

    fn function() -> Function {
        Function {
            schema_version: 1,
            snapshot_id: "sha256:s".into(),
            id: "sha256:f".into(),
            language: "python".into(),
            path: "a.py".into(),
            kind: "function".into(),
            name: Some("f".into()),
            qualified_name: None,
            parent_id: None,
            start_byte: 0,
            end_byte: 18,
            body_start_byte: None,
            body_end_byte: None,
            start_line: 1,
            start_column: 0,
            end_line: 2,
            end_column: 8,
            source_hash: "sha256:src".into(),
            file_hash: "sha256:file".into(),
            flags: FunctionFlags::default(),
            node_kind: "function_definition".into(),
            source: Some("def f():\n  pass".into()),
        }
    }
    fn features() -> Features {
        Features {
            lines: 2,
            bytes: 15,
            nested_callables: 0,
            syntax_traits: vec![],
        }
    }
    fn questions(ids: &[&str]) -> Vec<Question> {
        ids.iter()
            .map(|id| crate::weakness::question(id, &Role::Finding))
            .collect()
    }

    /// Rejects any request with more than `limit` questions as too large; answers 0.5 otherwise.
    struct Limited {
        limit: usize,
        short: bool,
        sizes: Mutex<Vec<usize>>,
    }
    impl Provider for Limited {
        fn config(&self) -> Value {
            json!({})
        }
        fn max_questions(&self) -> usize {
            usize::MAX
        }
        fn decide(
            &self,
            _: &State,
            questions: &[&Question],
        ) -> Result<(Vec<Answer>, Usage), ProviderError> {
            self.sizes.lock().unwrap().push(questions.len());
            if questions.len() > self.limit {
                return Err(ProviderError {
                    code: "provider_http",
                    message: "too large".into(),
                    retryable: false,
                    split: true,
                });
            }
            let n = questions.len() - usize::from(self.short);
            let usage = Usage {
                requests: 1,
                ..Usage::default()
            };
            Ok((vec![Answer::Probability(0.5); n], usage))
        }
    }

    #[test]
    fn splitting_halves_until_accepted_and_keeps_order() {
        let f = function();
        let qs = questions(&["CWE-89", "CWE-78", "CWE-79", "REL-001", "CWE-120"]);
        let refs: Vec<&Question> = qs.iter().collect();
        let p = Limited {
            limit: 2,
            short: false,
            sizes: Mutex::default(),
        };
        let (a, u) = decide_splitting(
            &p,
            &State {
                function: &f,
                features: &features(),
            },
            &refs,
        )
        .unwrap();
        assert_eq!(a.len(), 5);
        assert_eq!(u.requests, 3);
        assert_eq!(*p.sizes.lock().unwrap(), [5, 2, 3, 1, 2]);
    }

    #[test]
    fn splitting_stops_at_one_question_and_checks_answer_count() {
        let f = function();
        let qs = questions(&["CWE-89", "CWE-78"]);
        let refs: Vec<&Question> = qs.iter().collect();
        let x = features();
        let state = State {
            function: &f,
            features: &x,
        };
        let p = Limited {
            limit: 0,
            short: false,
            sizes: Mutex::default(),
        };
        let e = decide_splitting(&p, &state, &refs).unwrap_err();
        assert!(e.split);
        assert_eq!(*p.sizes.lock().unwrap(), [2, 1]);
        let p = Limited {
            limit: 9,
            short: true,
            sizes: Mutex::default(),
        };
        let e = decide_splitting(&p, &state, &refs).unwrap_err();
        assert_eq!(e.code, "provider_protocol");
        assert!(e.retryable);
    }

    #[test]
    fn probability_accepts_unit_interval_and_refusals() {
        let p = |v: Value| probability(&v, "p");
        assert_eq!(p(json!({"p":0})), Some(Answer::Probability(0.0)));
        assert_eq!(p(json!({"p":1.0})), Some(Answer::Probability(1.0)));
        assert_eq!(p(json!({"type":"refusal","p":0.7})), Some(Answer::Refused));
        for bad in [
            json!({"p":1.01}),
            json!({"p":-0.1}),
            json!({"p":"0.5"}),
            json!({}),
        ] {
            assert_eq!(p(bad.clone()), None, "{bad}");
        }
    }

    #[test]
    fn usage_counts_one_request_and_tolerates_missing_fields() {
        assert_eq!(
            Usage::from_json(&Value::Null),
            Usage {
                requests: 1,
                ..Usage::default()
            }
        );
        let mut u = Usage::from_json(
            &json!({"input_tokens":10,"output_tokens":2,"input_tokens_details":{"cached_tokens":4}}),
        );
        u.add(&u.clone());
        assert_eq!(
            (u.requests, u.input_tokens, u.cached_tokens, u.output_tokens),
            (2, 20, 8, 4)
        );
    }

    #[test]
    fn state_shows_features_and_names_anonymous_functions() {
        let mut f = function();
        let mut x = features();
        let text = |f: &Function, x: &Features| {
            State {
                function: f,
                features: x,
            }
            .text()
        };
        assert!(text(&f, &x).starts_with(
            "Language: python\nPath: a.py\nKind: function\nName: f\nSize: 2 lines, 15 bytes, 0 nested callables\nSyntax traits: none proven\n"
        ));
        x.syntax_traits = vec!["loops".into(), "pointers".into()];
        assert!(text(&f, &x).contains("\nSyntax traits: loops, pointers\n"));
        f.qualified_name = Some("m.f".into());
        assert!(text(&f, &x).contains("Name: m.f\n"));
        f.name = None;
        f.qualified_name = None;
        assert!(text(&f, &x).contains("Name: <anonymous>\n"));
        assert!(text(&f, &x).ends_with("```\ndef f():\n  pass\n```"));
        let state = State {
            function: &f,
            features: &x,
        };
        assert_eq!(state.json()["features"]["lines"], 2);
        assert_eq!(state.cache_key(), "sha256:src");
    }

    #[test]
    fn openai_reads_any_documented_container_and_rejects_gaps() {
        let qs = questions(&["CWE-89", "REL-001"]);
        let refs: Vec<&Question> = qs.iter().collect();
        for key in ["answers", "output", "decisions", "results"] {
            let resp = json!({key: [{"name":"REL_001","probability":0.2},{"name":"CWE_89","probability":0.9}]});
            let (a, _) = openai::parse(&resp, &refs).unwrap();
            assert_eq!(
                a,
                [Answer::Probability(0.9), Answer::Probability(0.2)],
                "{key}"
            );
        }
        let missing = json!({"answers":[{"name":"CWE_89","probability":0.9}]});
        assert!(openai::parse(&missing, &refs)
            .unwrap_err()
            .message
            .contains("REL_001"));
        let range = json!({"answers":[{"name":"CWE_89","probability":9},{"name":"REL_001","probability":0.1}]});
        assert!(openai::parse(&range, &refs).is_err());
        assert!(openai::parse(&json!({"answers":{}}), &refs).is_err());
    }

    #[test]
    fn jev_reads_refusals_and_rejects_out_of_range() {
        let qs = questions(&["CWE-89"]);
        let refs: Vec<&Question> = qs.iter().collect();
        let resp = json!({"answers":{"CWE_89":{"type":"refusal"}}});
        assert_eq!(jev::parse(&resp, &refs).unwrap().0, [Answer::Refused]);
        let resp = json!({"answers":{"CWE_89":{"type":"noul","noul":1.5}}});
        assert_eq!(
            jev::parse(&resp, &refs).unwrap_err().code,
            "provider_protocol"
        );
    }

    #[test]
    fn openai_caps_question_limit_and_trims_base_url() {
        let p = openai::OpenAi::new(
            "https://api.example/".into(),
            "m".into(),
            None,
            10_000,
            std::time::Duration::from_secs(1),
            0,
        );
        assert_eq!(p.max_questions(), openai::MAX_QUESTIONS);
        assert_eq!(p.base_url, "https://api.example");
    }
}
