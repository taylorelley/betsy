//! Decision-model providers. Each question asks about exactly one weakness; providers may
//! evaluate many independent questions against the same function state in one request.
use crate::{model::Function, weakness::Question};
use serde::Serialize;
use serde_json::{json, Value};

mod http;
pub mod jev;
pub mod mock;
pub mod openai;

/// The shared evidence for every question about one function.
pub struct State<'a> {
    pub function: &'a Function,
}
impl State<'_> {
    pub fn json(&self) -> Value {
        let f = self.function;
        json!({"language":f.language,"path":f.path,"kind":f.kind,"name":f.name,"qualified_name":f.qualified_name,"source":f.source})
    }
    /// Text form; the function comes first so every question reuses the same cached prefix.
    pub fn text(&self) -> String {
        let f = self.function;
        format!(
            "Language: {}\nPath: {}\nKind: {}\nName: {}\nSource:\n```\n{}\n```",
            f.language,
            f.path,
            f.kind,
            f.qualified_name
                .as_deref()
                .or(f.name.as_deref())
                .unwrap_or("<anonymous>"),
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
