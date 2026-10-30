//! Deterministic offline provider for tests and dry runs. Never contacts a network.
use super::{Answer, Provider, ProviderError, State, Usage};
use crate::{model::hash, weakness::Question};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub weakness: String,
    /// Applies only when the function source contains this text.
    #[serde(default)]
    pub contains: Option<String>,
    pub probability: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Script {
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Probability for unmatched questions; when absent, a stable hash-derived value is used.
    #[serde(default)]
    pub default: Option<f64>,
}
#[derive(Default)]
pub struct Mock {
    pub script: Script,
    pub max_questions: usize,
    pub requests: AtomicUsize,
    pub questions: AtomicUsize,
    pub largest_request: AtomicUsize,
    /// Every (function source hash, weakness id) asked, in arrival order.
    pub log: Mutex<Vec<(String, String)>>,
}
impl Mock {
    pub fn new(script: Script, max_questions: usize) -> Self {
        Self {
            script,
            max_questions,
            ..Self::default()
        }
    }
}
impl Provider for Mock {
    fn config(&self) -> Value {
        json!({"provider":"mock","model":"mock-v1","script":crate::model::identity(&self.script),"state":super::STATE_VERSION})
    }
    fn max_questions(&self) -> usize {
        self.max_questions
    }
    fn decide(
        &self,
        state: &State,
        questions: &[&Question],
    ) -> Result<(Vec<Answer>, Usage), ProviderError> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        self.questions.fetch_add(questions.len(), Ordering::SeqCst);
        self.largest_request
            .fetch_max(questions.len(), Ordering::SeqCst);
        let source = state.function.source.as_deref().unwrap_or_default();
        let mut log = self.log.lock().expect("mock log");
        let answers = questions
            .iter()
            .map(|q| {
                log.push((state.function.source_hash.clone(), q.weakness_id.clone()));
                let rule = self.script.rules.iter().find(|r| {
                    let id = |s: &str| crate::weakness::normalize_id(s).unwrap_or(s.to_string());
                    id(&r.weakness) == id(&q.weakness_id)
                        && r.contains
                            .as_ref()
                            .is_none_or(|c| source.contains(c.as_str()))
                });
                let p = match (rule, self.script.default) {
                    (Some(r), _) => r.probability,
                    (None, Some(d)) => d,
                    (None, None) => {
                        let h =
                            hash(format!("{}{}", state.function.source_hash, q.hash).as_bytes());
                        u32::from_str_radix(&h[7..11], 16).unwrap_or(0) as f64 / 65535.0
                    }
                };
                Answer::Probability(p)
            })
            .collect();
        Ok((
            answers,
            Usage {
                requests: 1,
                input_tokens: (source.len() / 4 + questions.len() * 60) as u64,
                cached_tokens: 0,
                output_tokens: questions.len() as u64,
            },
        ))
    }
}
