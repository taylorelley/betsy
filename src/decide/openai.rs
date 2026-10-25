//! OpenAI Decisions (`POST /v1/decisions`), asking each weakness as a predicate.
use super::{http::Client, probability, protocol, Answer, Provider, ProviderError, State, Usage};
use crate::weakness::Question;
use serde_json::{json, Value};

/// Documented per-request question limit.
pub const MAX_QUESTIONS: usize = 400;

pub struct OpenAi {
    pub base_url: String,
    pub model: String,
    pub max_questions: usize,
    client: Client,
}
impl OpenAi {
    pub fn new(
        base_url: String,
        model: String,
        api_key: Option<String>,
        max_questions: usize,
        timeout: std::time::Duration,
        max_retries: u32,
    ) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').into(),
            model,
            max_questions: max_questions.min(MAX_QUESTIONS),
            client: Client::new(api_key, timeout, max_retries),
        }
    }
}
pub fn request(model: &str, state: &State, questions: &[&Question]) -> Value {
    let qs: Vec<Value> = questions
        .iter()
        .map(|q| {
            json!({"type":"predicate","name":q.key,"instructions":format!(
                "{}\nAnswer true if: {}\nAnswer false if: {}",
                q.instructions, q.criteria_true, q.criteria_false
            )})
        })
        .collect();
    // The implicit cache breakpoint sits at the end of `input`, so the function is the
    // shared prefix for every chunk and hierarchy round.
    json!({"model":model,"input":state.text(),"questions":qs,"prompt_cache_key":state.cache_key()})
}
pub fn parse(resp: &Value, questions: &[&Question]) -> Result<(Vec<Answer>, Usage), ProviderError> {
    let list = ["answers", "output", "decisions", "results"]
        .iter()
        .find_map(|k| resp[*k].as_array())
        .ok_or_else(|| protocol("response has no answer list".into()))?;
    let answers = questions
        .iter()
        .map(|q| {
            list.iter()
                .find(|a| a["name"] == q.key.as_str())
                .and_then(|a| probability(a, "probability"))
                .ok_or_else(|| protocol(format!("missing predicate answer for {}", q.key)))
        })
        .collect::<Result<_, _>>()?;
    Ok((answers, Usage::from_json(&resp["usage"])))
}
impl Provider for OpenAi {
    fn config(&self) -> Value {
        json!({"provider":"openai","model":self.model,"api":"v1/decisions","question_type":"predicate"})
    }
    fn max_questions(&self) -> usize {
        self.max_questions
    }
    fn decide(
        &self,
        state: &State,
        questions: &[&Question],
    ) -> Result<(Vec<Answer>, Usage), ProviderError> {
        let resp = self.client.post(
            &format!("{}/v1/decisions", self.base_url),
            &[],
            &request(&self.model, state, questions),
        )?;
        parse(&resp, questions)
    }
}
