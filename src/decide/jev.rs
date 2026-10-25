//! TypeSafe System One (`POST /v1/systemone`), asking each weakness as a Noul.
use super::{http::Client, probability, protocol, Answer, Provider, ProviderError, State, Usage};
use crate::weakness::Question;
use serde_json::{json, Map, Value};

pub struct Jev {
    pub base_url: String,
    pub model: String,
    pub max_questions: usize,
    pub long_context: bool,
    client: Client,
}
impl Jev {
    pub fn new(
        base_url: String,
        model: String,
        api_key: Option<String>,
        max_questions: usize,
        long_context: bool,
        timeout: std::time::Duration,
        max_retries: u32,
    ) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').into(),
            model,
            max_questions,
            long_context,
            client: Client::new(api_key, timeout, max_retries),
        }
    }
}
pub fn request(model: &str, state: &State, questions: &[&Question]) -> Value {
    let qs: Map<String, Value> = questions
        .iter()
        .map(|q| {
            (
                q.key.clone(),
                json!({"type":"noul","instructions":q.instructions,"criteria":{"true":q.criteria_true,"false":q.criteria_false}}),
            )
        })
        .collect();
    json!({"model":model,"state":state.json(),"questions":qs})
}
pub fn parse(resp: &Value, questions: &[&Question]) -> Result<(Vec<Answer>, Usage), ProviderError> {
    let answers = questions
        .iter()
        .map(|q| {
            probability(&resp["answers"][&q.key], "noul")
                .ok_or_else(|| protocol(format!("missing noul answer for {}", q.key)))
        })
        .collect::<Result<_, _>>()?;
    Ok((answers, Usage::from_json(&resp["usage"])))
}
impl Provider for Jev {
    fn config(&self) -> Value {
        json!({"provider":"jev","model":self.model,"api":"v1/systemone","question_type":"noul"})
    }
    fn max_questions(&self) -> usize {
        self.max_questions
    }
    fn decide(
        &self,
        state: &State,
        questions: &[&Question],
    ) -> Result<(Vec<Answer>, Usage), ProviderError> {
        let headers: &[(&str, &str)] = if self.long_context {
            &[("TypeSafe-Danger-Zone-Long-Context", "true")]
        } else {
            &[]
        };
        let resp = self.client.post(
            &format!("{}/v1/systemone", self.base_url),
            headers,
            &request(&self.model, state, questions),
        )?;
        parse(&resp, questions)
    }
}
