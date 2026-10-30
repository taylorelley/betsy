//! TypeSafe System One (`POST /v1/systemone`), asking each weakness as a Noul.
use super::{http::Client, probability, protocol, Answer, Provider, ProviderError, State, Usage};
use crate::weakness::Question;
use serde_json::{json, Map, Value};

pub struct Jev {
    pub base_url: String,
    pub model: String,
    pub max_questions: usize,
    pub long_context: bool,
    /// Send the text rendering as a single string state instead of the JSON object.
    pub text_state: bool,
    /// Leave out the true/false criteria; the instructions alone carry the question.
    pub omit_criteria: bool,
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
            text_state: false,
            omit_criteria: false,
            client: Client::new(api_key, timeout, max_retries),
        }
    }
    pub fn with_text_state(mut self, text_state: bool) -> Self {
        self.text_state = text_state;
        self
    }
    pub fn with_omit_criteria(mut self, omit_criteria: bool) -> Self {
        self.omit_criteria = omit_criteria;
        self
    }
}
pub fn request(
    model: &str,
    state: &State,
    questions: &[&Question],
    text_state: bool,
    omit_criteria: bool,
) -> Value {
    let qs: Map<String, Value> = questions
        .iter()
        .map(|q| {
            let mut v = json!({"type":"noul","instructions":q.instructions});
            if !omit_criteria {
                v["criteria"] = json!({"true":q.criteria_true,"false":q.criteria_false});
            }
            (q.key.clone(), v)
        })
        .collect();
    let state = if text_state {
        Value::String(state.text())
    } else {
        state.json()
    };
    json!({"model":model,"state":state,"questions":qs})
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
        let mut c = json!({"provider":"jev","model":self.model,"api":"v1/systemone","question_type":"noul","state":super::STATE_VERSION});
        // Only non-default options are recorded, so existing runs keep their identity.
        if self.text_state {
            c["state_format"] = json!("text");
        }
        if self.omit_criteria {
            c["criteria"] = json!(false);
        }
        c
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
            &request(
                &self.model,
                state,
                questions,
                self.text_state,
                self.omit_criteria,
            ),
        )?;
        parse(&resp, questions)
    }
}
