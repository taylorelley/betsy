use super::ProviderError;
use serde_json::Value;
use std::time::Duration;

pub struct Client {
    agent: ureq::Agent,
    api_key: Option<String>,
    max_retries: u32,
}
impl Client {
    pub fn new(api_key: Option<String>, timeout: Duration, max_retries: u32) -> Self {
        Self {
            agent: ureq::AgentBuilder::new().timeout(timeout).build(),
            api_key,
            max_retries,
        }
    }
    /// POSTs JSON with exponential backoff on transport errors, 408, 429 and 5xx,
    /// honouring `Retry-After`. Payload-size rejections are reported for splitting.
    pub fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &Value,
    ) -> Result<Value, ProviderError> {
        let mut attempt = 0;
        loop {
            let mut req = self.agent.post(url);
            if let Some(k) = &self.api_key {
                req = req.set("Authorization", &format!("Bearer {k}"));
            }
            for (k, v) in headers {
                req = req.set(k, v);
            }
            let (err, wait) = match req.send_json(body) {
                Ok(resp) => {
                    return resp.into_json().map_err(|e| ProviderError {
                        code: "provider_protocol",
                        message: format!("invalid JSON response: {e}"),
                        retryable: true,
                        split: false,
                    })
                }
                Err(ureq::Error::Status(code, resp)) => {
                    let retry_after = resp
                        .header("Retry-After")
                        .and_then(|s| s.trim().parse::<f64>().ok())
                        .map(|s| Duration::from_secs_f64(s.clamp(0.0, 60.0)));
                    let text: String = resp
                        .into_string()
                        .unwrap_or_default()
                        .chars()
                        .take(2000)
                        .collect();
                    let retryable = matches!(code, 408 | 429 | 500..=599);
                    let e = ProviderError {
                        code: if code == 429 {
                            "rate_limited"
                        } else {
                            "provider_http"
                        },
                        message: format!("HTTP {code}: {text}"),
                        retryable,
                        split: matches!(code, 413 | 422)
                            || (code == 400 && text.to_ascii_lowercase().contains("question")),
                    };
                    if !retryable {
                        return Err(e);
                    }
                    (e, retry_after)
                }
                Err(e) => (
                    ProviderError {
                        code: "provider_transport",
                        message: e.to_string(),
                        retryable: true,
                        split: false,
                    },
                    None,
                ),
            };
            if attempt >= self.max_retries {
                return Err(err);
            }
            let backoff = Duration::from_millis(500 * 2u64.pow(attempt.min(6)));
            std::thread::sleep(wait.unwrap_or(backoff).min(Duration::from_secs(60)));
            attempt += 1;
        }
    }
}
