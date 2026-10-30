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
                    let wait = retry_after(resp.header("Retry-After"));
                    let text: String = resp
                        .into_string()
                        .unwrap_or_default()
                        .chars()
                        .take(2000)
                        .collect();
                    let e = status_error(code, &text);
                    if !e.retryable {
                        return Err(e);
                    }
                    (e, wait)
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

/// `Retry-After` in seconds, clamped to a minute. HTTP-date values are ignored in favour of backoff.
fn retry_after(header: Option<&str>) -> Option<Duration> {
    header
        .and_then(|s| s.trim().parse::<f64>().ok())
        .filter(|s| s.is_finite())
        .map(|s| Duration::from_secs_f64(s.clamp(0.0, 60.0)))
}
/// Retries 408, 429 and 5xx; asks for a split on payload-size rejections.
fn status_error(code: u16, text: &str) -> ProviderError {
    ProviderError {
        code: if code == 429 {
            "rate_limited"
        } else {
            "provider_http"
        },
        message: format!("HTTP {code}: {text}"),
        retryable: matches!(code, 408 | 429 | 500..=599),
        split: matches!(code, 413 | 422)
            || (code == 400 && text.to_ascii_lowercase().contains("question")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_reads_seconds_and_clamps() {
        assert_eq!(
            retry_after(Some(" 2.5 ")),
            Some(Duration::from_millis(2500))
        );
        assert_eq!(retry_after(Some("600")), Some(Duration::from_secs(60)));
        assert_eq!(retry_after(Some("-3")), Some(Duration::ZERO));
        assert_eq!(retry_after(Some("NaN")), None);
        assert_eq!(retry_after(Some("Wed, 21 Oct 2026 07:28:00 GMT")), None);
        assert_eq!(retry_after(None), None);
    }

    #[test]
    fn statuses_classify_retry_and_split() {
        let e = status_error(429, "slow down");
        assert_eq!(
            (e.code, e.retryable, e.split),
            ("rate_limited", true, false)
        );
        for code in [408, 500, 502, 503, 599] {
            let e = status_error(code, "");
            assert!(e.retryable && !e.split, "{code}");
        }
        for code in [413, 422] {
            let e = status_error(code, "");
            assert!(e.split && !e.retryable, "{code}");
        }
        assert!(status_error(400, "Too many Questions").split);
        let e = status_error(400, "bad model");
        assert!(!e.split && !e.retryable);
        assert!(!status_error(401, "").retryable);
        assert_eq!(status_error(404, "nope").message, "HTTP 404: nope");
    }
}
