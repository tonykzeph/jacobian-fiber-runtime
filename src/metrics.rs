use std::sync::{Arc, Mutex};

use prometheus_client::{encoding::text::encode, metrics::counter::Counter, registry::Registry};

use crate::{JfrError, Result};

#[derive(Clone)]
pub struct Metrics {
    registry: Arc<Mutex<Registry>>,
    pub http_requests: Counter,
    pub mutations: Counter,
    pub authentication_failures: Counter,
    pub request_failures: Counter,
}

impl Metrics {
    #[must_use]
    pub fn new() -> Self {
        let http_requests = Counter::default();
        let mutations = Counter::default();
        let authentication_failures = Counter::default();
        let request_failures = Counter::default();
        let mut registry = Registry::default();
        registry.register(
            "jfr_http_requests",
            "HTTP requests received by the runtime",
            http_requests.clone(),
        );
        registry.register(
            "jfr_mutations",
            "Committed fiber-state mutations",
            mutations.clone(),
        );
        registry.register(
            "jfr_authentication_failures",
            "Rejected authentication attempts",
            authentication_failures.clone(),
        );
        registry.register(
            "jfr_request_failures",
            "HTTP requests returning a failure response",
            request_failures.clone(),
        );
        Self {
            registry: Arc::new(Mutex::new(registry)),
            http_requests,
            mutations,
            authentication_failures,
            request_failures,
        }
    }

    pub fn encode(&self) -> Result<String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| JfrError::Internal("metrics registry lock was poisoned".to_owned()))?;
        let mut output = String::new();
        encode(&mut output, &registry)
            .map_err(|error| JfrError::Internal(format!("metrics encoding: {error}")))?;
        Ok(output)
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
