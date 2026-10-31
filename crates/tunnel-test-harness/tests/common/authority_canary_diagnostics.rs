//! C248 failure-only diagnostics. Never echo an HTTP body, arbitrary error
//! string, token, key, URL, request payload or private state document.
use serde_json::{Value, json};
use std::{fs, io::Read, path::Path};

#[derive(Default)]
pub(crate) struct Observation {
    pub(crate) stage: &'static str,
    pub(crate) status: Option<u16>,
    body_bytes: Option<usize>,
    code: Option<&'static str>,
    execution: Option<&'static str>,
    retryable: Option<bool>,
    retry_after_ms: Option<u64>,
}

impl Observation {
    pub(crate) fn response(&mut self, body: &[u8]) {
        self.body_bytes = Some(body.len());
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            return;
        };
        // Closed labels: a response body cannot smuggle arbitrary text into
        // CI output by putting it in an otherwise plausible metadata field.
        self.code = match value["code"].as_str() {
            Some("PEER_UNAVAILABLE") => Some("PEER_UNAVAILABLE"),
            Some("PEER_UNTRUSTED") => Some("PEER_UNTRUSTED"),
            Some("CLUSTER_UNREADY") => Some("CLUSTER_UNREADY"),
            Some("AUTHORIZATION_UNAVAILABLE") => Some("AUTHORIZATION_UNAVAILABLE"),
            Some("AUTHORIZATION_STALE") => Some("AUTHORIZATION_STALE"),
            Some("AUTHORIZATION_EXPIRED") => Some("AUTHORIZATION_EXPIRED"),
            Some("AUTHORIZATION_REVOKED") => Some("AUTHORIZATION_REVOKED"),
            Some("UNAUTHORIZED") => Some("UNAUTHORIZED"),
            Some("FORBIDDEN") => Some("FORBIDDEN"),
            Some("NOT_FOUND") => Some("NOT_FOUND"),
            Some("RESOURCE_EXHAUSTED") => Some("RESOURCE_EXHAUSTED"),
            Some("STREAM_LIMIT") => Some("STREAM_LIMIT"),
            Some("ADMISSION_LIMIT") => Some("ADMISSION_LIMIT"),
            Some("CONTROL_LIMIT") => Some("CONTROL_LIMIT"),
            Some("CONTROL_UNAVAILABLE") => Some("CONTROL_UNAVAILABLE"),
            Some("BODY_LIMIT") => Some("BODY_LIMIT"),
            Some("FRAME_LIMIT") => Some("FRAME_LIMIT"),
            Some("STREAM_NOT_FOUND") => Some("STREAM_NOT_FOUND"),
            Some("ROTATION_FREEZE") => Some("ROTATION_FREEZE"),
            Some("OWNER_CHANGED") => Some("OWNER_CHANGED"),
            Some("OWNER_UNAVAILABLE") => Some("OWNER_UNAVAILABLE"),
            Some("OWNER_FENCING_REQUIRED") => Some("OWNER_FENCING_REQUIRED"),
            Some("OWNER_AUTHORITY_UNKNOWN") => Some("OWNER_AUTHORITY_UNKNOWN"),
            Some("DEVICE_OFFLINE") => Some("DEVICE_OFFLINE"),
            Some("DEVICE_UNAVAILABLE") => Some("DEVICE_UNAVAILABLE"),
            Some("REVERSE_CHANNEL_UNAVAILABLE") => Some("REVERSE_CHANNEL_UNAVAILABLE"),
            Some("REVERSE_CHANNEL_INTERRUPTED") => Some("REVERSE_CHANNEL_INTERRUPTED"),
            Some("OPEN_ADMISSION_TIMEOUT") => Some("OPEN_ADMISSION_TIMEOUT"),
            Some("SERVICE_NOT_FOUND") => Some("SERVICE_NOT_FOUND"),
            Some("SERVICE_AMBIGUOUS") => Some("SERVICE_AMBIGUOUS"),
            Some("METHOD_NOT_ALLOWED") => Some("METHOD_NOT_ALLOWED"),
            Some("BAD_REQUEST") => Some("BAD_REQUEST"),
            Some(_) => Some("unrecognized"),
            None => None,
        };
        self.execution = match value["execution"].as_str() {
            Some("not_dispatched") => Some("not_dispatched"),
            Some("completed") => Some("completed"),
            Some("unknown") => Some("unknown"),
            Some(_) => Some("unrecognized"),
            None => None,
        };
        self.retryable = value["retryable"].as_bool();
        self.retry_after_ms = value["retry_after_ms"].as_u64();
    }

    pub(crate) fn event(
        &self,
        phase: &'static str,
        elapsed_ms: u128,
        reason: &'static str,
    ) -> Value {
        json!({"phase": phase, "stage": self.stage, "elapsed_ms": elapsed_ms,
            "failure": reason, "http_status": self.status, "body_bytes": self.body_bytes,
            "code": self.code, "execution": self.execution, "retryable": self.retryable,
            "retry_after_ms": self.retry_after_ms})
    }
}

pub(crate) fn bounded_json(path: &Path, maximum: usize) -> Option<Value> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > maximum {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

pub(crate) fn authority_counters(state: Option<Value>) -> Value {
    let Some(state) = state else {
        return json!({"available": false});
    };
    let expires = state["confirmed"]["expires_at"]
        .as_str()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.timestamp_millis() - chrono::Utc::now().timestamp_millis());
    json!({"available": true,
        "membership_high_water": state["membership_high_water"].as_u64(),
        "checkpoint_high_water": state["checkpoint_high_water"].as_u64(),
        "confirmed_version": state["confirmed"]["membership_version"].as_u64(),
        "confirmed_remaining_ms": expires})
}

pub(crate) fn relay_counters(state: Option<Value>) -> Value {
    let Some(state) = state else {
        return json!({"available": false});
    };
    let state = &state["state"];
    json!({"available": true, "checkpoint_version": state["checkpoint_version"].as_u64(),
        "node_versions": {"relay-a": state["node_versions"]["relay-a"].as_u64(),
            "relay-b": state["node_versions"]["relay-b"].as_u64(),
            "relay-c": state["node_versions"]["relay-c"].as_u64()}})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_response_retains_typed_cause_without_body_or_arbitrary_labels() {
        let mut observed = Observation {
            stage: "response_assert",
            status: Some(503),
            ..Default::default()
        };
        observed.response(br#"{"code":"PEER_UNAVAILABLE","execution":"not_dispatched","retryable":true,"retry_after_ms":250,"message":"synthetic-private-body","token":"synthetic-private-token"}"#);
        let event = observed.event(
            "continuous-two-publication-refreshes",
            17,
            "non-owner public canary was refused",
        );
        assert_eq!(event["code"], "PEER_UNAVAILABLE");
        assert_eq!(event["http_status"], 503);
        assert_eq!(event["execution"], "not_dispatched");
        assert_eq!(event["retry_after_ms"], 250);
        assert!(!event.to_string().contains("synthetic-private"));
        observed.response(br#"{"code":"CLUSTER_UNREADY","execution":"not_dispatched"}"#);
        assert_eq!(
            observed.event(
                "continuous-two-publication-refreshes",
                18,
                "non-owner public canary was refused"
            )["code"],
            "CLUSTER_UNREADY"
        );
        observed.response(
            br#"{"code":"synthetic-private-code","execution":"synthetic-private-execution"}"#,
        );
        let event = observed.event(
            "initial-public-through-relay-a",
            18,
            "non-owner public canary was refused",
        );
        assert_eq!(event["code"], "unrecognized");
        assert_eq!(event["execution"], "unrecognized");
        assert!(!event.to_string().contains("synthetic-private"));
    }

    #[test]
    fn private_state_projection_emits_only_numeric_counters() {
        let state = json!({"membership_high_water": 7, "checkpoint_high_water": 9,
            "inventory": {"secret": "synthetic-private-inventory"}, "confirmed": {"membership_version": 6},
            "state": {"checkpoint_version": 8, "node_versions": {"relay-a": 6, "relay-b": 6,
                "relay-c": 6, "synthetic-private-node": 100}, "secret": "synthetic-private-state"}});
        let authority = authority_counters(Some(state.clone()));
        let relay = relay_counters(Some(state));
        assert_eq!(authority["membership_high_water"], 7);
        assert_eq!(relay["checkpoint_version"], 8);
        assert!(!format!("{authority}{relay}").contains("synthetic-private"));
        assert_eq!(authority_counters(None)["available"], false);
        assert_eq!(relay_counters(None)["available"], false);
    }
}
