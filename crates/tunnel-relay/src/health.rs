//! Bounded, redacted relay health endpoints.
//!
//! Liveness answers whether the HTTP process can answer a request. Readiness
//! is owned by the cluster membership provider on a cluster relay, and by the
//! cached Redis authority state ([`crate::authority_readiness`], task row
//! M6-C67) on a relay without `[cluster]`; either is allowed to fail closed
//! while liveness remains available. Every relay `serve` starts also follows
//! its clock offset from Redis ([`crate::clock_offset`], M7-C175): an offset
//! beyond the cluster clock-skew bound is not ready. Neither endpoint exposes membership
//! records, endpoints, pins, tenant identifiers, or backend error details, and
//! neither reaches Redis while answering.

use std::sync::Arc;

use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;

use crate::{
    authority_readiness::AuthorityReadiness, clock_offset::ClockOffsetHealth,
    peer_runtime::PeerRuntime,
};

/// The background readiness checks besides the peer runtime, each only when
/// the relay runs it.
#[derive(Clone, Default)]
pub(crate) struct ReadinessChecks {
    /// A single relay's Redis authority state (M6-C67).
    pub(crate) authority: Option<Arc<AuthorityReadiness>>,
    /// The relay's clock offset from Redis (M7-C175).
    pub(crate) clock: Option<Arc<ClockOffsetHealth>>,
}

const LIVE_STATUS: &str = "live";
const READY_STATUS: &str = "ready";
const UNREADY_STATUS: &str = "unready";

#[derive(Serialize)]
struct HealthBody {
    status: &'static str,
}

/// Build the public, bounded liveness/readiness endpoints.
///
/// The optional peer runtime is the existing cluster startup seam. The
/// optional authority state is a single relay's (`serve` without `[cluster]`,
/// M6-C67): it is ready only while its last bounded Redis authority check
/// succeeded recently.  A library relay with neither is ready once its HTTP
/// actor is serving.
pub(crate) fn router<S>(peer: Option<Arc<PeerRuntime>>, checks: ReadinessChecks) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let readiness_peer = peer;
    Router::<S>::new()
        .route("/livez", get(|| async { livez() }))
        .route(
            "/readyz",
            get(move || {
                let peer = readiness_peer.clone();
                let checks = checks.clone();
                async move { ready_response(relay_ready(peer.as_ref(), &checks)) }
            }),
        )
}

/// The one readiness decision `/readyz` answers and the private metrics
/// listener reports: the peer runtime's (cluster), the Redis authority's
/// (single relay, M6-C67) and the clock offset's (M7-C175), each only when
/// present.
pub(crate) fn relay_ready(peer: Option<&Arc<PeerRuntime>>, checks: &ReadinessChecks) -> bool {
    peer.is_none_or(|runtime| runtime.is_ready())
        && checks
            .authority
            .as_ref()
            .is_none_or(|state| state.is_ready())
        && checks.clock.as_ref().is_none_or(|state| state.is_ready())
}

/// Return a process-only liveness response. This must not consult Redis,
/// membership, owner routing, or any other external authority.
pub(crate) fn livez() -> Response {
    (
        StatusCode::OK,
        Json(HealthBody {
            status: LIVE_STATUS,
        }),
    )
        .into_response()
}

/// Return a redacted readiness response from the caller-provided state.
pub(crate) fn ready_response(ready: bool) -> Response {
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = if ready { READY_STATUS } else { UNREADY_STATUS };
    (status, Json(HealthBody { status: body })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn liveness_is_always_ok() {
        assert_eq!(livez().status(), StatusCode::OK);
    }

    #[test]
    fn readiness_fails_closed_without_leaking_a_reason() {
        assert_eq!(
            ready_response(false).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(ready_response(true).status(), StatusCode::OK);
    }
}
