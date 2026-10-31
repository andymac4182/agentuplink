//! M4-70: a missed freshness window is retryable; actual authority loss is not.
//! These tests finish a real admitted filesystem stream challenge and inspect
//! the same reset watch and close-code mapper used by the consumer route.

use std::{collections::BTreeSet, time::Instant};

use chrono::{Duration, Utc};
use tokio::sync::{mpsc, oneshot};
use tunnel_catalog::{
    AuthenticatedConsumer, DeviceIdentity, GrantSnapshot, OwnerClaim, PermissionSet,
};
use uuid::Uuid;

use super::{
    DataCarrier, DeviceChallenge, EchoOutcome, RuntimeProfile, SessionKey, StreamAdmissionReply,
    runtime::CarrierContext, stream_identity_tests::admitted_control_actor,
};

#[derive(Clone, Copy, Debug)]
enum Case {
    Live,
    Window,
    Owner,
    Token,
    Snapshot,
    Credential,
    Revoked,
    Revision,
    Unavailable,
    WindowAndToken,
    OwnerAndToken,
}

async fn check(case: Case, expected_reason: Option<u16>, expected_close: Option<u16>) {
    let now = Utc::now();
    let tenant_id = Uuid::from_u128(7071);
    let device_id = Uuid::from_u128(7072);
    let principal_id = Uuid::from_u128(7073);
    let service_id = Uuid::from_u128(7074);
    let mut identity = DeviceIdentity {
        tenant_id,
        device_id,
        owner_user_id: principal_id,
        credential_id: Uuid::from_u128(7075),
        spki_fingerprint: "m4c70-synthetic-spki".into(),
        credential_not_before: now - Duration::minutes(1),
        expires_at: now + Duration::minutes(1),
        credential_revoked_at: None,
        device_active: true,
        credential_active: true,
        device_version: 1,
        owner_epoch: 1,
        last_seen_at: Some(now),
    };
    let grant = GrantSnapshot {
        tenant_id,
        principal_id,
        device_id,
        service_id,
        revision: 1,
        permissions: PermissionSet {
            operations: BTreeSet::from([crate::FS_SESSION_OPERATION.to_owned()]),
        },
        constraints: serde_json::json!({}),
        valid_until: now + Duration::minutes(1),
        read_started_at: now,
    };
    let key = SessionKey {
        tenant_id,
        device_id,
        session_id: format!("m4c70-{case:?}"),
        epoch: 1,
    };
    let (mut actor, mut control) = admitted_control_actor(identity.clone(), key.clone());
    let (data_tx, _data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
    let session = actor.sessions.get_mut(&key.scope()).expect("session");
    session.profile = RuntimeProfile::M2;
    session.data_tx = Some(data_tx.clone());
    session.active_carrier = Some(DataCarrier {
        context: CarrierContext::new(key.session_id.clone(), key.epoch, 1, "m4c70-data"),
        tx: data_tx,
    });
    let (open_tx, open_rx) = oneshot::channel();
    actor.open_consumer_stream(
        AuthenticatedConsumer {
            tenant_id,
            principal_id,
        },
        device_id,
        service_id,
        grant.clone(),
        now + Duration::minutes(1),
        None,
        StreamAdmissionReply::Fs {
            response: open_tx,
            capabilities: "read,list".into(),
        },
    );
    let registration = open_rx.await.expect("reply").expect("filesystem admitted");
    drop(control.rx.try_recv().expect("OPEN queued"));
    let stream_id = registration.base.stream_id;
    let challenge_id = "m4c70-challenge";
    {
        let stream = actor
            .sessions
            .get_mut(&key.scope())
            .expect("session")
            .streams
            .get_mut(&stream_id)
            .expect("stream");
        stream.open_pending = false;
        stream.authorization_in_flight = true;
        stream.challenge_id = Some(challenge_id.into());
        if matches!(
            case,
            Case::Token | Case::WindowAndToken | Case::OwnerAndToken
        ) {
            stream.consumer_expires_at = now - Duration::seconds(1);
        }
    }
    let mut current = grant.clone();
    if matches!(case, Case::Snapshot) {
        current.valid_until = now - Duration::seconds(1);
    }
    if matches!(case, Case::Credential) {
        identity.expires_at = now - Duration::seconds(1);
    }
    if matches!(case, Case::Revision) {
        current.revision += 1;
    }
    let owner = OwnerClaim {
        token: actor.sessions[&key.scope()].owner.clone(),
        lease_expires_at: now + Duration::minutes(1),
    };
    let mono = Instant::now();
    let owner_deadline = if matches!(case, Case::Owner | Case::OwnerAndToken) {
        mono - std::time::Duration::from_secs(1)
    } else {
        mono + std::time::Duration::from_secs(60)
    };
    let result = if matches!(case, Case::Unavailable) {
        Err("synthetic catalog outage".into())
    } else {
        Ok((
            (!matches!(case, Case::Revoked)).then_some(current),
            Some(owner),
            Some(identity),
            Some(owner_deadline),
        ))
    };
    let (pending_tx, pending_rx) = oneshot::channel();
    let (dispatched_tx, dispatched_rx) = oneshot::channel();
    if !matches!(case, Case::Live) {
        let stream = actor
            .sessions
            .get_mut(&key.scope())
            .unwrap()
            .streams
            .get_mut(&stream_id)
            .unwrap();
        stream.pending_records.push_back((Vec::new(), pending_tx));
        stream.response_records.push_back(dispatched_tx);
    }
    actor.finish_stream_challenge(
        key.clone(),
        DeviceChallenge {
            message_id: "m4c70-message".into(),
            stream_id,
            service_id: service_id.to_string(),
            challenge_id: challenge_id.into(),
            nonce: "m4c70-nonce".into(),
            permission_digest: super::wire::permission_digest(&grant, &service_id.to_string()),
            grant_revision: grant.revision,
            received_at: if matches!(case, Case::Window | Case::WindowAndToken) {
                mono - std::time::Duration::from_secs(3)
            } else {
                mono
            },
            lifetime: std::time::Duration::from_secs(2),
        },
        result,
    );
    let observed = registration.peer_reset.borrow().map(|reset| reset.reason);
    assert_eq!(
        observed, expected_reason,
        "{case:?}: exact published reason"
    );
    if let Some(code) = expected_close {
        assert!(
            registration.base.closed.is_cancelled(),
            "{case:?}: stream closed"
        );
        let stream = &actor.sessions[&key.scope()].streams[&stream_id];
        assert!(stream.terminal);
        assert!(stream.pending_records.is_empty() && stream.response_records.is_empty());
        assert_eq!(stream.orphaned_response_records, 1);
        let expected_outcome = if matches!(case, Case::Window) {
            "AUTHORIZATION_STALE"
        } else {
            "AUTHORIZATION_REVOKED"
        };
        for (receiver, expected_execution) in
            [(pending_rx, "not_dispatched"), (dispatched_rx, "unknown")]
        {
            match receiver.await.expect("waiter answered") {
                Err(EchoOutcome::Failure { code, execution }) => {
                    assert_eq!(code, expected_outcome, "{case:?}");
                    assert_eq!(execution, expected_execution, "{case:?}");
                }
                other => panic!("{case:?}: expected failure, got {other:?}"),
            }
        }
        let terminal = actor
            .stream_terminal_events
            .back()
            .expect("retained terminal");
        assert_eq!(
            terminal.reason, expected_outcome,
            "{case:?}: terminal reason"
        );
        assert_eq!(
            terminal.authorization_failure_code,
            stream.authorization_failure_code
        );
        assert_eq!(
            stream.authorization_failure_code,
            Some(match case {
                Case::Window => "AUTHORIZATION_STALE",
                Case::Owner => "OWNER_UNAVAILABLE",
                Case::Unavailable => "AUTHORIZATION_UNAVAILABLE",
                Case::Revoked => "GRANT_UNAVAILABLE",
                Case::Snapshot | Case::Credential | Case::Revision => "AUTHORIZATION_CHANGED",
                _ => "AUTHORIZATION_EXPIRED",
            })
        );
        assert_eq!(
            super::http::fs::session_close_code_for_reset(observed),
            Some(code),
            "{case:?}"
        );
    } else {
        assert!(!registration.base.closed.is_cancelled());
        let stream = &actor.sessions[&key.scope()].streams[&stream_id];
        assert!(!stream.terminal && !stream.authorization_in_flight);
        assert!(stream.authorized_until.is_some());
    }
}

#[tokio::test]
async fn m4c70_window_only_lapse_is_retryable() {
    check(Case::Window, Some(4_006), Some(1011)).await;
}
#[tokio::test]
async fn m4c70_owner_only_lapse_is_retryable() {
    check(Case::Owner, None, Some(1011)).await;
}
#[tokio::test]
async fn m4c70_token_expiry_remains_terminal() {
    check(Case::Token, Some(4_001), Some(1008)).await;
}
#[tokio::test]
async fn m4c70_snapshot_expiry_remains_terminal() {
    check(Case::Snapshot, Some(4_001), Some(1008)).await;
}
#[tokio::test]
async fn m4c70_credential_expiry_remains_terminal() {
    check(Case::Credential, Some(4_001), Some(1008)).await;
}
#[tokio::test]
async fn m4c70_revoked_grant_remains_terminal() {
    check(Case::Revoked, Some(4_001), Some(1008)).await;
}
#[tokio::test]
async fn m4c70_revision_change_remains_terminal() {
    check(Case::Revision, Some(4_001), Some(1008)).await;
}
#[tokio::test]
async fn m4c70_catalog_failure_remains_retryable() {
    check(Case::Unavailable, None, Some(1011)).await;
}
#[tokio::test]
async fn m4c70_live_challenge_still_confirms() {
    check(Case::Live, None, None).await;
}
#[tokio::test]
async fn m4c70_expired_token_beats_window_lapse() {
    check(Case::WindowAndToken, Some(4_001), Some(1008)).await;
}
#[tokio::test]
async fn m4c70_expired_token_beats_owner_lapse() {
    check(Case::OwnerAndToken, Some(4_001), Some(1008)).await;
}
