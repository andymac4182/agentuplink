//! Regressions for task row M6-C180: a unary echo whose connector challenge
//! arrives more than five seconds after admission -- the device was stopped
//! or slow -- must be authorized by a fresh catalog read: not refused as
//! revoked when nothing changed, and still refused when the grant really was
//! revoked in the meantime.
//!
//! The catalog bounds a grant read to five seconds from its read start
//! (`valid_until = read_started_at + 5 s`, in Redis and in the memory
//! catalog alike).  The relay used the **admission** read's start for the
//! challenge's dispatch read, so any challenge later than that came back
//! `None` ("grant unavailable") and the consumer was answered
//! `AUTHORIZATION_REVOKED` although nothing was revoked.  Hosted chaos saw it
//! after a 10 s SIGSTOP; a local probe reproduced it after 10 s and 15 s
//! stops.  Elapsed time is simulated by moving the admission read's start
//! back, so the tests need no wall-clock sleep.

use std::sync::Arc;

use chrono::{Duration, Utc};
use tokio::sync::{mpsc, oneshot};
use tunnel_catalog::{AuthenticatedConsumer, Catalog, GrantSnapshot, MemoryCatalog};
use tunnel_protocol::{AuthorizationChallenge, ControlMessage};
use uuid::Uuid;

use super::{
    Command, ControlOutbound, DataCarrier, DispatchRequest, EchoOutcome, RelayActor, SessionKey,
    SharedCatalog,
    runtime::CarrierContext,
    stream_identity_tests::{admitted_control_actor, shared_device_fixture},
    wire,
};

const STREAM_ID: u64 = 1;

struct Admitted {
    actor: RelayActor,
    control_rx: mpsc::Receiver<ControlOutbound>,
    _data_rx: mpsc::Receiver<super::DataOutbound>,
    response_rx: oneshot::Receiver<EchoOutcome>,
    catalog: MemoryCatalog,
    consumer: AuthenticatedConsumer,
    grant: GrantSnapshot,
    service_id: Uuid,
    key: SessionKey,
}

fn control_messages(rx: &mut mpsc::Receiver<ControlOutbound>) -> Vec<ControlMessage> {
    let mut messages = Vec::new();
    while let Ok(item) = rx.try_recv() {
        if let ControlOutbound::Text(mut text) = item {
            messages.push(wire::parse_control(text.as_bytes()).expect("control decodes"));
            text.release();
        }
    }
    messages
}

/// A unary echo admitted on an M2 session and answered by no challenge yet,
/// whose admission read is six seconds old: past the catalog's bound.
async fn admitted_six_seconds_ago() -> Admitted {
    let (fixture, device_id, tenant_id, _tenant_b, spki, _spki_b) = shared_device_fixture();
    let catalog = MemoryCatalog::new();
    catalog.seed_fixture(&fixture).await.expect("seed fixture");
    let identity = catalog
        .resolve_device(&spki, Utc::now())
        .await
        .expect("resolve device")
        .expect("device identity");
    let consumer = AuthenticatedConsumer {
        tenant_id,
        principal_id: identity.owner_user_id,
    };
    let service_id = fixture.services[0].service_id;
    let now = Utc::now();
    let grant = catalog
        .authorize(&consumer, device_id, service_id, now, now)
        .await
        .expect("admission read")
        .expect("admission grant");
    let key = SessionKey {
        tenant_id,
        device_id,
        session_id: "m6c180-session".to_owned(),
        epoch: 1,
    };
    let (mut actor, mut registration) = admitted_control_actor(identity, key.clone());
    actor.catalog = Arc::new(catalog.clone()) as SharedCatalog;
    let (data_tx, data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
    {
        let session = actor.sessions.get_mut(&key.scope()).expect("session");
        session.profile = super::RuntimeProfile::M2;
        session.data_tx = Some(data_tx.clone());
        session.active_carrier = Some(DataCarrier {
            context: CarrierContext::new(key.session_id.clone(), key.epoch, 1, "m6c180".to_owned()),
            tx: data_tx,
        });
    }
    let (response, response_rx) = oneshot::channel();
    actor
        .dispatch_echo(DispatchRequest {
            consumer: consumer.clone(),
            device_id,
            service_id,
            grant: grant.clone(),
            body: b"m6c180-synthetic".to_vec(),
            consumer_expires_at: Utc::now() + Duration::minutes(5),
            response,
        })
        .await;
    actor
        .sessions
        .get_mut(&key.scope())
        .and_then(|session| session.pending.get_mut(&STREAM_ID))
        .expect("pending unary echo")
        .grant
        .read_started_at = grant.read_started_at - Duration::seconds(6);
    let _ = control_messages(&mut registration.rx);
    Admitted {
        actor,
        control_rx: registration.rx,
        _data_rx: data_rx,
        response_rx,
        catalog,
        consumer,
        grant,
        service_id,
        key,
    }
}

/// The device's challenge for the admitted echo, matching the admission
/// snapshot's revision and digest; returns the authorization read's result.
async fn challenge(admitted: &mut Admitted) -> Command {
    let challenge = AuthorizationChallenge::new(
        "m6c180-auth",
        admitted.key.session_id.clone(),
        admitted.key.epoch,
        STREAM_ID,
        "m6c180-challenge",
        "m6c180-nonce",
        admitted.service_id.to_string(),
        wire::permission_digest(&admitted.grant, &admitted.service_id.to_string()),
        admitted.grant.revision,
    );
    admitted
        .actor
        .begin_device_challenge(admitted.key.clone(), challenge);
    tokio::time::timeout(std::time::Duration::from_secs(5), admitted.actor.rx.recv())
        .await
        .expect("the challenge's authorization read completes")
        .expect("command channel open")
}

#[tokio::test]
async fn m6c180_a_unary_challenge_after_the_admission_read_bound_is_authorized_fresh() {
    let mut admitted = admitted_six_seconds_ago().await;
    let Command::ChallengeAuthorized { result, .. } = challenge(&mut admitted).await else {
        panic!("expected the challenge's authorization result");
    };
    let (current, _owner, _identity, _owner_deadline) =
        (*result).expect("the authorization read succeeds");
    let current = current.expect(
        "a challenge arriving after the admission read's bound must be authorized by a fresh \
         read, not refused as revoked (M6-C180)",
    );
    assert_eq!(current.revision, admitted.grant.revision);
    assert!(
        current.valid_until > Utc::now(),
        "the fresh read carries a live validity window"
    );
    assert!(
        !control_messages(&mut admitted.control_rx)
            .iter()
            .any(|message| matches!(message, ControlMessage::AuthorizationInvalidated(_))),
        "no AUTHORIZATION_INVALIDATED may be queued"
    );
}

/// The fresh read is still a read: a grant revoked between admission and a
/// challenge more than five seconds later is refused, never dispatched on
/// the strength of the admission snapshot.
#[tokio::test]
async fn m6c180_a_grant_revoked_before_a_late_unary_challenge_is_still_refused() {
    let mut admitted = admitted_six_seconds_ago().await;
    admitted
        .catalog
        .revoke_grant(
            admitted.consumer.tenant_id,
            admitted.consumer.principal_id,
            admitted.key.device_id,
            admitted.service_id,
            Utc::now(),
        )
        .await
        .expect("revoke the grant after admission");
    let Command::ChallengeAuthorized {
        key,
        challenge,
        result,
    } = challenge(&mut admitted).await
    else {
        panic!("expected the challenge's authorization result");
    };
    admitted
        .actor
        .finish_device_challenge(key, challenge, *result);

    match admitted.response_rx.try_recv() {
        Ok(EchoOutcome::Failure { code, execution }) => {
            assert_eq!(code, "AUTHORIZATION_REVOKED");
            assert_eq!(execution, "not_dispatched");
        }
        other => panic!("a revoked grant must refuse the late challenge: {other:?}"),
    }
    let messages = control_messages(&mut admitted.control_rx);
    assert!(
        messages.iter().any(|message| matches!(
            message,
            ControlMessage::AuthorizationInvalidated(invalidated)
                if invalidated.stream_id == STREAM_ID
                    // The refusal comes from the fresh grant read itself, not
                    // from a later check the fixture happens to fail.
                    && invalidated.reason == "grant unavailable"
        )),
        "the device must be sent AUTHORIZATION_INVALIDATED: {messages:?}"
    );
    assert!(
        !messages
            .iter()
            .any(|message| matches!(message, ControlMessage::AuthorizationConfirmed(_))),
        "a revoked grant must never be confirmed"
    );
    assert_eq!(admitted.actor.snapshot().lifetime_application_dispatches, 0);
}
