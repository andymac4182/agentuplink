//! Regression for task row M6-C180: a unary echo whose connector challenge
//! arrives more than five seconds after admission -- the device was stopped
//! or slow -- must be authorized by a fresh catalog read, not refused as
//! revoked.
//!
//! The catalog bounds a grant read to five seconds from its read start
//! (`valid_until = read_started_at + 5 s`, in Redis and in the memory
//! catalog alike).  The relay used the **admission** read's start for the
//! challenge's dispatch read, so any challenge later than that came back
//! `None` ("grant unavailable") and the consumer was answered
//! `AUTHORIZATION_REVOKED` although nothing was revoked.  Hosted chaos saw it
//! after a 10 s SIGSTOP; a local probe reproduced it after 10 s and 15 s
//! stops.  Elapsed time is simulated by moving the admission read's start
//! back, so the test needs no wall-clock sleep.

use std::sync::Arc;

use chrono::{Duration, Utc};
use tokio::sync::{mpsc, oneshot};
use tunnel_catalog::{AuthenticatedConsumer, Catalog, MemoryCatalog};
use tunnel_protocol::{AuthorizationChallenge, ControlMessage};

use super::{
    Command, ControlOutbound, DataCarrier, DispatchRequest, SessionKey, SharedCatalog,
    runtime::CarrierContext,
    stream_identity_tests::{admitted_control_actor, shared_device_fixture},
    wire,
};

#[tokio::test]
async fn m6c180_a_unary_challenge_after_the_admission_read_bound_is_authorized_fresh() {
    let (fixture, device_id, tenant_id, _tenant_b, spki, _spki_b) = shared_device_fixture();
    let catalog = MemoryCatalog::new();
    catalog.seed_fixture(&fixture).await.expect("seed fixture");
    let identity = catalog
        .resolve_device(&spki, Utc::now())
        .await
        .expect("resolve device")
        .expect("device identity");
    let principal_id = identity.owner_user_id;
    let service_id = fixture.services[0].service_id;
    let consumer = AuthenticatedConsumer {
        tenant_id,
        principal_id,
    };
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
    actor.catalog = Arc::new(catalog) as SharedCatalog;
    let (data_tx, _data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
    {
        let session = actor.sessions.get_mut(&key.scope()).expect("session");
        session.profile = super::RuntimeProfile::M2;
        session.data_tx = Some(data_tx.clone());
        session.active_carrier = Some(DataCarrier {
            context: CarrierContext::new(key.session_id.clone(), key.epoch, 1, "m6c180".to_owned()),
            tx: data_tx,
        });
    }
    let (response, _response_rx) = oneshot::channel();
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
    let stream_id = 1;
    // The device answers six seconds after admission: past the admission
    // read's five-second bound.
    actor
        .sessions
        .get_mut(&key.scope())
        .and_then(|session| session.pending.get_mut(&stream_id))
        .expect("pending unary echo")
        .grant
        .read_started_at = grant.read_started_at - Duration::seconds(6);
    while let Ok(item) = registration.rx.try_recv() {
        if let ControlOutbound::Text(mut text) = item {
            text.release();
        }
    }

    actor.begin_device_challenge(
        key.clone(),
        AuthorizationChallenge::new(
            "m6c180-auth",
            key.session_id.clone(),
            key.epoch,
            stream_id,
            "m6c180-challenge",
            "m6c180-nonce",
            service_id.to_string(),
            wire::permission_digest(&grant, &service_id.to_string()),
            grant.revision,
        ),
    );
    let command = tokio::time::timeout(std::time::Duration::from_secs(5), actor.rx.recv())
        .await
        .expect("the challenge's authorization read completes")
        .expect("command channel open");
    let Command::ChallengeAuthorized { result, .. } = command else {
        panic!("expected the challenge's authorization result");
    };
    let (current, _owner, _identity, _owner_deadline) =
        (*result).expect("the authorization read succeeds");
    let current = current.expect(
        "a challenge arriving after the admission read's bound must be authorized by a fresh \
         read, not refused as revoked (M6-C180)",
    );
    assert_eq!(current.revision, grant.revision);
    assert!(
        current.valid_until > Utc::now(),
        "the fresh read carries a live validity window"
    );
    // Nothing was refused on the way.
    assert!(
        !std::iter::from_fn(|| registration.rx.try_recv().ok()).any(|item| matches!(
            item,
            ControlOutbound::Text(ref text)
                if matches!(
                    wire::parse_control(text.as_bytes()),
                    Ok(ControlMessage::AuthorizationInvalidated(_))
                )
        )),
        "no AUTHORIZATION_INVALIDATED may be queued"
    );
}
