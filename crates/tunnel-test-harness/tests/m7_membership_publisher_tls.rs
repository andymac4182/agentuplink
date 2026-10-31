//! M6-C231: operator publishing uses explicit Redis TLS and a restricted ACL.
#![cfg(unix)]

use std::{env, time::Duration};
use tunnel_catalog::{Catalog, RedisCatalog, RedisMembershipPublisher, RedisTlsOptions};
use tunnel_test_harness::{ClusterFixture, FixturePki};
use tunnel_transport::load_server_config_from_pem;
use uuid::Uuid;

#[path = "common/m7_deployment.rs"]
mod common;
use common::{RedisTlsProxy, parse_plaintext_upstream};

type TestResult = Result<(), &'static str>;

#[tokio::test]
#[ignore = "requires disposable loopback TEST_REDIS_URL with ACL administration"]
async fn publisher_tls_authenticates_and_cannot_write_other_catalog_keys() {
    let upstream_url = env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL is required");
    let upstream = parse_plaintext_upstream(&upstream_url).unwrap();
    let suffix = Uuid::new_v4().simple().to_string();
    let namespace = format!("test-publisher-tls-{suffix}");
    let username = format!("publisher-{suffix}");
    let password = Uuid::new_v4().simple().to_string();
    let client = redis::Client::open(upstream_url.as_str()).expect("admin client");
    let mut admin = client
        .get_multiplexed_async_connection()
        .await
        .expect("admin connection");
    let _: () = redis::cmd("ACL")
        .arg("SETUSER")
        .arg(&username)
        .arg("reset")
        .arg("on")
        .arg(format!(">{password}"))
        .arg(format!("~tunnel-catalog:{namespace}:membership:operator:*"))
        .arg(&[
            "+ping", "+info", "+eval", "+hget", "+hlen", "+hset", "+expire",
        ])
        .query_async(&mut admin)
        .await
        .expect("create isolated publisher ACL");

    // The task join captures test panics as well as ordinary errors so cleanup
    // still removes only this test's user and namespace on every outcome.
    let run_namespace = namespace.clone();
    let run_username = username.clone();
    let run = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(30), async {
            let pki = FixturePki::new().map_err(|_| "fixture PKI")?;
            let wrong_pki = FixturePki::new().map_err(|_| "foreign fixture PKI")?;
            let cluster = ClusterFixture::new(&pki).map_err(|_| "membership fixture")?;
            let record = cluster
                .membership("relay-a")
                .ok_or("missing fixture member")?
                .catalog_record();
            let leaf = pki
                .issue_server("publisher-redis")
                .map_err(|_| "Redis server leaf")?;
            let identity = pki
                .issue_peer("publisher-client")
                .map_err(|_| "Redis client leaf")?;
            let tls = load_server_config_from_pem(
                leaf.certificate_pem.as_bytes(),
                leaf.private_key_pem.as_bytes(),
                Some(pki.peer_ca.certificate_pem.as_bytes()),
            )
            .map_err(|_| "Redis server TLS")?;
            let proxy = RedisTlsProxy::bind(upstream, tls)
                .await
                .map_err(|_| "Redis TLS proxy")?;
            let url = proxy.url().replacen(
                "rediss://",
                &format!("rediss://{run_username}:{password}@"),
                1,
            );
            let options =
                RedisTlsOptions::with_root_cert_pem(pki.server_ca.certificate_pem.as_bytes())
                    .with_client_identity_pem(
                        identity.certificate_pem.as_bytes(),
                        identity.private_key_pem.as_bytes(),
                    );
            let publisher =
                RedisMembershipPublisher::connect_with_tls(&url, &run_namespace, options.clone())
                    .await
                    .map_err(|_| "authenticated publisher connection")?;
            publisher
                .publish_signed_membership_for_node("relay-a", &record)
                .await
                .map_err(|_| "restricted publisher membership update")?;
            let reader = RedisCatalog::connect(&upstream_url, &run_namespace)
                .await
                .map_err(|_| "catalog reader")?;
            let stored = reader
                .read_signed_memberships()
                .await
                .map_err(|_| "catalog membership read")?;
            if stored.len() != 1 || stored[0] != record {
                return Err("published canonical membership did not round trip");
            }

            // Same credentials and allowed HSET command; the key scope itself
            // must prevent writes outside the membership operator directory.
            let raw = redis::Client::build_with_tls(
                url.as_str(),
                redis::TlsCertificates {
                    client_tls: Some(redis::ClientTlsConfig {
                        client_cert: identity.certificate_pem.as_bytes().to_vec(),
                        client_key: identity.private_key_pem.as_bytes().to_vec(),
                    }),
                    root_cert: Some(pki.server_ca.certificate_pem.as_bytes().to_vec()),
                },
            )
            .map_err(|_| "restricted raw client")?;
            let mut restricted = raw
                .get_multiplexed_async_connection()
                .await
                .map_err(|_| "restricted raw connection")?;
            let denied: redis::RedisResult<i64> = redis::cmd("HSET")
                .arg(format!("tunnel-catalog:{run_namespace}:unauthorized"))
                .arg("field")
                .arg("synthetic")
                .query_async(&mut restricted)
                .await;
            if !denied.is_err_and(|error| error.code() == Some("NOPERM")) {
                return Err("publisher ACL allowed an unrelated catalog write");
            }

            let mut wrong_trust = options.clone();
            wrong_trust.root_cert_pem =
                Some(wrong_pki.server_ca.certificate_pem.as_bytes().to_vec());
            for (candidate_url, candidate_options) in [
                (url.clone(), wrong_trust),
                (url.replace("localhost", "127.0.0.1"), options.clone()),
                (
                    url.replace(&password, "incorrect-synthetic-password"),
                    options.clone(),
                ),
                (
                    url.clone(),
                    RedisTlsOptions::with_root_cert_pem(pki.server_ca.certificate_pem.as_bytes()),
                ),
                (url.replacen("rediss://", "redis://", 1), options),
            ] {
                if RedisMembershipPublisher::connect_with_tls(
                    &candidate_url,
                    &run_namespace,
                    candidate_options,
                )
                .await
                .is_ok()
                {
                    return Err("invalid publisher transport or credentials were accepted");
                }
            }
            drop(restricted);
            drop(publisher);
            drop(reader);
            proxy
                .shutdown()
                .await
                .map_err(|_| "Redis TLS proxy shutdown")?;
            Ok(())
        })
        .await
        .map_err(|_| "publisher TLS gate exceeded 30 seconds")?
    });
    let result: Result<TestResult, _> = run.await;
    let cleanup_keys: redis::RedisResult<i64> = redis::cmd("DEL")
        .arg(format!(
            "tunnel-catalog:{namespace}:membership:operator:directory"
        ))
        .arg(format!("tunnel-catalog:{namespace}:unauthorized"))
        .query_async(&mut admin)
        .await;
    let cleanup_user: redis::RedisResult<i64> = redis::cmd("ACL")
        .arg("DELUSER")
        .arg(&username)
        .query_async(&mut admin)
        .await;
    cleanup_keys.expect("remove test-owned keys");
    assert_eq!(cleanup_user.expect("remove test-owned ACL user"), 1);
    result
        .expect("publisher test task")
        .expect("publisher TLS acceptance");
}
