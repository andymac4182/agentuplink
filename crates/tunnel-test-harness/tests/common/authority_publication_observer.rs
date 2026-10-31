//! Passive, test-only publication evidence. This is not a trust source or a
//! substitute for the three real relays' signature/nonce verification.
use super::{GateResult, MembershipVersionState, SignedMembershipCheckpoint, require};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
};

pub const MAX_BYTES: usize = 256 * 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirmation {
    inventory_revision: u64,
    pub membership_version: u64,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    schema_version: u16,
    inventory: Value,
    expected_redis_run_id: String,
    pub membership_high_water: u64,
    pub checkpoint_high_water: u64,
    known_node_ids: BTreeSet<String>,
    pub confirmed: Option<Confirmation>,
}

#[derive(Clone, Copy)]
pub enum Mode<'a> {
    Steady,
    /// Engine::open clears confirmation before the listener starts. Only this
    /// declared restart transition may wait for None; its eventual publication
    /// must exceed the retained pre-restart allocation floor.
    RestartPending {
        before: &'a Observation,
    },
}

impl Observation {
    pub fn read(
        reader: impl Read,
        inventory: &Value,
        run: &str,
        now: DateTime<Utc>,
        previous: Option<&Self>,
        mode: Mode<'_>,
    ) -> GateResult<Self> {
        let mut bytes = Vec::new();
        reader
            .take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "read passive authority observation")?;
        require(
            bytes.len() <= MAX_BYTES,
            "authority observation exceeds byte bound",
        )?;
        let current: Self =
            serde_json::from_slice(&bytes).map_err(|_| "authority observation schema")?;
        let nodes = inventory["nodes"]
            .as_array()
            .ok_or("expected inventory nodes")?;
        let expected_nodes: BTreeSet<_> = nodes
            .iter()
            .map(|node| {
                node["node_id"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or("expected node identity")
            })
            .collect::<GateResult<_>>()?;
        require(
            current.schema_version == 1
                && current.inventory == *inventory
                && current.expected_redis_run_id == run
                && expected_nodes.len() == 3
                && current.known_node_ids == expected_nodes,
            "authority observation inventory/run binding mismatch",
        )?;
        if let Some(confirmed) = &current.confirmed {
            require(
                Some(confirmed.inventory_revision) == inventory["revision"].as_u64()
                    && confirmed.membership_version > 0
                    && confirmed.membership_version <= current.membership_high_water
                    && confirmed.expires_at > now
                    && confirmed.expires_at <= now + chrono::Duration::seconds(60),
                "authority observation confirmation is invalid or expired",
            )?;
            if let Mode::RestartPending { before } = mode {
                require(
                    confirmed.membership_version > before.membership_high_water,
                    "restart observer saw a pre-restart confirmation",
                )?;
            }
        }
        if let Some(previous) = previous {
            require(
                current.membership_high_water >= previous.membership_high_water
                    && current.checkpoint_high_water >= previous.checkpoint_high_water
                    && match (&previous.confirmed, &current.confirmed) {
                        (Some(old), Some(new)) => {
                            new.membership_version >= old.membership_version
                                && (new.membership_version != old.membership_version
                                    || new.expires_at == old.expires_at)
                        }
                        (Some(_), None) => matches!(mode, Mode::RestartPending { .. }),
                        _ => true,
                    },
                "authority observation rolled back or extended a fixed confirmation",
            )?;
        }
        Ok(current)
    }

    pub fn next_target(&self, previous: &Self) -> GateResult<Option<AdoptionTarget>> {
        let Some(confirmed) = &self.confirmed else {
            return Ok(None);
        };
        if confirmed.membership_version <= previous.membership_high_water {
            return Ok(None);
        }
        let checkpoint_version = self
            .checkpoint_high_water
            .checked_add(1)
            .ok_or("passive checkpoint adoption floor overflow")?;
        Ok(Some(AdoptionTarget {
            checkpoint_version,
            minimum_versions: self
                .known_node_ids
                .iter()
                .map(|node| (node.clone(), confirmed.membership_version))
                .collect(),
            expires_at: confirmed.expires_at,
        }))
    }
}

/// Unsigned observation target. Never encode this as a signed checkpoint or
/// give it to a runtime verifier. Each running relay verifies its own fresh
/// checkpoint and signed records before its durable fences can satisfy this.
pub struct AdoptionTarget {
    pub checkpoint_version: u64,
    pub minimum_versions: BTreeMap<String, u64>,
    pub expires_at: DateTime<Utc>,
}

impl From<&SignedMembershipCheckpoint> for AdoptionTarget {
    fn from(checkpoint: &SignedMembershipCheckpoint) -> Self {
        Self {
            checkpoint_version: checkpoint.checkpoint_version,
            minimum_versions: checkpoint.minimum_versions.clone(),
            expires_at: checkpoint.expires_at,
        }
    }
}

impl AdoptionTarget {
    pub fn adopted(&self, states: &[MembershipVersionState]) -> bool {
        states.len() == 3
            && states.iter().all(|state| {
                state
                    .checkpoint_version
                    .is_some_and(|version| version >= self.checkpoint_version)
                    && self.minimum_versions.iter().all(|(node, minimum)| {
                        state
                            .node_versions
                            .get(node)
                            .is_some_and(|version| version >= minimum)
                    })
            })
    }
}

/// Apply before constructing any observer request, including negative HTTP
/// tests. A serving relay already owns this node's single authority permit.
pub fn require_no_serving_relays(count: usize) -> GateResult {
    require(
        count == 0,
        "active relay forbids competing checkpoint observer HTTP",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture(now: DateTime<Utc>) -> Value {
        json!({"schema_version":1,"inventory":{"revision":2,"deployment_id":"d",
            "deployment_incarnation":"i","publisher_key_id":"p", "nodes":[
            {"node_id":"relay-a"},{"node_id":"relay-b"},{"node_id":"relay-c"}]},
            "expected_redis_run_id":"run", "membership_high_water":2,"checkpoint_high_water":8,
            "known_node_ids":["relay-a","relay-b","relay-c"],
            "confirmed":{"inventory_revision":2,"membership_version":2,
                "expires_at":now+chrono::Duration::seconds(55)}})
    }

    fn decode(
        value: &Value,
        expected: &Value,
        now: DateTime<Utc>,
        previous: Option<&Observation>,
    ) -> GateResult<Observation> {
        Observation::read(
            serde_json::to_vec(value).unwrap().as_slice(),
            &expected["inventory"],
            "run",
            now,
            previous,
            Mode::Steady,
        )
    }

    #[test]
    fn passive_observation_requires_exact_inventory_run_and_bounded_schema() {
        let now = Utc::now();
        let original = fixture(now);
        assert!(decode(&original, &original, now, None).is_ok());
        for (pointer, value) in [
            ("/schema_version", json!(2)),
            ("/inventory/deployment_id", json!("other")),
            ("/inventory/deployment_incarnation", json!("other")),
            ("/inventory/publisher_key_id", json!("other")),
            ("/inventory/nodes/0/node_id", json!("other")),
            ("/expected_redis_run_id", json!("other")),
            ("/known_node_ids", json!(["relay-a", "relay-b"])),
        ] {
            let mut invalid = original.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(decode(&invalid, &original, now, None).is_err(), "{pointer}");
        }
        assert!(
            Observation::read(
                vec![b' '; MAX_BYTES + 1].as_slice(),
                &original["inventory"],
                "run",
                now,
                None,
                Mode::Steady,
            )
            .is_err()
        );
        assert!(
            Observation::read(
                b"{}".as_slice(),
                &original["inventory"],
                "run",
                now,
                None,
                Mode::Steady
            )
            .is_err()
        );
    }

    #[test]
    fn passive_observation_rejects_unconfirmed_expired_extended_or_rolled_back_rounds() {
        let now = Utc::now();
        let original = fixture(now);
        let previous = decode(&original, &original, now, None).unwrap();
        for (pointer, value) in [
            ("/confirmed/inventory_revision", json!(1)),
            ("/confirmed/membership_version", json!(3)),
            ("/confirmed/expires_at", json!(now)),
            (
                "/confirmed/expires_at",
                json!(now + chrono::Duration::seconds(61)),
            ),
            ("/membership_high_water", json!(1)),
            ("/checkpoint_high_water", json!(7)),
            ("/confirmed/membership_version", json!(1)),
            ("/confirmed", Value::Null),
            (
                "/confirmed/expires_at",
                json!(now + chrono::Duration::seconds(56)),
            ),
        ] {
            let mut invalid = original.clone();
            *invalid.pointer_mut(pointer).unwrap() = value;
            assert!(
                decode(&invalid, &original, now, Some(&previous)).is_err(),
                "{pointer}"
            );
        }
        let mut pending = original.clone();
        pending["confirmed"] = Value::Null;
        let pending = decode(&pending, &original, now, None).unwrap();
        assert!(pending.next_target(&previous).unwrap().is_none());
        let mut spent = original.clone();
        spent["membership_high_water"] = json!(3);
        assert!(
            decode(&spent, &original, now, Some(&previous))
                .unwrap()
                .next_target(&previous)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn only_declared_restart_waits_for_cleared_confirmation_and_requires_a_new_round() {
        let now = Utc::now();
        let original = fixture(now);
        let before = decode(&original, &original, now, None).unwrap();
        let mode = Mode::RestartPending { before: &before };
        let read = |value: &Value, previous: &Observation| {
            Observation::read(
                serde_json::to_vec(value).unwrap().as_slice(),
                &original["inventory"],
                "run",
                now,
                Some(previous),
                mode,
            )
        };
        let mut pending = original.clone();
        pending["confirmed"] = Value::Null;
        let pending_observation = read(&pending, &before).unwrap();
        assert!(pending_observation.next_target(&before).unwrap().is_none());
        assert!(decode(&pending, &original, now, Some(&before)).is_err());
        assert!(
            read(&original, &pending_observation).is_err(),
            "old confirmation reused"
        );
        for field in ["membership_high_water", "checkpoint_high_water"] {
            let mut rollback = pending.clone();
            rollback[field] = json!(0);
            assert!(read(&rollback, &pending_observation).is_err());
        }
        let mut fresh = original.clone();
        fresh["membership_high_water"] = json!(3);
        fresh["confirmed"]["membership_version"] = json!(3);
        let confirmed = read(&fresh, &pending_observation).unwrap();
        assert!(confirmed.next_target(&before).unwrap().is_some());
        assert!(decode(&pending, &original, now, Some(&confirmed)).is_err());
        fresh["confirmed"]["expires_at"] = json!(now);
        assert!(read(&fresh, &pending_observation).is_err());
    }

    #[test]
    fn passive_target_is_fixed_checked_and_requires_all_three_verified_floor_sets() {
        let now = Utc::now();
        let old = fixture(now);
        let previous = decode(&old, &old, now, None).unwrap();
        let mut new = old.clone();
        new["membership_high_water"] = json!(3);
        new["confirmed"]["membership_version"] = json!(3);
        let target = decode(&new, &old, now, Some(&previous))
            .unwrap()
            .next_target(&previous)
            .unwrap()
            .unwrap();
        assert_eq!(target.checkpoint_version, 9);
        let good = MembershipVersionState {
            checkpoint_version: Some(9),
            node_versions: target.minimum_versions.clone(),
        };
        assert!(target.adopted(&[good.clone(), good.clone(), good.clone()]));
        assert!(!target.adopted(&[good.clone(), good.clone()]));
        let mut stale = good.clone();
        stale.checkpoint_version = Some(8);
        assert!(!target.adopted(&[good.clone(), good.clone(), stale]));
        let mut stale = good.clone();
        stale.node_versions.insert("relay-b".into(), 2);
        assert!(!target.adopted(&[good.clone(), good.clone(), stale]));
        let mut missing = good.clone();
        missing.node_versions.remove("relay-c");
        assert!(!target.adopted(&[good.clone(), good, missing]));
        new["checkpoint_high_water"] = json!(u64::MAX);
        assert!(
            decode(&new, &old, now, Some(&previous))
                .unwrap()
                .next_target(&previous)
                .is_err()
        );
        assert_eq!(target.checkpoint_version, 9);
    }

    #[test]
    fn active_relay_observer_is_refused_before_any_http_dispatch() {
        for count in 1..=3 {
            let mut dispatched = false;
            let result = require_no_serving_relays(count).map(|()| {
                dispatched = true;
            });
            assert!(result.is_err());
            assert!(!dispatched);
        }
        assert!(require_no_serving_relays(0).is_ok());
    }
}
