//! Independent acceptance predicates, including deliberately invalid witnesses.
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use tunnel_relay::RelayRotationSnapshot;

use super::{
    ADAPTERS,
    driver::{Event, Probe},
};
use crate::{HarnessError, Result};

#[derive(Clone, Debug, Default, Serialize)]
pub(super) struct StreamProof {
    pub adapter: String,
    pub role: String,
    pub stream_id: u64,
    pub probe: Probe,
    pub received_before_freeze: u64,
    pub request_emitted: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct FsAdaptersRotationEvidence {
    pub(super) interval_seconds: u64,
    pub(super) handshake_seconds: u64,
    pub(super) overlap_seconds: u64,
    pub(super) token_seconds: u64,
    pub(super) creation_bracket_ms: u64,
    pub(super) scheduled_start_lower_ms: u64,
    pub(super) host_checked_at_ms: u64,
    pub(super) held_streams: Vec<StreamProof>,
    pub(super) freeze: Option<RelayRotationSnapshot>,
    pub(super) freeze_repeat: Option<RelayRotationSnapshot>,
    pub(super) completed: Option<RelayRotationSnapshot>,
    pub(super) frozen_phase: String,
    pub(super) rotations_before: u64,
    pub(super) rotations_after: u64,
    pub(super) generation_before: u64,
    pub(super) generation_after: u64,
    pub(super) stable_session_epoch: bool,
    pub(super) replayed_frames: u64,
    pub(super) forced_retirement: bool,
    pub(super) recovery: bool,
    pub(super) resumed_in_ms: u64,
    pub(super) frozen_sockets: u8,
    pub(super) final_sockets: u8,
    pub(super) socket_peak: u64,
    pub(super) host_before_freeze: bool,
    pub(super) host_after_rotation: bool,
    pub(super) host_negative_red: bool,
    pub(super) completed_exchanges: u64,
    pub(super) completed_bytes_written: u64,
    pub(super) native_rotation: BTreeMap<String, Event>,
    pub(super) native_revocation: BTreeMap<String, Event>,
    pub(super) host_before_revocation: bool,
    pub(super) host_after_revocation: bool,
    pub(super) revocation_in_ms: u64,
    pub(super) non_owner_refused: bool,
    pub(super) revoked_admission_refused: bool,
    pub(super) revoked_admission_no_stream_opened: bool,
    pub(super) last_revoked_stream_id: u64,
    pub(super) next_control_stream_id: u64,
    pub(super) independent_grant_survived: bool,
    pub(super) versions: BTreeMap<String, String>,
    pub(super) node: String,
    pub(super) cleanup_joined: bool,
}

pub(super) fn same_fences(left: &RelayRotationSnapshot, right: &RelayRotationSnapshot) -> bool {
    left.attempt == right.attempt
        && left.snapshot_id == right.snapshot_id
        && left.relay_fence_digest == right.relay_fence_digest
        && left.connector_fence_digest == right.connector_fence_digest
        && left.relay_fence_sequences == right.relay_fence_sequences
        && left.connector_fence_sequences == right.connector_fence_sequences
}

fn fail(rule: &str) -> HarnessError {
    HarnessError::Process(format!("fs adapters rotation: {rule}"))
}

fn require(condition: bool, rule: &str) -> Result<()> {
    if condition { Ok(()) } else { Err(fail(rule)) }
}

/// Validate the full real-framework, host, fence and revocation witness.
///
/// # Errors
/// The first acceptance predicate not established by the witness.
pub fn validate_fs_adapters_rotation_evidence(e: &FsAdaptersRotationEvidence) -> Result<()> {
    require(
        (
            e.interval_seconds,
            e.handshake_seconds,
            e.overlap_seconds,
            e.token_seconds,
        ) == (300, 10, 30, 900),
        "production rotation policy and bounded synthetic token",
    )?;
    require(
        e.creation_bracket_ms <= 1000 && e.scheduled_start_lower_ms >= 299_999,
        "first rotation followed the actual 300-second policy timer",
    )?;
    require(
        e.host_checked_at_ms < 300_000 && e.host_before_freeze,
        "all host writes were observed before the earliest possible freeze",
    )?;
    require(
        e.node == "v24.21.0" && e.versions == expected_versions(),
        "pinned Node and real framework packages",
    )?;
    require(
        e.held_streams.len() == 8,
        "eight separately identified held streams",
    )?;
    let identities: BTreeSet<_> = e
        .held_streams
        .iter()
        .map(|s| (s.adapter.as_str(), s.role.as_str()))
        .collect();
    let expected: BTreeSet<_> = ADAPTERS
        .into_iter()
        .flat_map(|adapter| ["read", "write"].map(|role| (adapter, role)))
        .collect();
    require(
        identities == expected
            && e.held_streams
                .iter()
                .map(|s| s.stream_id)
                .collect::<BTreeSet<_>>()
                .len()
                == 8,
        "one read and one write stream per actual framework",
    )?;
    let freeze = e.freeze.as_ref().ok_or_else(|| fail("missing freeze"))?;
    let repeat = e
        .freeze_repeat
        .as_ref()
        .ok_or_else(|| fail("missing repeated freeze"))?;
    let completed = e
        .completed
        .as_ref()
        .ok_or_else(|| fail("missing completion proof"))?;
    require(
        freeze.attempt.as_ref().is_some_and(|a| {
            !a.session_id.is_empty()
                && !a.rotation_id.is_empty()
                && a.old_generation == e.generation_before
                && a.new_generation == e.generation_after
        }) && freeze.snapshot_id.as_ref().is_some_and(|s| !s.is_empty())
            && freeze
                .relay_fence_digest
                .as_ref()
                .is_some_and(|s| !s.is_empty())
            && freeze
                .connector_fence_digest
                .as_ref()
                .is_some_and(|s| !s.is_empty())
            && freeze.attempt_active
            && repeat.attempt_active
            && freeze.writer_barrier_flushed == [true; 2]
            && repeat.writer_barrier_flushed == [true; 2]
            && freeze.candidate_ready
            && repeat.candidate_ready
            && freeze.old_socket_closed == [false; 2]
            && repeat.old_socket_closed == [false; 2]
            && !freeze.commit_accepted
            && !repeat.commit_accepted
            && ["quiescing", "draining", "committing"].contains(&e.frozen_phase.as_str()),
        "live uncommitted frozen attempt",
    )?;
    require(
        same_fences(freeze, repeat) && same_fences(freeze, completed),
        "immutable complete sequence fences",
    )?;
    for stream in &e.held_streams {
        let p = &stream.probe;
        require(
            p.armed
                && p.sent == 1
                && p.replies == 0
                && p.tag.is_some()
                && p.fid.is_some()
                && p.offset.as_deref() == Some("0")
                && p.count > 0
                && p.attaches == 1,
            "selected request actually sent and unanswered at freeze",
        )?;
        if stream.role == "write" {
            require(
                p.count == 4096 && p.writes == 1 && p.written_bytes == 4096,
                "exactly one held write dispatch per framework",
            )?;
        }
        let connector_fence = freeze
            .connector_fence_sequences
            .iter()
            .find(|(id, _)| *id == stream.stream_id)
            .map(|(_, seq)| *seq);
        let relay_fence = freeze
            .relay_fence_sequences
            .iter()
            .find(|(id, _)| *id == stream.stream_id)
            .map(|(_, seq)| *seq);
        require(
            connector_fence.is_some_and(|f| f > stream.received_before_freeze)
                && relay_fence
                    .is_some_and(|f| stream.request_emitted > 0 && f >= stream.request_emitted),
            "each selected exchange was inside the immutable freeze",
        )?;
    }
    for (fences, acknowledgements) in [
        (
            &completed.relay_fence_sequences,
            &completed.relay_ack_sequences,
        ),
        (
            &completed.connector_fence_sequences,
            &completed.connector_ack_sequences,
        ),
    ] {
        require(
            fences.iter().all(|(id, fence)| {
                acknowledgements
                    .iter()
                    .any(|(ack_id, ack)| ack_id == id && ack >= fence)
            }),
            "both complete direction fences were acknowledged",
        )?;
    }
    require(
        completed.commit_sent
            && completed.commit_accepted
            && completed.old_socket_closed == [true; 2],
        "commit and old-carrier retirement",
    )?;
    require(
        e.rotations_before == 0
            && e.rotations_after == 1
            && e.generation_after == e.generation_before + 1
            && e.stable_session_epoch
            && e.replayed_frames == 0
            && !e.forced_retirement
            && !e.recovery
            && e.resumed_in_ms < 30_000,
        "bounded clean rotation without reconnect or replay",
    )?;
    require(
        e.frozen_sockets == 3 && e.final_sockets == 2 && e.socket_peak == 3,
        "two steady sockets and one bounded rotation candidate",
    )?;
    require(
        e.host_after_rotation
            && e.host_negative_red
            && e.completed_exchanges == 8
            && e.completed_bytes_written == 5 * 4096,
        "independent host oracle and completed-exchange write count",
    )?;
    for adapter in ADAPTERS {
        let result = e
            .native_rotation
            .get(adapter)
            .ok_or_else(|| fail("missing native rotation result"))?;
        require(
            result.read_matches && result.reference_survived && result.write.success,
            "actual framework read/write and client reuse succeeded",
        )?;
        for role in ["read", "write"] {
            let p = result
                .probes
                .get(role)
                .ok_or_else(|| fail("missing completion probe"))?;
            require(
                p.attaches == 1 && p.sent == 1 && p.replies == 1 && p.close_code.is_none(),
                "same native session received exactly one held reply",
            )?;
            let held = e
                .held_streams
                .iter()
                .find(|s| s.adapter == adapter && s.role == role)
                .ok_or_else(|| fail("completion lost its selected stream"))?;
            require(
                p.tag == held.probe.tag
                    && p.fid == held.probe.fid
                    && p.offset == held.probe.offset
                    && p.count == held.probe.count,
                "held tag/fid correlated with its completion",
            )?;
        }
        let p = &result.probes["write"];
        require(
            p.writes == 1 && p.written_bytes == 4096,
            "no native replay after resumption",
        )?;
        let revoked = e
            .native_revocation
            .get(adapter)
            .ok_or_else(|| fail("missing native revocation result"))?;
        let p = revoked
            .probes
            .get("revoked")
            .ok_or_else(|| fail("missing revoked probe"))?;
        let write = &revoked.write;
        require(
            !write.success
                && write.native_failure
                && write.unknown
                && write.no_retry
                && write.native_ambiguity_visible
                && p.close_code == Some(1008)
                && p.sent == 1
                && p.replies == 0
                && p.writes == 1
                && p.written_bytes == 4096,
            "native revoked write preserves unknown without replay",
        )?;
        require(
            adapter != "ai" || write.incomplete_uploads == 1,
            "ambiguous AI upload retained without reference",
        )?;
    }
    require(
        e.host_before_revocation
            && e.host_after_revocation
            && e.revocation_in_ms < 20_000
            && e.non_owner_refused
            && e.revoked_admission_refused
            && e.revoked_admission_no_stream_opened
            && e.last_revoked_stream_id > 0
            && e.last_revoked_stream_id.checked_add(1) == Some(e.next_control_stream_id)
            && e.independent_grant_survived,
        "bounded revocation, host effect, refusal and unaffected grant",
    )?;
    require(e.cleanup_joined, "all fixture processes and tasks joined")
}

pub(super) fn expected_versions() -> BTreeMap<String, String> {
    [
        ("files-sdk", "2.4.0"),
        ("@mastra/core", "1.65.0"),
        ("ai", "7.0.94"),
        ("just-bash", "3.4.2"),
        ("@ai-sdk/provider", "4.0.11"),
    ]
    .into_iter()
    .map(|(name, version)| (name.into(), version.into()))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production_cluster::fs_adapters_rotation::driver::NativeWrite;
    use tunnel_protocol::rotation_control::RotationAttemptIdentity;

    fn valid() -> FsAdaptersRotationEvidence {
        let mut e = FsAdaptersRotationEvidence {
            interval_seconds: 300,
            handshake_seconds: 10,
            overlap_seconds: 30,
            token_seconds: 900,
            creation_bracket_ms: 30,
            scheduled_start_lower_ms: 300_040,
            host_checked_at_ms: 295_100,
            frozen_phase: "draining".into(),
            rotations_before: 0,
            rotations_after: 1,
            generation_before: 1,
            generation_after: 2,
            stable_session_epoch: true,
            resumed_in_ms: 80,
            frozen_sockets: 3,
            final_sockets: 2,
            socket_peak: 3,
            host_before_freeze: true,
            host_after_rotation: true,
            host_negative_red: true,
            completed_exchanges: 8,
            completed_bytes_written: 20_480,
            host_before_revocation: true,
            host_after_revocation: true,
            revocation_in_ms: 700,
            non_owner_refused: true,
            revoked_admission_refused: true,
            revoked_admission_no_stream_opened: true,
            last_revoked_stream_id: 13,
            next_control_stream_id: 14,
            independent_grant_survived: true,
            versions: expected_versions(),
            node: "v24.21.0".into(),
            cleanup_joined: true,
            ..FsAdaptersRotationEvidence::default()
        };
        let probe = Probe {
            armed: true,
            sent: 1,
            tag: Some(7),
            fid: Some(1),
            offset: Some("0".into()),
            count: 4096,
            attaches: 1,
            writes: 1,
            written_bytes: 4096,
            ..Probe::default()
        };
        for adapter in ADAPTERS {
            for role in ["read", "write"] {
                e.held_streams.push(StreamProof {
                    adapter: adapter.into(),
                    role: role.into(),
                    stream_id: e.held_streams.len() as u64 + 1,
                    probe: probe.clone(),
                    received_before_freeze: 4,
                    request_emitted: 6,
                });
            }
            let answered = Probe {
                replies: 1,
                ..probe.clone()
            };
            e.native_rotation.insert(
                adapter.into(),
                Event {
                    read_matches: true,
                    reference_survived: true,
                    write: NativeWrite {
                        success: true,
                        ..NativeWrite::default()
                    },
                    probes: [
                        ("read".into(), answered.clone()),
                        ("write".into(), answered),
                    ]
                    .into(),
                    ..Event::default()
                },
            );
            e.native_revocation.insert(
                adapter.into(),
                Event {
                    write: NativeWrite {
                        native_failure: true,
                        unknown: true,
                        no_retry: true,
                        native_ambiguity_visible: true,
                        incomplete_uploads: 1,
                        ..NativeWrite::default()
                    },
                    probes: [(
                        "revoked".into(),
                        Probe {
                            close_code: Some(1008),
                            ..probe.clone()
                        },
                    )]
                    .into(),
                    ..Event::default()
                },
            );
        }
        let freeze = RelayRotationSnapshot {
            snapshot_id: Some("snapshot".into()),
            attempt: Some(RotationAttemptIdentity::new(
                "session", 1, "owner", "rotation", 1, 2, "old", "new",
            )),
            attempt_active: true,
            relay_fence_digest: Some("relay-digest".into()),
            connector_fence_digest: Some("connector-digest".into()),
            relay_fence_sequences: (1..=8).map(|id| (id, 6)).collect(),
            connector_fence_sequences: (1..=8).map(|id| (id, 5)).collect(),
            writer_barrier_flushed: [true; 2],
            candidate_ready: true,
            ..RelayRotationSnapshot::default()
        };
        e.freeze = Some(freeze.clone());
        e.freeze_repeat = Some(freeze.clone());
        e.completed = Some(RelayRotationSnapshot {
            commit_sent: true,
            commit_accepted: true,
            old_socket_closed: [true; 2],
            relay_ack_sequences: freeze.relay_fence_sequences.clone(),
            connector_ack_sequences: freeze.connector_fence_sequences.clone(),
            ..freeze
        });
        e
    }

    #[test]
    fn fs_adapters_rotation_accepts_the_complete_witness() {
        validate_fs_adapters_rotation_evidence(&valid()).unwrap();
    }

    #[test]
    fn fs_adapters_rotation_rejects_missing_or_counterfeit_proof() {
        type Corrupt = fn(&mut FsAdaptersRotationEvidence);
        let cases: &[(&str, Corrupt)] = &[
            ("accelerated interval", |e| e.interval_seconds = 6),
            ("ambiguous clock origin", |e| e.creation_bracket_ms = 1001),
            ("rotation before 300 seconds", |e| {
                e.scheduled_start_lower_ms = 299_000
            }),
            ("late host observation", |e| e.host_checked_at_ms = 300_000),
            ("no host effect", |e| e.host_before_freeze = false),
            ("missing adapter", |e| {
                e.held_streams.pop();
            }),
            ("one shared stream", |e| {
                e.held_streams[1].stream_id = e.held_streams[0].stream_id
            }),
            ("parked but undispatched", |e| {
                e.held_streams[0].probe.sent = 0
            }),
            ("already answered", |e| e.held_streams[0].probe.replies = 1),
            ("reply outside freeze", |e| {
                e.held_streams[0].received_before_freeze = 5
            }),
            ("request outside freeze", |e| {
                e.held_streams[0].request_emitted = 7
            }),
            ("missing stream fence", |e| {
                e.freeze.as_mut().unwrap().connector_fence_sequences.pop();
            }),
            ("mutable digest", |e| {
                e.freeze_repeat.as_mut().unwrap().relay_fence_digest = Some("changed".into())
            }),
            ("mutable attempt", |e| {
                e.freeze_repeat
                    .as_mut()
                    .unwrap()
                    .attempt
                    .as_mut()
                    .unwrap()
                    .rotation_id = "changed".into()
            }),
            ("mutable sequence", |e| {
                e.freeze_repeat.as_mut().unwrap().relay_fence_sequences[0].1 += 1
            }),
            ("undrained completion", |e| {
                e.completed.as_mut().unwrap().connector_ack_sequences[0].1 -= 1
            }),
            ("old socket retained", |e| {
                e.completed.as_mut().unwrap().old_socket_closed[0] = false
            }),
            ("new logical session", |e| e.stable_session_epoch = false),
            ("forced retirement", |e| e.forced_retirement = true),
            ("transport replay", |e| e.replayed_frames = 1),
            ("fourth device socket", |e| e.socket_peak = 4),
            ("unmatched held tag", |e| {
                e.native_rotation
                    .get_mut("files")
                    .unwrap()
                    .probes
                    .get_mut("read")
                    .unwrap()
                    .tag = Some(8)
            }),
            ("unbounded resumption", |e| e.resumed_in_ms = 30_000),
            ("same-offset duplicate host write", |e| {
                e.completed_bytes_written += 4096
            }),
            ("missing completed report", |e| e.completed_exchanges -= 1),
            ("broken negative control", |e| e.host_negative_red = false),
            ("framework replay", |e| {
                e.native_rotation
                    .get_mut("files")
                    .unwrap()
                    .probes
                    .get_mut("write")
                    .unwrap()
                    .writes = 2
            }),
            ("unknown hidden by tool loop", |e| {
                e.native_revocation
                    .get_mut("mastra")
                    .unwrap()
                    .write
                    .native_ambiguity_visible = false
            }),
            ("revocation marked retryable", |e| {
                e.native_revocation.get_mut("files").unwrap().write.no_retry = false
            }),
            ("wrong close classification", |e| {
                e.native_revocation
                    .get_mut("ai")
                    .unwrap()
                    .probes
                    .get_mut("revoked")
                    .unwrap()
                    .close_code = Some(1011)
            }),
            ("missing AI incomplete upload", |e| {
                e.native_revocation
                    .get_mut("ai")
                    .unwrap()
                    .write
                    .incomplete_uploads = 0
            }),
            ("collateral grant loss", |e| {
                e.independent_grant_survived = false
            }),
            ("non-owner secretly forwarded", |e| {
                e.non_owner_refused = false
            }),
            ("fresh revoked admission allowed", |e| {
                e.revoked_admission_refused = false
            }),
            ("revoked admission opened a stream", |e| {
                e.revoked_admission_no_stream_opened = false
            }),
            ("transient forbidden stream allocation", |e| {
                e.next_control_stream_id += 1
            }),
            ("missing allocation witness", |e| {
                e.last_revoked_stream_id = 0
            }),
            ("allocation witness overflow", |e| {
                e.last_revoked_stream_id = u64::MAX;
                e.next_control_stream_id = 0
            }),
            ("cleanup detached", |e| e.cleanup_joined = false),
        ];
        for (label, corrupt) in cases {
            let mut witness = valid();
            corrupt(&mut witness);
            assert!(
                validate_fs_adapters_rotation_evidence(&witness).is_err(),
                "accepted {label}"
            );
        }
    }
}
