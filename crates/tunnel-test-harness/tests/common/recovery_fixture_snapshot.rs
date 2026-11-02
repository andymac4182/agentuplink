//! Bounded, namespace-only snapshots for the synthetic recovery process drill.
//!
//! The caller must stop all catalog writers before capture or restore. These
//! opaque DUMP records model an independently retained backup and later external
//! revocation reconciliation; they are not production backup tooling or an
//! automatic reconciliation authority. No bytes, keys, or Redis diagnostics are
//! exposed through Debug or errors. The scenario owns and fences the Redis
//! process separately; this helper can touch only its exact random test prefix.
//!
//! The durable-key predicate deliberately matches recovery_backup_rollback.rs:
//! preserve catalog revisions, epochs, generation and provisioning markers;
//! leave run/incarnation metadata, owners, tickets and signed directory records
//! untouched. Authorization membership records remain durable. Relative TTLs,
//! if present, are replayed as captured, as in that existing synthetic fixture.
//!
//! A failed restore has an uncertain/possibly partial outcome. MULTI/EXEC does
//! not roll back a command's runtime error. Never retry it or proceed to sign an
//! approval after failure; abort the drill and clean up its owned namespace.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    net::SocketAddr,
    pin::Pin,
    time::Duration,
};

use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

type Result<T> = std::result::Result<T, String>;
const MAX_KEYS: usize = 256;
const MAX_KEY_BYTES: usize = 512;
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
const MAX_SCAN_ROUNDS: usize = 128;
const MAX_LINE_BYTES: usize = 512;
const MAX_REPLY_BYTES: usize = 256 * 1024;
const MAX_REPLY_VALUES: usize = 1024;
const MAX_ARRAY_VALUES: usize = 2 * MAX_KEYS;
const MAX_RESP_DEPTH: usize = 4;
const MAX_REQUEST_BYTES: usize = MAX_SNAPSHOT_BYTES + MAX_KEYS * MAX_KEY_BYTES + 128 * 1024;
const COMMAND_DEADLINE: Duration = Duration::from_secs(2);
const OPERATION_DEADLINE: Duration = Duration::from_secs(20);

struct Record {
    payload: Vec<u8>,
    ttl_ms: i64,
}

/// Private synthetic data; deliberately does not implement Debug or Serialize.
pub(crate) struct Snapshot {
    prefix: String,
    records: BTreeMap<String, Record>,
    bytes: usize,
}

/// Capture only the durable records of a quiescent, random test namespace.
pub(crate) async fn capture(address: SocketAddr, prefix: &str) -> Result<Snapshot> {
    validate_target(address, prefix)?;
    timeout(OPERATION_DEADLINE, async {
        let mut redis = RawRedis::connect(address).await?;
        let keys = scan_keys(&mut redis, prefix).await?;
        let mut records = BTreeMap::new();
        let mut bytes = 0;
        for key in keys.iter().filter(|key| is_durable_key(prefix, key)) {
            let payload = bulk(redis.command(&[b"DUMP", key.as_bytes()]).await?)?;
            let ttl_ms = integer(redis.command(&[b"PTTL", key.as_bytes()]).await?)?;
            // PTTL 0 is about to expire: RESTORE 0 would turn that into a
            // persistent record, so refuse instead of changing its semantics.
            validate_record(key, &payload, ttl_ms, &mut bytes)?;
            records.insert(key.clone(), Record { payload, ttl_ms });
        }
        if records.is_empty() {
            return Err("durable fixture snapshot was empty".into());
        }
        let after = scan_keys(&mut redis, prefix).await?;
        if durable_keys(prefix, &after) != durable_keys(prefix, &keys) {
            return Err("durable fixture key set changed during capture".into());
        }
        Ok(Snapshot {
            prefix: prefix.to_owned(),
            records,
            bytes,
        })
    })
    .await
    .map_err(|_| "fixture snapshot capture deadline".to_owned())?
}

impl Snapshot {
    /// Payload-free artifact summary: record count, retained bytes, and a hash
    /// of the captured opaque records. This hash is not the catalog's recovery
    /// digest: Redis may serialize equivalent objects differently after load.
    pub(crate) fn summary(&self) -> (usize, usize, String) {
        let mut hash = Sha256::new();
        hash.update(b"agentuplink-synthetic-snapshot-v1\0");
        for (key, record) in &self.records {
            hash.update((key.len() as u64).to_be_bytes());
            hash.update(key.as_bytes());
            hash.update(record.ttl_ms.to_be_bytes());
            hash.update((record.payload.len() as u64).to_be_bytes());
            hash.update(&record.payload);
        }
        (
            self.records.len(),
            self.bytes,
            format!("{:x}", hash.finalize()),
        )
    }

    /// Replace only durable keys in the original prefix. Excluded runtime
    /// keys are neither deleted nor restored. Every refusal aborts the drill.
    pub(crate) async fn restore(&self, address: SocketAddr, prefix: &str) -> Result<()> {
        validate_target(address, prefix)?;
        if prefix != self.prefix {
            return Err("fixture snapshot cannot cross namespace boundaries".into());
        }
        timeout(OPERATION_DEADLINE, async {
            let mut redis = RawRedis::connect(address).await?;
            let current = scan_keys(&mut redis, prefix).await?;
            let (request, deletions) = restore_request(self, &current)?;
            redis
                .transaction(&request, deletions, self.records.len())
                .await?;
            let after = scan_keys(&mut redis, prefix).await?;
            if durable_keys(prefix, &after) != self.records.keys().map(String::as_str).collect() {
                return Err("fixture restore durable key set did not match snapshot".into());
            }
            Ok(())
        })
        .await
        .map_err(|_| "fixture restore deadline; outcome may be partial".to_owned())?
    }
}

fn validate_target(address: SocketAddr, prefix: &str) -> Result<()> {
    if !address.ip().is_loopback() || matches!(address.port(), 0 | 16379) {
        return Err("fixture snapshot requires a dedicated loopback Redis address".into());
    }
    validate_prefix(prefix)
}

fn validate_prefix(prefix: &str) -> Result<()> {
    let namespace = prefix
        .strip_prefix("tunnel-catalog:test-")
        .and_then(|value| value.strip_suffix(':'))
        .ok_or("fixture snapshot requires an exact random test namespace")?;
    let (label, nonce) = namespace
        .rsplit_once('-')
        .ok_or("fixture snapshot namespace omitted its UUID suffix")?;
    if label.is_empty()
        || label.len() > 80
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || nonce.bytes().all(|byte| byte == b'0')
        || uuid::Uuid::parse_str(nonce).is_err()
    {
        return Err("fixture snapshot namespace is not a bounded random test prefix".into());
    }
    Ok(())
}

fn is_durable_key(prefix: &str, key: &str) -> bool {
    let Some(suffix) = key.strip_prefix(prefix) else {
        return false;
    };
    !suffix.starts_with("coord:owner:")
        && !suffix.starts_with("coord:ticket:")
        && !suffix.starts_with("coord:tickets:")
        && !suffix.starts_with("membership:operator:")
        && suffix != "meta:active_incarnation"
        && suffix != "meta:redis_run_id"
}

fn durable_keys<'a>(prefix: &str, keys: &'a BTreeSet<String>) -> BTreeSet<&'a str> {
    keys.iter()
        .filter(|key| is_durable_key(prefix, key))
        .map(String::as_str)
        .collect()
}

fn validate_record(key: &str, payload: &[u8], ttl_ms: i64, bytes: &mut usize) -> Result<()> {
    if payload.is_empty() || ttl_ms < -1 || ttl_ms == 0 {
        return Err("fixture snapshot record disappeared or has an unsafe TTL".into());
    }
    let size = key
        .len()
        .checked_add(payload.len())
        .and_then(|value| value.checked_add(size_of::<i64>()))
        .ok_or("fixture snapshot record size overflow")?;
    if key.len() > MAX_KEY_BYTES || size > MAX_RECORD_BYTES {
        return Err("fixture snapshot record exceeded its byte bound".into());
    }
    let total = bytes
        .checked_add(size)
        .filter(|value| *value <= MAX_SNAPSHOT_BYTES)
        .ok_or("fixture snapshot exceeded its total byte bound")?;
    *bytes = total;
    Ok(())
}

fn restore_request(snapshot: &Snapshot, current: &BTreeSet<String>) -> Result<(Vec<u8>, usize)> {
    let mut request = Vec::new();
    append_command(&mut request, &[b"MULTI"])?;
    let mut deletions = 0;
    for key in current {
        if !key.starts_with(&snapshot.prefix) || key.len() > MAX_KEY_BYTES {
            return Err("fixture restore key escaped its exact namespace".into());
        }
        if is_durable_key(&snapshot.prefix, key) && !snapshot.records.contains_key(key) {
            append_command(&mut request, &[b"DEL", key.as_bytes()])?;
            deletions += 1;
        }
    }
    for (key, record) in &snapshot.records {
        let ttl = record.ttl_ms.max(0).to_string();
        append_command(
            &mut request,
            &[
                b"RESTORE",
                key.as_bytes(),
                ttl.as_bytes(),
                &record.payload,
                b"REPLACE",
            ],
        )?;
    }
    append_command(&mut request, &[b"EXEC"])?;
    Ok((request, deletions))
}

struct RawRedis {
    stream: TcpStream,
}

impl RawRedis {
    async fn connect(address: SocketAddr) -> Result<Self> {
        let stream = timeout(COMMAND_DEADLINE, TcpStream::connect(address))
            .await
            .map_err(|_| "fixture Redis connect deadline")?
            .map_err(|_| "fixture Redis connection failed")?;
        Ok(Self { stream })
    }

    async fn command(&mut self, args: &[&[u8]]) -> Result<Resp> {
        let mut request = Vec::new();
        append_command(&mut request, args)?;
        timeout(COMMAND_DEADLINE, async {
            self.stream
                .write_all(&request)
                .await
                .map_err(|_| "fixture Redis command write failed")?;
            read_reply(&mut self.stream).await
        })
        .await
        .map_err(|_| "fixture Redis command deadline".to_owned())?
    }

    async fn transaction(
        &mut self,
        request: &[u8],
        deletions: usize,
        restores: usize,
    ) -> Result<()> {
        timeout(COMMAND_DEADLINE, async {
            self.stream
                .write_all(request)
                .await
                .map_err(|_| "fixture restore write failed; outcome may be partial")?;
            simple(read_reply(&mut self.stream).await?, b"OK")?;
            for _ in 0..deletions + restores {
                simple(read_reply(&mut self.stream).await?, b"QUEUED")?;
            }
            let replies = array(read_reply(&mut self.stream).await?)?;
            if replies.len() != deletions + restores {
                return Err("fixture restore transaction response count".into());
            }
            for (index, reply) in replies.into_iter().enumerate() {
                if index < deletions {
                    if !matches!(integer(reply)?, 0 | 1) {
                        return Err("fixture restore deletion response".into());
                    }
                } else {
                    simple(reply, b"OK")?;
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| "fixture restore transaction deadline; outcome may be partial".to_owned())?
    }
}

async fn scan_keys(redis: &mut RawRedis, prefix: &str) -> Result<BTreeSet<String>> {
    let pattern = format!("{prefix}*");
    let mut cursor = 0_u64;
    let mut keys = BTreeSet::new();
    let mut cursors = BTreeSet::new();
    for _ in 0..MAX_SCAN_ROUNDS {
        let cursor_text = cursor.to_string();
        let response = redis
            .command(&[
                b"SCAN",
                cursor_text.as_bytes(),
                b"MATCH",
                pattern.as_bytes(),
                b"COUNT",
                b"256",
            ])
            .await?;
        let mut parts = array(response)?;
        if parts.len() != 2 {
            return Err("fixture Redis SCAN response shape".into());
        }
        let page = array(parts.pop().ok_or("fixture Redis SCAN key page")?)?;
        let cursor_bytes = bulk(parts.pop().ok_or("fixture Redis SCAN cursor")?)?;
        if cursor_bytes.len() > 20 || !cursor_bytes.iter().all(u8::is_ascii_digit) {
            return Err("fixture Redis SCAN cursor encoding".into());
        }
        cursor = std::str::from_utf8(&cursor_bytes)
            .ok()
            .and_then(|value| value.parse().ok())
            .ok_or("fixture Redis SCAN cursor number")?;
        for value in page {
            let bytes = bulk(value)?;
            if bytes.len() > MAX_KEY_BYTES {
                return Err("fixture Redis key exceeded its byte bound".into());
            }
            let key = String::from_utf8(bytes).map_err(|_| "fixture Redis key encoding")?;
            if !key.starts_with(prefix) || key.len() == prefix.len() {
                return Err("fixture Redis SCAN escaped its exact namespace".into());
            }
            keys.insert(key);
            if keys.len() > MAX_KEYS {
                return Err("fixture Redis namespace exceeded its key bound".into());
            }
        }
        if cursor == 0 {
            return Ok(keys);
        }
        if !cursors.insert(cursor) {
            return Err("fixture Redis SCAN repeated a cursor".into());
        }
    }
    Err("fixture Redis SCAN exceeded its iteration bound".into())
}

fn append_command(encoded: &mut Vec<u8>, args: &[&[u8]]) -> Result<()> {
    let header = format!("*{}\r\n", args.len());
    let size = args.iter().try_fold(header.len(), |total, arg| {
        total
            .checked_add(arg.len())
            .and_then(|value| value.checked_add(arg.len().to_string().len() + 5))
            .ok_or("fixture Redis request size overflow")
    })?;
    if encoded
        .len()
        .checked_add(size)
        .is_none_or(|value| value > MAX_REQUEST_BYTES)
    {
        return Err("fixture Redis request exceeded its byte bound".into());
    }
    encoded.extend_from_slice(header.as_bytes());
    for arg in args {
        encoded.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        encoded.extend_from_slice(arg);
        encoded.extend_from_slice(b"\r\n");
    }
    Ok(())
}

enum Resp {
    Simple(Vec<u8>),
    Integer(i64),
    Bulk(Option<Vec<u8>>),
    Array(Vec<Resp>),
}

struct ReplyBudget {
    bytes: usize,
    values: usize,
}

impl ReplyBudget {
    fn take_bytes(&mut self, count: usize) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_sub(count)
            .ok_or("fixture Redis response exceeded its byte bound")?;
        Ok(())
    }
}

async fn read_reply<R: AsyncRead + Unpin + Send>(stream: &mut R) -> Result<Resp> {
    let mut budget = ReplyBudget {
        bytes: MAX_REPLY_BYTES,
        values: MAX_REPLY_VALUES,
    };
    read_resp(stream, &mut budget, 0).await
}

fn read_resp<'a, R: AsyncRead + Unpin + Send + 'a>(
    stream: &'a mut R,
    budget: &'a mut ReplyBudget,
    depth: usize,
) -> Pin<Box<dyn Future<Output = Result<Resp>> + Send + 'a>> {
    Box::pin(async move {
        if depth > MAX_RESP_DEPTH || budget.values == 0 {
            return Err("fixture Redis response exceeded its structure bound".into());
        }
        budget.values -= 1;
        let kind = read_byte(stream, budget).await?;
        let line = read_line(stream, budget).await?;
        match kind {
            b'+' => Ok(Resp::Simple(line)),
            // Consume but never echo a potentially payload-bearing error.
            b'-' => Err("Redis refused fixture snapshot operation".into()),
            b':' => Ok(Resp::Integer(parse_integer(&line)?)),
            b'$' => {
                let size = parse_integer(&line)?;
                if size == -1 {
                    return Ok(Resp::Bulk(None));
                }
                let size = usize::try_from(size)
                    .ok()
                    .filter(|value| *value <= MAX_RECORD_BYTES)
                    .ok_or("fixture Redis bulk response exceeded its bound")?;
                budget.take_bytes(size + 2)?;
                let mut bytes = vec![0; size + 2];
                stream
                    .read_exact(&mut bytes)
                    .await
                    .map_err(|_| "fixture Redis bulk read failed")?;
                if !bytes.ends_with(b"\r\n") {
                    return Err("fixture Redis bulk terminator".into());
                }
                bytes.truncate(size);
                Ok(Resp::Bulk(Some(bytes)))
            }
            b'*' => {
                let count = usize::try_from(parse_integer(&line)?)
                    .ok()
                    .filter(|value| *value <= MAX_ARRAY_VALUES && *value <= budget.values)
                    .ok_or("fixture Redis array response exceeded its bound")?;
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    values.push(read_resp(stream, budget, depth + 1).await?);
                }
                Ok(Resp::Array(values))
            }
            _ => Err("fixture Redis response type is unsupported".into()),
        }
    })
}

async fn read_byte<R: AsyncRead + Unpin>(stream: &mut R, budget: &mut ReplyBudget) -> Result<u8> {
    budget.take_bytes(1)?;
    stream
        .read_u8()
        .await
        .map_err(|_| "fixture Redis response read failed".into())
}

async fn read_line<R: AsyncRead + Unpin>(
    stream: &mut R,
    budget: &mut ReplyBudget,
) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    for _ in 0..MAX_LINE_BYTES {
        line.push(read_byte(stream, budget).await?);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return Ok(line);
        }
    }
    Err("fixture Redis response line exceeded its bound".into())
}

fn parse_integer(bytes: &[u8]) -> Result<i64> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| "fixture Redis integer encoding".into())
}

fn simple(value: Resp, expected: &[u8]) -> Result<()> {
    match value {
        Resp::Simple(actual) if actual == expected => Ok(()),
        _ => Err("fixture Redis simple response shape".into()),
    }
}

fn integer(value: Resp) -> Result<i64> {
    match value {
        Resp::Integer(value) => Ok(value),
        _ => Err("fixture Redis integer response shape".into()),
    }
}

fn bulk(value: Resp) -> Result<Vec<u8>> {
    match value {
        Resp::Bulk(Some(value)) => Ok(value),
        _ => Err("fixture Redis record missing or bulk response shape".into()),
    }
}

fn array(value: Resp) -> Result<Vec<Resp>> {
    match value {
        Resp::Array(values) => Ok(values),
        _ => Err("fixture Redis array response shape".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "tunnel-catalog:test-authority-recovery-11111111111141118111111111111111:";

    #[test]
    fn only_exact_random_test_prefixes_are_accepted() {
        assert!(validate_prefix(PREFIX).is_ok());
        for prefix in [
            "tunnel-catalog:production:",
            "tunnel-catalog:test-*:",
            "tunnel-catalog:test-recovery-00000000000000000000000000000000:",
            "tunnel-catalog:test-recovery-11111111111141118111111111111111:*",
            "tunnel-catalog:test-recovery:other-11111111111141118111111111111111:",
        ] {
            assert!(validate_prefix(prefix).is_err());
        }
        assert!(validate_target("192.0.2.1:6379".parse().unwrap(), PREFIX).is_err());
        assert!(validate_target("127.0.0.1:16379".parse().unwrap(), PREFIX).is_err());
    }

    #[test]
    fn restore_neither_deletes_nor_replays_runtime_authority() {
        let retained = [
            "meta:fixture_seeded",
            "meta:catalog_generation",
            "meta:continuity",
            "coord:epoch:tenant:device",
            "membership:tenant:user",
            "credential:tenant:device:credential",
        ];
        let excluded = [
            "meta:active_incarnation",
            "meta:redis_run_id",
            "coord:owner:incarnation:tenant:device",
            "coord:ticket:incarnation:ticket",
            "coord:tickets:incarnation:tenant:device",
            "membership:operator:directory",
        ];
        let records: BTreeMap<_, _> = retained
            .iter()
            .map(|suffix| {
                let key = format!("{PREFIX}{suffix}");
                assert!(is_durable_key(PREFIX, &key));
                (
                    key,
                    Record {
                        payload: b"opaque-rdb-record".to_vec(),
                        ttl_ms: -1,
                    },
                )
            })
            .collect();
        let snapshot = Snapshot {
            prefix: PREFIX.into(),
            records,
            bytes: 0,
        };
        let mut current: BTreeSet<_> = snapshot.records.keys().cloned().collect();
        for suffix in excluded {
            let key = format!("{PREFIX}{suffix}");
            assert!(!is_durable_key(PREFIX, &key));
            current.insert(key);
        }
        let obsolete = format!("{PREFIX}grant:tenant:user:device:obsolete");
        current.insert(obsolete.clone());
        let (request, deletions) = restore_request(&snapshot, &current).unwrap();
        assert_eq!(deletions, 1);
        for suffix in excluded {
            let key = format!("{PREFIX}{suffix}");
            assert!(
                !request
                    .windows(key.len())
                    .any(|part| part == key.as_bytes())
            );
        }
        assert!(
            request
                .windows(obsolete.len())
                .any(|part| part == obsolete.as_bytes())
        );
        for key in snapshot.records.keys() {
            assert!(
                request
                    .windows(key.len())
                    .any(|part| part == key.as_bytes())
            );
        }
        assert_eq!(snapshot.summary().0, retained.len());
        current.insert("tunnel-catalog:another:grant:record".into());
        assert!(restore_request(&snapshot, &current).is_err());
    }

    #[test]
    fn record_and_aggregate_bounds_refuse_before_accounting_changes() {
        let key = format!("{PREFIX}meta:catalog_generation");
        let mut bytes = MAX_SNAPSHOT_BYTES - key.len() - 9;
        validate_record(&key, b"x", -1, &mut bytes).unwrap();
        assert_eq!(bytes, MAX_SNAPSHOT_BYTES);
        assert!(validate_record(&key, b"x", -1, &mut bytes).is_err());
        assert_eq!(bytes, MAX_SNAPSHOT_BYTES);
        assert!(validate_record(&key, &vec![0; MAX_RECORD_BYTES], -1, &mut 0).is_err());
        assert!(validate_record(&key, b"x", 0, &mut 0).is_err());
        assert!(validate_record(&key, b"x", -2, &mut 0).is_err());
    }

    #[tokio::test]
    async fn malformed_resp_is_bounded_before_payload_allocation() {
        let malicious = [
            b"$65537\r\n".as_slice(),
            b"$-2\r\n",
            b"*513\r\n",
            b"*-1\r\n",
            b"*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n+OK\r\n",
            b"$1\r\nxXX",
            b"-ERR private-payload-must-not-escape\r\n",
        ];
        for mut input in malicious {
            let error = match read_reply(&mut input).await {
                Ok(_) => panic!("malformed fixture RESP was accepted"),
                Err(error) => error,
            };
            assert!(!error.contains("private-payload"));
        }
        let mut oversized_line = vec![b'x'; MAX_LINE_BYTES + 1];
        oversized_line[0] = b'+';
        assert!(read_reply(&mut oversized_line.as_slice()).await.is_err());
        let mut budget = ReplyBudget {
            bytes: 32,
            values: MAX_REPLY_VALUES,
        };
        let mut input = b"$64\r\n".as_slice();
        assert!(read_resp(&mut input, &mut budget, 0).await.is_err());
        let mut valid = b"*2\r\n$1\r\n0\r\n*1\r\n$3\r\nkey\r\n".as_slice();
        assert!(read_reply(&mut valid).await.is_ok());
    }
}
