//! Bounded NDJSON control of four isolated installed-framework processes.
use std::{
    collections::BTreeMap,
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout},
    time::timeout_at,
};

use crate::{HarnessError, Result};

const MAX_EVENT_BYTES: u64 = 16_384;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct Probe {
    pub armed: bool,
    pub sent: u32,
    pub replies: u32,
    pub tag: Option<u16>,
    pub fid: Option<u32>,
    pub offset: Option<String>,
    pub count: u32,
    pub attaches: u32,
    pub writes: u64,
    pub written_bytes: u64,
    pub close_code: Option<u16>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct NativeWrite {
    pub success: bool,
    pub native_failure: bool,
    pub unknown: bool,
    pub no_retry: bool,
    pub native_ambiguity_visible: bool,
    pub incomplete_uploads: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct Event {
    pub event: String,
    pub adapter: String,
    pub role: String,
    pub versions: BTreeMap<String, String>,
    pub node: String,
    pub probe: Probe,
    pub probes: BTreeMap<String, Probe>,
    pub read_matches: bool,
    pub reference_survived: bool,
    pub write: NativeWrite,
}

pub(super) struct Driver {
    pub adapter: &'static str,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Driver {
    pub async fn start(adapter: &'static str, plan: &Path, ca: &Path) -> Result<Self> {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packages/client/e2e/adapters-rotation.ts");
        let mut child = tokio::process::Command::new("node")
            .arg(source)
            .arg(plan)
            .env("NODE_EXTRA_CA_CERTS", ca)
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .env_remove("NODE_OPTIONS")
            .env_remove("NODE_TLS_REJECT_UNAUTHORIZED")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(HarnessError::Io)?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| fail("driver stdin absent"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| fail("driver stdout absent"))?;
        Ok(Self {
            adapter,
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    pub async fn send(&mut self, command: &str, deadline: Instant) -> Result<()> {
        timeout_at(deadline.into(), async {
            self.stdin.write_all(command.as_bytes()).await?;
            self.stdin.write_all(b"\n").await?;
            self.stdin.flush().await
        })
        .await
        .map_err(|_| fail("driver command deadline"))?
        .map_err(HarnessError::Io)
    }

    pub async fn event(&mut self, expected: &str, deadline: Instant) -> Result<Event> {
        loop {
            let mut line = Vec::new();
            let bytes = timeout_at(
                deadline.into(),
                (&mut self.stdout)
                    .take(MAX_EVENT_BYTES + 1)
                    .read_until(b'\n', &mut line),
            )
            .await
            .map_err(|_| fail(&format!("{} driver {expected} deadline", self.adapter)))?
            .map_err(HarnessError::Io)?;
            if bytes == 0 || bytes as u64 > MAX_EVENT_BYTES || line.last() != Some(&b'\n') {
                return Err(fail("driver event missing or exceeds bound"));
            }
            let event: Event = serde_json::from_slice(&line).map_err(HarnessError::Json)?;
            if event.event == "heartbeat" {
                continue;
            }
            if event.event != expected {
                // Do not print arbitrary child data; only expected closed labels.
                return Err(fail(&format!(
                    "{} driver did not report {expected}",
                    self.adapter
                )));
            }
            return Ok(event);
        }
    }

    pub async fn shutdown(&mut self, deadline: Instant) -> Result<()> {
        if self.child.try_wait().map_err(HarnessError::Io)?.is_none() {
            let graceful = async {
                self.send("exit", deadline).await?;
                self.event("exiting", deadline).await?;
                let status = timeout_at(deadline.into(), self.child.wait())
                    .await
                    .map_err(|_| fail("driver exit deadline"))?
                    .map_err(HarnessError::Io)?;
                if !status.success() {
                    return Err(fail("driver exited unsuccessfully"));
                }
                Ok(())
            }
            .await;
            if graceful.is_err() {
                let _ = self.child.start_kill();
                let forced = timeout_at(
                    (Instant::now() + Duration::from_secs(2)).into(),
                    self.child.wait(),
                )
                .await;
                if !matches!(forced, Ok(Ok(_))) {
                    return Err(fail("driver forced cleanup did not join"));
                }
            }
            graceful
        } else {
            Err(fail("driver exited before cleanup"))
        }
    }
}

fn fail(message: &str) -> HarnessError {
    HarnessError::Process(message.to_owned())
}
