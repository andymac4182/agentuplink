//! Bounded loopback-only RESP proxy: discard exactly one acknowledged
//! membership EVAL reply, then sever unforwarded siblings at that same version.
//! The test reads Redis independently to prove the committed partial round.
//! No credentials, scripts or signed payloads are retained in diagnostics.
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Notify, oneshot},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

type Result<T = ()> = std::result::Result<T, &'static str>;
const IO_BOUND: Duration = Duration::from_secs(5);
const MAX_RESP_FRAME: usize = 256 * 1024;
const MAX_RESP_ITEMS: usize = 256;

#[derive(Clone)]
struct Control {
    armed: Arc<AtomicBool>,
    ever_armed: Arc<AtomicBool>,
    cuts: Arc<AtomicUsize>,
    cut: Arc<Notify>,
    attempts: Arc<Mutex<Vec<(String, u64)>>>,
    publication_gate: Arc<tokio::sync::Mutex<()>>,
    cut_version: Arc<AtomicU64>,
}

pub struct FaultProxy {
    address: SocketAddr,
    control: Control,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl FaultProxy {
    pub async fn start(upstream: SocketAddr) -> Result<Self> {
        if !upstream.ip().is_loopback() {
            return Err("fault proxy requires loopback Redis");
        }
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| "bind fault proxy")?;
        let address = listener.local_addr().map_err(|_| "fault proxy address")?;
        let control = Control {
            armed: Arc::new(AtomicBool::new(false)),
            ever_armed: Arc::new(AtomicBool::new(false)),
            cuts: Arc::new(AtomicUsize::new(0)),
            cut: Arc::new(Notify::new()),
            attempts: Arc::new(Mutex::new(Vec::new())),
            publication_gate: Arc::new(tokio::sync::Mutex::new(())),
            cut_version: Arc::new(AtomicU64::new(0)),
        };
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(run(listener, upstream, control.clone(), stopped));
        Ok(Self {
            address,
            control,
            stop: Some(stop),
            task: Some(task),
        })
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn arm_next_committed_publish(&self) -> Result {
        if self.control.ever_armed.swap(true, Ordering::SeqCst) {
            return Err("fault proxy already armed");
        }
        self.control.armed.store(true, Ordering::SeqCst);
        Ok(())
    }
    pub fn cut_count(&self) -> usize {
        self.control.cuts.load(Ordering::SeqCst)
    }
    pub fn attempts(&self) -> Vec<(String, u64)> {
        self.control
            .attempts
            .lock()
            .expect("fixture attempt lock")
            .clone()
    }
    pub async fn wait_committed_cut(&self) -> Result {
        timeout(Duration::from_secs(10), async {
            loop {
                let notified = self.control.cut.notified();
                if self.cut_count() > 0 {
                    return;
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| "no committed publication reply was cut")
    }
    pub async fn shutdown(mut self) -> Result {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(mut task) = self.task.take() {
            match timeout(IO_BOUND, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err("fault proxy cleanup failed"),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    return Err("fault proxy cleanup failed");
                }
            }
        }
        Ok(())
    }
}

impl Drop for FaultProxy {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn run(
    listener: TcpListener,
    upstream: SocketAddr,
    control: Control,
    mut stopped: oneshot::Receiver<()>,
) {
    let mut tasks = JoinSet::new();
    loop {
        while tasks.try_join_next().is_some() {}
        tokio::select! {
            _ = &mut stopped => break,
            accepted = listener.accept() => {
                let Ok((socket, _)) = accepted else { break; };
                if tasks.len() >= 16 { continue; }
                tasks.spawn(connection(socket, upstream, control.clone()));
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

async fn connection(mut client: TcpStream, upstream: SocketAddr, control: Control) {
    let Ok(Ok(mut server)) = timeout(IO_BOUND, TcpStream::connect(upstream)).await else {
        return;
    };
    loop {
        // No artificial idle timer: the healthy publisher refreshes every20s.
        // Once a frame starts, each complete request/reply is bounded.
        let mut first = [0];
        if !client.peek(&mut first).await.is_ok_and(|count| count > 0) {
            return;
        }
        let Ok(Ok(request)) = timeout(IO_BOUND, read_resp_frame(&mut client, 0)).await else {
            return;
        };
        let publish = publication(&request);
        if let Some(attempt) = &publish {
            let mut attempts = control.attempts.lock().expect("fixture attempt lock");
            if attempts.len() >= 128 {
                return;
            }
            attempts.push(attempt.clone());
        }
        // A failed round may have up to four concurrent requests. Serialize
        // their forwarding so the selected commit is observable as a partial
        // inventory, then sever its remaining version before forwarding it.
        // A strictly higher recovery round is unaffected. This avoids making
        // the partial-round witness depend on executor/connection scheduling.
        let _publication = if let Some((_, version)) = &publish {
            let permit = control.publication_gate.lock().await;
            if control.cut_version.load(Ordering::SeqCst) == *version {
                return;
            }
            Some(permit)
        } else {
            None
        };
        if !matches!(
            timeout(IO_BOUND, server.write_all(&request)).await,
            Ok(Ok(()))
        ) {
            return;
        }
        let Ok(Ok(response)) = timeout(IO_BOUND, read_resp_frame(&mut server, 0)).await else {
            return;
        };
        // This exact Lua success reply is received only after Redis committed.
        // The one-shot exchange ensures other concurrent replies pass through.
        if publish.is_some()
            && response == b"*1\r\n$2\r\nok\r\n"
            && control
                .armed
                .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            control.cut_version.store(
                publish.as_ref().expect("selected publication").1,
                Ordering::SeqCst,
            );
            control.cuts.fetch_add(1, Ordering::SeqCst);
            control.cut.notify_one();
            return;
        }
        if !matches!(
            timeout(IO_BOUND, client.write_all(&response)).await,
            Ok(Ok(()))
        ) {
            return;
        }
    }
}

fn publication(request: &[u8]) -> Option<(String, u64)> {
    if request.first() != Some(&b'*') {
        return None;
    }
    let (count, mut cursor) = raw_line(request, 1)?;
    let count = std::str::from_utf8(count).ok()?.parse::<usize>().ok()?;
    if count != 9 {
        return None;
    }
    let mut args = Vec::new();
    for _ in 0..count {
        if request.get(cursor) != Some(&b'$') {
            return None;
        }
        let (length, next) = raw_line(request, cursor + 1)?;
        let length = std::str::from_utf8(length).ok()?.parse::<usize>().ok()?;
        let end = next.checked_add(length)?;
        if request.get(end..end.checked_add(2)?)? != b"\r\n" {
            return None;
        }
        args.push(request.get(next..end)?);
        cursor = end + 2;
    }
    if args[0] != b"EVAL"
        || args[2] != b"1"
        || !args[3].ends_with(b":membership:operator:directory")
    {
        return None;
    }
    let node = std::str::from_utf8(args[4]).ok()?;
    if node.len() > 128 {
        return None;
    }
    let version = std::str::from_utf8(args[5]).ok()?.parse().ok()?;
    Some((node.to_owned(), version))
}

fn raw_line(bytes: &[u8], start: usize) -> Option<(&[u8], usize)> {
    let relative = bytes
        .get(start..)?
        .windows(2)
        .position(|pair| pair == b"\r\n")?;
    let end = start.checked_add(relative)?;
    Some((&bytes[start..end], end.checked_add(2)?))
}

fn read_resp_frame<'a, R>(
    reader: &'a mut R,
    depth: usize,
) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + 'a>>
where
    R: AsyncRead + Unpin + Send + 'a,
{
    Box::pin(async move {
        if depth > 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RESP nesting bound",
            ));
        }
        let mut raw = Vec::new();
        let mut marker = [0_u8; 1];
        reader.read_exact(&mut marker).await?;
        raw.push(marker[0]);
        match marker[0] {
            b'+' | b'-' | b':' | b',' | b'#' | b'_' | b'(' => {
                read_resp_line(reader, &mut raw).await?;
            }
            b'$' | b'!' | b'=' => {
                let line = read_resp_line(reader, &mut raw).await?;
                let length = parse_resp_integer(&line)?;
                if length < -1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid RESP bulk length",
                    ));
                }
                if length >= 0 {
                    let length = usize::try_from(length).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "RESP bulk length overflow")
                    })?;
                    if length > MAX_RESP_FRAME {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "RESP bulk frame bound",
                        ));
                    }
                    let mut payload = vec![0_u8; length.saturating_add(2)];
                    reader.read_exact(&mut payload).await?;
                    if payload[length..] != *b"\r\n" {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "RESP bulk terminator",
                        ));
                    }
                    raw.extend(payload);
                }
            }
            b'*' | b'~' | b'>' => {
                let line = read_resp_line(reader, &mut raw).await?;
                let count = parse_resp_integer(&line)?;
                if count < -1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid RESP array count",
                    ));
                }
                if count == -1 {
                    return Ok(raw);
                }
                let count = usize::try_from(count).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "RESP array count overflow")
                })?;
                if count > MAX_RESP_ITEMS {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "RESP array bound",
                    ));
                }
                for _ in 0..count {
                    raw.extend(read_resp_frame(reader, depth + 1).await?);
                    if raw.len() > MAX_RESP_FRAME {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "RESP frame bound",
                        ));
                    }
                }
            }
            b'%' => {
                let line = read_resp_line(reader, &mut raw).await?;
                let count = parse_resp_integer(&line)?;
                if count < -1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid RESP map count",
                    ));
                }
                if count == -1 {
                    return Ok(raw);
                }
                let count = usize::try_from(count)
                    .ok()
                    .and_then(|count| count.checked_mul(2))
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "RESP map count overflow")
                    })?;
                if count > MAX_RESP_ITEMS {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "RESP map bound"));
                }
                for _ in 0..count {
                    raw.extend(read_resp_frame(reader, depth + 1).await?);
                    if raw.len() > MAX_RESP_FRAME {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "RESP frame bound",
                        ));
                    }
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported RESP marker",
                ));
            }
        }
        if raw.len() > MAX_RESP_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RESP frame bound",
            ));
        }
        Ok(raw)
    })
}

async fn read_resp_line<R>(reader: &mut R, raw: &mut Vec<u8>) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        reader.read_exact(&mut byte).await?;
        raw.push(byte[0]);
        line.push(byte[0]);
        if line.len() > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RESP line bound",
            ));
        }
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
}

fn parse_resp_integer(line: &[u8]) -> io::Result<i64> {
    let line = line
        .strip_suffix(b"\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RESP line terminator"))?;
    std::str::from_utf8(line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "RESP integer encoding"))?
        .parse::<i64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "RESP integer"))
}
