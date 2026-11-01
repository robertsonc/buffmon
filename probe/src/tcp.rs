//! TCP connect probe: service reachability and handshake time. The RTT comes
//! from the kernel's TCP_INFO (the SYN → SYN-ACK sample) when available.

use crate::clock;
use crate::config::{ProbeConfig, TcpTarget};
use crate::record::{Record, SessionMeta};
use crate::sys;
use crate::tracker::{Reply, Tracker, TrackerConfig};
use crate::{error_reason, sleep_until, POLL_INTERVAL};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct Connected {
    pub rtt_ns: i64,
    /// RTT came from the kernel's TCP_INFO rather than a user-space timer.
    pub kernel_rtt: bool,
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    pub reason: &'static str,
    pub remote: Option<SocketAddrV4>,
}

/// Resolves `host:port` to the first IPv4 address, bounded by `timeout`
/// (getaddrinfo itself has no timeout, so it runs on a helper thread).
pub fn resolve_v4(target: &str, timeout: Duration) -> Option<SocketAddrV4> {
    let (tx, rx) = mpsc::channel();
    let target = target.to_string();
    let spawned = std::thread::Builder::new().name("tcp-resolve".into()).spawn(move || {
        let addr = target.to_socket_addrs().ok().and_then(|mut it| it.find_map(|a| sys::v4(a).ok()));
        let _ = tx.send(addr);
    });
    if spawned.is_err() {
        return None;
    }
    rx.recv_timeout(timeout).ok().flatten()
}

/// One non-blocking connect with a timeout. The socket is closed immediately.
pub fn connect_once(target: &str, dscp: u8, timeout: Duration) -> Result<Connected, Failure> {
    let remote = resolve_v4(target, timeout).ok_or(Failure { reason: "dns", remote: None })?;
    let fail = |reason: &'static str| Failure { reason, remote: Some(remote) };
    let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).map_err(|e| fail(error_reason(&e)))?;
    sock.set_tos(u32::from(dscp) << 2).map_err(|e| fail(error_reason(&e)))?;
    sock.set_nonblocking(true).map_err(|e| fail(error_reason(&e)))?;

    let start = Instant::now();
    match sock.connect(&SockAddr::from(remote)) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {
            let ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
            match sys::wait_writable(sock.as_raw_fd(), ms) {
                Ok(true) => {}
                Ok(false) => return Err(fail("timeout")),
                Err(e) => return Err(fail(error_reason(&e))),
            }
            if let Ok(Some(e)) = sock.take_error() {
                return Err(fail(error_reason(&e)));
            }
        }
        Err(e) => return Err(fail(error_reason(&e))),
    }
    let elapsed_ns = start.elapsed().as_nanos() as i64;
    let (rtt_ns, kernel_rtt) = match sys::tcp_rtt_us(sock.as_raw_fd()) {
        Some(us) => (i64::from(us) * 1000, true),
        None => (elapsed_ns, false),
    };
    let local = sock
        .local_addr()
        .ok()
        .and_then(|a| a.as_socket())
        .and_then(|a| sys::v4(a).ok())
        .unwrap_or(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    Ok(Connected { rtt_ns, kernel_rtt, local, remote })
}

pub fn spawn(
    probe: &ProbeConfig,
    t: &TcpTarget,
    out: Sender<Record>,
    stop: Arc<AtomicBool>,
) -> io::Result<Vec<JoinHandle<()>>> {
    let connect_timeout_ms = t.timeout_ms.unwrap_or(3000);
    let mut meta = SessionMeta {
        probe_id: probe.probe_id.clone(),
        site: probe.site.clone(),
        session: t.name.clone(),
        kind: "tcp",
        app_class: probe.app_class(&t.app_class).to_string(),
        dscp: t.dscp,
        src: "0.0.0.0:0".to_string(),
        dst: "0.0.0.0:0".to_string(),
    };
    // The tracker's loss timeout must outlast the connect timeout, so every
    // attempt is resolved by the attempt itself (success or a classified failure).
    let mut tracker = Tracker::new(TrackerConfig::new(connect_timeout_ms + 1000, false));
    let interval = Duration::from_millis(t.interval_ms);
    let timeout = Duration::from_millis(connect_timeout_ms);
    let target = t.target.clone();
    let dscp = t.dscp;
    log::info!("tcp {}: connect to {} every {} ms, dscp {}", t.name, target, t.interval_ms, dscp);

    let handle = std::thread::Builder::new().name(format!("tcp-{}", t.name)).spawn(move || {
        let start = Instant::now();
        let mut k: u32 = 0;
        loop {
            let due = start + interval * k;
            // Poll (emit records) while waiting for the next attempt.
            while Instant::now() < due {
                if !sleep_until((Instant::now() + POLL_INTERVAL).min(due), &stop) {
                    return;
                }
                if !emit(&mut tracker, &meta, &out) {
                    return;
                }
            }
            if Instant::now().saturating_duration_since(due) > interval * 2 {
                k = (start.elapsed().as_secs_f64() / interval.as_secs_f64()).ceil() as u32;
                continue;
            }
            k = k.wrapping_add(1);

            let t1 = clock::now_ns();
            let seq = tracker.on_sent(t1);
            match connect_once(&target, dscp, timeout) {
                Ok(c) => {
                    meta.src = SocketAddrV4::new(*c.local.ip(), 0).to_string();
                    meta.dst = c.remote.to_string();
                    let local = clock::status();
                    tracker.on_reply(Reply {
                        seq,
                        t4_ns: t1 + c.rtt_ns,
                        kernel_ts: c.kernel_rtt,
                        remote: None,
                        ttl_back: None,
                        local_synced: local.synced,
                        local_err_us: local.est_error_us,
                        rtt_ns: Some(c.rtt_ns),
                        echoed_t1_ns: None,
                    });
                }
                Err(f) => {
                    if let Some(r) = f.remote {
                        meta.dst = r.to_string();
                    }
                    tracker.on_failure(seq, f.reason);
                }
            }
            if !emit(&mut tracker, &meta, &out) {
                return;
            }
        }
    })?;
    Ok(vec![handle])
}

fn emit(tracker: &mut Tracker, meta: &SessionMeta, out: &Sender<Record>) -> bool {
    tracker.poll(clock::now_ns()).into_iter().all(|b| out.send(Record::new(meta, b)).is_ok())
}
