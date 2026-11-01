//! STAMP Session-Sender: one UDP socket per target, a pacing thread that sends
//! and a receive thread that timestamps replies, feeds the tracker and emits
//! records.

use crate::clock;
use crate::config::{parse_v4_endpoint, ProbeConfig, StampTarget};
use crate::ntp;
use crate::output::Item;
use crate::record::{Record, SessionMeta};
use crate::stamp::{ReflectorPacket, SenderPacket, PORT};
use crate::sys;
use crate::trace::{self, TtlDebounce, TtlHint};
use crate::tracker::{RemoteTimes, Reply, Tracker, TrackerConfig};
use crate::{error_reason, lock, sleep_until, Throttle, POLL_INTERVAL};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub fn spawn(
    probe: &ProbeConfig,
    t: &StampTarget,
    out: Sender<Item>,
    stop: Arc<AtomicBool>,
) -> io::Result<Vec<JoinHandle<()>>> {
    let invalid = |e: String| io::Error::new(io::ErrorKind::InvalidInput, e);
    let dst = parse_v4_endpoint(&t.target, PORT).map_err(invalid)?;
    let src = match &t.source {
        Some(s) => parse_v4_endpoint(s, 0).map_err(invalid)?,
        None => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    };

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.bind(&SockAddr::from(src))?;
    sock.set_tos(u32::from(t.dscp) << 2)?;
    // Connecting filters replies to the reflector's address and pins the source.
    sock.connect(&SockAddr::from(dst))?;
    sock.set_read_timeout(Some(POLL_INTERVAL))?;
    sys::enable_rx_timestamps(sock.as_raw_fd())?;
    sys::enable_recv_ttl(sock.as_raw_fd())?;
    let local = sock.local_addr()?.as_socket().map(sys::v4).transpose()?.unwrap_or(src);

    let meta = SessionMeta {
        probe_id: probe.probe_id.clone(),
        site: probe.site.clone(),
        session: t.name.clone(),
        kind: "stamp",
        app_class: probe.app_class(&t.app_class).to_string(),
        dscp: t.dscp,
        src: local.to_string(),
        dst: dst.to_string(),
    };
    log::info!(
        "stamp {}: {} -> {} at {} pps, dscp {}, {} B, app_class {}",
        t.name,
        local,
        dst,
        t.pps,
        t.dscp,
        t.size,
        meta.app_class
    );

    let tracker =
        Arc::new(Mutex::new(Tracker::new(TrackerConfig::new(probe.timeout_ms(t.timeout_ms), t.stateful_reflector))));
    let interval = Duration::from_secs_f64(1.0 / t.pps);
    let hint = Arc::new(TtlHint::default());
    let mut handles = Vec::new();

    if t.trace.enabled {
        let flow = trace::Flow { local, dst, tag: trace_tag(&t.name, local) };
        handles.push(trace::spawn(
            sock.try_clone()?,
            t.trace.clone(),
            meta.clone(),
            flow,
            Arc::clone(&hint),
            out.clone(),
            Arc::clone(&stop),
        )?);
    }
    if let Some(cap) = t.capacity.as_ref().filter(|c| c.enabled) {
        handles.push(crate::capacity::spawn(
            cap.clone(),
            local,
            dst,
            t.dscp,
            Duration::from_millis(probe.timeout_ms(t.timeout_ms)),
            meta.clone(),
            out.clone(),
            Arc::clone(&stop),
        )?);
    }

    let tx = {
        let sock = sock.try_clone()?;
        let tracker = Arc::clone(&tracker);
        let stop = Arc::clone(&stop);
        let name = t.name.clone();
        let size = t.size;
        std::thread::Builder::new()
            .name(format!("stamp-tx-{name}"))
            .spawn(move || send_loop(&sock, &tracker, interval, size, &stop, &name))?
    };
    let rx = {
        let stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name(format!("stamp-rx-{}", t.name))
            .spawn(move || recv_loop(&sock, &tracker, &meta, &out, &hint, &stop))?
    };
    handles.extend([tx, rx]);
    Ok(handles)
}

/// Identifies this session's trace packets when routers quote the payload.
fn trace_tag(name: &str, local: SocketAddrV4) -> u16 {
    let h = name
        .bytes()
        .chain(local.port().to_be_bytes())
        .fold(0x811c_9dc5_u32, |h, b| (h ^ u32::from(b)).wrapping_mul(0x0100_0193));
    (h ^ (h >> 16)) as u16
}

fn send_loop(sock: &Socket, tracker: &Mutex<Tracker>, interval: Duration, size: usize, stop: &AtomicBool, name: &str) {
    let mut buf = vec![0_u8; size];
    let mut throttle = Throttle::new(Duration::from_secs(30));
    let start = Instant::now();
    let mut k: u32 = 0;
    loop {
        let due = start + interval * k;
        if !sleep_until(due, stop) {
            return;
        }
        let behind = Instant::now().saturating_duration_since(due);
        if behind > interval * 2 {
            // Suspended or starved: skip the missed slots instead of bursting.
            k = (start.elapsed().as_secs_f64() / interval.as_secs_f64()).ceil() as u32;
            continue;
        }
        k = k.wrapping_add(1);

        let status = clock::status();
        let (seq, t1) = {
            let mut tr = lock(tracker);
            let t1 = clock::now_ns();
            (tr.on_sent(t1), t1)
        };
        SenderPacket {
            seq: seq as u32,
            timestamp: ntp::from_unix_ns(t1),
            error_estimate: clock::encode_error_estimate(status),
        }
        .encode(&mut buf);
        if let Err(e) = sock.send(&buf) {
            lock(tracker).on_failure(seq, error_reason(&e));
            if let Some(n) = throttle.ready() {
                log::warn!("stamp {name}: send failed: {e} ({n} similar suppressed)");
            }
        }
    }
}

fn recv_loop(
    sock: &Socket,
    tracker: &Mutex<Tracker>,
    meta: &SessionMeta,
    out: &Sender<Item>,
    hint: &TtlHint,
    stop: &AtomicBool,
) {
    let fd = sock.as_raw_fd();
    // A path-length change shows up in the TTLs within a second; the trace
    // thread re-traces on it. Three equal replies in a row before it counts.
    let mut ttl_debounce = TtlDebounce::new(3);
    let mut buf = [0_u8; 2048];
    let mut last_poll = Instant::now();
    let mut err_throttle = Throttle::new(Duration::from_secs(30));
    let mut malformed: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        match sys::recv_meta(fd, &mut buf) {
            Ok(m) => match ReflectorPacket::decode(&buf[..m.len]) {
                Some(p) => {
                    if let Some(back) = m.ttl {
                        ttl_debounce.observe(p.sender_ttl, back, hint);
                    }
                    let t4 = m.kernel_ts_ns.unwrap_or_else(clock::now_ns);
                    let local = clock::status();
                    let (synced, err_us) = clock::decode_error_estimate(p.error_estimate);
                    let mut tr = lock(tracker);
                    let seq = tr.widen32(p.sender_seq);
                    tr.on_reply(Reply {
                        seq,
                        t4_ns: t4,
                        kernel_ts: m.kernel_ts_ns.is_some(),
                        remote: Some(RemoteTimes {
                            t2_ns: ntp::to_unix_ns_near(p.receive_timestamp, t4),
                            t3_ns: ntp::to_unix_ns_near(p.timestamp, t4),
                            reflector_seq: p.seq,
                            synced,
                            err_us,
                            ttl_fwd: p.sender_ttl,
                        }),
                        ttl_back: m.ttl,
                        local_synced: local.synced,
                        local_err_us: local.est_error_us,
                        rtt_ns: None,
                        echoed_t1_ns: Some(ntp::to_unix_ns_near(p.sender_timestamp, t4)),
                    });
                }
                None => {
                    malformed += 1;
                    if let Some(n) = err_throttle.ready() {
                        log::warn!(
                            "stamp {}: {malformed} malformed replies so far ({n} logs suppressed)",
                            meta.session
                        );
                    }
                }
            },
            Err(e) if sys::is_timeout(&e) => {}
            Err(e) => {
                // ECONNREFUSED here means an ICMP port-unreachable came back: the
                // reflector is down. The packets are counted lost by timeout.
                if let Some(n) = err_throttle.ready() {
                    log::warn!("stamp {}: receive error: {e} ({n} similar suppressed)", meta.session);
                }
                std::thread::sleep(POLL_INTERVAL);
            }
        }
        if last_poll.elapsed() >= POLL_INTERVAL {
            last_poll = Instant::now();
            let buckets = lock(tracker).poll(clock::now_ns());
            for b in buckets {
                if out.send(Record::new(meta, b).into()).is_err() {
                    return; // output thread gone: shutting down
                }
            }
        }
    }
}
