//! ICMP echo. Reachability, not path quality: routers and firewalls rate-limit
//! and deprioritise ICMP, so these results are labelled as reachability.
//!
//! Uses a raw socket (needs CAP_NET_RAW) and falls back to the unprivileged
//! datagram ICMP socket when the capability is missing.

use crate::clock;
use crate::config::{IcmpTarget, ProbeConfig};
use crate::output::Item;
use crate::record::{Record, SessionMeta};
use crate::sys;
use crate::tracker::{Reply, Tracker, TrackerConfig};
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

const MAGIC: &[u8; 8] = b"BUFFMON1";
const ECHO_REQUEST: u8 = 8;
const ECHO_REPLY: u8 = 0;
/// 8-byte ICMP header + magic + logical seq + session tag.
const ECHO_LEN: usize = 8 + 8 + 8 + 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Raw,
    Datagram,
}

/// Internet checksum (RFC 1071).
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 { u16::from_be_bytes([chunk[0], chunk[1]]) } else { u16::from(chunk[0]) << 8 };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn build_echo(ident: u16, seq: u64, tag: u64) -> [u8; ECHO_LEN] {
    let mut p = [0_u8; ECHO_LEN];
    p[0] = ECHO_REQUEST;
    p[4..6].copy_from_slice(&ident.to_be_bytes());
    p[6..8].copy_from_slice(&(seq as u16).to_be_bytes());
    p[8..16].copy_from_slice(MAGIC);
    p[16..24].copy_from_slice(&seq.to_be_bytes());
    p[24..32].copy_from_slice(&tag.to_be_bytes());
    let c = checksum(&p);
    p[2..4].copy_from_slice(&c.to_be_bytes());
    p
}

/// Parses an echo reply (ICMP message without IP header). Returns the logical
/// sequence number if it is one of ours.
pub fn parse_reply(icmp: &[u8], ident: Option<u16>, tag: u64) -> Option<u64> {
    if icmp.len() < ECHO_LEN || icmp[0] != ECHO_REPLY || icmp[1] != 0 {
        return None;
    }
    if let Some(id) = ident {
        if u16::from_be_bytes([icmp[4], icmp[5]]) != id {
            return None;
        }
    }
    if &icmp[8..16] != MAGIC || u64::from_be_bytes(icmp[24..32].try_into().ok()?) != tag {
        return None;
    }
    Some(u64::from_be_bytes(icmp[16..24].try_into().ok()?))
}

fn open() -> io::Result<(Socket, Mode)> {
    match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(s) => Ok((s, Mode::Raw)),
        Err(e) if matches!(e.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) => {
            log::warn!("no CAP_NET_RAW; using unprivileged datagram ICMP (needs net.ipv4.ping_group_range)");
            Ok((Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?, Mode::Datagram))
        }
        Err(e) => Err(e),
    }
}

fn session_tag(name: &str) -> u64 {
    // FNV-1a over the session name, mixed with the pid and start time so two
    // probes on one host never claim each other's replies.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h ^ (u64::from(std::process::id()) << 32) ^ (clock::now_ns() as u64)
}

pub fn spawn(
    probe: &ProbeConfig,
    t: &IcmpTarget,
    out: Sender<Item>,
    stop: Arc<AtomicBool>,
) -> io::Result<Vec<JoinHandle<()>>> {
    let (sock, mode) = open()?;
    let dst = SocketAddrV4::new(t.target, 0);
    sock.set_tos(u32::from(t.dscp) << 2)?;
    // connect() also filters raw-socket input to this remote address.
    sock.connect(&SockAddr::from(dst))?;
    sock.set_read_timeout(Some(POLL_INTERVAL))?;
    sys::enable_rx_timestamps(sock.as_raw_fd())?;
    if mode == Mode::Datagram {
        sys::enable_recv_ttl(sock.as_raw_fd())?;
    }
    let local_ip = sock.local_addr()?.as_socket().map(sys::v4).transpose()?.map_or(Ipv4Addr::UNSPECIFIED, |a| *a.ip());

    let tag = session_tag(&t.name);
    // Datagram ICMP sockets rewrite the identifier; only raw mode can match on it.
    let ident = (tag as u16) ^ (std::process::id() as u16);
    let meta = SessionMeta {
        probe_id: probe.probe_id.clone(),
        site: probe.site.clone(),
        session: t.name.clone(),
        kind: "icmp",
        app_class: probe.app_class(&t.app_class).to_string(),
        dscp: t.dscp,
        src: SocketAddrV4::new(local_ip, 0).to_string(),
        dst: dst.to_string(),
    };
    log::info!("icmp {}: {} -> {} at {} pps ({:?} socket)", t.name, local_ip, t.target, t.pps, mode);

    let tracker = Arc::new(Mutex::new(Tracker::new(TrackerConfig::new(probe.timeout_ms(t.timeout_ms), false))));
    let interval = Duration::from_secs_f64(1.0 / t.pps);

    let tx = {
        let sock = sock.try_clone()?;
        let tracker = Arc::clone(&tracker);
        let stop = Arc::clone(&stop);
        let name = t.name.clone();
        std::thread::Builder::new().name(format!("icmp-tx-{name}")).spawn(move || {
            let mut throttle = Throttle::new(Duration::from_secs(30));
            let start = Instant::now();
            let mut k: u32 = 0;
            loop {
                let due = start + interval * k;
                if !sleep_until(due, &stop) {
                    return;
                }
                if Instant::now().saturating_duration_since(due) > interval * 2 {
                    k = (start.elapsed().as_secs_f64() / interval.as_secs_f64()).ceil() as u32;
                    continue;
                }
                k = k.wrapping_add(1);
                let seq = lock(&tracker).on_sent(clock::now_ns());
                if let Err(e) = sock.send(&build_echo(ident, seq, tag)) {
                    lock(&tracker).on_failure(seq, error_reason(&e));
                    if let Some(n) = throttle.ready() {
                        log::warn!("icmp {name}: send failed: {e} ({n} similar suppressed)");
                    }
                }
            }
        })?
    };

    let rx = {
        let stop = Arc::clone(&stop);
        std::thread::Builder::new().name(format!("icmp-rx-{}", t.name)).spawn(move || {
            let fd = sock.as_raw_fd();
            let mut buf = [0_u8; 2048];
            let mut last_poll = Instant::now();
            let mut throttle = Throttle::new(Duration::from_secs(30));
            while !stop.load(Ordering::Relaxed) {
                match sys::recv_meta(fd, &mut buf) {
                    Ok(m) => {
                        let pkt = &buf[..m.len];
                        let (icmp, ttl) = match mode {
                            Mode::Raw => {
                                if pkt.len() < 20 {
                                    continue;
                                }
                                let ihl = usize::from(pkt[0] & 0x0F) * 4;
                                if pkt.len() < ihl {
                                    continue;
                                }
                                (&pkt[ihl..], Some(pkt[8]))
                            }
                            Mode::Datagram => (pkt, m.ttl),
                        };
                        let want_ident = if mode == Mode::Raw { Some(ident) } else { None };
                        if let Some(seq) = parse_reply(icmp, want_ident, tag) {
                            let local = clock::status();
                            lock(&tracker).on_reply(Reply {
                                seq,
                                t4_ns: m.kernel_ts_ns.unwrap_or_else(clock::now_ns),
                                kernel_ts: m.kernel_ts_ns.is_some(),
                                remote: None,
                                ttl_back: ttl,
                                local_synced: local.synced,
                                local_err_us: local.est_error_us,
                                rtt_ns: None,
                                echoed_t1_ns: None,
                            });
                        }
                    }
                    Err(e) if sys::is_timeout(&e) => {}
                    Err(e) => {
                        if let Some(n) = throttle.ready() {
                            log::warn!("icmp {}: receive error: {e} ({n} similar suppressed)", meta.session);
                        }
                        std::thread::sleep(POLL_INTERVAL);
                    }
                }
                if last_poll.elapsed() >= POLL_INTERVAL {
                    last_poll = Instant::now();
                    for b in lock(&tracker).poll(clock::now_ns()) {
                        if out.send(Record::new(&meta, b).into()).is_err() {
                            return;
                        }
                    }
                }
            }
        })?
    };
    Ok(vec![tx, rx])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_valid_packet_is_zero() {
        let p = build_echo(0x1234, 7, 42);
        assert_eq!(checksum(&p), 0);
    }

    #[test]
    fn checksum_matches_rfc1071_example() {
        // RFC 1071 §3: 0001 f203 f4f5 f6f7 → sum ddf2, checksum 220d.
        assert_eq!(checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]), 0x220d);
    }

    #[test]
    fn reply_parsing_matches_only_our_packets() {
        let mut reply = build_echo(0xBEEF, 1_000_000, 99);
        reply[0] = ECHO_REPLY;
        assert_eq!(parse_reply(&reply, Some(0xBEEF), 99), Some(1_000_000));
        assert_eq!(parse_reply(&reply, None, 99), Some(1_000_000));
        assert_eq!(parse_reply(&reply, Some(0xBEEE), 99), None, "other identifier");
        assert_eq!(parse_reply(&reply, Some(0xBEEF), 98), None, "other session");
        reply[0] = ECHO_REQUEST;
        assert_eq!(parse_reply(&reply, Some(0xBEEF), 99), None, "not a reply");
    }
}
