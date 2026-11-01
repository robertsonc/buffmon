//! End-to-end on 127.0.0.1 with real sockets: reflector + STAMP sender, ICMP
//! echo, and TCP connect, each producing records through the public API.

use buffmon_probe::config::ProbeConfig;
use buffmon_probe::output::Item;
use buffmon_probe::record::Record;
use buffmon_probe::reflector::{Reflector, ReflectorConfig};
use buffmon_probe::stamp::{ReflectorPacket, SenderPacket};
use buffmon_probe::{icmp, stamp_session, sys, tcp};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{SocketAddrV4, TcpListener};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

fn start_reflector(allow: &[&str]) -> (SocketAddrV4, Arc<AtomicBool>, JoinHandle<()>) {
    let cfg = ReflectorConfig {
        listen: "127.0.0.1:0".into(),
        allow: allow.iter().map(|s| s.to_string()).collect(),
        ..ReflectorConfig::default()
    };
    let r = Reflector::bind(cfg).expect("bind reflector");
    let addr = r.local_addr();
    let stop = Arc::new(AtomicBool::new(false));
    let s = Arc::clone(&stop);
    let h = std::thread::spawn(move || {
        r.run(&s);
    });
    (addr, stop, h)
}

fn probe_config(body: &str) -> ProbeConfig {
    let cfg: ProbeConfig = toml::from_str(&format!(
        "probe_id = \"test-probe\"\nsite = \"LAB\"\n[output]\n[defaults]\ntimeout_ms = 500\n{body}"
    ))
    .expect("config parses");
    cfg.validate().expect("config valid");
    cfg
}

/// Collects everything sessions emit for `run_for`, then stops them and drains.
fn collect_items(
    rx: mpsc::Receiver<Item>,
    stop: &AtomicBool,
    handles: Vec<JoinHandle<()>>,
    run_for: Duration,
) -> Vec<Item> {
    let deadline = Instant::now() + run_for;
    let mut out = Vec::new();
    while Instant::now() < deadline {
        if let Ok(r) = rx.recv_timeout(Duration::from_millis(50)) {
            out.push(r);
        }
    }
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().expect("session thread");
    }
    out.extend(rx.try_iter());
    out
}

/// As [`collect_items`], keeping only the per-second records.
fn collect(
    rx: mpsc::Receiver<Item>,
    stop: &AtomicBool,
    handles: Vec<JoinHandle<()>>,
    run_for: Duration,
) -> Vec<Record> {
    collect_items(rx, stop, handles, run_for)
        .into_iter()
        .filter_map(|i| match i {
            Item::Record(r) => Some(r),
            _ => None,
        })
        .collect()
}

#[test]
fn stamp_session_against_reflector() {
    let (addr, rstop, rh) = start_reflector(&["127.0.0.0/8"]);
    let cfg = probe_config(&format!(
        "[[stamp]]\nname = \"lo-voice\"\ntarget = \"{addr}\"\npps = 50\ndscp = 46\napp_class = \"voice\"\n"
    ));
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let handles = stamp_session::spawn(&cfg, &cfg.stamp[0], tx, Arc::clone(&stop)).expect("spawn");
    let records = collect(rx, &stop, handles, Duration::from_millis(3_500));
    rstop.store(true, Ordering::Relaxed);
    rh.join().unwrap();

    assert!(records.len() >= 2, "expected >= 2 one-second records, got {}", records.len());
    for r in &records {
        assert_eq!((r.kind, r.session.as_str(), r.dscp, r.app_class.as_str()), ("stamp", "lo-voice", 46, "voice"));
        assert_eq!(r.dst, addr.to_string());
        assert_eq!(r.ts_ms % 1000, 0);
        assert_eq!(r.sent, r.received + r.lost, "sent = received + lost");
        assert_eq!(r.rtt_us.len() as u32, r.received);
        assert_eq!(r.lost, 0, "no loss on loopback: {r:?}");
        assert_eq!((r.fwd_lost, r.back_lost), (Some(0), Some(0)));
        assert!(r.rtt_us.iter().all(|us| *us < 20_000), "loopback RTT under 20 ms: {:?}", r.rtt_us);
        assert_eq!(r.rx_ts, "kernel", "kernel receive timestamps");
        assert!(r.ttl_fwd.is_some() && r.ttl_back.is_some());
        assert_eq!(r.ttl_fwd, r.ttl_back, "loopback: same TTL both ways");
        assert!(r.ipdv_fwd_n > 0 && r.ipdv_back_n > 0);
    }
    // A full second at 50 pps.
    assert!(records.iter().any(|r| r.sent >= 45), "{:?}", records.iter().map(|r| r.sent).collect::<Vec<_>>());
    // Records come out in time order with no duplicates.
    let ts: Vec<i64> = records.iter().map(|r| r.ts_ms).collect();
    assert!(ts.windows(2).all(|w| w[0] < w[1]), "{ts:?}");
}

#[test]
fn reflector_reflects_dscp_size_and_ttl() {
    let (addr, rstop, rh) = start_reflector(&["127.0.0.1/32"]);
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    sock.bind(&SockAddr::from("127.0.0.1:0".parse::<SocketAddrV4>().unwrap())).unwrap();
    sock.set_tos(0xB8 | 0x01).unwrap(); // EF + ECN(ECT1): DSCP must come back, ECN must not
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    sys::enable_recv_tos(sock.as_raw_fd()).unwrap();

    let mut pkt = vec![0_u8; 200];
    SenderPacket { seq: 7, timestamp: 123, error_estimate: 0x0101 }.encode(&mut pkt);
    sock.send_to(&pkt, &SockAddr::from(addr)).unwrap();
    sock.send_to(&pkt, &SockAddr::from(addr)).unwrap();

    let mut buf = [0_u8; 2048];
    let m1 = sys::recv_meta(sock.as_raw_fd(), &mut buf).expect("reply 1");
    let r1 = ReflectorPacket::decode(&buf[..m1.len]).unwrap();
    let m2 = sys::recv_meta(sock.as_raw_fd(), &mut buf).expect("reply 2");
    let r2 = ReflectorPacket::decode(&buf[..m2.len]).unwrap();
    rstop.store(true, Ordering::Relaxed);
    rh.join().unwrap();

    assert_eq!(m1.len, 200, "reply is the same size as the request");
    assert_eq!(m1.tos, Some(0xB8), "DSCP reflected, ECN not");
    assert_eq!((r1.sender_seq, r1.sender_timestamp, r1.sender_error_estimate), (7, 123, 0x0101));
    assert!(r1.sender_ttl > 0, "reflector reports the TTL it received");
    assert_eq!((r1.seq, r2.seq), (0, 1), "stateful: reflector numbers packets per session");
    assert!(r1.timestamp >= r1.receive_timestamp, "T3 >= T2");
}

#[test]
fn reflector_ignores_sources_outside_the_allowlist() {
    let (addr, rstop, rh) = start_reflector(&["10.0.0.0/8"]);
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(400))).unwrap();
    let mut pkt = [0_u8; 44];
    SenderPacket { seq: 1, timestamp: 1, error_estimate: 1 }.encode(&mut pkt);
    sock.send_to(&pkt, &SockAddr::from(addr)).unwrap();
    let mut buf = [0_u8; 128];
    let got = sys::recv_meta(sock.as_raw_fd(), &mut buf);
    rstop.store(true, Ordering::Relaxed);
    rh.join().unwrap();
    assert!(got.is_err(), "no reply expected");
}

#[test]
fn stamp_to_dead_reflector_counts_loss() {
    // Nothing listens here: every packet is lost, the split is unknown.
    let cfg = probe_config("[[stamp]]\nname = \"dead\"\ntarget = \"127.0.0.1:9\"\npps = 20\n");
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let handles = stamp_session::spawn(&cfg, &cfg.stamp[0], tx, Arc::clone(&stop)).unwrap();
    let records = collect(rx, &stop, handles, Duration::from_millis(5_500));
    assert!(!records.is_empty());
    for r in &records {
        assert_eq!(r.received, 0);
        assert_eq!(r.lost, r.sent);
        assert_eq!((r.fwd_lost, r.back_lost), (None, None), "no reply ever arrived, so no split");
    }
}

#[test]
fn icmp_echo_to_loopback() {
    let cfg = probe_config("[[icmp]]\nname = \"lo-gw\"\ntarget = \"127.0.0.1\"\npps = 20\n");
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let handles = match icmp::spawn(&cfg, &cfg.icmp[0], tx, Arc::clone(&stop)) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("skipping: no ICMP socket available here ({e})");
            return;
        }
    };
    let records = collect(rx, &stop, handles, Duration::from_millis(2_800));
    assert!(!records.is_empty());
    for r in &records {
        assert_eq!(r.kind, "icmp");
        assert_eq!(r.lost, 0, "{r:?}");
        assert!(r.received > 0);
        assert!(r.ttl_back.is_some());
        assert_eq!((r.fwd_lost, r.back_lost), (None, None));
    }
}

#[test]
fn tcp_connect_success_and_refusal() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let open_port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            drop(s);
        }
    });
    // A port that was just free: bind, read the port, release it.
    let closed_port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();

    let cfg = probe_config(&format!(
        "[[tcp]]\nname = \"open\"\ntarget = \"127.0.0.1:{open_port}\"\ninterval_ms = 500\n\
         [[tcp]]\nname = \"closed\"\ntarget = \"127.0.0.1:{closed_port}\"\ninterval_ms = 500\n"
    ));
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = tcp::spawn(&cfg, &cfg.tcp[0], tx.clone(), Arc::clone(&stop)).unwrap();
    handles.extend(tcp::spawn(&cfg, &cfg.tcp[1], tx, Arc::clone(&stop)).unwrap());
    let records = collect(rx, &stop, handles, Duration::from_millis(3_500));

    let open: Vec<&Record> = records.iter().filter(|r| r.session == "open").collect();
    let closed: Vec<&Record> = records.iter().filter(|r| r.session == "closed").collect();
    assert!(!open.is_empty() && !closed.is_empty());
    assert!(open.iter().all(|r| r.lost == 0 && r.received == r.sent));
    assert!(open.iter().all(|r| r.dst == format!("127.0.0.1:{open_port}")));
    assert!(closed.iter().all(|r| r.received == 0 && r.errors.get("refused") == Some(&r.lost)));
}
