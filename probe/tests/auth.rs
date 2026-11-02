//! Authenticated STAMP (RFC 8762) and RFC 8972 TLV handling, end to end on
//! loopback: reflector with a keys file, real sessions and hand-made packets.

use buffmon_probe::config::ProbeConfig;
use buffmon_probe::output::Item;
use buffmon_probe::record::Record;
use buffmon_probe::reflector::{add_key, parse_keys, ReflectedControlConfig, Reflector, ReflectorConfig, Stats};
use buffmon_probe::stamp::{
    check_ext_hmac, flag, min_len, parse_tlvs, tlv_type, ExtIntegrity, Key, Mode, ReflectedControl, ReflectorPacket,
    SenderPacket, Tlv, AUTH_BASE_LEN, BASE_LEN,
};
use buffmon_probe::{stamp_session, sys};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::SocketAddrV4;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SSID: u16 = 4101;

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("bm-auth-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_keys(dir: &Path) -> PathBuf {
    let keys = dir.join("keys.toml");
    std::fs::write(&keys, format!("[keys]\n{SSID} = \"{KEY_HEX}\"\n")).unwrap();
    let key = dir.join("probe.key");
    std::fs::write(&key, format!("{KEY_HEX}\n")).unwrap();
    keys
}

fn start(cfg: ReflectorConfig) -> (SocketAddrV4, Arc<AtomicBool>, JoinHandle<Stats>) {
    let r = Reflector::bind(cfg).expect("bind");
    let addr = r.local_addr();
    let stop = Arc::new(AtomicBool::new(false));
    let s = Arc::clone(&stop);
    (addr, stop, std::thread::spawn(move || r.run(&s)))
}

fn reflector_cfg(keys: &Path) -> ReflectorConfig {
    ReflectorConfig {
        listen: "127.0.0.1:0".into(),
        allow: vec!["127.0.0.0/8".into()],
        // 127.0.0.2 talks authenticated; everything else in 127/8 does not.
        authenticated_sources: vec!["127.0.0.2/32".into()],
        keys_file: Some(keys.display().to_string()),
        ..ReflectorConfig::default()
    }
}

fn run_session(cfg_body: &str, run_for: Duration) -> Vec<Record> {
    let cfg: ProbeConfig = toml::from_str(&format!(
        "probe_id = \"t\"\nsite = \"LAB\"\n[output]\n[defaults]\ntimeout_ms = 500\n{cfg_body}"
    ))
    .unwrap();
    cfg.validate().unwrap();
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let handles = stamp_session::spawn(&cfg, &cfg.stamp[0], tx, Arc::clone(&stop)).unwrap();
    let deadline = Instant::now() + run_for;
    let mut out = Vec::new();
    while Instant::now() < deadline {
        if let Ok(Item::Record(r)) = rx.recv_timeout(Duration::from_millis(50)) {
            out.push(r);
        }
    }
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().unwrap();
    }
    out
}

fn totals(rs: &[Record]) -> (u32, u32) {
    (rs.iter().map(|r| r.sent).sum(), rs.iter().map(|r| r.received).sum())
}

#[test]
fn authenticated_and_unauthenticated_sessions_share_a_reflector() {
    let dir = tmpdir("mixed");
    let keys = write_keys(&dir);
    let (addr, stop, h) = start(reflector_cfg(&keys));
    let key_file = dir.join("probe.key").display().to_string();
    let auth = run_session(
        &format!(
            "[[stamp]]\nname = \"a\"\ntarget = \"{addr}\"\nsource = \"127.0.0.2:0\"\npps = 50\nsize = 300\n\
             [stamp.trace]\nenabled = false\n[stamp.auth]\nssid = {SSID}\nkey_file = \"{key_file}\"\n"
        ),
        Duration::from_millis(2600),
    );
    let plain = run_session(
        &format!("[[stamp]]\nname = \"u\"\ntarget = \"{addr}\"\nsource = \"127.0.0.1:0\"\npps = 50\n[stamp.trace]\nenabled = false\n"),
        Duration::from_millis(2600),
    );
    stop.store(true, Ordering::Relaxed);
    let stats = h.join().unwrap();
    let (sa, ra) = totals(&auth);
    let (su, ru) = totals(&plain);
    assert!(sa > 50 && ra == sa, "authenticated session: {ra}/{sa} received");
    assert!(su > 50 && ru == su, "unauthenticated session: {ru}/{su} received");
    assert_eq!((stats.auth_failed, stats.integrity_failed), (0, 0));
    assert!(auth.iter().all(|r| r.fwd_lost == Some(0) || r.sent == 0), "stateful split still works");
}

#[test]
fn a_wrong_key_gets_no_replies() {
    let dir = tmpdir("wrong");
    let keys = write_keys(&dir);
    std::fs::write(dir.join("probe.key"), "ff".repeat(32)).unwrap();
    let (addr, stop, h) = start(reflector_cfg(&keys));
    let key_file = dir.join("probe.key").display().to_string();
    let recs = run_session(
        &format!(
            "[[stamp]]\nname = \"a\"\ntarget = \"{addr}\"\nsource = \"127.0.0.2:0\"\npps = 50\n\
             [stamp.trace]\nenabled = false\n[stamp.auth]\nssid = {SSID}\nkey_file = \"{key_file}\"\n"
        ),
        Duration::from_millis(1800),
    );
    stop.store(true, Ordering::Relaxed);
    let stats = h.join().unwrap();
    assert_eq!(totals(&recs).1, 0, "nothing reflected");
    assert!(stats.auth_failed > 20, "{stats:?}");
}

fn exchange(from: &str, to: SocketAddrV4, pkt: &[u8]) -> Option<Vec<u8>> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    sock.bind(&SockAddr::from(from.parse::<SocketAddrV4>().unwrap())).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    sock.send_to(pkt, &SockAddr::from(to)).unwrap();
    let mut buf = [0_u8; 2048];
    sys::recv_meta(sock.as_raw_fd(), &mut buf).ok().map(|m| buf[..m.len].to_vec())
}

#[test]
fn tlvs_come_back_with_reflector_flags_and_integrity_is_enforced() {
    let dir = tmpdir("tlv");
    let keys = write_keys(&dir);
    let (addr, stop, h) = start(reflector_cfg(&keys));
    let key = Key::from_hex(KEY_HEX).unwrap();
    let sp = SenderPacket { seq: 1, timestamp: 2, error_estimate: 3, ssid: SSID };
    let unknown = Tlv::new(200, vec![1, 2, 3, 4]);

    // Authenticated, valid HMAC TLV: unknown TLV comes back with U, HMAC TLV recomputed, size kept.
    let pkt = sp.build(Mode::Authenticated, Some(&key), std::slice::from_ref(&unknown), 300).unwrap();
    let r = exchange("127.0.0.2:0", addr, &pkt).expect("reply");
    assert_eq!(r.len(), 300);
    let (rp, ext) = ReflectorPacket::parse(&r, Mode::Authenticated, Some(&key)).unwrap();
    assert_eq!((rp.sender_seq, rp.ssid), (1, SSID));
    assert_eq!([ext.tlvs[0].typ, ext.tlvs[1].typ, ext.tlvs[2].typ], [200, tlv_type::HMAC, tlv_type::EXTRA_PADDING]);
    assert_eq!(ext.tlvs[0].flags, flag::U, "not understood");
    assert_eq!(ext.tlvs[1].flags & flag::U, 0, "HMAC TLV processed");
    assert_eq!(check_ext_hmac(&ext, &rp.seq.to_be_bytes(), Some(&key), true), ExtIntegrity::Valid);

    // Tamper with the TLV after the base HMAC: base still valid, extensions fail -> I on every TLV.
    let mut bad = pkt.clone();
    bad[AUTH_BASE_LEN + 4] ^= 0xFF;
    let r = exchange("127.0.0.2:0", addr, &bad).expect("reply with I flags");
    let (_, ext) = ReflectorPacket::parse(&r, Mode::Authenticated, Some(&key)).unwrap();
    assert!(ext.tlvs.iter().all(|t| t.flags & flag::I != 0), "{:?}", ext.tlvs);

    // Tamper with the base: no reply at all.
    let mut forged = pkt.clone();
    forged[17] ^= 1;
    assert!(exchange("127.0.0.2:0", addr, &forged).is_none());

    // Unauthenticated packet from an authenticated source: refused.
    let plain = sp.build(Mode::Unauthenticated, None, &[], 112).unwrap();
    assert!(exchange("127.0.0.2:0", addr, &plain).is_none());

    // Legacy probe (zero padding instead of TLVs) from an unauthenticated source: same size back.
    let mut legacy = vec![0_u8; 200];
    legacy[..BASE_LEN].copy_from_slice(&sp.build(Mode::Unauthenticated, None, &[], BASE_LEN).unwrap());
    let r = exchange("127.0.0.1:0", addr, &legacy).expect("legacy reply");
    assert_eq!(r.len(), 200);
    assert_eq!(ReflectorPacket::decode(&r).unwrap().sender_seq, 1);
    assert_eq!(parse_tlvs(&r[BASE_LEN..]).tlvs.len(), 39, "type-0 TLVs returned with U");

    stop.store(true, Ordering::Relaxed);
    let stats = h.join().unwrap();
    assert_eq!((stats.auth_failed, stats.integrity_failed), (2, 1), "{stats:?}");
}

#[test]
fn keys_are_minted_added_and_reloaded() {
    let dir = tmpdir("mint");
    let keys = dir.join("keys.toml");
    add_key(&keys, 7, &dir.join("p7.key"), false).unwrap();
    add_key(&keys, 8, &dir.join("p8.key"), false).unwrap();
    assert!(add_key(&keys, 7, &dir.join("again.key"), false).unwrap_err().contains("already has a key"));
    assert!(add_key(&keys, 9, &dir.join("p7.key"), false).unwrap_err().contains("must not exist"));
    let map = parse_keys(&std::fs::read_to_string(&keys).unwrap()).unwrap();
    let p7 = Key::from_hex(&std::fs::read_to_string(dir.join("p7.key")).unwrap()).unwrap();
    assert_eq!(map.get(&7), Some(&p7));
    use std::os::unix::fs::PermissionsExt;
    for f in ["keys.toml", "p7.key"] {
        assert_eq!(std::fs::metadata(dir.join(f)).unwrap().permissions().mode() & 0o777, 0o600, "{f}");
    }
}

// -- RFC 10052 return trains -------------------------------------------------------------

fn rc_cfg(keys: &Path, enabled: bool) -> ReflectorConfig {
    let mut c = reflector_cfg(keys);
    c.reflected_control = ReflectedControlConfig {
        enabled,
        max_packets: 64,
        max_volume_bytes: 40_000,
        max_rate_bytes_per_s: 1_000,
        max_packet_len: 1472,
    };
    c
}

/// Sends `pkt` and collects every reply for `wait`.
fn exchange_all(from: &str, to: SocketAddrV4, pkt: &[u8], wait: Duration) -> Vec<Vec<u8>> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    sock.bind(&SockAddr::from(from.parse::<SocketAddrV4>().unwrap())).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    sock.send_to(pkt, &SockAddr::from(to)).unwrap();
    let mut out = Vec::new();
    let mut buf = [0_u8; 9216];
    let end = Instant::now() + wait;
    while Instant::now() < end {
        if let Ok(m) = sys::recv_meta(sock.as_raw_fd(), &mut buf) {
            out.push(buf[..m.len].to_vec());
        }
    }
    out
}

fn request(key: &Key, seq: u32, ctl: ReflectedControl, mode: Mode) -> Vec<u8> {
    let sp = SenderPacket { seq, timestamp: 9, error_estimate: 0, ssid: SSID };
    let tlv = ctl.tlv();
    let k = (mode == Mode::Authenticated).then_some(key);
    let len = min_len(mode, std::slice::from_ref(&tlv), k.is_some());
    sp.build(mode, k, &[tlv], len).unwrap()
}

fn ctl_flags(key: &Key, r: &[u8]) -> u8 {
    let (_, ext) = ReflectorPacket::parse(r, Mode::Authenticated, Some(key)).unwrap();
    ext.find(tlv_type::REFLECTED_CONTROL).unwrap().flags
}

#[test]
fn rfc_10052_trains_limits_and_refusals() {
    let dir = tmpdir("rc");
    let keys = write_keys(&dir);
    let key = Key::from_hex(KEY_HEX).unwrap();
    let (addr, stop, h) = start(rc_cfg(&keys, true));
    let ok = ReflectedControl { len: 300, count: 10, interval_ns: 0 };
    // One session (fixed source port): the replay check is per session.
    const SRC: &str = "127.0.0.2:47001";

    // A train: 10 packets of 300 octets, each authenticated, control processed (U, C clear).
    let train = exchange_all(SRC, addr, &request(&key, 1, ok, Mode::Authenticated), Duration::from_millis(400));
    assert_eq!(train.len(), 10);
    for r in &train {
        assert_eq!(r.len(), 300);
        let (p, ext) = ReflectorPacket::parse(r, Mode::Authenticated, Some(&key)).unwrap();
        assert_eq!(p.sender_seq, 1);
        assert_eq!(check_ext_hmac(&ext, &p.seq.to_be_bytes(), Some(&key), true), ExtIntegrity::Valid);
        assert_eq!(ctl_flags(&key, r) & (flag::U | flag::C), 0);
    }
    // A paced train keeps its spacing (1 ms apart) on the reflector's clock.
    let paced = ReflectedControl { len: 200, count: 5, interval_ns: 1_000_000 };
    let p5 = exchange_all(SRC, addr, &request(&key, 2, paced, Mode::Authenticated), Duration::from_millis(400));
    let t3: Vec<u64> =
        p5.iter().map(|r| ReflectorPacket::parse(r, Mode::Authenticated, Some(&key)).unwrap().0.timestamp).collect();
    assert_eq!(t3.len(), 5);
    let gaps_ms: Vec<f64> = t3.windows(2).map(|w| (w[1] - w[0]) as f64 / 4_294_967_296.0 * 1000.0).collect();
    assert!(gaps_ms.iter().all(|g| (0.9..1.5).contains(g)), "{gaps_ms:?}");

    // Replay (same sequence number): one packet, U set.
    let replay = exchange_all(SRC, addr, &request(&key, 2, ok, Mode::Authenticated), Duration::from_millis(200));
    assert_eq!(replay.len(), 1);
    assert_ne!(ctl_flags(&key, &replay[0]) & flag::U, 0);
    // Over max_packets: one packet, C set, at the reflected length.
    let many = ReflectedControl { count: 65, ..ok };
    let r = exchange_all(SRC, addr, &request(&key, 3, many, Mode::Authenticated), Duration::from_millis(200));
    assert_eq!((r.len(), r[0].len()), (1, 300));
    assert_ne!(ctl_flags(&key, &r[0]) & flag::C, 0);
    // Longer than the MTU: one packet of max_packet_len, C set.
    let jumbo = ReflectedControl { len: 4000, count: 2, interval_ns: 0 };
    let r = exchange_all(SRC, addr, &request(&key, 4, jumbo, Mode::Authenticated), Duration::from_millis(200));
    assert_eq!((r.len(), r[0].len()), (1, 1472));
    assert_ne!(ctl_flags(&key, &r[0]) & flag::C, 0);
    // Per-source budget (40 kB bucket, 1 kB/s): a 36 kB train fits once, not twice in a row.
    let big = ReflectedControl { len: 1200, count: 30, interval_ns: 0 };
    let r = exchange_all(SRC, addr, &request(&key, 5, big, Mode::Authenticated), Duration::from_millis(300));
    assert_eq!(r.len(), 30);
    let r = exchange_all(SRC, addr, &request(&key, 6, big, Mode::Authenticated), Duration::from_millis(200));
    assert_eq!(r.len(), 1, "budget spent");
    assert_ne!(ctl_flags(&key, &r[0]) & flag::C, 0);
    // Count 0: no reply at all.
    let none = ReflectedControl { count: 0, ..ok };
    let r = exchange_all(SRC, addr, &request(&key, 7, none, Mode::Authenticated), Duration::from_millis(200));
    assert!(r.is_empty());
    // From an unauthenticated source: one ordinary reply, control not processed (U).
    let r = exchange_all("127.0.0.1:0", addr, &request(&key, 8, ok, Mode::Unauthenticated), Duration::from_millis(200));
    assert_eq!(r.len(), 1);
    let (_, ext) = ReflectorPacket::parse(&r[0], Mode::Unauthenticated, None).unwrap();
    assert_ne!(ext.find(tlv_type::REFLECTED_CONTROL).unwrap().flags & flag::U, 0);

    stop.store(true, Ordering::Relaxed);
    let stats = h.join().unwrap();
    assert_eq!((stats.trains_sent, stats.trains_refused), (3, 3), "{stats:?}");
    assert_eq!(stats.trains_not_processed, 2);

    // A reflector with reflected_control off: U, never a train.
    let (addr, stop, h) = start(rc_cfg(&keys, false));
    let r = exchange_all(SRC, addr, &request(&key, 1, ok, Mode::Authenticated), Duration::from_millis(200));
    assert_eq!(r.len(), 1);
    assert_ne!(ctl_flags(&key, &r[0]) & flag::U, 0);
    stop.store(true, Ordering::Relaxed);
    h.join().unwrap();
}
