//! Directional loss attribution through real sockets.
//!
//! A relay sits between the STAMP sender and the reflector and drops exactly
//! every Nth packet in one direction. Because the drops are deterministic, the
//! forward/return split must come out exact, not approximately right.

use buffmon_probe::config::ProbeConfig;
use buffmon_probe::output::Item;
use buffmon_probe::record::Record;
use buffmon_probe::reflector::{Reflector, ReflectorConfig};
use buffmon_probe::stamp_session;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum Drop {
    Forward(u64),
    Return(u64),
}

/// UDP relay: client → relay → reflector and back, dropping every Nth packet
/// in one direction. Returns the relay's address.
fn start_relay(reflector: SocketAddr, drop: Drop, stop: Arc<AtomicBool>) -> (SocketAddr, JoinHandle<()>) {
    let front = UdpSocket::bind("127.0.0.1:0").unwrap();
    let back = UdpSocket::bind("127.0.0.1:0").unwrap();
    back.connect(reflector).unwrap();
    front.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    back.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    let addr = front.local_addr().unwrap();
    let h = std::thread::spawn(move || {
        let mut client: Option<SocketAddr> = None;
        let (mut fwd_n, mut ret_n) = (0_u64, 0_u64);
        let mut buf = [0_u8; 2048];
        while !stop.load(Ordering::Relaxed) {
            if let Ok((n, from)) = front.recv_from(&mut buf) {
                client = Some(from);
                fwd_n += 1;
                if !matches!(drop, Drop::Forward(k) if fwd_n % k == 0) {
                    let _ = back.send(&buf[..n]);
                }
            }
            if let (Ok(n), Some(c)) = (back.recv(&mut buf), client) {
                ret_n += 1;
                if !matches!(drop, Drop::Return(k) if ret_n % k == 0) {
                    let _ = front.send_to(&buf[..n], c);
                }
            }
        }
    });
    (addr, h)
}

fn run(drop: Drop) -> Vec<Record> {
    let stop = Arc::new(AtomicBool::new(false));
    let reflector = Reflector::bind(ReflectorConfig {
        listen: "127.0.0.1:0".into(),
        allow: vec!["127.0.0.0/8".into()],
        ..ReflectorConfig::default()
    })
    .unwrap();
    let raddr = SocketAddr::V4(reflector.local_addr());
    let rstop = Arc::clone(&stop);
    let rh = std::thread::spawn(move || {
        reflector.run(&rstop);
    });
    let (relay, relay_h) = start_relay(raddr, drop, Arc::clone(&stop));

    let cfg: ProbeConfig = toml::from_str(&format!(
        "probe_id = \"t\"\nsite = \"LAB\"\n[output]\n[defaults]\ntimeout_ms = 500\n\
         [[stamp]]\nname = \"impaired\"\ntarget = \"{relay}\"\npps = 50\n"
    ))
    .unwrap();
    cfg.validate().unwrap();
    let (tx, rx) = mpsc::channel();
    let sstop = Arc::new(AtomicBool::new(false));
    let handles = stamp_session::spawn(&cfg, &cfg.stamp[0], tx, Arc::clone(&sstop)).unwrap();

    let deadline = Instant::now() + Duration::from_millis(4_500);
    let mut records = Vec::new();
    while Instant::now() < deadline {
        if let Ok(Item::Record(r)) = rx.recv_timeout(Duration::from_millis(50)) {
            records.push(r);
        }
    }
    sstop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    relay_h.join().unwrap();
    rh.join().unwrap();
    records
}

fn totals(records: &[Record]) -> (u32, u32, u32, u32) {
    let sent = records.iter().map(|r| r.sent).sum();
    let lost = records.iter().map(|r| r.lost).sum();
    let fwd = records.iter().map(|r| r.fwd_lost.expect("split known")).sum();
    let back = records.iter().map(|r| r.back_lost.expect("split known")).sum();
    (sent, lost, fwd, back)
}

#[test]
fn forward_loss_is_attributed_to_the_forward_direction() {
    let records = run(Drop::Forward(10));
    let (sent, lost, fwd, back) = totals(&records);
    assert!(sent >= 150, "sent {sent}");
    // Every 10th packet dropped: 10% ± one packet at the window edges.
    let expected = f64::from(sent) / 10.0;
    assert!((f64::from(lost) - expected).abs() <= 1.0, "lost {lost} of {sent}");
    assert_eq!((fwd, back), (lost, 0), "all loss is forward");
}

#[test]
fn return_loss_is_attributed_to_the_return_direction() {
    let records = run(Drop::Return(20));
    let (sent, lost, fwd, back) = totals(&records);
    assert!(sent >= 150, "sent {sent}");
    let expected = f64::from(sent) / 20.0;
    assert!((f64::from(lost) - expected).abs() <= 1.0, "lost {lost} of {sent}");
    assert_eq!((fwd, back), (0, lost), "all loss is on the return path");
}
