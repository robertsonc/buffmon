//! Lab tool: a UDP relay that drops a percentage of packets per direction, for
//! demonstrating loss attribution when `tc netem` is not available.
//!
//!   cargo run --example impair -- --listen 0.0.0.0:8621 --to 10.10.0.20:862 \
//!       --forward-loss 2 --return-loss 0
//!
//! Point a probe session at the relay instead of the reflector. Lab use only:
//! it relays for one client at a time (the most recent sender).

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

/// xorshift64: enough randomness for drop decisions.
struct Rng(u64);
impl Rng {
    fn chance(&mut self, pct: f64) -> bool {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % 1_000_000) as f64 / 10_000.0 < pct
    }
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let usage =
        "usage: impair --listen <ip:port> --to <reflector ip:port> [--forward-loss <pct>] [--return-loss <pct>]";
    let listen: SocketAddr = arg(&args, "--listen").and_then(|s| s.parse().ok()).expect(usage);
    let to: SocketAddr = arg(&args, "--to").and_then(|s| s.parse().ok()).expect(usage);
    let fwd_pct: f64 = arg(&args, "--forward-loss").and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let ret_pct: f64 = arg(&args, "--return-loss").and_then(|s| s.parse().ok()).unwrap_or(0.0);

    let front = UdpSocket::bind(listen)?;
    let back = UdpSocket::bind("0.0.0.0:0")?;
    back.connect(to)?;
    front.set_read_timeout(Some(Duration::from_millis(5)))?;
    back.set_read_timeout(Some(Duration::from_millis(5)))?;
    eprintln!("impair: {listen} -> {to}, forward loss {fwd_pct}%, return loss {ret_pct}%");

    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0x9E37_79B9_7F4A_7C15, |d| d.as_nanos() as u64 | 1);
    let mut rng = Rng(seed);
    let mut client: Option<SocketAddr> = None;
    let (mut fwd, mut fwd_drop, mut ret, mut ret_drop) = (0_u64, 0_u64, 0_u64, 0_u64);
    let mut buf = [0_u8; 2048];
    let mut last_report = std::time::Instant::now();
    loop {
        if let Ok((n, from)) = front.recv_from(&mut buf) {
            client = Some(from);
            fwd += 1;
            if rng.chance(fwd_pct) {
                fwd_drop += 1;
            } else {
                let _ = back.send(&buf[..n]);
            }
        }
        if let (Ok(n), Some(c)) = (back.recv(&mut buf), client) {
            ret += 1;
            if rng.chance(ret_pct) {
                ret_drop += 1;
            } else {
                let _ = front.send_to(&buf[..n], c);
            }
        }
        if last_report.elapsed() >= Duration::from_secs(30) {
            last_report = std::time::Instant::now();
            eprintln!("impair: forward {fwd_drop}/{fwd} dropped, return {ret_drop}/{ret} dropped");
        }
    }
}
