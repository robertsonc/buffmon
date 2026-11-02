//! buffmon-reflector: stateful STAMP Session-Reflector.
//!
//!   buffmon-reflector --config /etc/buffmon/reflector.toml
//!   buffmon-reflector --listen 0.0.0.0:862 --allow 10.0.0.0/8 --allow 172.16.0.0/12
//!   buffmon-reflector --new-key 4101 --keys-file /etc/buffmon/stamp-keys.toml --key-out sjc-br01-p1.key
//!       (a random key for SSID 4101: added to the reflector's keys file, and
//!       written to a new 0600 file to install on the probe)

use buffmon_probe::reflector::{add_key, Reflector, ReflectorConfig};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

fn usage() -> ! {
    eprintln!(
        "buffmon-reflector {}\n\n  -c, --config <path>    TOML config\n      --listen <ip:port> (default 0.0.0.0:862)\n      --allow <cidr>     allowed source prefix (repeatable)\n      --allow-any        accept any source (lab only)\n      --new-key <ssid> --keys-file <path> --key-out <path> [--replace]\n                         mint an HMAC key for an authenticated session and exit\n  -V, --version",
        buffmon_probe::VERSION
    );
    std::process::exit(2);
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut config: Option<PathBuf> = None;
    let mut listen: Option<String> = None;
    let mut allow: Vec<String> = Vec::new();
    let mut allow_any = false;
    let mut new_key: Option<u16> = None;
    let mut keys_file: Option<PathBuf> = None;
    let mut key_out: Option<PathBuf> = None;
    let mut replace = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--config" => config = Some(args.next().map(PathBuf::from).unwrap_or_else(|| usage())),
            "--listen" => listen = Some(args.next().unwrap_or_else(|| usage())),
            "--allow" => allow.push(args.next().unwrap_or_else(|| usage())),
            "--allow-any" => allow_any = true,
            "--new-key" => new_key = Some(args.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())),
            "--keys-file" => keys_file = Some(args.next().map(PathBuf::from).unwrap_or_else(|| usage())),
            "--key-out" => key_out = Some(args.next().map(PathBuf::from).unwrap_or_else(|| usage())),
            "--replace" => replace = true,
            "-V" | "--version" => {
                println!("buffmon-reflector {}", buffmon_probe::VERSION);
                return ExitCode::SUCCESS;
            }
            _ => usage(),
        }
    }

    if let Some(ssid) = new_key {
        let (Some(keys), Some(out)) = (keys_file, key_out) else { usage() };
        return match add_key(&keys, ssid, &out, replace) {
            Ok(()) => {
                println!(
                    "SSID {ssid}: key added to {} and written to {} (0600).\n\
                     Install that file on the probe and set [stamp.auth] ssid = {ssid}, key_file = <its path>.\n\
                     The running reflector picks the new key up within a few seconds.",
                    keys.display(),
                    out.display()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                log::error!("{e}");
                ExitCode::from(1)
            }
        };
    }

    let mut cfg = match &config {
        Some(path) => {
            let parsed =
                std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display())).and_then(
                    |raw| toml::from_str::<ReflectorConfig>(&raw).map_err(|e| format!("{}: {e}", path.display())),
                );
            match parsed {
                Ok(c) => c,
                Err(e) => {
                    log::error!("{e}");
                    return ExitCode::from(1);
                }
            }
        }
        None => ReflectorConfig::default(),
    };
    if let Some(l) = listen {
        cfg.listen = l;
    }
    cfg.allow.extend(allow);
    cfg.allow_any |= allow_any;

    let reflector = match Reflector::bind(cfg) {
        Ok(r) => r,
        Err(e) => {
            log::error!("{e}");
            return ExitCode::from(1);
        }
    };
    // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
    let stats = reflector.run(&STOP);
    log::info!("stopped: {stats:?}");
    ExitCode::SUCCESS
}
