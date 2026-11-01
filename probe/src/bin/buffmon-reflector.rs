//! buffmon-reflector: stateful STAMP Session-Reflector.
//!
//!   buffmon-reflector --config /etc/buffmon/reflector.toml
//!   buffmon-reflector --listen 0.0.0.0:862 --allow 10.0.0.0/8 --allow 172.16.0.0/12

use buffmon_probe::reflector::{Reflector, ReflectorConfig};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

fn usage() -> ! {
    eprintln!(
        "buffmon-reflector {}\n\n  -c, --config <path>    TOML config\n      --listen <ip:port> (default 0.0.0.0:862)\n      --allow <cidr>     allowed source prefix (repeatable)\n      --allow-any        accept any source (lab only)\n  -V, --version",
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
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--config" => config = Some(args.next().map(PathBuf::from).unwrap_or_else(|| usage())),
            "--listen" => listen = Some(args.next().unwrap_or_else(|| usage())),
            "--allow" => allow.push(args.next().unwrap_or_else(|| usage())),
            "--allow-any" => allow_any = true,
            "-V" | "--version" => {
                println!("buffmon-reflector {}", buffmon_probe::VERSION);
                return ExitCode::SUCCESS;
            }
            _ => usage(),
        }
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
