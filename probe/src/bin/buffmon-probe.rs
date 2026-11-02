//! buffmon-probe: runs every configured STAMP / ICMP / TCP session and ships
//! 1-second records to the ingest service.
//!
//!   buffmon-probe --config /etc/buffmon/probe.toml
//!   buffmon-probe --config probe.toml --print       # also write records to stdout
//!   buffmon-probe --config probe.toml --check       # validate config and exit

use buffmon_probe::config::{resolve_token, ProbeConfig};
use buffmon_probe::{icmp, output, speedtest, stamp_session, tcp};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() {
    // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
}

fn usage() -> ! {
    eprintln!(
        "buffmon-probe {}\n\n  -c, --config <path>   probe config (default /etc/buffmon/probe.toml)\n      --print           also write each record to stdout as JSON\n      --check           validate the config and exit\n  -V, --version",
        buffmon_probe::VERSION
    );
    std::process::exit(2);
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut config = PathBuf::from("/etc/buffmon/probe.toml");
    let mut print = false;
    let mut check = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--config" => config = args.next().map(PathBuf::from).unwrap_or_else(|| usage()),
            "--print" => print = true,
            "--check" => check = true,
            "-V" | "--version" => {
                println!("buffmon-probe {}", buffmon_probe::VERSION);
                return ExitCode::SUCCESS;
            }
            _ => usage(),
        }
    }

    let cfg = match ProbeConfig::load(&config) {
        Ok(c) => c,
        Err(e) => {
            log::error!("{e}");
            return ExitCode::from(1);
        }
    };
    let mut token_for_jobs: Option<String> = None;
    let uploader = match &cfg.output.url {
        Some(url) => {
            let token = match resolve_token(&cfg.output) {
                Ok(t) => t,
                Err(e) => {
                    log::error!("{e}");
                    return ExitCode::from(1);
                }
            };
            token_for_jobs = Some(token.clone());
            match output::Uploader::new(&cfg.output, url, &token, &cfg.probe_id) {
                Ok(u) => Some(u),
                Err(e) => {
                    log::error!("{e}");
                    return ExitCode::from(1);
                }
            }
        }
        None if print => None,
        None => {
            log::error!("output.url is not set; use --print to run without an ingest service");
            return ExitCode::from(1);
        }
    };
    if check {
        println!(
            "config OK: probe {} at {}, {} stamp / {} icmp / {} tcp session(s), {} speed-test target(s) enabled",
            cfg.probe_id,
            cfg.site,
            cfg.stamp.len(),
            cfg.icmp.len(),
            cfg.tcp.len(),
            cfg.speedtest.iter().filter(|t| t.enabled).count()
        );
        return ExitCode::SUCCESS;
    }

    install_signal_handlers();
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    let mut handles = Vec::new();
    let mut failed = false;
    for t in &cfg.stamp {
        match stamp_session::spawn(&cfg, t, tx.clone(), Arc::clone(&stop)) {
            Ok(h) => handles.extend(h),
            Err(e) => {
                log::error!("stamp {}: {e}", t.name);
                failed = true;
            }
        }
    }
    for t in &cfg.icmp {
        match icmp::spawn(&cfg, t, tx.clone(), Arc::clone(&stop)) {
            Ok(h) => handles.extend(h),
            Err(e) => {
                log::error!("icmp {}: {e}", t.name);
                failed = true;
            }
        }
    }
    for t in &cfg.tcp {
        match tcp::spawn(&cfg, t, tx.clone(), Arc::clone(&stop)) {
            Ok(h) => handles.extend(h),
            Err(e) => {
                log::error!("tcp {}: {e}", t.name);
                failed = true;
            }
        }
    }
    // RFC 9946 speed tests: only with enabled targets and an ingest service to ask.
    if cfg.speedtest.iter().any(|t| t.enabled) {
        match (cfg.jobs.resolved_url(cfg.output.url.as_deref()), &token_for_jobs, output::http_agent(&cfg.output)) {
            (Some(url), Some(token), Ok(agent)) => {
                let (out, stop) = (tx.clone(), Arc::clone(&stop));
                let (probe_id, site, targets) = (cfg.probe_id.clone(), cfg.site.clone(), cfg.speedtest.clone());
                let poll = std::time::Duration::from_secs(cfg.jobs.poll_s);
                let auth = format!("Bearer {token}");
                match std::thread::Builder::new().name("speedtest-jobs".into()).spawn(move || {
                    speedtest::jobs_loop(&agent, &url, &auth, &probe_id, &site, &targets, poll, &out, &stop)
                }) {
                    Ok(h) => handles.push(h),
                    Err(e) => {
                        log::error!("speed tests: {e}");
                        failed = true;
                    }
                }
            }
            (_, _, Err(e)) => {
                log::error!("speed tests: {e}");
                failed = true;
            }
            _ => {
                log::error!("speed tests need output.url and a token");
                failed = true;
            }
        }
    }
    drop(tx);
    if failed {
        // Refuse to run half-configured: a silently missing session looks like
        // a healthy one on the dashboard.
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            let _ = h.join();
        }
        return ExitCode::from(1);
    }

    // Propagate the signal flag to the session threads.
    {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !STOP.load(Ordering::Relaxed) {
                std::thread::sleep(buffmon_probe::POLL_INTERVAL);
            }
            log::info!("stopping");
            stop.store(true, Ordering::Relaxed);
        });
    }

    let stats = output::run(&cfg.output, uploader, rx, &stop, print);
    for h in handles {
        let _ = h.join();
    }
    log::info!(
        "stopped: {} delivered, {} dropped (queue full), {} rejected",
        stats.delivered,
        stats.dropped_overflow,
        stats.dropped_rejected
    );
    ExitCode::SUCCESS
}
