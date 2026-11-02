//! RFC 9946 (UDPSTP) speed tests on demand (P3.3, DESIGN D14).
//!
//! A speed test fills the path for its duration, so it is never part of
//! monitoring. The collector queues a job (after its own policy: who, when,
//! one test per site at a time); this probe fetches it and runs it only if it
//! fits the probe's own `[[speedtest]]` limits: target enabled, direction
//! allowed, rate and duration within the local caps, a non-priority DSCP. A
//! compromised or misconfigured collector cannot push a probe past them.
//!
//! The client is OB-UDPST's `udpst` (Broadband Forum TR-471, RFC 9946 since
//! 9.0.0), run without a shell and with a cleared environment:
//! `-4` (IPv4), `-X` (random payload: a compressing WAN optimiser cannot shrink it), `-o`
//! (one-way delay variation, the RFC 9946 default), `-f json -s` (summary
//! JSON), `-K <file> -y <id>` (RFC 9946 authentication; the key never appears
//! on the command line).

use crate::config::{expand_env, SpeedtestTarget};
use crate::output::Item;
use crate::{clock, sleep_until, Throttle};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

/// Jobs taken per poll; the rest wait for the next poll.
const MAX_JOBS_PER_POLL: usize = 4;
/// How long past the test duration `udpst` may run before it is killed.
const RUN_GRACE: Duration = Duration::from_secs(20);
/// Output kept from `udpst` (summary JSON is a few kB).
const MAX_OUTPUT: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Down,
    Up,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::Down => "down",
            Direction::Up => "up",
        }
    }
}

/// A job from the collector.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub job_id: String,
    pub target: String,
    pub direction: Direction,
    pub max_mbps: u32,
    pub duration_s: u32,
}

/// The probe's own guard: returns the target the job may run against, or why not.
pub fn check_job<'a>(job: &Job, targets: &'a [SpeedtestTarget]) -> Result<&'a SpeedtestTarget, String> {
    if job.job_id.is_empty()
        || job.job_id.len() > 64
        || !job.job_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err("bad job_id".into());
    }
    let t = targets.iter().find(|t| t.name == job.target).ok_or("unknown target")?;
    if !t.enabled {
        return Err("target not enabled on this probe".into());
    }
    if !t.directions.iter().any(|d| d == job.direction.as_str()) {
        return Err(format!("direction {} not allowed on this probe", job.direction.as_str()));
    }
    if job.max_mbps == 0 || job.max_mbps > t.max_mbps {
        return Err(format!("max_mbps {} outside this probe's cap of {}", job.max_mbps, t.max_mbps));
    }
    if job.duration_s == 0 || job.duration_s > t.max_duration_s {
        return Err(format!("duration_s {} outside this probe's cap of {}", job.duration_s, t.max_duration_s));
    }
    Ok(t)
}

/// `udpst` client arguments for a checked job.
pub fn udpst_args(job: &Job, t: &SpeedtestTarget) -> Result<Vec<String>, String> {
    let key_file = expand_env(&t.key_file)?;
    Ok(vec![
        match job.direction {
            Direction::Down => "-d",
            Direction::Up => "-u",
        }
        .into(),
        // The probe is IPv4-only (and its systemd unit allows no AF_INET6).
        "-4".into(),
        "-f".into(),
        "json".into(),
        "-s".into(),
        "-X".into(),
        "-o".into(),
        "-B".into(),
        job.max_mbps.to_string(),
        "-t".into(),
        job.duration_s.to_string(),
        "-m".into(),
        (u32::from(t.dscp) << 2).to_string(),
        "-K".into(),
        key_file,
        "-y".into(),
        t.key_id.to_string(),
        t.server.clone(),
    ])
}

/// What `udpst -f json -s` reported.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Parsed {
    pub error_status: i64,
    pub error_message: String,
    pub max_ip_capacity_mbps: Option<f64>,
    pub loss_ratio_at_max: Option<f64>,
    pub rtt_range_ms_at_max: Option<f64>,
    pub pdv_range_ms_at_max: Option<f64>,
    pub summary_capacity_mbps: Option<f64>,
    pub summary_loss_ratio: Option<f64>,
    pub delivered_pct: Option<f64>,
    pub ecn_bleaching: Option<bool>,
    pub udpst_version: Option<String>,
}

fn num(v: &serde_json::Value, path: &[&str]) -> Option<f64> {
    let mut cur = v;
    for p in path {
        cur = cur.get(p)?;
    }
    cur.as_f64().filter(|x| x.is_finite())
}

/// Parses OB-UDPST client JSON (TR-181 "IPLayerCapacity" names). Times in
/// the JSON are seconds; they come out in milliseconds.
pub fn parse_output(stdout: &str) -> Result<Parsed, String> {
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).map_err(|e| format!("udpst output is not JSON: {e}"))?;
    let error_status =
        v.get("ErrorStatus").and_then(serde_json::Value::as_i64).ok_or("udpst output has no ErrorStatus")?;
    let msg = |k: &str| v.get(k).and_then(serde_json::Value::as_str).unwrap_or("").trim().to_string();
    let error_message = [msg("ErrorMessage"), msg("ErrorMessage2")]
        .into_iter()
        .filter(|m| !m.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    let ms = |x: Option<f64>| x.map(|s| (s * 1000.0 * 1000.0).round() / 1000.0);
    Ok(Parsed {
        error_status,
        error_message: error_message.chars().take(300).collect(),
        max_ip_capacity_mbps: num(&v, &["Output", "AtMax", "MaxIPLayerCapacity"]),
        loss_ratio_at_max: num(&v, &["Output", "AtMax", "LossRatioAtMax"]),
        rtt_range_ms_at_max: ms(num(&v, &["Output", "AtMax", "RTTRangeAtMax"])),
        pdv_range_ms_at_max: ms(num(&v, &["Output", "AtMax", "PDVRangeAtMax"])),
        summary_capacity_mbps: num(&v, &["Output", "Summary", "IPLayerCapacitySummary"]),
        summary_loss_ratio: num(&v, &["Output", "Summary", "LossRatioSummary"]),
        delivered_pct: num(&v, &["Output", "Summary", "DeliveredPercent"]),
        ecn_bleaching: num(&v, &["Output", "ECNBleachingDetected"]).map(|x| x != 0.0),
        udpst_version: v
            .get("IPLayerCapSupported")
            .and_then(|c| c.get("SoftwareVersion"))
            .and_then(serde_json::Value::as_str)
            .map(|s| s.chars().take(32).collect()),
    })
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SpeedtestResult {
    pub v: u32,
    pub probe_id: String,
    pub site: String,
    pub kind: &'static str,
    pub target: String,
    pub server: String,
    pub job_id: String,
    pub direction: Direction,
    /// Test start, Unix ms.
    pub ts_ms: i64,
    pub duration_s: u32,
    pub max_mbps: u32,
    pub dscp: u8,
    /// completed, warning (udpst ErrorStatus 1-49), failed, refused (by this probe).
    pub status: &'static str,
    pub error_status: Option<i64>,
    pub error: Option<String>,
    pub max_ip_capacity_mbps: Option<f64>,
    pub loss_ratio_at_max: Option<f64>,
    pub rtt_range_ms_at_max: Option<f64>,
    pub pdv_range_ms_at_max: Option<f64>,
    pub summary_capacity_mbps: Option<f64>,
    pub summary_loss_ratio: Option<f64>,
    pub delivered_pct: Option<f64>,
    pub ecn_bleaching: Option<bool>,
    pub udpst_version: Option<String>,
}

pub struct Ctx<'a> {
    pub probe_id: &'a str,
    pub site: &'a str,
}

fn result(ctx: &Ctx<'_>, job: &Job, t: Option<&SpeedtestTarget>, ts_ms: i64) -> SpeedtestResult {
    SpeedtestResult {
        v: crate::record::RECORD_VERSION,
        probe_id: ctx.probe_id.to_string(),
        site: ctx.site.to_string(),
        kind: "speedtest",
        target: job.target.chars().take(64).collect(),
        server: t.map(|t| t.server.clone()).unwrap_or_default(),
        job_id: job.job_id.chars().take(64).collect(),
        direction: job.direction,
        ts_ms,
        duration_s: job.duration_s,
        max_mbps: job.max_mbps,
        dscp: t.map_or(0, |t| t.dscp),
        status: "failed",
        error_status: None,
        error: None,
        max_ip_capacity_mbps: None,
        loss_ratio_at_max: None,
        rtt_range_ms_at_max: None,
        pdv_range_ms_at_max: None,
        summary_capacity_mbps: None,
        summary_loss_ratio: None,
        delivered_pct: None,
        ecn_bleaching: None,
        udpst_version: None,
    }
}

/// A job this probe will not run.
pub fn refused(ctx: &Ctx<'_>, job: &Job, why: String) -> SpeedtestResult {
    SpeedtestResult { status: "refused", error: Some(why), ..result(ctx, job, None, clock::now_ns() / 1_000_000) }
}

/// Runs `udpst` for a checked job and reports what happened.
pub fn run(ctx: &Ctx<'_>, job: &Job, t: &SpeedtestTarget) -> SpeedtestResult {
    let ts_ms = clock::now_ns() / 1_000_000;
    let mut r = result(ctx, job, Some(t), ts_ms);
    let args = match udpst_args(job, t) {
        Ok(a) => a,
        Err(e) => {
            r.error = Some(e);
            return r;
        }
    };
    let out = run_bounded(&t.udpst, &args, Duration::from_secs(u64::from(job.duration_s)) + RUN_GRACE);
    let stdout = match out {
        Ok(s) => s,
        Err(e) => {
            r.error = Some(e);
            return r;
        }
    };
    match parse_output(&stdout) {
        Ok(p) => {
            r.status = match p.error_status {
                0 => "completed",
                1..=49 => "warning",
                _ => "failed",
            };
            r.error_status = Some(p.error_status);
            r.error = (!p.error_message.is_empty()).then_some(p.error_message);
            r.max_ip_capacity_mbps = p.max_ip_capacity_mbps;
            r.loss_ratio_at_max = p.loss_ratio_at_max;
            r.rtt_range_ms_at_max = p.rtt_range_ms_at_max;
            r.pdv_range_ms_at_max = p.pdv_range_ms_at_max;
            r.summary_capacity_mbps = p.summary_capacity_mbps;
            r.summary_loss_ratio = p.summary_loss_ratio;
            r.delivered_pct = p.delivered_pct;
            r.ecn_bleaching = p.ecn_bleaching;
            r.udpst_version = p.udpst_version;
        }
        Err(e) => r.error = Some(e),
    }
    r
}

/// Runs a program (no shell, empty environment, no stdin, no ambient
/// capabilities) and returns its stdout, killing it after `limit`.
fn run_bounded(program: &str, args: &[String], limit: Duration) -> Result<String, String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        // Its own process group, so a timeout kills anything it started too.
        .process_group(0);
    // The probe runs with CAP_NET_RAW as an ambient capability (systemd), and
    // ambient capabilities survive exec. udpst needs none: drop them.
    // SAFETY: prctl is async-signal-safe and touches only the forked child.
    unsafe {
        cmd.pre_exec(|| {
            if libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start {program}: {e}"))?;
    let drain = |mut s: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = s.by_ref().take(MAX_OUTPUT as u64).read_to_end(&mut buf);
            // Keep draining past the cap so the child never blocks on a full pipe.
            let _ = std::io::copy(&mut s, &mut std::io::sink());
            buf
        })
    };
    let out = drain(Box::new(child.stdout.take().ok_or("no stdout")?));
    let err = drain(Box::new(child.stderr.take().ok_or("no stderr")?));
    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if Instant::now() >= deadline => {
                if let Ok(pgid) = libc::pid_t::try_from(child.id()) {
                    // SAFETY: signals only the process group created above for this child.
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                    }
                }
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(format!("waiting for {program}: {e}")),
        }
    };
    let stdout = String::from_utf8_lossy(&out.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&err.join().unwrap_or_default()).chars().take(300).collect::<String>();
    match status {
        None => Err(format!("{program} did not finish within {} s; killed", limit.as_secs())),
        // udpst exits with its ErrorStatus; the JSON on stdout carries the details.
        Some(_) if !stdout.trim().is_empty() => Ok(stdout),
        Some(s) => Err(format!("{program} exited ({s}) with no JSON output: {}", stderr.trim())),
    }
}

/// What this probe tells the collector it can test (no keys, no paths).
#[derive(Debug, Serialize)]
struct Capability<'a> {
    name: &'a str,
    server: &'a str,
    directions: &'a [String],
    max_mbps: u32,
    max_duration_s: u32,
    dscp: u8,
}

#[derive(Debug, Serialize)]
struct Poll<'a> {
    probe_id: &'a str,
    /// The collector allows one speed test per site at a time.
    site: &'a str,
    targets: Vec<Capability<'a>>,
}

#[derive(Debug, Deserialize)]
struct PollResponse {
    #[serde(default)]
    jobs: Vec<serde_json::Value>,
}

/// Polls the collector for jobs and runs them one at a time.
#[allow(clippy::too_many_arguments)]
pub fn jobs_loop(
    agent: &ureq::Agent,
    url: &str,
    auth_header: &str,
    probe_id: &str,
    site: &str,
    targets: &[SpeedtestTarget],
    poll: Duration,
    out: &Sender<Item>,
    stop: &AtomicBool,
) {
    let ctx = Ctx { probe_id, site };
    let mut err_log = Throttle::new(Duration::from_secs(300));
    let body = serde_json::to_vec(&Poll {
        probe_id,
        site,
        targets: targets
            .iter()
            .filter(|t| t.enabled)
            .map(|t| Capability {
                name: &t.name,
                server: &t.server,
                directions: &t.directions,
                max_mbps: t.max_mbps,
                max_duration_s: t.max_duration_s,
                dscp: t.dscp,
            })
            .collect(),
    })
    .unwrap_or_default();
    log::info!(
        "speed tests: {} target(s) enabled; asking {url} for jobs every {} s",
        targets.iter().filter(|t| t.enabled).count(),
        poll.as_secs()
    );
    let mut next = Instant::now() + Duration::from_secs(2);
    loop {
        if !sleep_until(next, stop) {
            return;
        }
        next = Instant::now() + poll;
        let resp = agent
            .post(url)
            .set("authorization", auth_header)
            .set("content-type", "application/json")
            .send_bytes(&body)
            .map_err(|e| e.to_string())
            .and_then(|r| r.into_string().map_err(|e| e.to_string()))
            .and_then(|b| serde_json::from_str::<PollResponse>(&b).map_err(|e| e.to_string()));
        let jobs = match resp {
            Ok(r) => r.jobs,
            Err(e) => {
                if let Some(n) = err_log.ready() {
                    log::warn!("speed tests: polling {url} failed: {e} ({n} similar suppressed)");
                }
                continue;
            }
        };
        for raw in jobs.into_iter().take(MAX_JOBS_PER_POLL) {
            let job: Job = match serde_json::from_value(raw) {
                Ok(j) => j,
                Err(e) => {
                    log::warn!("speed tests: ignoring a malformed job: {e}");
                    continue;
                }
            };
            let result = match check_job(&job, targets) {
                Ok(t) => {
                    log::warn!(
                        "speed test {} STARTING: {} {} to {} at up to {} Mbit/s for {} s",
                        job.job_id,
                        job.target,
                        job.direction.as_str(),
                        t.server,
                        job.max_mbps,
                        job.duration_s
                    );
                    let r = run(&ctx, &job, t);
                    log::info!(
                        "speed test {} {}: max {} Mbit/s{}",
                        job.job_id,
                        r.status,
                        r.max_ip_capacity_mbps.map_or("-".into(), |m| format!("{m:.1}")),
                        r.error.as_deref().map(|e| format!(" ({e})")).unwrap_or_default()
                    );
                    r
                }
                Err(why) => {
                    log::warn!("speed test {} refused by this probe: {why}", job.job_id);
                    refused(&ctx, &job, why)
                }
            };
            if out.send(Item::Speedtest(result)).is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> SpeedtestTarget {
        SpeedtestTarget {
            name: "dc1-st".into(),
            enabled: true,
            server: "192.0.2.10:24601".into(),
            udpst: "/usr/local/bin/udpst".into(),
            max_mbps: 500,
            max_duration_s: 10,
            dscp: 10,
            directions: vec!["down".into()],
            key_file: "/etc/buffmon/udpst.keys".into(),
            key_id: 3,
        }
    }

    fn job() -> Job {
        Job { job_id: "j-1".into(), target: "dc1-st".into(), direction: Direction::Down, max_mbps: 200, duration_s: 10 }
    }

    #[test]
    fn local_limits_hold_whatever_the_collector_asks() {
        let ts = [target()];
        assert!(check_job(&job(), &ts).is_ok());
        let cases: [(Job, &str); 6] = [
            (Job { max_mbps: 501, ..job() }, "cap"),
            (Job { duration_s: 11, ..job() }, "cap"),
            (Job { direction: Direction::Up, ..job() }, "direction"),
            (Job { target: "other".into(), ..job() }, "unknown target"),
            (Job { job_id: "j 1; rm".into(), ..job() }, "job_id"),
            (Job { max_mbps: 0, ..job() }, "cap"),
        ];
        for (j, why) in cases {
            assert!(check_job(&j, &ts).unwrap_err().contains(why), "{j:?}");
        }
        let off = [SpeedtestTarget { enabled: false, ..target() }];
        assert!(check_job(&job(), &off).unwrap_err().contains("not enabled"));
    }

    #[test]
    fn udpst_arguments_carry_the_guards_and_no_key() {
        let a = udpst_args(&job(), &target()).unwrap();
        assert_eq!(
            a,
            [
                "-d",
                "-4",
                "-f",
                "json",
                "-s",
                "-X",
                "-o",
                "-B",
                "200",
                "-t",
                "10",
                "-m",
                "40",
                "-K",
                "/etc/buffmon/udpst.keys",
                "-y",
                "3",
                "192.0.2.10:24601"
            ]
        );
    }

    const OK: &str = r#"{"IPLayerCapSupported":{"SoftwareVersion":"9.1.0"},"Output":{"Summary":
        {"DeliveredPercent":99.9,"LossRatioSummary":0.001,"IPLayerCapacitySummary":180.5},
        "AtMax":{"MaxIPLayerCapacity":197.8,"LossRatioAtMax":0.0002,"RTTRangeAtMax":0.0042,"PDVRangeAtMax":0.0031},
        "ECNBleachingDetected":0},"ErrorStatus":0,"ErrorMessage":"","ErrorMessage2":""}"#;

    #[test]
    fn json_output_is_parsed_into_mbps_and_ms() {
        let p = parse_output(OK).unwrap();
        assert_eq!(p.max_ip_capacity_mbps, Some(197.8));
        assert_eq!((p.rtt_range_ms_at_max, p.pdv_range_ms_at_max), (Some(4.2), Some(3.1)));
        assert_eq!((p.error_status, p.ecn_bleaching, p.udpst_version.as_deref()), (0, Some(false), Some("9.1.0")));
        let failed = parse_output(
            r#"{"ErrorStatus":52,"ErrorMessage":"ERROR: Server bandwidth unavailable","ErrorMessage2":""}"#,
        )
        .unwrap();
        assert_eq!((failed.error_status, failed.max_ip_capacity_mbps), (52, None));
        assert!(failed.error_message.contains("bandwidth"));
        assert!(parse_output("not json").is_err());
        assert!(parse_output("{}").unwrap_err().contains("ErrorStatus"));
    }

    fn fake_udpst(dir: &std::path::Path, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("udpst");
        std::fs::write(&script, format!("#!/bin/sh\necho \"$@\" > {}/args\n{body}\n", dir.display())).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script.display().to_string()
    }

    #[test]
    fn runs_udpst_without_a_shell_and_reports() {
        let dir = std::env::temp_dir().join(format!("bm-udpst-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("out.json"), OK).unwrap();
        let t = SpeedtestTarget { udpst: fake_udpst(&dir, &format!("cat {}/out.json", dir.display())), ..target() };
        let ctx = Ctx { probe_id: "p1", site: "S" };
        let r = run(&ctx, &job(), &t);
        assert_eq!((r.status, r.max_ip_capacity_mbps, r.error_status), ("completed", Some(197.8), Some(0)));
        let args = std::fs::read_to_string(dir.join("args")).unwrap();
        assert!(args.starts_with("-d -4 -f json -s -X -o -B 200 -t 10 -m 40 -K "), "{args}");

        let t = SpeedtestTarget { udpst: fake_udpst(&dir, "echo boom >&2; exit 3"), ..target() };
        let r = run(&ctx, &job(), &t);
        assert_eq!(r.status, "failed");
        assert!(r.error.unwrap().contains("boom"));

        // A hung client (and anything it forked) is killed at the limit.
        let t = SpeedtestTarget { udpst: fake_udpst(&dir, "sleep 30"), ..target() };
        let started = Instant::now();
        let r = run_bounded(&t.udpst, &[], Duration::from_millis(500));
        assert!(r.unwrap_err().contains("killed") && started.elapsed() < Duration::from_secs(5));
        let r = run(&ctx, &job(), &SpeedtestTarget { udpst: "/nonexistent/udpst".into(), ..target() });
        assert!(r.error.unwrap().contains("cannot start"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
