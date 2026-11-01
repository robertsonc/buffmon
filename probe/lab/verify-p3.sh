#!/usr/bin/env bash
# Phase 3 acceptance run in the namespace lab (lab/netns.sh):
#   1. path tracing: same-length reroute (r2a -> r2b) is flagged by the next
#      scheduled trace; a longer reroute (-> r2c1/r2c2) is flagged at once via
#      the STAMP TTL tripwire;
#   2. capacity: forward estimate vs tbf rate on r3 -> reflector, several rates,
#      plus a shaper with a burst allowance larger than half a train, and a
#      narrower return path.
# Needs root and release binaries: cargo build --release
#   lab/verify-p3.sh [outdir]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
bin=$here/../target/release
out=${1:-$(mktemp -d)}
lab=$here/netns.sh
mkdir -p "$out"

"$lab" up >/dev/null
trap '"$lab" down; kill $(jobs -p) 2>/dev/null || true' EXIT

cat >"$out/probe.toml" <<TOML
probe_id = "lab-p1"
site = "LAB"
[output]
[defaults]
timeout_ms = 1000
[[stamp]]
name = "dc-voice"
target = "10.90.9.2"
source = "10.90.1.2:40001"
pps = 20
dscp = 46
app_class = "voice"
[stamp.trace]
interval_s = 30
min_gap_s = 5
start_delay_s = 2
[stamp.capacity]
enabled = true
interval_s = 60
start_delay_s = 12
packets = 64
size = 1200
trains = 5
train_gap_ms = 300
dscp = 0
TOML

ip netns exec bm-refl "$bin/buffmon-reflector" --listen 0.0.0.0:862 --allow 10.90.0.0/16 2>"$out/reflector.log" &
sleep 0.5
ip netns exec bm-probe "$bin/buffmon-probe" --config "$out/probe.toml" --print >"$out/items.jsonl" 2>"$out/probe.log" &

step() { echo "$(date -u +%H:%M:%S) $*" | tee -a "$out/steps.log"; }
step "path a, unshaped";            sleep 8
step "shape fwd 20mbit burst 8kb";  "$lab" shape 20mbit 8kb >/dev/null;  sleep 2
step "path b (same length)";        "$lab" path b >/dev/null;            sleep 38
step "path c (one hop longer)";     "$lab" path c >/dev/null;            sleep 12
step "shape fwd 5mbit burst 4kb";   "$lab" shape 5mbit 4kb >/dev/null;   sleep 50
step "shape fwd 50mbit burst 16kb"; "$lab" shape 50mbit 16kb >/dev/null; sleep 60
step "shape fwd 10mbit burst 48kb (burst > half a train)"; "$lab" shape 10mbit 48kb >/dev/null; sleep 60
step "fwd 50mbit, return 8mbit";    "$lab" shape 50mbit 16kb >/dev/null; "$lab" shape 8mbit 8kb back >/dev/null; sleep 62
step "done"
kill %2 2>/dev/null; sleep 1
echo "results in $out"
