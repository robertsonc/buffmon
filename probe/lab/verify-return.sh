#!/usr/bin/env bash
# P3.2 acceptance in the namespace lab (lab/netns.sh): RFC 10052 return trains
# over authenticated STAMP, against tbf shaping in each direction.
#   A. forward 10 Mbit/s, return 30 Mbit/s  (return wider: the old method only
#      gets a floor of ~10; RFC 10052 should measure ~30)
#   B. forward 50 Mbit/s, return 8 Mbit/s   (return narrower)
#   C. forward unshaped, return 100 Mbit/s
# Needs root and release binaries (cargo build --release).
#   lab/verify-return.sh [outdir]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
bin=$here/../target/release
out=${1:-$(mktemp -d)}
lab=$here/netns.sh
mkdir -p "$out"
rm -f "$out/keys.toml" "$out/probe.key"

"$lab" up >/dev/null
trap '"$lab" down; kill $(jobs -p) 2>/dev/null || true' EXIT

"$bin/buffmon-reflector" --new-key 4101 --keys-file "$out/keys.toml" --key-out "$out/probe.key" >/dev/null
cat >"$out/reflector.toml" <<TOML
listen = "0.0.0.0:862"
allow = ["10.90.0.0/16"]
authenticated_sources = ["10.90.1.0/24"]
keys_file = "$out/keys.toml"
[reflected_control]
enabled = true
max_packets = 128
max_volume_bytes = 400000
max_rate_bytes_per_s = 1000000
TOML
cat >"$out/probe.toml" <<TOML
probe_id = "lab-p1"
site = "LAB"
[output]
[defaults]
timeout_ms = 1000
[[stamp]]
name = "dc-bulk"
target = "10.90.9.2"
source = "10.90.1.2:40001"
pps = 10
dscp = 0
app_class = "bulk"
[stamp.trace]
enabled = false
[stamp.auth]
ssid = 4101
key_file = "$out/probe.key"
[stamp.capacity]
enabled = true
interval_s = 60
start_delay_s = 4
packets = 64
size = 1200
trains = 5
train_gap_ms = 300
return_trains = true
TOML

ip netns exec bm-refl "$bin/buffmon-reflector" --config "$out/reflector.toml" 2>"$out/reflector.log" &
sleep 0.5
ip netns exec bm-probe "$bin/buffmon-probe" --config "$out/probe.toml" --print >"$out/items.jsonl" 2>"$out/probe.log" &

step() { echo "$(date -u +%H:%M:%S) $*" | tee -a "$out/steps.log"; }
step "A: fwd 10mbit, return 30mbit"; "$lab" shape 10mbit 8kb >/dev/null; "$lab" shape 30mbit 16kb back >/dev/null; sleep 60
step "B: fwd 50mbit, return 8mbit";  "$lab" shape 50mbit 16kb >/dev/null; "$lab" shape 8mbit 8kb back >/dev/null;   sleep 60
step "C: fwd unshaped, return 100mbit"; "$lab" unshape >/dev/null; "$lab" shape 100mbit 32kb back >/dev/null;       sleep 62
step "done"
kill %2 2>/dev/null; sleep 1
echo "results in $out"
