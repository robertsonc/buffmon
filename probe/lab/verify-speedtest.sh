#!/usr/bin/env bash
# P3.3 acceptance in the namespace lab (lab/netns.sh): RFC 9946 speed tests
# with OB-UDPST against tbf-shaped links. Part 1 runs the udpst client
# directly; part 2 runs the same test through buffmon (probe job poll,
# collector policy and API, real udpst).
# Needs root, release binaries (cargo build --release), the services venv
# (buffmon-ingest), and an OB-UDPST build (deploy/udpst/README.md).
#   lab/verify-speedtest.sh /path/to/udpst /path/to/venv [outdir]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
bin=$here/../target/release
udpst=${1:?path to udpst}
venv=${2:?path to the services virtualenv}
out=${3:-$(mktemp -d)}
lab=$here/netns.sh
mkdir -p "$out"

"$lab" up >/dev/null
trap '"$lab" down; kill $(jobs -p) 2>/dev/null || true' EXIT

umask 077
printf '7, %s\n' "$(openssl rand -hex 32)" >"$out/udpst.keys"
umask 022
ip netns exec bm-refl "$udpst" -4 -K "$out/udpst.keys" -B 1000 -t 10 >"$out/udpst-server.log" 2>&1 &
sleep 1

# Expected IP-layer capacity: udpst's default 1222-octet payload is 1250 octets
# at IP and 1264 on the Ethernet link tbf meters.
expect() { python3 -c "print(round($1 * 1250 / 1264, 2))"; }
client() { # client <-u|-d> <label>
  ip netns exec bm-probe "$udpst" "$1" -4 -f json -s -X -o -B 500 -t 10 -K "$out/udpst.keys" -y 7 10.90.9.2 \
    >"$out/$2.json" 2>"$out/$2.err" || true
  python3 - "$out/$2.json" "$3" "$2" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); exp = float(sys.argv[2])
m = d.get("Output", {}).get("AtMax", {})
cap = m.get("MaxIPLayerCapacity")
err = (cap - exp) / exp * 100 if cap else None
print(f"{sys.argv[3]:<22} expected {exp:7.2f}  measured {cap!s:>8}  error {err:+6.1f}%  "
      f"loss@max {m.get('LossRatioAtMax')}  ErrorStatus {d.get('ErrorStatus')} {d.get('ErrorMessage','')}"
      if cap else f"{sys.argv[3]}: no result: ErrorStatus {d.get('ErrorStatus')} {d.get('ErrorMessage')}")
PY
}

echo "== part 1: udpst client against shaped links (Mbit/s, IP layer)"
"$lab" shape 50mbit 16kb >/dev/null; "$lab" shape 20mbit 16kb back >/dev/null
client -u up-50 "$(expect 50)"
client -d down-20 "$(expect 20)"
"$lab" shape 10mbit 8kb >/dev/null; "$lab" shape 100mbit 32kb back >/dev/null
client -u up-10 "$(expect 10)"
client -d down-100 "$(expect 100)"

echo "== part 2: the same through buffmon (probe job poll -> collector -> real udpst)"
"$lab" shape 50mbit 16kb >/dev/null; "$lab" shape 20mbit 16kb back >/dev/null
token=$(openssl rand -hex 24)
python3 -c "import hashlib,json,sys; print(json.dumps({'lab-p1': hashlib.sha256(sys.argv[1].encode()).hexdigest()}))" \
  "bm_$token" >"$out/probe-tokens.json"
printf 'bm_%s\n' "$token" >"$out/probe-token"
chmod 600 "$out/probe-tokens.json" "$out/probe-token"
cat >"$out/policy.yaml" <<YAML
enabled: true
probes: ["lab-*"]
max_mbps: 500
max_duration_s: 10
allowed_dscp: [0]
YAML
cat >"$out/probe.toml" <<TOML
probe_id = "lab-p1"
site = "LAB"
[output]
url = "http://127.0.0.1:18090/v1/probe/results"
token_file = "$out/probe-token"
[[stamp]]
name = "dc-bulk"
target = "10.90.9.2:18620"
pps = 5
[stamp.trace]
enabled = false
[[speedtest]]
name = "dc-st"
enabled = true
server = "10.90.9.2"
udpst = "$udpst"
max_mbps = 500
key_file = "$out/udpst.keys"
key_id = 7
[jobs]
poll_s = 5
TOML
ip netns exec bm-refl "$bin/buffmon-reflector" --listen 0.0.0.0:18620 --allow 10.90.0.0/16 2>/dev/null &
ip netns exec bm-probe env BUFFMON_PORT=18090 BUFFMON_CLICKHOUSE_ENABLED=false BUFFMON_UI_AUTH=disabled \
  BUFFMON_PROBE_TOKENS_FILE="$out/probe-tokens.json" BUFFMON_SPEEDTEST_POLICY="$out/policy.yaml" \
  BUFFMON_SPEEDTEST_POLL_S=5 "$venv/bin/buffmon-ingest" >"$out/ingest.log" 2>&1 &
sleep 2
ip netns exec bm-probe "$bin/buffmon-probe" --config "$out/probe.toml" 2>"$out/probe.log" &
sleep 8
api() { ip netns exec bm-probe curl -sS -m 5 "$@"; }
for dir in up down; do
  api -X POST -H 'content-type: application/json' \
    -d "{\"probe_id\":\"lab-p1\",\"target\":\"dc-st\",\"direction\":\"$dir\"}" http://127.0.0.1:18090/v1/speedtests >/dev/null
  for _ in $(seq 1 40); do
    state=$(api http://127.0.0.1:18090/v1/speedtests | python3 -c 'import json,sys; print(json.load(sys.stdin)["jobs"][0]["state"])')
    [[ $state == queued || $state == dispatched ]] || break
    sleep 1
  done
done
api http://127.0.0.1:18090/v1/speedtests >"$out/speedtests.json"
python3 - "$out/speedtests.json" "$(expect 50)" "$(expect 20)" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); exp = {"up": float(sys.argv[2]), "down": float(sys.argv[3])}
for j in reversed(d["jobs"]):
    r = j.get("result") or {}
    cap = r.get("max_ip_capacity_mbps")
    e = exp[j["direction"]]
    err = f"{(cap - e) / e * 100:+.1f}%" if cap else "-"
    print(f"buffmon {j['direction']:<5} state {j['state']:<10} expected {e:7.2f}  measured {cap!s:>8}  error {err}  "
          f"{r.get('error') or ''}")
PY
echo "results in $out"
