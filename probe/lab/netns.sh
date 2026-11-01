#!/usr/bin/env bash
# Routed lab in Linux network namespaces for testing path tracing and
# packet-train capacity without touching a real network. Needs root (or
# CAP_NET_ADMIN + CAP_SYS_ADMIN) and iproute2. Everything lives in namespaces
# named bm-*; `down` removes them all.
#
#   probe 10.90.1.2 ─ r1 ─┬─ r2a ──────────┬─ r3 ─ reflector 10.90.9.2
#                         ├─ r2b ──────────┤
#                         └─ r2c1 ─ r2c2 ──┘
#
#   lab/netns.sh up                # build it; forward path via r2a
#   lab/netns.sh path a|b|c        # switch r1's route to the reflector (c is one hop longer)
#   lab/netns.sh shape <rate> [burst] [dir]   # tbf on r3 -> reflector (dir=fwd) or r1 -> probe (dir=back)
#   lab/netns.sh unshape [dir]
#   lab/netns.sh down
#   ip netns exec bm-probe <cmd>   # run something on the probe host
set -euo pipefail

NS=(bm-probe bm-r1 bm-r2a bm-r2b bm-r2c1 bm-r2c2 bm-r3 bm-refl)
x() { ip netns exec "$@"; }

link() { # link <nsA> <ifA> <addrA> <nsB> <ifB> <addrB>
  ip link add "$2" netns "$1" type veth peer name "$5" netns "$4"
  x "$1" ip addr add "$3" dev "$2"; x "$1" ip link set "$2" up
  x "$4" ip addr add "$6" dev "$5"; x "$4" ip link set "$5" up
}

up() {
  down 2>/dev/null || true
  for n in "${NS[@]}"; do
    ip netns add "$n"
    x "$n" ip link set lo up
    x "$n" sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
  done
  link bm-probe p0  10.90.1.2/24  bm-r1   r1p   10.90.1.1/24
  link bm-r1   r1a  10.90.2.1/30  bm-r2a  r2a1  10.90.2.2/30
  link bm-r2a  r2a3 10.90.4.1/30  bm-r3   r3a   10.90.4.2/30
  link bm-r1   r1b  10.90.3.1/30  bm-r2b  r2b1  10.90.3.2/30
  link bm-r2b  r2b3 10.90.5.1/30  bm-r3   r3b   10.90.5.2/30
  link bm-r1   r1c  10.90.6.1/30  bm-r2c1 r2c1a 10.90.6.2/30
  link bm-r2c1 r2c1b 10.90.7.1/30 bm-r2c2 r2c2a 10.90.7.2/30
  link bm-r2c2 r2c2b 10.90.8.1/30 bm-r3   r3c   10.90.8.2/30
  link bm-r3   r3r  10.90.9.1/24  bm-refl r0    10.90.9.2/24
  x bm-probe ip route add default via 10.90.1.1
  x bm-refl  ip route add default via 10.90.9.1
  # Every router knows both ends; r1's route to the reflector picks the path.
  x bm-r2a  ip route add 10.90.9.0/24 via 10.90.4.2;  x bm-r2a  ip route add 10.90.1.0/24 via 10.90.2.1
  x bm-r2b  ip route add 10.90.9.0/24 via 10.90.5.2;  x bm-r2b  ip route add 10.90.1.0/24 via 10.90.3.1
  x bm-r2c1 ip route add 10.90.9.0/24 via 10.90.7.2;  x bm-r2c1 ip route add 10.90.1.0/24 via 10.90.6.1
  x bm-r2c2 ip route add 10.90.9.0/24 via 10.90.8.2;  x bm-r2c2 ip route add 10.90.1.0/24 via 10.90.7.1
  x bm-r3   ip route add 10.90.1.0/24 via 10.90.4.1   # return path always via r2a
  path a
}

path() {
  case "${1:-}" in
    a) via=10.90.2.2 ;; b) via=10.90.3.2 ;; c) via=10.90.6.2 ;;
    *) echo "path a|b|c" >&2; exit 2 ;;
  esac
  x bm-r1 ip route replace 10.90.9.0/24 via "$via"
  echo "forward path -> $1 (via $via)"
}

shape() { # shape <rate> [burst] [fwd|back]
  local rate=${1:?rate, e.g. 20mbit} burst=${2:-16kb} dir=${3:-fwd}
  local ns=bm-r3 dev=r3r
  [[ $dir == back ]] && { ns=bm-r1; dev=r1p; }
  x "$ns" tc qdisc replace dev "$dev" root tbf rate "$rate" burst "$burst" latency 200ms
  echo "$dir shaped: tbf rate $rate burst $burst on $ns/$dev"
}

unshape() {
  local ns=bm-r3 dev=r3r
  [[ ${1:-fwd} == back ]] && { ns=bm-r1; dev=r1p; }
  x "$ns" tc qdisc del dev "$dev" root 2>/dev/null || true
}

down() {
  for n in "${NS[@]}"; do ip netns del "$n" 2>/dev/null || true; done
}

cmd=${1:-}; shift || true
case "$cmd" in
  up|down|path|shape|unshape) "$cmd" "$@" ;;
  *) sed -n '2,17p' "$0"; exit 2 ;;
esac
