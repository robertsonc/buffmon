# RFC 9946 speed tests with OB-UDPST (P3.3)

buffmon runs on-demand speed tests with the Broadband Forum's open-source
OB-UDPST (`udpst`, BSD-3-Clause, TR-471; RFC 9946 compatible since 9.0.0).
The probe runs the client; you run the server next to your reflectors.
docs/DESIGN.md D14 explains what a speed test measures and why it is guarded.

**Status: lab-verified with OB-UDPST v9.1.0** (`probe/lab/verify-speedtest.sh`):
upstream and downstream Maximum IP-Layer Capacity within 0.2% of tbf-shaped
rates, both with the udpst client directly and through buffmon (probe job
poll, collector policy and API).

## Build (client and server), pinned

```bash
git clone https://github.com/BroadbandForum/obudpst.git && cd obudpst
git checkout v9.1.0          # 2026-09-18; review the CHANGELOG before moving up
# Server: RATE_LIMITING caps each test at the bandwidth the client asked for
# (-B), so the server enforces the cap too, not only the probe.
cmake -D RATE_LIMITING=ON . && make
sudo install -m 0755 udpst /usr/local/bin/udpst
```

The probe hosts need only the client binary (the same build; `RATE_LIMITING`
matters on the server).

## Keys (RFC 9946 authentication)

`udpst` key files are CSV: `<key id 0-255>, <key, up to 64 characters>`, `#`
comments. One server takes up to 256 key IDs, so give IDs per site or region
rather than per probe once a fleet passes that.

```bash
umask 077
printf '7, %s\n' "$(openssl rand -hex 32)" > /etc/buffmon/udpst.keys
```

Install the same line on the server (its `-K` file, all IDs) and on the probe
(`[[speedtest]] key_file`, `key_id = 7`). The key never goes on a command line.

## Server

```bash
udpst -4 -K /etc/buffmon/udpst.keys -B 1000 -t 10 -l /var/log/udpst.log
```

- `-4`: the server binds IPv4 and IPv6 by default and exits with "Address
  family not supported" on a host without IPv6. buffmon probes are IPv4-only.

- `-B`: bandwidth the server can give (admission control, per direction).
- `-t`: longest test it accepts.
- Control port UDP 24601; test traffic uses ephemeral UDP ports
  (`net.ipv4.ip_local_port_range`), which the firewall in front must allow.
- Run one instance per interface or port for more aggregate capacity (see
  OB-UDPST "Server Bandwidth Management").

## Probe

```toml
[[speedtest]]
name = "dc1-st"
enabled = true
server = "st.dc1.example.net:24601"
max_mbps = 300          # never above what the circuit should carry
max_duration_s = 10
dscp = 0                # 32 and up (priority classes) are refused
directions = ["down", "up"]
key_file = "${CREDENTIALS_DIRECTORY}/udpst-keys"
key_id = 7
```

The probe runs `udpst -d|-u -4 -f json -s -X -o -B <mbps> -t <s> -m <tos> -K
<file> -y <id> <server>` with no shell, an empty environment and no ambient
capabilities, and kills it (and anything it started) if it overruns.

## Collector

Set `BUFFMON_SPEEDTEST_POLICY` to a copy of `deploy/speedtest-policy.example.yaml`.
Without it, speed tests are disabled. The dashboard then shows a "Speed test"
section in each session drawer for probes that advertise targets.
