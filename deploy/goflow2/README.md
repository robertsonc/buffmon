# EdgeConnect flow export → buffmon

```
EdgeConnect ──IPFIX/UDP 2055──▶ goflow2 ──JSON lines──▶ buffmon-flows ──▶ ClickHouse
                                (child process)          allowlist        flows
                                                         + enrichment     probe_flows
                                                                          flow_minute
```

## Collector: goflow2 v2.2.7 (pinned)

[goflow2](https://github.com/netsampler/goflow2) decodes NetFlow v9 / IPFIX and
writes one JSON object per flow. buffmon pins **v2.2.7** (tag commit
`74af41bea8baddeac1e710acb5441a3e5896b68a`) because `buffmon-flows` parses its
JSON field names (`buffmon/flows/goflow2.py`). Build it from the tag:

```bash
git clone --depth 1 --branch v2.2.7 https://github.com/netsampler/goflow2
cd goflow2 && git rev-parse HEAD   # must print 74af41be...
CGO_ENABLED=0 go build -trimpath -o goflow2 ./cmd/goflow2
sudo install -m 0755 goflow2 /usr/local/bin/goflow2
```

`buffmon-flows` starts it as:

```
goflow2 -listen=netflow://0.0.0.0:2055 -format=json -transport=file [-mapping=FILE]
```

Status in this repository: the parser is written and tested against goflow2's
JSON format as read from the v2.2.7 source. goflow2 itself has **not** been run
in the build environment yet; the first lab run is the check.

## Configure the EdgeConnect side

Point each appliance's IPFIX / flow export at the collector, UDP 2055. Exact
steps depend on your Orchestrator release; use your release's documentation and
change one lab appliance first (this is a config push).

Then list each appliance's **export source address** in `/etc/buffmon/sites.yaml`
(`deploy/sites.example.yaml`). Records from unlisted exporters are dropped.

## What is stored today

Standard IPFIX information elements only: 5-tuple, ipClassOfService (DSCP + ECN),
octets, packets, ingress/egress ifIndex, flow start/end, sampling rate.

EdgeConnect-specific elements (overlay, tunnel, application, ...) are
enterprise-specific (a Private Enterprise Number plus an element id). They are
**not** mapped yet, deliberately: we will take the numbers from a capture of a
real export instead of guessing. To capture one:

```bash
sudo tcpdump -i <iface> -w ec-ipfix.pcap udp port 2055 -c 2000
```

The capture must include a **template** set (sent periodically, so capture for
a few minutes). From it we add a goflow2 `-mapping` file with entries like:

```yaml
# Placeholder shape only — PEN and element numbers come from the capture.
formatter:
  fields: [type, time_received_ns, sampler_address, time_flow_start_ns, time_flow_end_ns,
           bytes, packets, src_addr, dst_addr, proto, src_port, dst_port, in_if, out_if,
           ip_tos, sampling_rate, observation_domain_id, ec_overlay]
  protobuf:
    - { name: ec_overlay, index: 1001, type: string }
ipfix:
  mapping:
    - { field: <element id>, penprovided: true, pen: <PEN>, destination: ec_overlay }
```

Note that a `formatter.fields` list replaces goflow2's default field list, so it
must include every standard field `buffmon-flows` reads (above).

## Path validation

For every live STAMP session, the dashboard looks up the probe's own 5-tuple in
`probe_flows` (both directions) and shows which appliance and interfaces it
crossed and with which DSCP. It warns when the exported DSCP differs from what
the probe marks: if your overlay policy classifies on DSCP, that probe is not on
the overlay of the traffic it represents.

Whether ipClassOfService is observed before or after the appliance's own
marking, and which ifIndex an overlay-carried flow reports as egress, depend on
the EdgeConnect release. The capture above settles both.
