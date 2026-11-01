# Probe + reflector image for lab/demo use. Production site probes should run
# the binaries under systemd (deploy/systemd/) on the host network.
#
# Never --privileged. The image runs as a non-root user:
#   probe:     docker run --cap-drop=ALL --cap-add=NET_RAW ... buffmon-probe
#              (file capability cap_net_raw on the binary; do NOT add
#              no-new-privileges, which disables file capabilities — without
#              NET_RAW the probe falls back to datagram ICMP)
#   reflector: docker run --cap-drop=ALL -p 862:8620/udp --entrypoint buffmon-reflector ...
#              --listen 0.0.0.0:8620 (unprivileged port: no capability at all)

FROM rust:1.97.0-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release --locked

FROM debian:bookworm-20261005-slim
COPY --from=build /src/target/release/buffmon-probe /src/target/release/buffmon-reflector /usr/local/bin/
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libcap2-bin \
    && setcap cap_net_raw+ep /usr/local/bin/buffmon-probe \
    && apt-get purge -y libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin buffmon
USER 10001
ENTRYPOINT ["/usr/local/bin/buffmon-probe"]
CMD ["--config", "/etc/buffmon/probe.toml"]
