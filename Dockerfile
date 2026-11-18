# syntax=docker/dockerfile:1

# ---- build ------------------------------------------------------------------
ARG RUST_VERSION=1
FROM rust:${RUST_VERSION}-bookworm AS build
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Cache the registry and target dir between builds; copy the binary out of the
# cache mount so it lands in the image layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && install -Dm755 target/release/thurang /out/thurang

# ---- runtime ----------------------------------------------------------------
FROM debian:bookworm-slim

# iproute2: `ip route`; iptables: NAT/forward rules; procps: `sysctl`.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 iptables procps \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/thurang /usr/local/bin/thurang

# State (keys, peers, journal, IPC socket). Must be root-owned and not
# group/world-writable, or thurang refuses to start.
ENV THURANG_HOME=/etc/thurang
RUN install -d -m 0700 /etc/thurang
VOLUME ["/etc/thurang"]

# 51820/udp WireGuard, 51821/tcp pairing.
EXPOSE 51820/udp 51821/tcp

ENTRYPOINT ["thurang"]
CMD ["server", "up"]
