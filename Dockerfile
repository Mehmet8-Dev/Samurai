# Native (ZMQ) control-plane image for DDoSamurai.
#
# The project migrated off the Python entrypoint (`python -m ddos_samurai.cli`)
# to a native C++ control plane. This builds the native daemons + commodity
# workers and ships them on a slim runtime. The master and slave are separate
# binaries; the Kubernetes workloads select one via `command:` (no --role).
#
#   docker build -f Dockerfile.prod -t ddos-samurai:native .
#   docker run --rm ddos-samurai:native samurai_master --help

# ---- builder ---------------------------------------------------------------
FROM debian:bookworm-slim AS build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    pkg-config \
    git \
    libssl-dev \
    libzmq3-dev \
    libhiredis-dev \
    libpcap-dev \
    libnghttp2-dev \
    libngtcp2-dev \
    libngtcp2-crypto-gnutls-dev \
    libnghttp3-dev \
    libgnutls28-dev \
    liburing-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Configure once, then build the deployable targets (CLI + daemons + commodity
# and telco workers). GPU/DPDK/DOCA backends are gated on their toolchains and
# skip cleanly when absent, so they are omitted from the default image.
RUN cmake -S ddos_samurai -B build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build -j "$(nproc)" --target \
      samurai \
      samurai_master \
      samurai_slave \
      samurai_cpu_worker \
      samurai_afpacket_worker \
      samurai_afxdp_worker \
      samurai_l7_worker \
      samurai_scenario_worker \
      samurai_defense_worker \
      samurai_telco_worker

# ---- runtime ---------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libzmq5 \
    libhiredis0.14 \
    libpcap0.8 \
    libnghttp2-14 \
    libngtcp2-9 \
    libngtcp2-crypto-gnutls2 \
    libnghttp3-3 \
    libgnutls30 \
    liburing2 \
    ca-certificates \
    iproute2 \
    curl \
    tini \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (matches the Helm securityContext runAsUser).
RUN useradd -u 10001 -m -s /usr/sbin/nologin samurai

# Install the native binaries on PATH. `--parents` preserves nothing; we flatten
# every built daemon/worker into /usr/local/bin.
COPY --from=build /src/build/cli/samurai                  /usr/local/bin/
COPY --from=build /src/build/control/daemon/samurai_master /usr/local/bin/
COPY --from=build /src/build/control/daemon/samurai_slave  /usr/local/bin/
COPY --from=build /src/build/zmq/samurai_cpu_worker        /usr/local/bin/
COPY --from=build /src/build/zmq/samurai_afpacket_worker   /usr/local/bin/
COPY --from=build /src/build/zmq/samurai_afxdp_worker      /usr/local/bin/
COPY --from=build /src/build/zmq/samurai_l7_worker         /usr/local/bin/
COPY --from=build /src/build/zmq/samurai_scenario_worker   /usr/local/bin/
COPY --from=build /src/build/zmq/samurai_defense_worker    /usr/local/bin/
COPY --from=build /src/build/zmq/samurai_telco_worker      /usr/local/bin/

USER 10001:10001
WORKDIR /home/samurai

# tini reaps the worker subprocesses the slave forks. The Kubernetes workloads
# override `command`/`args`; the default just prints master usage.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["samurai_master", "--help"]
