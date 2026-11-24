# Samurai Containerfile / Dockerfile
#
# Supports two modes:
#   1. Source-only GHCR image (`--target source-runtime`):
#      Ships the C++17 toolchain + full repository source without compiling on CI.
#      On first run on a user's machine, `/usr/local/bin/samurai-entrypoint.sh`
#      compiles natively with `SAMURAI_NATIVE_ARCH=ON` into `/var/cache/samurai`.
#   2. Direct local baked build (`docker build -t samurai:local .`):
#      Compiles locally during `docker build` with `SAMURAI_NATIVE_ARCH=ON` into
#      a minimal runtime image (`samurai_master`, `samurai_slave`, `samurai_mcp`,
#      `samurai`, workers, benchmarks, skills, and Mahoraga RL weights).

# ---- toolchain (shared deps for source-runtime & local build) --------------
FROM debian:bookworm-slim AS toolchain

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
    ca-certificates \
    iproute2 \
    curl \
    tini \
    && rm -rf /var/lib/apt/lists/*

# ---- source-runtime (GHCR: uncompiled source + local-first-run compile) ----
FROM toolchain AS source-runtime

RUN useradd -u 10001 -m -s /usr/sbin/nologin samurai

WORKDIR /opt/samurai/src
COPY . /opt/samurai/src
COPY docker/samurai-entrypoint.sh /usr/local/bin/samurai-entrypoint.sh

RUN chmod 0755 /usr/local/bin/samurai-entrypoint.sh \
 && mkdir -p /usr/local/share/samurai/skills /usr/local/share/samurai/rl /var/cache/samurai/bin /var/cache/samurai/lib /var/cache/samurai/build \
 && cp -r /opt/samurai/src/skills/. /usr/local/share/samurai/skills/ \
 && find /opt/samurai/src/artifacts/rl -maxdepth 1 -name '*.srlp' ! -name '*.bak.srlp' ! -name '*.prev.srlp' -exec cp {} /usr/local/share/samurai/rl/ \; \
 && find /opt/samurai/src/samurai -type f | LC_ALL=C sort | xargs sha256sum | sha256sum | awk '{print $1}' > /opt/samurai/.source-stamp \
 && chmod 0777 /var/cache/samurai /var/cache/samurai/bin /var/cache/samurai/lib /var/cache/samurai/build \
 && chown -R 10001:10001 /var/cache/samurai

ENV PATH="/var/cache/samurai/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV LD_LIBRARY_PATH="/var/cache/samurai/lib"
ENV SAMURAI_SOURCE_DIR="/opt/samurai/src"
ENV SAMURAI_BUILD_CACHE_DIR="/var/cache/samurai"
ENV SAMURAI_NATIVE_ARCH="ON"
ENV SAMURAI_SKILLS_DIR="/usr/local/share/samurai/skills"
ENV SAMURAI_RL_DIR="/usr/local/share/samurai/rl"

USER 10001:10001
WORKDIR /home/samurai

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/samurai-entrypoint.sh"]
CMD ["samurai_master", "--help"]

# ---- builder (local host docker build / CI smoke) --------------------------
FROM toolchain AS build

WORKDIR /src
COPY . .

# Configure once, then build the deployable targets (CLI + daemons + commodity
# and telco workers + reproducible benchmark harnesses). Defaults to
# `SAMURAI_NATIVE_ARCH=ON` so local `docker build` compiles for the host CPU and
# any host-present GPU/DPDK toolchains. Pass `--build-arg SAMURAI_NATIVE_ARCH=OFF`
# for portable multi-host CI images.
ARG SAMURAI_NATIVE_ARCH=ON
RUN cmake -S samurai -B build -DCMAKE_BUILD_TYPE=Release -DSAMURAI_NATIVE_ARCH=${SAMURAI_NATIVE_ARCH} \
 && cmake --build build -j "$(nproc)" --target \
      samurai \
      samurai_mcp \
      samurai_master \
      samurai_slave \
      samurai_cpu_worker \
      samurai_afpacket_worker \
      samurai_afxdp_worker \
      samurai_dpdk_worker \
      samurai_gpu_worker \
      samurai_doca_worker \
      samurai_l7_worker \
      samurai_scenario_worker \
      samurai_defense_worker \
      samurai_telco_worker \
      test_100k_tcp_flows \
      test_1m_tcp_flows \
      bench_l7_stateful_userspace \
 && mkdir -p /opt/samurai_rl \
 && find /src/artifacts/rl -maxdepth 1 -name '*.srlp' ! -name '*.bak.srlp' ! -name '*.prev.srlp' -exec cp {} /opt/samurai_rl/ \;

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
COPY --from=build /src/build/mcp/samurai_mcp              /usr/local/bin/
COPY --from=build /src/build/control/daemon/samurai_master /usr/local/bin/
COPY --from=build /src/build/control/daemon/samurai_slave  /usr/local/bin/
COPY --from=build /src/build/zmq/samurai_cpu_worker        /usr/local/bin/
COPY --from=build /src/build/zmq/samurai_afpacket_worker   /usr/local/bin/
COPY --from=build /src/build/zmq/samurai_afxdp_worker      /usr/local/bin/
COPY --from=build /src/build/zmq/samurai_dpdk_worker       /usr/local/bin/
COPY --from=build /src/build/zmq/samurai_gpu_worker        /usr/local/bin/
COPY --from=build /src/build/zmq/samurai_doca_worker       /usr/local/bin/
COPY --from=build /src/build/zmq/samurai_l7_worker         /usr/local/bin/
COPY --from=build /src/build/zmq/samurai_scenario_worker   /usr/local/bin/
COPY --from=build /src/build/zmq/samurai_defense_worker    /usr/local/bin/
COPY --from=build /src/build/zmq/samurai_telco_worker             /usr/local/bin/
COPY --from=build /src/build/l4/test_100k_tcp_flows               /usr/local/bin/samurai_bench_100k_tcp
COPY --from=build /src/build/l4/test_1m_tcp_flows                 /usr/local/bin/samurai_bench_1m_tcp
COPY --from=build /src/build/zmq/bench_l7_stateful_userspace      /usr/local/bin/samurai_bench_l7
COPY --from=build /src/skills                                     /usr/local/share/samurai/skills
COPY --from=build /opt/samurai_rl                                 /usr/local/share/samurai/rl

USER 10001:10001
WORKDIR /home/samurai

# tini reaps the worker subprocesses the slave forks. The Kubernetes workloads
# override `command`/`args`; the default just prints master usage.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["samurai_master", "--help"]
