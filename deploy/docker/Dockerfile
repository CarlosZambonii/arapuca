# syntax=docker/dockerfile:1
#
# Arapuca honeypot image.
#
# Ubuntu 24.04 is the only supported base, in the builder and at runtime, and
# it is what the VPS runs. libssh 0.10.6 comes from it.
#
# The runtime stage carries no compiler, no package manager cache and no shell
# utilities beyond what the daemon links against. A honeypot is a machine
# attackers reach on purpose, so the blast radius of a hypothetical escape is
# worth minimising even though nothing attacker supplied is ever executed.

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
FROM ubuntu:26.04 AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        git \
        libcurl4-openssl-dev \
        libmaxminddb-dev \
        libminizip-dev \
        libssh-dev \
        libssl-dev \
        libyaml-cpp-dev \
        ninja-build \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Dependency declarations first, so a source change does not refetch the
# pinned header only libraries on every build.
COPY CMakeLists.txt CMakePresets.json ./
COPY cmake/ cmake/

# Then the sources.
COPY include/ include/
COPY src/ src/
COPY tests/ tests/

RUN cmake -S . -B build \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DARAPUCA_BUILD_TESTS=OFF \
    && cmake --build build --target arapucad \
    && strip build/src/arapucad

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM ubuntu:26.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Runtime libraries only. No -dev, no compiler, no package lists left behind.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libcurl4 \
        libmaxminddb0 \
        libminizip1t64 \
        libssh-4 \
        libyaml-cpp0.8 \
    && rm -rf /var/lib/apt/lists/*

# A fixed, unprivileged uid. The honeypot listens on high ports inside the
# container and the host maps 22 and 80 onto them, so nothing here ever needs
# a privileged port or root. Safety invariant S5.
RUN groupadd --gid 10001 arapuca \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin arapuca

COPY --from=build /src/build/src/arapucad /usr/local/bin/arapucad
COPY config/ /etc/arapuca/

# Writable state. The root filesystem is mounted read only by the compose
# file, so these are the only paths that can be written, and they are volumes.
RUN mkdir -p /var/lib/arapuca/state /var/lib/arapuca/quarantine /var/lib/arapuca/geoip /var/log/arapuca \
    && chown -R 10001:10001 /var/lib/arapuca /var/log/arapuca

USER 10001:10001
WORKDIR /var/lib/arapuca

EXPOSE 2222 8080

# No shell form, so the daemon is pid 1 and receives SIGTERM directly rather
# than through a shell that would swallow it.
ENTRYPOINT ["/usr/local/bin/arapucad"]
CMD ["--config", "/etc/arapuca/arapuca.yaml"]
