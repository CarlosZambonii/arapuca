# Arapuca

> Work in progress. The full documentation, architecture diagram and dashboard screenshots
> land in phase 10. See [PLAN.md](PLAN.md) for the architecture and the phase roadmap.

Arapuca is a medium interaction SSH and HTTP honeypot written in C++20. It records attacker
behavior, enriches every event with GeoIP and MITRE ATT&CK context, captures dropped payloads
into a password protected quarantine, and ships structured JSON events to New Relic, where
dashboards and alerts are provisioned as code.

**It never executes anything an attacker sends.** Every shell response is simulated, and CI
fails the build if a process execution primitive appears anywhere in the sources.

## Quick start

```bash
# Dependencies, see docs/DEPENDENCIES.md
sudo apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build pkg-config \
    libssl-dev libcurl4-openssl-dev \
    libssh-dev libyaml-cpp-dev libmaxminddb-dev libminizip-dev

cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

## Supported platform

Ubuntu 24.04 LTS (noble) on x86_64 and arm64, with libssh 0.10.6. That is the only supported
base, in CI, in the container and on the VPS.

## Legal and ethical notice

Arapuca records only what is voluntarily sent to it by whoever connects. Run it on
infrastructure you own, understand your local law before publishing collected data, and never
use it to attack anyone. The IoC feed publishes source addresses and file hashes for
defensive use.

## License

MIT, see [LICENSE](LICENSE).
