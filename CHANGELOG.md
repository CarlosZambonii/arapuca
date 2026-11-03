# Changelog

Notable changes to Arapuca. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The event schema has its own version, `schema_version` in every event, which
is bumped only on a breaking change to the envelope and is documented in
[`docs/EVENT_SCHEMA.md`](docs/EVENT_SCHEMA.md).

## [Unreleased]

### Added

* The public map zooms and pans: a wheel or a pinch over it magnifies the map
  rather than the page, a drag moves it, the arrow keys and `+`, `-` and `0`
  work when it has focus, and a control in the corner resets the view.
* A link preview image. `web/card.html` is rendered to `web/og.png` by
  `scripts/render_social_card.sh`, so sharing the page shows the map rather
  than an empty rectangle.
* A session replay on the public page: the busiest captured session is
  exported with each command's `seq` and `since_prev_ms`, and a terminal
  panel plays it back at the attacker's own rhythm, with play, pause and
  restart, a static render under reduced motion, and the panel hidden until a
  session is worth showing.
* ThreadSanitizer runs in CI and in `scripts/verify.sh`. The preset existed
  from the first commit and nothing ever ran it, on a daemon that is threaded
  throughout.
* Coverage measurement: a `coverage` preset, `scripts/coverage.sh`, and a CI
  job that publishes the HTML report as an artifact and fails under a floor.
* CodeQL analysis for C++ and Python, on every push and weekly.
* Trivy scanning of the container image, with the findings uploaded to the
  security tab and a CycloneDX bill of materials kept as an artifact.
* A nightly fuzzing campaign, ten minutes per target with a corpus that
  accumulates between runs, separate from the sixty second smoke test on
  pull requests.
* `ruff` and `mypy --strict` over `tools/`, which previously had no checks at
  all and only ever runs unattended on a schedule.
* Keyless cosign signatures on every published container image, so a pull
  can be checked against the workflow and repository that built it.
* A release workflow: a `v*` tag is verified against the version in
  `CMakeLists.txt` and this changelog, built and tested, and turned into a
  GitHub release whose notes are the changelog section for that version.
* `SECURITY.md`, `CONTRIBUTING.md`, this changelog, issue forms and a pull
  request template.

### Fixed

* A release tag built a container image and then threw it away: the publish
  job was triggered by `v*` tags but its condition only ever allowed `main`.
  Tags now publish `:v1.2.3`, `:1.2.3` and `:latest`.
* Netlify rebuilt the page on every push, including the ones that cannot
  change it. The build is now skipped unless something under `web/` changed.
* The README showed two broken images where the dashboard screenshots will
  go. It now describes what the dashboards contain, which is true today.

## [0.1.0] - 2026-11-02

First public release: the sensor is live on a public address and collecting.

### Added

* **SSH honeypot** on libssh, accepting only credentials from a list of the
  weak ones real brute forcers try, with every attempt recorded whether it
  worked or not. Port forwarding, X11, agent forwarding and every subsystem
  are refused at the callback level.
* **Fake shell** with more than forty commands over an in memory filesystem,
  and a line editor that records the keystrokes rather than the result.
* **HTTP honeypot** with an admin panel on the paths scanners actually
  request and decoy files holding fabricated credentials.
* **Capture engine**: an attacker's `wget` or `curl` is fetched on a worker
  thread with hard timeouts and a size cap, validated against an address
  policy that rejects private ranges, loopback and the cloud metadata service
  on the resolved address at every redirect hop, quarantined as an encrypted
  read only `<sha256>.zip`, and looked up on VirusTotal by hash alone.
* **Enrichment**: GeoIP from DB-IP Lite, MITRE ATT&CK mapping from rules in
  YAML, and a session classifier that reads typing rhythm.
* **Observability**: one JSON object per line on a documented schema, shipped
  by the New Relic Infrastructure Agent, with two dashboards and an alert
  policy of eight conditions defined in Terraform.
* **Infrastructure**: Terraform for Oracle Cloud, Ansible that moves the real
  SSH daemon before it opens port 22, a multi architecture container that
  runs unprivileged on a read only filesystem with no capabilities.
* **The public page**: a bilingual live map of attack origins, deployed on
  Netlify from data a scheduled job exports, so the New Relic key never
  reaches a browser.
* **Gates**: a four way build matrix, ASan and UBSan, libFuzzer targets with
  a committed corpus, clang-tidy, and a CI check that fails the build if a
  process spawning primitive appears anywhere in the sources.

[Unreleased]: https://github.com/CarlosZambonii/arapuca/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/CarlosZambonii/arapuca/releases/tag/v0.1.0
