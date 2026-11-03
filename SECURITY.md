# Security policy

## What is in scope

Arapuca is a honeypot. It is **meant** to be attacked, and most of what looks
like a vulnerability in it is the product working: weak passwords are accepted
on purpose, the shell hands out credentials that open nothing, and the decoy
files at `/.env` and `/.git/config` contain fabricated secrets.

A report is in scope if it describes a way to make the honeypot do something
outside its own sandbox. Concretely, any of these is a defect, not a feature:

* Executing anything an attacker sends. Nothing is ever executed; every shell
  response is fabricated or read from an in memory filesystem.
* Reaching a real service through the honeypot: port forwarding, tunnelling,
  a subsystem, or a download aimed at a private range, at loopback, or at the
  cloud metadata service on `169.254.169.254`.
* Reading or writing anything on the host outside the paths the container is
  given, including a path traversal out of the virtual filesystem.
* Filling the disk, exhausting memory, or keeping the process down, from a
  single connection or a cheap sequence of them.
* Uploading a captured sample anywhere, or any path that sends a file rather
  than a hash to a third party.
* A secret reaching the repository, a log, the public page or a build log.

## What is not in scope

* Guessing a password and getting a shell. That is the invitation.
* The fabricated credentials in the decoy files.
* Findings against `arapuca.netlify.app` that amount to it being a static
  page with no backend.
* Denial of service against the live sensor by volume. It is a single always
  free instance; flooding it proves nothing and takes the sensor off the air
  for everyone else.

## Reporting

Use GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/CarlosZambonii/arapuca/security/advisories/new)**.

Please include the version or commit, the configuration, and the smallest
input that reproduces it. A crashing input from the fuzzers is ideal: drop it
in as a file and say which target found it.

Expect a first reply within seven days. There is no bounty programme: this is
a portfolio project run by one person, and a credit in the advisory and in the
changelog is what is on offer.

## Supported versions

`main` only. Each release is a tag and a container image on GHCR; fixes land
on `main` and go out in the next tag rather than being backported.
