# Decoy files

Files in this directory are served by the HTTP honeypot in place of the built
in set. The built in decoys live in `src/http/decoys.cpp` and are used when
this directory is empty or missing, so a bare checkout is still a working trap.

## Naming

A file name here maps to the request paths it answers, because some of those
paths cannot be file names in a repository checkout:

| File name | Request paths |
|-----------|---------------|
| `dot-env` | `/.env`, `/.env.local`, `/.env.production`, `/api/.env` |
| `git-config` | `/.git/config`, `/.git/HEAD` |
| `backup.sql` | `/backup.sql`, `/dump.sql`, `/db.sql`, `/database.sql` |
| `config.php` | `/config.php`, `/wp-config.php`, `/configuration.php` |
| `aws-credentials` | `/.aws/credentials`, `/credentials` |
| `docker-compose.yml` | `/docker-compose.yml`, `/docker-compose.yaml` |
| anything else | `/<file name>` |

## Writing a decoy

A scanner that asks for `/.env` and gets a 404 learns nothing and moves on.
One that gets a plausible `.env` takes the credentials away, and whatever it
does with them next is visible from somewhere else. That makes a decoy hit one
of the highest signal events this honeypot produces, so the content is worth
getting right:

* Shape the values like the real thing, including key lengths and prefixes.
  An AWS key that is the wrong length is noticed.
* Keep the file internally consistent with the rest of the fake machine. The
  database host in `.env` should be the host that appears in `/etc/hosts` in
  the fake filesystem.
* Never use a real credential, a real internal hostname, or a real public
  address. Everything here is published in a public repository.
* Use reserved ranges (`10.0.0.0/8`, `198.51.100.0/24`) and the `.invalid`
  top level domain for anything that looks like an address.

Every value in the built in set is fabricated and opens nothing.
