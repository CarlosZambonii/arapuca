# Indicators of compromise

Generated daily by `.github/workflows/iocs.yml` from this sensor's own
telemetry. Nothing here comes from a third party feed.

| File | Contents |
|------|----------|
| `latest-ips.csv` | source addresses seen attacking, most active first |
| `latest-hashes.csv` | sha256 of samples captured, newest first |
| `ips-YYYY-MM-DD.{csv,json}` | that day's snapshot |
| `hashes-YYYY-MM-DD.{csv,json}` | that day's snapshot |

## What an entry means

An address is here because it connected to a machine that advertises nothing,
hosts nothing and is linked from nowhere. There is no confidence score,
because there is nothing to be unsure about: the only way to arrive is to go
looking.

That said, read them with the obvious caveats:

* **Addresses are reused.** A compromised home router today is somebody's
  home internet tomorrow. These are observations with timestamps, not a
  permanent blocklist, and `last_seen` is there for exactly that reason.
* **Shared addresses exist.** Carrier grade NAT and cloud egress mean one
  address can cover thousands of unrelated users.
* **Blocking on this alone is a bad idea.** It is evidence to correlate with
  what you see in your own logs, not a drop list to paste into a firewall.

## Sample hashes

A hash is here because the sample was fetched from a URL an attacker typed
into the fake shell, and the file is held in quarantine on the sensor. Where
a VirusTotal verdict is present it is a lookup by hash: no sample is ever
uploaded anywhere.

An empty `vt_detections` means VirusTotal has never seen that hash, which is
the most interesting case in the file.

## Using them

```bash
# Addresses active in the last day
cut -d, -f1 iocs/latest-ips.csv | tail -n +2

# Cross reference against your own logs
grep -F -f <(cut -d, -f1 iocs/latest-ips.csv | tail -n +2) /var/log/auth.log
```
