# Arapuca weekly report, 2026-W47

_Generated 2026-11-16 16:20 UTC from the sensor's own telemetry._

## Summary

- **190,498 events** from **1,584 distinct addresses** across **51,731 sessions** (about the same as the week before).
- **0 new samples** captured and quarantined.
- **0 download attempts refused** by the address policy.

## Credentials tried

These are the passwords being sprayed at the internet right now. The
honeypot accepts only a short list, so most of these failed and were
recorded anyway: a refused login is as much of a product as an accepted
one.

### Passwords

| password | attempts |
|---|---:|
| `(empty)` | 39,058 |
| `123456` | 1,898 |
| `123` | 775 |
| `1234` | 725 |
| `password` | 444 |
| `12345678` | 430 |
| `root` | 402 |
| `123MUDAR` | 390 |
| `1` | 375 |
| `12345` | 375 |
| `zzq-7K1-not-a-real-pass` | 364 |
| `123456789` | 297 |
| `admin` | 268 |
| `P@ssw0rd` | 196 |
| `111111` | 187 |


### Usernames

| username | attempts |
|---|---:|
| `root` | 37,125 |
| `ubuntu` | 3,986 |
| `admin` | 2,939 |
| `user` | 1,287 |
| `test` | 873 |
| `deploy` | 845 |
| `Tronlong` | 537 |
| `user1` | 400 |
| `support` | 386 |
| `debian` | 374 |
| `dev` | 355 |
| `ftpuser` | 346 |
| `postgres` | 306 |
| `claude` | 302 |
| `developer` | 300 |


### Credentials that worked

Pairs that matched the weak credential list, meaning the session reached
the fake shell. These are the sessions worth reading.

| username / password | sessions |
|---|---:|
| `support / support` | 159 |
| `root / 123456789` | 118 |
| `root / admin` | 88 |
| `root / 123456` | 83 |
| `admin / admin` | 80 |
| `root / 1234` | 79 |
| `root / root` | 75 |
| `ubnt / ubnt` | 75 |
| `root / 12345` | 74 |
| `root / password` | 63 |


## What they did once inside

| command | times |
|---|---:|
| `uname -s -v -n -r -m` | 648 |
| `/bin/./uname -s -v -n -r -m` | 19 |
| `(empty)` | 6 |
| `uname -s -m` | 4 |
| `cat /etc/issue` | 3 |
| `cat /proc/mounts` | 3 |
| `echo xsec` | 3 |
| `sh -c 'printf '"'"'\n%s\|%s\n'"'"' '"'"'check_496a2ad563f2c9b75e8a964ce85e69b8_small_control'"'"' '"'"'check_496a2ad563f2c9b75e8a964ce85e69b8'"'"''` | 1 |
| `sh -c 'printf '"'"'\n%s\|%s\n'"'"' '"'"'check_9911a3e20ed2bdf9a144fcc741492bd1_small_control'"'"' '"'"'check_9911a3e20ed2bdf9a144fcc741492bd1'"'"''` | 1 |
| `sh -c 'printf '"'"'\n%s\|%s\n'"'"' '"'"'check_3be21ff03e2c3a30636df6b0790d37c0_small_control'"'"' '"'"'check_3be21ff03e2c3a30636df6b0790d37c0'"'"''` | 1 |
| `sh -c 'printf '"'"'\n%s\|%s\n'"'"' '"'"'check_484441944895c768d6484b8cf6b40eeb_small_pid'"'"' "$$"'` | 1 |
| `echo; echo 'check_a527d0c840f454b1f13e81938c95525c_transport_done'` | 1 |
| `sh -c 'printf '"'"'\n%s\|%s\n'"'"' '"'"'check_4139d524dcda96574ba881ae5c27689f_small_control'"'"' '"'"'check_4139d524dcda96574ba881ae5c27689f'"'"''` | 1 |
| `sh -c 'set -- '"'"'check_73be6190f4fc3096f6599bb25bb1f0a9_arg1'"'"' '"'"'check_73be6190f4fc3096f6599bb25bb1f0a9_arg2'"'"'; printf '"'"'\n%s\|%s\n'"'"' '"'"'check_73be6190f4fc3096f6599bb25bb1f0a9_small_positional'"'"' "$#\|$1\|$2"'` | 1 |
| `set -- 'check_02f25973de343e5ca26ed27d19840543_arg1' 'check_02f25973de343e5ca26ed27d19840543_arg2'; echo 'check_02f25973de343e5ca26ed27d19840543_small_positional\|'"$#\|$1\|$2"` | 1 |
| `echo 'check_ac8398c3296fe506d157e438c0ec115e_small_done'` | 1 |
| `sh -c 'f_check_b487210ca6a48f41215fe3bc611c401f() { printf '"'"'\n%s\|%s\n'"'"' '"'"'check_b487210ca6a48f41215fe3bc611c401f_small_function'"'"' "$1\|$#"; }; f_check_b487210ca6a48f41215fe3bc611c401f '"'"'check_b487210ca6a48f41215fe3bc611c401f_function_value'"'"''` | 1 |
| `sh -c 'printf '"'"'\n%s\|%s\n'"'"' '"'"'check_8f78404d32f7ace65228f77e2d62c4e5_small_control'"'"' '"'"'check_8f78404d32f7ace65228f77e2d62c4e5'"'"''` | 1 |
| `echo 'check_837021b2a41729ab6123e4ce42808cb4_small_pid\|'"$$"` | 1 |
| `echo 'check_ec07f3f78db0920e276b0a37a21742aa_small_done'` | 1 |


### Commands the shell does not implement

Automated traffic repeats itself, so an unrecognised command usually
means a person or a toolkit not seen here before. Worth implementing the
common ones: a shell that answers more convincingly keeps attackers
longer.

| command | times |
|---|---:|
| `set` | 788 |
| `/bin/./uname` | 19 |
| `f_check_3f9b8337e29fb2b457655aa10a8a0329()` | 1 |
| `f_check_1b9ea1d73e604ddd081d3211ee31f95b()` | 1 |
| `f_check_db69bcc0115b5e25984a3a497e797b58()` | 1 |
| `f_check_bea508f081896aca514c50c8a5aab026()` | 1 |
| `f_check_ad7d9cc81dadc68c8d2453c2b1e2181b()` | 1 |
| `f_check_54c3cbb25d24298620d314100e7b1636()` | 1 |
| `f_check_245145090ae3976da965a36c2fa427fd()` | 1 |
| `f_check_1431298bd173c7e497ea43f90d3ba4e2()` | 1 |
| `f_check_5cc0e49f11f3932fb3b2dc6139dd462a()` | 1 |
| `f_check_1cf8170f54ff124089cfa031def55edd()` | 1 |
| `f_check_bb1b0bd3ee35f6bedfd2eeca89891bc1()` | 1 |
| `f_check_ea6103e6820057612ca62e60666ce5d1()` | 1 |
| `f_check_970b6450309a27e6e533158cd4670a20()` | 1 |


## MITRE ATT&CK

| technique | events |
|---|---:|
| `T1110 / Brute Force` | 79,867 |
| `T1059.004 / Command and Scripting Interpreter: Unix Shell` | 4,900 |
| `T1552.001 / Credentials In Files` | 2,052 |
| `T1082 / System Information Discovery` | 885 |
| `T1021.004 / Remote Services: SSH` | 575 |
| `T1105 / Ingress Tool Transfer` | 162 |
| `T1087.001 / Account Discovery: Local Account` | 14 |
| `T1003.008 / OS Credential Dumping: /etc/passwd and /etc/shadow` | 3 |
| `T1552.004 / Private Keys` | 2 |


## Where from

| country | events |
|---|---:|
| `The Netherlands` | 77,241 |
| `France` | 61,336 |
| `Andorra` | 12,798 |
| `Brazil` | 9,133 |
| `United States` | 6,941 |
| `Germany` | 4,567 |
| `China` | 3,968 |
| `United Kingdom` | 3,451 |
| `Vietnam` | 2,498 |
| `Belgium` | 1,141 |
| `South Korea` | 1,111 |
| `Iran` | 1,084 |
| `Switzerland` | 1,020 |
| `Turkey` | 735 |
| `Hong Kong` | 636 |


## Sessions

| classification | sessions |
|---|---:|
| `unknown` | 39,323 |
| `bot` | 4 |


Classification is by rhythm, not content: a script pastes commands at
machine speed with almost no variation, a person pauses to read, mistypes
and uses the line editor. `unknown` means the session was too short to
carry evidence either way, which is most of them.

## Decoy files taken

Whoever took these credentials will use them somewhere, and that use is
visible from elsewhere. Every value in them is fabricated.

| decoy | hits |
|---|---:|
| `login-form` | 1,299 |
| `env` | 175 |
| `git-config` | 46 |
| `config-php` | 10 |
| `aws-credentials` | 8 |
| `docker-compose` | 5 |
| `backup-sql` | 4 |
| `server-status` | 1 |


## Samples captured

_No new samples this week._

## Refused by the honeypot's own limits

### Download attempts to blocked ranges

An attacker aiming the honeypot at a private range or at the cloud
metadata service. The address is checked after resolution and before
every connect, so none of these reached anything.

_Nothing recorded this week._


### SSH channel requests refused

Port forwarding and subsystem requests. Someone wanted a proxy or a file
transfer, not a shell.

| request type | attempts |
|---|---:|
| `direct-tcpip` | 572 |
| `subsystem` | 3 |


---

Generated by `tools/weekly_report.py`. Every figure comes from events this
sensor recorded itself.
