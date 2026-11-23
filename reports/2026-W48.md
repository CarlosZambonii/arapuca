# Arapuca weekly report, 2026-W48

_Generated 2026-11-23 18:41 UTC from the sensor's own telemetry._

## Summary

- **168,750 events** from **2,322 distinct addresses** across **56,134 sessions** (down 10% on the week before).
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
| `(empty)` | 32,372 |
| `123456` | 1,816 |
| `123` | 893 |
| `1234` | 750 |
| `12345678` | 487 |
| `password` | 466 |
| `root` | 435 |
| `1` | 409 |
| `12345` | 369 |
| `admin` | 327 |
| `123456789` | 305 |
| `P@ssw0rd` | 195 |
| `admin123` | 188 |
| `test` | 181 |
| `123123` | 179 |


### Usernames

| username | attempts |
|---|---:|
| `root` | 24,654 |
| `ubuntu` | 2,973 |
| `admin` | 2,959 |
| `user` | 1,259 |
| `deploy` | 971 |
| `test` | 891 |
| `support` | 527 |
| `user1` | 490 |
| `Tronlong` | 490 |
| `debian` | 442 |
| `developer` | 426 |
| `claude` | 394 |
| `dev` | 377 |
| `postgres` | 348 |
| `guest` | 330 |


### Credentials that worked

Pairs that matched the weak credential list, meaning the session reached
the fake shell. These are the sessions worth reading.

| username / password | sessions |
|---|---:|
| `support / support` | 170 |
| `admin / admin` | 110 |
| `root / 1234` | 101 |
| `test / test` | 99 |
| `root / admin` | 90 |
| `root / 123456789` | 87 |
| `root / 123456` | 71 |
| `root / root` | 67 |
| `root / 12345` | 59 |
| `admin / 123456` | 51 |


## What they did once inside

| command | times |
|---|---:|
| `uname -s -v -n -r -m` | 541 |
| `echo SHELL_TEST` | 28 |
| `uname -s -m` | 8 |
| `/bin/./uname -s -v -n -r -m` | 6 |
| `uname -a` | 6 |
| `sh -s` | 5 |
| `cat /etc/issue` | 5 |
| `echo 'check_dfed70dad965b543028794de3bdbc24e_small_done'` | 1 |
| `echo; echo 'check_338904642976fb639e000c0a91212c2e_transport_done'` | 1 |
| `echo 'check_dfed70dad965b543028794de3bdbc24e_small_math\|'"$((497*152+96))"` | 1 |
| `sh -c 'printf '"'"'\n%s\|%s\n'"'"' '"'"'check_49f1fb7301f3d65c65007744618d269d_small_control'"'"' '"'"'check_49f1fb7301f3d65c65007744618d269d'"'"''` | 1 |
| `sh -c 'f_check_395a907f592d89544c49bc1e645427f6() { printf '"'"'\n%s\|%s\n'"'"' '"'"'check_395a907f592d89544c49bc1e645427f6_small_function'"'"' "$1\|$#"; }; f_check_395a907f592d89544c49bc1e645427f6 '"'"'check_395a907f592d89544c49bc1e645427f6_function_value'"'"''` | 1 |
| `set -- 'check_f1d56a6cfaf8615606b0117558d3692a_arg1' 'check_f1d56a6cfaf8615606b0117558d3692a_arg2'; echo 'check_f1d56a6cfaf8615606b0117558d3692a_small_positional\|'"$#\|$1\|$2"` | 1 |
| `echo 'check_210282634df25fc56a0e3b74cb9e2868_small_pid\|'"$$"` | 1 |
| `echo 'check_fb03cb0fef7b97daea4f2a31b9cf75bb_small_math\|'"$((452*452+46))"` | 1 |
| `echo 'check_bafc96c613d9b9771b2b4af15f8ba993_small_math\|'"$((13*941+48))"` | 1 |
| `echo 'check_5422aedfc8de5d23cd353c13861fa22a_small_pid\|'"$$"` | 1 |
| `echo; echo 'check_98190a73ddf386944848ee75908688f4_transport_done'` | 1 |
| `set -- 'check_4dfd32cdcfdebb2b61babca21caa94e1_arg1' 'check_4dfd32cdcfdebb2b61babca21caa94e1_arg2'; echo 'check_4dfd32cdcfdebb2b61babca21caa94e1_small_positional\|'"$#\|$1\|$2"` | 1 |
| `echo 'check_e7a5671531ab2083094089f99ccfd72c_small_control\|check_e7a5671531ab2083094089f99ccfd72c'` | 1 |


### Commands the shell does not implement

Automated traffic repeats itself, so an unrecognised command usually
means a person or a toolkit not seen here before. Worth implementing the
common ones: a shell that answers more convincingly keeps attackers
longer.

| command | times |
|---|---:|
| `set` | 584 |
| `/bin/./uname` | 6 |
| `f_check_76fd6a97dc7b857e7b434ebd7737f409()` | 1 |
| `f_check_80cea964a1183be91188790b9f162a63()` | 1 |
| `f_check_84924e8b2e7aee8dabce05eaac989289()` | 1 |
| `f_check_193981dce337247da6dcd7804432c869()` | 1 |
| `f_check_9a97e505578d473bda785885f186b87f()` | 1 |
| `f_check_76bb86de8061206a4b9c03797d98e49d()` | 1 |
| `f_check_9fd16e112086adea46b390657f14a2f1()` | 1 |
| `f_check_a27a5e8e99b1f9ceadb315014891f1d7()` | 1 |
| `f_check_9601a041b0847f60ccde4ff71b300a70()` | 1 |
| `f_check_73cb6058795e45662c4414bd952bd986()` | 1 |
| `f_check_229497dbe122595463d844d76f0e56c6()` | 1 |
| `f_check_a2148b291f032bfe07f2d588fa8cf6f6()` | 1 |
| `f_check_cbd55c56c0270c3ca875cb2afeeb72a2()` | 1 |


## MITRE ATT&CK

| technique | events |
|---|---:|
| `T1110 / Brute Force` | 67,266 |
| `T1552.001 / Credentials In Files` | 5,211 |
| `T1059.004 / Command and Scripting Interpreter: Unix Shell` | 3,504 |
| `T1082 / System Information Discovery` | 850 |
| `T1021.004 / Remote Services: SSH` | 757 |
| `T1105 / Ingress Tool Transfer` | 128 |
| `T1087.001 / Account Discovery: Local Account` | 8 |
| `T1003.008 / OS Credential Dumping: /etc/passwd and /etc/shadow` | 5 |
| `T1046 / Network Service Discovery` | 1 |


## Where from

| country | events |
|---|---:|
| `The Netherlands` | 84,081 |
| `France` | 45,584 |
| `Andorra` | 8,988 |
| `United States` | 5,276 |
| `Brazil` | 3,655 |
| `United Kingdom` | 3,029 |
| `China` | 3,005 |
| `Germany` | 2,887 |
| `South Korea` | 2,359 |
| `Slovenia` | 2,154 |
| `Vietnam` | 932 |
| `Turkey` | 746 |
| `India` | 617 |
| `Singapore` | 490 |
| `Hungary` | 479 |


## Sessions

| classification | sessions |
|---|---:|
| `unknown` | 33,675 |


Classification is by rhythm, not content: a script pastes commands at
machine speed with almost no variation, a person pauses to read, mistypes
and uses the line editor. `unknown` means the session was too short to
carry evidence either way, which is most of them.

## Decoy files taken

Whoever took these credentials will use them somewhere, and that use is
visible from elsewhere. Every value in them is fabricated.

| decoy | hits |
|---|---:|
| `login-form` | 2,767 |
| `git-config` | 451 |
| `env` | 243 |
| `config-php` | 33 |
| `backup-sql` | 30 |
| `aws-credentials` | 30 |
| `docker-compose` | 10 |
| `server-status` | 5 |
| `README` | 1 |


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
| `direct-tcpip` | 750 |
| `subsystem` | 7 |


---

Generated by `tools/weekly_report.py`. Every figure comes from events this
sensor recorded itself.
