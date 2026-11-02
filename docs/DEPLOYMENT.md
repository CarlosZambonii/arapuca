# Deployment

The sensor runs on a single Oracle Cloud Always Free instance. Everything below
was exercised on a real tenancy, and the failure modes documented here were all
hit for real while bringing the first sensor up.

## Instance

| Property | Value |
|----------|-------|
| Shape | `VM.Standard.E2.1.Micro` (Always Free) |
| Resources | 1 OCPU, 1 GB RAM, 50 GB boot volume |
| Image | Canonical Ubuntu 24.04 LTS, x86_64 |
| Region | the tenancy home region (Always Free resources exist only there) |
| Public address | a reserved public IP, so the sensor keeps its address across rebuilds |

The Ampere A1 shape (up to 4 OCPU and 24 GB) is the better machine and the code
runs on arm64 as well, but A1 capacity is frequently exhausted in some regions
and a launch fails with `Out of host capacity`. The micro shape is what is
reliably obtainable, so it is what the deployment targets. 1 GB of RAM is tight
once Docker and the New Relic agent are resident, which is why cloud-init
creates a 2 GB swap file.

## Network

The VCN carries one public subnet and a single security list. Ports are opened
in the order the honeypot can safely accept them:

| Port | When it opens | Why |
|------|---------------|-----|
| operator SSH (high, non standard) | at provisioning | the only management path |
| 22 | only once the honeypot container is running | this is the trap, never the real sshd |
| 80 | only once the honeypot container is running | the fake admin panel |

Safety invariant S6: the real sshd is moved off port 22 before port 22 is ever
reachable. The security list does not open 22 at provisioning time at all, so
there is no window in which a real sshd is exposed there.

## cloud-init

`deploy/cloud-init/bootstrap.yaml.tmpl` carries the real port as
`__REAL_SSH_PORT__` and is rendered at apply time. The literal port is not
committed, because this repository is public.

The template only writes configuration and then reboots. That shape is not a
stylistic choice, it is the result of three failed provisioning attempts:

1. **A synchronous `systemctl restart ssh.socket` from inside cloud-init
   deadlocks the boot.** `ssh.socket` is ordered after `cloud-init.service`, so
   systemd waits for cloud-init to finish before touching the socket, while
   cloud-init waits for the restart to return. The boot stops dead. The
   instance still answers TCP, because the kernel and the network came up
   first, but there is no sshd, no snapd and therefore no Oracle Cloud Agent,
   which leaves it completely unmanageable.
2. **`--no-block` avoids the hang but not the problem.** The boot completed in
   119 seconds, cleanly, and the port still did not move. A plain reboot of
   that instance did not fix it either, which ruled out the configuration files
   themselves.
3. **Writing configuration and rebooting works.** No service is restarted
   underneath a running cloud-init, socket activation is disabled in favour of
   the plain `ssh.service`, and the second boot starts sshd from the final
   configuration with no ordering question to get wrong.

The template also pre-answers the debconf questions for `iptables-persistent`.
Without that the package install blocks forever on a non interactive boot,
holding the dpkg lock, which in turn blocks snapd and the Oracle Cloud Agent.

## Diagnosing an instance you cannot reach

When the management port is the thing that is broken, the usual tools are gone.
Two channels still work and neither needs an open port:

**Serial console history.** Read only, and it shows the whole boot including
every line cloud-init printed:

```bash
oci compute console-history capture --instance-id "$INSTANCE"
oci compute console-history get-content \
    --instance-console-history-id "$HISTORY" --length 400000 --file console.txt
```

This is what identified the systemd deadlock: the log simply stops at
`systemctl restart ssh.socket` and nothing follows it.

**Oracle Cloud Agent run command.** Executes a script inside the instance with
no network path from the operator:

```bash
oci instance-agent command create --compartment-id "$COMPARTMENT" \
    --timeout-in-seconds 120 --target "{\"instanceId\":\"$INSTANCE\"}" \
    --content file://command.json --display-name diag
```

It only works when the instance is healthy enough to run the agent, so it is
the second thing to try, not the first. A command that stays in `ACCEPTED` with
delivery `VISIBLE` for several minutes is itself a strong signal that the
instance is wedged.

Every boot also writes the listening sockets to the serial console through
`arapuca-console-report.service`, so the console history answers the question
"where is sshd listening" without any access at all.

## Telling a closed port from a blocked one

Three outcomes, three different causes, and confusing them wastes hours:

| Result | Meaning |
|--------|---------|
| Connection timed out | the OCI security list is dropping the packet |
| No route to host | the packet reached the host and a local `iptables REJECT` refused it |
| Connection refused | the packet reached a listening stack and nothing was bound to that port |

Comparing a port that is open in the security list against one that is not
isolates the layer immediately.

## Remaining hardening, handled by Ansible in phase 7

* Remove `rpcbind`, which the stock image leaves listening on port 111.
* fail2ban on the operator SSH port.
* Unattended upgrades, already enabled by cloud-init.
* Docker, the New Relic Infrastructure Agent, and the compose stack.
