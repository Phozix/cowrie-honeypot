# Hardened Cowrie SSH Honeypot

A medium-interaction SSH honeypot built with [Cowrie](https://github.com/cowrie/cowrie) and Docker Compose, running on a hardened Ubuntu Server 26.04 LTS virtual machine.

The goal of this project is to **observe real attacker behaviour** (credentials tried, commands typed, malware downloaded) while applying **defence-in-depth** so that the honeypot itself cannot become a foothold.

> Status: lab phase complete (local VM). Next step: deployment to a cloud VM and a Python analysis tool.

---

## Architecture

```
MacBook (admin)
 └── SSH, key only ──► Ubuntu Server 26.04 VM (VMware Fusion, NAT)
                        ├── ufw firewall        (deny incoming by default)
                        ├── sshd :22            (real admin access, key only, no root)
                        └── Docker
                             └── cowrie container :2222   (the trap - fake hostname "web-prod-01")
                                  └── volumes: cowrie-var (logs, sessions), cowrie-etc (config)
```

Attackers who connect to port 2222 land in a **fake shell** that imitates a Debian server. Every login attempt and keystroke is recorded as structured JSON.

---

## Security layers

| Layer | Measure | Why |
|---|---|---|
| Isolation | Dedicated VM | A full escape still lands in a disposable machine, not the host |
| Container | `read_only: true` + `tmpfs /tmp` | Root filesystem is immutable; only the volumes are writable |
| Container | `cap_drop: ALL` | Removes every Linux capability (least privilege) |
| Container | `no-new-privileges` | Blocks privilege escalation through setuid binaries |
| Container | `mem_limit: 512m`, `pids_limit: 100` | Prevents resource exhaustion and fork bombs |
| Deception | Custom hostname `web-prod-01` | Removes Cowrie's well-known default `svr04` fingerprint |
| Host SSH | Key-based auth only, root login disabled | Brute force against the real SSH becomes useless |
| Host SSH | Config in `sshd_config.d/00-hardening.conf` | sshd keeps the **first** value it reads, so `00-` overrides later files such as `50-cloud-init.conf` |
| Host firewall | ufw: deny incoming, SSH allowed from admin network only | Minimal attack surface |

### Lesson learned: Docker bypasses ufw

Docker writes its own iptables rules for published ports, **before** ufw's rules. I verified it: after deleting the ufw rule for port 2222, a connection from the Mac (`nc -zv <vm-ip> 2222`) still **succeeded**.

For the honeypot this is fine (the port is meant to be public), but for any service that must stay private, ufw is not enough. Options:
- publish the port on localhost only: `"127.0.0.1:8080:8080"`
- filter in the `DOCKER-USER` iptables chain

---

## Repository content

| File | Purpose |
|---|---|
| `docker-compose.yml` | Hardened Cowrie service |
| `host-hardening/00-hardening.conf` | sshd drop-in config (key-only, no root) |
| `host-hardening/ufw-rules.sh` | Host firewall rules |
| `queries.md` | `jq` queries to analyse `cowrie.json` |

---

## Quick start

```bash
# On an Ubuntu server with Docker and the compose plugin
sudo apt install -y docker.io docker-compose-v2 jq
git clone <this-repo> && cd cowrie-honeypot
sudo docker compose up -d
sudo docker compose ps              # cowrie should be "Up"

# Verify the hardening
sudo docker inspect cowrie --format 'ReadOnly={{.HostConfig.ReadonlyRootfs}} CapDrop={{.HostConfig.CapDrop}}'
# -> ReadOnly=true CapDrop=[ALL]

# Play the attacker
ssh -p 2222 root@127.0.0.1
```

Logs are stored in the `cowrie-var` volume:

```bash
sudo tail -n 3 /var/lib/docker/volumes/cowrie_cowrie-var/_data/log/cowrie/cowrie.json | jq
```

See [`queries.md`](queries.md) for more analysis queries.

---

## What I learned

- Building and administering a Linux server over SSH (Ubuntu Server, LVM resize, systemd)
- Docker and Docker Compose, named volumes, data persistence
- Container hardening and the principle of least privilege
- SSH key-based authentication and sshd configuration precedence
- Host firewalling with ufw, and its interaction with Docker's iptables rules
- Reading and filtering structured JSON logs with `jq`
- Honeypot fingerprinting: default hostnames, `Exec format error` on unknown commands, OS banner mismatches

---

## Roadmap

- [x] Local lab: VM, Docker, Cowrie, persistent JSON logs
- [x] Container hardening
- [x] Host hardening (SSH keys, ufw)
- [ ] Python analysis tool (top credentials, source countries, commands, downloads) with charts
- [ ] Cloud deployment (Azure for Students) with Cowrie on port 22 and admin SSH on another port
- [ ] Infrastructure as Code with Terraform
- [ ] Alerting with Wazuh

---

## Disclaimer

This honeypot is for educational and research purposes. Collected data (IPs, credentials, files) may contain sensitive or malicious content and is **never committed** to this repository (see `.gitignore`).
