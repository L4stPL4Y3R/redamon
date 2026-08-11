# Troubleshooting

> **Full troubleshooting guide**: [Wiki — Troubleshooting](https://github.com/samugit83/redamon/wiki/Troubleshooting)

## Operating System Compatibility

RedAmon is fully Dockerized and runs on **any OS** that supports Docker and Docker Compose v2+. Below are common OS-specific issues and their fixes.

### Linux

| Problem | Cause | Fix |
|---------|-------|-----|
| Docker socket permission denied | User not in `docker` group | `sudo usermod -aG docker $USER` then log out and back in |
| `docker compose` not found | Old Docker version uses `docker-compose` (hyphen) | Install [Docker Compose V2 plugin](https://docs.docker.com/compose/install/) or use `docker-compose` |
| Port already in use (3000, 8010, etc.) | Another service occupies the port | Change ports in `.env` or stop the conflicting service |
| Containers killed (OOM) | Insufficient RAM | Increase swap or free memory — see [minimum requirements](../../README.md#prerequisites) |
| Volume mount denied (SELinux) | Fedora / RHEL / CentOS enforce SELinux | Add `:z` suffix to volume mounts in `docker-compose.yml`, or run `sudo setsebool -P container_manage_cgroup on` |
| Firewall blocks container traffic | `firewalld` or `ufw` blocking Docker bridge | `sudo ufw allow in on docker0` or allow the Docker subnet in firewalld |
| DNS fails inside containers | `systemd-resolved` conflicts (Ubuntu 22.04+) | Add `{"dns": ["8.8.8.8", "8.8.4.4"]}` to `/etc/docker/daemon.json` and restart Docker |
| `/var/run/docker.sock` not found | Docker not running or rootless Docker uses a different path | `sudo systemctl start docker` or set `DOCKER_HOST` to the correct socket path |

### Windows

| Problem | Cause | Fix |
|---------|-------|-----|
| Docker socket unavailable | Windows uses named pipes, not Unix sockets | Use [Docker Desktop](https://www.docker.com/products/docker-desktop/) with **WSL2 backend** enabled |
| Line ending errors (`\r\n`) | Git auto-converts LF → CRLF on Windows | `git config --global core.autocrlf input` then re-clone the repo |
| Path too long errors | Windows 260-character path limit | `git config --global core.longpaths true` |
| Volume mount fails | Windows path format incompatible with Linux containers | Run from inside WSL2 filesystem (`~/redamon`), **not** from `/mnt/c/` |
| Extremely slow performance | Bind mounts across Windows ↔ WSL boundary | Store the project inside WSL2 home (`~/`), not on a Windows-mounted drive |
| Docker Desktop won't start | WSL2 or Hyper-V not enabled | Run `wsl --install` in PowerShell (admin), reboot, then install Docker Desktop |
| Socket permission error in WSL2 | Docker Desktop integration not enabled for your WSL distro | Docker Desktop → Settings → Resources → WSL Integration → enable your distro |

### macOS

| Problem | Cause | Fix |
|---------|-------|-----|
| Slow bind-mount performance | macOS filesystem sharing overhead | Upgrade to Docker Desktop 4.x+ and enable **VirtioFS** in Settings → General |
| Port 5000 conflict | macOS AirPlay Receiver uses port 5000 | Disable AirPlay Receiver in System Settings → General → AirDrop & Handoff, or remap the port in `.env` |
| `docker compose` not found | Docker CLI plugins not in PATH | Run `brew install docker-compose` or reinstall Docker Desktop |
| Containers OOM-killed during install | Docker Desktop default Memory below RedAmon minimum | Docker Desktop → Settings → Resources → Memory: set to 4 GB (8 GB with `--gvm`), then `./redamon.sh install` |
| `Cannot connect to the Docker daemon` | Docker Desktop not started | `open /Applications/Docker.app` and wait until the whale icon stops animating before running `./redamon.sh` |
| `Mounts denied` / `path not shared` | Repo cloned outside Docker Desktop's File Sharing allowlist | Clone the repo under `~/` (default-allowed), or add the custom path in Settings → Resources → File Sharing |
| SYN scans (naabu, masscan) miss hosts on the local LAN | `network_mode: host` joins Docker Desktop's LinuxKit VM, not the Mac's network | Expected on Docker Desktop. Internet targets work normally; for LAN scans, run RedAmon on a Linux host |
| Login fails after install with no error in logs | Non-interactive shell (CI, agents, some multiplexers) injected a `\u0001` SOH byte into the admin email/password prompt | Run `./redamon.sh create-admin` to (re)create the admin cleanly (`reset-password` only works once an admin already exists) |
| No admin prompt appeared at install / can't log in | Webapp was slow to come up on first boot (common with `--gvm` or a small VM), so the automatic admin prompt was skipped | Run `./redamon.sh create-admin` once the stack is up (`./redamon.sh status`); it waits for the webapp, then prompts. Safe to re-run |

---

## The graph page hangs, 502s, or Neo4j logs "network aborts"

These three symptoms usually appear together on a project with a very large
graph. They have distinct causes, so check them in this order.

| Symptom | Cause | Fix |
|---------|-------|-----|
| Neo4j logs `Increase in network aborts detected`, connection count climbs steadily | **Fixed in this release.** The webapp used to create a new Neo4j driver (and a new pool of up to 50 Bolt connections) on *every* production request, abandoning the previous one | Update. Confirm with `CALL dbms.listConnections()` — the count must stay flat while you reload the graph page, not climb |
| API requests sit in `[pending]` forever, no error, no timeout | **Fixed in this release.** The driver's connection timeouts only bound *acquiring* a connection, so an unbounded whole-graph query ran forever | Update. Tune with `NEO4J_QUERY_TIMEOUT_MS` (default 120000) if you legitimately run long analytical queries |
| HTTP 502 from nginx, `recv() failed (104: Connection reset by peer)` in its error log | The webapp container was OOM-killed mid-response. A reset with no timeout means the process died, rather than the request being slow | Check `./redamon.sh status` for OOM-killed containers and restart counts. Memory limits are sized from host RAM automatically; see [README.MEMORY_GOVERNOR.md](README.MEMORY_GOVERNOR.md) |
| Containers OOM-killed generally | Host genuinely too small, or limits pinned by hand in `.env` | `./redamon.sh status` shows the computed allocation and warns when a running container has drifted from it |

Useful checks:

```bash
./redamon.sh status                                    # OOM kills, restarts, allocation, disk
docker logs redamon-neo4j --tail 50 | grep -i abort    # Bolt connection aborts
docker inspect redamon-webapp --format '{{.RestartCount}} {{.State.OOMKilled}}'
```
