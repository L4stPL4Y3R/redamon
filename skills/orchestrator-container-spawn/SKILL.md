---
name: orchestrator-container-spawn
description: >
  Spawning and hardening scan containers from the recon orchestrator: the
  security flags that look correct and break the container, and the sibling
  bind-mount path handling. cap_drop and no-new-privileges were each reverted
  after breaking real scans.
  Trigger: editing recon_orchestrator/container_manager.py; changing how a scan
  container is spawned or hardened; touching _scanner_hardening, sibling_host_path,
  cap_drop, security_opt, or a bind mount for a spawned container.
license: MIT
metadata:
  author: redamon
  version: "1.0.0"
  scope: [recon_orchestrator]
  auto_invoke:
    - "Spawning or hardening a scan container from the orchestrator"
    - "Editing container_manager.py bind mounts or security options"
---

## When to Use

- Changing how the orchestrator launches or secures a scan container
  ([recon_orchestrator/container_manager.py](../../recon_orchestrator/container_manager.py)).

For the no-`env_file` knob rule, see the recon_orchestrator
[AGENTS.md](../AGENTS.md) CRITICAL RULES (not repeated here).

---

## Critical Rules

- **NEVER add `cap_drop: [ALL]` to a scan container that writes to a host-owned
  source bind mount.** It strips `CAP_DAC_OVERRIDE`, so root-in-container can no
  longer write the host-owned files, and the scan breaks. This was reverted after
  breaking recon/partial spawns; hardening is deliberately deferred with
  `drop_caps=False` at **every** spawn site
  ([container_manager.py:775](../../recon_orchestrator/container_manager.py#L775),
  :1731, :2101). Keep it deferred unless the mount is not host-owned.
- **NEVER add `security_opt: no-new-privileges` to these spawns.** It breaks
  `execve` for non-root users inside the recon image (reverted once already):
  [container_manager.py:877](../../recon_orchestrator/container_manager.py#L877).
- **ALWAYS apply hardening through `_scanner_hardening()`**
  ([container_manager.py:505](../../recon_orchestrator/container_manager.py#L505)),
  not ad-hoc per spawn, so all three spawn sites stay consistent.
- **ALWAYS keep `sibling_host_path()` robust to BOTH POSIX (`/`) and Windows
  (`\`) host paths** ([container_manager.py:53](../../recon_orchestrator/container_manager.py#L53)).
  It derives a sibling source dir's host path for bind mounts; a POSIX-only
  assumption breaks spawns on Windows hosts.

---

## Why these flags break here

Scan containers run as root and **bind-mount host-owned source** (the live
working tree) so a `.py` change is picked up without a rebuild. Standard
container hardening (drop all caps, no-new-privileges) assumes the container owns
its filesystem and runs unprivileged - neither holds here, so the "secure
defaults" a reviewer would add are exactly what broke production twice.

## Commands

```bash
docker compose restart recon-orchestrator     # container_manager.py is volume-mounted
./redamon.sh test unit                        # recon_orchestrator section
```

## Resources

- [recon_orchestrator/container_manager.py](../../recon_orchestrator/container_manager.py) - the three spawn sites and `_scanner_hardening`
- Related: recon_orchestrator [AGENTS.md](../AGENTS.md) CRITICAL RULES (the no-`env_file` knob rule)
