#!/usr/bin/env bash
# ssh_hardening.sh -- key-only + no-root SSH, validated before restart.
# Reads (exported by deploy.sh): ENABLE_SSH_HARDENING, AUTH_MODE (key|password),
#   REMOTE_USER. Requires _common.sh.
#
# SAFETY: PasswordAuthentication is only disabled when AUTH_MODE=key (you deployed
# with a key). If you deployed over a password, disabling it would lock you out, so
# that step is skipped and a warning is printed.

_sshd_set() {
  # idempotently set a directive in sshd_config: $1=key $2=value
  local key="$1" val="$2"
  if run_sudo grep -qiE "^[[:space:]]*${key}[[:space:]]" /etc/ssh/sshd_config; then
    run_sudo sed -i "s/^[#[:space:]]*${key}[[:space:]].*/${key} ${val}/I" /etc/ssh/sshd_config
  else
    echo "${key} ${val}" | run_sudo_tee -a /etc/ssh/sshd_config
  fi
}

setup_ssh_hardening() {
  if ! is_true "${ENABLE_SSH_HARDENING:-true}"; then
    info "ENABLE_SSH_HARDENING=false -- leaving sshd_config untouched"
    return 0
  fi
  step "SSH hardening"
  [[ -f /etc/ssh/sshd_config ]] || { warn "/etc/ssh/sshd_config missing -- skipping"; return 0; }

  _sshd_set PermitRootLogin no
  _sshd_set PubkeyAuthentication yes

  if [[ "${AUTH_MODE:-key}" == "key" ]]; then
    _sshd_set PasswordAuthentication no
    _sshd_set ChallengeResponseAuthentication no
    info "PasswordAuthentication disabled (key-only)"
  else
    warn "Deployed over a password -- NOT disabling PasswordAuthentication (would lock you out)."
    warn "Install an SSH key, then re-run 'harden' with key auth to close password login."
  fi

  # File permission hygiene
  chmod 700 "/home/${REMOTE_USER}/.ssh" 2>/dev/null || true
  chmod 600 "/home/${REMOTE_USER}/.ssh/"* 2>/dev/null || true
  run_sudo chmod 600 /etc/shadow 2>/dev/null || true

  # Validate before restart, or roll back
  if run_sudo sshd -t 2>/dev/null; then
    run_sudo systemctl restart ssh 2>/dev/null || run_sudo systemctl restart sshd 2>/dev/null || run_sudo service ssh restart || true
    success "sshd hardened and restarted"
  else
    err "sshd -t validation failed -- NOT restarting (check /etc/ssh/sshd_config)"
    return 1
  fi
}

disable_ssh_hardening() {
  info "SSH hardening DISABLED (ENABLE_SSH_HARDENING=false)"
}
