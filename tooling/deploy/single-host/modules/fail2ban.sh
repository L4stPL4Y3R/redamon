#!/usr/bin/env bash
# fail2ban.sh -- sshd + nginx jails (§10). Repointed from the example: the Django
# [django-auth] jail is dropped (no such log here). Reads ENABLE_FAIL2BAN. Requires
# _common.sh.

setup_fail2ban() {
  if ! is_true "${ENABLE_FAIL2BAN:-true}"; then
    disable_fail2ban
    return 0
  fi
  step "fail2ban (sshd + nginx jails)"
  install_if_missing fail2ban
  run_sudo mkdir -p /etc/fail2ban/jail.d

  # NOTE: backend is set PER JAIL, not in [DEFAULT]. A global `backend = systemd` makes
  # the nginx jails read the journal and IGNORE their file `logpath`, so they never fire.
  # sshd uses systemd (journald auth), nginx jails use auto (file/inotify).
  cat <<F2B | run_sudo_tee /etc/fail2ban/jail.d/redamon.conf
# RedAmon fail2ban jails: SSH brute-force + nginx auth/badbots/rate-limit.

[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

[sshd]
enabled  = true
port     = ${SSH_PORT:-22}
filter   = sshd
backend  = systemd
maxretry = 3
bantime  = 7200
findtime = 600

[nginx-http-auth]
enabled  = true
port     = http,https
filter   = nginx-http-auth
logpath  = /var/log/nginx/error.log
maxretry = 5
bantime  = 3600

[nginx-badbots]
enabled  = true
port     = http,https
filter   = nginx-badbots
logpath  = /var/log/nginx/access.log
maxretry = 2
bantime  = 86400

[nginx-limit-req]
enabled  = true
port     = http,https
filter   = nginx-limit-req
logpath  = /var/log/nginx/error.log
maxretry = 10
findtime = 60
bantime  = 600
F2B

  run_sudo touch /var/log/auth.log 2>/dev/null || true
  run_sudo systemctl enable fail2ban >/dev/null 2>&1 || true
  run_sudo systemctl restart fail2ban || true
  sleep 2
  if run_sudo systemctl is-active --quiet fail2ban; then
    success "fail2ban active"
    run_sudo fail2ban-client status 2>/dev/null | grep -i "jail list" || true
  else
    warn "fail2ban failed to start"
    run_sudo journalctl -u fail2ban -n 20 --no-pager 2>/dev/null || true
  fi
}

disable_fail2ban() {
  info "fail2ban DISABLED (ENABLE_FAIL2BAN=false)"
  if systemctl list-unit-files 2>/dev/null | grep -q '^fail2ban.service'; then
    run_sudo systemctl stop fail2ban 2>/dev/null || true
    run_sudo systemctl disable fail2ban 2>/dev/null || true
  fi
}
