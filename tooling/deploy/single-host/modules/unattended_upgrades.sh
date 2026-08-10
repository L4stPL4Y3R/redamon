#!/usr/bin/env bash
# unattended_upgrades.sh -- enable automatic security patches. Reads
# ENABLE_UNATTENDED_UPGRADES. Requires _common.sh.

setup_unattended_upgrades() {
  if ! is_true "${ENABLE_UNATTENDED_UPGRADES:-true}"; then
    disable_unattended_upgrades
    return 0
  fi
  step "unattended-upgrades"
  install_if_missing unattended-upgrades
  echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";' | run_sudo_tee /etc/apt/apt.conf.d/20auto-upgrades
  run_sudo systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
  success "unattended-upgrades enabled (security patches)"
}

disable_unattended_upgrades() {
  info "unattended-upgrades DISABLED (ENABLE_UNATTENDED_UPGRADES=false)"
  run_sudo systemctl disable --now unattended-upgrades >/dev/null 2>&1 || true
}
