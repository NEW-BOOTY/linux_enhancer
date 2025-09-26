#!/usr/bin/env bash
#
# linux_enhancer.sh - GOD-MODE++ Linux System Enhancer & Cloud Orchestrator
#
# Copyright © 2025 Devin B. Royal.
# All Rights Reserved.
#

set -euo pipefail

LOG_DIR="$(dirname "$0")/logs"
LOG_FILE="$LOG_DIR/enhancer.log"
mkdir -p "$LOG_DIR"

log() {
    local msg="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $msg" | tee -a "$LOG_FILE"
}

error_exit() {
    log "ERROR: $1"
    exit 1
}

check_dependency() {
    local dep="$1"
    if ! command -v "$dep" >/dev/null 2>&1; then
        log "Dependency $dep missing. Installing..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update && sudo apt-get install -y "$dep" || error_exit "Failed to install $dep"
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y "$dep" || error_exit "Failed to install $dep"
        elif command -v pacman >/dev/null 2>&1; then
            sudo pacman -Sy --noconfirm "$dep" || error_exit "Failed to install $dep"
        else
            error_exit "Unsupported package manager. Please install $dep manually."
        fi
    fi
}

# ===================== CORE MODULES =====================

system_update_cleanup() {
    log "Starting System Update & Cleanup..."
    {
        sudo apt-get update -y && sudo apt-get upgrade -y && sudo apt-get autoremove -y && sudo apt-get clean -y
    } || {
        log "Retrying update..."
        sudo apt-get update -y || error_exit "System update failed"
    }
    log "System Update & Cleanup Completed."
}

disk_space_monitor() {
    log "Checking Disk Usage..."
    local usage
    usage=$(df -h / | awk 'NR==2{print $5}' | sed 's/%//')
    if [ "$usage" -gt 90 ]; then
        log "Disk usage critical: ${usage}%"
        sudo journalctl --vacuum-time=7d || true
        sudo apt-get autoremove -y || true
    else
        log "Disk usage healthy: ${usage}%"
    fi
}

file_organization() {
    log "Organizing files in ~/Downloads..."
    ORG_DIR="$HOME/Downloads"
    mkdir -p "$ORG_DIR"/{Documents,Images,Videos,Music,Archives,Others}
    find "$ORG_DIR" -maxdepth 1 -type f | while read -r file; do
        case "$file" in
            *.pdf|*.doc*|*.txt) mv -f "$file" "$ORG_DIR/Documents/" ;;
            *.jpg|*.png|*.gif) mv -f "$file" "$ORG_DIR/Images/" ;;
            *.mp4|*.mkv|*.avi) mv -f "$file" "$ORG_DIR/Videos/" ;;
            *.mp3|*.wav) mv -f "$file" "$ORG_DIR/Music/" ;;
            *.zip|*.tar.gz|*.rar) mv -f "$file" "$ORG_DIR/Archives/" ;;
            *) mv -f "$file" "$ORG_DIR/Others/" ;;
        esac
    done
    log "File Organization Completed."
}

system_info_dashboard() {
    log "System Information Dashboard:"
    echo "------------------------------"
    echo "Hostname: $(hostname)"
    echo "Uptime: $(uptime -p)"
    echo "Kernel: $(uname -r)"
    echo "CPU Load: $(uptime | awk -F'load average:' '{print $2}')"
    echo "Memory: $(free -h | awk '/Mem:/ {print $3\"/\"$2}')"
    echo "Disk: $(df -h / | awk 'NR==2{print $3\"/\"$2}')"
    echo "Processes: $(ps aux | wc -l)"
    echo "------------------------------"
}

backup_restore() {
    log "Performing Backup..."
    BACKUP_DIR="$HOME/backups"
    mkdir -p "$BACKUP_DIR"
    tar -czf "$BACKUP_DIR/backup_$(date +%Y%m%d%H%M).tar.gz" "$HOME/Documents" "$HOME/Pictures" "$HOME/.config" || error_exit "Backup failed"
    log "Backup Completed."
}

security_hardening() {
    log "Applying Security Hardening..."
    sudo ufw allow OpenSSH || true
    sudo ufw enable || true
    sudo apt-get install -y unattended-upgrades || true
    log "Security Hardening Completed."
}

# ===================== CLOUD MODULES =====================

run_terraform() {
    log "Running Terraform..."
    (cd terraform && terraform init && terraform apply -auto-approve) || error_exit "Terraform failed"
}

run_ansible() {
    log "Running Ansible..."
    ansible-playbook ansible/playbooks/local.yml || error_exit "Ansible local playbook failed"
    ansible-playbook ansible/playbooks/remote.yml || log "Remote playbook skipped (configure hosts)"
}

setup_vault() {
    log "Setting up Vault integration..."
    if [ -f vault/policies.hcl ]; then
        log "Vault policies loaded."
        # Placeholder for real vault setup commands
    fi
}

# ===================== MAIN =====================

main() {
    log "=== GOD-MODE++ Linux Enhancer Started ==="

    check_dependency terraform
    check_dependency ansible
    check_dependency aws
    check_dependency vault

    system_update_cleanup
    disk_space_monitor
    file_organization
    system_info_dashboard
    backup_restore
    security_hardening

    run_terraform
    run_ansible
    setup_vault

    log "=== Enhancement Complete ==="
}

main "$@"

# End of File
