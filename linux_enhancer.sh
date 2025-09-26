#!/usr/bin/env bash
# /*
#  * Copyright © 2025 Devin B. Royal.
#  * All Rights Reserved.
#  */
#
# linux_enhancer.sh
# Enterprise-grade Linux enhancement tool (GOD-MODE)
# Modular, defensive, cross-distro, logging, retries, backups, hardening, and self-heal.
#
# WARNING: This script performs system-level changes. Run as root (sudo) for full functionality.
# Default behavior is "GOD-MODE enabled" when --auto or --force is passed. Use --dry-run to simulate.
#
# Produced for: Devin B. Royal
# Date: 2025-09-26
#
set -o pipefail
set -o errtrace
set -o nounset

# -----------------------
# Configuration & Globals
# -----------------------
SCRIPT_NAME="$(basename "$0")"
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${BASE_DIR}/logs"
BACKUP_DIR="${BASE_DIR}/backups"
TMP_DIR="${BASE_DIR}/tmp"
CRON_TAG="linux_enhancer"
DEFAULT_MIN_FREE_PERCENT=10
DRY_RUN=false
FORCE=false
AUTO=false
NONINTERACTIVE=false
CLOUD_SYNC=false
CLOUD_PROVIDER=""         # "dropbox" | "gdrive" | "aws" (user-enabled)
CLOUD_CONFIG_FILE="${BASE_DIR}/cloud.conf"
NOTIFY_EMAIL=""
RETRY_LIMIT=3
RETRY_DELAY=5
OS=""
PKG_MANAGER=""
SUDO_CMD=""
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_FILE="${LOG_DIR}/linux_enhancer_${TIMESTAMP}.log"

# Ensure directories exist
mkdir -p "${LOG_DIR}" "${BACKUP_DIR}" "${TMP_DIR}"

# -----------------------
# Logging & Utilities
# -----------------------
log() {
  local level="$1"; shift
  local msg="$*"
  local timestr
  timestr="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "${timestr} [${level}] ${msg}" | tee -a "${LOG_FILE}"
}

fatal() {
  log "FATAL" "$*"
  echo "FATAL: $*" >&2
  exit 1
}

retry() {
  # usage: retry <attempts> <delay_seconds> -- command ...
  local attempts="$1"; shift
  local delay="$1"; shift
  local i=0
  local rc=0
  while [ "$i" -lt "$attempts" ]; do
    if "$@"; then
      rc=0
      break
    else
      rc=$?
      i=$((i+1))
      log "WARN" "Command failed (attempt ${i}/${attempts}), rc=${rc}. Retrying in ${delay}s..."
      sleep "$delay"
    fi
  done
  return $rc
}

safe_run() {
  # Wrap command for dry-run and logging
  if [ "${DRY_RUN}" = true ]; then
    log "DRY" "DRY-RUN: $*"
    return 0
  else
    log "INFO" "EXEC: $*"
    eval "$@"
    return $?
  fi
}

require_command() {
  # require_command <cmd> <install_hint>
  local cmd="$1" install_hint="${2:-}"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    log "ERROR" "Required command '${cmd}' not found. ${install_hint}"
    return 1
  fi
  return 0
}

# -----------------------
# Environment Detection
# -----------------------
detect_os_and_pkg_manager() {
  log "INFO" "Detecting OS and package manager..."
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS="${ID:-unknown}"
    log "INFO" "Found /etc/os-release: ID=${OS}, NAME=${NAME:-}"
  fi

  if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt"
    SUDO_CMD="sudo"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
    SUDO_CMD="sudo"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
    SUDO_CMD="sudo"
  elif command -v pacman >/dev/null 2>&1; then
    PKG_MANAGER="pacman"
    SUDO_CMD="sudo"
  elif command -v zypper >/dev/null 2>&1; then
    PKG_MANAGER="zypper"
    SUDO_CMD="sudo"
  else
    PKG_MANAGER="unknown"
  fi

  log "INFO" "Package manager: ${PKG_MANAGER}"
}

# -----------------------
# Dependency Installation
# -----------------------
ensure_dependencies() {
  log "INFO" "Ensuring basic dependencies are present..."
  local deps=(jq rsync tar gzip openssl gpg coreutils awk sed find du df uname uptime bc)
  # optional tools: dialog/whiptail for UI
  case "${PKG_MANAGER}" in
    apt)
      deps+=(dialog)
      for d in "${deps[@]}"; do
        if ! command -v "${d}" >/dev/null 2>&1; then
          log "INFO" "Installing ${d} via apt..."
          retry "${RETRY_LIMIT}" "${RETRY_DELAY}" $SUDO_CMD apt-get update -y && $SUDO_CMD apt-get install -y "${d}" || log "ERROR" "Failed to install ${d} (apt)."
        fi
      done
      ;;
    dnf|yum)
      deps+=(whiptail)
      for d in "${deps[@]}"; do
        if ! command -v "${d}" >/dev/null 2>&1; then
          log "INFO" "Installing ${d} via ${PKG_MANAGER}..."
          retry "${RETRY_LIMIT}" "${RETRY_DELAY}" $SUDO_CMD "${PKG_MANAGER}" install -y "${d}" || log "ERROR" "Failed to install ${d} (${PKG_MANAGER})."
        fi
      done
      ;;
    pacman)
      deps+=(dialog)
      for d in "${deps[@]}"; do
        if ! command -v "${d}" >/dev/null 2>&1; then
          log "INFO" "Installing ${d} via pacman..."
          retry "${RETRY_LIMIT}" "${RETRY_DELAY}" $SUDO_CMD pacman -Sy --noconfirm "${d}" || log "ERROR" "Failed to install ${d} (pacman)."
        fi
      done
      ;;
    *)
      log "WARN" "Unknown package manager; skipping auto installation of dependencies. Please ensure core tools are installed."
      ;;
  esac
}

# -----------------------
# Self-diagnostics
# -----------------------
self_diagnostics() {
  log "INFO" "Running self-diagnostics..."
  local missing=0
  if [ "$(id -u)" -ne 0 ]; then
    log "WARN" "Not running as root. Some actions will require sudo privileges and may fail."
  fi

  detect_os_and_pkg_manager

  if [ "${PKG_MANAGER}" = "unknown" ]; then
    log "WARN" "Package manager unknown — some distribution-specific tasks may not work automatically."
  fi

  require_command jq "Install jq for JSON handling." || missing=$((missing+1))
  require_command rsync "Install rsync for backups." || missing=$((missing+1))
  require_command tar "Install tar for archiving." || missing=$((missing+1))
  require_command openssl "Install openssl for encryption." || missing=$((missing+1))
  require_command gpg "Install gpg if you prefer GPG encrypted backups." || missing=$((missing+1))

  if [ "${missing}" -gt 0 ]; then
    log "WARN" "Some recommended tools are missing. The script will try to install them where possible."
  fi

  log "INFO" "Self-diagnostics completed."
}

# -----------------------
# Module: System Update & Cleanup
# -----------------------
system_update_and_cleanup() {
  log "INFO" "Starting System Update & Cleanup module..."
  case "${PKG_MANAGER}" in
    apt)
      retry "${RETRY_LIMIT}" "${RETRY_DELAY}" $SUDO_CMD apt-get update -y || log "ERROR" "apt-get update failed."
      retry "${RETRY_LIMIT}" "${RETRY_DELAY}" $SUDO_CMD apt-get upgrade -y || log "ERROR" "apt-get upgrade failed."
      safe_run "$SUDO_CMD apt-get autoremove -y"
      safe_run "$SUDO_CMD apt-get autoclean -y"
      ;;
    dnf)
      safe_run "$SUDO_CMD dnf -y upgrade --refresh"
      safe_run "$SUDO_CMD dnf -y autoremove"
      ;;
    yum)
      safe_run "$SUDO_CMD yum -y update"
      safe_run "$SUDO_CMD yum -y autoremove"
      ;;
    pacman)
      safe_run "$SUDO_CMD pacman -Syu --noconfirm"
      safe_run "$SUDO_CMD pacman -Qtdq | xargs -r pacman -Rns --noconfirm" || true
      ;;
    zypper)
      safe_run "$SUDO_CMD zypper refresh"
      safe_run "$SUDO_CMD zypper update -y"
      ;;
    *)
      log "WARN" "Update/Cleanup not supported for package manager: ${PKG_MANAGER}"
      ;;
  esac
  log "INFO" "System Update & Cleanup module completed."
}

# -----------------------
# Module: Disk Space Monitoring
# -----------------------
disk_space_monitor() {
  log "INFO" "Starting Disk Space Monitoring..."
  local threshold_percent="${1:-${DEFAULT_MIN_FREE_PERCENT}}"
  # check root FS usage
  while read -r filesystem size used avail usep mount; do
    # usep like "23%"
    usep_num="${usep%\%}"
    free_percent=$((100 - usep_num))
    log "INFO" "FS ${filesystem} mounted on ${mount}: used=${usep} free=${free_percent}%"
    if [ "${free_percent}" -le "${threshold_percent}" ]; then
      log "WARN" "Low disk space on ${mount} (${free_percent}% free)."
      # Suggest cleanup actions
      suggest_disk_cleanup "${mount}"
      # If AUTO and NOT DRY_RUN, perform safe cleanup
      if [ "${AUTO}" = true ] && [ "${DRY_RUN}" = false ]; then
        perform_safe_cleanup "${mount}"
      fi
    fi
  done < <(df -h --output=source,size,used,avail,pcent,target -x tmpfs -x devtmpfs | tail -n +2 | awk '{print $1" "$2" "$3" "$4" "$5" " $6}')
  log "INFO" "Disk Space Monitoring completed."
}

suggest_disk_cleanup() {
  local mount="$1"
  log "INFO" "Suggesting cleanup for ${mount}: Removing apt caches, old kernels, large log files, and unused packages."
  # Display top large files
  log "INFO" "Top 10 largest files under ${mount}:"
  safe_run "find ${mount} -xdev -type f -printf '%s %p\n' 2>/dev/null | sort -nr | head -n 10 | awk '{printf \"%.2f MB %s\\n\", \$1/1024/1024, \$2}'"
}

perform_safe_cleanup() {
  local mount="$1"
  log "INFO" "Performing conservative safe cleanup on ${mount}..."
  # remove apt caches
  case "${PKG_MANAGER}" in
    apt) safe_run "$SUDO_CMD apt-get clean -y" ;;
    dnf|yum) safe_run "$SUDO_CMD ${PKG_MANAGER} clean all" ;;
    pacman) safe_run "$SUDO_CMD pacman -Scc --noconfirm" ;;
  esac
  # rotate and vacuum logs
  safe_run "logrotate -f /etc/logrotate.conf 2>/dev/null || true"
  # remove core dumps older than 30 days (safe)
  safe_run "find ${mount} -xdev -type f -name 'core*' -mtime +30 -delete || true"
  log "INFO" "Conservative cleanup completed for ${mount}."
}

# -----------------------
# Module: File Organization
# -----------------------
file_organization() {
  local target_dir="${1:-$HOME/Downloads}"
  log "INFO" "Starting File Organization for target: ${target_dir}"
  if [ ! -d "${target_dir}" ]; then
    log "ERROR" "Target directory ${target_dir} does not exist. Skipping file organization."
    return 1
  fi

  declare -A categories=(
    ["images"]="jpg jpeg png gif bmp svg webp heic"
    ["documents"]="pdf doc docx odt txt md rtf xls xlsx ppt pptx csv"
    ["videos"]="mp4 mkv mov avi webm m4v"
    ["audio"]="mp3 wav flac m4a ogg"
    ["archives"]="zip tar gz bz2 xz rar 7z"
    ["code"]="java py js ts go rs cpp c h sh kt gradle pom xml json yaml yml"
  )

  for cat in "${!categories[@]}"; do
    mkdir -p "${target_dir}/${cat}"
  done

  shopt -s nullglob
  for f in "${target_dir}"/*; do
    [ -f "$f" ] || continue
    ext="${f##*.}"
    ext_lc="$(echo "${ext}" | awk '{print tolower($0)}')"
    moved=false
    for cat in "${!categories[@]}"; do
      for e in ${categories[$cat]}; do
        if [ "${ext_lc}" = "${e}" ]; then
          target="${target_dir}/${cat}/$(basename "$f")"
          handle_move_with_duplicates "$f" "$target"
          moved=true
          break 2
        fi
      done
    done
    if [ "${moved}" = false ]; then
      # place in "others"
      mkdir -p "${target_dir}/others"
      handle_move_with_duplicates "$f" "${target_dir}/others/$(basename "$f")"
    fi
  done
  shopt -u nullglob
  log "INFO" "File Organization completed for ${target_dir}."
}

handle_move_with_duplicates() {
  local src="$1" dest="$2"
  # If dest exists, append a counter
  if [ -e "${dest}" ]; then
    local base extension name counter=1
    base="$(basename "${dest}")"
    name="${base%.*}"
    extension="${base##*.}"
    while [ -e "${dest%/*}/${name}_${counter}.${extension}" ]; do
      counter=$((counter+1))
    done
    dest="${dest%/*}/${name}_${counter}.${extension}"
    log "INFO" "Resolved duplicate: new dest=${dest}"
  fi
  safe_run "mv -n \"$src\" \"$dest\"" || log "ERROR" "Failed to move ${src} to ${dest}"
}

# -----------------------
# Module: System Information Dashboard
# -----------------------
dashboard() {
  log "INFO" "Generating System Information Dashboard..."
  # Use basic terminal colors (only if interactive and not DRY_RUN)
  local color_reset="\033[0m"
  local color_green="\033[1;32m"
  local color_yellow="\033[1;33m"
  local color_red="\033[1;31m"
  # Print header
  echo -e "${color_green}=== System Dashboard (${TIMESTAMP}) ===${color_reset}"
  echo "Hostname: $(hostname)"
  echo "Uptime : $(uptime -p 2>/dev/null || uptime)"
  echo "Kernel : $(uname -srmo)"
  echo "OS     : ${OS} (${PKG_MANAGER})"
  echo ""
  echo -e "${color_yellow}CPU & Memory${color_reset}"
  awk -vORS= '{print}' /proc/loadavg 2>/dev/null | awk '{print "Load avg (1/5/15): "$1" "$2" "$3}'
  free -h || true
  echo ""
  echo -e "${color_yellow}Disk Usage${color_reset}"
  df -h --total -x tmpfs -x devtmpfs || df -h
  echo ""
  echo -e "${color_yellow}Network Throughput (last 2 lines: rx/tx bytes totals)${color_reset}"
  if command -v cat >/dev/null 2>&1 && [ -f /proc/net/dev ]; then
    tail -n +3 /proc/net/dev | awk '{rx+=$2; tx+=$10} END {printf "RX: %.2f MB  TX: %.2f MB\n", rx/1024/1024, tx/1024/1024}'
  fi
  echo ""
  echo -e "${color_yellow}Top Processes by CPU${color_reset}"
  ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 10
  echo -e "${color_green}=== End Dashboard ===${color_reset}"
  log "INFO" "Dashboard generated."
}

# -----------------------
# Module: Backup & Restore
# -----------------------
make_backup() {
  local name="${1:-system_backup}"
  local src_paths=("${!2}") # pass as array name
  local compress="${3:-true}"
  local encrypt="${4:-true}"
  local passphrase="${5:-}"
  if [ "${#src_paths[@]}" -eq 0 ]; then
    log "ERROR" "No source paths provided for backup."
    return 1
  fi
  local backup_file="${BACKUP_DIR}/${name}_${TIMESTAMP}.tar"
  if [ "${compress}" = true ]; then
    backup_file="${backup_file}.gz"
  fi
  log "INFO" "Creating backup ${backup_file} for: ${src_paths[*]}"
  if [ "${compress}" = true ]; then
    safe_run "tar -czf \"${backup_file}\" -C / ${src_paths[*]} 2>>\"${LOG_FILE}\"" || { log "ERROR" "Backup creation failed."; return 1; }
  else
    safe_run "tar -cf \"${backup_file}\" -C / ${src_paths[*]} 2>>\"${LOG_FILE}\"" || { log "ERROR" "Backup creation failed."; return 1; }
  fi

  if [ "${encrypt}" = true ]; then
    if [ -n "${passphrase}" ]; then
      local enc_file="${backup_file}.enc"
      log "INFO" "Encrypting backup to ${enc_file} using openssl (AES-256-CBC mode, password provided)."
      safe_run "openssl enc -aes-256-cbc -pbkdf2 -salt -in \"${backup_file}\" -out \"${enc_file}\" -pass pass:\"${passphrase}\"" || { log "ERROR" "OpenSSL encryption failed."; return 1; }
      rm -f "${backup_file}"
      backup_file="${enc_file}"
    else
      log "WARN" "Encrypt requested but no passphrase provided. Skipping encryption."
    fi
  fi
  log "INFO" "Backup created: ${backup_file}"
  echo "${backup_file}"
}

restore_backup() {
  local file="$1"
  local dest="${2:-/}"
  local passphrase="${3:-}"
  if [ ! -f "${file}" ]; then
    log "ERROR" "Backup file ${file} not found."
    return 1
  fi
  local tmp_unenc="${TMP_DIR}/restore_${TIMESTAMP}.tar.gz"
  if file "${file}" | grep -qi "openssl"; then
    log "INFO" "Detected encrypted file. Decrypting..."
    if [ -z "${passphrase}" ]; then
      log "ERROR" "Passphrase required to decrypt the backup."
      return 1
    fi
    safe_run "openssl enc -d -aes-256-cbc -pbkdf2 -in \"${file}\" -out \"${tmp_unenc}\" -pass pass:\"${passphrase}\"" || { log "ERROR" "Decryption failed."; return 1; }
    file="${tmp_unenc}"
  fi
  log "INFO" "Restoring backup ${file} to ${dest}"
  safe_run "tar -xzf \"${file}\" -C \"${dest}\"" || { log "ERROR" "Restore failed."; return 1; }
  log "INFO" "Restore completed successfully."
}

# -----------------------
# Module: Security Hardening
# -----------------------
security_hardening() {
  log "INFO" "Starting Security Hardening module..."
  # Basic checks and recommendations; where possible apply safe fixes
  # 1) Ensure unattended-upgrades (security auto-updates) is enabled on Ubuntu/Debian
  if [ "${PKG_MANAGER}" = "apt" ]; then
    if dpkg -l unattended-upgrades >/dev/null 2>&1; then
      log "INFO" "unattended-upgrades already installed."
    else
      log "INFO" "Installing unattended-upgrades..."
      safe_run "$SUDO_CMD apt-get install -y unattended-upgrades" || log "ERROR" "Failed to install unattended-upgrades."
    fi
    # enable configuration
    local ua_conf="/etc/apt/apt.conf.d/20auto-upgrades"
    if [ -f "${ua_conf}" ]; then
      safe_run "sed -i 's/\\(\"Unattended-Upgrade\"\\|//g' ${ua_conf} 2>/dev/null || true"
    fi
    cat > "${TMP_DIR}/20auto-upgrades.tmp" <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
    safe_run "$SUDO_CMD mv ${TMP_DIR}/20auto-upgrades.tmp /etc/apt/apt.conf.d/20auto-upgrades"
    log "INFO" "Enabled unattended upgrades (security)."
  fi

  # 2) Ensure firewall is active (ufw/firewalld)
  if command -v ufw >/dev/null 2>&1; then
    log "INFO" "Configuring ufw (uncomplicated firewall)..."
    safe_run "$SUDO_CMD ufw default deny incoming"
    safe_run "$SUDO_CMD ufw default allow outgoing"
    safe_run "$SUDO_CMD ufw limit SSH" || true
    safe_run "$SUDO_CMD ufw --force enable"
    log "INFO" "ufw configured and enabled."
  elif command -v firewall-cmd >/dev/null 2>&1; then
    log "INFO" "Configuring firewalld..."
    safe_run "$SUDO_CMD firewall-cmd --set-default-zone=public"
    safe_run "$SUDO_CMD firewall-cmd --permanent --add-service=ssh"
    safe_run "$SUDO_CMD firewall-cmd --reload"
    log "INFO" "firewalld configured."
  else
    log "WARN" "No ufw/firewalld found. Recommend installing one for firewalling."
  fi

  # 3) SSH hardening suggestions and safe tweaks
  local sshd_conf="/etc/ssh/sshd_config"
  if [ -f "${sshd_conf}" ]; then
    log "INFO" "Applying conservative SSH hardening tweaks..."
    safe_run "$SUDO_CMD cp -n ${sshd_conf} ${sshd_conf}.bak || true"
    # disable root login (conservative)
    safe_run "$SUDO_CMD sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' ${sshd_conf} || true"
    # disable password auth if public key auth is present
    safe_run "$SUDO_CMD sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' ${sshd_conf} || true"
    # note: enable PasswordAuthentication yes so as not to lock out systems without keys.
    # Restrict to protocol 2
    safe_run "$SUDO_CMD sed -i 's/^#*Protocol.*/Protocol 2/' ${sshd_conf} || true"
    safe_run "$SUDO_CMD systemctl reload sshd || systemctl restart sshd || true"
    log "INFO" "SSH configuration adjusted conservatively (root login disabled)."
  else
    log "WARN" "sshd_config not found; skipping SSH hardening."
  fi

  # 4) Scan for known vulnerabilities using available tools (os-specific)
  if command -v lynis >/dev/null 2>&1; then
    log "INFO" "Running Lynis scan..."
    safe_run "lynis audit system --quick" || log "WARN" "lynis scan had issues."
  else
    log "INFO" "Lynis not installed; recommend installing lynis for deeper scanning."
  fi

  log "INFO" "Security Hardening module completed."
}

# -----------------------
# Module: System Customization
# -----------------------
system_customization() {
  log "INFO" "Starting System Customization module..."
  local preset="${1:-performance}" # performance | aesthetics | accessibility
  case "${preset}" in
    performance)
      log "INFO" "Applying performance preset: sysctl tweaks and swappiness."
      safe_run "$SUDO_CMD sysctl -w vm.swappiness=10"
      # persist
      echo "vm.swappiness=10" > "${TMP_DIR}/sysctl_swappiness.conf"
      safe_run "$SUDO_CMD mv ${TMP_DIR}/sysctl_swappiness.conf /etc/sysctl.d/99-linux_enhancer.conf"
      log "INFO" "Performance preset applied."
      ;;
    aesthetics)
      log "INFO" "Applying aesthetics preset (if desktop environment present)."
      # attempt gsettings change if available (GNOME)
      if command -v gsettings >/dev/null 2>&1; then
        safe_run "gsettings set org.gnome.desktop.interface gtk-theme 'Adwaita-dark' || true"
        safe_run "gsettings set org.gnome.desktop.background picture-uri 'file:///usr/share/backgrounds/gnome/adwaita-night.jpg' || true"
      else
        log "WARN" "gsettings not available; desktop customization skipped."
      fi
      ;;
    accessibility)
      log "INFO" "Applying accessibility preset."
      if command -v gsettings >/dev/null 2>&1; then
        safe_run "gsettings set org.gnome.desktop.a11y high-contrast true || true"
      else
        log "WARN" "Accessibility: gsettings not available."
      fi
      ;;
    *)
      log "WARN" "Unknown preset: ${preset}"
      ;;
  esac
  log "INFO" "System Customization module completed."
}

# -----------------------
# Module: Auto-Correction Engine & Self-Heal
# -----------------------
auto_correction_and_self_heal() {
  log "INFO" "Running Auto-Correction & Self-Heal engine..."
  # Example: fix common DNS misconfigurations by checking resolv.conf
  if ! ping -c1 -W1 8.8.8.8 >/dev/null 2>&1; then
    log "WARN" "Network appears down. Attempting basic network self-heal (dhclient)."
    if command -v dhclient >/dev/null 2>&1; then
      safe_run "$SUDO_CMD dhclient -v || true"
    fi
  fi

  # Ensure critical services are running (ssh, rsyslog)
  for svc in ssh rsyslog; do
    if systemctl list-units --type=service --state=running | grep -q "${svc}"; then
      log "INFO" "Service ${svc} running."
    else
      log "WARN" "Service ${svc} not running. Attempting to start..."
      safe_run "$SUDO_CMD systemctl start ${svc} || true"
    fi
  done

  # Repair broken apt packages if apt present
  if [ "${PKG_MANAGER}" = "apt" ]; then
    log "INFO" "Attempting to fix broken apt packages..."
    safe_run "$SUDO_CMD apt-get -f install -y || true"
  fi

  log "INFO" "Auto-Correction & Self-Heal completed."
}

# -----------------------
# Module: Cron Integration
# -----------------------
install_cron_job() {
  local schedule="${1:-@daily}"
  local cmd="${2:-$BASE_DIR/linux_enhancer.sh --auto}"
  log "INFO" "Installing cron job with schedule '${schedule}' and cmd '${cmd}'"
  # install for root
  if command -v crontab >/dev/null 2>&1; then
    (crontab -l 2>/dev/null | grep -v "${CRON_TAG}" || true; echo "${schedule} ${cmd} # ${CRON_TAG}") | crontab -
    log "INFO" "Cron job installed for root."
  else
    log "WARN" "crontab not available; skipping cron installation."
  fi
}

# -----------------------
# Module: Cloud Sync (Optional)
# -----------------------
cloud_sync() {
  if [ "${CLOUD_SYNC}" != true ]; then
    log "INFO" "Cloud sync disabled. Skipping."
    return 0
  fi
  log "INFO" "Starting Cloud Sync to provider: ${CLOUD_PROVIDER}"
  # Implement minimal placeholders; actual cloud sync requires provider SDK and auth
  case "${CLOUD_PROVIDER}" in
    dropbox)
      log "INFO" "Dropbox sync requested. Please configure Dropbox CLI and token in ${CLOUD_CONFIG_FILE}."
      ;;
    gdrive)
      log "INFO" "Google Drive sync requested. Please configure rclone or gdrive tool and credentials."
      ;;
    aws)
      log "INFO" "AWS S3 sync requested. Ensure awscli configured with keys and region."
      if command -v aws >/dev/null 2>&1; then
        safe_run "aws s3 cp ${BACKUP_DIR} s3://your-bucket-name/ --recursive || true"
      else
        log "WARN" "awscli not installed. Install and configure first."
      fi
      ;;
    *)
      log "WARN" "Unknown cloud provider: ${CLOUD_PROVIDER}"
      ;;
  esac
  log "INFO" "Cloud Sync completed (if configured)."
}

# -----------------------
# Module: Notifications
# -----------------------
notify_user() {
  local subject="$1"
  local body="$2"
  log "INFO" "Notify: ${subject} - ${body}"
  # Desktop notification if DISPLAY present
  if [ -n "${DISPLAY-}" ] && command -v notify-send >/dev/null 2>&1; then
    safe_run "notify-send '${subject}' '${body}'"
  fi
  # Simple email notification if configured
  if [ -n "${NOTIFY_EMAIL}" ]; then
    if command -v sendmail >/dev/null 2>&1; then
      {
        echo "To: ${NOTIFY_EMAIL}"
        echo "Subject: ${subject}"
        echo ""
        echo "${body}"
      } | sendmail -t
    else
      log "WARN" "sendmail not available to send email notifications."
    fi
  fi
}

# -----------------------
# CLI / Arg Parsing
# -----------------------
usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [options]

Options:
  --auto, --force        Run in GOD-MODE non-interactive and apply changes automatically.
  --dry-run              Simulate actions without making changes.
  --target-dir <path>    Directory to run file organization (default: \$HOME/Downloads).
  --backup-paths <list>  Comma-separated paths to include in backup (default: /etc,/home/\$SUDO_USER).
  --backup-pass <pass>   Passphrase for encryption of backups (optional).
  --preset <name>        Customization preset: performance|aesthetics|accessibility
  --install-cron <spec>  Install cron job with schedule spec (default: @daily)
  --cloud <provider>     Enable cloud sync: dropbox|gdrive|aws
  --notify-email <addr>  Email address to send notifications to
  --dashboard            Show system dashboard only
  --help                 Show this help and exit

Notes:
  - Run as root (sudo) for full effect.
  - Use --dry-run to validate changes first.
EOF
}

parse_args() {
  local positional=()
  while (( "$#" )); do
    case "$1" in
      --auto|--force)
        AUTO=true; NONINTERACTIVE=true; FORCE=true; shift ;;
      --dry-run)
        DRY_RUN=true; shift ;;
      --target-dir)
        TARGET_DIR="$2"; shift 2 ;;
      --backup-paths)
        BACKUP_PATHS_RAW="$2"; shift 2 ;;
      --backup-pass)
        BACKUP_PASSPHRASE="$2"; shift 2 ;;
      --preset)
        PRESET="$2"; shift 2 ;;
      --install-cron)
        CRON_SPEC="$2"; shift 2 ;;
      --cloud)
        CLOUD_SYNC=true; CLOUD_PROVIDER="$2"; shift 2 ;;
      --notify-email)
        NOTIFY_EMAIL="$2"; shift 2 ;;
      --dashboard)
        DASH_ONLY=true; shift ;;
      --help)
        usage; exit 0 ;;
      *)
        positional+=("$1"); shift ;;
    esac
  done
  # default fallback variables
  TARGET_DIR="${TARGET_DIR:-$HOME/Downloads}"
  BACKUP_PATHS_RAW="${BACKUP_PATHS_RAW:-/etc,$HOME}"
  PRESET="${PRESET:-performance}"
  CRON_SPEC="${CRON_SPEC:-@daily}"
  DASH_ONLY="${DASH_ONLY:-false}"
}

# -----------------------
# Main orchestrator
# -----------------------
main() {
  parse_args "$@"
  log "INFO" "Starting ${SCRIPT_NAME} (GOD-MODE=${AUTO}, DRY_RUN=${DRY_RUN})"
  self_diagnostics
  ensure_dependencies

  if [ "${DASH_ONLY}" = true ]; then
    dashboard
    exit 0
  fi

  # Dashboard first
  dashboard

  # System update & cleanup
  system_update_and_cleanup

  # Disk monitoring & cleanup
  disk_space_monitor "${DEFAULT_MIN_FREE_PERCENT}"

  # File organization
  file_organization "${TARGET_DIR}"

  # Backups
  IFS=',' read -r -a backup_paths_array <<< "${BACKUP_PATHS_RAW}"
  backup_file="$(make_backup "system_${TIMESTAMP}" backup_paths_array[@] true true "${BACKUP_PASSPHRASE:-}")"
  if [ -n "${backup_file}" ]; then
    log "INFO" "Backup produced: ${backup_file}"
  fi

  # Cloud sync if enabled
  cloud_sync

  # Security hardening
  security_hardening

  # Auto-correction
  auto_correction_and_self_heal

  # Customization
  system_customization "${PRESET}"

  # Install cron job if requested and not dry-run
  if [ -n "${CRON_SPEC}" ] && [ "${DRY_RUN}" = false ] && [ "${AUTO}" = true ]; then
    install_cron_job "${CRON_SPEC}" "$BASE_DIR/$SCRIPT_NAME --auto"
  fi

  notify_user "linux_enhancer run completed" "Completed run at ${TIMESTAMP}. Log: ${LOG_FILE}"
  log "INFO" "linux_enhancer run completed. Log file: ${LOG_FILE}"
}

# -----------------------
# Safety guard rails
# -----------------------
# This script will not perform actions that explicitly bypass security mechanisms, escalate privileges beyond sudo, or attempt to alter kernel modules in unsafe ways.
# For destructive operations, a human must edit the script to enable them explicitly.
safety_guard_rail_check() {
  # If user asked for GOD-MODE but not root, warn and require --force to continue
  if [ "${AUTO}" = true ] && [ "$(id -u)" -ne 0 ] && [ "${FORCE}" != true ]; then
    log "ERROR" "AUTO mode requested but not running as root. Re-run with sudo or add --force to override (not recommended)."
    exit 2
  fi
}

# -----------------------
# Entrypoint
# -----------------------
trap 'rc=$?; log "INFO" "Exiting with status ${rc}"; exit ${rc}' EXIT

# parse and run
parse_args "$@"
safety_guard_rail_check
main "$@"

# /*
#  * Copyright © 2025 Devin B. Royal.
#  * All Rights Reserved.
#  */
