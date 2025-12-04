#!/bin/bash
# JP_V2 (Full - Part 1/4)
# Full original style — bagian 1 dari 4.
# Simpan sebagai: jp_part1.sh

set -euo pipefail
IFS=$'\n\t'

# ---------------------------
# Load existing config if any
# ---------------------------
if [[ -f /root/jp_v1-config.sh ]]; then
  # shellcheck source=/root/jp_v1-config.sh
  source /root/jp_v1-config.sh || true
fi

# ---------------------------
# Defaults (do not override existing)
# ---------------------------
SSH_PORT=${SSH_PORT:-2222}
DROPBEAR_PORT1=${DROPBEAR_PORT1:-442}
DROPBEAR_PORT2=${DROPBEAR_PORT2:-109}
WS_TLS_PORT=${WS_TLS_PORT:-443}
WS_NON_TLS_PORT=${WS_NON_TLS_PORT:-80}
XRAY_VMESS_PORT=${XRAY_VMESS_PORT:-10000}
XRAY_VLESS_PORT=${XRAY_VLESS_PORT:-10001}
XRAY_TROJAN_PORT=${XRAY_TROJAN_PORT:-10002}
XRAY_UDP_PORT=${XRAY_UDP_PORT:-10003}
WS_SSH_PORT=${WS_SSH_PORT:-10004}
HYSTERIA_PORT=${HYSTERIA_PORT:-40000}
ZIPVPN_PORT=${ZIPVPN_PORT:-5667}
TROJAN_PASS=${TROJAN_PASS:-$(openssl rand -base64 12 2>/dev/null || echo "tpassfallback")}
HYSTERIA_PASS=${HYSTERIA_PASS:-$(openssl rand -base64 12 2>/dev/null || echo "hpassfallback")}
ZIVPN_PASS=${ZIVPN_PASS:-$(openssl rand -base64 12 2>/dev/null || echo "zpassfallback")}
DOMAIN=${DOMAIN:-}
SSL_PATH=${SSL_PATH:-/etc/letsencrypt/live/${DOMAIN}}

# ---------------------------
# Colors & helpers
# ---------------------------
R="\033[1;31m"; G="\033[1;32m"; Y="\033[1;33m"; B="\033[1;34m"; C="\033[1;36m"; Z="\033[0m"
msg(){ echo -e "[${C}..${Z}] $*"; }
ok(){ echo -e "[${G}OK${Z}] $*"; }
err(){ echo -e "[${R}ERR${Z}] $*"; }
warn(){ echo -e "[${Y}WARN${Z}] $*"; }

check_root(){ if [[ $EUID -ne 0 ]]; then echo -e "${R}Run as root${Z}"; exit 1; fi }

generate_uuid(){
  if command -v uuidgen >/dev/null 2>&1; then uuidgen; else openssl rand -hex 16 | sed -r 's/^(.{8})(.{4})(.{4})(.{4})(.{12})$/\1-\2-\3-\4-\5/'; fi
}

svc_restart(){ local s="$1"; if systemctl list-units --type=service --all | grep -q "$s"; then systemctl restart "$s" >/dev/null 2>&1 || warn "Restart $s failed"; fi }

safe_jq_write(){
  local file="$1"; local tmp; tmp=$(mktemp) || tmp="/tmp/jq.tmp.$$"
  if jq "$2" "$file" > "$tmp" 2>/dev/null; then mv "$tmp" "$file"; else rm -f "$tmp"; warn "jq failed on $file"; fi
}

# ---------------------------
# Install dependencies for dashboard
# ---------------------------
install_fullscreen_deps(){
  apt update -qq 2>/dev/null || true
  apt install -y tmux neofetch figlet toilet boxes htop glances jq curl wget unzip nginx openssl >/dev/null 2>&1 || true
  if ! command -v lolcat >/dev/null 2>&1; then
    if command -v gem >/dev/null 2>&1; then gem install lolcat >/dev/null 2>&1 || true; fi
  fi
}

# ---------------------------
# TMUX fullscreen dashboard
# ---------------------------
setup_fullscreen_dashboard(){
  install_fullscreen_deps
  tmux kill-session -t JP_V1 2>/dev/null || true
  tmux new-session -d -s JP_V1 "bash $0 --dashboard"
  local watch_ports="(22|${SSH_PORT}|80|443|${DROPBEAR_PORT1}|${DROPBEAR_PORT2}|${HYSTERIA_PORT}|${ZIPVPN_PORT})"
  tmux split-window -h -t JP_V1:0.0 "watch -n 2 \"ss -tuln | grep -E '${watch_ports}' | lolcat\"" || true
  tmux split-window -v -t JP_V1:0.1 "watch -n 3 \"htop -C | head -20 | lolcat\"" || true
  tmux split-window -v -t JP_V1:0.2 "watch -n 5 \"glances --tree | head -15 | lolcat\"" || true
  tmux select-pane -t JP_V1:0.0 || true
  tmux attach-session -t JP_V1 || true
}

# ---------------------------
# Dashboard UI loop
# ---------------------------
dashboard_fullscreen(){
  clear; tput civis || true
  while true; do
    clear
    if command -v neofetch >/dev/null 2>&1; then neofetch 2>/dev/null || true; else echo -e "${C}$(hostname) | $(uptime -p)${Z}"; fi
    toilet -f standard "JP_V2" 2>/dev/null | lolcat -a -s 120 2>/dev/null || true
    echo -e "${B}┌──────────────────────────────────────────────────────┐${Z}"
    echo -e "${B}│${C}                   LIVE STATUS                       ${B}│${Z}"
    echo -e "${B}├──────────────────────────────────────────────────────┤${Z}"
    services=(xray nginx hysteria zivpn sshd dropbear wstunnel)
    status_line=""
    for svc in "${services[@]}"; do
      st=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
      [[ "$st" == "active" ]] && status_line+="${G}●" || status_line+="${R}○"
      status_line+=" $svc "
    done
    echo -e "${B}│${status_line}${B}│${Z}"
    users=$(wc -l < /root/users.txt 2>/dev/null || echo 0)
    ip=$(curl -s --max-time 3 ifconfig.me 2>/dev/null || echo "N/A")
    echo -e "${B}│ Users:${G} $users ${B}| IP:${G} $ip ${B}│${Z}"
    echo -e "${B}└──────────────────────────────────────────────────────┘${Z}\n"

    cat <<'MENU' | boxes -d stone -p a2x2 | lolcat
1) Install / Reinstall All
2) Create Multi User
3) Check Expired & Cleanup
4) Renew Account
5) DDoS Protection Manager
6) Traffic Monitor
7) Service Control
8) ZIPVPN Manager
9) Backup / Restore
0) Exit
MENU

    echo -ne "${Y}Choice: ${Z}"; read -r opt || true
    case $opt in
      1) install_all_services ;;
      2) create_user ;;
      3) check_expired ;;
      4) renew_account ;;
      5) install_ddos_protection ;;
      6) watch -n 1 "ss -tuln | grep -E '(22|${SSH_PORT}|80|443|${DROPBEAR_PORT1}|${DROPBEAR_PORT2})' | lolcat" ;;
      7) systemctl list-units --type=service --state=running | grep -E "xray|nginx|hysteria|zivpn|sshd|dropbear" | less ;;
      8) zipvpn_pro_manager_cli ;;
      9) create_backup ;;
      0) tput cnorm || true; exit 0 ;;
      *) echo "Invalid"; sleep 1 ;;
    esac
  done
}

# ---------------------------
# End Part 1/4
# (Continue to Part 2/4)
