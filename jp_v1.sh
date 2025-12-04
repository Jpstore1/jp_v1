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
# JP_V2 (Full - Part 2/4)
# Lanjutan langsung dari Part 1

# ==================================================
# SSL CHECK
# ==================================================
check_ssl(){
  if [[ -z "${SSL_PATH:-}" || -z "${DOMAIN:-}" ]]; then return 1; fi
  [[ -f "${SSL_PATH}/fullchain.pem" && -f "${SSL_PATH}/privkey.pem" ]]
}

# ==================================================
# Interactive domain setup (before installation)
# ==================================================
interactive_config_domain(){
  clear
  echo -e "${C}=== JP_V2 DOMAIN SETUP ===${Z}"

  while true; do
    echo -ne "${Y}Input Domain (example: vpn.example.com): ${Z}"
    read -r dom || true

    dom=${dom:-$DOMAIN}

    if [[ -n "$dom" && "$dom" != *" "* ]]; then
      DOMAIN="$dom"
      SSL_PATH="/etc/letsencrypt/live/$DOMAIN"
      ok "Domain set: $DOMAIN"
      break
    else
      err "Invalid domain!"
    fi
  done

  echo -ne "${Y}SSH Port (default $SSH_PORT): ${Z}"
  read -r ss || true
  SSH_PORT=${ss:-$SSH_PORT}

  echo -ne "${Y}Hysteria Port (default $HYSTERIA_PORT): ${Z}"
  read -r hy || true
  HYSTERIA_PORT=${hy:-$HYSTERIA_PORT}

  echo -ne "${Y}ZIPVPN Port (default $ZIPVPN_PORT): ${Z}"
  read -r zv || true
  ZIPVPN_PORT=${zv:-$ZIPVPN_PORT}

  TROJAN_PASS=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-20)
  HYSTERIA_PASS=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-20)
  ZIVPN_PASS=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-20)

  echo -e "${G}Generated passwords:${Z}"
  echo -e "Trojan:   ${Y}$TROJAN_PASS${Z}"
  echo -e "Hysteria: ${Y}$HYSTERIA_PASS${Z}"
  echo -e "ZIPVPN:   ${Y}$ZIVPN_PASS${Z}"

  echo -ne "${Y}Continue installation? (y/n): ${Z}"
  read -r c || true
  [[ "$c" != "y" && "$c" != "Y" ]] && exit 1

  # save config
  cat > /root/jp_v1-config.sh <<EOF
export DOMAIN="$DOMAIN"
export SSL_PATH="$SSL_PATH"
export SSH_PORT="$SSH_PORT"
export DROPBEAR_PORT1="$DROPBEAR_PORT1"
export DROPBEAR_PORT2="$DROPBEAR_PORT2"
export WS_TLS_PORT="$WS_TLS_PORT"
export WS_NON_TLS_PORT="$WS_NON_TLS_PORT"
export XRAY_VMESS_PORT="$XRAY_VMESS_PORT"
export XRAY_VLESS_PORT="$XRAY_VLESS_PORT"
export XRAY_TROJAN_PORT="$XRAY_TROJAN_PORT"
export XRAY_UDP_PORT="$XRAY_UDP_PORT"
export WS_SSH_PORT="$WS_SSH_PORT"
export HYSTERIA_PORT="$HYSTERIA_PORT"
export ZIPVPN_PORT="$ZIPVPN_PORT"
export TROJAN_PASS="$TROJAN_PASS"
export HYSTERIA_PASS="$HYSTERIA_PASS"
export ZIVPN_PASS="$ZIVPN_PASS"
EOF

  ok "Configuration saved."
}

# ==================================================
# Install SSH + Dropbear + WS Tunnel
# ==================================================
install_ssh_multi(){
  msg "Installing SSH Multi (Dropbear + WS Tunnel)..."

  apt install -y dropbear >/dev/null 2>&1 || warn "dropbear failed"

  echo "DROPBEAR_PORTS=\"$DROPBEAR_PORT1 $DROPBEAR_PORT2\"" > /etc/default/dropbear
  sed -i 's/#DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-w"/' /etc/default/dropbear || true

  systemctl restart dropbear >/dev/null 2>&1
  systemctl enable dropbear >/dev/null 2>&1

  # wstunnel binary
  if [[ ! -f /usr/local/bin/wstunnel ]]; then
    wget -q https://github.com/erebe/wstunnel/releases/latest/download/wstunnel-x86_64-unknown-linux-musl \
      -O /usr/local/bin/wstunnel
    chmod +x /usr/local/bin/wstunnel
  fi

  # WS services
  cat > /etc/systemd/system/ssh-ws-tls.service <<EOF
[Unit]
Description=SSH WS TLS
After=network.target nginx.service

[Service]
ExecStart=/usr/local/bin/wstunnel client ws://127.0.0.1:$SSH_PORT --listen 127.0.0.1:$XRAY_VMESS_PORT
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/ssh-ws-nontls.service <<EOF
[Unit]
Description=SSH WS Non-TLS
After=network.target

[Service]
ExecStart=/usr/local/bin/wstunnel client ws://127.0.0.1:$SSH_PORT --listen 127.0.0.1:$WS_SSH_PORT
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable ssh-ws-tls ssh-ws-nontls
  systemctl restart ssh-ws-tls ssh-ws-nontls

  ok "SSH Multi installed!"
}

# ==================================================
# INSTALL ALL SERVICES
# ==================================================
install_all_services(){
  clear
  check_root

  if [[ -f /root/jp_v1-installed.flag ]]; then
    echo -ne "${Y}Already installed. Reinstall? (y/n): ${Z}"
    read -r r || true
    [[ "$r" != "y" ]] && return
    rm -f /root/jp_v1-installed.flag
  fi

  if [[ ! -f /root/jp_v1-config.sh ]]; then
    interactive_config_domain
  else
    source /root/jp_v1-config.sh || true
  fi

  if ! check_ssl; then
    warn "SSL not found, attempting Certbot..."

    if ! command -v certbot >/dev/null 2>&1; then
      apt install -y snapd >/dev/null 2>&1
      snap install core >/dev/null 2>&1
      snap install --classic certbot >/dev/null 2>&1
      ln -sf /snap/bin/certbot /usr/bin/certbot
    fi

    certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos --email admin@"$DOMAIN" || warn "Certbot failed"
  fi

  msg "Installing core dependencies..."
  apt update -y >/dev/null 2>&1
  apt install -y curl wget unzip jq git nginx socat ufw vnstat iptables-persistent >/dev/null 2>&1

  ln -sf /usr/share/zoneinfo/Asia/Jakarta /etc/localtime || true

  # XRAY INSTALL
  msg "Installing Xray core..."
  if ! command -v xray >/dev/null 2>&1; then
    bash -c "$(curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)" @ install
  fi

  # HYSTERIA
  msg "Installing Hysteria..."
  if [[ ! -f /usr/local/bin/hysteria ]]; then
    wget -qO /usr/local/bin/hysteria https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64
    chmod +x /usr/local/bin/hysteria
  fi

  mkdir -p /etc/hysteria

  cat > /etc/hysteria/config.json <<EOF
{
  "listen": ":$HYSTERIA_PORT",
  "tls": {
    "cert": "$SSL_PATH/fullchain.pem",
    "key": "$SSL_PATH/privkey.pem"
  },
  "auth": { "mode": "password", "config": {} },
  "obfs": { "type": "wechat-video", "password": "obfs123" }
}
EOF

  cat > /etc/systemd/system/hysteria.service <<EOF
[Unit]
Description=Hysteria Server
After=network.target

[Service]
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.json
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable hysteria
  systemctl restart hysteria

# ZIPVPN SECTION START
  msg "Installing ZIPVPN..."

  mkdir -p /etc/zivpn

  if ! command -v zivpn >/dev/null 2>&1; then
    cd /tmp
    wget -q -O zi.sh https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/zi.sh
    bash zi.sh >/dev/null 2>&1 || true
  fi

  if [[ ! -f /etc/zivpn/config.json ]]; then
    echo "{\"users\":{},\"port\":$ZIPVPN_PORT,\"tls\":true}" > /etc/zivpn/config.json
  fi

  tmp=$(mktemp)
  jq --arg p "$ZIPVPN_PORT" '.port=($p|tonumber)' /etc/zivpn/config.json > "$tmp" && mv "$tmp" /etc/zivpn/config.json

  tmp=$(mktemp)
  jq --arg c "$SSL_PATH/fullchain.pem" --arg k "$SSL_PATH/privkey.pem" '.cert=$c | .key=$k' /etc/zivpn/config.json > "$tmp" && mv "$tmp" /etc/zivpn/config.json

  tmp=$(mktemp)
  jq --arg p "$ZIVPN_PASS" '.users.admin={"password":$p,"limit_up":100,"limit_down":100}' /etc/zivpn/config.json > "$tmp" && mv "$tmp" /etc/zivpn/config.json

# ZIPVPN SECTION END

  ok "ZIPVPN installed!"

# END OF PART 2/4
