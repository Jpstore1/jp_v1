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
# JP_V2 (Full - Part 3/4)
# Lanjutan langsung dari Part 2

# ==================================================
# NGINX CONFIGURATION
# ==================================================
msg "Configuring Nginx..."

cat > /etc/nginx/sites-available/jp_v2 <<'EOF_NGINX'
server {
    listen 80;
    listen [::]:80;
    server_name DOMAIN_PLACEHOLDER;

    location /ssh-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:WS_SSH_PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
    }

    location / {
        return 301 https://$server_name$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name DOMAIN_PLACEHOLDER;

    ssl_certificate SSL_FULLCHAIN_PLACEHOLDER;
    ssl_certificate_key SSL_PRIVKEY_PLACEHOLDER;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;

    add_header Strict-Transport-Security "max-age=63072000" always;

    # VMESS WS
    location /vmess-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:XRAY_VMESS_PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # VLESS WS
    location /vless-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:XRAY_VLESS_PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # TROJAN WS
    location /trojan-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:XRAY_TROJAN_PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # SSH WS TLS
    location /ssh-ws-tls {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:XRAY_VMESS_PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
EOF_NGINX

# Replace placeholders
sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" /etc/nginx/sites-available/jp_v2
sed -i "s#SSL_FULLCHAIN_PLACEHOLDER#$SSL_PATH/fullchain.pem#g" /etc/nginx/sites-available/jp_v2
sed -i "s#SSL_PRIVKEY_PLACEHOLDER#$SSL_PATH/privkey.pem#g" /etc/nginx/sites-available/jp_v2
sed -i "s/WS_SSH_PORT_PLACEHOLDER/$WS_SSH_PORT/g" /etc/nginx/sites-available/jp_v2
sed -i "s/XRAY_VMESS_PORT_PLACEHOLDER/$XRAY_VMESS_PORT/g" /etc/nginx/sites-available/jp_v2
sed -i "s/XRAY_VLESS_PORT_PLACEHOLDER/$XRAY_VLESS_PORT/g" /etc/nginx/sites-available/jp_v2
sed -i "s/XRAY_TROJAN_PORT_PLACEHOLDER/$XRAY_TROJAN_PORT/g" /etc/nginx/sites-available/jp_v2

ln -sf /etc/nginx/sites-available/jp_v2 /etc/nginx/sites-enabled/jp_v2

systemctl restart nginx
ok "Nginx configured!"

# ==================================================
# XRAY CONFIGURATION
# ==================================================
msg "Configuring XRAY..."

mkdir -p /usr/local/etc/xray

XRAY_UUID=$(generate_uuid)

cat > /usr/local/etc/xray/config.json <<EOF_XRAY
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": $XRAY_VMESS_PORT,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$XRAY_UUID",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vmess-ws"
        }
      }
    },
    {
      "port": $XRAY_VLESS_PORT,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$XRAY_UUID"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vless-ws"
        }
      }
    },
    {
      "port": $XRAY_TROJAN_PORT,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$TROJAN_PASS"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/trojan-ws"
        }
      }
    }
  ],

  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF_XRAY

systemctl enable xray
systemctl restart xray

ok "XRAY configured!"

# ==================================================
# USER MANAGEMENT
# ==================================================
msg "Setting up user manager..."

touch /root/users.txt

create_user(){
  local user="$1"
  local pass="$2"
  local days="$3"

  if id "$user" >/dev/null 2>&1; then
    err "User $user already exists!"
    return
  fi

  useradd -M -s /bin/false "$user"
  echo "$user:$pass" | chpasswd

  expire_date=$(date -d "$days days" +"%Y-%m-%d")
  chage -E "$expire_date" "$user"

  echo "$user $pass $expire_date" >> /root/users.txt

  ok "User created: $user (expired: $expire_date)"
}

check_expired(){
  msg "Checking expired users..."

  today=$(date +%Y-%m-%d)
  tmp=$(mktemp)

  while read -r u p exp; do
    if [[ "$exp" < "$today" ]]; then
      userdel -f "$u" >/dev/null 2>&1
    else
      echo "$u $p $exp" >> "$tmp"
    fi
  done < /root/users.txt

  mv "$tmp" /root/users.txt
  ok "Expired users cleaned"
}

renew_account(){
  echo -ne "Username: "
  read -r u
  echo -ne "Extra days: "
  read -r d

  new_date=$(date -d "$d days" +"%Y-%m-%d")
  chage -E "$new_date" "$u"
  sed -i "s/^$u .*/$u $(grep $u /root/users.txt | awk '{print $2}') $new_date/" /root/users.txt

  ok "User $u renewed until $new_date"
}

# END OF PART 3 / 4
# JP_V2 (Full - Part 4/4)
# Lanjutan langsung dari Part 3

# ==================================================
# ZIPVPN PRO
# ==================================================
msg "Setting up ZIPVPN..."

zipvpn_pro_manager_cli(){
  echo
  echo "=== ZIPVPN PRO MANAGER ==="
  echo "1) Create ZIPVPN User"
  echo "2) Delete ZIPVPN User"
  echo "3) List ZIPVPN Users"
  echo "0) Back"
  echo -ne "Choice: "
  read -r c

  case $c in
    1)
      echo -ne "Username: "
      read -r u
      echo -ne "Password: "
      read -r p
      jq --arg user "$u" --arg pass "$p" \
        '.users += [{name: $user, password: $pass}]' \
        /etc/zipvpn/config.json > tmp.json &&
      mv tmp.json /etc/zipvpn/config.json
      ok "ZIPVPN user added!"
      ;;
    2)
      echo -ne "Username: "
      read -r u
      jq --arg user "$u" \
        'del(.users[] | select(.name==$user))' \
        /etc/zipvpn/config.json > tmp.json &&
      mv tmp.json /etc/zipvpn/config.json
      ok "ZIPVPN user removed!"
      ;;
    3)
      echo "=== Users ==="
      jq '.users' /etc/zipvpn/config.json
      ;;
    0) return ;;
    *) err "Invalid"; sleep 1 ;;
  esac
}

# ==================================================
# BACKUP / RESTORE
# ==================================================
create_backup(){
  msg "Creating backup..."
  mkdir -p /root/jp_backup
  cp -r /usr/local/etc/xray /root/jp_backup/
  cp -r /etc/nginx /root/jp_backup/
  cp -r /etc/zipvpn /root/jp_backup/
  cp /root/users.txt /root/jp_backup/
  tar -czf jp_backup.tar.gz /root/jp_backup
  ok "Backup saved → jp_backup.tar.gz"
}

restore_backup(){
  msg "Restoring backup..."
  tar -xzf jp_backup.tar.gz -C /
  ok "Backup restored!"
}

# ==================================================
# INSTALL / REINSTALL CORE SERVICES
# ==================================================
install_all_services(){
  msg "Installing JP_V2 core services..."

  apt update -y
  apt install -y nginx unzip jq curl socat

  systemctl enable nginx
  systemctl restart nginx

  msg "Installing XRAY..."
  bash <(curl -s https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)

  msg "Installing ZIPVPN..."
  mkdir -p /etc/zipvpn
  cat > /etc/zipvpn/config.json <<EOF_ZIP
{
  "port": $ZIPVPN_PORT,
  "tls": true,
  "users": []
}
EOF_ZIP

  ok "All core services installed!"
}

# ==================================================
# DDOS PROTECTION
# ==================================================
install_ddos_protection(){
  msg "Installing basic DDoS protection..."
  apt install -y iptables-persistent

  iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 40 --connlimit-mask 32 -j DROP
  iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 100 --connlimit-mask 32 -j DROP

  netfilter-persistent save

  ok "DDoS protection enabled!"
}

# ==================================================
# MAIN MENU
# ==================================================
main_menu(){
  while true; do
    clear
    echo -e "${C}======= JP_V2 VPS PANEL =======${Z}"
    echo -e "${G}1) Install / Reinstall All${Z}"
    echo -e "${G}2) Create Multi User${Z}"
    echo -e "${G}3) Check Expired & Cleanup${Z}"
    echo -e "${G}4) Renew Account${Z}"
    echo -e "${G}5) Install DDoS Protection${Z}"
    echo -e "${G}6) Port Monitor${Z}"
    echo -e "${G}7) ZIPVPN Manager${Z}"
    echo -e "${G}8) Backup / Restore${Z}"
    echo -e "${G}0) Exit${Z}"
    echo -ne "Choice: "
    read -r opt

    case $opt in
      1) install_all_services ;;
      2) echo -ne "User: "; read -r u
         echo -ne "Pass: "; read -r p
         echo -ne "Days: "; read -r d
         create_user "$u" "$p" "$d" ;;
      3) check_expired ;;
      4) renew_account ;;
      5) install_ddos_protection ;;
      6) watch -n 1 "ss -tulnp | grep -E '443|80|$ZIPVPN_PORT|$XRAY_VMESS_PORT|$XRAY_VLESS_PORT|$XRAY_TROJAN_PORT'" ;;
      7) zipvpn_pro_manager_cli ;;
      8) echo "1) Backup  2) Restore"
         read -r br
         [[ $br == 1 ]] && create_backup
         [[ $br == 2 ]] && restore_backup ;;
      0) exit 0 ;;
      *) echo "Invalid"; sleep 1 ;;
    esac
  done
}

# ==================================================
# START JP_V2
# ==================================================
main_menu

# END OF PART 4 (FINAL)
