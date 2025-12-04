#!/bin/bash
# ================================================================================================
# JP_V2 - FINAL FULL VERSION (1 FILE)
# ================================================================================================

set -euo pipefail
IFS=$'\n\t'

# ==================================================
# LOAD CONFIG (if exists)
# ==================================================
if [[ -f /root/jp_v1-config.sh ]]; then
    source /root/jp_v1-config.sh
fi

# ==================================================
# DEFAULTS
# ==================================================
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

# ==================================================
# COLORS
# ==================================================
R="\033[1;31m" G="\033[1;32m" Y="\033[1;33m" C="\033[1;36m" W="\033[1;37m" Z="\033[0m"

# ==================================================
# Helpers
# ==================================================
msg(){ echo -e "[${C}..${Z}] $*"; }
ok(){ echo -e "[${G}OK${Z}] $*"; }
err(){ echo -e "[${R}ERR${Z}] $*"; }
warn(){ echo -e "[${Y}WARN${Z}] $*"; }

check_root(){ if [[ $EUID -ne 0 ]]; then err "HARUS ROOT!"; exit 1; fi }

generate_uuid(){
  if command -v uuidgen >/dev/null 2>&1; then uuidgen;
  else openssl rand -hex 16 | sed -r 's/^(.{8})(.{4})(.{4})(.{4})(.{12})$/\1-\2-\3-\4-\5/'; fi
}

svc_restart(){
    local svc="$1"
    systemctl restart "$svc" >/dev/null 2>&1 || warn "Restart $svc gagal"
}

# ==================================================
# SSL CHECK
# ==================================================
check_ssl(){
    [[ -f "${SSL_PATH}/fullchain.pem" && -f "${SSL_PATH}/privkey.pem" ]]
}

# ==================================================
# DOMAIN CONFIG
# ==================================================
interactive_config_domain(){
    clear
    echo -e "${C}=== JP_V2 SETUP ===${Z}"

    while true; do
        echo -ne "${Y}Masukkan Domain: ${Z}"
        read -r dom
        dom="${dom,,}"

        if [[ -n "$dom" && "$dom" != *" "* ]]; then
            DOMAIN="$dom"
            SSL_PATH="/etc/letsencrypt/live/$DOMAIN"
            break
        else
            err "Domain tidak valid!"
        fi
    done

    echo -ne "${Y}SSH Port [${SSH_PORT}]: ${Z}"
    read -r a; SSH_PORT="${a:-$SSH_PORT}"

    echo -ne "${Y}Hysteria Port [${HYSTERIA_PORT}]: ${Z}"
    read -r b; HYSTERIA_PORT="${b:-$HYSTERIA_PORT}"

    echo -ne "${Y}ZIPVPN Port [${ZIPVPN_PORT}]: ${Z}"
    read -r c; ZIPVPN_PORT="${c:-$ZIPVPN_PORT}"

    TROJAN_PASS=$(openssl rand -hex 12)
    HYSTERIA_PASS=$(openssl rand -hex 12)
    ZIVPN_PASS=$(openssl rand -hex 12)

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

    source /root/jp_v1-config.sh
    ok "Konfigurasi domain disimpan!"
}

# ==================================================
# INSTALL SSH MULTI
# ==================================================
install_ssh_multi(){
    msg "Installing SSH Multi..."

    apt install -y dropbear >/dev/null 2>&1

    echo "DROPBEAR_PORTS=\"${DROPBEAR_PORT1} ${DROPBEAR_PORT2}\"" > /etc/default/dropbear
    sed -i 's/#DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-w"/' /etc/default/dropbear

    systemctl enable dropbear
    systemctl restart dropbear

    if [[ ! -f /usr/local/bin/wstunnel ]]; then
        wget -q -O /usr/local/bin/wstunnel \
        https://github.com/erebe/wstunnel/releases/latest/download/wstunnel-x86_64-unknown-linux-musl
        chmod +x /usr/local/bin/wstunnel
    fi

    cat > /etc/systemd/system/ssh-ws-tls.service <<EOF
[Unit]
Description=SSH WS TLS
After=network.target nginx.service
[Service]
ExecStart=/usr/local/bin/wstunnel client ws://127.0.0.1:${SSH_PORT} --listen 127.0.0.1:${XRAY_VMESS_PORT}
Restart=always
User=nobody
[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/ssh-ws-non-tls.service <<EOF
[Unit]
Description=SSH WS Non-TLS
After=network.target nginx.service
[Service]
ExecStart=/usr/local/bin/wstunnel client ws://127.0.0.1:${SSH_PORT} --listen 127.0.0.1:${WS_SSH_PORT}
Restart=always
User=nobody
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ssh-ws-tls ssh-ws-non-tls
    systemctl restart ssh-ws-tls ssh-ws-non-tls

    ok "SSH Multi installed!"
}
# ==================================================
# INSTALL ALL SERVICES
# ==================================================
install_all_services(){
    clear
    msg "Installing JP_V2 full package..."
    check_root

    if [[ ! -f /root/jp_v1-config.sh ]]; then
        interactive_config_domain
    else
        source /root/jp_v1-config.sh
    fi

    # ========= SSL Certificate =========
    if ! check_ssl; then
        msg "Obtaining SSL certificate for $DOMAIN"

        apt install -y snapd >/dev/null 2>&1
        snap install core >/dev/null 2>&1
        snap install --classic certbot >/dev/null 2>&1
        ln -s /snap/bin/certbot /usr/bin/certbot 2>/dev/null || true

        certbot certonly --nginx \
        -d "$DOMAIN" \
        --non-interactive \
        --agree-tos \
        --email admin@"$DOMAIN" || warn "SSL install failed! Pastikan DNS benar."
    fi

    # ========= Install core packages =========
    apt update -y >/dev/null 2>&1
    apt install -y curl wget unzip jq nginx socat ufw iptables-persistent >/dev/null 2>&1

    ln -sf /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

    # ========= Install XRAY =========
    msg "Installing Xray core..."
    if ! command -v xray >/dev/null 2>&1; then
        bash -c "$(curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)" @ install
    fi

    # ========= Install Hysteria =========
    msg "Installing Hysteria..."
    wget -q -O /usr/local/bin/hysteria \
    https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64
    chmod +x /usr/local/bin/hysteria

    mkdir -p /etc/hysteria
    cat > /etc/hysteria/config.json <<EOF
{
  "listen": ":${HYSTERIA_PORT}",
  "tls": {
    "cert": "${SSL_PATH}/fullchain.pem",
    "key": "${SSL_PATH}/privkey.pem"
  },
  "auth": {
    "mode": "password",
    "config": {}
  },
  "obfs": { "type": "wechat-video", "password": "obfs123" }
}
EOF

    cat > /etc/systemd/system/hysteria.service <<EOF
[Unit]
Description=Hysteria Service
After=network.target
[Service]
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.json
Restart=always
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable hysteria
    systemctl restart hysteria

    ok "Hysteria installed!"
}

# ==================================================
# INSTALL ZIPVPN
# ==================================================
install_zipvpn(){
    msg "Installing ZIPVPN..."

    mkdir -p /etc/zivpn

    if ! command -v zivpn >/dev/null 2>&1; then
        cd /tmp
        wget -q -O zi.sh https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/zi.sh
        bash zi.sh >/dev/null 2>&1
    fi

    # base config
    echo '{"users":{},"port":'"${ZIPVPN_PORT}"',"tls":true}' > /etc/zivpn/config.json

    # set cert
    jq --arg cert "$SSL_PATH/fullchain.pem" \
       --arg key "$SSL_PATH/privkey.pem" \
       '.cert=$cert | .key=$key' \
       /etc/zivpn/config.json > /tmp/zv1.json
    mv /tmp/zv1.json /etc/zivpn/config.json

    # set admin
    jq --arg pass "$ZIVPN_PASS" \
       '.users.admin={"password":$pass,"limit_up":100,"limit_down":100}' \
       /etc/zivpn/config.json > /tmp/zv2.json
    mv /tmp/zv2.json /etc/zivpn/config.json

    systemctl restart zivpn 2>/dev/null || true
    systemctl enable zivpn 2>/dev/null || true

    ok "ZIPVPN installed!"
}

# ==================================================
# INSTALL NGINX
# ==================================================
install_nginx(){
    msg "Configuring Nginx..."

    rm -f /etc/nginx/sites-enabled/default
    rm -f /etc/nginx/sites-available/default

    cat > /etc/nginx/sites-available/jp_v2 <<EOF
server {
    listen 80;
    server_name ${DOMAIN};

    location /ssh-ws {
        proxy_pass http://127.0.0.1:${WS_SSH_PORT};
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }

    location / {
        return 301 https://${DOMAIN}\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate     ${SSL_PATH}/fullchain.pem;
    ssl_certificate_key ${SSL_PATH}/privkey.pem;

    location /vmess-ws {
        proxy_pass http://127.0.0.1:${XRAY_VMESS_PORT};
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }

    location /vless-ws {
        proxy_pass http://127.0.0.1:${XRAY_VLESS_PORT};
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }

    location /trojan-ws {
        proxy_pass http://127.0.0.1:${XRAY_TROJAN_PORT};
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }

    location /ssh-ws-tls {
        proxy_pass http://127.0.0.1:${XRAY_VMESS_PORT};
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF

    ln -sf /etc/nginx/sites-available/jp_v2 /etc/nginx/sites-enabled/jp_v2

    systemctl restart nginx
    ok "Nginx installed!"
}

# ==================================================
# XRAY CONFIG
# ==================================================
install_xray_config(){
    msg "Setting XRAY config..."

    mkdir -p /usr/local/etc/xray

    UUID_VMESS=$(generate_uuid)
    UUID_VLESS=$(generate_uuid)
    UUID_TROJAN=$(generate_uuid)

    cat > /usr/local/etc/xray/config.json <<EOF
{
  "inbounds": [
    {
      "port": ${XRAY_VMESS_PORT},
      "protocol": "vmess",
      "settings": {
        "clients": [{ "id": "${UUID_VMESS}" }]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "/vmess-ws" }
      }
    },
    {
      "port": ${XRAY_VLESS_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "${UUID_VLESS}" }],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "/vless-ws" }
      }
    },
    {
      "port": ${XRAY_TROJAN_PORT},
      "protocol": "trojan",
      "settings": {
        "clients": [{ "password": "${TROJAN_PASS}" }]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "/trojan-ws" }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom" },
    { "protocol": "blackhole", "tag": "blocked" }
  ]
}
EOF

    systemctl restart xray
    systemctl enable xray

    ok "XRAY configuration applied!"
}
# ==================================================
# USER MANAGEMENT
# ==================================================

create_user(){
    clear
    echo -e "${B}=== CREATE USER ===${Z}"

    read -p "Username : " username
    read -p "Password : " password
    read -p "Expired (days) : " exp_days

    if [[ -z "$username" || -z "$password" || -z "$exp_days" ]]; then
        err "Input tidak boleh kosong!"
        return
    fi

    exp_date=$(date -d "+$exp_days days" +"%Y-%m-%d")

    echo "$username|$password|$exp_date" >> /root/users.txt

    ok "User berhasil dibuat!"
    echo -e "${G}$username | $password | Exp: $exp_date${Z}"
    sleep 2
}

# ==================================================
# CHECK EXPIRED USERS
# ==================================================
check_expired(){
    clear
    echo -e "${B}=== USER EXPIRED CHECK ===${Z}"

    [[ ! -f /root/users.txt ]] && { warn "Belum ada user."; sleep 2; return; }

    now=$(date +%s)
    tmpfile=$(mktemp)

    while IFS="|" read -r usr pass exp; do
        exp_ts=$(date -d "$exp" +%s)
        if (( exp_ts < now )); then
            echo -e "${R}Expired: $usr | $exp${Z}"
        else
            echo "$usr|$pass|$exp" >> "$tmpfile"
        fi
    done < /root/users.txt

    mv "$tmpfile" /root/users.txt

    ok "Expired users dibersihkan!"
    sleep 2
}

# ==================================================
# RENEW USER
# ==================================================
renew_account(){
    clear
    echo -e "${B}=== RENEW USER ===${Z}"

    [[ ! -f /root/users.txt ]] && { warn "Belum ada user."; return; }

    read -p "Username: " username
    read -p "Tambah hari: " more_days

    tmpfile=$(mktemp)
    found=0

    while IFS="|" read -r usr pass exp; do
        if [[ "$usr" == "$username" ]]; then
            found=1
            new_exp=$(date -d "$exp +$more_days days" +"%Y-%m-%d")
            echo "$usr|$pass|$new_exp" >> "$tmpfile"
            echo -e "${G}Renewed → $usr | New Exp: $new_exp${Z}"
        else
            echo "$usr|$pass|$exp" >> "$tmpfile"
        fi
    done < /root/users.txt

    mv "$tmpfile" /root/users.txt

    [[ $found -eq 0 ]] && warn "User tidak ditemukan."
    sleep 2
}

# ==================================================
# ZIPVPN PRO MANAGER
# ==================================================
zipvpn_pro_manager(){
    clear
    echo -e "${C}=== ZIPVPN ONE DEVICE MANAGER ===${Z}"

    read -p "Username baru: " u
    read -p "Password: " p

    if [[ -z "$u" || -z "$p" ]]; then
        err "Input kosong!"
        return
    fi

    tmp=$(mktemp)
    jq --arg u "$u" --arg p "$p" \
       '.users[$u] = {"password":$p,"limit_up":30,"limit_down":30}' \
       /etc/zivpn/config.json > "$tmp"

    mv "$tmp" /etc/zivpn/config.json

    systemctl restart zivpn

    ok "ZIPVPN user berhasil ditambahkan!"
    sleep 2
}

# ==================================================
# DDOS PROTECTION (Basic Firewall Rules)
# ==================================================
install_ddos_protection(){
    msg "Enabling DDoS basic protection..."

    ufw allow 22/tcp
    ufw allow "$SSH_PORT/tcp"
    ufw allow 443/tcp
    ufw allow 80/tcp
    ufw allow "$HYSTERIA_PORT/udp"
    ufw allow "$ZIPVPN_PORT/udp"

    ufw limit ssh
    ufw --force enable

    iptables -A INPUT -p tcp --syn -m limit --limit 50/s --limit-burst 20 -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

    netfilter-persistent save >/dev/null 2>&1

    ok "DDoS protection aktif!"
}

# ==================================================
# INSTALL MULTI SSH (DROPBEAR + WSTUNNEL)
# ==================================================
install_multi_ssh(){
    msg "Installing Dropbear + WS Tunnel..."

    apt install -y dropbear >/dev/null 2>&1

    echo "DROPBEAR_PORT=$DROPBEAR_PORT1" > /etc/default/dropbear

    systemctl restart dropbear
    systemctl enable dropbear

    mkdir -p /usr/local/bin

    if [[ ! -f /usr/local/bin/wstunnel ]]; then
        wget -q -O /usr/local/bin/wstunnel \
        https://github.com/erebe/wstunnel/releases/latest/download/wstunnel-x86_64-unknown-linux-musl
        chmod +x /usr/local/bin/wstunnel
    fi

    cat > /etc/systemd/system/ssh-ws.service <<EOF
[Unit]
Description=SSH over WS
After=network.target
[Service]
ExecStart=/usr/local/bin/wstunnel client ws://127.0.0.1:${SSH_PORT} --listen 127.0.0.1:${WS_SSH_PORT}
Restart=always
User=nobody
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ssh-ws
    systemctl restart ssh-ws

    ok "SSH WebSocket aktif!"
}

# ==================================================
# BACKUP RESTORE
# ==================================================
backup_restore(){
    clear
    echo -e "${Y}=== BACKUP / RESTORE ===${Z}"

    echo "1) Backup"
    echo "2) Restore"
    read -p "Pilih: " opt

    if [[ "$opt" == "1" ]]; then
        tstamp=$(date +%Y%m%d-%H%M)
        tar -czf /root/jp_v2-backup-$tstamp.tar.gz \
            /etc/xray \
            /etc/nginx \
            /etc/hysteria \
            /etc/zivpn \
            /root/users.txt \
            /root/jp_v1-config.sh

        ok "Backup saved: /root/jp_v2-backup-$tstamp.tar.gz"
        sleep 2
    else
        read -p "File backup: " file

        [[ ! -f "$file" ]] && err "File tidak ditemukan!" && return

        tar -xzf "$file" -C /
        ok "Restore success!"
        sleep 2
    fi
}
# ==================================================
# MAIN MENU
# ==================================================
menu(){
    while true; do
        clear
        echo -e "${C}=== JP_V2 PANEL ===${Z}"
        echo "1) Install / Reinstall All"
        echo "2) Create / Manage User"
        echo "3) Check Expired"
        echo "4) Renew User"
        echo "5) DDoS Protection"
        echo "6) Traffic Monitor"
        echo "7) Service Control"
        echo "8) ZIPVPN Manager"
        echo "9) Backup System"
        echo "10) Trial User Generator"
        echo "0) Exit"
        echo -ne "${Y}Select: ${Z}"
        read -r opt

        case $opt in
            1) install_all_services; complete_install ;;
            2) create_user ;;
            3) check_expired ;;
            4) renew_account ;;
            5) install_ddos_protection ;;
            6) watch -n 1 ss -tuln ;;
            7) service_panel ;;
            8) zipvpn_pro_manager ;;
            9) backup_system ;;
            10)
                for i in {1..5}; do
                    trial_user="trial$(openssl rand -hex 3)"
                    trial_pass=$(openssl rand -hex 4)
                    create_user "$trial_user" "$trial_pass" "3"
                    echo -e "${G}Trial $i: $trial_user | $trial_pass (3 days)${Z}"
                done
                ;;
            0) exit ;;
            *) echo -e "${R}Invalid choice!${Z}" ;;
        esac
    done
}

# ==================================================
# FINAL SETUP AND START
# ==================================================
if [[ "${1:-}" == "--dashboard" ]]; then
    dashboard_fullscreen
else
    menu
fi
