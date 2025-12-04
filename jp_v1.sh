#!/bin/bash
# ================================================================================================
# JP_V2 - Full Version (Rebuilt) with Mandatory Domain, Auto-SSL, Multi-Tunneling, Dashboard
# Rebuilt and closed properly — send in 4 parts. Paste parts 1→2→3→4 in order.
# ================================================================================================

set -euo pipefail
IFS=$'\n\t'

# ==================================================
# LOAD CONFIG (if exists)
# ==================================================
if [[ -f /root/jp_v1-config.sh ]]; then
    # shellcheck source=/root/jp_v1-config.sh
    source /root/jp_v1-config.sh || true
fi

# ==================================================
# DEFAULTS (will not override existing env vars)
# ==================================================
SSH_PORT=${SSH_PORT:-2222}
DROPBEAR_PORT1=${DROPBEAR_PORT1:-442}
DROPBEAR_PORT2=${DROPBEAR_PORT2:-109}
WS_TLS_PORT=${WS_TLS_PORT:-443}
WS_NON_TLS_PORT=${WS_NON_TLS_PORT:-80}
XRAY_VMESS_PORT=${XRAY_VMESS_PORT:-10000}
XRAY_VLESS_PORT=${XRAY_VLESS_PORT:-10001}
XRAY_TROJAN_PORT=${XRAY_VMESS_PORT:-10002}  # note: fallback if not provided
XRAY_UDP_PORT=${XRAY_UDP_PORT:-10003}
WS_SSH_PORT=${WS_SSH_PORT:-10004}
HYSTERIA_PORT=${HYSTERIA_PORT:-40000}
ZIPVPN_PORT=${ZIPVPN_PORT:-5667}

TROJAN_PASS=${TROJAN_PASS:-$(openssl rand -base64 12 2>/dev/null || echo "tpassfallback")}
HYSTERIA_PASS=${HYSTERIA_PASS:-$(openssl rand -base64 12 2>/dev/null || echo "hpassfallback")}
ZIVPN_PASS=${ZIVPN_PASS:-$(openssl rand -base64 12 2>/dev/null || echo "zpassfallback")}

DOMAIN=${DOMAIN:-}
SSL_PATH=${SSL_PATH:-"/etc/letsencrypt/live/${DOMAIN}"}

# ==================================================
# COLORS
# ==================================================
R="\033[1;31m" 
G="\033[1;32m" 
Y="\033[1;33m" 
B="\033[1;34m" 
P="\033[1;35m"
C="\033[1;36m" 
W="\033[1;37m" 
Z="\033[0m"

# ==================================================
# UI Helpers
# ==================================================
msg(){ echo -e "[${C}..${Z}] $*"; }
ok(){ echo -e "[${G}OK${Z}] $*"; }
err(){ echo -e "[${R}ERR${Z}] $*"; }
warn(){ echo -e "[${Y}WARN${Z}] $*"; }

# ==================================================
# Basic utilities
# ==================================================
check_root(){ 
    if [[ $EUID -ne 0 ]]; then 
        echo -e "${R}Harus ROOT! Jalankan: sudo bash $0${Z}"
        exit 1
    fi
}

generate_uuid(){
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen
  else
    openssl rand -hex 16 | sed -r 's/^(.{8})(.{4})(.{4})(.{4})(.{12})$/\1-\2-\3-\4-\5/'
  fi
}

svc_restart(){ 
    local svc="$1"
    if systemctl list-units --type=service --all | grep -q "$svc"; then 
        systemctl restart "$svc" >/dev/null 2>&1 || warn "Restart $svc failed"
    else 
        msg "$svc not found"
    fi 
}

safe_jq_update(){ 
  local src="$1" tmp="$2" filter="$3"
  if [[ ! -f "$src" ]]; then echo '{}'>"$src"; fi
  if jq "$filter" "$src" > "$tmp" 2>/dev/null; then 
      mv "$tmp" "$src"
  else 
      warn "jq update failed for $src"
      rm -f "$tmp"
  fi
}

# ==================================================
# Install fullscreen deps (tmux dashboard)
# ==================================================
install_fullscreen_deps(){
    apt update -qq 2>/dev/null || true
    apt install -y tmux neofetch figlet lolcat boxes toilet htop glances nload speedtest-cli >/dev/null 2>&1 || true

    if ! command -v lolcat >/dev/null 2>&1; then
        if command -v gem >/dev/null 2>&1; then 
            gem install lolcat >/dev/null 2>&1 || true
        fi
    fi
}

# ==================================================
# TMUX Dashboard setup
# ==================================================
setup_fullscreen_dashboard(){
    install_fullscreen_deps
    tmux kill-session -t JP_V1 2>/dev/null || true
    tmux new-session -d -s JP_V1 "bash $0 --dashboard"

    local watch_ports="(22|${SSH_PORT}|80|443|${DROPBEAR_PORT1}|${DROPBEAR_PORT2}|${HYSTERIA_PORT}|${ZIPVPN_PORT})"

    tmux split-window -h -t JP_V1:0.0 "watch -n 2 \"ss -tuln | grep -E '${watch_ports}' | lolcat\"" || true
    tmux split-window -v -t JP_V1:0.1 "watch -n 3 \"htop -C --no-header --no-bold -d 10 | head -20 | lolcat\"" || true
    tmux split-window -v -t JP_V1:0.2 "watch -n 5 \"glances --tree | head -15 | lolcat\"" || true

    tmux select-pane -t JP_V1:0.0 || true
    tmux resize-pane -x 120 -y 35 || true
    tmux attach-session -t JP_V1 || true
}

# ==================================================
# Dashboard UI
# ==================================================
dashboard_fullscreen(){
    clear
    tput civis || true
    while true; do
        clear

        if command -v neofetch >/dev/null 2>&1; then 
            neofetch --config '{"colors":{"title":5,"separator":5},"info":{"cpu":"off","memory":"off"}}' 2>/dev/null || true
        else 
            echo -e "${C}🌐 $(hostname) | $(uptime -p)${Z}"
        fi

        toilet -f slant "JP_V2" 2>/dev/null | lolcat -a -s 120 2>/dev/null || true
        figlet -f big "FULLSCREEN" 2>/dev/null | lolcat -s 200 2>/dev/null || true

        echo -e "${B}┌──────────────────────────────────────────────────────┐${Z}"
        echo -e "${B}│${P}                    LIVE STATUS                       ${B}│${Z}"
        echo -e "${B}├──────────────────────────────────────────────────────┤${Z}"

        services=(xray nginx hysteria zivpn sshd dropbear wstunnel)
        status_line=""

        for svc in "${services[@]}"; do
            st=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
            [[ "$st" == "active" ]] && status_line+="${G}🔥" || status_line+="${R}❌"
            status_line+=" $svc "
        done

        echo -e "${B}│${status_line}${B}│${Z}"

        users=$(wc -l < /root/users.txt 2>/dev/null || echo 0)
        conns=$(ss -tuln | wc -l 2>/dev/null || echo 0)
        ip=$(curl -s --max-time 3 ifconfig.me 2>/dev/null || echo "N/A")

        echo -e "${B}│${Y}Users:${G} $users ${Y}|${G} Ports:${Y} $conns ${Y}|${C} IP:${G} $ip ${B}│${Z}"
        echo -e "${B}└──────────────────────────────────────────────────────┘${Z}\n"

        boxes -d banner3-d -p a2x2 << 'EOF' | lolcat
1️⃣  🔧 INSTALL / REINSTALL ALL
2️⃣  👥 CREATE MULTI-FUNG USER
3️⃣  📋 USER STATUS + AUTO CLEAN
4️⃣  🔄 RENEW USER EXPIRED
5️⃣  🛡️ DDOS PROTECTION MANAGER
6️⃣  📊 FULL TRAFFIC MONITOR
7️⃣  🔐 SERVICE CONTROL PANEL
8️⃣  ⚡ ZIPVPN 1-DEVICE MANAGER
9️⃣  💾 BACKUP / RESTORE
🔟  🎁 TRIAL USER GENERATOR (x5)
0️⃣  ❌ EXIT FULLSCREEN MODE
EOF

        echo -ne "${Y}👉 Pilih [0-10]: ${Z}"
        read -r opt || true

        case $opt in
            1) install_all_services ;;
            2) create_user ;;
            3) check_expired ;;
            4) renew_account ;;
            5) install_ddos_protection ;;
            6)
                clear
                echo -e "${P}📊 FULLSCREEN TRAFFIC MONITOR${Z}"
                watch -n 1 "ss -tuln | grep -E '(22|${SSH_PORT}|80|443|${DROPBEAR_PORT1}|${DROPBEAR_PORT2}|${HYSTERIA_PORT}|${ZIPVPN_PORT})' | lolcat && echo && glances --tree | head -15 | lolcat"
                ;;
            7)
                clear
                echo -e "${P}🔐 SERVICE CONTROL${Z}"
                systemctl list-units --type=service --state=running | grep -E "(xray|nginx|hysteria|zivpn|sshd|dropbear|wstunnel)" | lolcat
                echo -ne "${Y}Service (restart/stop): ${Z}"; read svc
                [[ -n $svc ]] && systemctl restart "$svc" && echo -e "${G}✅ $svc restarted${Z}"
                sleep 3
                ;;
            8) zipvpn_pro_manager ;;
            9)
                timestamp=$(date +%Y%m%d-%H%M%S)
                tar -czf "/root/jp_v2-backup-$timestamp.tar.gz" /etc/nginx /usr/local/etc/xray /etc/zivpn /root/users.txt /root/jp_v1-config.sh /etc/hysteria 2>/dev/null || warn "Beberapa path mungkin tidak ada"
                echo -e "${G}💾 Backup: /root/jp_v2-backup-$timestamp.tar.gz${Z}"
                ;;
            10)
                for i in {1..5}; do
                    trial_username="trial$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8 | tr '[:upper:]' '[:lower:]')"
                    trial_password=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 12)
                    create_user "$trial_username" "$trial_password" "3"
                    echo -e "${G}🎁 Trial $i: ${trial_username}:${trial_password} (3 days)${Z}"
                done
                ;;
            0)
                echo -e "${C}👋 Keluar dari Fullscreen Mode...${Z}"
                tput cnorm || true
                exit 0
                ;;
            *) echo -e "${R}❌ Pilihan tidak valid!${Z}"; sleep 1 ;;
        esac
        sleep 1
    done
}
# ================================================
# SSL CHECK
# ================================================
check_ssl(){
    if [[ -z "${SSL_PATH:-}" || -z "${DOMAIN:-}" ]]; then return 1; fi
    [[ -f "${SSL_PATH}/fullchain.pem" && -f "${SSL_PATH}/privkey.pem" ]]
}

# ================================================
# Interactive domain setup (before installation)
# ================================================
interactive_config_domain(){
    clear
    echo -e "${C}=== JP_V2 DOMAIN SETUP ===${Z}"

    while true; do
        echo -ne "${Y}Input Domain (example: vpn.example.com): ${Z}"
        read -r dom
        dom="${dom,,}"   # lowercase

        if [[ -n "$dom" && "$dom" != *" "* ]]; then
            DOMAIN="$dom"
            SSL_PATH="/etc/letsencrypt/live/$DOMAIN"
            break
        else
            echo -e "${R}Domain tidak valid!${Z}"
        fi
    done

    echo -ne "${Y}SSH Port [default ${SSH_PORT}]: ${Z}"
    read -r in1; SSH_PORT="${in1:-$SSH_PORT}"

    echo -ne "${Y}Hysteria Port [default ${HYSTERIA_PORT}]: ${Z}"
    read -r in2; HYSTERIA_PORT="${in2:-$HYSTERIA_PORT}"

    echo -ne "${Y}ZIPVPN Port [default ${ZIPVPN_PORT}]: ${Z}"
    read -r in3; ZIPVPN_PORT="${in3:-$ZIPVPN_PORT}"

    TROJAN_PASS=$(openssl rand -hex 12)
    HYSTERIA_PASS=$(openssl rand -hex 12)
    ZIVPN_PASS=$(openssl rand -hex 12)

    echo -e "${G}Generated Passwords:${Z}"
    echo -e "Trojan: ${Y}$TROJAN_PASS${Z}"
    echo -e "Hysteria: ${Y}$HYSTERIA_PASS${Z}"
    echo -e "ZIPVPN: ${Y}$ZIVPN_PASS${Z}"

    echo -ne "${Y}Lanjut install? (y/n): ${Z}"
    read -r cf
    [[ "$cf" != "y" ]] && exit 1

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
}

# ================================================
# Install SSH Multi (Dropbear + WS)
# ================================================
install_ssh_multi(){
    msg "Installing SSH Multi..."

    apt install -y dropbear >/dev/null 2>&1

    echo "DROPBEAR_PORTS=\"${DROPBEAR_PORT1} ${DROPBEAR_PORT2}\"" > /etc/default/dropbear
    sed -i 's/#DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-w"/' /etc/default/dropbear

    systemctl restart dropbear
    systemctl enable dropbear

    # Install wstunnel
    if [[ ! -f /usr/local/bin/wstunnel ]]; then
        wget -q -O /usr/local/bin/wstunnel https://github.com/erebe/wstunnel/releases/latest/download/wstunnel-x86_64-unknown-linux-musl
        chmod +x /usr/local/bin/wstunnel
    fi

    # WS services
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
Description=SSH WS NON-TLS
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

# ================================================
# Install ALL services
# ================================================
install_all_services(){
    clear
    msg "Starting JP_V2 full installation..."
    check_root

    if [[ ! -f /root/jp_v1-config.sh ]]; then
        interactive_config_domain
    else
        source /root/jp_v1-config.sh
    fi

    # SSL check
    if ! check_ssl; then
        msg "Getting SSL certificate for $DOMAIN..."

        apt install -y snapd >/dev/null 2>&1
        snap install core
        snap install --classic certbot
        ln -sf /snap/bin/certbot /usr/bin/certbot

        certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos --email admin@"$DOMAIN" \
            || echo -e "${R}Certbot gagal, pastikan DNS sudah benar${Z}"
    fi

    # Core packages
    apt update -y
    apt install -y curl wget unzip jq nginx socat ufw iptables-persistent

    # Timezone
    ln -sf /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

    # Install Xray
    msg "Installing Xray..."
    bash -c "$(curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)" @ install

    # Install Hysteria
    msg "Installing Hysteria..."
    wget -q -O /usr/local/bin/hysteria https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64
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
}
# ================================================
# Install ZIPVPN (UDP)
# ================================================
install_zipvpn(){
    msg "Installing ZIPVPN..."

    mkdir -p /etc/zivpn

    if ! command -v zivpn >/dev/null 2>&1; then
        cd /tmp
        wget -q -O zi.sh https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/zi.sh
        bash zi.sh >/dev/null 2>&1
    fi

    if [[ ! -f /etc/zivpn/config.json ]]; then
        echo '{"users":{},"port":'"${ZIPVPN_PORT}"',"tls":true}' > /etc/zivpn/config.json
    fi

    jq --arg cert "$SSL_PATH/fullchain.pem" \
       --arg key "$SSL_PATH/privkey.pem" \
       '.cert=$cert | .key=$key' /etc/zivpn/config.json > /tmp/zivpn1.json
    mv /tmp/zivpn1.json /etc/zivpn/config.json

    jq --arg port "$ZIPVPN_PORT" \
       '.port=($port|tonumber)' /etc/zivpn/config.json > /tmp/zivpn2.json
    mv /tmp/zivpn2.json /etc/zivpn/config.json

    jq --arg pass "$ZIVPN_PASS" \
       '.users.admin={"password":$pass,"limit_up":100,"limit_down":100}' \
       /etc/zivpn/config.json > /tmp/zivpn3.json
    mv /tmp/zivpn3.json /etc/zivpn/config.json

    systemctl restart zivpn 2>/dev/null || true
    systemctl enable zivpn 2>/dev/null || true

    ok "ZIPVPN installed!"
}

# ================================================
# NGINX CONFIG
# ================================================
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

    ln -sf /etc/nginx/sites-available/jp_v2 /etc/nginx/sites-enabled/

    systemctl restart nginx
    ok "Nginx configured!"
}

# ================================================
# XRAY CONFIG BUILDER
# ================================================
install_xray_config(){
    msg "Generating XRAY config..."

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
        "clients": [{"id": "${UUID_VMESS}"}]
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
        "clients": [{"id": "${UUID_VLESS}"}],
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
        "clients": [{"password": "${TROJAN_PASS}"}]
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

    ok "XRAY config installed!"
}

# ================================================
# Final Installation Handler
# ================================================
complete_install(){
    install_ssh_multi
    install_nginx
    install_xray_config
    install_zipvpn

    touch /root/jp_v1-installed.flag

    ok "JP_V2 Installation Completed!"
}

# ================================================
# User Management (Create / Expire / Renew)
# ================================================
create_user(){
    username="$1"
    password="$2"
    days="$3"

    exp_date=$(date -d "+${days} days" +"%Y-%m-%d")

    echo "$username $password $exp_date" >> /root/users.txt
    ok "User created: $username | Expire: $exp_date"
}

check_expired(){
    today=$(date +"%Y-%m-%d")
    if [[ ! -f /root/users.txt ]]; then echo "0"; return; fi

    while read -r u p exp; do
        if [[ "$exp" < "$today" ]]; then
            sed -i "/$u $p $exp/d" /root/users.txt
            echo -e "${R}User expired: $u${Z}"
        fi
    done < /root/users.txt
}

renew_account(){
    echo -ne "${Y}Username: ${Z}"
    read -r user
    echo -ne "${Y}Extra days: ${Z}"
    read -r days

    old_exp=$(grep "^$user" /root/users.txt | awk '{print $3}')
    [[ -z "$old_exp" ]] && echo -e "${R}User not found!${Z}" && return

    new_exp=$(date -d "$old_exp + $days days" +"%Y-%m-%d")

    sed -i "s/$old_exp/$new_exp/" /root/users.txt
    ok "Updated: $user | New Exp: $new_exp"
}
# ================================================
# ZIPVPN PRO MANAGER
# ================================================
zipvpn_pro_manager(){
    clear
    echo -e "${C}=== ZIPVPN MANAGER ===${Z}"
    echo "1) Add User"
    echo "2) Delete User"
    echo "3) List User"
    echo "0) Back"
    echo -ne "${Y}Choose: ${Z}"
    read -r opt

    case $opt in
        1)
            echo -ne "${Y}Username: ${Z}"; read -r u
            echo -ne "${Y}Password: ${Z}"; read -r p
            jq --arg user "$u" --arg pass "$p" \
               '.users[$user]={password:$pass,limit_up:100,limit_down:100}' \
               /etc/zivpn/config.json > /tmp/zv_add.json
            mv /tmp/zv_add.json /etc/zivpn/config.json
            systemctl restart zivpn
            ok "User added!"
            ;;
        2)
            echo -ne "${Y}Username: ${Z}"; read -r u
            jq "del(.users.\"$u\")" /etc/zivpn/config.json > /tmp/zv_del.json
            mv /tmp/zv_del.json /etc/zivpn/config.json
            systemctl restart zivpn
            ok "User deleted!"
            ;;
        3)
            echo -e "${G}=== User List ===${Z}"
            jq '.users' /etc/zivpn/config.json
            ;;
        0) return ;;
        *) echo -e "${R}Invalid!${Z}" ;;
    esac
}

# ================================================
# DDOS Firewall
# ================================================
install_ddos_protection(){
    msg "Installing Anti-DDoS Rules..."

    iptables -F
    iptables -X

    iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    iptables -A INPUT -m state --state INVALID -j DROP
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

    netfilter-persistent save
    netfilter-persistent reload

    ok "DDOS protection installed!"
}

# ================================================
# Service Control Panel
# ================================================
service_panel(){
    clear
    echo -e "${C}=== SERVICE CONTROL PANEL ===${Z}"
    systemctl list-units --type=service --state=running | grep -E "xray|nginx|hysteria|zivpn|ssh|dropbear"

    echo -ne "${Y}Restart service: ${Z}"
    read -r svc
    [[ -n "$svc" ]] && systemctl restart "$svc" && ok "$svc restarted!"
}

# ================================================
# Backup & Restore
# ================================================
backup_system(){
    ts=$(date +%Y%m%d-%H%M%S)
    file="/root/jp_backup_${ts}.tar.gz"

    tar -czf "$file" \
        /etc/nginx \
        /usr/local/etc/xray \
        /etc/zivpn \
        /root/users.txt \
        /etc/hysteria \
        /root/jp_v1-config.sh 2>/dev/null

    ok "Backup created: $file"
}

# ================================================
# FULLSCREEN / MENU ENTRY
# ================================================
menu(){
    while true; do
        clear
        echo -e "${G}========= JP_V2 PANEL =========${Z}"
        echo "1) Install / Reinstall All"
        echo "2) Add User"
        echo "3) Check Expired"
        echo "4) Renew User"
        echo "5) Install DDOS Protection"
        echo "6) Traffic Monitor"
        echo "7) Service Panel"
        echo "8) ZIPVPN Manager"
        echo "9) Backup System"
        echo "10) Generate 5 Trial Users"
        echo "0) Exit"
        echo -ne "${Y}Select: ${Z}"
        read -r x

        case $x in
            1) install_all_services; complete_install ;;
            2)
                echo -ne "Username: "; read user
                echo -ne "Password: "; read pass
                echo -ne "Days: "; read d
                create_user "$user" "$pass" "$d"
                ;;
            3) check_expired ;;
            4) renew_account ;;
            5) install_ddos_protection ;;
            6) watch -n 1 ss -tuln ;;
            7) service_panel ;;
            8) zipvpn_pro_manager ;;
            9) backup_system ;;
            10)
                for i in {1..5}; do
                    u="trial$(openssl rand -hex 3)"
                    p=$(openssl rand -hex 4)
                    create_user "$u" "$p" "3"
                    echo -e "${G}Trial $i: $u | $p (3 days)${Z}"
                done
                ;;
            0) exit ;;
            *) echo "Invalid"; sleep 1 ;;
        esac
    done
}

# ================================================
# RUNTIME ENTRY
# ================================================
if [[ "${1:-}" == "--dashboard" ]]; then
    dashboard_fullscreen
else
    menu
fi
