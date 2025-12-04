#!/bin/bash
# ================================================================================================
# JP_V2 - JP_V1 upgraded -> fixed + Add Domain on install
# Goals: keep original structure, add robust defaults, safe jq usage, Add Domain prompt during install
# ================================================================================================

set -euo pipefail
IFS=$'\n\t'

# ==================================================
# LOAD CONFIG (if exists)
# ==================================================
if [[ -f /root/jp_v1-config.sh ]]; then
    # shellcheck source=/root/jp_v1-config.sh
    source /root/jp_v1-config.sh
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
R="\033[1;31m" G="\033[1;32m" Y="\033[1;33m" B="\033[1;34m" P="\033[1;35m"
C="\033[1;36m" W="\033[1;37m" Z="\033[0m"

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
check_root(){ if [[ $EUID -ne 0 ]]; then echo -e "${R}Harus ROOT! Jalankan: sudo bash $0${Z}"; exit 1; fi }

generate_uuid(){
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen
  else
    openssl rand -hex 16 | sed -r 's/^(.{8})(.{4})(.{4})(.{4})(.{12})$/\1-\2-\3-\4-\5/'
  fi
}

svc_restart(){ local svc="$1"; if systemctl list-units --type=service --all | grep -q "$svc"; then systemctl restart "$svc" >/dev/null 2>&1 || warn "Restart $svc failed"; else msg "$svc not found"; fi }

safe_jq_update(){ # args: sourcefile tmpfile jq_filter
  local src="$1" tmp="$2" filter="$3"
  if [[ ! -f "$src" ]]; then echo '{}'>"$src"; fi
  if jq "$filter" "$src" > "$tmp" 2>/dev/null; then mv "$tmp" "$src"; else warn "jq update failed for $src"; rm -f "$tmp"; fi
}

# ==================================================
# Install fullscreen deps (tmux dashboard)
# ==================================================
install_fullscreen_deps(){
    apt update -qq 2>/dev/null || true
    apt install -y tmux neofetch figlet lolcat boxes toilet htop glances nload speedtest-cli >/dev/null 2>&1 || true
    if ! command -v lolcat >/dev/null 2>&1; then
        if command -v gem >/dev/null 2>&1; then gem install lolcat >/dev/null 2>&1 || true; fi
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
        if command -v neofetch >/dev/null 2>&1; then neofetch --config '{"colors":{"title":5,"separator":5},"info":{"cpu":"off","memory":"off"}}' 2>/dev/null || true; else echo -e "${C}🌐 $(hostname) | $(uptime -p)${Z}"; fi

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

# ==================================================
# INSTALL FUNCTIONS
# ==================================================

# safe check ssl
check_ssl(){
  if [[ -z "${SSL_PATH:-}" || -z "${DOMAIN:-}" ]]; then return 1; fi
  [[ -f "${SSL_PATH}/fullchain.pem" && -f "${SSL_PATH}/privkey.pem" ]]
}

# Interactive initial domain/config prompt (adds domain before SSL check)
interactive_config_domain(){
    clear
    toilet -f mono12 -F gay "JP_V2 Setup" 2>/dev/null || true
    echo -e "${B}=== KONFIGURASI JP_V2 v1.0 ===${Z}"

    while true; do
        echo -ne "${Y}🔗 Masukkan DOMAIN Anda (contoh: vpn.example.com): ${Z}"
        read -r DOMAIN_INPUT || true
        DOMAIN_INPUT=${DOMAIN_INPUT:-$DOMAIN}
        if [[ -n "$DOMAIN_INPUT" && "$DOMAIN_INPUT" != *" "* ]]; then
            DOMAIN="$DOMAIN_INPUT"
            SSL_PATH="/etc/letsencrypt/live/$DOMAIN"
            ok "Domain: $DOMAIN"
            break
        else
            err "Domain tidak valid!"
        fi
    done

    echo -ne "${Y}🔐 SSH Port (default $SSH_PORT): ${Z}"; read -r SSH_PORT_INPUT || true; SSH_PORT=${SSH_PORT_INPUT:-$SSH_PORT}
    echo -ne "${Y}🌪️ Hysteria Port (default $HYSTERIA_PORT): ${Z}"; read -r HYSTERIA_PORT_INPUT || true; HYSTERIA_PORT=${HYSTERIA_PORT_INPUT:-$HYSTERIA_PORT}
    echo -ne "${Y}⚡ ZIPVPN Port (default $ZIPVPN_PORT): ${Z}"; read -r ZIPVPN_PORT_INPUT || true; ZIPVPN_PORT=${ZIPVPN_PORT_INPUT:-$ZIPVPN_PORT}

    TROJAN_PASS=${TROJAN_PASS:-$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-20)}
    HYSTERIA_PASS=${HYSTERIA_PASS:-$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-20)}
    ZIVPN_PASS=${ZIVPN_PASS:-$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-20)}

    echo -e "${G}✅ Password otomatis:${Z}"
    echo -e "${Y}Trojan: $TROJAN_PASS${Z}"
    echo -e "${Y}Hysteria: $HYSTERIA_PASS${Z}"
    echo -e "${Y}ZIVPN: $ZIVPN_PASS${Z}"

    echo -ne "${Y}Lanjutkan instalasi? (y/n): ${Z}"; read -r confirm || true
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && { err "Install dibatalkan!"; exit 1; }

    # write config
    cat > /root/jp_v1-config.sh <<EOF
#!/bin/bash
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
    ok "Konfigurasi disimpan di /root/jp_v1-config.sh"
    sleep 1
}

# Install SSH multi (dropbear + wstunnel)
install_ssh_multi(){
    msg "🚀 Menginstal SSH Multi-Fungsi (Dropbear + WS Tunnel)"
    apt install -y dropbear >/dev/null 2>&1 || warn "dropbear install failed"
    echo "DROPBEAR_PORTS=\"$DROPBEAR_PORT1 $DROPBEAR_PORT2\"" > /etc/default/dropbear
    sed -i 's/#DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-w"/' /etc/default/dropbear || true
    systemctl restart dropbear >/dev/null 2>&1 || true
    systemctl enable dropbear >/dev/null 2>&1 || true

    # wstunnel
    mkdir -p /usr/local/bin
    if [[ ! -f /usr/local/bin/wstunnel ]]; then
        wget -q https://github.com/erebe/wstunnel/releases/latest/download/wstunnel-x86_64-unknown-linux-musl -O /usr/local/bin/wstunnel || true
        chmod +x /usr/local/bin/wstunnel || true
    fi

    # create service units
    cat > /etc/systemd/system/ssh-ws-tls.service <<EOF
[Unit]
Description=SSH WS TLS (JP_V2)
After=network.target nginx.service
[Service]
ExecStart=/usr/local/bin/wstunnel client ws://127.0.0.1:$SSH_PORT --listen 127.0.0.1:$XRAY_VMESS_PORT
Restart=always
User=nobody
[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/ssh-ws-non-tls.service <<EOF
[Unit]
Description=SSH WS Non-TLS (JP_V2)
After=network.target nginx.service
[Service]
ExecStart=/usr/local/bin/wstunnel client ws://127.0.0.1:$SSH_PORT --listen 127.0.0.1:$WS_SSH_PORT
Restart=always
User=nobody
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload || true
    systemctl enable ssh-ws-tls ssh-ws-non-tls >/dev/null 2>&1 || true
    systemctl restart ssh-ws-tls ssh-ws-non-tls >/dev/null 2>&1 || true
    ok "✅ SSH Multi-Fungsi terinstal!"
}

# ==================================================
# install_all_services - main installer
# ==================================================
install_all_services(){
    clear
    toilet -f mono12 -F gay "JP_V2 Install" 2>/dev/null || true
    msg "🚀 Memulai Instalasi JP_V2 FULL..."
    check_root

    if [[ -f /root/jp_v1-installed.flag ]]; then
        echo -ne "${Y}JP_V2 sudah terinstal. Reinstal? (y/n): ${Z}"; read -r reinstall || true
        [[ "$reinstall" != "y" && "$reinstall" != "Y" ]] && { ok "Instalasi dibatalkan."; return; }
        rm -f /root/jp_v1-installed.flag
    fi

    # prompt domain/config if config missing
    if [[ ! -f /root/jp_v1-config.sh ]]; then
        interactive_config_domain
    else
        source /root/jp_v1-config.sh || true
    fi

    # SSL check and obtain if missing
    if ! check_ssl; then
        warn "Sertifikat SSL untuk $DOMAIN tidak ditemukan. Mencoba memperoleh dengan Certbot..."
        if ! command -v certbot >/dev/null 2>&1; then
            apt install -y snapd >/dev/null 2>&1 || true
            snap install core >/dev/null 2>&1 || true
            snap install --classic certbot >/dev/null 2>&1 || true
            ln -s /snap/bin/certbot /usr/bin/certbot 2>/dev/null || true
        fi
        certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos --email admin@${DOMAIN} || warn "Certbot failed, lanjut dengan konfigurasi manual"
        if ! check_ssl; then
            err "Gagal memperoleh sertifikat SSL untuk $DOMAIN. Pastikan DNS mengarah ke server Anda. Lanjutkan? (y/n)"
            read -r cont || true
            [[ "$cont" != "y" && "$cont" != "Y" ]] && exit 1
        else
            ok "Sertifikat SSL berhasil diperoleh!"
        fi
    fi

    # Core dependencies
    msg "Menginstal dependensi inti..."
    apt update -y >/dev/null 2>&1 || true
    apt upgrade -y >/dev/null 2>&1 || true
    apt install -y curl wget git unzip jq nginx ufw socat vnstat openssl iptables-persistent >/dev/null 2>&1 || true

    # Timezone
    ln -sf /usr/share/zoneinfo/Asia/Jakarta /etc/localtime 2>/dev/null || true

    # Xray core
    msg "Menginstal Xray Core..."
    if ! command -v xray >/dev/null 2>&1; then
        bash -c "$(curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)" @ install >/dev/null 2>&1 || warn "Xray install script failed"
    fi

    # Hysteria
    msg "Menginstal Hysteria..."
    if [[ ! -f /usr/local/bin/hysteria ]]; then
        wget -qO /usr/local/bin/hysteria "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64" || true
        chmod +x /usr/local/bin/hysteria || true
    fi
    mkdir -p /etc/hysteria
    cat > /etc/hysteria/config.json <<EOF
{
  "listen": ":$HYSTERIA_PORT",
  "tls": {"cert": "$SSL_PATH/fullchain.pem", "key": "$SSL_PATH/privkey.pem"},
  "auth": {"mode": "password", "config": {}},
  "obfs": {"type": "wechat-video", "password": "obfs123"}
}
EOF
    cat > /etc/systemd/system/hysteria.service <<EOF
[Unit]
Description=Hysteria V1
After=network.target
[Service]
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.json
Restart=always
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload || true
    systemctl enable hysteria >/dev/null 2>&1 || true
    systemctl restart hysteria >/dev/null 2>&1 || true

    # ZIPVPN (zivpn)
    msg "Menginstal ZIPVPN..."
    if [[ ! -d /etc/zivpn ]]; then
        mkdir -p /etc/zivpn
    fi
    # try to fetch install if external script exists, otherwise create minimal config
    if ! command -v zivpn >/dev/null 2>&1; then
        cd /tmp || true
        rm -f zi.sh 2>/dev/null || true
        wget -q -O zi.sh https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/zi.sh || true
        bash zi.sh >/dev/null 2>&1 || true
    fi
    if [[ ! -f /etc/zivpn/config.json ]]; then
        echo '{"users":{},"port":'$ZIPVPN_PORT',"tls":true}' > /etc/zivpn/config.json
    else
        # ensure port set
        jq --arg p "$ZIPVPN_PORT" '.port = ($p|tonumber)' /etc/zivpn/config.json > /tmp/zivpn_port.json && mv /tmp/zivpn_port.json /etc/zivpn/config.json || true
    fi
    # set cert paths
    jq --arg cert "$SSL_PATH/fullchain.pem" --arg key "$SSL_PATH/privkey.pem" '.cert=$cert | .key=$key' /etc/zivpn/config.json > /tmp/zivpn_cert.json && mv /tmp/zivpn_cert.json /etc/zivpn/config.json 2>/dev/null || true
    # set admin password
    tmpfile=$(mktemp)
    jq --arg pass "$ZIVPN_PASS" '.users.admin = {"password":$pass,"limit_up":100,"limit_down":100}' /etc/zivpn/config.json > "$tmpfile" && mv "$tmpfile" /etc/zivpn/config.json || true

    # Nginx config
    msg "Mengkonfigurasi Nginx..."
    cat > /etc/nginx/sites-available/jp_v2 <<'NGINXCONF'
server {
    listen 80; listen [::]:80;
    server_name DOMAIN_PLACEHOLDER;
    location /ssh-ws {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:WS_SSH_PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
    }
    location / { return 301 https://$server_name$request_uri; }
}

server {
    listen 443 ssl http2; listen [::]:443 ssl http2;
    server_name DOMAIN_PLACEHOLDER;
    ssl_certificate SSL_FULLCHAIN_PLACEHOLDER;
    ssl_certificate_key SSL_PRIVKEY_PLACEHOLDER;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;
    add_header Strict-Transport-Security "max-age=63072000" always;

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
    location /ssh-ws-tls {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:XRAY_VMESS_PORT_PLACEHOLDER;
        proxy_http_version 1.1;
