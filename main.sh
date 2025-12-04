#!/bin/bash 
# ================================================================================================ 
# JP_V1 v1.0 - ULTIMATE CLI PANEL + SCREEN TERMINAL (TMUX + SPLITSCREEN + LIVE STATS) 
# Layanan: SSH Multi + Xray + Hysteria + ZIPVPN | UI: Neofetch + Boxes + Lolcat + Tmux Fullscreen 
# ================================================================================================ 
 
# ================================================== 
# LOAD CONFIG & INSTALL UI DEPS 
# ================================================== 
if [[ -f /root/jp_v1-config.sh ]]; then 
    source /root/jp_v1-config.sh 
fi 
 
# Super Colors 
R="\033[1;31m" G="\033[1;32m" Y="\033[1;33m" B="\033[1;34m" P="\033[1;35m"  
C="\033[1;36m" W="\033[1;37m" Z="\033[0m" 
 
install_fullscreen_deps() { 
    apt update -qq 2>/dev/null 
    apt install -y tmux neofetch figlet lolcat boxes toilet htop glances nload speedtest-cli 2>/dev/null 
    gem install lolcat 2>/dev/null || snap install lolcat 2>/dev/null 2>/dev/null 
} 
 
# ================================================== 
# FULLSCREEN TMUX DASHBOARD SETUP 
# ================================================== 
setup_fullscreen_dashboard() { 
    install_fullscreen_deps 
     
    # Kill existing JP_V1 sessions 
    tmux kill-session -t JP_V1 2>/dev/null 
     
    # Create main fullscreen session 
    tmux new-session -d -s JP_V1 'clear; bash /root/jp_v1.sh --dashboard' 
     
    # Split screen layout 
    tmux split-window -h -t JP_V1:0.0 'watch -n 2 "ss -tuln | grep -E \"(22|$SSH_PORT|80|443|$DROPBEAR_PORT1|$DROPBEAR_PORT2|$HYSTERIA_PORT|$ZIPVPN_PORT)\" | lolcat"' 
    tmux split-window -v -t JP_V1:0.1 'watch -n 3 "htop -C --no-header --no-bold -d 10 | head -20 | lolcat"' 
    tmux split-window -v -t JP_V1:0.2 'watch -n 5 "glances --tree | head -15 | lolcat"' 
     
    # Main window menu 
    tmux select-pane -t JP_V1:0.0 
    tmux resize-pane -x 120 -y 35 
    tmux attach-session -t JP_V1 
} 
 
# ================================================== 
# FULLSCREEN DASHBOARD INTERFACE 
# ================================================== 
dashboard_fullscreen() { 
    clear 
    tput civis  # Hide cursor 
     
    while true; do 
        # Header dengan Neofetch mini 
        clear 
        echo -e "${RV}" 
        neofetch --config '{"colors":{"title":5,"separator":5},"info":{"cpu":"off","memory":"off"}}' 2>/dev/null || { 
            echo -e "${C}🌐 $(hostname) | $(uptime -p) | $(free -h | grep Mem | awk '{print $3\"/\"$2}')${Z}" 
        } 
         
        # Mega Banner 
        toilet -f slant "JP_V1 v1.0" | lolcat -a -s 120 
        figlet -f big "FULLSCREEN" | lolcat -s 200 
         
        # Live Stats Boxes 
        echo -e "${B}┌──────────────────────────────────────────────────────┐${Z}" 
        echo -e "${B}│${P}                    LIVE STATUS                       ${B}│${Z}" 
        echo -e "${B}├──────────────────────────────────────────────────────┤${Z}" 
         
        # Service Status 
        services=(xray nginx hysteria zivpn sshd dropbear wstunnel) 
        status_line="" 
        for svc in "${services[@]}"; do 
            st=$(systemctl is-active $svc 2>/dev/null) 
            [[ "$st" == "active" ]] && status_line+="${G}🔥" || status_line+="${R}❌" 
            status_line+=" $svc " 
        done 
        echo -e "${B}│${status_line}${B}│${Z}" 
         
        # Connection Stats 
        users=$(wc -l < /root/users.txt 2>/dev/null || echo 0) 
        conns=$(ss -tuln | wc -l) 
        ip=$(curl -s ifconfig.me 2>/dev/null || echo "N/A") 
        echo -e "${B}│${Y}Users:${G} $users ${Y}|${G} Ports:${Y} $conns ${Y}|${C} IP:${G} $ip ${B}│${Z}" 
        echo -e "${B}└──────────────────────────────────────────────────────┘${Z}\n" 
         
        # Fullscreen Menu dengan Boxes 
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
        read -r opt 
         
        case $opt in 
            1) install_all_services ;; 
            2) create_user ;; 
            3) check_expired ;; 
            4) renew_account ;; 
            5) install_ddos_protection ;; 
            6) 
                clear 
                echo -e "${P}📊 FULLSCREEN TRAFFIC MONITOR${Z}" 
                watch -n 1 "ss -tuln | grep -E '(22|$SSH_PORT|80|443|$DROPBEAR_PORT1|$DROPBEAR_PORT2|$HYSTERIA_PORT|$ZIPVPN_PORT)' | lolcat && echo && glances --tree | head -15 | lolcat" 
                ;; 
            7) 
                clear 
                echo -e "${P}🔐 SERVICE CONTROL${Z}" 
                systemctl list-units --type=service --state=running | grep -E "(xray|nginx|hysteria|zivpn|sshd|dropbear|wstunnel)" | lolcat 
                echo -ne "${Y}Service (restart/stop): ${Z}"; read svc 
                [[ -n $svc ]] && systemctl restart $svc && echo -e "${G}✅ $svc restarted${Z}" 
                sleep 3 
                ;; 
            8) zipvpn_pro_manager ;; 
            9) 
                timestamp=$(date +%Y%m%d-%H%M%S) 
                tar -czf "/root/jp_v1-backup-$timestamp.tar.gz" /etc/nginx /usr/local/etc/xray /etc/zivpn /root/users.txt /root/jp_v1-config.sh /etc/hysteria 2>/dev/null 
                echo -e "${G}💾 Backup: /root/jp_v1-backup-$timestamp.tar.gz${Z}" 
                ;; 
            10) 
                # Create trial users with specific usernames and passwords 
                for i in {1..5}; do 
                    trial_username="trial$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8 | tr '[:upper:]' '[:lower:]')" 
                    trial_password=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 12) 
                    create_user "$trial_username" "$trial_password" "3" 
                    echo -e "${G}🎁 Trial $i: ${trial_username}:${trial_password} (3 days)${Z}" 
                done 
                ;; 
            0) 
                echo -e "${C}👋 Keluar dari Fullscreen Mode...${Z}" 
                tput cnorm  # Show cursor 
                exit 0 
                ;; 
            *) echo -e "${R}❌ Pilihan tidak valid!${Z}"; sleep 1 ;; 
        esac 
         
        sleep 1 
    done 
} 
 
# ================================================== 
# MAIN PROGRAM LOGIC (SHARED FUNCTIONS) 
# ================================================== 
 
# Function to check if the script is run as root 
check_root() { 
    if [[ $EUID -ne 0 ]]; then 
        echo -e "${R}[!] Harus ROOT! Silakan jalankan dengan 'sudo bash $0'${Z}" 
        exit 1 
    fi 
} 
 
# Function to generate UUID 
generate_uuid() { 
    openssl rand -hex 16 | sed 's/\(.\{8\}\)\(.\{4\}\)\(.\{4\}\)\(.\{4\}\)\(.\{12\}\)/\1-\2-\3-\4-\5/g' 
} 
 
# Function to check SSL certificates 
check_ssl() { 
    if [[ ! -f "$SSL_PATH/fullchain.pem" || ! -f "$SSL_PATH/privkey.pem" ]]; then 
        return 1 
    fi 
    echo -e "${G}[✓] SSL OK: $DOMAIN${Z}" 
    return 0 
} 
 
# Interactive Configuration for first time setup 
interactive_config() { 
    clear 
    toilet -f mono12 -F gay "JP_V1 Setup" | lolcat 
    msg "=== KONFIGURASI JP_V1 v1.0 ===" 
    echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Z}" 
     
    while true; do 
        echo -n "${Y}🔗 Masukkan DOMAIN Anda (contoh: vpn.example.com): ${Z}"; read DOMAIN_INPUT 
        if [[ -n "$DOMAIN_INPUT" && "$DOMAIN_INPUT" != *" "* ]]; then 
            DOMAIN="$DOMAIN_INPUT" 
            SSL_PATH="/etc/letsencrypt/live/$DOMAIN" 
            ok "Domain: $DOMAIN" 
            break 
        else 
            err "❌ Domain tidak valid!" 
        fi 
    done 
     
    echo -n "${Y}🔐 SSH Port (default 2222): ${Z}"; read SSH_PORT_INPUT; SSH_PORT=${SSH_PORT_INPUT:-2222} 
    echo -n "${Y}🌪️ Hysteria Port (default 40000): ${Z}"; read HYSTERIA_PORT_INPUT; HYSTERIA_PORT=${HYSTERIA_PORT_INPUT:-40000} 
    echo -n "${Y}⚡ ZIPVPN Port (default 5667): ${Z}"; read ZIPVPN_PORT_INPUT; ZIPVPN_PORT=${ZIPVPN_PORT_INPUT:-5667} 
     
    TROJAN_PASS=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-20) 
    HYSTERIA_PASS=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-20) 
    ZIVPN_PASS=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-20) 
     
    echo -e "${G}✅ Password Otomatis:${Z}" 
    echo -e "${Y}Trojan: $TROJAN_PASS${Z}" 
    echo -e "${Y}Hysteria: $HYSTERIA_PASS${Z}" 
    echo -e "${Y}ZIVPN: $ZIVPN_PASS${Z}" 
     
    echo -n "${Y}Lanjutkan instalasi? (y/n): ${Z}"; read confirm 
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && { err "Install dibatalkan!"; exit 1; } 
     
    # Save config to a persistent file 
    cat > /root/jp_v1-config.sh << EOF 
#!/bin/bash 
export DOMAIN="$DOMAIN" 
export SSL_PATH="$SSL_PATH" 
export SSH_PORT="$SSH_PORT" 
export DROPBEAR_PORT1="442" 
export DROPBEAR_PORT2="109" 
export WS_TLS_PORT="443" 
export WS_NON_TLS_PORT="80" 
export XRAY_VMESS_PORT="10000" 
export XRAY_VLESS_PORT="10001" 
export XRAY_TROJAN_PORT="10002" 
export XRAY_UDP_PORT="10003" 
export WS_SSH_PORT="10004" 
export HYSTERIA_PORT="$HYSTERIA_PORT" 
export ZIPVPN_PORT="$ZIPVPN_PORT" 
export TROJAN_PASS="$TROJAN_PASS" 
export HYSTERIA_PASS="$HYSTERIA_PASS" 
export ZIVPN_PASS="$ZIVPN_PASS" 
EOF 
    source /root/jp_v1-config.sh 
    ok "✅ Konfigurasi disimpan di /root/jp_v1-config.sh" 
    sleep 2 
} 
 
# Install SSH Multi-Fungsi (OpenSSH, Dropbear, WebSocket Tunnel) 
install_ssh_multi() { 
    msg "🚀 Menginstal SSH Multi-Fungsi (WS TLS/Non-TLS + Dropbear + UDP)..." 
     
    # Install Dropbear 
    apt install -y dropbear >/dev/null 2>&1 
    echo "DROPBEAR_PORTS=\"$DROPBEAR_PORT1 $DROPBEAR_PORT2\"" > /etc/default/dropbear 
    sed -i 's/#DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-w"/' /etc/default/dropbear # Enable password auth 
    systemctl restart dropbear >/dev/null 2>&1 
    systemctl enable dropbear >/dev/null 2>&1 
     
    # Install wstunnel 
    cd /usr/local/bin || exit 
    wget -q https://github.com/erebe/wstunnel/releases/latest/download/wstunnel-x86_64-unknown-linux-musl -O wstunnel 
    chmod +x wstunnel 
     
    # Setup wstunnel services 
    cat > /etc/systemd/system/ssh-ws-tls.service << EOF 
[Unit] 
Description=JP_V1 SSH over WebSocket TLS (Port 443 proxy to SSH) 
After=network.target nginx.service 
 
[Service] 
ExecStart=/usr/local/bin/wstunnel client ws://127.0.0.1:$SSH_PORT --listen 127.0.0.1:$XRAY_VMESS_PORT 
Restart=always 
User=nobody 
 
[Install] 
WantedBy=multi-user.target 
EOF 
 
    cat > /etc/systemd/system/ssh-ws-non-tls.service << EOF 
[Unit] 
Description=JP_V1 SSH over WebSocket Non-TLS (Port 80 proxy to SSH) 
After=network.target nginx.service 
 
[Service] 
ExecStart=/usr/local/bin/wstunnel client ws://127.0.0.1:$SSH_PORT --listen 127.0.0.1:$WS_SSH_PORT 
Restart=always 
User=nobody 
 
[Install] 
WantedBy=multi-user.target 
EOF 
     
    systemctl daemon-reload 
    systemctl enable ssh-ws-tls ssh-ws-non-tls 
    systemctl restart ssh-ws-tls ssh-ws-non-tls 
     
    # Update Nginx config for SSH WebSocket paths 
    # Nginx config is part of install_all_services 
     
    ok "✅ SSH Multi-Fungsi terinstal!" 
} 
 
# All Services Installer 
install_all_services() { 
    clear 
    toilet -f mono12 -F gay "JP_V1 Install" | lolcat 
    msg "🚀 Memulai Instalasi JP_V1 v1.0 FULL..." 
    check_root 
     
    if [[ -f /root/jp_v1-installed.flag ]]; then 
        echo -n "${Y}JP_V1 sudah terinstal. Reinstal? (y/n): ${Z}"; read reinstall 
        [[ "$reinstall" != "y" && "$reinstall" != "Y" ]] && { ok "Instalasi dibatalkan."; return; } 
        rm -f /root/jp_v1-installed.flag 2>/dev/null 
    fi 
     
    [[ ! -f /root/jp_v1-config.sh ]] && interactive_config || source /root/jp_v1-config.sh 
     
    if ! check_ssl; then 
        warn "Sertifikat SSL untuk $DOMAIN tidak ditemukan. Mencoba memperoleh dengan Certbot..." 
        if ! command -v certbot &>/dev/null; then 
            apt install -y snapd >/dev/null 2>&1 
            snap install core >/dev/null 2>&1 
            snap install --classic certbot >/dev/null 2>&1 
            ln -s /snap/bin/certbot /usr/bin/certbot 2>/dev/null 
        fi 
        certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos --email admin@"$DOMAIN" 
        if [[ $? -ne 0 ]]; then 
            err "Gagal memperoleh sertifikat SSL untuk $DOMAIN. Mohon pastikan domain sudah terhubung ke IP VPS Anda." 
            err "Coba secara manual: certbot certonly --standalone -d $DOMAIN" 
            exit 1 
        fi 
        ok "Sertifikat SSL berhasil diperoleh!" 
    fi 
    check_ssl || { err "SSL check failed after attempt."; exit 1; } 
 
    # Core Dependencies 
    msg "Menginstal dependensi inti..." 
    apt update -y >/dev/null 2>&1 
    apt upgrade -y >/dev/null 2>&1 
    apt install -y curl wget git unzip jq nginx ufw socat vnstat openssl iptables-persistent >/dev/null 2>&1 
     
    # Timezone 
    ln -sf /usr/share/zoneinfo/Asia/Jakarta /etc/localtime >/dev/null 2>&1 
     
    # Xray Core 
    msg "Menginstal Xray Core..." 
    bash -c "$(curl -L https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)" @ install >/dev/null 2>&1 
     
    # Hysteria V1 
    msg "Menginstal Hysteria V1..." 
    wget -qO /usr/local/bin/hysteria "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64" 
    chmod +x /usr/local/bin/hysteria 
    mkdir -p /etc/hysteria 
    cat > /etc/hysteria/config.json << EOF 
{ 
  "listen": ":$HYSTERIA_PORT", 
  "tls": {"cert": "$SSL_PATH/fullchain.pem", "key": "$SSL_PATH/privkey.pem"}, 
  "auth": {"mode": "password", "config": {}}, 
  "obfs": {"type": "wechat-video", "password": "obfs123"} 
} 
EOF 
    cat > /etc/systemd/system/hysteria.service << EOF 
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
     
    # ZIPVPN (ZIVPN) 
    msg "Menginstal ZIPVPN..." 
    cd /tmp && rm -f zi.sh && wget -O zi.sh https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/zi.sh && bash zi.sh >/dev/null 2>&1 
    sed -i "s/port = .*/port = $ZIPVPN_PORT/" /etc/zivpn/config.json 2>/dev/null || echo '{"port":'$ZIPVPN_PORT',"tls":true}' > /etc/zivpn/config.json 
    sed -i 's/"tls": false/"tls": true/' /etc/zivpn/config.json 2>/dev/null 
    sed -i "s|\"cert\":.*|\"cert\": \"$SSL_PATH/fullchain.pem\"|" /etc/zivpn/config.json 2>/dev/null 
    sed -i "s|\"key\":.*|\"key\": \"$SSL_PATH/privkey.pem\"|" /etc/zivpn/config.json 2>/dev/null 
    jq --arg pass "$ZIVPN_PASS" '.users.admin = {"password": $pass, "limit_up": 100, "limit_down": 100}' /etc/zivpn/config.json > /tmp/config.json && mv /tmp/config.json /etc/zivpn/config.json 
     
    # Nginx Configuration (for Xray & SSH WS) 
    msg "Mengkonfigurasi Nginx..." 
    cat > /etc/nginx/sites-available/jp_v1 << EOF 
server { 
    listen $WS_NON_TLS_PORT; listen [::]:$WS_NON_TLS_PORT; 
    server_name $DOMAIN; 
     
    location /ssh-ws { 
        proxy_redirect off; 
        proxy_pass http://127.0.0.1:$WS_SSH_PORT; 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade \$http_upgrade; 
        proxy_set_header Connection "upgrade"; 
        proxy_set_header Host \$http_host; 
    } 
     
    location / { return 301 https://\$server_name\$request_uri; } 
} 
 
server { 
    listen 443 ssl http2; listen [::]:443 ssl http2; 
    server_name $DOMAIN; 
     
    ssl_certificate $SSL_PATH/fullchain.pem; 
    ssl_certificate_key $SSL_PATH/privkey.pem; 
    ssl_protocols TLSv1.2 TLSv1.3; 
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256; 
    ssl_prefer_server_ciphers on; 
    add_header Strict-Transport-Security "max-age=63072000" always; 
     
    location /vmess-ws { 
        proxy_redirect off; 
        proxy_pass http://127.0.0.1:$XRAY_VMESS_PORT; 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade \$http_upgrade; 
        proxy_set_header Connection "upgrade"; 
        proxy_set_header Host \$http_host; 
        proxy_set_header X-Real-IP \$remote_addr; 
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; 
    } 
    location /vless-ws { 
        proxy_redirect off; 
        proxy_pass http://127.0.0.1:$XRAY_VLESS_PORT; 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade \$http_upgrade; 
        proxy_set_header Connection "upgrade"; 
        proxy_set_header Host \$http_host; 
        proxy_set_header X-Real-IP \$remote_addr; 
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; 
    } 
    location /trojan-ws { 
        proxy_redirect off; 
        proxy_pass http://127.0.0.1:$XRAY_TROJAN_PORT; 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade \$http_upgrade; 
        proxy_set_header Connection "upgrade"; 
        proxy_set_header Host \$http_host; 
        proxy_set_header X-Real-IP \$remote_addr; 
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; 
    } 
    location /ssh-ws-tls { 
        proxy_redirect off; 
        proxy_pass http://127.0.0.1:$XRAY_VMESS_PORT; # Redirect to the same port as vmess 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade \$http_upgrade; 
        proxy_set_header Connection "upgrade"; 
        proxy_set_header Host \$http_host; 
    } 
    location / { 
        root /var/www/html; 
        index index.html; 
    } 
} 
EOF 
    rm -f /etc/nginx/sites-enabled/default 
    ln -sf /etc/nginx/sites-available/jp_v1 /etc/nginx/sites-enabled/ 
    mkdir -p /var/www/html 
    echo "<h1>JP_V1 v1.0 is Active!</h1>" > /var/www/html/index.html 
    nginx -t >/dev/null 2>&1 && systemctl restart nginx >/dev/null 2>&1 && systemctl enable nginx >/dev/null 2>&1 
     
    # Xray Configuration 
    msg "Mengkonfigurasi Xray..." 
    cat > /usr/local/etc/xray/config.json << EOF 
{ 
  "log": {"loglevel": "warning"}, 
  "inbounds": [ 
    {"port":$XRAY_VMESS_PORT,"protocol":"vmess","settings":{"clients":[]},"streamSettings":{"network":"ws","wsSettings":{"path":"/vmess-ws"}}}, 
    {"port":$XRAY_VLESS_PORT,"protocol":"vless","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"ws","wsSettings":{"path":"/vless-ws"}}}, 
    {"port":$XRAY_TROJAN_PORT,"protocol":"trojan","settings":{"clients":[]},"streamSettings":{"network":"ws","wsSettings":{"path":"/trojan-ws"}}}, 
    {"port":$XRAY_UDP_PORT,"protocol":"dokodemo-door","settings":{"network":"udp","followRedirect":true},"tag":"udp_in"} 
  ], 
  "outbounds":[ 
    {"protocol":"freedom","tag":"direct"}, 
    {"protocol":"blackhole","tag":"blocked"} 
  ], 
  "routing": { 
    "rules": [ 
      {"type": "field","ip": ["geoip:private"],"outboundTag": "blocked"}, 
      {"type": "field","protocol": ["udp"],"inboundTag": ["udp_in"],"outboundTag": "direct"} 
    ], 
    "domainStrategy": "AsIs" 
  } 
} 
EOF 
    systemctl restart xray >/dev/null 2>&1 && systemctl enable xray >/dev/null 2>&1 
 
    # SSH & Dropbear 
    msg "Mengkonfigurasi SSH dan Dropbear..." 
    sed -i "s/^#*Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config 
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config 
    echo "DROPBEAR_PORTS=\"$DROPBEAR_PORT1 $DROPBEAR_PORT2\"" > /etc/default/dropbear 
    sed -i 's/#DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-w"/' /etc/default/dropbear 
    systemctl restart sshd dropbear >/dev/null 2>&1 && systemctl enable sshd dropbear >/dev/null 2>&1 
 
    # Install SSH Multi-Fungsi utilities 
    install_ssh_multi # This will configure wstunnel for SSH WS. 
 
    # Firewall 
    msg "Mengkonfigurasi Firewall (UFW & Iptables)..." 
    ufw disable >/dev/null 2>&1 
    iptables -F # Clear existing rules from ddos protection if any 
     
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 
    iptables -A INPUT -p tcp --dport "$DROPBEAR_PORT1" -j ACCEPT 
    iptables -A INPUT -p tcp --dport "$DROPBEAR_PORT2" -j ACCEPT 
    iptables -A INPUT -p tcp --dport "$WS_NON_TLS_PORT" -j ACCEPT # For SSH WS Non-TLS 
    iptables -A INPUT -p tcp --dport "$WS_TLS_PORT" -j ACCEPT     # For SSH WS TLS & Xray 
    iptables -A INPUT -p udp --dport "$HYSTERIA_PORT" -j ACCEPT 
    iptables -A INPUT -p udp --dport "$ZIPVPN_PORT" -j ACCEPT 
    iptables -A INPUT -p udp --dport "$XRAY_UDP_PORT" -j ACCEPT   # For Xray Dokodemo-door UDP 
    iptables -A INPUT -p tcp -m state --state NEW -m recent --set 
    iptables -A INPUT -p tcp -m state --state NEW -m recent --update --seconds 60 --hitcount 50 -j DROP # Basic rate limiting 
    netfilter-persistent save >/dev/null 2>&1 
 
    # Create user database if not exists 
    touch /root/users.txt 
     
    # Enable all services 
    systemctl daemon-reload 
    systemctl enable xray nginx hysteria zivpn sshd dropbear ssh-ws-tls ssh-ws-non-tls 
    systemctl restart xray nginx hysteria zivpn sshd dropbear ssh-ws-tls ssh-ws-non-tls 
 
    # Final touch 
    touch /root/jp_v1-installed.flag 
    clear 
    toilet -f standard "JP_V1 Ready!" | lolcat 
    echo -e "${G}🎉 JP_V1 v1.0 FULLY INSTALLED!${Z}" 
    echo -e "${Y}SSH: $SSH_PORT | Dropbear: $DROPBEAR_PORT1,$DROPBEAR_PORT2 | WS TLS: $WS_TLS_PORT/ssh-ws-tls | ZIPVPN: $ZIPVPN_PASS${Z}" 
    sleep 5 
} 
 
# Create Multi-Fungsi User 
create_user() { 
    clear 
    toilet -f mini -F gay "Create User" | lolcat 
    msg "👤 CREATE MULTI-FUNKSI USER (SSH+Dropbear+WS+UDP+Xray+Hysteria+ZIPVPN)" 
    echo -n "${Y}Username: ${Z}"; read user 
    echo -n "${Y}Password: ${Z}"; read -s pass; echo 
    echo -n "${Y}Masa Aktif (hari): ${Z}"; read days; days=${days:-30} 
     
    if [[ -z "$user" || -z "$pass" ]]; then err "❌ Username atau Password tidak boleh kosong!"; sleep 2; return; fi 
    if id "$user" &>/dev/null; then err "❌ User $user sudah ada!"; sleep 2; return; fi 
     
    expire=$(date -d "$days days" +%s) 
    uuid=$(generate_uuid) 
     
    # 1. SSH & Dropbear User 
    useradd -m -s /bin/bash "$user" >/dev/null 2>&1 
    echo "$user:$pass" | chpasswd >/dev/null 2>&1 
     
    # 2. ZIPVPN User (1 Device Lock by protocol behavior) 
    jq --arg u "$user" --arg p "$pass" '.users[$u]={"password":$p,"limit_up":100,"limit_down":100}' /etc/zivpn/config.json > /tmp/z.json && mv /tmp/z.json /etc/zivpn/config.json 
     
    # 3. Xray User (VMess, VLESS, Trojan - all with same UUID/pass) 
    # Reconstruct Xray config to add clients dynamically 
    local xray_config_path="/usr/local/etc/xray/config.json" 
    local current_xray_config=$(cat "$xray_config_path") 
    local updated_xray_config=$(echo "$current_xray_config" | jq --arg uuid "$uuid" --arg user "$user" --arg pass "$TROJAN_PASS" ' 
        .inbounds[0].settings.clients += [ {"id":$uuid, "email":$user} ] 
        | .inbounds[1].settings.clients += [ {"id":$uuid, "email":$user, "level":0} ] 
        | .inbounds[2].settings.clients += [ {"password":$pass, "email":$user} ] # Trojan uses global pass for now 
    ') 
    echo "$updated_xray_config" > "$xray_config_path" 
     
    # 4. Hysteria User 
    jq --arg u "$user" --arg p "$pass" '.auth.config[$u]=$p' /etc/hysteria/config.json > /tmp/h.json && mv /tmp/h.json /etc/hysteria/config.json 
     
    # Save to /root/users.txt (format: user:pass:expire_timestamp:uuid) 
    echo "$user:$pass:$expire:$uuid" >> /root/users.txt 
     
    # Generate client config file 
    create_client_config "$user" "$pass" "$uuid" "$days" 
     
    systemctl restart xray zivpn hysteria >/dev/null 2>&1 
    ok "✅ User $user CREATED (Multi-Mode) | Config: /root/clients/$user-multi.txt" 
    sleep 3 
} 
 
# Create Client Config 
create_client_config() { 
    local user=$1 pass=$2 uuid=$3 days=$4 
    local IP=$(curl -s ifconfig.me) 
    mkdir -p /root/clients 2>/dev/null 
     
    cat > "/root/clients/${user}-multi.txt" << EOF 
# ==================================================================================================== 
# JP_V1 v1.0 - Multi-Mode Client Config for: $user 
# Expired: $(date -d "@$(( $(date +%s) + days*86400 ))" '+%Y-%m-%d') | IP: $IP | Domain: $DOMAIN 
# ==================================================================================================== 
 
**1️⃣ DIRECT SSH (Untuk Termux/PuTTY/KPN Rev)** 
Host: $IP 
Port: $SSH_PORT 
Username: $user 
Password: $pass 
 
**2️⃣ DROPBEAR SSH (Untuk HTTP Custom/KPN Tunnel)** 
Host: $IP 
Port: $DROPBEAR_PORT1 (Default HTTP Custom SSH Port) 
Port Alternatif: $DROPBEAR_PORT2 
Username: $user 
Password: $pass 
 
**3️⃣ SSH WEBSOCKET TLS (Untuk HTTP Custom/KPN Rev, dll)** 
Server Address: $DOMAIN 
Server Port: $WS_TLS_PORT 
WebSocket Path: /ssh-ws-tls 
SSL/TLS: ON (SNI: $DOMAIN) 
Username: $user 
Password: $pass 
 
**4️⃣ SSH WEBSOCKET NON-TLS (Untuk HTTP Custom/KPN Rev, dll)** 
Server Address: $DOMAIN 
Server Port: $WS_NON_TLS_PORT 
WebSocket Path: /ssh-ws 
SSL/TLS: OFF 
Username: $user 
Password: $pass 
 
**5️⃣ XRAY VMESS WS TLS (Untuk V2RayNG/Nekobox/HTTP Custom)** 
vmess://$(echo -n '{"v":"2","ps":"JP_V1-VMess-'$user'","add":"'$DOMAIN'","port":"'$WS_TLS_PORT'","id":"'$uuid'","aid":"0","net":"ws","type":"none","host":"'$DOMAIN'","path":"/vmess-ws","tls":"tls","sni":"'$DOMAIN'"}' | base64 -w0) 
 
**6️⃣ XRAY VLESS WS TLS (Untuk V2RayNG/Nekobox/HTTP Custom)** 
vless://$uuid@$DOMAIN:$WS_TLS_PORT?encryption=none&security=tls&type=ws&host=$DOMAIN&path=/vless-ws&sni=$DOMAIN#JP_V1-VLESS-$user 
 
**7️⃣ XRAY TROJAN WS TLS (Untuk V2RayNG/Nekobox/HTTP Custom)** 
trojan://$TROJAN_PASS@$DOMAIN:$WS_TLS_PORT/?security=tls&type=ws&host=$DOMAIN&path=/trojan-ws&sni=$DOMAIN#JP_V1-Trojan-$user 
(Note: Trojan menggunakan password server global: $TROJAN_PASS) 
 
**8️⃣ HTTP CUSTOM UDP (Untuk aplikasi HTTP Custom fitur "UDP Custom")** 
Mode SSH-WS (TLS/Non-TLS) atau SSH-Dropbear 
Di HTTP Custom, centang "UDP Custom" atau "Enable DNS" 
Trafik UDP akan diteruskan melalui Xray Dokodemo-door. 
 
**9️⃣ HYSTERIA V1 (Untuk Hysteria Client)** 
Client Address: $DOMAIN 
Client Port: $HYSTERIA_PORT 
Password: $pass 
SNI: $DOMAIN 
(Note: Pastikan setting obfs = wechat-video, password = obfs123) 
 
**🔟 ZIPVPN (Untuk aplikasi ZIVPN/ZIPVPN - 1 Device Lock)** 
Server Address: $DOMAIN 
Server Port: $ZIPVPN_PORT 
Username: $user 
Password: $pass 
(Note: Fitur ini memastikan hanya 1 koneksi aktif per user/pass. Jika ada device kedua login, device pertama akan terputus.) 
 
==================================================================================================== 
EOF 
    chmod 644 "/root/clients/${user}-multi.txt" 
} 
 
# Check Expired Accounts & Auto-Delete 
check_expired() { 
    clear 
    toilet -f mini -F gay "Check Users" | lolcat 
    msg "📊 STATUS USER & AUTO CLEANUP (SEMUA LAYANAN)" 
    local now=$(date +%s) 
    local temp_users_file=$(mktemp) 
     
    printf "%-15s %-12s %-10s %-10s %-10s %-10s\n" "USERNAME" "STATUS" "SSH" "XRAY" "HYSTERIA" "ZIPVPN" | lolcat -a 
    echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Z}" 
     
    local found_users=0 
    while IFS=: read user pass expire uuid; do 
        found_users=1 
        if [[ $now -gt $expire ]]; then 
            echo -e "${R}⛔ ${user} EXPIRED! Dihapus dari semua layanan.${Z}" 
            # Delete from SSH/Dropbear 
            userdel -f "$user" 2>/dev/null 
            # Delete from ZIPVPN 
            jq "del(.users[\"$user\"])" /etc/zivpn/config.json > /tmp/z.json && mv /tmp/z.json /etc/zivpn/config.json 2>/dev/null 
            # Delete from Xray (VMess, VLESS, Trojan) 
            local xray_config_path="/usr/local/etc/xray/config.json" 
            local current_xray_config=$(cat "$xray_config_path") 
            local updated_xray_config=$(echo "$current_xray_config" | jq --arg user "$user" ' 
                .inbounds[0].settings.clients |= map(select(.email != $user)) 
                | .inbounds[1].settings.clients |= map(select(.email != $user)) 
                | .inbounds[2].settings.clients |= map(select(.email != $user)) 
            ') 
            echo "$updated_xray_config" > "$xray_config_path" 2>/dev/null 
            # Delete from Hysteria 
            jq --arg u "$user" 'del(.auth.config[$u])' /etc/hysteria/config.json > /tmp/h.json && mv /tmp/h.json /etc/hysteria/config.json 2>/dev/null 
             
            # Remove client config file 
            rm -f "/root/clients/${user}-multi.txt" 2>/dev/null 
        else 
            local days_left=$(( ($expire - $now) / 86400 )) 
            local status_text="${G}${days_left} hari${Z}" 
             
            # Check real service status for display 
            local ssh_stat=$(id "$user" &>/dev/null && echo "${G}OK${Z}" || echo "${R}ERR${Z}") 
            local xray_stat=$(grep -q "\"email\":\"$user\"" /usr/local/etc/xray/config.json &>/dev/null && echo "${G}OK${Z}" || echo "${R}ERR${Z}") 
            local hyst_stat=$(jq --arg u "$user" '.auth.config[$u]' /etc/hysteria/config.json &>/dev/null && echo "${G}OK${Z}" || echo "${R}ERR${Z}") 
            local zip_stat=$(jq --arg u "$user" '.users[$u]' /etc/zivpn/config.json &>/dev/null && echo "${G}OK${Z}" || echo "${R}ERR${Z}") 
 
            printf "%-15s %-12s %-10s %-10s %-10s %-10s\n" "$user" "$status_text" "$ssh_stat" "$xray_stat" "$hyst_stat" "$zip_stat" 
            echo "$user:$pass:$expire:$uuid" >> "$temp_users_file" 
        fi 
    done < /root/users.txt 
     
    if [[ $found_users -eq 0 ]]; then warn "Tidak ada user yang terdaftar."; fi 
     
    mv "$temp_users_file" /root/users.txt 
    systemctl restart xray zivpn hysteria >/dev/null 2>&1 
    echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Z}" 
    echo -e "${Y}Tekan Enter untuk lanjut...${Z}" 
    read -r 
} 
 
# Renew Account 
renew_account() { 
    clear 
    toilet -f mini -F gay "Renew User" | lolcat 
    echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Z}" 
    echo -n "${Y}Masukkan username yang akan diperpanjang: ${Z}"; read renew_user 
     
    local temp_users_file=$(mktemp) 
    local found_user_entry="" 
     
    while IFS=: read user pass expire uuid; do 
        if [[ "$user" == "$renew_user" ]]; then 
            found_user_entry="$user:$pass:$expire:$uuid" 
        else 
            echo "$user:$pass:$expire:$uuid" >> "$temp_users_file" 
        fi 
    done < /root/users.txt 
     
    if [[ -n "$found_user_entry" ]]; then 
        IFS=: read user pass expire uuid <<< "$found_user_entry" 
         
        local current_date=$(date -d "@$expire" "+%Y-%m-%d") 
        echo -e "${G}User ditemukan: $user${Z}" 
        echo -e "${Y}Masa aktif saat ini: $current_date (tersisa $(( (expire - $(date +%s)) / 86400 )) hari)${Z}" 
        echo -n "${Y}Tambahkan berapa hari lagi? (contoh: 30, default 30): ${Z}"; read add_days; add_days=${add_days:-30} 
         
        local new_expire_timestamp=$(( expire + (add_days * 86400) )) 
        echo "$user:$pass:$new_expire_timestamp:$uuid" >> "$temp_users_file" 
        mv "$temp_users_file" /root/users.txt 
         
        ok "✅ Masa aktif $user berhasil diperpanjang menjadi $(date -d "@$new_expire_timestamp" "+%Y-%m-%d") (+ $add_days hari)." 
    else 
        err "❌ User $renew_user tidak ditemukan." 
        rm "$temp_users_file" 
    fi 
    echo -e "${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${Z}" 
    echo -e "${Y}Tekan Enter untuk lanjut...${Z}" 
    read -r 
} 
 
# DDoS Protection Installer/Updater 
install_ddos_protection() { 
    clear 
    toilet -f mini -F gay "DDoS Protect" | lolcat 
    msg "🛡️ Menginstal dan Mengkonfigurasi Proteksi DDoS/DoS (Iptables & Fail2Ban)..." 
     
    # 1. Install iptables-persistent & Fail2Ban 
    apt install -y iptables-persistent fail2ban >/dev/null 2>&1 
     
    # 2. Iptables Rules 
    iptables -F 
    iptables -X 
    iptables -Z 
    iptables -t nat -F 
    iptables -t nat -X 
    iptables -t mangle -F 
    iptables -t mangle -X 
 
    iptables -P INPUT DROP 
    iptables -P FORWARD DROP 
    iptables -P OUTPUT ACCEPT 
 
    iptables -A INPUT -i lo -j ACCEPT 
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 
 
    # Proteksi SYN-Flood 
    iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -m limit --limit 25/s --limit-burst 50 -j ACCEPT 
    iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -j DROP 
 
    # Batasi koneksi baru per IP 
    iptables -I INPUT -p tcp -m conntrack --ctstate NEW -m recent --set 
    iptables -I INPUT -p tcp -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 50 -j DROP 
     
    # Proteksi SSH Brute-Force 
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW -m recent --set --name SSH --rsource 
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 5 --name SSH --rsource -j DROP 
 
    # Izinkan port layanan yang digunakan 
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 
    iptables -A INPUT -p tcp --dport "$DROPBEAR_PORT1" -j ACCEPT 
    iptables -A INPUT -p tcp --dport "$DROPBEAR_PORT2" -j ACCEPT 
    iptables -A INPUT -p tcp --dport "$WS_NON_TLS_PORT" -j ACCEPT 
    iptables -A INPUT -p tcp --dport "$WS_TLS_PORT" -j ACCEPT 
    iptables -A INPUT -p udp --dport "$HYSTERIA_PORT" -j ACCEPT 
    iptables -A INPUT -p udp --dport "$ZIPVPN_PORT" -j ACCEPT 
    iptables -A INPUT -p udp --dport "$XRAY_UDP_PORT" -j ACCEPT 
     
    iptables -A INPUT -j DROP # Drop sisa trafik 
     
    netfilter-persistent save >/dev/null 2>&1 
    netfilter-persistent reload >/dev/null 2>&1 
    ok "✅ Aturan iptables berhasil dikonfigurasi dan disimpan." 
 
    # 3. Fail2Ban 
    cat > /etc/fail2ban/jail.local << EOF 
[DEFAULT] 
bantime = 1h 
findtime = 10m 
maxretry = 5 
banaction = iptables-allports 
destemail = root@localhost 
 
[sshd] 
enabled = true 
port = $SSH_PORT 
logpath = /var/log/auth.log 
backend = systemd 
 
[nginx-http-auth] 
enabled = true 
port = http,https 
logpath = /var/log/nginx/error.log 
backend = auto 
EOF 
    systemctl enable fail2ban >/dev/null 2>&1 
    systemctl restart fail2ban >/dev/null 2>&1 
    ok "✅ Fail2Ban berhasil dikonfigurasi dan dijalankan." 
 
    ok "🛡️ Proteksi DDoS/DoS selesai dikonfigurasi!" 
    echo -e "${Y}Tekan Enter untuk lanjut...${Z}" 
    read -r 
} 
 
# ZIPVPN Pro Manager 
zipvpn_pro_manager() { 
    clear 
    toilet -f mini -F gay "ZIPVPN Manager" | lolcat 
    echo -e "${P}⚡ ZIPVPN 1-DEVICE MANAGER (Port $ZIPVPN_PORT)...${Z}" 
     
    boxes -d banner3-d -p a2x2 << EOF | lolcat 
1. 👥 LIST ACTIVE USERS 
2. ➕ ADD NEW USER (1 Device) 
3. ❌ DELETE USER 
4. 🔑 CHANGE PASSWORD (Kick All) 
5. 📊 CONNECTION STATUS 
6. ⚙️  FULL CONFIG 
7. 🔄 RESTART SERVICE 
0. ⬅️  BACK 
EOF 
     
    echo -ne "${Y}Pilih [0-7]: ${Z}"; read -r zip_opt 
    case $zip_opt in 
        1) 
            msg "👥 DAFTAR USER ZIPVPN:" 
            if jq -e '.users | keys | length > 0' /etc/zivpn/config.json >/dev/null; then 
                jq -r '.users | keys[] as $k | "  📱 \($k)"' /etc/zivpn/config.json | lolcat 
            else 
                warn "Tidak ada user ZIPVPN terdaftar." 
            fi 
            ;; 
        2) 
            echo -n "${Y}Username ZIPVPN baru: ${Z}"; read z_user 
            echo -n "${Y}Password ZIPVPN baru: ${Z}"; read -s z_pass; echo 
            if [[ -z "$z_user" || -z "$z_pass" ]]; then err "❌ Username/Password tidak boleh kosong!"; break; fi 
            jq --arg u "$z_user" --arg p "$z_pass" '.users[$u] = {"password": $p, "limit_up": 100, "limit_down": 100}' \ 
               /etc/zivpn/config.json > /tmp/zivpn_config.json && mv /tmp/zivpn_config.json /etc/zivpn/config.json 
            systemctl restart zivpn >/dev/null 2>&1 
            ok "✅ User $z_user ditambahkan ke ZIPVPN (1 Device Lock)!" 
            warn "Untuk manajemen user terintegrasi, gunakan 'Create Multi-Fungsi User' di menu utama." 
            ;; 
        3) 
            echo -n "${Y}Username ZIPVPN yang akan dihapus: ${Z}"; read z_user_del 
            if jq -e --arg u "$z_user_del" '.users[$u]' /etc/zivpn/config.json >/dev/null; then 
                jq --arg u "$z_user_del" 'del(.users[$u])' /etc/zivpn/config.json > /tmp/zivpn_config.json 
                mv /tmp/zivpn_config.json /etc/zivpn/config.json 
                systemctl restart zivpn >/dev/null 2>&1 
                ok "✅ User $z_user_del dihapus dari ZIPVPN!" 
            else 
                err "❌ User $z_user_del tidak ditemukan!" 
            fi 
            ;; 
        4) 
            echo -n "${Y}Username ZIPVPN yang akan diubah password-nya: ${Z}"; read z_user_chpass 
            echo -n "${Y}Password ZIPVPN baru: ${Z}"; read -s z_pass_new; echo 
            if jq -e --arg u "$z_user_chpass" '.users[$u]' /etc/zivpn/config.json >/dev/null; then 
                jq --arg u "$z_user_chpass" --arg p "$z_pass_new" '.users[$u].password = $p' \ 
                   /etc/zivpn/config.json > /tmp/zivpn_config.json && mv /tmp/zivpn_config.json /etc/zivpn/config.json 
                systemctl restart zivpn >/dev/null 2>&1 
                ok "✅ Password $z_user_chpass diubah! (Semua device lama akan DISCONNECT)" 
            else 
                err "❌ User $z_user_chpass tidak ditemukan!" 
            fi 
            ;; 
        5) 
            msg "📊 STATUS KONEKSI ZIPVPN AKTIF:" 
            ss -ulnp | grep "$ZIPVPN_PORT" || echo -e "${Y}Tidak ada koneksi aktif di port ZIPVPN.${Z}" 
            ;; 
        6) 
            msg "⚙️ KONFIGURASI ZIPVPN LENGKAP:" 
            jq . /etc/zivpn/config.json | lolcat 
            ;; 
        7) 
            systemctl restart zivpn >/dev/null 2>&1 
            systemctl status zivpn --no-pager -l | head -n 10 | lolcat 
            ok "✅ ZIPVPN di-restart!" 
            ;; 
        0) break ;; 
        *) err "❌ Pilihan tidak valid!" ;; 
    esac 
    echo -e "${Y}Tekan Enter untuk lanjut...${Z}" 
    read -r 
} 
 
# MAIN LOOP / LAUNCHER 
check_root 
 
# Argument parser untuk mode dashboard 
if [[ "$1" == "--dashboard" ]]; then 
    dashboard_fullscreen 
else 
    # Jika tidak dalam tmux, buat session dan attach 
    if [[ -z "$TMUX" ]]; then 
        setup_fullscreen_dashboard 
    else 
        # Jika sudah di dalam tmux, langsung tampilkan dashboard (misal dari pane lain) 
        dashboard_fullscreen 
    fi 
fi 

