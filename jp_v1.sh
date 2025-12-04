#!/bin/bash 
# ================================================================================================ 
# JP_V2 - FINAL FULL VERSION (1 FILE) 
# ================================================================================================ 
 
set -euo pipefail 
IFS=$'\n\t' 
 
# ================================================== 
# LOAD CONFIG (if exists) 
# ================================================== 
# Memuat konfigurasi dari file jika ada. 
# Jika tidak ada, variabel akan menggunakan nilai default yang didefinisikan nanti. 
if [[ -f /root/jp_v1-config.sh ]]; then 
    source /root/jp_v1-config.sh 
fi 
 
# ================================================== 
# DEFAULTS 
# ================================================== 
# Mendefinisikan port default dan password fallback jika belum diatur dalam konfigurasi. 
SSH_PORT=${SSH_PORT:-2222} 
DROPBEAR_PORT1=${DROPBEAR_PORT1:-442} 
DROPBEAR_PORT2=${DROPBEAR_PORT2:-109} 
WS_TLS_PORT=${WS_TLS_PORT:-443} # Umumnya digunakan Nginx, tidak langsung oleh wstunnel SSH 
WS_NON_TLS_PORT=${WS_NON_TLS_PORT:-80} # Umumnya digunakan Nginx 
XRAY_VMESS_PORT=${XRAY_VMESS_PORT:-10000} 
XRAY_VLESS_PORT=${XRAY_VLESS_PORT:-10001} 
XRAY_TROJAN_PORT=${XRAY_TROJAN_PORT:-10002} 
XRAY_UDP_PORT=${XRAY_UDP_PORT:-10003} # Port UDP untuk Xray (opsional, perlu konfigurasi Xray lebih lanjut) 
WS_SSH_PORT=${WS_SSH_PORT:-10004} # Port untuk SSH over WebSocket (Non-TLS, di belakang Nginx) 
HYSTERIA_PORT=${HYSTERIA_PORT:-40000} 
ZIPVPN_PORT=${ZIPVPN_PORT:-5667} 
 
# Generasi password yang lebih robust, atau fallback ke nilai statis. 
TROJAN_PASS=${TROJAN_PASS:-$(openssl rand -base64 12 2>/dev/null || echo "trojanfallbackpass")} 
HYSTERIA_PASS=${HYSTERIA_PASS:-$(openssl rand -base64 12 2>/dev/null || echo "hysteriafallbackpass")} 
ZIVPN_PASS=${ZIVPN_PASS:-$(openssl rand -base64 12 2>/dev/null || echo "zivpnfallbackpass")} 
 
DOMAIN=${DOMAIN:-} 
SSL_PATH=${SSL_PATH:-/etc/letsencrypt/live/${DOMAIN}} # Akan diperbarui jika DOMAIN diatur 
 
# File untuk menyimpan data pengguna 
USER_DB="/etc/jp_v2/users.db" 
# Direktori untuk data konfigurasi dan sertifikat 
CONFIG_DIR="/etc/jp_v2" 
 
# ================================================== 
# COLORS 
# ================================================== 
R="\033[1;31m" G="\033[1;32m" Y="\033[1;33m" C="\033[1;36m" W="\033[1;37m" Z="\033[0m" 
B="\033[1m" # Bold 
 
# ================================================== 
# Helpers 
# ================================================== 
# Fungsi untuk menampilkan pesan berwarna 
msg(){ echo -e "[${C}..${Z}] $*"; } 
ok(){ echo -e "[${G}OK${Z}] $*"; } 
err(){ echo -e "[${R}ERR${Z}] $*"; } 
warn(){ echo -e "[${Y}WARN${Z}] $*"; } 
 
# Memastikan skrip dijalankan sebagai root 
check_root(){ 
    if [[ $EUID -ne 0 ]]; then 
        err "HARUS DIJALANKAN SEBAGAI ROOT!" 
        exit 1 
    fi 
} 
 
# Membuat UUID secara cross-platform 
generate_uuid(){ 
  if command -v uuidgen >/dev/null 2>&1; then uuidgen; 
  else openssl rand -hex 16 | sed -r 's/^(.{8})(.{4})(.{4})(.{4})(.{12})$/\1-\2-\3-\4-\5/'; fi 
} 
 
# Restart layanan dengan penanganan error 
svc_restart(){ 
    local svc="$1" 
    msg "Mencoba restart $svc..." 
    if systemctl is-active --quiet "$svc"; then 
        systemctl restart "$svc" >/dev/null 2>&1 && ok "$svc berhasil direstart." || warn "Gagal restart $svc." 
    else 
        warn "$svc tidak aktif atau tidak ditemukan, mencoba start..." 
        systemctl start "$svc" >/dev/null 2>&1 && ok "$svc berhasil distart." || warn "Gagal start $svc." 
    fi 
} 
 
# Memeriksa keberadaan sertifikat SSL 
check_ssl(){ 
    [[ -f "${SSL_PATH}/fullchain.pem" && -f "${SSL_PATH}/privkey.pem" ]] 
} 
 
# ================================================== 
# DOMAIN CONFIGURATION 
# ================================================== 
interactive_config_domain(){ 
    clear 
    echo -e "${C}=== JP_V2 SETUP KONFIGURASI AWAL ===${Z}" 
 
    # Meminta domain dari pengguna 
    while true; do 
        echo -ne "${Y}Masukkan Domain (contoh: example.com): ${Z}" 
        read -r dom 
        dom="${dom,,}" # Konversi ke huruf kecil 
 
if?(\.?)*$ ]]; then
[[ -n "$dom" && "$dom" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])
            DOMAIN="$dom" 
            SSL_PATH="/etc/letsencrypt/live/$DOMAIN" 
            break 
        else 
            err "Domain tidak valid atau kosong! Harap masukkan domain yang benar." 
        fi 
    done 
 
    # Meminta input port dari pengguna atau menggunakan default 
    echo -ne "${Y}SSH Port [${SSH_PORT}]: ${Z}" 
    read -r a; SSH_PORT="${a:-$SSH_PORT}" 
 
    echo -ne "${Y}Dropbear Port 1 [${DROPBEAR_PORT1}]: ${Z}" 
    read -r b; DROPBEAR_PORT1="${b:-$DROPBEAR_PORT1}" 
 
    echo -ne "${Y}Dropbear Port 2 [${DROPBEAR_PORT2}]: ${Z}" 
    read -r c; DROPBEAR_PORT2="${c:-$DROPBEAR_PORT2}" 
 
    echo -ne "${Y}Hysteria Port [${HYSTERIA_PORT}]: ${Z}" 
    read -r d; HYSTERIA_PORT="${d:-$HYSTERIA_PORT}" 
 
    echo -ne "${Y}ZIPVPN Port [${ZIPVPN_PORT}]: ${Z}" 
    read -r e; ZIPVPN_PORT="${e:-$ZIPVPN_PORT}" 
 
    # Menggenerasi password baru untuk layanan 
    TROJAN_PASS=$(openssl rand -hex 16) 
    HYSTERIA_PASS=$(openssl rand -hex 16) 
    ZIVPN_PASS=$(openssl rand -hex 16) 
 
    # Menyimpan konfigurasi ke file agar persisten 
    mkdir -p "$CONFIG_DIR" # Pastikan direktori ada 
    cat > "$CONFIG_DIR/jp_v1-config.sh" <<EOF 
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
 
    source "$CONFIG_DIR/jp_v1-config.sh" # Memuat kembali konfigurasi yang baru disimpan 
    ok "Konfigurasi domain dan port berhasil disimpan di $CONFIG_DIR/jp_v1-config.sh!" 
} 
 
# ================================================== 
# INSTALL CORE PACKAGES 
# ================================================== 
install_core_packages(){ 
    msg "Memperbarui sistem dan menginstal paket dasar..." 
    apt update -y >/dev/null 2>&1 || warn "Gagal update apt." 
    apt install -y curl wget unzip jq nginx socat ufw iptables-persistent net-tools >/dev/null 2>&1 \ 
        || err "Gagal menginstal paket dasar. Pastikan koneksi internet stabil." 
 
    # Menyesuaikan zona waktu 
    ln -sf /usr/share/zoneinfo/Asia/Jakarta /etc/localtime && ok "Zona waktu diatur ke Asia/Jakarta." \ 
        || warn "Gagal mengatur zona waktu." 
} 
 
# ================================================== 
# INSTALL SSL CERTIFICATE (LETSENCRYPT) 
# ================================================== 
install_ssl(){ 
    if check_ssl; then 
        ok "Sertifikat SSL untuk $DOMAIN sudah ada." 
        return 0 
    fi 
 
    msg "Memperoleh sertifikat SSL untuk $DOMAIN menggunakan Certbot..." 
     
    # Instal snapd dan certbot 
    if ! command -v snap >/dev/null 2>&1; then 
        msg "Menginstal snapd..." 
        apt install -y snapd >/dev/null 2>&1 || err "Gagal menginstal snapd." 
        systemctl enable --now snapd apparmor >/dev/null 2>&1 
        snap install core >/dev/null 2>&1 
    fi 
    if ! command -v certbot >/dev/null 2>&1; then 
        msg "Menginstal Certbot..." 
        snap install --classic certbot >/dev/null 2>&1 
        ln -s /snap/bin/certbot /usr/bin/certbot 2>/dev/null || true # Buat symlink 
    fi 
 
    # Meminta sertifikat 
    certbot certonly --nginx \ 
        -d "$DOMAIN" \ 
        --non-interactive \ 
        --agree-tos \ 
        --email "admin@$DOMAIN" \ 
        --expand \ 
        --break-my-certs \ 
        --renew-by-default \ 
        --preferred-challenges http \ 
        --staple-ocsp \ 
        --rsa-key-size 4096 \ 
        --force-renewal || { err "Gagal memperoleh sertifikat SSL! Pastikan DNS A record sudah mengarah ke IP server ini dan port 80/443 tidak digunakan."; return 1; } 
 
    # Setup perpanjangan otomatis 
    if ! grep -q "certbot renew" /etc/crontab; then 
        echo "0 0 * * * root certbot renew --quiet --nginx" >> /etc/crontab 
    fi 
     
    ok "Sertifikat SSL berhasil diperoleh dan perpanjangan otomatis diatur." 
} 
 
# ================================================== 
# INSTALL NGINX 
# ================================================== 
install_nginx(){ 
    msg "Mengkonfigurasi Nginx..." 
 
    # Hapus konfigurasi default Nginx 
    rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default 
 
    # Buat konfigurasi Nginx untuk proxying WebSocket dan SSL 
    cat > /etc/nginx/sites-available/jp_v2 <<EOF 
server { 
    listen 80; 
    server_name ${DOMAIN}; 
 
    # Redirect semua HTTP ke HTTPS 
    location / { 
        return 301 https://${DOMAIN}\$request_uri; 
    } 
} 
 
server { 
    listen 443 ssl http2; 
    server_name ${DOMAIN}; 
 
    ssl_certificate     ${SSL_PATH}/fullchain.pem; 
    ssl_certificate_key ${SSL_PATH}/privkey.pem; 
    ssl_session_cache shared:SSL:10m; 
    ssl_session_timeout 10m; 
    ssl_protocols TLSv1.2 TLSv1.3; 
    ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"; 
    ssl_prefer_server_ciphers on; 
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"; 
    add_header X-Content-Type-Options nosniff; 
    add_header X-XSS-Protection "1; mode=block"; 
    add_header X-Frame-Options DENY; 
 
    # Xray VMess WebSocket 
    location /vmess-ws { 
        proxy_redirect off; 
        proxy_pass http://127.0.0.1:${XRAY_VMESS_PORT}; 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade \$http_upgrade; 
        proxy_set_header Connection "upgrade"; 
        proxy_set_header Host \$host; 
        proxy_set_header X-Real-IP \$remote_addr; 
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; 
    } 
 
    # Xray VLess WebSocket 
    location /vless-ws { 
        proxy_redirect off; 
        proxy_pass http://127.0.0.1:${XRAY_VLESS_PORT}; 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade \$http_upgrade; 
        proxy_set_header Connection "upgrade"; 
        proxy_set_header Host \$host; 
        proxy_set_header X-Real-IP \$remote_addr; 
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; 
    } 
 
    # Xray Trojan WebSocket 
    location /trojan-ws { 
        proxy_redirect off; 
        proxy_pass http://127.0.0.1:${XRAY_TROJAN_PORT}; 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade \$http_upgrade; 
        proxy_set_header Connection "upgrade"; 
        proxy_set_header Host \$host; 
        proxy_set_header X-Real-IP \$remote_addr; 
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; 
    } 
 
    # SSH WebSocket (TLS) 
    location /ssh-ws-tls { 
        proxy_redirect off; 
        proxy_pass http://127.0.0.1:${WS_SSH_PORT}; # wstunnel akan mendengarkan di port ini 
        proxy_http_version 1.1; 
        proxy_set_header Upgrade \$http_upgrade; 
        proxy_set_header Connection "upgrade"; 
        proxy_set_header Host \$host; 
        proxy_set_header X-Real-IP \$remote_addr; 
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; 
    } 
 
    # Default fallback - bisa menampilkan halaman error atau redirect 
    location / { 
        # Menampilkan halaman default atau error 404 
        return 404; 
    } 
} 
EOF 
 
    # Buat symlink ke sites-enabled dan restart Nginx 
    ln -sf /etc/nginx/sites-available/jp_v2 /etc/nginx/sites-enabled/jp_v2 
    nginx -t && svc_restart nginx || err "Nginx konfigurasi error, instalasi dibatalkan." 
     
    ok "Nginx berhasil dikonfigurasi." 
} 
 
# ================================================== 
# INSTALL DROPBEAR 
# ================================================== 
install_dropbear(){ 
    msg "Menginstal Dropbear..." 
 
    apt install -y dropbear >/dev/null 2>&1 || err "Gagal menginstal Dropbear." 
 
    # Konfigurasi Dropbear untuk mendengarkan di port yang ditentukan 
    echo "DROPBEAR_PORTS=\"${DROPBEAR_PORT1} ${DROPBEAR_PORT2}\"" > /etc/default/dropbear 
    # Opsi lain untuk Dropbear, misalnya agar tidak mengizinkan login root langsung (opsional) 
    sed -i 's/#DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-w -g"/' /etc/default/dropbear # -w: allow root login, -g: password login allowed 
     
    # Restart dan enable Dropbear 
    systemctl enable dropbear >/dev/null 2>&1 
    svc_restart dropbear 
 
    ok "Dropbear berhasil diinstal dan dikonfigurasi." 
} 
 
# ================================================== 
# INSTALL WSTUNNEL (SSH over WebSocket) 
# ================================================== 
install_wstunnel(){ 
    msg "Menginstal Wstunnel untuk SSH over WebSocket..." 
 
    mkdir -p /usr/local/bin 
 
    # Download wstunnel jika belum ada 
    if [[ ! -f /usr/local/bin/wstunnel ]]; then 
        msg "Mengunduh wstunnel binary..." 
        wget -q -O /usr/local/bin/wstunnel "https://github.com/erebe/wstunnel/releases/latest/download/wstunnel-x86_64-unknown-linux-musl" \ 
            || err "Gagal mengunduh wstunnel. Cek koneksi internet atau URL." 
        chmod +x /usr/local/bin/wstunnel 
    fi 
 
    # Konfigurasi systemd service untuk SSH WS Non-TLS (diakses Nginx melalui port 80) 
    cat > /etc/systemd/system/ssh-ws-non-tls.service <<EOF 
[Unit] 
Description=SSH WebSocket Non-TLS Listener 
After=network.target 
[Service] 
ExecStart=/usr/local/bin/wstunnel client ws://127.0.0.1:${SSH_PORT} --listen 127.0.0.1:${WS_SSH_PORT} --udp-port ${XRAY_UDP_PORT} 
Restart=always 
User=nobody 
[Install] 
WantedBy=multi-user.target 
EOF 
 
    # Konfigurasi systemd service untuk SSH WS TLS (langsung didengarkan oleh Nginx, bukan wstunnel) 
    # Catatan: Layanan ini sebenarnya tidak dibutuhkan jika Nginx proxy ke WS_SSH_PORT 
    # Namun, jika ingin membuat koneksi langsung (tanpa Nginx), bisa diaktifkan 
    # Untuk kasus ini, saya akan menganggap `WS_SSH_PORT` digunakan sebagai backend Nginx. 
    # Jika ingin wstunnel mendengarkan port 443 langsung, Nginx harus dinonaktifkan di port itu. 
    # Mempertimbangkan struktur Nginx yang ada, `ssh-ws-non-tls.service` sudah cukup. 
 
    systemctl daemon-reload 
    systemctl enable ssh-ws-non-tls >/dev/null 2>&1 
    svc_restart ssh-ws-non-tls 
 
    ok "Wstunnel (SSH over WebSocket) berhasil diinstal." 
} 
 
# ================================================== 
# INSTALL XRAY CORE 
# ================================================== 
install_xray(){ 
    msg "Menginstal Xray core..." 
    if ! command -v xray >/dev/null 2>&1; then 
        bash -c "$(curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)" @ install \ 
            || err "Gagal menginstal Xray core. Cek koneksi internet." 
    fi 
 
    mkdir -p /usr/local/etc/xray 
 
    # Membuat UUID baru untuk setiap protokol 
    UUID_VMESS=$(generate_uuid) 
    UUID_VLESS=$(generate_uuid) 
     
    # Konfigurasi Xray dengan VMess, VLess, dan Trojan (WebSocket) 
    cat > /usr/local/etc/xray/config.json <<EOF 
{ 
  "log": { 
    "loglevel": "warning" 
  }, 
  "inbounds": [ 
    { 
      "port": ${XRAY_VMESS_PORT}, 
      "listen": "127.0.0.1", 
      "protocol": "vmess", 
      "settings": { 
        "clients": [ 
          { "id": "${UUID_VMESS}", "alterId": 0 } 
        ] 
      }, 
      "streamSettings": { 
        "network": "ws", 
        "wsSettings": { 
          "path": "/vmess-ws", 
          "headers": { 
            "Host": "${DOMAIN}" 
          } 
        }, 
        "security": "none" 
      } 
    }, 
    { 
      "port": ${XRAY_VLESS_PORT}, 
      "listen": "127.0.0.1", 
      "protocol": "vless", 
      "settings": { 
        "clients": [ 
          { "id": "${UUID_VLESS}" } 
        ], 
        "decryption": "none" 
      }, 
      "streamSettings": { 
        "network": "ws", 
        "wsSettings": { 
          "path": "/vless-ws", 
          "headers": { 
            "Host": "${DOMAIN}" 
          } 
        }, 
        "security": "none" 
      } 
    }, 
    { 
      "port": ${XRAY_TROJAN_PORT}, 
      "listen": "127.0.0.1", 
      "protocol": "trojan", 
      "settings": { 
        "clients": [ 
          { "password": "${TROJAN_PASS}" } 
        ], 
        "fallbacks": [] 
      }, 
      "streamSettings": { 
        "network": "ws", 
        "wsSettings": { 
          "path": "/trojan-ws", 
          "headers": { 
            "Host": "${DOMAIN}" 
          } 
        }, 
        "security": "none" 
      } 
    } 
  ], 
  "outbounds": [ 
    { 
      "protocol": "freedom", 
      "settings": {} 
    }, 
    { 
      "protocol": "blackhole", 
      "settings": {}, 
      "tag": "blocked" 
    } 
  ], 
  "routing": { 
    "rules": [ 
      { 
        "type": "field", 
        "ip": [ 
          "geoip:private" 
        ], 
        "outboundTag": "blocked" 
      } 
    ] 
  } 
} 
EOF 
    # Memastikan Xray service aktif dan berjalan 
    systemctl enable xray >/dev/null 2>&1 
    svc_restart xray 
 
    ok "Xray berhasil diinstal dan dikonfigurasi." 
} 
 
# ================================================== 
# INSTALL HYSTERIA 
# ================================================== 
install_hysteria(){ 
    msg "Menginstal Hysteria..." 
 
    # Download Hysteria binary 
    if [[ ! -f /usr/local/bin/hysteria ]]; then 
        msg "Mengunduh hysteria binary..." 
        wget -q -O /usr/local/bin/hysteria "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64" \ 
            || err "Gagal mengunduh Hysteria. Cek koneksi internet atau URL." 
        chmod +x /usr/local/bin/hysteria 
    fi 
 
    mkdir -p /etc/hysteria 
     
    # Konfigurasi Hysteria server 
    cat > /etc/hysteria/config.json <<EOF 
{ 
  "listen": ":${HYSTERIA_PORT}", 
  "tls": { 
    "cert": "${SSL_PATH}/fullchain.pem", 
    "key": "${SSL_PATH}/privkey.pem" 
  }, 
  "auth": { 
    "mode": "password", 
    "config": { 
      "password": "${HYSTERIA_PASS}" 
    } 
  }, 
  "obfs": { "mode": "none" } # 'wechat-video' sudah deprecated di Hysteria v2, pakai mode: 'none' atau 'salamander' 
} 
EOF 
 
    # Systemd service untuk Hysteria 
    cat > /etc/systemd/system/hysteria.service <<EOF 
[Unit] 
Description=Hysteria Service 
After=network.target 
[Service] 
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.json 
Restart=always 
LimitNOFILE=65536 
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW 
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW 
NoNewPrivileges=true 
User=nobody 
[Install] 
WantedBy=multi-user.target 
EOF 
 
    systemctl daemon-reload 
    systemctl enable hysteria >/dev/null 2>&1 
    svc_restart hysteria 
 
    ok "Hysteria berhasil diinstal dan dikonfigurasi." 
} 
 
# ================================================== 
# INSTALL ZIPVPN 
# ================================================== 
install_zipvpn(){ 
    msg "Menginstal ZIPVPN..." 
 
    mkdir -p /etc/zivpn 
 
    # Instalasi script ZIPVPN dari zahidbd2 (jika belum ada) 
    if ! command -v zivpn >/dev/null 2>&1; then 
        msg "Mengunduh dan menjalankan script instalasi zivpn..." 
        (cd /tmp && wget -q -O zi.sh https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/zi.sh && bash zi.sh >/dev/null 2>&1) \ 
            || err "Gagal menginstal ZIPVPN dari zahidbd2. Cek koneksi internet." 
    fi 
 
    # Konfigurasi dasar zivpn 
    echo '{"users":{},"port":'"${ZIPVPN_PORT}"',"tls":true}' > /etc/zivpn/config.json 
 
    # Set sertifikat SSL untuk zivpn 
    # Pastikan file sertifikat sudah ada 
    if check_ssl; then 
        jq --arg cert "$SSL_PATH/fullchain.pem" \ 
           --arg key "$SSL_PATH/privkey.pem" \ 
           '.cert=$cert | .key=$key' \ 
           /etc/zivpn/config.json > /tmp/zv1.json && mv /tmp/zv1.json /etc/zivpn/config.json 
    else 
        warn "Sertifikat SSL tidak ditemukan untuk ZIPVPN, TLS mungkin tidak berfungsi." 
    fi 
 
    # Tambahkan user admin default 
    jq --arg pass "$ZIVPN_PASS" \ 
       '.users.admin={"password":$pass,"limit_up":100,"limit_down":100}' \ 
       /etc/zivpn/config.json > /tmp/zv2.json && mv /tmp/zv2.json /etc/zivpn/config.json 
 
    systemctl enable zivpn >/dev/null 2>&1 
    svc_restart zivpn 
 
    ok "ZIPVPN berhasil diinstal dan dikonfigurasi." 
} 
 
# ================================================== 
# DDOS PROTECTION (Basic Firewall Rules) 
# ================================================== 
install_ddos_protection(){ 
    msg "Mengaktifkan perlindungan DDoS dasar dengan UFW dan IPTables..." 
 
    # Pastikan UFW terinstal 
    if ! command -v ufw >/dev/null 2>&1; then 
        apt install -y ufw >/dev/null 2>&1 || err "Gagal menginstal UFW." 
    fi 
 
    ufw --force reset # Reset aturan UFW yang ada 
    ufw default deny incoming 
    ufw default allow outgoing 
 
    # Aturan untuk layanan yang digunakan 
    ufw allow 22/tcp comment 'Standard SSH Port' 
    ufw allow "$SSH_PORT/tcp" comment 'Custom SSH Port' 
    ufw allow "$DROPBEAR_PORT1/tcp" comment 'Dropbear Port 1' 
    ufw allow "$DROPBEAR_PORT2/tcp" comment 'Dropbear Port 2' 
    ufw allow 80/tcp comment 'HTTP for Certbot/Nginx' 
    ufw allow 443/tcp comment 'HTTPS for Nginx, Xray, Hysteria' 
    ufw allow "$HYSTERIA_PORT/udp" comment 'Hysteria UDP' 
    ufw allow "$ZIPVPN_PORT/udp" comment 'ZIPVPN UDP' 
    # Jika Xray UDP diaktifkan, tambahkan juga: 
    # ufw allow "$XRAY_UDP_PORT/udp" comment 'Xray UDP' 
 
    # Batasi koneksi SSH untuk mencegah brute-force 
    ufw limit 22/tcp 
    ufw limit "$SSH_PORT/tcp" 
    ufw limit "$DROPBEAR_PORT1/tcp" 
    ufw limit "$DROPBEAR_PORT2/tcp" 
 
    # Aktifkan UFW 
    ufw --force enable 
 
    # Aturan iptables tambahan untuk SYN flood dan paket invalid 
    iptables -A INPUT -p tcp --syn -m limit --limit 50/s --limit-burst 20 -j ACCEPT 
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP 
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 5 -j ACCEPT 
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP 
 
    # Simpan aturan iptables secara persisten 
    netfilter-persistent save >/dev/null 2>&1 
 
    ok "Perlindungan DDoS dasar aktif (UFW dan IPTables)." 
} 
 
# ================================================== 
# INSTALL ALL SERVICES (MAIN INSTALLATION FUNCTION) 
# ================================================== 
install_all_services(){ 
    clear 
    msg "Memulai instalasi JP_V2 full package..." 
    check_root 
 
    # Pastikan direktori konfigurasi ada 
    mkdir -p "$CONFIG_DIR" 
 
    # Muat atau buat konfigurasi domain 
    if [[ ! -f "$CONFIG_DIR/jp_v1-config.sh" ]]; then 
        warn "File konfigurasi tidak ditemukan, memulai setup interaktif." 
        interactive_config_domain 
    else 
        source "$CONFIG_DIR/jp_v1-config.sh" 
        ok "Konfigurasi dimuat dari $CONFIG_DIR/jp_v1-config.sh." 
    fi 
 
    # Urutan instalasi yang logis 
    install_core_packages 
    install_ssl || { err "Instalasi SSL gagal. Menghentikan proses."; exit 1; } 
    install_nginx 
    install_dropbear 
    install_wstunnel 
    install_xray 
    install_hysteria 
    install_zipvpn 
    install_ddos_protection # Terapkan setelah semua layanan terinstal agar portnya terbuka 
 
    ok "Semua layanan JP_V2 berhasil diinstal dan dikonfigurasi!" 
    display_connection_details 
} 
 
# ================================================== 
# DISPLAY CONNECTION DETAILS 
# ================================================== 
display_connection_details(){ 
    clear 
    echo -e "${C}=== DETAIL KONEKSI JP_V2 ===${Z}" 
    echo -e "${G}Domain: ${DOMAIN}${Z}" 
    echo -e "${G}IP Server: $(hostname -I | awk '{print $1}') ${Z}" 
    echo "" 
 
    echo -e "${Y}--- SSH & Dropbear ---${Z}" 
    echo -e "  Standard SSH: Port 22" 
    echo -e "  Custom SSH: Port ${SSH_PORT}" 
    echo -e "  Dropbear: Port ${DROPBEAR_PORT1}, ${DROPBEAR_PORT2}" 
    echo -e "  SSH over WS (Non-TLS via Nginx): ws://${DOMAIN}/ssh-ws-tls (Port 80)" 
    echo -e "  SSH over WS (TLS via Nginx): wss://${DOMAIN}/ssh-ws-tls (Port 443)" 
    echo "" 
 
    echo -e "${Y}--- Xray (WebSocket TLS via Nginx) ---${Z}" 
    echo -e "  VMess WS: wss://${DOMAIN}/vmess-ws" 
    echo -e "    UUID VMess: ${UUID_VMESS:-N/A (Generate ulang atau cek Xray config)}" 
    echo -e "  VLess WS: wss://${DOMAIN}/vless-ws" 
    echo -e "    UUID VLess: ${UUID_VLESS:-N/A (Generate ulang atau cek Xray config)}" 
    echo -e "  Trojan WS: wss://${DOMAIN}/trojan-ws" 
    echo -e "    Password Trojan: ${TROJAN_PASS}" 
    echo "" 
 
    echo -e "${Y}--- Hysteria V2 ---${Z}" 
    echo -e "  Server Address: ${DOMAIN}:${HYSTERIA_PORT}" 
    echo -e "  Password: ${HYSTERIA_PASS}" 
    echo -e "  Protokol: UDP" 
    echo "" 
 
    echo -e "${Y}--- ZIPVPN ---${Z}" 
    echo -e "  Server Address: ${DOMAIN}:${ZIPVPN_PORT}" 
    echo -e "  Password Admin: ${ZIVPN_PASS}" 
    echo -e "  Protokol: UDP/TLS" 
    echo "" 
    echo -e "${Y}Catatan: UUID Xray akan ditampilkan jika instalasi Xray berhasil menghasilkan config.json.${Z}" 
    echo "" 
    read -p "Tekan Enter untuk kembali ke menu utama..." 
} 
 
 
# ================================================== 
# USER MANAGEMENT (Refactor for robustness) 
# ================================================== 
# Membuat file database pengguna jika belum ada 
init_user_db(){ 
    mkdir -p "$(dirname "$USER_DB")" 
    touch "$USER_DB" 
} 
 
create_user_account(){ 
    clear 
    echo -e "${B}=== BUAT AKUN PENGGUNA ===${Z}" 
 
    read -p "Masukkan Username: " username 
    read -s -p "Masukkan Password: " password; echo 
    read -p "Masa Aktif (hari): " exp_days 
 
    # Validasi input 
    if [[ -z "$username" || -z "$password" || -z "$exp_days" ]]; then 
        err "Username, Password, dan Masa Aktif tidak boleh kosong!" 
        sleep 2 
        return 
    fi 
    if ! [[ "$exp_days" =~ ^[0-9]+$ ]] || (( exp_days < 1 )); then 
        err "Masa aktif harus berupa angka positif." 
        sleep 2 
        return 
    fi 
    if grep -q "^$username|" "$USER_DB"; then 
        warn "Username '$username' sudah ada. Silakan pilih username lain." 
        sleep 2 
        return 
    fi 
 
    # Hitung tanggal kedaluwarsa 
    local exp_timestamp=$(date -d "+$exp_days days" +%s) 
    local exp_date=$(date -d "@$exp_timestamp" +"%Y-%m-%d") 
 
    # Tambahkan pengguna ke sistem Linux 
    useradd -m "$username" -s /bin/bash >/dev/null 2>&1 || { err "Gagal membuat user sistem."; sleep 2; return; } 
    echo "$username:$password" | chpasswd || { err "Gagal mengatur password user sistem."; sleep 2; userdel -r "$username"; return; } 
 
    # Simpan informasi pengguna ke database 
    echo "$username|$password|$exp_date|$exp_timestamp" >> "$USER_DB" 
 
    ok "Akun pengguna '$username' berhasil dibuat!" 
    echo -e "${G}Username: ${username}${Z}" 
    echo -e "${G}Password: ${password}${Z}" 
    echo -e "${G}Masa Aktif: ${exp_date}${Z}" 
    sleep 3 
} 
 
list_users(){ 
    clear 
    echo -e "${B}=== DAFTAR PENGGUNA ===${Z}" 
    if [[ ! -s "$USER_DB" ]]; then 
        warn "Belum ada pengguna terdaftar." 
        sleep 2 
        return 
    fi 
 
    echo -e "${Y}--------------------------------------------------${Z}" 
    printf "%-15s %-15s %-15s\n" "USERNAME" "PASSWORD" "MASA AKTIF" 
    echo -e "${Y}--------------------------------------------------${Z}" 
    while IFS="|" read -r usr pass exp_date exp_ts; do 
        printf "%-15s %-15s %-15s\n" "$usr" "$pass" "$exp_date" 
    done < "$USER_DB" 
    echo -e "${Y}--------------------------------------------------${Z}" 
    read -p "Tekan Enter untuk melanjutkan..." 
} 
 
delete_user_account(){ 
    clear 
    echo -e "${B}=== HAPUS AKUN PENGGUNA ===${Z}" 
 
    read -p "Masukkan Username yang akan dihapus: " username 
 
    if [[ -z "$username" ]]; then 
        err "Username tidak boleh kosong!" 
        sleep 2 
        return 
    fi 
 
    if ! grep -q "^$username|" "$USER_DB"; then 
        warn "Username '$username' tidak ditemukan." 
        sleep 2 
        return 
    fi 
 
    # Hapus user dari sistem Linux 
    userdel -r "$username" >/dev/null 2>&1 || warn "Gagal menghapus user sistem '$username'." 
 
    # Hapus user dari database 
    sed -i "/^$username|/d" "$USER_DB" 
 
    ok "Akun pengguna '$username' berhasil dihapus." 
    sleep 2 
} 
 
manage_users(){ 
    while true; do 
        clear 
        echo -e "${B}=== MANAJEMEN PENGGUNA ===${Z}" 
        echo "1) Buat Akun Baru" 
        echo "2) Hapus Akun" 
        echo "3) Perpanjang Akun" 
        echo "4) Cek Akun Kadaluarsa" 
        echo "5) Tampilkan Semua Akun" 
        echo "0) Kembali ke Menu Utama" 
        echo -ne "${Y}Pilih opsi: ${Z}" 
        read -r user_opt 
 
        case $user_opt in 
            1) create_user_account ;; 
            2) delete_user_account ;; 
            3) renew_account ;; 
            4) check_expired ;; 
            5) list_users ;; 
            0) break ;; 
            *) err "Pilihan tidak valid!" ; sleep 1 ;; 
        esac 
    done 
} 
 
check_expired(){ 
    clear 
    echo -e "${B}=== CEK AKUN KADALUARSA ===${Z}" 
 
    if [[ ! -s "$USER_DB" ]]; then 
        warn "Belum ada pengguna terdaftar." 
        sleep 2 
        return 
    fi 
 
    local now_ts=$(date +%s) 
    local tmpfile=$(mktemp) 
    local expired_found=0 
 
    echo -e "${Y}--------------------------------------------------${Z}" 
    printf "%-15s %-15s %-15s\n" "USERNAME" "STATUS" "TANGGAL KADALUARSA" 
    echo -e "${Y}--------------------------------------------------${Z}" 
 
    while IFS="|" read -r usr pass exp_date exp_ts; do 
        if (( exp_ts < now_ts )); then 
            printf "${R}%-15s %-15s %-15s${Z}\n" "$usr" "KADALUARSA" "$exp_date" 
            # Hapus user dari sistem Linux 
            userdel -r "$usr" >/dev/null 2>&1 || warn "Gagal menghapus user sistem '$usr'." 
            expired_found=1 
        else 
            printf "%-15s %-15s %-15s\n" "$usr" "AKTIF" "$exp_date" 
            echo "$usr|$pass|$exp_date|$exp_ts" >> "$tmpfile" 
        fi 
    done < "$USER_DB" 
    echo -e "${Y}--------------------------------------------------${Z}" 
 
    if [[ "$expired_found" -eq 1 ]]; then 
        mv "$tmpfile" "$USER_DB" 
        ok "Akun kadaluarsa berhasil dibersihkan dan dihapus dari sistem." 
    else 
        rm "$tmpfile" 
        ok "Tidak ada akun kadaluarsa ditemukan." 
    fi 
    sleep 3 
} 
 
renew_account(){ 
    clear 
    echo -e "${B}=== PERPANJANG AKUN PENGGUNA ===${Z}" 
 
    if [[ ! -s "$USER_DB" ]]; then 
        warn "Belum ada pengguna terdaftar." 
        sleep 2 
        return 
    fi 
 
    read -p "Masukkan Username yang akan diperpanjang: " username 
    read -p "Tambahkan berapa hari masa aktif: " more_days 
 
    if [[ -z "$username" || -z "$more_days" ]]; then 
        err "Username dan jumlah hari tidak boleh kosong!" 
        sleep 2 
        return 
    fi 
    if ! [[ "$more_days" =~ ^[0-9]+$ ]] || (( more_days < 1 )); then 
        err "Jumlah hari harus berupa angka positif." 
        sleep 2 
        return 
    fi 
 
    local tmpfile=$(mktemp) 
    local found=0 
 
    while IFS="|" read -r usr pass exp_date exp_ts; do 
        if [[ "$usr" == "$username" ]]; then 
            found=1 
            local new_exp_ts=$(( exp_ts + (more_days * 86400) )) # Tambah hari dalam detik 
            local new_exp_date=$(date -d "@$new_exp_ts" +"%Y-%m-%d") 
            echo "$usr|$pass|$new_exp_date|$new_exp_ts" >> "$tmpfile" 
            ok "Akun '$usr' berhasil diperpanjang hingga: ${new_exp_date}" 
        else 
            echo "$usr|$pass|$exp_date|$exp_ts" >> "$tmpfile" 
        fi 
    done < "$USER_DB" 
 
    if [[ "$found" -eq 0 ]]; then 
        warn "Username '$username' tidak ditemukan." 
    else 
        mv "$tmpfile" "$USER_DB" 
    fi 
    sleep 3 
} 
 
# ================================================== 
# ZIPVPN MANAGER 
# ================================================== 
zipvpn_user_manager(){ 
    clear 
    echo -e "${C}=== ZIPVPN PENGATUR PENGGUNA ===${Z}" 
 
    read -p "Username ZIPVPN baru: " u 
    read -p "Password ZIPVPN: " p 
    read -p "Batas Upload (MB/s, default 30): " limit_up 
    read -p "Batas Download (MB/s, default 30): " limit_down 
 
    limit_up=${limit_up:-30} 
    limit_down=${limit_down:-30} 
 
    if [[ -z "$u" || -z "$p" ]]; then 
        err "Username dan password tidak boleh kosong!" 
        sleep 2 
        return 
    fi 
 
    local tmp=$(mktemp) 
    # Memodifikasi /etc/zivpn/config.json untuk menambahkan pengguna baru 
    jq --arg u "$u" --arg p "$p" \ 
       --argjson lu "$limit_up" --argjson ld "$limit_down" \ 
       '.users[$u] = {"password":$p,"limit_up":$lu,"limit_down":$ld}' \ 
       /etc/zivpn/config.json > "$tmp" 
 
    mv "$tmp" /etc/zivpn/config.json 
 
    svc_restart zivpn 
 
    ok "Pengguna ZIPVPN '$u' berhasil ditambahkan!" 
    echo -e "  Username: ${u}" 
    echo -e "  Password: ${p}" 
    echo -e "  Batas Up/Down: ${limit_up}MB/s / ${limit_down}MB/s" 
    sleep 3 
} 
 
# ================================================== 
# TRAFFIC MONITOR 
# ================================================== 
traffic_monitor(){ 
    clear 
    echo -e "${B}=== MONITOR TRAFFIC JARINGAN (Tekan Ctrl+C untuk keluar) ===${Z}" 
    echo -e "${Y}Monitoring koneksi aktif pada port terbuka:${Z}" 
    # Menggunakan `netstat` untuk melihat koneksi TCP dan UDP, diupdate setiap 1 detik 
    watch -n 1 'netstat -tnpul | grep -E "(${SSH_PORT}|${DROPBEAR_PORT1}|${DROPBEAR_PORT2}|80|443|${HYSTERIA_PORT}|${ZIPVPN_PORT}|${XRAY_VMESS_PORT}|${XRAY_VLESS_PORT}|${XRAY_TROJAN_PORT})" || echo "Tidak ada traffic yang relevan terdeteksi..."' 
    # Alternatif modern: ss 
    # watch -n 1 'ss -tnpul | grep -E "(${SSH_PORT}|${DROPBEAR_PORT1}|${DROPBEAR_PORT2}|80|443|${HYSTERIA_PORT}|${ZIPVPN_PORT}|${XRAY_VMESS_PORT}|${XRAY_VLESS_PORT}|${XRAY_TROJAN_PORT})" || echo "Tidak ada traffic yang relevan terdeteksi..."' 
} 
 
# ================================================== 
# SERVICE CONTROL PANEL 
# ================================================== 
service_panel(){ 
    while true; do 
        clear 
        echo -e "${B}=== KONTROL LAYANAN JP_V2 ===${Z}" 
        echo "1) Status Semua Layanan" 
        echo "2) Restart Nginx" 
        echo "3) Restart Xray" 
        echo "4) Restart Hysteria" 
        echo "5) Restart ZIPVPN" 
        echo "6) Restart Dropbear" 
        echo "7) Restart Wstunnel (SSH WS)" 
        echo "0) Kembali ke Menu Utama" 
        echo -ne "${Y}Pilih opsi: ${Z}" 
        read -r svc_opt 
 
        case $svc_opt in 
            1) 
                echo -e "${Y}--- Status Layanan ---${Z}" 
                systemctl status nginx xray hysteria zivpn dropbear ssh-ws-non-tls --no-pager 
                read -p "Tekan Enter untuk melanjutkan..." 
                ;; 
            2) svc_restart nginx ;; 
            3) svc_restart xray ;; 
            4) svc_restart hysteria ;; 
            5) svc_restart zivpn ;; 
            6) svc_restart dropbear ;; 
            7) svc_restart ssh-ws-non-tls ;; 
            0) break ;; 
            *) err "Pilihan tidak valid!" ; sleep 1 ;; 
        esac 
        sleep 2 # Beri waktu untuk membaca pesan OK/ERR 
    done 
} 
 
# ================================================== 
# BACKUP SYSTEM 
# ================================================== 
backup_system(){ 
    clear 
    echo -e "${Y}=== BACKUP / RESTORE KONFIGURASI JP_V2 ===${Z}" 
 
    echo "1) Buat Backup" 
    echo "2) Restore dari Backup" 
    echo "0) Kembali ke Menu Utama" 
    read -p "Pilih opsi: " opt 
 
    if [[ "$opt" == "1" ]]; then 
        local tstamp=$(date +%Y%m%d-%H%M%S) 
        local backup_file="/root/jp_v2-backup-$tstamp.tar.gz" 
        msg "Membuat backup ke $backup_file..." 
 
        # Pastikan direktori config ada sebelum backup 
        mkdir -p "$CONFIG_DIR" 
 
        tar -czf "$backup_file" \ 
            "$CONFIG_DIR/jp_v1-config.sh" \ 
            "$USER_DB" \ 
            /etc/xray \ 
            /etc/nginx \ 
            /etc/hysteria \ 
            /etc/zivpn \ 
            /etc/letsencrypt/live/"$DOMAIN" \ 
            /etc/letsencrypt/archive/"$DOMAIN" \ 
            /etc/default/dropbear \ 
            /etc/systemd/system/ssh-ws-non-tls.service \ 
            --exclude='*/log/*' \ 
            --exclude='*/cache/*' \ 
            --absolute-names \ 
            --ignore-failed-read \ 
            --warning=no-file-changed || warn "Ada beberapa file yang gagal di-backup." 
             
        ok "Backup berhasil dibuat: $backup_file" 
        sleep 3 
    elif [[ "$opt" == "2" ]]; then 
        read -p "Masukkan path lengkap file backup (.tar.gz): " file 
 
        if [[ ! -f "$file" ]]; then 
            err "File backup '$file' tidak ditemukan!" 
            sleep 2 
            return 
        fi 
 
        msg "Melakukan restore dari '$file'..." 
        # Hentikan layanan yang mungkin menulis ke file konfigurasi saat restore 
        systemctl stop nginx xray hysteria zivpn dropbear ssh-ws-non-tls >/dev/null 2>&1 || true 
 
        # Ekstrak backup 
        tar -xzf "$file" -C / --overwrite-dir \ 
            --warning=no-file-changed || { err "Gagal melakukan restore. Pastikan file backup valid."; sleep 3; return; } 
         
        # Muat ulang konfigurasi setelah restore 
        if [[ -f "$CONFIG_DIR/jp_v1-config.sh" ]]; then 
            source "$CONFIG_DIR/jp_v1-config.sh" 
        fi 
 
        # Restart layanan 
        svc_restart nginx 
        svc_restart xray 
        svc_restart hysteria 
        svc_restart zivpn 
        svc_restart dropbear 
        svc_restart ssh-ws-non-tls 
 
        ok "Restore berhasil! Layanan dihidupkan kembali." 
        read -p "Tekan Enter untuk menampilkan detail koneksi..." 
        display_connection_details 
    elif [[ "$opt" == "0" ]]; then 
        return 
    else 
        err "Pilihan tidak valid!" 
        sleep 1 
    fi 
} 
 
# ================================================== 
# TRIAL USER GENERATOR 
# ================================================== 
generate_trial_users(){ 
    clear 
    echo -e "${B}=== GENERATOR PENGGUNA UJI COBA ===${Z}" 
 
    read -p "Jumlah pengguna uji coba yang akan dibuat (default 5): " num_trials 
    num_trials=${num_trials:-5} 
 
    if ! [[ "$num_trials" =~ ^[0-9]+$ ]] || (( num_trials < 1 )); then 
        err "Jumlah harus berupa angka positif." 
        sleep 2 
        return 
    fi 
 
    echo -e "${Y}Membuat ${num_trials} pengguna uji coba (3 hari masa aktif):${Z}" 
    for (( i=1; i<=num_trials; i++ )); do 
        local trial_user="trial$(head /dev/urandom | tr -dc a-z0-9 | head -c 6)" 
        local trial_pass=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8) 
        local exp_date=$(date -d "+3 days" +"%Y-%m-%d") 
        local exp_ts=$(date -d "+3 days" +%s) 
 
        # Tambahkan pengguna ke sistem Linux 
        useradd -m "$trial_user" -s /bin/bash >/dev/null 2>&1 
        echo "$trial_user:$trial_pass" | chpasswd 
 
        # Simpan ke database pengguna 
        echo "$trial_user|$trial_pass|$exp_date|$exp_ts" >> "$USER_DB" 
        echo -e "${G}Trial $i: Username: ${trial_user}, Password: ${trial_pass}, Exp: ${exp_date}${Z}" 
    done 
    ok "${num_trials} pengguna uji coba berhasil dibuat." 
    sleep 5 
} 
 
# ================================================== 
# MAIN MENU 
# ================================================== 
menu(){ 
    init_user_db # Pastikan database user terinisialisasi 
    while true; do 
        clear 
        echo -e "${C}=== JP_V2 PANEL MANAJEMEN SERVER ===${Z}" 
        echo "1) Instalasi / Reinstalasi Semua Layanan" 
        echo "2) Manajemen Pengguna SSH" 
        echo "3) Manajemen Pengguna ZIPVPN" 
        echo "4) Monitor Traffic Jaringan" 
        echo "5) Kontrol Layanan (Start/Stop/Restart)" 
        echo "6) Perlindungan DDoS (UFW/IPTables)" 
        echo "7) Backup / Restore Konfigurasi" 
        echo "8) Generator Pengguna Uji Coba" 
        echo "0) Keluar" 
        echo -ne "${Y}Pilih opsi: ${Z}" 
        read -r opt 
 
        case $opt in 
            1) install_all_services ;; 
            2) manage_users ;; 
            3) zipvpn_user_manager ;; 
            4) traffic_monitor ;; 
            5) service_panel ;; 
            6) install_ddos_protection ;; 
            7) backup_system ;; 
            8) generate_trial_users ;; 
            0) ok "Terima kasih telah menggunakan JP_V2 Panel!"; exit 0 ;; 
            *) err "Pilihan tidak valid! Silakan coba lagi." ; sleep 1 ;; 
        esac 
    done 
} 
 
# ================================================== 
# FINAL SETUP AND START 
# ================================================== 
# Jika ada argumen --dashboard, jalankan mode dashboard (fungsi dashboard_fullscreen tidak didefinisikan dalam script ini, jadi ini placeholder) 
if [[ "${1:-}" == "--dashboard" ]]; then 
    warn "Mode dashboard belum diimplementasikan. Menjalankan menu utama." 
    menu 
else 
    menu 
fi 
 

