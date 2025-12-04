#!/bin/bash
# ==============================================================
# KONOH A FULL INSTALLER + PREMIUM PANEL (SSH + XRAY + TROJAN + SS2022)
# - Domain manual input
# - ACME cert via acme.sh (standalone)
# - Xray install (official xray install script)
# - Create/Delete/Renew/List/Online check for SSH, VMESS, VLESS, TROJAN, SS2022
# - KONOHA logo + Bandwidth realtime + Premium menu UI
# - For Debian/Ubuntu
# ==============================================================

set -euo pipefail
IFS=$'\n\t'

# -----------------------------
# Colors
# -----------------------------
RED='\e[1;31m'; GREEN='\e[0;32m'; YELLOW='\e[1;33m'
BLUE='\e[1;34m'; MAG='\e[1;35m'; NC='\e[0m'

# -----------------------------
# Helpers
# -----------------------------
err() { echo -e "${RED}[ERROR]${NC} $*"; }
info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

require_root() {
  if [ "$EUID" -ne 0 ]; then
    err "Please run as root."
    exit 1
  fi
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# -----------------------------
# Pre-check
# -----------------------------
require_root

# -----------------------------
# Ask domain (manual)
# -----------------------------
clear
cat <<'KONOHA_LOGO'
           .::::::::::::.
        .:::'.:::::::.`:::.
      .:::'  ':::::::'  `:::.
     :::''   .::::::::.   '':::
    :::     :::::::::::::     :::
    :::    :::::::::::::::    :::
    :::    :::::::::::::::    :::
     :::.   '::::::::::::'   .:::
      `:::..  `':::::::'`  ..:::'
        `:::::..      ..:::::'
           `'::::::::::::'`
                `'::::'`
KONOHA_LOGO

echo -ne "${YELLOW}Masukkan domain (FQDN) yang akan digunakan untuk Xray (contoh vpn.example.com): ${NC}"
read -r DOMAIN
if [[ -z "$DOMAIN" ]]; then
  err "Domain tidak boleh kosong."
  exit 1
fi
echo "$DOMAIN" > /etc/konoha_domain
info "Domain disimpan: $DOMAIN"

# -----------------------------
# Update & basic tools
# -----------------------------
info "Update & install basic packages..."
apt update -y
apt install -y curl wget socat cron jq unzip ca-certificates lsof net-tools procps iptables iproute2 bc vnstat openssl

# ensure vnstat db exists (optional)
if ! command_exists vnstat; then
  apt install -y vnstat
fi

# -----------------------------
# Check DNS A record
# -----------------------------
DNSIP=$(dig +short A "$DOMAIN" @1.1.1.1 | head -n1 || true)
MYIP=$(curl -s --max-time 10 ipv4.icanhazip.com || echo "")
info "Your VPS IP: $MYIP"
if [[ -z "$DNSIP" ]]; then
  warn "No A record found for $DOMAIN (DNS lookup empty). Make sure domain points to this VPS."
else
  if [[ "$DNSIP" != "$MYIP" ]]; then
    warn "Domain A record ($DNSIP) does not match VPS IP ($MYIP). Proceeding anyway."
  else
    info "Domain A record points to this VPS."
  fi
fi

# -----------------------------
# Install acme.sh for certs
# -----------------------------
info "Installing acme.sh..."
if ! command_exists acme.sh; then
  curl -s https://get.acme.sh | sh
  export PATH="$HOME/.acme.sh:$PATH"
fi
# ensure acme.sh available
if ! command_exists ~/.acme.sh/acme.sh && ! command_exists acme.sh; then
  warn "acme.sh not found after install. Continuing but cert issuance may fail."
fi

# -----------------------------
# Issue certificate (standalone)
# -----------------------------
info "Issuing certificate for $DOMAIN using acme.sh (standalone mode). Port 80 will be used temporarily."
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
~/.acme.sh/acme.sh --issue --standalone -d "$DOMAIN" --keylength ec-256 || {
  warn "acme.sh standalone failed. Trying RSA..."
  ~/.acme.sh/acme.sh --issue --standalone -d "$DOMAIN" || {
    err "Certificate issuance failed. You can later run: ~/.acme.sh/acme.sh --issue --standalone -d $DOMAIN"
  }
}

CERT_DIR="/root/.acme.sh/$DOMAIN"
if [ -f "$CERT_DIR/${DOMAIN}.cer" ]; then
  info "Certificate issued and stored in $CERT_DIR"
else
  warn "Certificate not available at expected path. Continuing but TLS might fail."
fi

# -----------------------------
# Install Xray core (official)
# -----------------------------
info "Installing Xray core..."
bash <(curl -sL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh) install <<'EOD'
1
EOD || true

# create xray dirs
mkdir -p /usr/local/etc/xray /var/log/xray /etc/xray

# -----------------------------
# Generate UUID helper
# -----------------------------
gen_uuid() {
  cat /proc/sys/kernel/random/uuid
}

# -----------------------------
# Create base xray config (WS + gRPC + Trojan + Shadowsocks)
# We'll make a conservative config:
# - inbound vless+ws on 443 (tls)
# - inbound vmess+ws on 80 (non-tls) — optional
# - inbound trojan on 443 (fallback via different path)
# - shadowsocks inbound on 1443 (example)
# -----------------------------
XCONF="/usr/local/etc/xray/config.json"
info "Creating base Xray config at $XCONF"

# prepare cert paths
if [ -f "$CERT_DIR/${DOMAIN}.cer" ] && [ -f "$CERT_DIR/${DOMAIN}.key" ]; then
  CERT_PEM="$CERT_DIR/${DOMAIN}.cer"
  KEY_PEM="$CERT_DIR/${DOMAIN}.key"
else
  # try default acme paths
  CERT_PEM="/root/.acme.sh/${DOMAIN}/${DOMAIN}.cer"
  KEY_PEM="/root/.acme.sh/${DOMAIN}/${DOMAIN}.key"
fi

cat > "$XCONF" <<EOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vless-ws"
        },
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "$CERT_PEM",
              "keyFile": "$KEY_PEM"
            }
          ]
        }
      }
    },
    {
      "port": 80,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vmess-ws"
        }
      }
    },
    {
      "port": 1443,
      "protocol": "shadowsocks",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "tcp"
      }
    },
    {
      "port": 8443,
      "protocol": "trojan",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/trojan-ws"
        },
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "$CERT_PEM",
              "keyFile": "$KEY_PEM"
            }
          ]
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "settings": {} },
    { "protocol": "blackhole", "tag": "blocked", "settings": {} }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": []
  }
}
EOF

chown -R root:root "$XCONF"
chmod 640 "$XCONF"

# -----------------------------
# Ensure systemd unit exists and enable
# -----------------------------
if systemctl list-unit-files | grep -q xray; then
  systemctl enable --now xray || true
else
  warn "Systemd xray unit not present. Please check Xray install."
fi

# -----------------------------
# Data storage for users (simple DB)
# -----------------------------
mkdir -p /etc/konoha
USERS_DB="/etc/konoha/users.json"
if [ ! -f "$USERS_DB" ]; then
  echo '{"ssh": [], "vmess": [], "vless": [], "trojan": [], "ss2022": []}' > "$USERS_DB"
fi

# function: save DB
save_db() {
  echo "$1" > "$USERS_DB"
}

# read db
read_db() {
  cat "$USERS_DB"
}

# -----------------------------
# Functions: SSH CRUD
# -----------------------------
add_ssh() {
  read -rp "Username: " USER
  read -rp "Password: " PASS
  read -rp "Active days: " DAYS
  EXP=$(date -d "+$DAYS days" +%Y-%m-%d)
  if id "$USER" >/dev/null 2>&1; then
    err "User $USER already exists."
    return 1
  fi
  useradd -m -s /bin/false "$USER"
  echo "${USER}:${PASS}" | chpasswd
  chage -E "$EXP" "$USER" || true
  info "SSH user $USER created, expires $EXP"
  # store to DB
  DB=$(read_db)
  NEWDB=$(echo "$DB" | jq --arg u "$USER" --arg p "$PASS" --arg e "$EXP" '.ssh += [{"user":$u,"pass":$p,"expire":$e}]')
  save_db "$NEWDB"
}

del_ssh() {
  read -rp "Username to delete: " USER
  if id "$USER" >/dev/null 2>&1; then
    userdel -r "$USER" || true
    info "User $USER deleted."
    DB=$(read_db)
    NEWDB=$(echo "$DB" | jq --arg u "$USER" '.ssh |= map(select(.user != $u))')
    save_db "$NEWDB"
  else
    warn "User $USER not found."
  fi
}

renew_ssh() {
  read -rp "Username to renew: " USER
  read -rp "Add days: " DAYS
  if id "$USER" >/dev/null 2>&1; then
    CUR=$(chage -l "$USER" | awk -F: '/Account expires/ {print $2}' | xargs)
    if [[ "$CUR" == "never" ]]; then
      NEW=$(date -d "+$DAYS days" +%Y-%m-%d)
    else
      NEW=$(date -d "$CUR +$DAYS days" +%Y-%m-%d 2>/dev/null || date -d "+$DAYS days" +%Y-%m-%d)
    fi
    chage -E "$NEW" "$USER" || true
    info "User $USER renewed until $NEW"
    # update DB
    DB=$(read_db)
    NEWDB=$(echo "$DB" | jq --arg u "$USER" --arg e "$NEW" '.ssh |= map(if .user==$u then .expire=$e else . end)')
    save_db "$NEWDB"
  else
    warn "User $USER not found."
  fi
}

list_ssh() {
  echo "=== Local system SSH users ==="
  awk -F: '$3>=1000{print $1}' /etc/passwd || true
  echo ""
  echo "=== DB-stored SSH users ==="
  jq -r '.ssh[] | "\(.user) \t expire:\(.expire)"' "$USERS_DB" || true
}

# -----------------------------
# Functions: Xray user management
# We'll manipulate /usr/local/etc/xray/config.json using jq:
# - add client objects to respective inbound settings.clients arrays
# After change, restart xray.
# -----------------------------
add_vless() {
  read -rp "Username: " USER
  UUID=$(gen_uuid)
  read -rp "Days active: " DAYS
  EXPIRE=$(date -d "+$DAYS days" +%Y-%m-%d)
  # client object
  CLIENT=$(jq -n --arg id "$UUID" --arg email "$USER" '{id:$id, email:$email}')
  # add to inbound vless (port 443)
  tmp=$(mktemp)
  jq --argjson c "$CLIENT" '.inbounds |= map(if .protocol=="vless" then .settings.clients += [$c] else . end)' "$XCONF" > "$tmp" && mv "$tmp" "$XCONF"
  info "VLESS user $USER ($UUID) added to config."
  # store user in DB
  DB=$(read_db)
  NEWDB=$(echo "$DB" | jq --arg u "$USER" --arg id "$UUID" --arg e "$EXPIRE" '.vless += [{"user":$u,"id":$id,"expire":$e}]')
  save_db "$NEWDB"
  systemctl restart xray || warn "xray restart may have failed"
  # output links
  DOMAIN2="$DOMAIN"
  UUID_ENC="$UUID"
  VLESS_LINK="vless://${UUID_ENC}@${DOMAIN2}:443?path=/vless-ws&security=tls&type=ws#${USER}"
  echo "VLESS link: $VLESS_LINK"
}

add_vmess() {
  read -rp "Username: " USER
  ID=$(gen_uuid)
  read -rp "Days active: " DAYS
  EXPIRE=$(date -d "+$DAYS days" +%Y-%m-%d)
  CLIENT=$(jq -n --arg id "$ID" --arg alterId "0" --arg email "$USER" '{id:$id, email:$email, alterId:(0|0)}')
  tmp=$(mktemp)
  jq --argjson c "$CLIENT" '.inbounds |= map(if .protocol=="vmess" then .settings.clients += [$c] else . end)' "$XCONF" > "$tmp" && mv "$tmp" "$XCONF"
  info "VMESS user $USER ($ID) added."
  DB=$(read_db)
  NEWDB=$(echo "$DB" | jq --arg u "$USER" --arg id "$ID" --arg e "$EXPIRE" '.vmess += [{"user":$u,"id":$id,"expire":$e}]')
  save_db "$NEWDB"
  systemctl restart xray || warn "xray restart may have failed"
  # create vmess link (basic)
  VMESS_JSON=$(jq -n --arg v "2" --arg id "$ID" --arg host "$DOMAIN" '{v:$v,ps:env.USER,add:$host,port:"80",id:$id,aid:"0",net:"ws",type:"none",host:$host,path:"/vmess-ws",tls:""}')
  VMESS_B64=$(echo -n "$VMESS_JSON" | base64 -w0)
  echo "vmess://$VMESS_B64"
}

add_trojan() {
  read -rp "Account name: " USER
  PASS=$(openssl rand -hex 12)
  read -rp "Days active: " DAYS
  EXPIRE=$(date -d "+$DAYS days" +%Y-%m-%d)
  CLIENT=$(jq -n --arg pass "$PASS" --arg email "$USER" '{password:$pass, email:$email}')
  tmp=$(mktemp)
  jq --argjson c "$CLIENT" '.inbounds |= map(if .protocol=="trojan" then .settings.clients += [$c] else . end)' "$XCONF" > "$tmp" && mv "$tmp" "$XCONF"
  info "Trojan account $USER with pass $PASS added."
  DB=$(read_db)
  NEWDB=$(echo "$DB" | jq --arg u "$USER" --arg p "$PASS" --arg e "$EXPIRE" '.trojan += [{"user":$u,"pass":$p,"expire":$e}]')
  save_db "$NEWDB"
  systemctl restart xray || warn "xray restart may have failed"
  TROJAN_LINK="trojan://${PASS}@${DOMAIN}:8443?path=/trojan-ws&security=tls&type=ws#${USER}"
  echo "Trojan link: $TROJAN_LINK"
}

add_ss2022() {
  read -rp "Account name: " USER
  PASS=$(openssl rand -base64 12)
  read -rp "Days active: " DAYS
  EXPIRE=$(date -d "+$DAYS days" +%Y-%m-%d)
  CLIENT=$(jq -n --arg method "2022-blake3-aes-128-gcm" --arg password "$PASS" --arg email "$USER" '{method:$method, password:$password, email:$email}')
  tmp=$(mktemp)
  jq --argjson c "$CLIENT" '.inbounds |= map(if .protocol=="shadowsocks" then .settings.clients += [$c] else . end)' "$XCONF" > "$tmp" && mv "$tmp" "$XCONF"
  info "Shadowsocks2022 user $USER added."
  DB=$(read_db)
  NEWDB=$(echo "$DB" | jq --arg u "$USER" --arg p "$PASS" --arg e "$EXPIRE" '.ss2022 += [{"user":$u,"pass":$p,"expire":$e}]')
  save_db "$NEWDB"
  systemctl restart xray || warn "xray restart may have failed"
  echo "SS2022 user:$USER password:$PASS"
}

# -----------------------------
# Delete generic xray user by type
# -----------------------------
del_xray_user() {
  read -rp "Type (vless/vmess/trojan/ss2022): " TYPE
  read -rp "Identifier (username): " USER
  case "$TYPE" in
    vless)
      # remove from DB
      DB=$(read_db)
      NEWDB=$(echo "$DB" | jq --arg u "$USER" '.vless |= map(select(.user != $u))')
      save_db "$NEWDB"
      # remove from config by matching email field
      tmp=$(mktemp)
      jq --arg u "$USER" '.inbounds |= map(if .settings and .settings.clients then (.settings.clients |= map(select(.email != $u))) else . end)' "$XCONF" > "$tmp" && mv "$tmp" "$XCONF"
      ;;
    vmess)
      DB=$(read_db)
      NEWDB=$(echo "$DB" | jq --arg u "$USER" '.vmess |= map(select(.user != $u))')
      save_db "$NEWDB"
      tmp=$(mktemp)
      jq --arg u "$USER" '.inbounds |= map(if .settings and .settings.clients then (.settings.clients |= map(select(.email != $u))) else . end)' "$XCONF" > "$tmp" && mv "$tmp" "$XCONF"
      ;;
    trojan)
      DB=$(read_db)
      NEWDB=$(echo "$DB" | jq --arg u "$USER" '.trojan |= map(select(.user != $u))')
      save_db "$NEWDB"
      tmp=$(mktemp)
      jq --arg u "$USER" '.inbounds |= map(if .settings and .settings.clients then (.settings.clients |= map(select(.email != $u))) else . end)' "$XCONF" > "$tmp" && mv "$tmp" "$XCONF"
      ;;
    ss2022)
      DB=$(read_db)
      NEWDB=$(echo "$DB" | jq --arg u "$USER" '.ss2022 |= map(select(.user != $u))')
      save_db "$NEWDB"
      tmp=$(mktemp)
      jq --arg u "$USER" '.inbounds |= map(if .settings and .settings.clients then (.settings.clients |= map(select(.email != $u))) else . end)' "$XCONF" > "$tmp" && mv "$tmp" "$XCONF"
      ;;
    *)
      warn "Unknown type"
      return 1
      ;;
  esac
  systemctl restart xray || warn "xray restart may have failed"
  info "Deleted $TYPE user $USER"
}

# -----------------------------
# Show all users
# -----------------------------
show_all_users() {
  echo "==== Users DB ===="
  jq -r '. | to_entries[] | "\(.key): \(.value | length) entries"' "$USERS_DB"
  echo ""
  jq -r '. | to_entries[] | "\(.key):\n"+(.value|map("  \(.user) | expire:\(.expire // \"-\")")|join("\n"))' "$USERS_DB"
}

# -----------------------------
# Check online users (based on access log)
# -----------------------------
check_online() {
  LOG="/var/log/xray/access.log"
  if [ ! -f "$LOG" ]; then
    warn "Log file $LOG not found."
    return 1
  fi
  echo "=== Active connections (last 200 lines) ==="
  tail -n 200 "$LOG" | awk '{print $1, $3, $7}' | sort | uniq -c | sort -nr | head -n 50
}

# -----------------------------
# Backup & Restore
# -----------------------------
backup_all() {
  TIMESTAMP=$(date +"%Y%m%d-%H%M")
  TAR="/root/konoha-backup-$TIMESTAMP.tar.gz"
  tar czf "$TAR" /usr/local/etc/xray /etc/konoha /etc/domain /etc/letsencrypt 2>/dev/null || true
  info "Backup created: $TAR"
}

restore_from() {
  read -rp "Path to backup tar.gz: " TARPATH
  if [ ! -f "$TARPATH" ]; then
    err "Backup not found."
    return 1
  fi
  tar xzf "$TARPATH" -C / 2>/dev/null || true
  info "Restore complete. Please verify configs and restart services."
}

# -----------------------------
# Panel script (final menu)
# -----------------------------
PANEL_DIR="/usr/local/konoha-panel"
mkdir -p "$PANEL_DIR"
cat > "$PANEL_DIR/menu.sh" <<'EOF'
#!/bin/bash
# KONOHA PANEL FRONTEND
RED='\e[1;31m'; GREEN='\e[0;32m'; YELLOW='\e[1;33m'; BLUE='\e[1;34m'; NC='\e[0m'
DOMAIN="$(cat /etc/konoha_domain 2>/dev/null || echo 'unknown')"

while true; do
  clear
  # Logo
  cat <<'KLOGO'
           .::::::::::::.
        .:::'.:::::::.`:::.
      .:::'  ':::::::'  `:::.
     :::''   .::::::::.   '':::
    :::     :::::::::::::     :::
    :::    :::::::::::::::    :::
    :::    :::::::::::::::    :::
     :::.   '::::::::::::'   .:::
      `:::..  `':::::::'`  ..:::'
        `:::::..      ..:::::'
           `'::::::::::::'`
                `'::::'`
KLOGO

  # bandwidth
  IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {print $5; exit}')
  IFACE=${IFACE:-eth0}
  rx1=$(cat /sys/class/net/$IFACE/statistics/rx_bytes 2>/dev/null || echo 0)
  tx1=$(cat /sys/class/net/$IFACE/statistics/tx_bytes 2>/dev/null || echo 0)
  sleep 1
  rx2=$(cat /sys/class/net/$IFACE/statistics/rx_bytes 2>/dev/null || echo 0)
  tx2=$(cat /sys/class/net/$IFACE/statistics/tx_bytes 2>/dev/null || echo 0)
  rx=$(( (rx2 - rx1) / 1024 ))
  tx=$(( (tx2 - tx1) / 1024 ))

  echo -e "${YELLOW}Domain:${GREEN} $DOMAIN ${NC}    ${YELLOW}BW:${GREEN} ↓${rx}KB/s ↑${tx}KB/s${NC}"
  echo "======================================================="
  echo -e "${BLUE} 1${NC}. SSH Management"
  echo -e "${BLUE} 2${NC}. XRAY Management"
  echo -e "${BLUE} 3${NC}. Add TROJAN / SS"
  echo -e "${BLUE} 4${NC}. Backup / Restore"
  echo -e "${BLUE} 5${NC}. Show All Users"
  echo -e "${BLUE} 6${NC}. Check Online"
  echo -e "${BLUE} 7${NC}. Restart Services"
  echo -e "${BLUE} 0${NC}. Exit"
  echo -n "Select: "
  read opt
  case $opt in
    1)
      /usr/local/konoha-panel/ssh_menu.sh
      ;;
    2)
      /usr/local/konoha-panel/xray_menu.sh
      ;;
    3)
      /usr/local/konoha-panel/add_trojan_ss.sh
      ;;
    4)
      /usr/local/konoha-panel/backup_menu.sh
      ;;
    5)
      jq -r '. | to_entries[] | "\(.key):\n"+(.value|map("  \(.user) | expire:\(.expire // \"-\")")|join("\n"))' /etc/konoha/users.json
      read -p "Press enter..."
      ;;
    6)
      tail -n 200 /var/log/xray/access.log 2>/dev/null | awk '{print $1,$3,$7}' | sort | uniq -c | sort -nr | head -n 40
      read -p "Press enter..."
      ;;
    7)
      systemctl restart xray dropbear || true
      echo "Services restarted"
      sleep 1
      ;;
    0) exit 0 ;;
    *) echo "Invalid"; sleep 1 ;;
  esac
done
EOF
chmod +x "$PANEL_DIR/menu.sh"

# SSH submenu
cat > "$PANEL_DIR/ssh_menu.sh" <<'EOF'
#!/bin/bash
. /usr/local/konoha-panel/env.sh 2>/dev/null || true
while true; do
  clear
  echo "SSH MANAGEMENT"
  echo "1) Add SSH user"
  echo "2) Delete SSH user"
  echo "3) Renew SSH user"
  echo "4) List SSH users"
  echo "0) Back"
  read -rp "Choice: " c
  case $c in
    1) /usr/local/konoha-panel/handlers.sh add_ssh ;;
    2) /usr/local/konoha-panel/handlers.sh del_ssh ;;
    3) /usr/local/konoha-panel/handlers.sh renew_ssh ;;
    4) /usr/local/konoha-panel/handlers.sh list_ssh ;;
    0) break ;;
    *) echo "Invalid"; sleep 1;;
  esac
done
EOF
chmod +x "$PANEL_DIR/ssh_menu.sh"

# Xray submenu
cat > "$PANEL_DIR/xray_menu.sh" <<'EOF'
#!/bin/bash
while true; do
  clear
  echo "XRAY MANAGEMENT"
  echo "1) Add VLESS"
  echo "2) Add VMESS"
  echo "3) Add Trojan"
  echo "4) Add Shadowsocks2022"
  echo "5) Delete Xray user"
  echo "6) List all users (db)"
  echo "7) Restart Xray"
