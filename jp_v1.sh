#!/bin/bash
# ================================================================================================
# JP_V2 - Full Version with Mandatory Domain, Auto-SSL, Multi-Tunneling, Dashboard
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
