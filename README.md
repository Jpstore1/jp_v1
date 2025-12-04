# JP_V1 v1.0 - Ultimate VPN Server Manager 
 
!
[JP_V1 Banner](https://img.shields.io/badge/JP_V1-v1.0-blue.svg?style=for-the-badge&logo=github)
!
[License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)
!
[Status](https://img.shields.io/badge/Status-Fully%20Functional-brightgreen.svg?style=for-the-badge)
 
JP_V1 adalah skrip Bash lengkap dan canggih untuk menginstal, mengelola, dan memantau server VPN multi-protokol di VPS Anda. Dilengkapi dengan antarmuka CLI fullscreen yang interaktif dan estetis menggunakan `tmux`, `lolcat`, `figlet`, dan `boxes`. 
 
## ✨ Fitur Utama 
 
-   **Antarmuka CLI Fullscreen Interaktif:** Dashboard `tmux` 4-pane dengan informasi real-time, statistik, dan menu yang mudah digunakan. 
-   **Multi-Protokol SSH:** 
    -   **Direct SSH** (OpenSSH) 
    -   **Dropbear SSH** (Port 442 & 109 - ideal untuk HTTP Custom/KPN Tunnel) 
    -   **SSH WebSocket TLS** (melalui Nginx di Port 443) 
    -   **SSH WebSocket Non-TLS** (melalui Nginx di Port 80) 
    -   **UDP HTTP Custom** (melalui Xray Dokodemo-door UDP forwarding) 
-   **Xray Core:** 
    -   **VMess WebSocket TLS** (Port 443) 
    -   **VLESS WebSocket TLS** (Port 443) 
    -   **Trojan WebSocket TLS** (Port 443) 
-   **Hysteria V1:** Protokol UDP cepat dan obfuscated (Port 40000 - configurable). 
-   **ZIPVPN (ZIVPN):** Protokol UDP (Port 5667 - configurable) dengan **fitur "1 Device Lock" per user/password**. 
-   **Manajemen Pengguna Lengkap:** 
    -   **Create User:** Buat user baru untuk semua layanan VPN secara bersamaan. 
    -   **Check Expired Accounts:** Tampilkan status semua user dan hapus otomatis user yang expired dari semua layanan. 
    -   **Renew Account:** Perpanjang masa aktif user yang sudah ada. 
    -   **Trial User Generator:** Buat user trial (3 hari) secara massal. 
-   **Proteksi DDoS/DoS:** 
    -   Konfigurasi `iptables` untuk memitigasi serangan SYN-Flood dan membatasi koneksi per IP. 
    -   Integrasi `Fail2Ban` untuk melindungi SSH dan Nginx dari brute-force. 
-   **Manajemen SSL Otomatis:** Otomatis memperoleh dan memperbarui sertifikat SSL Let's Encrypt melalui Certbot. 
-   **Backup & Restore:** Mudah melakukan backup dan restore seluruh konfigurasi server. 
-   **Monitoring:** Live monitoring trafik, status layanan, dan penggunaan sistem (CPU/RAM) dengan `htop`, `glances`, dan `ss`. 
 
## 🖥️ Persyaratan Sistem 
 
-   **Sistem Operasi:** Debian 10/11/12 atau Ubuntu 20.04/22.04 LTS (direkomendasikan). 
-   **Akses:** Akses `root` ke VPS Anda. 
-   **Domain:** **Satu domain yang valid** dan sudah terarah (A record) ke IP VPS Anda. 
-   **Memori:** Minimal 1GB RAM (direkomendasikan 2GB+). 
 
## 🚀 Instalasi Cepat 
 
1.  **Login ke VPS Anda sebagai root.** 
2.  **Unduh skrip:** 
    ```bash 
    wget -O jp_v1.sh https://raw.githubusercontent.com/YourUsername/your-repo-name/main/jp_v1.sh 
    ``` 
    *(Ganti `YourUsername/your-repo-name` dengan username dan nama repo GitHub Anda)* 
3.  **Berikan izin eksekusi:** 
    ```bash 
    chmod +x jp_v1.sh 
    ``` 
4.  **Jalankan installer:** 
    ```bash 
    sudo ./jp_v1.sh 
    ``` 
    Skrip akan memandu Anda melalui proses konfigurasi awal (domain, port) dan instalasi semua layanan. 
 
## 👨‍💻 Cara Menggunakan Panel CLI 
 
Setelah instalasi selesai, cukup jalankan skrip lagi untuk mengakses panel interaktif: 
```bash 
sudo ./jp_v1.sh 

