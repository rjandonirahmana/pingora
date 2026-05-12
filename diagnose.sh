#!/bin/sh
# Diagnosa kenapa ulala.space tidak bisa dibuka
# Jalankan di server: sh diagnose.sh

echo "═══════════════════════════════════════════════════════"
echo "  kinetic-proxy diagnosa — ulala.space"
echo "═══════════════════════════════════════════════════════"

echo ""
echo "── 1. Port yang sedang listen ──────────────────────────"
ss -tlnp 2>/dev/null | grep -E ':80|:443|:3100|:8080' || \
netstat -tlnp 2>/dev/null | grep -E ':80|:443|:3100|:8080'

echo ""
echo "── 2. Container yang jalan ─────────────────────────────"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null

echo ""
echo "── 3. TLS cert Let's Encrypt ───────────────────────────"
CERT="/etc/letsencrypt/live/ulala.space/fullchain.pem"
KEY="/etc/letsencrypt/live/ulala.space/privkey.pem"
if [ -f "$CERT" ]; then
    echo "✅ cert ada: $CERT"
    openssl x509 -in "$CERT" -noout -dates 2>/dev/null | grep -E "notAfter|notBefore"
else
    echo "❌ cert TIDAK ADA: $CERT"
    echo "   → Jalankan: certbot certonly --standalone -d ulala.space"
fi
if [ -f "$KEY" ]; then
    echo "✅ key ada: $KEY"
else
    echo "❌ key TIDAK ADA: $KEY"
fi

echo ""
echo "── 4. Test koneksi lokal ───────────────────────────────"
echo -n "HTTP  localhost:80   → "; curl -s -o /dev/null -w "%{http_code}" http://localhost/health 2>/dev/null || echo "GAGAL"
echo ""
echo -n "HTTPS localhost:443  → "; curl -sk -o /dev/null -w "%{http_code}" https://localhost/health 2>/dev/null || echo "GAGAL"
echo ""
echo -n "Frontend :3100       → "; curl -s -o /dev/null -w "%{http_code}" http://localhost:3100/ 2>/dev/null || echo "GAGAL"
echo ""

echo ""
echo "── 5. DNS ulala.space ──────────────────────────────────"
dig +short ulala.space A 2>/dev/null || nslookup ulala.space 2>/dev/null | grep Address
MY_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s api.ipify.org 2>/dev/null)
echo "IP server ini: $MY_IP"

echo ""
echo "── 6. Log proxy (100 baris terakhir) ───────────────────"
docker logs kinetic-proxy --tail=100 2>/dev/null || \
journalctl -u kinetic-proxy -n 100 --no-pager 2>/dev/null || \
echo "Tidak bisa baca log — cek nama container/service"

echo ""
echo "── 7. Firewall ─────────────────────────────────────────"
iptables -L INPUT -n 2>/dev/null | grep -E "443|80" | head -5 || echo "(skip)"
ufw status 2>/dev/null | grep -E "443|80|Nginx|Apache" || echo "(ufw tidak aktif)"

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Solusi paling umum:"
echo "  1. Mount cert: docker run -v /etc/letsencrypt:/etc/letsencrypt:ro ..."
echo "  2. Buka port:  ufw allow 80 && ufw allow 443"
echo "  3. DNS A record ulala.space → IP server"
echo "═══════════════════════════════════════════════════════"
