#!/usr/bin/env bash
# Confere o sincronismo NTP do host (RT-12: "logs com sincronismo NTP"; dica do
# enunciado: "Ligue o NTP antes de tudo"). A linha do tempo forense so se sustenta
# com os relogios sincronizados - uma das falhas do INC-VA-0712 foi justamente a
# dessincronia. Todos os containers herdam o relogio do host.
# Uso: bash scripts/verificar_ntp.sh
set -euo pipefail
echo "== Relogio do host =="
date -u +"UTC: %Y-%m-%dT%H:%M:%SZ"
if command -v timedatectl >/dev/null 2>&1; then           # Linux
  timedatectl show -p NTP -p NTPSynchronized -p TimeUSec 2>/dev/null || timedatectl status
  timedatectl show -p NTPSynchronized | grep -q "NTPSynchronized=yes" \
    && echo "NTP sincronizado: OK" \
    || echo "NTP NAO sincronizado. Ative: sudo timedatectl set-ntp true"
elif command -v sntp >/dev/null 2>&1; then                # macOS
  sntp -sS time.apple.com 2>/dev/null | tail -1 || true
  systemsetup -getusingnetworktime 2>/dev/null || echo "(no lab Linux use: sudo timedatectl set-ntp true)"
else
  echo "Sem timedatectl/sntp. No lab Linux: sudo apt install -y systemd-timesyncd && sudo timedatectl set-ntp true"
fi
echo
echo "== Deriva entre host e container (deve ser ~0s) =="
if docker compose ps --services 2>/dev/null | grep -q postgres; then
  echo "host:      $(date -u +%H:%M:%S)"
  echo "container: $(docker compose exec -T postgres date -u +%H:%M:%S 2>/dev/null || echo 'postgres parado')"
fi
