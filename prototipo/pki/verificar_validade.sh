#!/usr/bin/env bash
# Lista os certificados emitidos e os dias ate expirar. Alerta os que vencem em menos
# de 30 dias e a propria CRL (que vence a cada 30 dias e precisa ser renovada).
# Uso: bash verificar_validade.sh   (rodar semanalmente, plano de manutencao RT-20)
set -euo pipefail
cd "$(dirname "$0")"
agora=$(date +%s)
dias_ate() { echo $(( ( $1 - agora ) / 86400 )); }
para_epoch() { date -d "$1" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$1" +%s; }
for c in certs/*.cert.pem; do
  fim="$(openssl x509 -in "$c" -noout -enddate | cut -d= -f2)"
  d=$(dias_ate "$(para_epoch "$fim")")
  flag=""; [ "$d" -lt 30 ] && flag="  <-- ROTACIONAR"
  printf "%-32s vence em %4d dias%s\n" "$(basename "$c")" "$d" "$flag"
done
fim_crl="$(openssl crl -in crl/vila-aurora.crl.pem -noout -nextupdate | cut -d= -f2)"
d=$(dias_ate "$(para_epoch "$fim_crl")")
flag=""; [ "$d" -lt 7 ] && flag="  <-- RENOVAR: openssl ca -config openssl.cnf -gencrl -out crl/vila-aurora.crl.pem"
printf "%-32s vence em %4d dias%s\n" "CRL" "$d" "$flag"
