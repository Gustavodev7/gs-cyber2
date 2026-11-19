#!/usr/bin/env bash
# Sobe o laboratorio completo da Rede Vila Aurora (E2), do zero:
#   1. valida o .env; 2. gera a CA e emite os certificados (com SAN no servidor);
#   3. sobe postgres, mosquitto, ingest, painel, WAF, sensores e no de borda;
#   4. roda o seed sintetico; 5. confere a saude do painel e da ingestao.
# Idempotente: pode rodar de novo. So dados sinteticos, lab isolado.
# Uso:  cd prototipo && bash scripts/subir_lab.sh
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "ERRO: crie o .env a partir de exemplo_variaveis_ambiente.txt"; exit 1; }
set -a; . ./.env; set +a
mkdir -p logs/postgres

echo "== PKI: CA + certificados =="
bash pki/gerar_ca.sh
# broker e ingestao sao SERVIDORES: precisam de SAN (nome/ip no certificado)
bash pki/emitir_dispositivo.sh mosquitto --servidor "DNS:mosquitto,DNS:localhost,IP:127.0.0.1"
bash pki/emitir_dispositivo.sh ingest    --servidor "DNS:ingest"
# clientes (sensores, borda, operador SOAR)
for n in borda-ubs ubs-geladeira escola-nivel abrigo-alagamento soar; do
  bash pki/emitir_dispositivo.sh "$n"
done

echo "== Subindo os servicos =="
docker compose up -d --build postgres
echo "aguardando o Postgres..."
for _ in $(seq 1 40); do
  docker compose exec -T postgres pg_isready -U vila_owner -d vila >/dev/null 2>&1 && break; sleep 1
done
docker compose up -d --build mosquitto ingest painel waf \
  sensor-ubs-geladeira sensor-escola-nivel sensor-abrigo-alagamento borda

echo "== Seed sintetico (operadores, titulares, historico) =="
# CREDENCIAIS_SAIDA no volume de logs (gravavel pelo usuario do container e fora
# do git). /app e do root; o painel roda como uid sem privilegio.
docker compose exec -T \
  -e PAINEL_DB_DSN_OWNER="postgresql://vila_owner:${PG_OWNER_PASSWORD}@postgres:5432/vila" \
  -e CREDENCIAIS_SAIDA=/var/log/vila/credenciais_lab.txt \
  painel python seed_sintetico.py

echo "== Saude =="
curl -fs "http://127.0.0.1:8080/saude" && echo "  painel (via WAF) OK"
docker compose exec -T borda sh -c 'test -f /dados/buffer.db' && echo "  buffer da borda criado OK" || true
docker compose ps
echo
echo "Painel: http://127.0.0.1:8080  (credenciais em logs/credenciais_lab.txt)"
echo "SIEM:   docker compose --profile siem up -d wazuh && bash siem/configurar_wazuh.sh"
