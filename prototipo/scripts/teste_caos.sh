#!/usr/bin/env bash
# Teste de caos controlado (RT-23): derruba o link WAN do no de borda por >=30 min
# e evidencia (a) continuidade local e (b) reconciliacao sem perda ao voltar.
# Aqui "derrubar a WAN" = desconectar o container 'borda' da rede 'wan' do compose
# (o broker local, na rede 'iot', continua; os sensores seguem publicando).
#
# Uso:  cd prototipo && bash scripts/teste_caos.sh [MINUTOS]   (padrao 30)
# Gera scripts/caos/ com amostras a cada 30s e, no fim, metricas + grafico ASCII.
set -euo pipefail
cd "$(dirname "$0")/.."
MIN="${1:-30}"
SAIDA="scripts/caos"; mkdir -p "$SAIDA"
REDE="$(basename "$PWD")_wan"
AMOSTRAS="$SAIDA/amostras.csv"
echo "ts,fase,backlog,total_recebido,link,cpu_pct,mem_mb" > "$AMOSTRAS"

amostra() {  # $1 = fase
  local ts cpu mem st bl tot link
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  read -r cpu mem < <(docker stats --no-stream --format '{{.CPUPerc}} {{.MemUsage}}' \
      "$(docker compose ps -q borda)" 2>/dev/null | sed 's/%//; s#/.*##; s/MiB//; s/GiB/*1024/' | awk '{print $1, $2}')
  st="$(docker compose exec -T borda sh -c 'tail -n 50 /var/log/vila/borda.json 2>/dev/null | grep "\"evento\": \"status\"" | tail -1' || true)"
  bl="$(printf '%s' "$st" | sed -n 's/.*"backlog": \([0-9]*\).*/\1/p')"
  tot="$(printf '%s' "$st" | sed -n 's/.*"total_recebido": \([0-9]*\).*/\1/p')"
  link="$(printf '%s' "$st" | sed -n 's/.*"link": "\([a-z]*\)".*/\1/p')"
  echo "$ts,$1,${bl:-0},${tot:-0},${link:-?},${cpu:-0},${mem:-0}" | tee -a "$AMOSTRAS"
}

echo "== Linha de base (link UP), 2 min =="
for _ in $(seq 1 4); do amostra baseline; sleep 30; done

echo "== Derrubando a WAN do no de borda (inicio: $(date -u +%H:%M:%SZ)) =="
docker network disconnect "$REDE" "$(docker compose ps -q borda)"
INICIO=$(date +%s)
while [ $(( ($(date +%s) - INICIO) / 60 )) -lt "$MIN" ]; do amostra sem_wan; sleep 30; done

echo "== Restaurando a WAN ($(date -u +%H:%M:%SZ)); medindo reconciliacao =="
docker network connect "$REDE" "$(docker compose ps -q borda)"
REC=$(date +%s)
while :; do
  amostra reconciliando
  bl="$(docker compose exec -T borda sh -c 'tail -n 50 /var/log/vila/borda.json | grep status | tail -1' | sed -n 's/.*"backlog": \([0-9]*\).*/\1/p')"
  [ "${bl:-1}" = "0" ] && break
  [ $(( $(date +%s) - REC )) -gt 600 ] && { echo "backlog nao zerou em 10 min"; break; }
  sleep 15
done
FIM=$(date +%s)
python3 scripts/medir_caos.py "$AMOSTRAS" "$INICIO" "$REC" "$FIM" | tee "$SAIDA/relatorio.txt"
echo "Prints: use scripts/caos/relatorio.txt e amostras.csv (grafico do backlog no tempo)."
