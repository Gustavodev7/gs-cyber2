#!/usr/bin/env bash
# Valida as regras com o wazuh-logtest, usando uma linha de exemplo para cada
# uma das 4 deteccoes obrigatorias (RT-13). Prova offline de que a regra casa;
# o print dos alertas REAIS vem de alerts.json durante os testes do lab.
set -euo pipefail
cd "$(dirname "$0")/.."
DC="docker compose --profile siem"
testar() {
  echo "=== $1"
  printf '%s\n' "$2" | $DC exec -T wazuh /var/ossec/bin/wazuh-logtest 2>&1 \
    | grep -E "id: '1001|level:|description:" || echo "  (nenhuma regra local casou)"
}
testar "(a) VPN de madrugada / IP desconhecido" \
  '{"ts":"2026-11-18T05:14:03.000Z","evento":"vpn_handshake","peer":"coord-vpn","srcip":"203.0.113.45","ip_conhecido":false}'
testar "(b) SQL Injection no painel" \
  '{"ts":"2026-11-18T05:15:10.000Z","app":"painel_legado","evento":"http","srcip":"10.8.0.66","metodo":"GET","rota":"/historico?dispositivo=x'"'"' UNION SELECT login,senha_hash,salt,totp_secret,perfil FROM operador-- ","status":200}'
testar "(c) certificado revogado no broker" \
  '2026-11-18T05:20:00: OpenSSL Error[0]: error:0A000086:SSL routines::certificate verify failed'
testar "(d) atuador fora de hora / perfil" \
  '{"ts":"2026-11-18T05:16:40.000Z","app":"painel","evento":"comando_atuador","login":"bruno","perfil":"operador","acao":"desligar_bomba","alvo":"escola-bomba","resultado":"negado_rbac"}'
