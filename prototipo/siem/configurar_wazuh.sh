#!/usr/bin/env bash
# Configura o Wazuh manager do compose (profile "siem"):
#   1. copia as regras locais (siem/local_rules.xml);
#   2. anexa as fontes de log (siem/localfile.xml) ao ossec.conf, uma vez so;
#   3. reinicia o manager e valida as regras com o wazuh-logtest.
# Uso (na pasta prototipo/):  docker compose --profile siem up -d wazuh && bash siem/configurar_wazuh.sh
# Ver alertas:  docker compose exec wazuh tail -f /var/ossec/logs/alerts/alerts.json
set -euo pipefail
cd "$(dirname "$0")/.."
DC="docker compose --profile siem"

echo "aguardando o manager subir..."
for _ in $(seq 1 60); do
  $DC exec -T wazuh test -x /var/ossec/bin/wazuh-control 2>/dev/null && break
  sleep 2
done

$DC exec -T wazuh cp /siem/local_rules.xml /var/ossec/etc/rules/local_rules.xml
$DC exec -T wazuh chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
if ! $DC exec -T wazuh grep -q "/var/log/vila/painel.json" /var/ossec/etc/ossec.conf; then
  $DC exec -T wazuh sh -c 'cat /siem/localfile.xml >> /var/ossec/etc/ossec.conf'
fi
$DC exec -T wazuh /var/ossec/bin/wazuh-control restart
echo "manager reiniciado com as regras 100100-100151."
bash siem/testar_regras.sh
