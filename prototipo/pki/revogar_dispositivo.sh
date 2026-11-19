#!/usr/bin/env bash
# Revoga o certificado de um dispositivo comprometido e regenera a CRL (RT-05).
# Uso: bash revogar_dispositivo.sh <nome>
# Depois de revogar, recarregar o broker Mosquitto para que ele releia a CRL.
set -euo pipefail
cd "$(dirname "$0")"
NOME="${1:?informe o nome do dispositivo}"

openssl ca -config openssl.cnf -revoke "certs/${NOME}.cert.pem" -crl_reason keyCompromise
openssl ca -config openssl.cnf -gencrl -out crl/vila-aurora.crl.pem
echo "Certificado de ${NOME} revogado e CRL atualizada."
echo "Agora: docker compose kill -s HUP mosquitto   (recarrega a CRL)"
