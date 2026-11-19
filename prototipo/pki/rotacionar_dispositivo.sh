#!/usr/bin/env bash
# Rotacao de credencial de um dispositivo (RT-05): gera par de chaves NOVO, emite
# certificado novo e revoga o antigo na CRL. O dispositivo passa a usar o novo; o
# antigo, mesmo que tenha vazado, deixa de ser aceito pelo broker.
# Uso: bash rotacionar_dispositivo.sh <nome> [--servidor "DNS:...,IP:..."]
# Rodar a cada 12 meses (plano de manutencao) ou quando houver suspeita de vazamento.
set -euo pipefail
cd "$(dirname "$0")"
NOME="${1:?informe o nome do dispositivo}"
shift
ANTIGO="certs/${NOME}.cert.pem"
[ -f "$ANTIGO" ] || { echo "nao existe certificado atual para ${NOME}"; exit 1; }

SERIAL_ANTIGO="$(openssl x509 -in "$ANTIGO" -noout -serial | cut -d= -f2)"
mkdir -p arquivados
cp "$ANTIGO" "arquivados/${NOME}.${SERIAL_ANTIGO}.cert.pem"
mv "private/${NOME}.key.pem" "arquivados/${NOME}.${SERIAL_ANTIGO}.key.pem.descartar"
chmod 400 "arquivados/${NOME}.${SERIAL_ANTIGO}.key.pem.descartar"

bash emitir_dispositivo.sh "$NOME" "$@"

openssl ca -config openssl.cnf -revoke "arquivados/${NOME}.${SERIAL_ANTIGO}.cert.pem" -crl_reason superseded
openssl ca -config openssl.cnf -gencrl -out crl/vila-aurora.crl.pem
rm -f "arquivados/${NOME}.${SERIAL_ANTIGO}.key.pem.descartar"
echo "Rotacao de ${NOME}: serial antigo ${SERIAL_ANTIGO} revogado (superseded); certificado novo em certs/${NOME}.cert.pem"
echo "Agora: docker compose kill -s HUP mosquitto   (o broker rele a CRL)"
