#!/usr/bin/env bash
# Emite um certificado X.509 unico para um dispositivo, operador ou servidor.
# Uso:
#   bash emitir_dispositivo.sh <nome>                              (cliente: sensor, borda, SOAR)
#   bash emitir_dispositivo.sh <nome> --servidor "DNS:x,IP:1.2.3.4" (servidor: broker, ingestao)
# O CN vira a identidade usada no mTLS e nas regras de autorizacao (ACL) do broker.
# Cada identidade tem o proprio par de chaves: nenhum segredo e compartilhado (RT-04).
set -euo pipefail
cd "$(dirname "$0")"
NOME="${1:?informe o nome do dispositivo}"
[[ "$NOME" =~ ^[a-z0-9-]{1,40}$ ]] || { echo "nome invalido: use a-z, 0-9 e hifen"; exit 2; }
SAN=""
if [ "${2:-}" = "--servidor" ]; then
  SAN="${3:?informe o subjectAltName, ex.: DNS:mosquitto,DNS:localhost,IP:127.0.0.1}"
fi

# Reemissao: remove a chave anterior (modo 400 bloquearia a sobrescrita). Emitir
# = novo par de chaves; para rotacao com revogacao do antigo use rotacionar_dispositivo.sh.
rm -f "private/${NOME}.key.pem" "certs/${NOME}.cert.pem"
openssl genrsa -out "private/${NOME}.key.pem" 2048
chmod 400 "private/${NOME}.key.pem"
openssl req -new -key "private/${NOME}.key.pem" \
  -subj "/C=BR/ST=SP/L=Serra Clara/O=Rede Vila Aurora/OU=Dispositivos/CN=${NOME}" \
  -out "certs/${NOME}.csr.pem"

if [ -n "$SAN" ]; then
  EXT="$(mktemp)"
  trap 'rm -f "$EXT"' EXIT
  {
    echo "basicConstraints = CA:FALSE"
    echo "keyUsage = critical, digitalSignature, keyEncipherment"
    echo "extendedKeyUsage = serverAuth"
    echo "subjectKeyIdentifier = hash"
    echo "authorityKeyIdentifier = keyid,issuer"
    echo "subjectAltName = ${SAN}"
  } > "$EXT"
  openssl ca -batch -config openssl.cnf -extfile "$EXT" -days 375 -notext -md sha256 \
    -in "certs/${NOME}.csr.pem" -out "certs/${NOME}.cert.pem"
else
  openssl ca -batch -config openssl.cnf -extensions usr_cert -days 375 -notext -md sha256 \
    -in "certs/${NOME}.csr.pem" -out "certs/${NOME}.cert.pem"
fi
rm -f "certs/${NOME}.csr.pem"
echo "Certificado emitido: certs/${NOME}.cert.pem (valido 375 dias, serial $(openssl x509 -in "certs/${NOME}.cert.pem" -noout -serial | cut -d= -f2))"
