#!/usr/bin/env bash
# Gera a CA raiz do projeto (X.509) e a infraestrutura de revogacao (CRL).
# Uso: bash gerar_ca.sh
# Nada aqui usa segredo compartilhado: cada dispositivo tem o proprio par de chaves.
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p ca certs crl private newcerts arquivados
touch index.txt
[ -f serial ] || echo 1000 > serial
[ -f crlnumber ] || echo 1000 > crlnumber

# 1. Chave e certificado da CA raiz (valida 10 anos, uso restrito a assinar certs)
if [ ! -f ca/ca.key.pem ]; then
  openssl genrsa -out ca/ca.key.pem 4096
  chmod 400 ca/ca.key.pem
  openssl req -x509 -new -nodes -key ca/ca.key.pem -sha256 -days 3650 \
    -subj "/C=BR/ST=SP/L=Serra Clara/O=Rede Vila Aurora/OU=PKI/CN=Vila Aurora Root CA" \
    -out ca/ca.cert.pem
  echo "CA raiz criada em ca/ca.cert.pem"
fi

# 2. CRL inicial (vazia). Renovar sempre que um certificado for revogado.
openssl ca -config openssl.cnf -gencrl -out crl/vila-aurora.crl.pem
echo "CRL em crl/vila-aurora.crl.pem"
