#!/usr/bin/env bash
# Gera as chaves e as configuracoes WireGuard do laboratorio (RT-06):
# concentrador (nuvem, 10.8.0.1) e no de borda da UBS (10.8.2.11).
# Saida em vpn/local/ (NAO versionado). Cada lado tem o proprio par de chaves.
# Uso: bash vpn/gerar_chaves_wg.sh <IP_OU_DNS_DO_CONCENTRADOR>
set -euo pipefail
cd "$(dirname "$0")"
ENDPOINT="${1:?informe o IP/DNS do concentrador, ex.: 192.168.0.10}"
command -v wg >/dev/null || { echo "instale wireguard-tools"; exit 1; }
umask 077
mkdir -p local
for n in concentrador borda-ubs; do
  [ -f "local/$n.key" ] || wg genkey > "local/$n.key"
  wg pubkey < "local/$n.key" > "local/$n.pub"
done
cat > local/wg0-concentrador.conf <<EOF
# Concentrador na nuvem/servidor do lab
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = $(cat local/concentrador.key)

[Peer]
# no de borda da UBS: so o proprio /32 (sem rota para outros segmentos)
PublicKey = $(cat local/borda-ubs.pub)
AllowedIPs = 10.8.2.11/32
EOF
cat > local/wg0-borda-ubs.conf <<EOF
# No de borda da UBS
[Interface]
Address = 10.8.2.11/32
PrivateKey = $(cat local/borda-ubs.key)

[Peer]
PublicKey = $(cat local/concentrador.pub)
Endpoint = ${ENDPOINT}:51820
# so o segmento de servicos da nuvem e alcancavel pela borda (menor privilegio)
AllowedIPs = 10.8.0.0/24
PersistentKeepalive = 25
EOF
printf '{"%s": "borda-ubs", "%s": "concentrador"}\n' "$(cat local/borda-ubs.pub)" "$(cat local/concentrador.pub)" > peers.json
echo "Configs em vpn/local/. No concentrador: sudo wg-quick up ./local/wg0-concentrador.conf"
echo "Na borda:                         sudo wg-quick up ./local/wg0-borda-ubs.conf"
echo "Conferir: sudo wg show   (esconder a chave privada nos prints)"
