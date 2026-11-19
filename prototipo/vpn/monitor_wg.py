"""
Monitor de sessoes WireGuard para o SIEM (RT-12, RT-13a).

O WireGuard nao grava log de login. Este monitor le `wg show <iface> dump` a cada
poucos segundos e, quando um peer faz um handshake novo, grava uma linha JSON em
logs/vpn.json com o peer, o IP de origem e se esse IP esta nas faixas conhecidas.
O Wazuh dispara a regra 100100 (madrugada) ou 100101 (IP desconhecido).

Uso (no concentrador, como root):  python3 vpn/monitor_wg.py --iface wg0
Faixas conhecidas: --conhecidas 192.168.0.0/16,10.0.0.0/8 (redes dos espacos).
Nomes dos peers: arquivo vpn/peers.json {"<chave publica>": "coord-vpn", ...}
"""

import argparse
import ipaddress
import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent


def agora():
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def ler_dump(iface):
    saida = subprocess.run(
        ["wg", "show", iface, "dump"], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    for linha in saida[1:]:  # a primeira linha e a propria interface
        campos = linha.split("\t")
        pub, endpoint, handshake = campos[0], campos[2], int(campos[4])
        yield pub, endpoint, handshake


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", default="wg0")
    p.add_argument("--conhecidas", default="192.168.0.0/16,172.16.0.0/12,10.0.0.0/8")
    p.add_argument("--log", default=str(RAIZ / "logs" / "vpn.json"))
    p.add_argument("--intervalo", type=float, default=5)
    a = p.parse_args()
    redes = [ipaddress.ip_network(r) for r in a.conhecidas.split(",")]
    nomes_arq = RAIZ / "vpn" / "peers.json"
    nomes = json.loads(nomes_arq.read_text()) if nomes_arq.exists() else {}
    ultimo = {}
    log = Path(a.log)
    log.parent.mkdir(exist_ok=True)
    while True:
        for pub, endpoint, hs in ler_dump(a.iface):
            if hs and hs != ultimo.get(pub):
                ja_visto = pub in ultimo
                # na primeira leitura, handshake antigo (> 3 min) so vira estado
                ultimo[pub] = hs
                if not ja_visto and hs < time.time() - 180:
                    continue
                ip = (
                    endpoint.rsplit(":", 1)[0].strip("[]")
                    if endpoint != "(none)"
                    else ""
                )
                conhecido = bool(ip) and any(
                    ipaddress.ip_address(ip) in r for r in redes
                )
                linha = {
                    "ts": agora(),
                    "app": "wireguard",
                    "evento": "vpn_handshake",
                    "peer": nomes.get(pub, pub[:10]),
                    "srcip": ip,
                    "ip_conhecido": conhecido,
                    "iface": a.iface,
                    "handshake_em": datetime.fromtimestamp(hs, UTC).isoformat(),
                }
                with log.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(linha) + "\n")
                print(json.dumps(linha))
        time.sleep(a.intervalo)


if __name__ == "__main__":
    main()
