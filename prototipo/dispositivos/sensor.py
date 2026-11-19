"""
Dispositivo de campo simulado (RT-01). Publica telemetria por MQTT sobre mTLS
(RT-04): apresenta o proprio certificado X.509; sem ele o broker recusa.

Cada instancia representa um sensor de um espaco (energia, agua, acesso, ambiente).
Uso:
  python sensor.py ubs-geladeira ubs ambiente
Variaveis de ambiente: MQTT_HOST, MQTT_PORT, PKI_DIR, LOG_DIR, INTERVALO.
Cada leitura leva um event_id unico: a nuvem usa esse id para nao duplicar
eventos na reconciliacao (idempotencia). So dados sinteticos.
"""

import json
import os
import random
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import paho.mqtt.client as mqtt

NOME, ESPACO, RECURSO = sys.argv[1], sys.argv[2], sys.argv[3]
HOST = os.environ.get("MQTT_HOST", "localhost")
PORT = int(os.environ.get("MQTT_PORT", "8883"))
PKI = os.environ.get("PKI_DIR", "../pki")
INTERVALO = float(os.environ.get("INTERVALO", "2"))
LOG = Path(os.environ.get("LOG_DIR", ".")) / "sensores.json"


def agora():
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def ler_valor():
    """Faixas normais por recurso; de vez em quando sai da faixa para exercitar
    as regras locais da borda (camara fria fora de 2-8 C, reservatorio baixo)."""
    fora = random.random() < 0.03
    if RECURSO == "ambiente":
        return round(random.uniform(8.5, 11.0) if fora else random.uniform(2.5, 7.5), 2)
    if RECURSO == "agua":
        return round(random.uniform(5, 14) if fora else random.uniform(20, 95), 1)
    if RECURSO == "energia":
        return round(random.uniform(40, 90), 1)
    return random.choice([0, 0, 0, 1])  # acesso: 1 = tentativa


def registrar(evento, **campos):
    linha = {"ts": agora(), "evento": evento, "dispositivo": NOME, **campos}
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(linha, ensure_ascii=False) + "\n")


def ao_conectar(_c, _u, _flags, reason_code, _props):
    registrar("mqtt_conectado", codigo=str(reason_code))


def main():
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=NOME)
    c.tls_set(
        ca_certs=f"{PKI}/ca/ca.cert.pem",
        certfile=f"{PKI}/certs/{NOME}.cert.pem",
        keyfile=f"{PKI}/private/{NOME}.key.pem",
    )
    c.on_connect = ao_conectar
    c.connect(HOST, PORT, keepalive=30)
    c.loop_start()  # thread de rede: CONNACK, PUBACK (QoS 1) e keepalive
    topico = f"vila/{ESPACO}/{RECURSO}/{NOME}"
    while True:
        payload = {
            "event_id": str(uuid.uuid4()),
            "dispositivo": NOME,
            "espaco": ESPACO,
            "recurso": RECURSO,
            "valor": ler_valor(),
            "ts": time.time(),
        }
        info = c.publish(topico, json.dumps(payload), qos=1)
        if info.rc == mqtt.MQTT_ERR_SUCCESS:
            registrar("publicado", event_id=payload["event_id"], valor=payload["valor"])
        else:
            registrar("falha_publicacao", rc=info.rc)
        time.sleep(INTERVALO)


if __name__ == "__main__":
    main()
