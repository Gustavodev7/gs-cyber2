"""
Ingestao na nuvem (RT-01, RT-02, RT-04): recebe o backlog dos nos de borda.

- HTTPS com mTLS (ver gunicorn_conf.py): so entra quem apresenta certificado da
  CA do projeto, nao revogado (CRL).
- Autorizacao pela identidade: o CN do certificado precisa ser borda-*.
- Idempotente: event_id e chave primaria; reenvio apos timeout nao duplica.
- Usuario de banco ingest_w: so INSERT na tabela de telemetria.
So dados sinteticos.
"""

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path

import psycopg
from flask import Flask, jsonify, request

app = Flask(__name__)
DSN = os.environ["INGEST_DB_DSN"]
LOG = Path(os.environ.get("LOG_DIR", ".")) / "ingest.json"
RE_BORDA = re.compile(r"^borda-[a-z0-9-]{1,30}$")
RE_UUID = re.compile(r"^[0-9a-f-]{36}$")
CAMPOS = ("dispositivo", "espaco", "recurso")


def agora():
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def registrar(evento, **campos):
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": agora(), "evento": evento, **campos}) + "\n")


def cn_do_cliente():
    """CN do certificado apresentado no handshake mTLS."""
    sock = request.environ.get("gunicorn.socket")
    cert = sock.getpeercert() if sock else None
    if not cert:
        return None
    for rdn in cert.get("subject", ()):
        for chave, valor in rdn:
            if chave == "commonName":
                return valor
    return None


def evento_valido(e):
    p = e.get("payload") if isinstance(e, dict) else None
    if not isinstance(p, dict):
        return None
    if not RE_UUID.match(str(p.get("event_id", ""))):
        return None
    if not all(isinstance(p.get(c), str) and len(p[c]) <= 40 for c in CAMPOS):
        return None
    if not isinstance(p.get("valor"), (int, float)) or not isinstance(
        p.get("ts"), (int, float)
    ):
        return None
    return p


@app.post("/ingest")
def ingest():
    cn = cn_do_cliente()
    if not cn or not RE_BORDA.match(cn):
        registrar("acesso_negado", cn=cn, ip=request.remote_addr)
        return jsonify(erro="identidade nao autorizada"), 403
    corpo = request.get_json(silent=True) or {}
    eventos = corpo.get("eventos")
    if not isinstance(eventos, list) or len(eventos) > 500:
        return jsonify(erro="lote invalido"), 400
    validos = [p for p in map(evento_valido, eventos) if p]
    aceitos = 0
    with psycopg.connect(DSN, connect_timeout=5) as con, con.cursor() as cur:
        for p in validos:
            cur.execute(
                "INSERT INTO vila.telemetria"
                "(event_id, borda, dispositivo, espaco, recurso, valor, ts_origem) "
                "VALUES (%s, %s, %s, %s, %s, %s, to_timestamp(%s)) "
                "ON CONFLICT (event_id) DO NOTHING",
                (
                    p["event_id"],
                    cn,
                    p["dispositivo"],
                    p["espaco"],
                    p["recurso"],
                    float(p["valor"]),
                    float(p["ts"]),
                ),
            )
            aceitos += cur.rowcount
    registrar(
        "lote_recebido",
        cn=cn,
        recebidos=len(eventos),
        validos=len(validos),
        aceitos=aceitos,
        duplicados=len(validos) - aceitos,
    )
    return jsonify(
        aceitos=aceitos,
        duplicados=len(validos) - aceitos,
        rejeitados=len(eventos) - len(validos),
    )


@app.get("/saude")
def saude():
    return jsonify(ok=True)
