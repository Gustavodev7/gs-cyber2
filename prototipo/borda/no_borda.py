"""
No de borda de um espaco comunitario (RT-01, RT-02).

Responsabilidades:
  - Assinar o broker MQTT local (mTLS) e consumir a telemetria dos sensores.
  - Aplicar REGRAS LOCAIS mesmo sem internet: alarme da camara fria da UBS e
    limite da bomba de agua (decisao de baixo risco, local).
  - Executar comandos de modo seguro vindos do SOAR (vila/<espaco>/comando/...).
  - Guardar tudo num buffer store-and-forward (SQLite) e sincronizar com a
    nuvem (HTTPS com mTLS) quando o link voltar, em ordem, sem perder dados.

A continuidade local nao depende da nuvem: se o uplink cair, o no segue
decidindo e acumulando. Ao reconectar, envia o backlog em lotes, em ordem.
A nuvem deduplica por event_id, entao reenvio apos timeout nao gera duplicata.
Cada acao relevante vira uma linha JSON em LOG_DIR/borda.json (SIEM e metricas).
So dados sinteticos.
"""

import json
import os
import sqlite3
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import paho.mqtt.client as mqtt
import requests

PKI = os.environ.get("PKI_DIR", "../pki")
NOME = os.environ.get("BORDA_NOME", "borda-ubs")
MQTT_HOST = os.environ.get("MQTT_HOST", "localhost")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "8883"))
NUVEM_URL = os.environ.get("NUVEM_URL", "https://ingest:8443/ingest")
BUF = Path(os.environ.get("BORDA_BUFFER", "buffer.db"))
LOG = Path(os.environ.get("LOG_DIR", ".")) / "borda.json"
LOTE = int(os.environ.get("LOTE", "200"))
PERIODO_SYNC = float(os.environ.get("PERIODO_SYNC", "5"))

# Limites das regras locais. Camara fria de vacinas: faixa segura 2-8 C.
TEMP_MIN, TEMP_MAX = 2.0, 8.0
AGUA_MIN = 15.0  # abaixo disso, bomba em modo economia (baixo risco)

trava = threading.Lock()  # o callback MQTT roda em outra thread


def agora():
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def registrar(evento, **campos):
    linha = {"ts": agora(), "evento": evento, "borda": NOME, **campos}
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(linha, ensure_ascii=False) + "\n")


def abrir_buffer():
    con = sqlite3.connect(BUF, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute(
        "CREATE TABLE IF NOT EXISTS fila("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE, ts REAL, "
        "topico TEXT, payload TEXT, enviado INTEGER DEFAULT 0)"
    )
    con.execute(
        "CREATE TABLE IF NOT EXISTS alarme_local("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, tipo TEXT, detalhe TEXT)"
    )
    con.commit()
    return con


def regra_local(con, dado):
    """Decisoes de baixo risco tomadas na borda, sem depender da nuvem (RT-02, RT-15)."""
    r, v, disp = dado.get("recurso"), dado.get("valor"), dado.get("dispositivo")
    if not isinstance(v, (int, float)):
        return
    if r == "ambiente" and disp == "ubs-geladeira" and not (TEMP_MIN <= v <= TEMP_MAX):
        con.execute(
            "INSERT INTO alarme_local(ts,tipo,detalhe) VALUES(?,?,?)",
            (time.time(), "camara-fria", f"temp {v}C fora de [{TEMP_MIN},{TEMP_MAX}]"),
        )
        registrar(
            "alarme_local",
            tipo="camara-fria",
            dispositivo=disp,
            valor=v,
            acao="alerta sonoro/visual no espaco",
        )
    if r == "agua" and v < AGUA_MIN:
        con.execute(
            "INSERT INTO alarme_local(ts,tipo,detalhe) VALUES(?,?,?)",
            (time.time(), "agua-baixa", f"nivel {v}% < {AGUA_MIN}%"),
        )
        # baixo risco: limitar vazao. Desligar a bomba do abrigo = alto risco,
        # exige aprovacao humana (automacao/responder.py).
        registrar(
            "alarme_local",
            tipo="agua-baixa",
            dispositivo=disp,
            valor=v,
            acao="bomba em modo economia",
        )


def executar_comando(dado, topico):
    """Comandos do SOAR. A borda so aceita acoes de baixo risco."""
    acao = dado.get("acao")
    if acao == "atuador_modo_seguro":
        registrar(
            "comando_executado",
            acao=acao,
            alvo=dado.get("alvo"),
            topico=topico,
            origem=dado.get("origem"),
        )
    else:
        registrar(
            "comando_recusado",
            acao=acao,
            topico=topico,
            motivo="acao nao permitida na borda sem aprovacao humana",
        )


def ao_conectar(cliente, _u, _flags, reason_code, _props):
    registrar("mqtt_conectado", codigo=str(reason_code))
    cliente.subscribe("vila/#", qos=1)  # reassina a cada reconexao


def ao_receber(con):
    def cb(_c, _u, msg):
        try:
            dado = json.loads(msg.payload)
        except (json.JSONDecodeError, UnicodeDecodeError):
            registrar("mensagem_invalida", topico=msg.topic)
            return
        if "/comando/" in msg.topic:
            executar_comando(dado, msg.topic)
            return
        with trava:
            con.execute(
                "INSERT OR IGNORE INTO fila(event_id,ts,topico,payload) VALUES(?,?,?,?)",
                (
                    dado.get("event_id"),
                    dado.get("ts", time.time()),
                    msg.topic,
                    msg.payload.decode(),
                ),
            )
            regra_local(con, dado)
            con.commit()

    return cb


def sincronizar(con):
    """Store-and-forward: envia o backlog em ordem; so marca enviado com 200."""
    with trava:
        pend = con.execute(
            "SELECT id,topico,payload FROM fila WHERE enviado=0 ORDER BY id LIMIT ?",
            (LOTE,),
        ).fetchall()
    if not pend:
        return 0, None
    lote = [{"topico": t, "payload": json.loads(p)} for _, t, p in pend]
    try:
        resp = requests.post(
            NUVEM_URL,
            json={"borda": NOME, "eventos": lote},
            verify=f"{PKI}/ca/ca.cert.pem",
            cert=(f"{PKI}/certs/{NOME}.cert.pem", f"{PKI}/private/{NOME}.key.pem"),
            timeout=10,
        )
    except requests.RequestException as e:
        return 0, type(e).__name__  # link caiu: mantem no buffer
    if resp.status_code != 200:
        return 0, f"http_{resp.status_code}"
    ids = [(i,) for i, _, _ in pend]
    with trava:
        con.executemany("UPDATE fila SET enviado=1 WHERE id=?", ids)
        con.commit()
    return len(ids), None


def status(con):
    with trava:
        backlog = con.execute("SELECT COUNT(*) FROM fila WHERE enviado=0").fetchone()[0]
        total = con.execute("SELECT COUNT(*) FROM fila").fetchone()[0]
    return backlog, total


def main():
    con = abrir_buffer()
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=NOME)
    c.tls_set(
        ca_certs=f"{PKI}/ca/ca.cert.pem",
        certfile=f"{PKI}/certs/{NOME}.cert.pem",
        keyfile=f"{PKI}/private/{NOME}.key.pem",
    )
    c.on_connect = ao_conectar
    c.on_message = ao_receber(con)
    c.connect(MQTT_HOST, MQTT_PORT, keepalive=30)
    c.loop_start()
    link_ok = None
    try:
        while True:
            enviados, erro = sincronizar(con)
            while enviados == LOTE:  # drena o backlog rapido quando o link volta
                enviados, erro = sincronizar(con)
            backlog, total = status(con)
            ok = erro is None
            if ok != link_ok:
                registrar("link_nuvem", estado="up" if ok else "down", erro=erro)
                link_ok = ok
            # linha de status a cada ciclo: base das metricas do teste de caos
            registrar(
                "status",
                backlog=backlog,
                total_recebido=total,
                link="up" if ok else "down",
            )
            time.sleep(PERIODO_SYNC)
    finally:
        c.loop_stop()


if __name__ == "__main__":
    main()
