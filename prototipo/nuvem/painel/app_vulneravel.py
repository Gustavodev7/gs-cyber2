"""
Painel de supervisao - VERSAO VULNERAVEL (apenas para o "antes" do RT-08).

Esta versao reproduz a falha do incidente INC-VA-0712: o campo de busca do
historico de acessos concatena a entrada do usuario diretamente no SQL.
Serve SO para demonstrar a exploracao e depois mostrar a correcao em
app_corrigido.py.

AVISO: codigo intencionalmente inseguro. Rodar exclusivamente no laboratorio
isolado da equipe (profile "vulneravel" do compose, porta so no loopback),
nunca exposto a rede e nunca com dados reais (LGPD).
"""

import json
import os
from datetime import UTC, datetime
from urllib.parse import unquote_plus

import psycopg
from flask import Flask, jsonify, request

app = Flask(__name__)
# usuario de banco com privilegios excessivos na versao legada (parte do problema)
DSN = os.environ["PAINEL_DB_DSN_LEGADO"]
LOG = os.environ.get("PAINEL_LOG", "/var/log/vila/painel_legado.json")


@app.after_request
def log_acesso(resp):
    # o legado tinha log de acesso; e ele que a forense usa na reproducao
    linha = {
        "ts": datetime.now(UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        "app": "painel_legado",
        "evento": "http",
        "srcip": request.remote_addr,
        "metodo": request.method,
        "rota": unquote_plus(request.full_path.rstrip("?")),
        "status": resp.status_code,
        "ua": request.headers.get("User-Agent", "")[:120],
    }
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(linha, ensure_ascii=False) + "\n")
    return resp


@app.get("/historico")
def historico():
    # FALHA: a string do usuario entra direto no texto da consulta.
    # E o vetor que o atacante do INC-VA-0712 usou para extrair a tabela de usuarios.
    filtro = request.args.get("dispositivo", "")
    sql = (
        "SELECT ts, espaco, recurso, dispositivo, evento FROM historico_acesso "
        "WHERE dispositivo = '" + filtro + "' ORDER BY ts DESC"
    )
    try:
        with psycopg.connect(DSN) as con, con.cursor() as cur:
            cur.execute(sql)
            linhas = cur.fetchall()
    except psycopg.Error as e:
        # FALHA: vaza o erro do banco e o SQL para a tela (ajuda o atacante)
        return jsonify(erro=str(e), sql_executado=sql), 500
    return jsonify(sql_executado=sql, linhas=[list(map(str, r)) for r in linhas])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
