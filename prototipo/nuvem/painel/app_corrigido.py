"""
Painel de supervisao da Rede Vila Aurora - VERSAO CORRIGIDA (RT-08, RT-09, RT-21).

Defesa em profundidade contra SQL Injection:
  1. Consultas sempre parametrizadas (psycopg, placeholders %s) - nunca f-string/concat.
  2. Validacao de entrada no servidor (tipo, tamanho, lista de valores aceitos).
  3. Usuario de banco com privilegio minimo: painel_ro so le VIEWS e executa
     funcoes especificas; nao le a tabela de operadores nem a de titulares.
  4. Mensagens de erro genericas: o detalhe vai para o log, nao para a tela.
  5. WAF (ModSecurity + OWASP CRS) na frente do painel (docker-compose.yml).
Acesso: MFA (senha + TOTP) e RBAC por permissao (operador, tecnico,
coordenacao, auditor). Bloqueio temporario apos tentativas falhas.
Cada requisicao vira uma linha JSON no log (SIEM, RT-12/RT-13).

So dados sinteticos. Rodar apenas no laboratorio isolado da equipe.
"""

import hashlib
import json
import logging
import os
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import UTC, datetime
from functools import wraps
from urllib.parse import unquote_plus

import psycopg
import pyotp
from flask import Flask, abort, g, jsonify, render_template, request, session

app = Flask(__name__)
app.secret_key = os.environ["PAINEL_SECRET"]  # injetado por variavel de ambiente
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    # em producao o painel fica atras de TLS (VPN + proxy); no lab e HTTP local
    SESSION_COOKIE_SECURE=os.environ.get("PAINEL_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=1800,
)

DSN = os.environ["PAINEL_DB_DSN"]  # usuario painel_ro
LOG_PATH = os.environ.get("PAINEL_LOG", "/var/log/vila/painel.json")
logging.basicConfig(filename=LOG_PATH, level=logging.INFO, format="%(message)s")
log = logging.getLogger("painel")

# RBAC por permissao (RT-09). O banco repete a regra dos atuadores
# (funcao registrar_comando), entao burlar o app nao basta.
PERMISSOES = {
    "operador": {"historico:ler", "telemetria:ler"},
    "tecnico": {"historico:ler", "telemetria:ler", "atuador:baixo"},
    "coordenacao": {
        "historico:ler",
        "telemetria:ler",
        "atuador:baixo",
        "atuador:alto",
        "comando:aprovar",
        "comando:ler",
    },
    "auditor": {"historico:ler", "telemetria:ler", "comando:ler"},
}
ACOES_BAIXO = {"atuador_modo_seguro", "bomba_modo_economia", "isolar_dispositivo"}
ACOES_ALTO = {"desligar_bomba", "liberar_todas_portas", "agendamento_bomba"}

# Validacao positiva (allowlist) por campo.
ESPACOS = {"centro", "escola", "ubs", "horta", "abrigo"}
RECURSOS = {"energia", "agua", "acesso", "ambiente"}
RE_ID = re.compile(r"^[a-z0-9-]{1,40}$")
RE_TOTP = re.compile(r"^[0-9]{6}$")

# Bloqueio por tentativas (forca bruta / credential stuffing): 5 falhas em 5 min.
FALHAS = defaultdict(deque)
MAX_FALHAS, JANELA = 5, 300
SALT_FICTICIO = secrets.token_hex(16)  # mesmo custo para usuario inexistente


def agora():
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def registrar(evento, **campos):
    """Uma linha JSON por evento: o decoder json do Wazuh separa os campos."""
    u = session.get("usuario") or {}
    linha = {
        "ts": agora(),
        "app": "painel",
        "evento": evento,
        "srcip": request.remote_addr if request else None,
        "login": u.get("login"),
        "perfil": u.get("perfil"),
        **campos,
    }
    log.info(json.dumps(linha, ensure_ascii=False))


def db():
    if "db" not in g:
        g.db = psycopg.connect(DSN, connect_timeout=5, autocommit=True)
    return g.db


@app.teardown_appcontext
def fechar_db(_):
    con = g.pop("db", None)
    if con is not None:
        con.close()


@app.after_request
def cabecalhos(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    # log de acesso estruturado: base da regra de SQLi do SIEM (url decodificada)
    registrar(
        "http",
        metodo=request.method,
        # decodificada (%27 -> ') para a regra de SQLi do SIEM enxergar o payload
        rota=unquote_plus(request.full_path.rstrip("?")),
        status=resp.status_code,
        ua=request.headers.get("User-Agent", "")[:120],
    )
    return resp


def exige(permissao):
    """Autorizacao: sessao autenticada com MFA e permissao do perfil."""

    def wrap(f):
        @wraps(f)
        def inner(*a, **kw):
            u = session.get("usuario")
            if not u or not session.get("mfa_ok"):
                abort(401)
            if permissao not in PERMISSOES.get(u["perfil"], set()):
                registrar("acesso_negado", permissao=permissao, rota=request.path)
                abort(403)
            return f(*a, **kw)

        return inner

    return wrap


def bloqueado(chave):
    fila = FALHAS[chave]
    limite = time.time() - JANELA
    while fila and fila[0] < limite:
        fila.popleft()
    return len(fila) >= MAX_FALHAS


@app.get("/")
def inicio():
    return render_template("index.html")


@app.post("/login")
def login():
    """Senha (PBKDF2) + segundo fator TOTP (RT-09)."""
    dados = request.get_json(silent=True) or {}
    login_u = str(dados.get("login", ""))[:40]
    senha = str(dados.get("senha", ""))[:200]
    totp = str(dados.get("totp", ""))
    if not RE_ID.match(login_u) or not RE_TOTP.match(totp):
        abort(400)
    chave = f"{request.remote_addr}|{login_u}"
    if bloqueado(chave):
        registrar("login_bloqueado", alvo=login_u)
        return jsonify(erro="muitas tentativas. Aguarde 5 minutos."), 429
    with db().cursor() as cur:
        cur.execute("SELECT salt_operador(%s)", (login_u,))
        salt = cur.fetchone()[0]
        calc = hashlib.pbkdf2_hmac(
            "sha256", senha.encode(), (salt or SALT_FICTICIO).encode(), 200_000
        ).hex()
        cur.execute(
            "SELECT perfil, totp_secret FROM autenticar(%s, %s)", (login_u, calc)
        )
        row = cur.fetchone() if salt else None
    if not row or not pyotp.TOTP(row[1]).verify(totp, valid_window=1):
        FALHAS[chave].append(time.time())
        registrar("login_falhou", alvo=login_u)
        time.sleep(0.3)
        # mesma resposta para usuario inexistente, senha errada ou TOTP errado
        return jsonify(erro="usuario, senha ou codigo invalidos"), 401
    FALHAS.pop(chave, None)
    session.clear()
    session.permanent = True
    session["usuario"] = {"login": login_u, "perfil": row[0]}
    session["mfa_ok"] = True
    registrar("login_ok")
    return jsonify(ok=True, perfil=row[0], permissoes=sorted(PERMISSOES[row[0]]))


@app.post("/logout")
def logout():
    registrar("logout")
    session.clear()
    return jsonify(ok=True)


@app.get("/historico")
@exige("historico:ler")
def historico():
    """Campo de busca do historico - era o ponto vulneravel a SQLi.

    Agora: parametro validado e consulta parametrizada. Nenhuma string do
    usuario entra no texto SQL.
    """
    espaco = request.args.get("espaco", "")
    recurso = request.args.get("recurso", "")
    dispositivo = request.args.get("dispositivo", "")
    # validacao por allowlist: fora disso, 400 sem tocar no banco
    if espaco and espaco not in ESPACOS:
        abort(400)
    if recurso and recurso not in RECURSOS:
        abort(400)
    if dispositivo and not RE_ID.match(dispositivo):
        abort(400)

    cond, params = [], []
    if espaco:
        cond.append("espaco = %s")
        params.append(espaco)
    if recurso:
        cond.append("recurso = %s")
        params.append(recurso)
    if dispositivo:
        cond.append("dispositivo = %s")
        params.append(dispositivo)
    where = (" WHERE " + " AND ".join(cond)) if cond else ""
    sql = (
        "SELECT ts, espaco, recurso, dispositivo, evento "
        "FROM v_historico_acesso" + where + " ORDER BY ts DESC LIMIT 200"
    )
    try:
        with db().cursor() as cur:
            cur.execute(sql, params)  # params passa separado do texto SQL
            linhas = [
                {
                    "ts": r[0].isoformat(),
                    "espaco": r[1],
                    "recurso": r[2],
                    "dispositivo": r[3],
                    "evento": r[4],
                }
                for r in cur.fetchall()
            ]
        return jsonify(total=len(linhas), historico=linhas)
    except psycopg.Error:
        # erro detalhado so no log; usuario recebe mensagem generica (RT-08)
        log.exception("falha na consulta de historico")
        return jsonify(erro="nao foi possivel consultar o historico"), 500


@app.get("/telemetria")
@exige("telemetria:ler")
def telemetria():
    with db().cursor() as cur:
        cur.execute(
            "SELECT dispositivo, espaco, recurso, valor, ts_origem "
            "FROM v_telemetria_recente ORDER BY espaco, dispositivo"
        )
        linhas = [
            {
                "dispositivo": r[0],
                "espaco": r[1],
                "recurso": r[2],
                "valor": r[3],
                "ts": r[4].isoformat(),
            }
            for r in cur.fetchall()
        ]
    return jsonify(sensores=linhas)


@app.post("/atuador")
def atuador():
    """Pedido de comando de atuador. Baixo risco: tecnico ou coordenacao, executa.
    Alto impacto: so coordenacao pede, e outra pessoa da coordenacao aprova."""
    u = session.get("usuario")
    if not u or not session.get("mfa_ok"):
        abort(401)
    dados = request.get_json(silent=True) or {}
    acao, alvo = str(dados.get("acao", "")), str(dados.get("alvo", ""))
    if acao not in ACOES_BAIXO | ACOES_ALTO or not RE_ID.match(alvo):
        abort(400)
    precisa = "atuador:alto" if acao in ACOES_ALTO else "atuador:baixo"
    if precisa not in PERMISSOES.get(u["perfil"], set()):
        # evento de atuador negado tambem vai para o SIEM (regra 100131)
        registrar("comando_atuador", acao=acao, alvo=alvo, resultado="negado_rbac")
        abort(403)
    try:
        with db().cursor() as cur:
            cur.execute(
                "SELECT id, risco, status FROM registrar_comando(%s, %s, %s)",
                (u["login"], acao, alvo),
            )
            cid, risco, status = cur.fetchone()
    except psycopg.Error:
        log.exception("falha ao registrar comando")
        return jsonify(erro="nao foi possivel registrar o comando"), 500
    registrar(
        "comando_atuador", acao=acao, alvo=alvo, risco=risco, resultado=status, id=cid
    )
    return jsonify(id=cid, risco=risco, status=status)


@app.post("/atuador/<int:cid>/decisao")
@exige("comando:aprovar")
def decidir(cid):
    dados = request.get_json(silent=True) or {}
    aprovar = dados.get("aprovar") is True
    try:
        with db().cursor() as cur:
            cur.execute(
                "SELECT decidir_comando(%s, %s, %s)",
                (cid, session["usuario"]["login"], aprovar),
            )
            status = cur.fetchone()[0]
    except psycopg.Error as e:
        registrar(
            "decisao_recusada", id=cid, motivo=getattr(e.diag, "message_primary", "")
        )
        return jsonify(
            erro="decisao nao permitida (precisa ser outra pessoa e o pedido estar pendente)"
        ), 409
    registrar("comando_decidido", id=cid, resultado=status)
    return jsonify(id=cid, status=status)


@app.get("/comandos")
@exige("comando:ler")
def comandos():
    with db().cursor() as cur:
        cur.execute(
            "SELECT id, solicitado_em, solicitante, perfil, acao, alvo, risco, status, "
            "aprovador, decidido_em FROM v_comando_atuador ORDER BY id DESC LIMIT 100"
        )
        cols = [d.name for d in cur.description]
        linhas = [
            {
                k: (v.isoformat() if hasattr(v, "isoformat") else v)
                for k, v in zip(cols, r)
            }
            for r in cur.fetchall()
        ]
    return jsonify(comandos=linhas)


@app.get("/saude")
def saude():
    return jsonify(ok=True)


if __name__ == "__main__":
    # escuta so no loopback; exposicao externa e feita pela VPN + WAF
    app.run(host="127.0.0.1", port=8080)
