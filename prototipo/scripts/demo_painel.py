"""
Ajudante de laboratorio para o painel (login MFA via API). Faz o que um navegador
faria, para scripts automatizados. So laboratorio isolado, dados sinteticos.

Subcomandos:
  sessao <login> [--url URL]   faz login (senha+TOTP de credenciais_lab.txt) e
                               imprime o cookie de sessao (para o --cookie do sqlmap).
  rbac [--url URL]             prova o RBAC (RT-09): um operador sem permissao recebe
                               403 ao pedir desligar_bomba; a coordenacao consegue
                               registrar e outra pessoa aprova (quatro olhos).
Le as credenciais de nuvem/painel/credenciais_lab.txt (gerado pelo seed).
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path

import pyotp

RAIZ = Path(__file__).resolve().parent.parent
# gerado por subir_lab.sh no volume de logs (fora do git)
CRED = Path(os.environ.get("CREDENCIAIS_SAIDA", RAIZ / "logs" / "credenciais_lab.txt"))


def credenciais():
    cred = {}
    for ln in CRED.read_text(encoding="utf-8").splitlines()[1:]:
        p = ln.split()
        if len(p) >= 4:
            cred[p[0]] = {"perfil": p[1], "senha": p[2], "totp": p[3]}
    return cred


def cliente():
    cj = CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj)), cj


def post(op, url, caminho, dados):
    req = urllib.request.Request(
        url + caminho,
        json.dumps(dados).encode(),
        {"Content-Type": "application/json"},
        method="POST",
    )

    def corpo(b):
        try:
            return json.loads(b or b"{}")
        except json.JSONDecodeError:
            return {}  # paginas de erro do Flask (abort) vem em HTML, nao JSON

    try:
        with op.open(req, timeout=10) as r:
            return r.status, corpo(r.read())
    except urllib.error.HTTPError as e:
        return e.code, corpo(e.read())


def login(op, url, login_u, cred):
    c = cred[login_u]
    return post(
        op,
        url,
        "/login",
        {"login": login_u, "senha": c["senha"], "totp": pyotp.TOTP(c["totp"]).now()},
    )


def cmd_sessao(a):
    cred = credenciais()
    op, cj = cliente()
    st, _ = login(op, a.url, a.quem, cred)
    if st != 200:
        print(f"login falhou ({st})", file=sys.stderr)
        return 1
    print("; ".join(f"{ck.name}={ck.value}" for ck in cj))
    return 0


def cmd_rbac(a):
    cred = credenciais()
    url = a.url
    print("== RBAC (RT-09) ==")
    op, _ = cliente()
    login(op, url, "bruno", cred)
    st, resp = post(
        op, url, "/atuador", {"acao": "desligar_bomba", "alvo": "escola-bomba"}
    )
    print(f"operador 'bruno' pede desligar_bomba -> HTTP {st} (esperado 403)")
    op_a, _ = cliente()
    login(op_a, url, "ana", cred)
    st, resp = post(
        op_a, url, "/atuador", {"acao": "desligar_bomba", "alvo": "escola-bomba"}
    )
    print(
        f"coordenacao 'ana' pede desligar_bomba -> HTTP {st}, status={resp.get('status')} (id {resp.get('id')})"
    )
    cid = resp.get("id")
    st, _ = post(op_a, url, f"/atuador/{cid}/decisao", {"aprovar": True})
    print(f"'ana' tenta aprovar o proprio pedido -> HTTP {st} (esperado 409)")
    op_b, _ = cliente()
    login(op_b, url, "beto", cred)
    st, resp = post(op_b, url, f"/atuador/{cid}/decisao", {"aprovar": True})
    print(
        f"'beto' aprova o pedido {cid} -> HTTP {st}, status={resp.get('status')} (esperado aprovado)"
    )
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sessao")
    s.add_argument("quem")
    s.add_argument("--url", default="http://127.0.0.1:8080")
    r = sub.add_parser("rbac")
    r.add_argument("--url", default="http://127.0.0.1:8080")
    a = ap.parse_args()
    return cmd_sessao(a) if a.cmd == "sessao" else cmd_rbac(a)


if __name__ == "__main__":
    raise SystemExit(main())
