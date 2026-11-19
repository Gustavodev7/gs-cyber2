"""
Respostas automatizadas por risco (RT-15 / SOAR). Roda no host do laboratorio,
na pasta prototipo/.

BAIXO risco -> executa na hora, de verdade:
  revogar_certificado <cn>   revoga na CA, regenera a CRL e recarrega o broker
  isolar_dispositivo <cn>    tira as permissoes do dispositivo na ACL e recarrega
  bloquear_ip <ip>           regra DROP na cadeia DOCKER-USER (Linux + root);
                             sem permissao, registra na lista de bloqueio
  encerrar_sessao_vpn <pub>  remove o peer do WireGuard (wg set ... remove)
  atuador_modo_seguro <espaco>/<alvo>  publica comando MQTT assinado pelo SOAR
ALTO impacto -> NAO executa: entra na fila e precisa de aprovacao de OUTRA pessoa
  desligar_bomba, liberar_todas_portas, desligar_energia_espaco
  python responder.py aprovar <id> --por <login>   |   negar <id> --por <login>

Toda acao vira uma linha JSON em logs/atuador.json (SIEM, regra 100130) e o
estado da fila fica em automacao/aprovacoes_pendentes.json.
Uso:
  python automacao/responder.py bloquear_ip 203.0.113.45 --motivo "VPN anomala" --por soc
  python automacao/responder.py desligar_bomba abrigo --motivo "nivel critico" --por ana
  python automacao/responder.py aprovar 1 --por beto
So dados sinteticos / laboratorio isolado.
"""

import argparse
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent  # prototipo/
PENDENTES = RAIZ / "automacao" / "aprovacoes_pendentes.json"
BLOQUEIOS = RAIZ / "automacao" / "ips_bloqueados.txt"
LOG = RAIZ / "logs" / "atuador.json"
ACL = RAIZ / "borda" / "acl"
PKI = RAIZ / "pki"
RE_CN = re.compile(r"^[a-z0-9-]{1,40}$")

RISCO = {
    "isolar_dispositivo": "baixo",
    "revogar_certificado": "baixo",
    "encerrar_sessao_vpn": "baixo",
    "bloquear_ip": "baixo",
    "atuador_modo_seguro": "baixo",
    "desligar_bomba": "alto",
    "liberar_todas_portas": "alto",
    "desligar_energia_espaco": "alto",
}


def agora():
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def registrar(**campos):
    LOG.parent.mkdir(exist_ok=True)
    linha = {"ts": agora(), "app": "soar", **campos}
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(linha, ensure_ascii=False) + "\n")
    print(json.dumps(linha, ensure_ascii=False))


def rodar(cmd):
    r = subprocess.run(cmd, cwd=RAIZ, capture_output=True, text=True, check=False)
    return r.returncode == 0, (r.stdout + r.stderr).strip()[-300:]


def recarregar_broker():
    return rodar(["docker", "compose", "kill", "-s", "HUP", "mosquitto"])


# ----------------------------------------------------------- acoes de baixo risco
def revogar_certificado(cn):
    if not RE_CN.match(cn):
        return False, "cn invalido"
    ok, saida = rodar(["bash", "pki/revogar_dispositivo.sh", cn])
    if ok:
        ok, saida2 = recarregar_broker()
        saida += " | broker: " + saida2
    return ok, saida


def isolar_dispositivo(cn):
    if not RE_CN.match(cn):
        return False, "cn invalido"
    linhas = ACL.read_text(encoding="utf-8").splitlines()
    saida, dentro, achou = [], False, False
    for ln in linhas:
        if ln.strip() == f"user {cn}":
            dentro, achou = True, True
            saida.append(f"# ISOLADO pelo SOAR em {agora()}: {ln}")
            continue
        if dentro and ln.startswith("topic "):
            saida.append(f"# {ln}")
            continue
        dentro = False
        saida.append(ln)
    if not achou:
        return False, f"{cn} nao esta na ACL"
    ACL.write_text("\n".join(saida) + "\n", encoding="utf-8")
    ok, s = recarregar_broker()
    return ok, "ACL sem permissoes para o dispositivo; broker recarregado. " + s


def bloquear_ip(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False, "ip invalido"
    with BLOQUEIOS.open("a", encoding="utf-8") as f:
        f.write(f"{ip}\n")
    if sys.platform.startswith("linux") and shutil.which("iptables"):
        ok, s = rodar(["iptables", "-I", "DOCKER-USER", "-s", ip, "-j", "DROP"])
        if ok:
            return (
                True,
                "DROP na cadeia DOCKER-USER (trafego do IP para os servicos bloqueado)",
            )
        return (
            True,
            f"registrado em ips_bloqueados.txt; iptables falhou (rodar como root): {s}",
        )
    return True, "registrado em ips_bloqueados.txt (aplicar no firewall do host Linux)"


def encerrar_sessao_vpn(chave_publica):
    if not re.fullmatch(r"[A-Za-z0-9+/]{42,43}=", chave_publica):
        return False, "chave publica WireGuard invalida"
    if not shutil.which("wg"):
        return False, "wg nao instalado neste host"
    ok, s = rodar(["wg", "set", "wg0", "peer", chave_publica, "remove"])
    return ok, s or "peer removido do wg0: sessao encerrada"


def atuador_modo_seguro(alvo):
    m = re.fullmatch(r"([a-z]{1,20})/([a-z0-9-]{1,40})", alvo)
    if not m:
        return False, "alvo deve ser <espaco>/<equipamento>"
    import paho.mqtt.client as mqtt  # so quando preciso

    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="soar")
    c.tls_set(
        ca_certs=str(PKI / "ca/ca.cert.pem"),
        certfile=str(PKI / "certs/soar.cert.pem"),
        keyfile=str(PKI / "private/soar.key.pem"),
    )
    c.connect("localhost", 8883, keepalive=10)
    c.loop_start()
    info = c.publish(
        f"vila/{m[1]}/comando/{m[2]}",
        json.dumps({"acao": "atuador_modo_seguro", "alvo": m[2], "origem": "soar"}),
        qos=1,
    )
    info.wait_for_publish(timeout=5)
    c.loop_stop()
    c.disconnect()
    return (
        info.is_published(),
        "comando publicado para a borda (MQTT/mTLS, identidade soar)",
    )


ACOES = {
    "revogar_certificado": revogar_certificado,
    "isolar_dispositivo": isolar_dispositivo,
    "bloquear_ip": bloquear_ip,
    "encerrar_sessao_vpn": encerrar_sessao_vpn,
    "atuador_modo_seguro": atuador_modo_seguro,
}


# ----------------------------------------------------------- fila de alto impacto
def ler_fila():
    return (
        json.loads(PENDENTES.read_text(encoding="utf-8")) if PENDENTES.exists() else []
    )


def gravar_fila(fila):
    PENDENTES.write_text(
        json.dumps(fila, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def pedir_aprovacao(acao, alvo, motivo, por):
    fila = ler_fila()
    pid = max((p["id"] for p in fila), default=0) + 1
    fila.append(
        {
            "id": pid,
            "acao": acao,
            "alvo": alvo,
            "motivo": motivo,
            "solicitado_por": por,
            "solicitado_em": agora(),
            "status": "aguardando_humano",
        }
    )
    gravar_fila(fila)
    registrar(
        evento="soar_acao",
        acao=acao,
        alvo=alvo,
        risco="alto",
        login=por,
        resultado="aguardando_aprovacao",
        id=pid,
        motivo=motivo,
    )


def decidir(pid, por, aprovar):
    fila = ler_fila()
    pedido = next((p for p in fila if p["id"] == pid), None)
    if not pedido or pedido["status"] != "aguardando_humano":
        print("pedido inexistente ou ja decidido")
        return 1
    if pedido["solicitado_por"] == por:
        registrar(
            evento="decisao_recusada",
            acao=pedido["acao"],
            id=pid,
            login=por,
            motivo="aprovador deve ser outra pessoa",
        )
        return 1
    pedido.update(
        status="aprovado" if aprovar else "negado",
        decidido_por=por,
        decidido_em=agora(),
    )
    gravar_fila(fila)
    # Aprovado: aqui o operador executa o comando fisico com o equipamento a vista.
    registrar(
        evento="soar_decisao",
        acao=pedido["acao"],
        alvo=pedido["alvo"],
        id=pid,
        login=por,
        resultado=pedido["status"],
    )
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="SOAR da Rede Vila Aurora")
    p.add_argument("acao")
    p.add_argument("alvo")
    p.add_argument("--motivo", default="")
    p.add_argument("--por", default="soar-automatico", help="quem pediu / quem decide")
    a = p.parse_args(argv)

    if a.acao in ("aprovar", "negar"):
        return decidir(int(a.alvo), a.por, a.acao == "aprovar")
    risco = RISCO.get(a.acao)
    if risco is None:
        registrar(
            evento="soar_acao", acao=a.acao, alvo=a.alvo, resultado="acao_desconhecida"
        )
        return 2
    if risco == "alto":
        pedir_aprovacao(a.acao, a.alvo, a.motivo, a.por)
        return 0
    t0 = time.perf_counter()
    ok, detalhe = ACOES[a.acao](a.alvo)
    registrar(
        evento="soar_acao",
        acao=a.acao,
        alvo=a.alvo,
        risco="baixo",
        login=a.por,
        resultado="executado" if ok else "falhou",
        detalhe=detalhe,
        motivo=a.motivo,
        duracao_ms=round((time.perf_counter() - t0) * 1000),
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
