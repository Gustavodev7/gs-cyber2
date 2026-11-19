"""
Linha do tempo forense do INC-VA-0712 (RT-14), com MITRE ATT&CK (Enterprise e ICS).

Duas linhas do tempo, separadas de proposito:
  1. INCIDENTE ORIGINAL: reconstruida a partir do relato da associacao e dos
     logs preservados (caso INC-VA-0712-original). Horario local (UTC-3).
  2. REPRODUCAO EM LABORATORIO: gerada AUTOMATICAMENTE a partir das evidencias
     coletadas (caso INC-VA-0712-repro), sem nada digitado a mao. Horario UTC.

Uso: python forense/consolidar_timeline.py [--caso INC-VA-0712-repro]
Saida: forense/casos/<caso>/timeline.json e timeline.md
"""

import argparse
import json
import re
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
CASOS = RAIZ / "forense" / "casos"

# (quando UTC-3, evento, fonte, tatica, tecnica). Fonte = de onde vem a afirmacao.
INCIDENTE_ORIGINAL = [
    (
        "2026-02-06 19:40",
        "E-mail 'da prefeitura' (texto gerado por IA) com link para pagina falsa de login",
        "relato da coordenadora",
        "Reconnaissance",
        "T1598.003 Spearphishing Link",
    ),
    (
        "2026-02-06 19:52",
        "Audio de WhatsApp com voz clonada do secretario reforca a urgencia",
        "relato da coordenadora",
        "Reconnaissance",
        "T1598.004 Spearphishing Voice",
    ),
    (
        "2026-02-06 20:05",
        "Usuario e senha digitados na pagina falsa (credencial colhida)",
        "relato da coordenadora",
        "Resource Development",
        "T1586 Compromise Accounts",
    ),
    (
        "2026-02-07 02:14",
        "Login na VPN legada (so senha, sem MFA) a partir de IP externo 203.0.113.45",
        "vpn.log (E01)",
        "Initial Access",
        "T1133 External Remote Services; T1078 Valid Accounts",
    ),
    (
        "2026-02-07 02:15",
        "SQL Injection no campo de busca do historico do painel legado",
        "painel.log (E02)",
        "Initial Access",
        "T1190 Exploit Public-Facing Application",
    ),
    (
        "2026-02-07 02:15",
        "Extracao da tabela de usuarios (UNION SELECT ... FROM operador)",
        "painel.log (E02)",
        "Collection",
        "T1213 Data from Information Repositories",
    ),
    (
        "2026-02-07 02:16",
        "Agendamento da bomba alterado para 03:00",
        "atuador.log (E03)",
        "Impair Process Control (ICS)",
        "T0836 Modify Parameter",
    ),
    (
        "2026-02-07 03:30",
        "Reservatorio da escola esvazia durante a madrugada",
        "relato da escola",
        "Impact (ICS)",
        "T0826 Loss of Availability",
    ),
    (
        "2026-02-07 03:45",
        "Fibra cai; camara fria da UBS sem alerta (dependia da nuvem)",
        "relato da UBS",
        "-",
        "Sem tecnica: falha de arquitetura, nao acao do atacante",
    ),
    (
        "2026-02-07 08:00",
        "Investigacao: logs espalhados, relogios fora de sincronia, parte sobrescrita",
        "equipe",
        "-",
        "Lacuna defensiva. Sobrescrita nao atribuivel ao atacante (T1070 nao confirmado)",
    ),
]

RE_SQLI = re.compile(
    r"(?i)(union\s+(all\s+)?select|'\s*(or|and)\s|pg_sleep|information_schema|'\s*;)"
)


def ler_jsonl(p):
    for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if ln.startswith("{"):
            try:
                yield json.loads(ln)
            except json.JSONDecodeError:
                continue


def agrupar(eventos):
    """Agrupa eventos repetidos (ex.: centenas de requisicoes do sqlmap) em uma
    linha com primeiro/ultimo horario e contagem."""
    grupos = {}
    for ts, chave, desc, fonte, tatica, tec in eventos:
        g = grupos.setdefault(
            chave,
            {
                "inicio": ts,
                "fim": ts,
                "qtd": 0,
                "evento": desc,
                "fonte": fonte,
                "tatica": tatica,
                "tecnica": tec,
            },
        )
        g["inicio"], g["fim"] = min(g["inicio"], ts), max(g["fim"], ts)
        g["qtd"] += 1
    return sorted(grupos.values(), key=lambda g: g["inicio"])


def reproducao(pasta):
    ev = []
    evid = pasta / "evidencias"
    for p in sorted(evid.glob("*.json")):
        for e in ler_jsonl(p):
            ts, nome = e.get("ts", ""), e.get("evento")
            if nome == "vpn_handshake":
                ev.append(
                    (
                        ts,
                        "vpn",
                        f"Sessao VPN do peer {e.get('peer')} a partir de {e.get('srcip')}",
                        p.name,
                        "Initial Access",
                        "T1133; T1078",
                    )
                )
            elif nome == "http" and RE_SQLI.search(e.get("rota", "")):
                ev.append(
                    (
                        ts,
                        f"sqli-{e.get('app')}",
                        f"Requisicoes com payload de SQL Injection em {e.get('app')} (origem {e.get('srcip')})",
                        p.name,
                        "Initial Access",
                        "T1190",
                    )
                )
            elif nome == "comando_atuador":
                ev.append(
                    (
                        ts,
                        f"atu-{e.get('resultado')}",
                        f"Pedido de comando {e.get('acao')} por {e.get('login')}/{e.get('perfil')}: {e.get('resultado')}",
                        p.name,
                        "Impair Process Control (ICS)",
                        "T0855 Unauthorized Command Message",
                    )
                )
            elif nome in ("soar_acao", "soar_decisao"):
                ev.append(
                    (
                        ts,
                        f"soar-{e.get('acao')}-{e.get('resultado')}",
                        f"Resposta SOAR: {e.get('acao')} {e.get('alvo')} -> {e.get('resultado')}",
                        p.name,
                        "Resposta",
                        "-",
                    )
                )
            elif nome == "alarme_local":
                ev.append(
                    (
                        ts,
                        f"alarme-{e.get('tipo')}",
                        f"Alarme local na borda: {e.get('tipo')}",
                        p.name,
                        "Deteccao local",
                        "-",
                    )
                )
    for p in sorted(evid.glob("*.log")):
        for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
            ts = ln[:23]
            if "agendamento_bomba" in ln and re.search(r"(?i)\bupdate\b", ln):
                ev.append(
                    (
                        ts,
                        "pg-bomba",
                        "UPDATE no agendamento da bomba via injecao empilhada (stacked query)",
                        p.name,
                        "Impair Process Control (ICS)",
                        "T0836 Modify Parameter",
                    )
                )
            elif re.search(r"(?i)from\s+(vila\.)?operador", ln) and "statement:" in ln:
                ev.append(
                    (
                        ts,
                        "pg-operador",
                        "Consulta a tabela operador (hashes e segredos) pelo usuario do legado",
                        p.name,
                        "Collection",
                        "T1213",
                    )
                )
            elif re.search(r"certificate (verify failed|revoked)|OpenSSL Error", ln):
                ev.append(
                    (
                        ln[:19],
                        "mqtt-cert",
                        "Broker recusou dispositivo com certificado invalido/revogado",
                        p.name,
                        "Initial Access (tentativa)",
                        "T1200 / T0848",
                    )
                )
    return agrupar(ev)


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--caso", default="INC-VA-0712-repro")
    caso = a.parse_args().caso
    pasta = CASOS / caso
    custodia_p = pasta / "custodia.json"
    custodia = (
        json.loads(custodia_p.read_text(encoding="utf-8"))
        if custodia_p.exists()
        else []
    )
    original = [
        dict(zip(("quando", "evento", "fonte", "tatica", "tecnica"), e))
        for e in INCIDENTE_ORIGINAL
    ]
    repro = reproducao(pasta) if (pasta / "evidencias").exists() else []
    (pasta).mkdir(parents=True, exist_ok=True)
    (pasta / "timeline.json").write_text(
        json.dumps(
            {
                "incidente": "INC-VA-0712",
                "incidente_original_utc-3": original,
                "reproducao_lab_utc": repro,
                "evidencias": custodia,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    md = [
        "# Linha do tempo - INC-VA-0712",
        "",
        "## 1. Incidente original (reconstruido, UTC-3)",
        "",
        "| Quando | Evento | Fonte | Tatica | Tecnica ATT&CK |",
        "|---|---|---|---|---|",
    ]
    md += [
        f"| {e['quando']} | {e['evento']} | {e['fonte']} | {e['tatica']} | {e['tecnica']} |"
        for e in original
    ]
    md += [
        "",
        f"## 2. Reproducao em laboratorio (gerada das evidencias de {caso}, UTC)",
        "",
    ]
    if repro:
        md += [
            "| Inicio | Fim | Qtd | Evento | Evidencia | Tatica | Tecnica |",
            "|---|---|---|---|---|---|---|",
        ]
        md += [
            f"| {g['inicio']} | {g['fim']} | {g['qtd']} | {g['evento']} | {g['fonte']} | {g['tatica']} | {g['tecnica']} |"
            for g in repro
        ]
    else:
        md.append(
            "_Sem evidencias coletadas ainda: rodar forense/reproduzir_incidente.sh._"
        )
    md += [
        "",
        "## Evidencias (cadeia de custodia)",
        "",
        "| ID | Evidencia | SHA-256 | Coletor | Em (UTC) |",
        "|---|---|---|---|---|",
    ]
    md += [
        f"| {e['id']} | {e['evidencia']} | `{e['sha256']}` | {e['coletado_por']} | {e['coletado_em']} |"
        for e in custodia
    ]
    (pasta / "timeline.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))


if __name__ == "__main__":
    main()
