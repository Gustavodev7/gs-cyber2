"""
Aquisicao forense com integridade (RT-14).

coletar:   copia cada evidencia para forense/casos/<caso>/evidencias/, calcula o
           SHA-256 da ORIGEM e da COPIA no momento da coleta (precisam bater) e
           registra na cadeia de custodia (quem, quando, onde, como). Append: o
           historico nunca e reescrito.
verificar: recalcula o hash de cada copia e compara com o registrado na custodia.
           Qualquer alteracao numa evidencia e detectada.

Uso:
  python forense/coletar_evidencia.py coletar --caso INC-VA-0712-repro \
      --coletor "Perito 1 (equipe)" --local lab-vila-aurora logs/painel_legado.json ...
  python forense/coletar_evidencia.py verificar --caso INC-VA-0712-repro
Sem dados pessoais na custodia: caminho relativo ao projeto e rotulo do host do lab.
"""

import argparse
import hashlib
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent  # prototipo/
CASOS = RAIZ / "forense" / "casos"


def sha256(caminho: Path) -> str:
    h = hashlib.sha256()
    with caminho.open("rb") as f:
        for bloco in iter(lambda: f.read(65536), b""):
            h.update(bloco)
    return h.hexdigest()


def relativo(p: Path) -> str:
    try:
        return str(p.resolve().relative_to(RAIZ))
    except ValueError:
        return p.name  # fora do projeto: so o nome, sem expor caminho pessoal


def coletar(a):
    pasta = CASOS / a.caso
    destino = pasta / "evidencias"
    destino.mkdir(parents=True, exist_ok=True)
    cust = pasta / "custodia.json"
    registros = json.loads(cust.read_text(encoding="utf-8")) if cust.exists() else []
    for arg in a.arquivos:
        origem = Path(arg)
        if not origem.is_file():
            print(f"ignorado (nao e arquivo): {arg}")
            continue
        h_origem = sha256(origem)
        copia = destino / origem.name
        shutil.copy2(origem, copia)
        h_copia = sha256(copia)
        if h_copia != h_origem:
            print(f"ERRO: copia de {origem.name} difere da origem")
            return 1
        copia.chmod(0o444)  # evidencia so leitura
        reg = {
            "id": f"{a.caso}-E{len(registros) + 1:02d}",
            "evidencia": origem.name,
            "origem": relativo(origem),
            "copia": relativo(copia),
            "sha256": h_origem,
            "tamanho_bytes": origem.stat().st_size,
            "coletado_por": a.coletor,
            "coletado_em": datetime.now(UTC).isoformat(timespec="seconds"),
            "local": a.local,
            "metodo": "copia logica (shutil.copy2) + SHA-256 da origem e da copia no momento da coleta",
        }
        registros.append(reg)
        print(f"{reg['id']}  {origem.name}  SHA-256={h_origem}")
    cust.write_text(
        json.dumps(registros, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"cadeia de custodia: {len(registros)} evidencia(s) em {relativo(cust)}")
    return 0


def verificar(a):
    cust = CASOS / a.caso / "custodia.json"
    registros = json.loads(cust.read_text(encoding="utf-8"))
    falhas = 0
    for r in registros:
        p = RAIZ / r["copia"]
        atual = sha256(p) if p.exists() else "AUSENTE"
        ok = atual == r["sha256"]
        falhas += not ok
        print(
            f"{'OK   ' if ok else 'FALHA'} {r['id']} {r['evidencia']} {atual[:16]}..."
        )
    print(
        "integridade confirmada"
        if not falhas
        else f"{falhas} evidencia(s) alterada(s)!"
    )
    return 1 if falhas else 0


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("coletar")
    c.add_argument("--caso", required=True)
    c.add_argument("--coletor", required=True)
    c.add_argument("--local", default="lab-vila-aurora")
    c.add_argument("arquivos", nargs="+")
    v = sub.add_parser("verificar")
    v.add_argument("--caso", required=True)
    a = p.parse_args()
    return coletar(a) if a.cmd == "coletar" else verificar(a)


if __name__ == "__main__":
    sys.exit(main())
