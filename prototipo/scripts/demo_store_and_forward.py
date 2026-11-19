"""
Demonstracao da continuidade local e do store-and-forward (RT-02, RT-22, RT-23).

Exercita a MESMA logica de buffer do no de borda, de forma autocontida (sem
broker nem nuvem), para provar duas propriedades mensuraveis:
  - operacao autonoma enquanto o link WAN esta fora (eventos continuam sendo
    coletados e as regras locais continuam decidindo);
  - reconciliacao SEM perda de dados ao voltar o link (todos os eventos do
    backlog chegam, em ordem, exatamente uma vez).

NAO substitui o teste de caos real de >=30 min com o link fisico derrubado:
isso o grupo executa e evidencia (RT-23). Aqui o tempo e simulado para medir a
corretude. Semente fixa -> reproduzivel.
Uso: python demo_store_and_forward.py
"""

import json
import sqlite3
import time
from pathlib import Path

AQUI = Path(__file__).resolve().parent
BUF = AQUI / "demo_buffer.db"
if BUF.exists():
    BUF.unlink()

con = sqlite3.connect(BUF)
con.execute(
    "CREATE TABLE fila(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, payload TEXT, enviado INTEGER DEFAULT 0)"
)
con.commit()

nuvem_recebida = []  # o que a "nuvem" efetivamente recebeu
link_up = False  # comeca com o link caido (cenario do temporal)

TEMP_MIN, TEMP_MAX = 2.0, 8.0
alarmes_locais = 0


def coletar(evento):
    """Sempre grava no buffer local, haja ou nao internet (continuidade)."""
    global alarmes_locais
    con.execute(
        "INSERT INTO fila(ts,payload) VALUES(?,?)", (evento["ts"], json.dumps(evento))
    )
    con.commit()
    if evento["recurso"] == "ambiente" and not (
        TEMP_MIN <= evento["valor"] <= TEMP_MAX
    ):
        alarmes_locais += 1  # regra local decide mesmo offline


def sincronizar():
    """Envia o backlog em ordem; so marca enviado quando a nuvem confirma."""
    if not link_up:
        return 0
    cur = con.execute("SELECT id,payload FROM fila WHERE enviado=0 ORDER BY id")
    n = 0
    for id_, payload in cur.fetchall():
        nuvem_recebida.append(json.loads(payload))  # entrega
        con.execute("UPDATE fila SET enviado=1 WHERE id=?", (id_,))
        n += 1
    con.commit()
    return n


# --- cenario ---------------------------------------------------------------
# 30 "minutos" de link fora, 1 evento por minuto por 4 sensores (simulado).
base = time.time()
total_gerado = 0
for minuto in range(30):
    for sensor, recurso, valor in [
        (
            "ubs-geladeira",
            "ambiente",
            5.0 if minuto % 7 else 11.0,
        ),  # as vezes fora da faixa
        ("escola-nivel", "agua", 40.0),
        ("centro-energia", "energia", 70.0),
        ("abrigo-alagamento", "ambiente", 6.0),
    ]:
        coletar(
            {
                "dispositivo": sensor,
                "recurso": recurso,
                "valor": valor,
                "ts": base + minuto * 60,
            }
        )
        total_gerado += 1
    sincronizar()  # tenta, mas link esta down -> nada sai

offline_backlog = con.execute("SELECT COUNT(*) FROM fila WHERE enviado=0").fetchone()[0]

# Link volta: reconciliacao
link_up = True
t0 = time.perf_counter()
enviados = sincronizar()
dt = time.perf_counter() - t0

# --- metricas --------------------------------------------------------------
perda = total_gerado - len(nuvem_recebida)
duplicados = len(nuvem_recebida) - len(
    {(e["dispositivo"], e["ts"]) for e in nuvem_recebida}
)
ordenado = all(
    nuvem_recebida[i]["ts"] <= nuvem_recebida[i + 1]["ts"]
    for i in range(len(nuvem_recebida) - 1)
)
print(f"eventos gerados offline........: {total_gerado}")
print(f"backlog acumulado no buffer....: {offline_backlog}")
print(f"alarmes locais decididos offline: {alarmes_locais}")
print(f"eventos entregues na reconciliacao: {enviados}")
print(f"perda de dados.................: {perda}  (esperado 0)")
print(f"duplicados.....................: {duplicados}  (esperado 0)")
print(f"ordem preservada...............: {ordenado}")
print(f"tempo de reconciliacao.........: {dt * 1000:.1f} ms")
con.close()
BUF.unlink(missing_ok=True)
assert perda == 0 and duplicados == 0 and ordenado, "store-and-forward falhou"
print("RESULTADO: continuidade local OK, reconciliacao sem perda nem duplicacao.")
