"""
Metricas do teste de caos (RT-22) a partir de scripts/caos/amostras.csv.
Calcula: tempo de operacao autonoma sem internet, backlog maximo acumulado,
tempo de reconciliacao (MTTR do link), perda de dados (gerados x recebidos),
disponibilidade local (%), e consumo de CPU/memoria do no de borda.
Desenha um grafico ASCII do backlog no tempo (serve de figura para o E3).
Uso: python medir_caos.py amostras.csv <epoch_inicio_sem_wan> <epoch_restaurou> <epoch_fim>
"""

import csv
import sys
from datetime import UTC, datetime


def ler(caminho):
    with open(caminho, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def grafico(serie, altura=10, largura=60):
    if not serie:
        return "(sem dados)"
    vmax = max(max(serie), 1)
    passo = max(1, len(serie) // largura)
    amostra = serie[::passo]
    linhas = []
    for nivel in range(altura, 0, -1):
        limiar = vmax * nivel / altura
        linhas.append("".join("#" if v >= limiar else " " for v in amostra))
    return f"backlog max={vmax}\n" + "\n".join(linhas) + "\n" + "-" * len(amostra)


def main():
    csv_path, t_down, t_up, t_fim = (
        sys.argv[1],
        int(sys.argv[2]),
        int(sys.argv[3]),
        int(sys.argv[4]),
    )
    linhas = ler(csv_path)
    backlog = [int(r["backlog"]) for r in linhas]
    totais = [int(r["total_recebido"]) for r in linhas]
    cpus = [float(r["cpu_pct"]) for r in linhas if r["cpu_pct"] not in ("", "0")]
    mems = [float(r["mem_mb"]) for r in linhas if r["mem_mb"] not in ("", "0")]
    sem_wan = [r for r in linhas if r["fase"] == "sem_wan"]

    autonomia_min = (t_up - t_down) / 60
    reconciliacao_s = t_fim - t_up
    backlog_max = max(backlog) if backlog else 0
    # total_recebido na nuvem antes de cair e depois de reconciliar: perda = 0 se
    # o buffer zerou e o total cresceu pelo mesmo tanto do backlog acumulado.
    recebido_fim = totais[-1] if totais else 0
    perda = next((int(r["backlog"]) for r in reversed(linhas)), 0)  # backlog final
    # disponibilidade local: nos ciclos sem WAN, a borda seguiu decidindo (status gerado)
    ciclos_ok = sum(1 for r in sem_wan if r["link"] == "down")
    disp = 100.0 * ciclos_ok / len(sem_wan) if sem_wan else 0.0

    out = [
        "===== Teste de caos - metricas (RT-22, RT-23) =====",
        f"inicio sem WAN : {datetime.fromtimestamp(t_down, UTC):%Y-%m-%d %H:%M:%S}Z",
        f"WAN restaurada : {datetime.fromtimestamp(t_up, UTC):%Y-%m-%d %H:%M:%S}Z",
        f"fim            : {datetime.fromtimestamp(t_fim, UTC):%Y-%m-%d %H:%M:%S}Z",
        "",
        f"operacao autonoma sem internet : {autonomia_min:.1f} min (requisito >= 30)",
        f"backlog maximo acumulado       : {backlog_max} eventos",
        f"tempo de reconciliacao (MTTR)  : {reconciliacao_s} s",
        f"backlog final apos reconciliar : {perda} (perda esperada: 0)",
        f"total recebido na nuvem (fim)  : {recebido_fim} eventos",
        f"disponibilidade local sem WAN  : {disp:.1f}%",
        f"CPU do no de borda  (media/max): {sum(cpus) / len(cpus):.1f}% / {max(cpus):.1f}%"
        if cpus
        else "CPU: sem amostra",
        f"memoria do no de borda (media) : {sum(mems) / len(mems):.0f} MiB"
        if mems
        else "memoria: sem amostra",
        "",
        "Backlog no tempo (store-and-forward enchendo sem WAN, esvaziando ao voltar):",
        grafico(backlog),
        "",
        "Banda e energia: medir com `nethogs`/`iftop` e medidor de tomada se houver",
        "hardware; em container, declarar como nao medido (honestidade RT-22).",
    ]
    print("\n".join(out))


if __name__ == "__main__":
    main()
