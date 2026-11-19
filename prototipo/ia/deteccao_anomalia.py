"""
IA defensiva (RT-16): deteccao de anomalias na telemetria com Isolation Forest.

Treina so com dados normais sinteticos e e avaliado contra um conjunto rotulado
(normal x anomalo) para medir precisao, revocacao e falsos positivos. Nenhuma
decisao fisica e tomada pela IA: ela so gera alertas para triagem humana (RT-17).

Analise critica honesta (RT-16 / rubrica C6): a contamination define o quao
sensivel o modelo e; varremos varios valores e mostramos o trade-off
precisao x revocacao, em vez de reportar um unico ponto escolhido a dedo.

Uso: python deteccao_anomalia.py
Gera metrics.json (entra no E3). So dados sinteticos, semente fixa -> reproduzivel.
"""

import json
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, roc_auc_score

RNG = np.random.default_rng(712)
AQUI = Path(__file__).resolve().parent


# Features por leitura: [temp_camara_fria, nivel_agua, carga_energia, tentativas_acesso_hora]
def normais(n):
    temp = RNG.normal(5.0, 1.0, n)  # faixa segura ~2-8 C
    agua = RNG.normal(60, 15, n).clip(15, 100)
    energia = RNG.normal(65, 12, n).clip(20, 95)
    acesso = RNG.poisson(1.5, n)  # poucas tentativas/hora
    return np.column_stack([temp, agua, energia, acesso])


def anomalas(n):
    # Anomalias que SE SOBREPOEM bastante as normais: parte sai da faixa, parte
    # fica no limite. Assim o problema nao e trivial (AUC < 1, revocacao < 1) e as
    # metricas refletem um cenario honesto, nao um brinquedo separavel.
    temp = np.concatenate(
        [RNG.normal(9.0, 1.8, n // 2), RNG.normal(1.5, 1.2, n - n // 2)]
    )
    agua = RNG.normal(22, 10, n).clip(0, 60)
    energia = RNG.normal(52, 16, n).clip(0, 100)
    acesso = RNG.poisson(4, n)  # rajada leve de tentativas
    return np.column_stack([temp, agua, energia, acesso])


def main():
    treino = normais(4000)
    X_norm, X_anom = normais(1000), anomalas(200)
    X_teste = np.vstack([X_norm, X_anom])
    y = np.array([0] * len(X_norm) + [1] * len(X_anom))

    varredura = []
    for cont in (0.02, 0.05, 0.10, 0.15):
        m = IsolationForest(n_estimators=300, contamination=cont, random_state=712)
        m.fit(treino)
        pred = (m.predict(X_teste) == -1).astype(int)
        varredura.append(
            {
                "contamination": cont,
                "precisao": round(float(precision_score(y, pred)), 4),
                "revocacao": round(float(recall_score(y, pred)), 4),
                "taxa_falso_positivo": round(float(pred[y == 0].mean()), 4),
            }
        )

    # ponto de operacao escolhido: prioriza nao perder anomalia (revocacao alta),
    # aceitando falsos positivos, porque e triagem humana (pior perder incidente).
    escolhido = IsolationForest(n_estimators=300, contamination=0.10, random_state=712)
    escolhido.fit(treino)
    pred = (escolhido.predict(X_teste) == -1).astype(int)
    scores = -escolhido.score_samples(X_teste)  # maior = mais anomalo
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())

    metrics = {
        "modelo": "IsolationForest",
        "n_estimators": 300,
        "features": [
            "temp_camara_fria",
            "nivel_agua",
            "carga_energia",
            "tentativas_acesso_hora",
        ],
        "amostras_treino": len(treino),
        "amostras_teste": len(y),
        "ponto_de_operacao": {
            "contamination": 0.10,
            "precisao": round(float(precision_score(y, pred)), 4),
            "revocacao": round(float(recall_score(y, pred)), 4),
            "auc_roc": round(float(roc_auc_score(y, scores)), 4),
            "verdadeiros_positivos": tp,
            "falsos_positivos": fp,
            "falsos_negativos": fn,
            "verdadeiros_negativos": tn,
            "taxa_falso_positivo": round(fp / (fp + tn), 4),
        },
        "varredura_contamination": varredura,
        "leitura": (
            "AUC-ROC mede a separacao independente do limiar. A contamination "
            "escolhe o ponto de operacao: mais alta pega mais anomalias (revocacao) "
            "ao custo de mais falsos positivos. Para triagem humana isso e aceitavel."
        ),
    }
    (AQUI / "metrics.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(metrics, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
