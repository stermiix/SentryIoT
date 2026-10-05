"""Avaliação do classificador.

Mede as predições contra o rótulo conhecido de cada linha: acurácia, macro-F1, F1 ponderado,
precisão, recall e F1 por classe, matriz de confusão, taxa de falso positivo, importância das
features, tempo de inferência e tamanho do modelo.

Duas distribuições. A amostra de treino tem teto de linhas por classe, então a proporção entre
as classes não é a do dataset. Cada medida sai de duas formas: `amostra`, na distribuição do
conjunto avaliado, e `original`, reponderada para que cada um dos 34 rótulos pese o que pesa no
conjunto completo, com as contagens do manifesto da amostra. O peso é por rótulo, e não por
classe do alvo. O recall de um rótulo não muda com a ponderação, mas o de uma categoria que
reúne vários rótulos muda, porque dentro dela os rótulos passam a pesar de outra forma.

Taxa de falso positivo. A global é a fração do tráfego benigno classificada como algum ataque.
A de cada classe é a fração das linhas das outras classes que o modelo pôs nela.

Teto. Quem só vê as features dá a mesma resposta a todas as linhas com o mesmo vetor. A regra
que mais acerta responde a classe de maior peso em cada vetor, e a acurácia dessa regra é o
limite que nenhum modelo passa naquele conjunto de linhas. É um limite por coincidência exata de
vetores e vale para o conjunto em que foi calculado: muda com a mistura de classes dele e cai
quando ele cresce, porque com mais linhas mais vetores se repetem com classes diferentes. O teto
reponderado de uma parte da amostra não estima, por isso, o teto do conjunto completo, que é
menor. O recall de cada classe nessa regra também é medido, mas não é um limite da classe,
porque a regra maximiza o acerto global e outra regra pode acertar mais numa classe.

Uso, a partir da raiz do repositório:
    python -m codigo.classificador.avaliar modelos/rf_f39_estratificada_c8.joblib
    python -m codigo.classificador.avaliar modelos/rf_f33_grupos_c8.joblib --csv captura.csv --rotulo DDoS-HTTP_Flood

Sem `--csv`, o modelo é avaliado na parte de teste da amostra, refeita pela divisão e pela
semente registradas nele. Com `--csv`, em um arquivo de fora com as 39 colunas, como a saída do
extrator: o rótulo vem da coluna `Label` ou de `--rotulo`.
"""
import argparse
import json
import statistics
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

from codigo.classificador.mapeamento import ROTULOS
from codigo.classificador.preparar import (
    ALVOS,
    agrupar,
    alvo,
    carregar,
    dividir,
    matriz,
)
from codigo.classificador.treinar import carregar_modelo, prever

LOTE = 1000  # janelas por lote na medida do tempo de inferência


def contar(rotulos, previsto, classes):
    """Cruza o rótulo real com a classe prevista: uma linha por rótulo presente, uma coluna por classe."""
    rotulos, previsto = np.asarray(rotulos, dtype=object), np.asarray(previsto, dtype=object)
    classes = list(classes)
    presentes = set(rotulos.tolist())
    desconhecidos = sorted(presentes - set(ROTULOS))
    if desconhecidos:
        raise ValueError(f"rótulo desconhecido: {', '.join(map(repr, desconhecidos))}")
    ordem = [rotulo for rotulo in ROTULOS if rotulo in presentes]
    fora = sorted(set(pd.unique(previsto).tolist()) - set(classes), key=str)
    if fora:
        raise ValueError(f"classe prevista fora do alvo: {', '.join(map(str, fora))}")
    linha = pd.Categorical(rotulos, categories=ordem).codes.astype(np.int64)
    coluna = pd.Categorical(previsto, categories=classes).codes
    contagem = np.bincount(linha * len(classes) + coluna, minlength=len(ordem) * len(classes))
    return pd.DataFrame(contagem.reshape(len(ordem), len(classes)), index=ordem, columns=classes)


def _conferir_populacao(rotulos, populacao):
    faltam = [rotulo for rotulo in rotulos if not populacao.get(rotulo)]
    if faltam:
        raise ValueError(f"rótulos sem contagem no conjunto completo: {', '.join(faltam)}")


def pesos(rotulos, populacao):
    """Peso de cada linha: as linhas do rótulo no conjunto completo sobre as linhas dele aqui."""
    posicao, unicos = pd.factorize(np.asarray(rotulos, dtype=object))
    _conferir_populacao(unicos, populacao)
    do_rotulo = np.array([populacao[rotulo] for rotulo in unicos], dtype=float) / np.bincount(posicao)
    return do_rotulo[posicao]


def matriz_de_confusao(por_rotulo, nome_do_alvo, populacao=None):
    """Matriz de confusão do alvo: a classe real nas linhas e a prevista nas colunas.

    Com `populacao`, as linhas de cada rótulo são ampliadas até a quantidade que o rótulo tem
    no conjunto completo, antes de os rótulos serem somados na classe do alvo.
    """
    definicao = ALVOS[nome_do_alvo]
    classes = list(definicao.classes)
    contagem = por_rotulo
    if populacao is not None:
        _conferir_populacao(por_rotulo.index, populacao)
        completo = pd.Series({rotulo: populacao[rotulo] for rotulo in por_rotulo.index}, dtype=float)
        contagem = por_rotulo.mul(completo, axis=0).div(por_rotulo.sum(axis=1), axis=0)
    real = pd.Series([definicao.classe_do_rotulo[rotulo] for rotulo in por_rotulo.index], index=por_rotulo.index)
    return contagem.groupby(real).sum().reindex(index=classes, columns=classes, fill_value=0)


def _numero(valor):
    return int(valor) if float(valor).is_integer() else float(valor)


def medir(confusao, benigno):
    """Métricas tiradas de uma matriz de confusão, globais e por classe.

    Classe sem linhas no conjunto avaliado fica sem recall e sem F1, e não entra nas médias.
    Classe com linhas que o modelo nunca responde tem precisão e F1 iguais a zero.
    """
    valores = confusao.to_numpy(dtype=float)
    total = valores.sum()
    certas, suporte, previstas = np.diag(valores), valores.sum(axis=1), valores.sum(axis=0)
    por_classe = {}
    for i, classe in enumerate(confusao.index):
        tem_linhas = suporte[i] > 0
        precisao = certas[i] / previstas[i] if previstas[i] > 0 else (0.0 if tem_linhas else None)
        recall = certas[i] / suporte[i] if tem_linhas else None
        f1 = None
        if tem_linhas:
            f1 = 2 * precisao * recall / (precisao + recall) if precisao + recall > 0 else 0.0
        outras = total - suporte[i]
        por_classe[classe] = {
            "precisao": precisao,
            "recall": recall,
            "f1": f1,
            "suporte": _numero(suporte[i]),
            "taxa_falso_positivo": (previstas[i] - certas[i]) / outras if outras > 0 else None,
        }
    com_linhas = [medida for medida in por_classe.values() if medida["f1"] is not None]
    do_benigno = list(confusao.index).index(benigno)
    return {
        "acuracia": certas.sum() / total,
        "macro_f1": sum(medida["f1"] for medida in com_linhas) / len(com_linhas),
        "f1_ponderado": sum(medida["f1"] * medida["suporte"] for medida in com_linhas) / total,
        "falso_positivo_benigno": (
            (suporte[do_benigno] - certas[do_benigno]) / suporte[do_benigno] if suporte[do_benigno] > 0 else None
        ),
        "por_classe": por_classe,
    }


def teto(grupos, rotulos, nome_do_alvo, populacao=None):
    """Maior acurácia possível, nestas linhas, para quem só vê as features.

    `grupos` diz quais linhas têm o mesmo vetor de features. Em cada grupo a resposta é a classe
    de maior peso; no empate, a primeira na ordem das tabelas. Devolve a acurácia dessa regra e o
    recall de cada classe nela. O recall não é um limite da classe: a regra maximiza o acerto
    global, e uma regra que desempatasse de outro modo acertaria mais numa classe e menos em outra.
    """
    classes = list(ALVOS[nome_do_alvo].classes)
    real = pd.Categorical(alvo(rotulos, nome_do_alvo), categories=classes).codes.astype(np.int64)
    peso = pesos(rotulos, populacao) if populacao is not None else np.ones(len(real))
    _, grupo = np.unique(grupos, return_inverse=True)
    quantos = int(grupo.max()) + 1
    massa = np.bincount(grupo * len(classes) + real, weights=peso, minlength=quantos * len(classes))
    massa = massa.reshape(quantos, len(classes))
    escolhida = massa.argmax(axis=1)
    acerto = np.bincount(escolhida, weights=massa[np.arange(quantos), escolhida], minlength=len(classes))
    suporte = massa.sum(axis=0)
    return {
        "acuracia": float(acerto.sum() / suporte.sum()),
        "recall_na_regra": {
            classe: float(acerto[i] / suporte[i]) if suporte[i] > 0 else None for i, classe in enumerate(classes)
        },
    }


def avaliar(previsto, rotulos, nome_do_alvo, grupos=None, populacao=None):
    """Mede as predições de um conjunto de linhas com rótulo conhecido.

    Devolve as medidas em `amostra` e, quando `populacao` é dada, também em `original`. Com
    `grupos`, cada uma traz o teto destas linhas e, por classe, o recall na regra do teto.
    `matriz_por_rotulo` guarda a contagem de que tudo sai.
    """
    definicao = ALVOS[nome_do_alvo]
    rotulos = np.asarray(rotulos, dtype=object)
    por_rotulo = contar(rotulos, previsto, definicao.classes)
    resultado = {
        "linhas": len(rotulos),
        "matriz_por_rotulo": {
            "classes": list(por_rotulo.columns),
            "rotulos": list(por_rotulo.index),
            "contagem": por_rotulo.to_numpy().tolist(),
        },
    }
    distribuicoes = {"amostra": None} | ({"original": populacao} if populacao is not None else {})
    for nome, contagens in distribuicoes.items():
        medidas = medir(matriz_de_confusao(por_rotulo, nome_do_alvo, contagens), definicao.benigno)
        if grupos is not None:
            limite = teto(grupos, rotulos, nome_do_alvo, contagens)
            medidas["teto"] = limite["acuracia"]
            for classe, medida in medidas["por_classe"].items():
                medida["recall_na_regra_do_teto"] = limite["recall_na_regra"][classe]
        resultado[nome] = medidas
    return resultado


def importancias(modelo, features):
    """Importância de cada feature no modelo (redução média de impureza), da maior para a menor."""
    if len(features) != modelo.n_features_in_:
        raise ValueError(
            f"o modelo foi treinado com {modelo.n_features_in_} features, e a lista dada tem {len(features)} features"
        )
    pares = sorted(zip(features, modelo.feature_importances_.tolist()), key=lambda par: -par[1])
    return dict(pares)


def tempo_por_mil(predicao, X, repeticoes=5):
    """Milissegundos que `predicao` leva para classificar 1.000 janelas: a mediana das repetições."""
    lote = X[:LOTE]
    tempos = []
    for _ in range(repeticoes):
        inicio = time.perf_counter()
        predicao(lote)
        tempos.append(time.perf_counter() - inicio)
    return 1000 * statistics.median(tempos) * LOTE / len(lote)


def populacao_do_manifesto(caminho):
    """Linhas de cada rótulo no conjunto completo, como o manifesto da amostra registra."""
    manifesto = json.loads(Path(caminho).read_text(encoding="utf-8"))
    return {classe["rotulo"]: classe["populacao"] for classe in manifesto["classes"]}


def _milhar(numero):
    return f"{round(numero):,}".replace(",", ".")


def _decimal(valor):
    return f"{valor:.1f}".replace(".", ",")


def _pct(valor):
    return "sem valor" if valor is None else f"{100 * valor:.2f}%".replace(".", ",")


def _relatar(resultado, origem):
    """O resumo da avaliação em texto, para a saída do comando."""
    texto = [f"avaliado em: {origem}, {_milhar(resultado['linhas'])} linhas"]
    titulos = {
        "amostra": "Na distribuição do conjunto avaliado",
        "original": "Reponderada para a distribuição do conjunto completo",
    }
    for chave, titulo in titulos.items():
        if chave not in resultado:
            continue
        medidas = resultado[chave]
        texto += [
            "",
            f"{titulo}:",
            (
                f"  acurácia {_pct(medidas['acuracia'])}, macro-F1 {_pct(medidas['macro_f1'])}, "
                f"F1 ponderado {_pct(medidas['f1_ponderado'])}, teto destas linhas {_pct(medidas.get('teto'))}"
            ),
            f"  tráfego benigno classificado como ataque: {_pct(medidas['falso_positivo_benigno'])}",
            f"  {'classe':<24}{'linhas':>12}{'precisão':>11}{'recall':>11}{'F1':>11}{'falso pos.':>12}",
        ]
        texto += [
            f"  {classe:<24}{_milhar(m['suporte']):>12}{_pct(m['precisao']):>11}{_pct(m['recall']):>11}"
            f"{_pct(m['f1']):>11}{_pct(m['taxa_falso_positivo']):>12}"
            for classe, m in medidas["por_classe"].items()
            if m["suporte"] or m["precisao"] is not None
        ]
    return "\n".join(texto)


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.classificador.avaliar",
        description="Avalia um modelo salvo, na parte de teste da amostra ou em um CSV de fora.",
    )
    analisador.add_argument("modelo", help="arquivo gravado por codigo.classificador.treinar")
    analisador.add_argument("--amostra", default="dados/processed/amostra.csv.gz")
    analisador.add_argument(
        "--manifesto", default="experimentos/resultados/manifesto_amostra.json",
        help="manifesto da amostra, de onde saem as contagens do conjunto completo",
    )
    analisador.add_argument("--csv", default=None, help="CSV de fora da amostra, com as 39 colunas")
    analisador.add_argument("--rotulo", default=None, help="rótulo de todas as linhas do CSV, se ele não tem Label")
    analisador.add_argument("--saida", default=None, help="arquivo JSON para a avaliação completa")
    try:
        argumentos = analisador.parse_args(argv)
    except SystemExit as encerramento:
        return encerramento.code
    try:
        pacote = carregar_modelo(argumentos.modelo)
        modelo, features, nome_do_alvo = pacote["modelo"], pacote["features"], pacote["alvo"]
        if argumentos.csv is not None:
            quadro, _ = carregar(argumentos.csv, rotulo=argumentos.rotulo)
            origem, populacao = Path(argumentos.csv).name, None
        else:
            if argumentos.rotulo is not None:
                raise ValueError("--rotulo só vale junto com --csv")
            if "divisao" not in pacote or "semente" not in pacote:
                raise ValueError("o modelo não registra a divisão entre treino e teste; avalie com --csv")
            quadro, sha256 = carregar(argumentos.amostra)
            if sha256 != pacote.get("amostra_sha256"):
                raise ValueError(f"{argumentos.amostra} não é a amostra com que o modelo foi treinado")
            _, teste = dividir(quadro, pacote["divisao"], pacote["semente"])
            quadro = quadro.iloc[teste]
            origem, populacao = "parte de teste da amostra", populacao_do_manifesto(argumentos.manifesto)
        X = matriz(quadro, features)
        resultado = avaliar(
            prever(modelo, X), quadro["Label"].to_numpy(), nome_do_alvo, grupos=agrupar(X), populacao=populacao
        )
        resultado["modelo"] = {
            "arquivo": Path(argumentos.modelo).name,
            "bytes": Path(argumentos.modelo).stat().st_size,
            "features": len(features),
            "alvo": nome_do_alvo,
        }
        resultado["importancias"] = importancias(modelo, features)
        resultado["inferencia_ms_por_mil_janelas"] = tempo_por_mil(lambda lote: prever(modelo, lote), X)
        if argumentos.saida is not None:
            destino = Path(argumentos.saida)
            destino.parent.mkdir(parents=True, exist_ok=True)
            destino.write_text(json.dumps(resultado, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (OSError, ValueError, KeyError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrompido", file=sys.stderr)
        return 130
    print(
        f"modelo: {resultado['modelo']['arquivo']}, {_decimal(resultado['modelo']['bytes'] / 1e6)} MB, "
        f"{len(features)} features, {len(ALVOS[nome_do_alvo].classes)} classes"
    )
    print(_relatar(resultado, origem))
    tempo = _decimal(resultado["inferencia_ms_por_mil_janelas"])
    print(f"\ninferência: {tempo} ms por 1.000 janelas, com um núcleo")
    if argumentos.saida is not None:
        print(f"avaliação completa em {argumentos.saida}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
