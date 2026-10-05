"""Treino exploratório do classificador: a grade de execuções e o relatório.

Roda o Random Forest sobre a amostra de treino em dez configurações e grava os resultados em
`experimentos/resultados/`. As oito execuções da grade combinam três escolhas que estão em
aberto no `ROADMAP.md`:

- features: as 39, ou 33 sem as seis colunas que dependem do tamanho da janela;
- divisão entre treino e teste: sorteio estratificado de linhas, ou por grupos de vetores idênticos;
- alvo: 8 categorias, ou 7 com DDoS e DoS fundidas.

As duas execuções de referência repetem, com 39 features e sorteio estratificado, os cenários de
34 classes e de ataque ou benigno do artigo do dataset.

O que é gravado:

- `manifesto_treino_exploratorio.json`: sementes, parâmetros, versões, hash da amostra, as
  divisões e todos os números de cada execução. Os outros arquivos saem dele;
- `treino_exploratorio.md`: o relatório;
- `metricas_classificador.csv` e `importancia_features.csv`, em formato longo;
- `matrizes_confusao/`: duas por execução, a do alvo e a que abre a classe real nos 34 rótulos.

Com a mesma amostra e a mesma semente, os números são os mesmos a cada execução. Só mudam a
data e as medidas de tempo.

Uso, a partir da raiz do repositório:
    python -m codigo.classificador.experimento
    python -m codigo.classificador.experimento --refazer-relatorio
"""
import argparse
import csv
import datetime
import json
import platform
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn

from codigo.classificador.avaliar import (
    avaliar,
    importancias,
    matriz_de_confusao,
    populacao_do_manifesto,
    tempo_por_mil,
)
from codigo.classificador.mapeamento import CATEGORIA_DO_ROTULO, ROTULOS
from codigo.classificador.preparar import (
    ALVOS,
    CONJUNTOS_DE_FEATURES,
    DEPENDENTES_DA_JANELA,
    DIVISOES,
    FRACAO_DE_TESTE,
    FUSAO,
    SEMENTE,
    agrupar,
    alvo,
    carregar,
    dividir,
    impressao_digital,
    matriz,
)
from codigo.classificador.treinar import ARVORES, _positivo, prever, salvar, treinar

# Com 34 classes cada nó da árvore guarda 34 contagens e as árvores têm mais nós: na amostra,
# cerca de 93 MB por árvore. Cem árvores passariam de 9 GB de memória, então esta execução usa menos.
ARVORES_COM_34_CLASSES = 25
MANIFESTO = "manifesto_treino_exploratorio.json"
RELATORIO = "treino_exploratorio.md"
METRICAS = "metricas_classificador.csv"
IMPORTANCIAS = "importancia_features.csv"
MATRIZES = "matrizes_confusao"

# Linhas do conjunto completo que repetem o vetor de outra, de `experimentos/resultados/exploracao.md` (seção 8).
LINHAS_REPETIDAS_NO_CONJUNTO = 0.5878

NOME_DA_DIVISAO = {"estratificada": "sorteio estratificado", "grupos": "divisão por grupos"}
NOME_DO_ALVO = {"34": "34 classes", "8": "8 categorias", "7": "7 categorias", "2": "ataque ou benigno"}
METODO_DA_DIVISAO = {
    "estratificada": (
        "Sorteio de linhas com train_test_split do scikit-learn, estratificado pelos 34 rótulos."
    ),
    "grupos": (
        "Sorteio de grupos com train_test_split do scikit-learn. Um grupo reúne as linhas com o mesmo "
        "vetor nas 33 features, em 32 bits, e o sorteio é estratificado pelo rótulo mais frequente do grupo."
    ),
}
# Categorias cujas classes o dataset agrega em janelas de 100 quadros; as demais usam 10.
JANELA_DE_100 = ("DDoS", "DoS", "Mirai", FUSAO)


@dataclass(frozen=True)
class Execucao:
    """Uma configuração do experimento."""

    features: str  # "39" ou "33"
    divisao: str  # "estratificada" ou "grupos"
    alvo: str  # "34", "8", "7" ou "2"

    @property
    def nome(self):
        return f"f{self.features}_{self.divisao}_c{self.alvo}"


GRADE = tuple(
    Execucao(features, divisao, classes)
    for features in ("39", "33") for divisao in DIVISOES for classes in ("8", "7")
)
REFERENCIAS = (Execucao("39", "estratificada", "34"), Execucao("39", "estratificada", "2"))


def _repetidas(grupos):
    """Linhas cujo vetor aparece mais de uma vez."""
    vezes = np.bincount(grupos)
    return int(vezes[vezes > 1].sum())


def rodar(quadro, populacao, execucoes=(*GRADE, *REFERENCIAS), semente=SEMENTE, arvores=ARVORES,
          pasta_dos_modelos=None, sha256=None, ao_terminar=None):
    """Treina e avalia cada execução. Devolve o registro das divisões e os resultados.

    Os modelos são gravados em `pasta_dos_modelos` para medir o tamanho em disco. Sem a pasta,
    vão para um diretório provisório e são apagados. `sha256` é o hash da amostra, que fica
    registrado em cada modelo.
    """
    rotulos = quadro["Label"].to_numpy()
    matrizes = {nome: matriz(quadro, features) for nome, features in CONJUNTOS_DE_FEATURES.items()}
    grupos = {nome: agrupar(X) for nome, X in matrizes.items()}
    divisoes = {nome: dividir(quadro, nome, semente) for nome in DIVISOES}
    registro = {
        "amostra": {
            "linhas": len(quadro),
            "linhas_por_rotulo": {r: int((rotulos == r).sum()) for r in ROTULOS if (rotulos == r).any()},
            "linhas_com_vazio_ou_infinito": int((~np.isfinite(quadro[list(CONJUNTOS_DE_FEATURES["39"])])).any(axis=1).sum()),
            "vetores_distintos": {nome: int(g.max()) + 1 for nome, g in grupos.items()},
            "linhas_repetidas": {nome: _repetidas(g) for nome, g in grupos.items()},
        },
        "divisoes": {
            nome: {
                "metodo": METODO_DA_DIVISAO[nome],
                "treino": len(treino),
                "teste": len(teste),
                "sha256_do_teste": impressao_digital(teste),
                "teste_com_vetor_no_treino": {
                    features: int(np.isin(g[teste], g[treino]).sum()) for features, g in grupos.items()
                },
            }
            for nome, (treino, teste) in divisoes.items()
        },
        "execucoes": [],
    }
    with tempfile.TemporaryDirectory() as provisorio:
        pasta = Path(pasta_dos_modelos or provisorio)
        for execucao in execucoes:
            inicio = time.perf_counter()
            X, y = matrizes[execucao.features], alvo(rotulos, execucao.alvo)
            treino, teste = divisoes[execucao.divisao]
            quantas = min(arvores, ARVORES_COM_34_CLASSES) if execucao.alvo == "34" else arvores
            modelo, treino_segundos = treinar(X[treino], y[treino], semente, quantas)
            X_teste = X[teste]
            antes = time.perf_counter()
            previsto = prever(modelo, X_teste)
            teste_segundos = time.perf_counter() - antes
            medidas = avaliar(
                previsto, rotulos[teste], execucao.alvo, grupos=grupos[execucao.features][teste], populacao=populacao
            )
            features = CONJUNTOS_DE_FEATURES[execucao.features]
            arquivo = pasta / f"rf_{execucao.nome}.joblib"
            tamanho = salvar(
                arquivo, modelo, features, execucao.alvo,
                divisao=execucao.divisao, semente=semente, arvores=quantas, amostra_sha256=sha256,
            )
            if pasta_dos_modelos is None:
                arquivo.unlink()
            resultado = {
                "nome": execucao.nome,
                "features": execucao.features,
                "divisao": execucao.divisao,
                "alvo": execucao.alvo,
                "arvores": quantas,
                "linhas_de_treino": len(treino),
                "linhas_de_teste": len(teste),
                "treino_segundos": treino_segundos,
                "teste_segundos": teste_segundos,
                "inferencia_ms_por_mil_janelas": {
                    "um_nucleo": tempo_por_mil(lambda lote, modelo=modelo: prever(modelo, lote), X_teste),
                    "todos_os_nucleos": tempo_por_mil(modelo.predict, X_teste),
                },
                "modelo_bytes": tamanho,
                "nos_por_arvore": float(np.mean([arvore.tree_.node_count for arvore in modelo.estimators_])),
                "profundidade_media": float(np.mean([arvore.tree_.max_depth for arvore in modelo.estimators_])),
                **{chave: medidas[chave] for chave in ("amostra", "original", "matriz_por_rotulo")},
                "importancias": importancias(modelo, features),
            }
            del modelo
            resultado["duracao_segundos"] = time.perf_counter() - inicio
            registro["execucoes"].append(resultado)
            if ao_terminar is not None:
                ao_terminar(resultado)
    return registro


def montar_manifesto(registro, populacao, amostra, manifesto_da_amostra, sha256, semente, arvores):
    """O registro do experimento: o que é preciso para refazê-lo e todos os números que ele produziu."""
    return {
        "descricao": "Treino exploratório do Random Forest sobre a amostra do CICIoT2023",
        "gerado_por": "python -m codigo.classificador.experimento",
        "gerado_em": datetime.datetime.now(tz=datetime.UTC).astimezone().strftime("%Y-%m-%d"),
        "semente": semente,
        "parametros": {
            "modelo": "sklearn.ensemble.RandomForestClassifier",
            "arvores": arvores,
            "arvores_com_34_classes": min(arvores, ARVORES_COM_34_CLASSES),
            "n_jobs": -1,
            "demais_parametros": "padrão do scikit-learn",
            "escalonamento": "nenhum",
            "fracao_de_teste": FRACAO_DE_TESTE,
            "predicao": "votos somados em ordem fixa, com um núcleo",
        },
        "versoes": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit-learn": sklearn.__version__,
            "joblib": joblib.__version__,
        },
        "amostra": {
            "arquivo": Path(amostra).as_posix(),
            "manifesto": Path(manifesto_da_amostra).as_posix(),
            "sha256_do_csv_descomprimido": sha256,
            **registro["amostra"],
        },
        "populacao": populacao,
        "features": {nome: list(features) for nome, features in CONJUNTOS_DE_FEATURES.items()},
        "dependentes_da_janela": list(DEPENDENTES_DA_JANELA),
        "divisoes": registro["divisoes"],
        "execucoes": registro["execucoes"],
    }


def _por_rotulo(execucao):
    """A contagem cruzada da execução, do jeito que `avaliar` a produz."""
    tabela = execucao["matriz_por_rotulo"]
    return pd.DataFrame(tabela["contagem"], index=tabela["rotulos"], columns=tabela["classes"])


def _confusao(execucao, populacao=None):
    return matriz_de_confusao(_por_rotulo(execucao), execucao["alvo"], populacao)


def _campo(valor):
    if valor is None:
        return ""
    return f"{valor:.6f}" if isinstance(valor, float) else str(valor)


def _gravar_csv(caminho, cabecalho, linhas):
    with open(caminho, "w", encoding="utf-8", newline="") as arquivo:
        escritor = csv.writer(arquivo, lineterminator="\n")
        escritor.writerow(cabecalho)
        escritor.writerows(linhas)


def gravar(manifesto, pasta):
    """Grava o manifesto e tudo o que sai dele: relatório, tabelas e matrizes de confusão."""
    pasta = Path(pasta)
    (pasta / MATRIZES).mkdir(parents=True, exist_ok=True)
    (pasta / MANIFESTO).write_text(json.dumps(manifesto, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (pasta / RELATORIO).write_text(montar_relatorio(manifesto), encoding="utf-8")
    _gravar_csv(
        pasta / METRICAS,
        ["execucao", "distribuicao", "classe", "precisao", "recall", "f1", "suporte", "taxa_falso_positivo",
         "recall_na_regra_do_teto"],
        [
            [
                execucao["nome"], distribuicao, classe, _campo(m["precisao"]), _campo(m["recall"]), _campo(m["f1"]),
                round(m["suporte"]), _campo(m["taxa_falso_positivo"]), _campo(m["recall_na_regra_do_teto"]),
            ]
            for execucao in manifesto["execucoes"]
            for distribuicao in ("amostra", "original")
            for classe, m in execucao[distribuicao]["por_classe"].items()
        ],
    )
    _gravar_csv(
        pasta / IMPORTANCIAS,
        ["execucao", "feature", "importancia"],
        [
            [execucao["nome"], feature, _campo(valor)]
            for execucao in manifesto["execucoes"] for feature, valor in execucao["importancias"].items()
        ],
    )
    for execucao in manifesto["execucoes"]:
        por_rotulo = _por_rotulo(execucao)
        por_rotulo.to_csv(pasta / MATRIZES / f"{execucao['nome']}_por_rotulo.csv", index_label="rotulo", lineterminator="\n")
        _confusao(execucao).to_csv(pasta / MATRIZES / f"{execucao['nome']}.csv", index_label="classe_real", lineterminator="\n")


def _milhar(numero):
    return f"{round(numero):,}".replace(",", ".")


def _decimal(valor, casas=1):
    return f"{valor:,.{casas}f}".translate(str.maketrans(",.", ".,"))


def _pct(valor, casas=2):
    return "sem linhas" if valor is None else f"{100 * valor:.{casas}f}%".replace(".", ",")


def _pp(diferenca):
    """Diferença entre dois percentuais, em pontos percentuais e com sinal."""
    texto = f"{100 * diferenca:+.2f}".replace(".", ",")
    return "0,00" if texto in ("+0,00", "-0,00") else texto


def _tabela(cabecalho, linhas):
    return [
        "| " + " | ".join(cabecalho) + " |",
        "|" + "---|" * len(cabecalho),
        *("| " + " | ".join(str(celula) for celula in linha) + " |" for linha in linhas),
    ]


def _descricao(execucao):
    return (
        f"{execucao['features']} features, {NOME_DA_DIVISAO[execucao['divisao']]}, {NOME_DO_ALVO[execucao['alvo']]}"
    )


def _como_ler(m):
    amostra, populacao = m["amostra"], m["populacao"]
    total, completo = amostra["linhas"], sum(populacao.values())
    floods = [rotulo for rotulo in ROTULOS if CATEGORIA_DO_ROTULO[rotulo] in ("DDoS", "DoS")]
    na_amostra = sum(amostra["linhas_por_rotulo"].get(rotulo, 0) for rotulo in floods)
    no_conjunto = sum(populacao[rotulo] for rotulo in floods)
    distintos, repetidas = amostra["vetores_distintos"], amostra["linhas_repetidas"]
    de_dos = [rotulo for rotulo in ROTULOS if CATEGORIA_DO_ROTULO[rotulo] == "DoS"]
    exemplo = ""
    if amostra["linhas_por_rotulo"].get("DoS-HTTP_Flood"):
        fatia_na_amostra = amostra["linhas_por_rotulo"]["DoS-HTTP_Flood"] / sum(
            amostra["linhas_por_rotulo"].get(rotulo, 0) for rotulo in de_dos
        )
        fatia_no_conjunto = populacao["DoS-HTTP_Flood"] / sum(populacao[rotulo] for rotulo in de_dos)
        exemplo = (
            f" Na amostra, `DoS-HTTP_Flood` é {_pct(fatia_na_amostra, 1)} das linhas de DoS; no conjunto "
            f"completo, {_pct(fatia_no_conjunto, 1)}."
        )
    return [
        "## Como ler os números",
        "",
        (
            f"**Amostra e conjunto completo.** Todas as execuções usam a amostra de treino "
            f"(`{m['amostra']['arquivo']}`, {_milhar(total)} linhas), que limita as linhas de cada classe. Nela, DDoS "
            f"e DoS somam {_pct(na_amostra / total, 1)} das linhas; no conjunto completo, de {_milhar(completo)} "
            f"linhas, somam {_pct(no_conjunto / completo, 1)}. Por isso cada medida aparece de duas formas:"
        ),
        "",
        "- **na amostra**: calculada sobre as linhas de teste como elas são;",
        "- **reponderada**: cada linha de teste pesa a quantidade de linhas do seu rótulo no conjunto completo",
        "  dividida pela quantidade no teste, com as contagens de `manifesto_amostra.json`. É a estimativa da",
        "  medida na distribuição original do dataset.",
        "",
        "A ponderação altera só o cálculo da medida. O modelo é o mesmo nas duas formas e foi treinado com as",
        "proporções da amostra.",
        "",
        (
            "O peso é por rótulo, entre os 34, e não por classe do alvo. O recall de um rótulo não muda com a "
            "ponderação. O de uma categoria que reúne vários rótulos muda, porque dentro dela os rótulos passam a "
            f"pesar de outra forma.{exemplo} A taxa de tráfego benigno classificado como ataque não muda, porque o "
            "tráfego benigno é um rótulo só."
        ),
        "",
        (
            "**Vetor idêntico.** Duas linhas têm o mesmo vetor quando são iguais em todas as features da execução, "
            "depois da conversão para ponto flutuante de 32 bits, que é como o scikit-learn as entrega às árvores. "
            f"A amostra tem {_milhar(distintos['39'])} vetores distintos com as 39 features e "
            f"{_milhar(distintos['33'])} com as 33. Com as 39, {_milhar(repetidas['39'])} linhas "
            f"({_pct(repetidas['39'] / total)}) repetem o vetor de outra linha. No conjunto completo são "
            f"{_pct(LINHAS_REPETIDAS_NO_CONJUNTO)} (`exploracao.md`): a amostra guarda uma fração pequena das "
            "classes grandes, e a maior parte das repetições delas fica de fora."
        ),
        "",
        (
            "**Teto.** É um limite por coincidência exata de vetores, calculado nas linhas de teste de cada "
            "execução. Quem só vê as features dá a mesma resposta a todas as linhas com o mesmo vetor. A regra que "
            "mais acerta responde, em cada vetor, a classe de maior peso, e as linhas das outras classes são erro "
            "certo. A acurácia dessa regra é a maior possível naquelas linhas, e é com ela que a acurácia do modelo "
            "na mesma execução se compara. O teto depende do tamanho e da mistura de classes do conjunto em que é "
            "medido: com mais linhas, mais vetores se repetem com classes diferentes. Por isso ele muda com a "
            "divisão. No sorteio de linhas, parte das repetições de um vetor fica no treino e não entra na conta. O "
            "teto que a exploração mediu vale para o conjunto completo, na proporção natural das classes, e não é o "
            "limite destas execuções."
        ),
        "",
        (
            "**Recall na regra do teto.** As tabelas por classe trazem o recall de cada classe na regra que dá o "
            "teto. Ele não é um limite por classe: a regra maximiza o acerto global, e outra regra pode acertar "
            "mais numa classe e menos em outra. No empate entre classes num vetor, a regra fica com a primeira na "
            "ordem das tabelas."
        ),
        "",
        (
            f"**Valores vazios e infinitos.** {_milhar(amostra['linhas_com_vazio_ou_infinito'])} linhas da amostra "
            "têm `Std` e `Variance` vazios ou `Rate` infinito. Elas são mantidas. O infinito entra como vazio, e o "
            "Random Forest do scikit-learn trata o vazio sem imputação."
        ),
        "",
        (
            f"**Uma semente.** Cada execução foi feita uma vez, com a semente {m['semente']} na divisão e no "
            "modelo. Diferenças pequenas entre execuções podem vir do sorteio, e não da escolha comparada. Para "
            "repetir com outro sorteio: `python -m codigo.classificador.experimento --semente N --saida OUTRA_PASTA`."
        ),
    ]


def _secao_divisoes(m):
    linhas = [
        [
            NOME_DA_DIVISAO[nome], _milhar(d["treino"]), _milhar(d["teste"]),
            *(
                f"{_milhar(d['teste_com_vetor_no_treino'][features])} "
                f"({_pct(d['teste_com_vetor_no_treino'][features] / d['teste'])})"
                for features in ("39", "33")
            ),
        ]
        for nome, d in m["divisoes"].items()
    ]
    return [
        "## Divisões entre treino e teste",
        "",
        (
            f"As duas divisões reservam {_pct(m['parametros']['fracao_de_teste'], 0)} das linhas para o teste e "
            "são as mesmas em todas as execuções que as usam, quaisquer que sejam as features e o alvo."
        ),
        "",
        "- **Sorteio estratificado**: sorteio de linhas com a mesma fração de cada um dos 34 rótulos no teste.",
        "  É o método dos autores do dataset.",
        "- **Divisão por grupos**: todas as linhas com o mesmo vetor nas 33 features ficam do mesmo lado. Linhas",
        "  iguais nas 39 também são iguais nas 33, então nenhum vetor aparece no treino e no teste, com",
        "  qualquer dos dois conjuntos de features. O sorteio dos grupos é estratificado pelo rótulo mais",
        "  frequente de cada grupo.",
        "",
        *_tabela(
            [
                "Divisão", "Linhas de treino", "Linhas de teste",
                "Linhas de teste com vetor que está no treino, 39 features", "Idem, 33 features",
            ],
            linhas,
        ),
        "",
        "O hash das linhas de teste de cada divisão está no manifesto do experimento.",
    ]


def _recalls(execucao, classe):
    """Recall de uma classe na amostra e reponderado, ou None se a classe não existe no alvo."""
    if classe not in execucao["amostra"]["por_classe"]:
        return None
    return tuple(execucao[d]["por_classe"][classe]["recall"] for d in ("amostra", "original"))


def _par(valores, vazio="não se aplica"):
    return vazio if valores is None else f"{_pct(valores[0])} e {_pct(valores[1])}"


def _destino_do_benigno(m):
    """Para onde vão as linhas benignas do teste nas execuções de 8 categorias."""
    execucoes = [e for e in _da_grade(m, classes="8") if "BenignTraffic" in e["matriz_por_rotulo"]["rotulos"]]
    if not execucoes:
        return []
    benignas = [_por_rotulo(e).loc["BenignTraffic"] for e in execucoes]
    linhas = [
        [classe, *(_pct(contagem[classe] / contagem.sum()) for contagem in benignas)]
        for classe in ALVOS["8"].classes
    ]
    amostra, populacao = m["amostra"]["linhas_por_rotulo"], m["populacao"]
    de_10 = [
        rotulo for rotulo in ROTULOS
        if CATEGORIA_DO_ROTULO[rotulo] not in JANELA_DE_100 and rotulo != "BenignTraffic"
    ]
    total, completo = sum(amostra.values()), sum(populacao.values())
    return [
        "Para onde vai o tráfego benigno nas execuções de 8 categorias, como fração das linhas benignas do teste:",
        "",
        *_tabela(["Classe prevista", *(f"`{e['nome']}`" for e in execucoes)], linhas),
        "",
        (
            f"Na amostra, o tráfego benigno é {_pct(amostra.get('BenignTraffic', 0) / total, 1)} das linhas, e as "
            "categorias de ataque com janela de 10 (Recon, Spoofing, Web e BruteForce) somam "
            f"{_pct(sum(amostra.get(rotulo, 0) for rotulo in de_10) / total, 1)}. No conjunto completo são "
            f"{_pct(populacao['BenignTraffic'] / completo, 1)} e "
            f"{_pct(sum(populacao[rotulo] for rotulo in de_10) / completo, 1)}."
        ),
        "",
    ]


def _secao_execucoes(m):
    globais, de_interesse = [], []
    for e in m["execucoes"]:
        a, o = e["amostra"], e["original"]
        globais.append([
            f"`{e['nome']}`", e["features"], NOME_DA_DIVISAO[e["divisao"]], NOME_DO_ALVO[e["alvo"]],
            _pct(a["acuracia"]), _pct(o["acuracia"]), _pct(a["macro_f1"]), _pct(o["macro_f1"]),
            _pct(a["f1_ponderado"]), _pct(o["f1_ponderado"]), _pct(a["teto"]), _pct(o["teto"]),
        ])
        benigno = ALVOS[e["alvo"]].benigno
        ataque_como_benigno = tuple(e[d]["por_classe"][benigno]["taxa_falso_positivo"] for d in ("amostra", "original"))
        de_interesse.append([
            f"`{e['nome']}`", _par(_recalls(e, "DDoS")), _par(_recalls(e, "DoS")), _par(_recalls(e, FUSAO)),
            _pct(a["por_classe"][benigno]["recall"]), _pct(a["falso_positivo_benigno"]), _par(ataque_como_benigno),
        ])
    return [
        "## As 10 execuções",
        "",
        "Medidas globais nas linhas de teste. Em cada par de colunas, a primeira é na amostra e a segunda é",
        "reponderada para a distribuição original.",
        "",
        *_tabela(
            [
                "Execução", "Features", "Divisão", "Alvo", "Acurácia na amostra", "Acurácia reponderada",
                "Macro-F1 na amostra", "Macro-F1 reponderado", "F1 ponderado na amostra", "F1 ponderado reponderado",
                "Teto na amostra", "Teto reponderado",
            ],
            globais,
        ),
        "",
        "Classes de interesse. Onde há dois valores, o primeiro é na amostra e o segundo é reponderado. O recall",
        "do tráfego benigno e a taxa de benigno classificado como ataque são iguais nas duas distribuições.",
        "",
        *_tabela(
            [
                "Execução", "Recall de DDoS", "Recall de DoS", f"Recall de {FUSAO}", "Recall de benigno",
                "Benigno classificado como ataque", "Ataque classificado como benigno",
            ],
            de_interesse,
        ),
        "",
        *_destino_do_benigno(m),
        (
            "As execuções de 34 classes e de ataque ou benigno servem de referência para os cenários do artigo do "
            "dataset (Neto et al., 2023). Os valores publicados não estão neste repositório e precisam ser "
            "conferidos no artigo antes de qualquer comparação. O artigo avalia na distribuição original, então a "
            "coluna comparável é a reponderada."
            + (
                f" A execução de 34 classes usa {m['parametros']['arvores_com_34_classes']} árvores, e as demais "
                f"usam {m['parametros']['arvores']} (ver \"Custo de cada execução\")."
                if m["parametros"]["arvores_com_34_classes"] != m["parametros"]["arvores"] else ""
            )
        ),
    ]


def _secao_por_classe(m):
    texto = [
        "## Resultados por classe",
        "",
        "Uma tabela para cada execução da grade. As colunas da esquerda são medidas na amostra, e as da direita",
        "são reponderadas. \"Falso positivo\" é a fração das linhas das outras classes que o modelo pôs na classe.",
        "\"Recall na regra do teto\" é o recall da classe na regra de maior acerto global, e não um limite da",
        "classe (ver \"Como ler os números\"). As mesmas medidas, com as execuções de",
        f"referência, estão em `{METRICAS}`, e as matrizes de confusão estão em `{MATRIZES}/`.",
    ]
    for e in m["execucoes"]:
        if e["alvo"] not in ("8", "7"):
            continue
        linhas = []
        for classe in ALVOS[e["alvo"]].classes:
            a, o = e["amostra"]["por_classe"][classe], e["original"]["por_classe"][classe]
            if not a["suporte"]:
                continue
            linhas.append([
                classe, _milhar(a["suporte"]),
                _pct(a["precisao"]), _pct(a["recall"]), _pct(a["f1"]), _pct(a["taxa_falso_positivo"]),
                _pct(a["recall_na_regra_do_teto"]),
                _pct(o["precisao"]), _pct(o["recall"]), _pct(o["f1"]), _pct(o["taxa_falso_positivo"]),
                _pct(o["recall_na_regra_do_teto"]),
            ])
        texto += [
            "",
            f"### `{e['nome']}`: {_descricao(e)}",
            "",
            *_tabela(
                [
                    "Classe", "Linhas no teste", "Precisão", "Recall", "F1", "Falso positivo",
                    "Recall na regra do teto",
                    "Precisão (repond.)", "Recall (repond.)", "F1 (repond.)", "Falso positivo (repond.)",
                    "Recall na regra do teto (repond.)",
                ],
                linhas,
            ),
        ]
    return texto


def _da_grade(m, features=None, divisao=None, classes=None):
    """Execuções da grade que casam com o que foi pedido, na ordem da grade."""
    return [
        e for e in m["execucoes"]
        if e["alvo"] in ("8", "7")
        and features in (None, e["features"]) and divisao in (None, e["divisao"]) and classes in (None, e["alvo"])
    ]


def _secao_importancias(m):
    texto = [
        "## Importância das features",
        "",
        "Importância por redução média de impureza, a que o scikit-learn calcula no treino. As importâncias de",
        "um modelo somam 100%. As features estão na ordem da primeira coluna, e as que dependem do tamanho da",
        f"janela estão marcadas. A tabela completa, com as execuções de referência, está em `{IMPORTANCIAS}`.",
    ]
    for features in CONJUNTOS_DE_FEATURES:
        execucoes = _da_grade(m, features=features)
        if not execucoes:
            continue
        linhas = [
            [
                posicao,
                f"`{feature}`" + (" (janela)" if feature in DEPENDENTES_DA_JANELA else ""),
                *(_pct(e["importancias"][feature]) for e in execucoes),
            ]
            for posicao, feature in enumerate(execucoes[0]["importancias"], start=1)
        ]
        texto += [
            "",
            f"### Com {features} features",
            "",
            *_tabela(["Posição", "Feature", *(f"`{e['nome']}`" for e in execucoes)], linhas),
        ]
    return texto


def _nota_das_34_classes(m):
    """A redução de árvores da execução de 34 classes, quando ela aconteceu."""
    p = m["parametros"]
    if p["arvores_com_34_classes"] == p["arvores"]:
        return []
    return [
        (
            f"A execução de 34 classes usa {p['arvores_com_34_classes']} árvores, e não {p['arvores']}. Com 34 "
            "classes cada nó guarda 34 contagens e as árvores têm mais nós, e a floresta de "
            f"{p['arvores']} árvores não caberia na memória da máquina usada. As medidas dessa execução não são "
            "diretamente comparáveis às das outras."
        ),
        "",
    ]


def _secao_custo(m):
    linhas = [
        [
            f"`{e['nome']}`", e["arvores"], _decimal(e["treino_segundos"]), _decimal(e["teste_segundos"]),
            _decimal(e["inferencia_ms_por_mil_janelas"]["um_nucleo"]),
            _decimal(e["inferencia_ms_por_mil_janelas"]["todos_os_nucleos"]),
            _decimal(e["modelo_bytes"] / 1e6), _milhar(e["nos_por_arvore"]), _decimal(e["profundidade_media"]),
        ]
        for e in m["execucoes"]
    ]
    return [
        "## Custo de cada execução",
        "",
        "Os tempos são da máquina em que o experimento rodou e mudam de uma execução para outra. O tempo de",
        "inferência é a mediana de cinco classificações de um lote de 1.000 janelas. O tamanho do modelo é o do",
        "arquivo gravado com `joblib`, sem compressão.",
        "",
        *_tabela(
            [
                "Execução", "Árvores", "Treino (s)", "Classificar o teste inteiro, um núcleo (s)",
                "1.000 janelas, um núcleo (ms)", "1.000 janelas, todos os núcleos (ms)", "Modelo (MB)",
                "Nós por árvore", "Profundidade média",
            ],
            linhas,
        ),
        "",
        *_nota_das_34_classes(m),
        "As predições usadas nas métricas somam os votos das árvores com um núcleo, em ordem fixa. Com vários",
        "núcleos o scikit-learn soma na ordem em que as árvores terminam, e uma linha com duas classes",
        "empatadas pode mudar de resposta de uma chamada para outra.",
    ]


def _variacao(antes, depois, chave):
    """Uma medida em duas execuções, na amostra e reponderada: valores e diferença em pontos percentuais."""
    celulas = []
    for distribuicao in ("amostra", "original"):
        a, d = antes[distribuicao][chave], depois[distribuicao][chave]
        celulas += [_pct(a), _pct(d), _pp(d - a)]
    return celulas


CABECALHO_DA_VARIACAO = (
    "Na amostra, {0}", "Na amostra, {1}", "Diferença (p.p.)", "Reponderada, {0}", "Reponderada, {1}", "Diferença (p.p.)",
)


def _entre_janelas(execucao, populacao=None):
    """Fração das linhas em que a classe real e a prevista são de grupos de janela diferentes."""
    confusao = _confusao(execucao, populacao)
    de_100 = np.array([classe in JANELA_DE_100 for classe in confusao.index])
    valores = confusao.to_numpy(dtype=float)
    return float(valores[np.not_equal.outer(de_100, de_100)].sum() / valores.sum())


def _decisao_janela(m):
    pares = [
        (com, sem)
        for com in _da_grade(m, features="39") for sem in _da_grade(m, features="33")
        if (com["divisao"], com["alvo"]) == (sem["divisao"], sem["alvo"])
    ]
    populacao = m["populacao"]
    acuracia = [
        [f"{NOME_DA_DIVISAO[com['divisao']]}, {NOME_DO_ALVO[com['alvo']]}", *_variacao(com, sem, "acuracia")]
        for com, sem in pares
    ]
    macro = [
        [f"{NOME_DA_DIVISAO[com['divisao']]}, {NOME_DO_ALVO[com['alvo']]}", *_variacao(com, sem, "macro_f1")]
        for com, sem in pares
    ]
    cruzados = [
        [
            f"{NOME_DA_DIVISAO[com['divisao']]}, {NOME_DO_ALVO[com['alvo']]}",
            _pct(_entre_janelas(com), 3), _pct(_entre_janelas(sem), 3),
            _pct(_entre_janelas(com, populacao), 3), _pct(_entre_janelas(sem, populacao), 3),
            _pct(com["amostra"]["falso_positivo_benigno"]), _pct(sem["amostra"]["falso_positivo_benigno"]),
        ]
        for com, sem in pares
    ]
    com_39 = _da_grade(m, features="39")
    soma = [sum(e["importancias"][coluna] for coluna in DEPENDENTES_DA_JANELA) for e in com_39]
    posicao = [list(e["importancias"]).index("Number") + 1 for e in com_39]
    colunas = [texto.format("39", "33") for texto in CABECALHO_DA_VARIACAO]
    return [
        "### Janela de 10 ou de 100 pacotes",
        "",
        "O que muda quando saem as seis colunas que dependem do tamanho da janela, com a divisão e o alvo fixos.",
        "",
        "Acurácia:",
        "",
        *_tabela(["Divisão e alvo", *colunas], acuracia),
        "",
        "Macro-F1:",
        "",
        *_tabela(["Divisão e alvo", *colunas], macro),
        "",
        "Erros entre os dois grupos de janela, isto é, linha de DDoS, DoS ou Mirai (janela de 100) classificada",
        "em categoria de janela de 10, ou o contrário, como fração das linhas de teste. Ao lado, o tráfego benigno",
        "classificado como ataque:",
        "",
        *_tabela(
            [
                "Divisão e alvo", "Entre janelas na amostra, 39", "Entre janelas na amostra, 33",
                "Entre janelas reponderado, 39", "Entre janelas reponderado, 33",
                "Benigno como ataque, 39", "Benigno como ataque, 33",
            ],
            cruzados,
        ),
        "",
        (
            f"- Nas quatro execuções com 39 features, as seis colunas somam de {_pct(min(soma), 1)} a "
            f"{_pct(max(soma), 1)} da importância, e `Number` fica entre a {min(posicao)}ª e a {max(posicao)}ª "
            "posição das 39."
        ),
        "- As seis colunas são função de colunas que ficam (`dados/README.md`), então as 33 guardam a mesma",
        "  informação sobre o tráfego. O que sai é a leitura direta do tamanho da janela.",
        "- Este experimento não mede o efeito de classificar tráfego agregado com uma janela diferente da do",
        "  treino. Treino e teste vêm da mesma amostra, em que a janela acompanha a classe, com 39 ou com 33",
        "  features. A medida direta é pontuar capturas processadas pelo extrator com outro tamanho de janela",
        "  (`python -m codigo.classificador.avaliar MODELO --csv CAPTURA --rotulo ROTULO`).",
    ]


def _decisao_divisao(m):
    pares = [
        (linhas, grupos)
        for linhas in _da_grade(m, divisao="estratificada") for grupos in _da_grade(m, divisao="grupos")
        if (linhas["features"], linhas["alvo"]) == (grupos["features"], grupos["alvo"])
    ]
    colunas = [texto.format("sorteio", "grupos") for texto in CABECALHO_DA_VARIACAO]

    def rotulo_do_par(e):
        return f"{e['features']} features, {NOME_DO_ALVO[e['alvo']]}"

    acuracia = [[rotulo_do_par(a), *_variacao(a, b, "acuracia")] for a, b in pares]
    macro = [[rotulo_do_par(a), *_variacao(a, b, "macro_f1")] for a, b in pares]
    teto = [[rotulo_do_par(a), *_variacao(a, b, "teto")] for a, b in pares]
    estratificada, amostra = m["divisoes"]["estratificada"], m["amostra"]
    no_treino = estratificada["teste_com_vetor_no_treino"]["39"]
    return [
        "### Divisão entre treino e teste",
        "",
        "O que muda do sorteio estratificado de linhas para a divisão por grupos, com as features e o alvo fixos.",
        "As duas divisões têm linhas de teste diferentes.",
        "",
        "Acurácia:",
        "",
        *_tabela(["Features e alvo", *colunas], acuracia),
        "",
        "Macro-F1:",
        "",
        *_tabela(["Features e alvo", *colunas], macro),
        "",
        "Teto:",
        "",
        *_tabela(["Features e alvo", *colunas], teto),
        "",
        (
            f"- No sorteio estratificado, {_milhar(no_treino)} das {_milhar(estratificada['teste'])} linhas de "
            f"teste ({_pct(no_treino / estratificada['teste'])}) têm o mesmo vetor de uma linha do treino, com as "
            "39 features. Na divisão por grupos, nenhuma."
        ),
        (
            f"- Na amostra, {_pct(amostra['linhas_repetidas']['39'] / amostra['linhas'])} das linhas repetem o "
            f"vetor de outra. No conjunto completo são {_pct(LINHAS_REPETIDAS_NO_CONJUNTO)}. A diferença entre as "
            "duas divisões medida aqui é a da amostra, com menos repetição do que haveria no dataset inteiro."
        ),
        "- O teto das duas divisões não mede a mesma coisa. Na divisão por grupos, todas as repetições de um",
        "  vetor ficam do mesmo lado, e o teto conta os conflitos de classe inteiros. No sorteio de linhas, parte",
        "  das repetições fica no treino, e o teto só conta os conflitos que caíram no teste.",
        "- A divisão por grupos separa vetores idênticos. Ela não separa janelas vizinhas do mesmo pcap, que são",
        "  parecidas sem ser iguais. A saída de dividir pelos CSVs por ataque, que preservam o arquivo de",
        "  origem, não é medida aqui: a amostra vem do `MERGED_CSV`, que não guarda o arquivo de cada linha.",
    ]


def _trocas(execucao, populacao=None):
    """Trocas entre DDoS e DoS num modelo de 8 categorias: fração das linhas e fração dos erros."""
    confusao = _confusao(execucao, populacao)
    valores = confusao.to_numpy(dtype=float)
    trocas = confusao.loc["DDoS", "DoS"] + confusao.loc["DoS", "DDoS"]
    total, erros = valores.sum(), valores.sum() - np.trace(valores)
    return {
        "dos_erros": float(trocas / erros) if erros else 0.0,
        "acuracia_com_fusao": float((np.trace(valores) + trocas) / total),
    }


def _decisao_ddos_e_dos(m):
    pares = [
        (oito, sete)
        for oito in _da_grade(m, classes="8") for sete in _da_grade(m, classes="7")
        if (oito["features"], oito["divisao"]) == (sete["features"], sete["divisao"])
    ]
    populacao = m["populacao"]
    colunas = [texto.format("8", "7") for texto in CABECALHO_DA_VARIACAO]

    def rotulo_do_par(e):
        return f"{e['features']} features, {NOME_DA_DIVISAO[e['divisao']]}"

    acuracia = [[rotulo_do_par(a), *_variacao(a, b, "acuracia")] for a, b in pares]
    teto = [[rotulo_do_par(a), *_variacao(a, b, "teto")] for a, b in pares]
    detalhe = []
    for oito, sete in pares:
        na_amostra, reponderada = _trocas(oito), _trocas(oito, populacao)
        detalhe.append([
            rotulo_do_par(oito),
            _par(_recalls(oito, "DDoS")), _par(_recalls(oito, "DoS")), _par(_recalls(sete, FUSAO)),
            f"{_pct(na_amostra['dos_erros'], 1)} e {_pct(reponderada['dos_erros'], 1)}",
            f"{_pct(na_amostra['acuracia_com_fusao'])} e {_pct(reponderada['acuracia_com_fusao'])}",
            f"{_pct(sete['amostra']['acuracia'])} e {_pct(sete['original']['acuracia'])}",
        ])
    custo = [
        [
            rotulo_do_par(oito),
            _decimal(oito["modelo_bytes"] / 1e6), _decimal(sete["modelo_bytes"] / 1e6),
            _milhar(oito["nos_por_arvore"]), _milhar(sete["nos_por_arvore"]),
            _decimal(oito["treino_segundos"]), _decimal(sete["treino_segundos"]),
        ]
        for oito, sete in pares
    ]
    return [
        "### DDoS e DoS",
        "",
        "O que muda de 8 categorias para 7, com DDoS e DoS fundidas, com as features e a divisão fixas.",
        "",
        "Acurácia:",
        "",
        *_tabela(["Features e divisão", *colunas], acuracia),
        "",
        "Teto:",
        "",
        *_tabela(["Features e divisão", *colunas], teto),
        "",
        "Recall das duas categorias e peso das trocas entre elas. Em cada célula, o primeiro valor é na amostra",
        "e o segundo é reponderado. \"Trocas\" são as linhas de DDoS classificadas como DoS e as de DoS",
        "classificadas como DDoS. A penúltima coluna conta essas trocas como acerto no modelo de 8 categorias, e",
        "a última é o modelo treinado com 7.",
        "",
        *_tabela(
            [
                "Features e divisão", "Recall de DDoS, 8 categorias", "Recall de DoS, 8 categorias",
                f"Recall de {FUSAO}, 7 categorias", "Trocas entre DDoS e DoS, como fração dos erros do modelo de 8",
                "Acurácia do modelo de 8 sem contar as trocas como erro", "Acurácia do modelo de 7",
            ],
            detalhe,
        ),
        "",
        "Custo do modelo:",
        "",
        *_tabela(
            [
                "Features e divisão", "Modelo de 8 (MB)", "Modelo de 7 (MB)", "Nós por árvore, 8",
                "Nós por árvore, 7", "Treino de 8 (s)", "Treino de 7 (s)",
            ],
            custo,
        ),
        "",
        "- O macro-F1 de 8 categorias e o de 7 são médias sobre conjuntos de classes diferentes e não se comparam",
        "  diretamente. Os dois estão na tabela das 10 execuções.",
        "- Os tetos desta seção são os das linhas de teste de cada execução. O teto que a exploração mediu no",
        "  conjunto completo vale para aquele conjunto, na proporção natural das classes, e não se compara com",
        "  eles. Nenhum deles limita o recall de DoS: o recall de uma categoria depende da regra, e a regra do",
        "  teto maximiza o acerto global.",
        "- A terceira saída em análise, deixar o modelo dizer o tipo de flood e separar DDoS de DoS pela",
        "  quantidade de origens no alerta, não é medida aqui: as 39 features não trazem endereços de origem.",
    ]


def _como_foram_obtidos(m):
    p = m["parametros"]
    return [
        "## Como os números foram obtidos",
        "",
        f"- Comando: `{m['gerado_por']}`, a partir da raiz do repositório. Semente {m['semente']} na divisão e no modelo.",
        (
            f"- Amostra: `{m['amostra']['arquivo']}`, com SHA-256 do CSV descomprimido "
            f"`{m['amostra']['sha256_do_csv_descomprimido']}`, conferido com `manifesto_amostra.json` antes de treinar."
        ),
        (
            f"- Modelo: `RandomForestClassifier` do scikit-learn com os parâmetros padrão, {p['arvores']} árvores, "
            "`n_jobs=-1` e sem `StandardScaler`. Não houve busca de hiperparâmetros."
        ),
        "- As métricas saem da matriz de confusão de cada execução. As reponderadas usam a matriz que abre a",
        f"  classe real nos 34 rótulos (`{MATRIZES}/*_por_rotulo.csv`) e as contagens do conjunto completo.",
        "- A média macro é sobre as classes do alvo. Os percentuais das tabelas são arredondados, e os valores",
        f"  completos estão em `{MANIFESTO}`.",
        f"- `{METRICAS}` tem uma linha por execução, distribuição e classe. A distribuição `amostra` é a medida",
        "  nas linhas de teste, e `original` é a reponderada.",
        f"- Com a mesma amostra e a mesma semente, `{METRICAS}`, `{IMPORTANCIAS}` e as matrizes saem idênticos.",
        "  As medidas de tempo mudam a cada execução.",
        "",
    ]


def montar_relatorio(m):
    """Monta o relatório do experimento em Markdown, a partir do manifesto."""
    v = m["versoes"]
    data = datetime.date.fromisoformat(m["gerado_em"]).strftime("%d/%m/%Y")
    secoes = [
        [
            "# Treino exploratório do classificador",
            "",
            (
                f"Gerado por `{m['gerado_por']}` em {data}, com Python {v['python']}, scikit-learn "
                f"{v['scikit-learn']}, pandas {v['pandas']} e numpy {v['numpy']}."
            ),
            "",
            "Dez execuções do Random Forest sobre a amostra de treino do CICIoT2023 (Neto et al., 2023). Oito",
            "combinam três escolhas que estão em aberto no `ROADMAP.md`: as colunas que dependem do tamanho da",
            "janela, a divisão entre treino e teste e a separação entre DDoS e DoS. Duas servem de referência para",
            "os cenários do artigo do dataset. O relatório traz os números e não recomenda nenhuma das saídas.",
        ],
        _como_ler(m),
        _secao_divisoes(m),
        _secao_execucoes(m),
        _secao_por_classe(m),
        _secao_importancias(m),
        _secao_custo(m),
        [
            "## O que os números dizem sobre cada decisão em aberto",
            "",
            "Só o que mudou e quanto, sem recomendação. As diferenças são da segunda coluna menos a primeira, em",
            "pontos percentuais. \"Na amostra\" é medido nas linhas de teste como elas são, e \"reponderada\" é a",
            "estimativa na distribuição original do dataset.",
            "",
            *_decisao_janela(m),
            "",
            *_decisao_divisao(m),
            "",
            *_decisao_ddos_e_dos(m),
        ],
        _como_foram_obtidos(m),
    ]
    return "\n".join("\n".join(secao) + "\n" for secao in secoes).rstrip("\n") + "\n"


def _relatar(resultado):
    print(
        f"{resultado['nome']}: {resultado['arvores']} árvores, treino em {_decimal(resultado['treino_segundos'])} s, "
        f"acurácia de {_pct(resultado['amostra']['acuracia'])} na amostra e "
        f"{_pct(resultado['original']['acuracia'])} reponderada",
        file=sys.stderr,
    )


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.classificador.experimento",
        description="Roda a grade do treino exploratório e grava os resultados.",
    )
    analisador.add_argument("--amostra", default="dados/processed/amostra.csv.gz")
    analisador.add_argument("--manifesto-da-amostra", default="experimentos/resultados/manifesto_amostra.json")
    analisador.add_argument("--saida", default="experimentos/resultados", help="pasta dos resultados")
    analisador.add_argument("--semente", type=int, default=SEMENTE, help=f"padrão: {SEMENTE}")
    analisador.add_argument("--arvores", type=_positivo, default=ARVORES, help=f"padrão: {ARVORES}")
    analisador.add_argument(
        "--modelos", default=None, help="pasta onde guardar os modelos treinados (padrão: não guardar)"
    )
    analisador.add_argument(
        "--refazer-relatorio", action="store_true",
        help="não treina: refaz o relatório e as tabelas a partir do manifesto do experimento",
    )
    try:
        argumentos = analisador.parse_args(argv)
    except SystemExit as encerramento:
        return encerramento.code
    saida = Path(argumentos.saida)
    try:
        if argumentos.refazer_relatorio:
            manifesto = json.loads((saida / MANIFESTO).read_text(encoding="utf-8"))
        else:
            quadro, sha256 = carregar(argumentos.amostra)
            da_amostra = json.loads(Path(argumentos.manifesto_da_amostra).read_text(encoding="utf-8"))
            if sha256 != da_amostra["saida"]["sha256_do_csv_descomprimido"]:
                raise ValueError(
                    f"{argumentos.amostra} não é a amostra registrada no manifesto {argumentos.manifesto_da_amostra}"
                )
            populacao = populacao_do_manifesto(argumentos.manifesto_da_amostra)
            registro = rodar(
                quadro, populacao, semente=argumentos.semente, arvores=argumentos.arvores,
                pasta_dos_modelos=argumentos.modelos, sha256=sha256, ao_terminar=_relatar,
            )
            manifesto = montar_manifesto(
                registro, populacao, argumentos.amostra, argumentos.manifesto_da_amostra, sha256,
                argumentos.semente, argumentos.arvores,
            )
        gravar(manifesto, saida)
    except (OSError, ValueError, KeyError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrompido: nenhum resultado foi gravado", file=sys.stderr)
        return 130
    print(f"resultados em {saida}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
