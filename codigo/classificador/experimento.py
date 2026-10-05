"""Treino exploratório do classificador: a grade de execuções e o relatório.

Roda o Random Forest sobre a amostra de treino e grava os resultados em
`experimentos/resultados/`. As oito execuções da grade combinam três escolhas que estão em
aberto no `ROADMAP.md`:

- features: as 39, ou 33 sem as seis colunas que dependem do tamanho da janela;
- divisão entre treino e teste: sorteio estratificado de linhas, ou por grupos de vetores idênticos;
- alvo: 8 categorias, ou 7 com DDoS e DoS fundidas.

Um quarto fator é a priori de treino. A amostra limita as linhas de cada rótulo, então quem
treina nela aprende as proporções da amostra, e não as do dataset. As quatro combinações do
sorteio estratificado são treinadas também com a proporção natural, em que cada linha de treino
pesa o que o seu rótulo pesa no conjunto completo.

As execuções de referência repetem, com 39 features e sorteio estratificado, os cenários de
34 classes e de ataque ou benigno do artigo do dataset, com as duas prioris.

Sementes. Tudo roda com a semente principal, na divisão e no modelo. A grade e as execuções com
a proporção natural são repetidas com outras sementes, para que o relatório mostre a faixa de
cada medida entre sementes e compare com ela as diferenças entre as escolhas.

O que é gravado:

- `manifesto_treino_exploratorio.json`: sementes, parâmetros, versões, hash da amostra, as
  divisões e todos os números de cada execução, as da semente principal e as das repetições.
  Os outros arquivos saem dele;
- `treino_exploratorio.md`: o relatório;
- `metricas_classificador.csv` e `importancia_features.csv`, em formato longo, com as execuções
  da semente principal;
- `matrizes_confusao/`: duas por execução da semente principal, a do alvo e a que abre a classe
  real nos 34 rótulos.

Com a mesma amostra e as mesmas sementes, os números são os mesmos a cada execução. Só mudam a
data e as medidas de tempo.

Uso, a partir da raiz do repositório:
    python -m codigo.classificador.experimento
    python -m codigo.classificador.experimento --repeticoes
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
    JANELAS_AVULSAS,
    avaliar,
    importancias,
    matriz_de_confusao,
    pesos,
    populacao_do_manifesto,
    tempo_por_janela,
    tempo_por_mil,
    teto,
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

# Medidas do conjunto completo que o relatório cita. Não saem deste experimento, que só lê a amostra:
# vêm de `experimentos/resultados/exploracao.md`, seção 8 ("Linhas repetidas"), e um teste confere
# cada valor contra o texto versionado da exploração.
FONTE_DO_CONJUNTO_COMPLETO = "`exploracao.md`, seção 8"
LINHAS_REPETIDAS_NO_CONJUNTO = 0.5878  # linhas que repetem as 39 features de outra linha
TETO_DE_8_CATEGORIAS_NO_CONJUNTO = 0.9287  # maior acerto em 8 categorias para quem só vê as 39 features

NOME_DA_DIVISAO = {"estratificada": "sorteio estratificado", "grupos": "divisão por grupos"}
PRIORIS = ("amostra", "natural")
REPETICOES = (7, 2026)  # sementes com que a grade é repetida, além da principal
# Uma diferença com o mesmo sinal em todas as sementes é comparada com a maior variação de uma mesma
# execução entre sementes. O relatório a chama de pequena abaixo do primeiro fator e de muito acima do
# ruído a partir do segundo.
FATOR_DE_DIFERENCA_PEQUENA = 2
FATOR_DE_MUITO_ACIMA_DO_RUIDO = 10
NOME_DA_PRIORI = {"amostra": "priori da amostra", "natural": "priori natural"}
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
# O relatório só afirma que o atalho da janela continua sem as seis colunas se o modelo de 33
# features ainda puser ao menos esta fração das linhas de teste no grupo de janela certo.
SEPARACAO_QUE_MANTEM_O_ATALHO = 0.99


@dataclass(frozen=True)
class Execucao:
    """Uma configuração do experimento."""

    features: str  # "39" ou "33"
    divisao: str  # "estratificada" ou "grupos"
    alvo: str  # "34", "8", "7" ou "2"
    priori: str = "amostra"  # "amostra", as proporções da amostra, ou "natural", as do conjunto completo

    @property
    def nome(self):
        nome = f"f{self.features}_{self.divisao}_c{self.alvo}"
        return nome if self.priori == "amostra" else f"{nome}_{self.priori}"


GRADE = tuple(
    Execucao(features, divisao, classes)
    for features in ("39", "33") for divisao in DIVISOES for classes in ("8", "7")
)
# As combinações do sorteio estratificado, treinadas com a proporção natural das classes.
GRADE_NATURAL = tuple(
    Execucao(features, "estratificada", classes, "natural") for features in ("39", "33") for classes in ("8", "7")
)
REFERENCIAS = tuple(
    Execucao("39", "estratificada", classes, priori) for classes in ("34", "2") for priori in PRIORIS
)


def pesos_de_treino(rotulos, populacao):
    """Peso de cada linha de treino na priori natural, com média 1.

    Cada linha pesa as linhas do seu rótulo no conjunto completo sobre as linhas dele no treino:
    somados, os pesos de um rótulo dão a fração que ele tem no conjunto completo.
    """
    peso = pesos(rotulos, populacao)
    return peso * (len(peso) / peso.sum())


def _repetidas(grupos):
    """Linhas cujo vetor aparece mais de uma vez."""
    vezes = np.bincount(grupos)
    return int(vezes[vezes > 1].sum())


def rodar(quadro, populacao, execucoes=(*GRADE, *GRADE_NATURAL, *REFERENCIAS), semente=SEMENTE, arvores=ARVORES,
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
    desconhecidas = sorted({execucao.priori for execucao in execucoes} - set(PRIORIS))
    if desconhecidas:
        raise ValueError(
            f"priori de treino desconhecida: {', '.join(map(repr, desconhecidas))} (as prioris são {', '.join(PRIORIS)})"
        )
    registro = {
        "amostra": {
            "linhas": len(quadro),
            "linhas_por_rotulo": {r: int((rotulos == r).sum()) for r in ROTULOS if (rotulos == r).any()},
            "linhas_com_vazio_ou_infinito": int((~np.isfinite(quadro[list(CONJUNTOS_DE_FEATURES["39"])])).any(axis=1).sum()),
            "vetores_distintos": {nome: int(g.max()) + 1 for nome, g in grupos.items()},
            "linhas_repetidas": {nome: _repetidas(g) for nome, g in grupos.items()},
            # O teto de todas as linhas da amostra, para comparar com o das linhas de teste de cada execução.
            "teto": {
                nome: {
                    nome_do_alvo: {
                        "amostra": teto(g, rotulos, nome_do_alvo)["acuracia"],
                        "original": teto(g, rotulos, nome_do_alvo, populacao)["acuracia"],
                    }
                    for nome_do_alvo in ALVOS
                }
                for nome, g in grupos.items()
            },
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
            naturais = pesos_de_treino(rotulos[treino], populacao) if execucao.priori == "natural" else None
            modelo, treino_segundos = treinar(X[treino], y[treino], semente, quantas, naturais)
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
                divisao=execucao.divisao, priori=execucao.priori, semente=semente, arvores=quantas,
                amostra_sha256=sha256,
            )
            if pasta_dos_modelos is None:
                arquivo.unlink()
            com_um_nucleo = lambda lote, modelo=modelo: prever(modelo, lote)
            resultado = {
                "nome": execucao.nome,
                "features": execucao.features,
                "divisao": execucao.divisao,
                "alvo": execucao.alvo,
                "priori": execucao.priori,
                "semente": semente,
                "arvores": quantas,
                "linhas_de_treino": len(treino),
                "linhas_de_teste": len(teste),
                "treino_segundos": treino_segundos,
                "teste_segundos": teste_segundos,
                "inferencia_ms_por_mil_janelas": {
                    "um_nucleo": tempo_por_mil(com_um_nucleo, X_teste),
                    "todos_os_nucleos": tempo_por_mil(modelo.predict, X_teste),
                },
                "inferencia_ms_por_janela_avulsa": tempo_por_janela(com_um_nucleo, X_teste),
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


def montar_manifesto(registro, populacao, amostra, manifesto_da_amostra, sha256, semente, arvores, repeticoes=()):
    """O registro do experimento: o que é preciso para refazê-lo e todos os números que ele produziu.

    `repeticoes` traz, para cada semente além da principal, as divisões e as execuções repetidas.
    """
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
        "repeticoes": list(repeticoes),
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
        f"{execucao['features']} features, {NOME_DA_DIVISAO[execucao['divisao']]}, "
        f"{NOME_DO_ALVO[execucao['alvo']]}, {NOME_DA_PRIORI[execucao['priori']]}"
    )


def _enumerar(itens):
    """Os itens em texto corrido: "42, 7 e 2026"."""
    itens = [str(item) for item in itens]
    return itens[0] if len(itens) == 1 else f"{', '.join(itens[:-1])} e {itens[-1]}"


def _todas(m):
    """Todas as execuções do manifesto: as da semente principal e as das repetições."""
    return [*m["execucoes"], *(e for repeticao in m["repeticoes"] for e in repeticao["execucoes"])]


def _sementes(m):
    """As sementes do experimento, a começar pela principal."""
    return [m["semente"], *(repeticao["semente"] for repeticao in m["repeticoes"])]


def _outras_sementes(m):
    """As sementes das repetições, em texto corrido: "a semente 7" ou "as sementes 7 e 2026"."""
    outras = [repeticao["semente"] for repeticao in m["repeticoes"]]
    return f"{'a semente' if len(outras) == 1 else 'as sementes'} {_enumerar(outras)}"


def _em_cada_semente(m, execucao):
    """A mesma configuração em cada semente em que rodou, a começar pela principal."""
    return [e for e in _todas(m) if e["nome"] == execucao["nome"]]


def _de_todas_as_sementes(m, execucoes):
    """As execuções dadas e as repetições delas com as outras sementes."""
    return [repetida for e in execucoes for repetida in _em_cada_semente(m, e)]


def _nas_sementes(m):
    """Complemento de frase que diz que a conta inclui as repetições."""
    return f", contadas as {len(_sementes(m))} sementes" if m["repeticoes"] else ""


def _faixa(valores, casas=2):
    """O menor e o maior de uma lista de percentuais: "de 1,00% a 2,00%", ou o valor só, se os dois coincidem."""
    menor, maior = _pct(min(valores), casas), _pct(max(valores), casas)
    return menor if menor == maior else f"de {menor} a {maior}"


def _benigno_e_janela_de_10(contagens):
    """Linhas de tráfego benigno e linhas das categorias de ataque com janela de 10, numa contagem por rótulo."""
    de_10 = [
        rotulo for rotulo in ROTULOS
        if CATEGORIA_DO_ROTULO[rotulo] not in JANELA_DE_100 and rotulo != "BenignTraffic"
    ]
    return contagens.get("BenignTraffic", 0), sum(contagens.get(rotulo, 0) for rotulo in de_10)


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
        "A ponderação altera só o cálculo da medida. O modelo avaliado é o mesmo nas duas formas, e o que ele",
        "aprendeu depende da priori de treino, descrita abaixo.",
        "",
        (
            "O peso é por rótulo, entre os 34, e não por classe do alvo. O recall de um rótulo não muda com a "
            "ponderação. O de uma categoria que reúne vários rótulos muda, porque dentro dela os rótulos passam a "
            f"pesar de outra forma.{exemplo} A taxa de tráfego benigno classificado como ataque não muda com a "
            "ponderação, porque o tráfego benigno é um rótulo só. Ela muda com a priori de treino."
        ),
        "",
        *_priori_de_treino(m),
        "",
        (
            "**Vetor idêntico.** Duas linhas têm o mesmo vetor quando são iguais em todas as features da execução, "
            "depois da conversão para ponto flutuante de 32 bits, que é como o scikit-learn as entrega às árvores. "
            f"A amostra tem {_milhar(distintos['39'])} vetores distintos com as 39 features e "
            f"{_milhar(distintos['33'])} com as 33. Com as 39, {_milhar(repetidas['39'])} linhas "
            f"({_pct(repetidas['39'] / total)}) repetem o vetor de outra linha. No conjunto completo são "
            f"{_pct(LINHAS_REPETIDAS_NO_CONJUNTO)} ({FONTE_DO_CONJUNTO_COMPLETO}): a amostra guarda uma fração "
            "pequena das classes grandes, e a maior parte das repetições delas fica de fora."
        ),
        "",
        (
            "**Teto.** É um limite por coincidência exata de vetores, calculado nas linhas de teste de cada "
            "execução. Quem só vê as features dá a mesma resposta a todas as linhas com o mesmo vetor. A regra que "
            "mais acerta responde, em cada vetor, a classe mais frequente, e as linhas das outras classes são erro "
            "certo. A acurácia dessa regra é a maior possível naquelas linhas, e é com ela que a acurácia na "
            "amostra da mesma execução se compara. O teto depende da mistura de classes do conjunto em que é "
            "medido e cai quando o conjunto cresce: com mais linhas, mais vetores se repetem com classes "
            "diferentes. Por isso ele muda com a divisão. No sorteio de linhas, parte das repetições de um vetor "
            "fica no treino e não entra na conta."
        ),
        "",
        _limite_da_reponderada(m),
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
        _paragrafo_das_sementes(m),
    ]


def _paragrafo_das_sementes(m):
    """O parágrafo que diz com que sementes o experimento rodou e como ler a faixa entre elas."""
    if not m["repeticoes"]:
        return (
            f"**Uma semente.** Cada execução foi feita uma vez, com a semente {m['semente']} na divisão e no "
            "modelo. Diferenças pequenas entre execuções podem vir do sorteio, e não da escolha comparada. Para "
            f"repetir a grade com outras sementes: `{m['gerado_por']} --repeticoes "
            f"{' '.join(map(str, REPETICOES))}`."
        )
    quantas = len(_sementes(m))
    return (
        f"**Sementes.** As tabelas trazem os valores da semente {m['semente']}, usada na divisão e no modelo. A "
        f"grade das três escolhas e as execuções com a priori natural foram repetidas com {_outras_sementes(m)}, "
        "cada uma com outra divisão e outros modelos. A faixa entre sementes vai do menor ao maior valor das "
        f"{quantas} sementes. Uma diferença "
        "entre duas escolhas que muda de sinal de uma comparação para outra não se distingue do ruído de semente. "
        "Uma diferença com o mesmo sinal em todas as comparações é consistente, e o tamanho dela é comparado com a "
        "maior variação de uma mesma execução entre sementes: o relatório a chama de pequena quando não chega a "
        f"{FATOR_DE_DIFERENCA_PEQUENA} vezes essa variação, e de muito acima do ruído a partir de "
        f"{FATOR_DE_MUITO_ACIMA_DO_RUIDO} vezes. Com {quantas} sementes isso descreve a variação observada e não é "
        f"um teste estatístico. As execuções de referência rodaram só com a semente {m['semente']}."
    )


def _priori_de_treino(m):
    """O parágrafo que explica as duas prioris de treino."""
    amostra, populacao = m["amostra"]["linhas_por_rotulo"], m["populacao"]
    proporcoes = []
    for contagens in (amostra, populacao):
        benigno, de_10 = _benigno_e_janela_de_10(contagens)
        proporcoes.append(f"1 para {_decimal(de_10 / benigno)}" if benigno else "sem tráfego benigno")
    return [
        (
            "**Priori de treino.** A amostra limita as linhas de cada rótulo, então o modelo treinado nela aprende "
            "uma proporção entre as classes que não é a do dataset. Entre o tráfego benigno e as categorias de "
            "ataque com janela de 10 (Recon, Spoofing, Web e BruteForce), a proporção é de "
            f"{proporcoes[0]} na amostra e de {proporcoes[1]} no conjunto completo. A reponderação das medidas não "
            "corrige isso: ela muda o peso das linhas na avaliação, e não o que o modelo aprendeu. Por isso as "
            "combinações do sorteio estratificado e as execuções de referência são treinadas de duas formas:"
        ),
        "",
        "- **proporções da amostra**: todas as linhas de treino pesam o mesmo. É a priori da amostra;",
        (
            "- **proporção natural**: cada linha de treino pesa a quantidade de linhas do seu rótulo no conjunto "
            "completo dividida pela quantidade no treino (`sample_weight`). É a priori natural. No scikit-learn "
            f"{m['versoes']['scikit-learn']}, o peso é a chance de a linha entrar no sorteio com reposição que monta "
            "o conjunto de cada árvore: cada árvore recebe a mesma quantidade de linhas, na proporção das classes "
            "do conjunto completo."
        ),
        "",
        "As execuções com a priori natural têm `_natural` no nome. A divisão entre treino e teste, as linhas de",
        "teste e a avaliação são as mesmas nas duas formas.",
    ]


def _limite_da_reponderada(m):
    """O parágrafo que diz qual é o limite da acurácia reponderada."""
    amostra = m["amostra"]
    de_teste = next(
        (
            f"{_pct(e['original']['teto'])} nas {_milhar(e['linhas_de_teste'])} linhas de teste de `{e['nome']}` e "
            for e in m["execucoes"] if (e["features"], e["divisao"], e["alvo"]) == ("39", "estratificada", "8")
        ),
        "",
    )
    return (
        "**Limite da acurácia reponderada.** No sorteio estratificado, a acurácia reponderada estima a acurácia do "
        "modelo no conjunto completo. O limite esperado dela é o teto do conjunto completo, e não o das linhas de "
        f"teste: em 8 categorias, {_pct(TETO_DE_8_CATEGORIAS_NO_CONJUNTO)} com as 39 features "
        f"({FONTE_DO_CONJUNTO_COMPLETO}). O teto reponderado de uma parte da amostra fica acima desse valor, porque "
        f"o teto cai quando o conjunto cresce: em 8 categorias e com as 39 features, ele é {de_teste}"
        f"{_pct(amostra['teto']['39']['8']['original'])} nas {_milhar(amostra['linhas'])} linhas da amostra "
        f"inteira, e o conjunto completo tem {_milhar(sum(m['populacao'].values()))} linhas. Por isso as tabelas "
        "trazem o teto das linhas de teste sem reponderar, e o reponderado fica só no manifesto. A exploração não "
        "mediu o teto do conjunto completo em 7 categorias, em 34 classes nem no cenário de ataque ou benigno."
    )


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
        "- **Sorteio estratificado de linhas**: sorteio de linhas com a mesma fração de cada um dos 34 rótulos",
        "  no teste. O notebook de exemplo dos autores do dataset divide de outra forma: por arquivo, com 80% dos",
        "  CSVs no treino, na proporção natural das classes e sem estratificar.",
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
        (
            f"A tabela é a da semente {m['semente']}. O hash das linhas de teste de cada divisão está no manifesto "
            "do experimento" + (", com as divisões das repetições." if m["repeticoes"] else ".")
        ),
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
    execucoes = [
        e for e in _da_grade(m, classes="8", priori=None) if "BenignTraffic" in e["matriz_por_rotulo"]["rotulos"]
    ]
    if not execucoes:
        return []
    benignas = [_por_rotulo(e).loc["BenignTraffic"] for e in execucoes]
    linhas = [
        [classe, *(_pct(contagem[classe] / contagem.sum()) for contagem in benignas)]
        for classe in ALVOS["8"].classes
    ]
    amostra, populacao = m["amostra"]["linhas_por_rotulo"], m["populacao"]
    total, completo = sum(amostra.values()), sum(populacao.values())
    (benigno_na_amostra, de_10_na_amostra), (benigno, de_10) = (
        _benigno_e_janela_de_10(contagens) for contagens in (amostra, populacao)
    )
    return [
        "Para onde vai o tráfego benigno nas execuções de 8 categorias, como fração das linhas benignas do teste:",
        "",
        *_tabela(["Classe prevista", *(f"`{e['nome']}`" for e in execucoes)], linhas),
        "",
        (
            f"Na amostra, o tráfego benigno é {_pct(benigno_na_amostra / total, 1)} das linhas, e as "
            "categorias de ataque com janela de 10 (Recon, Spoofing, Web e BruteForce) somam "
            f"{_pct(de_10_na_amostra / total, 1)}. No conjunto completo são {_pct(benigno / completo, 1)} e "
            f"{_pct(de_10 / completo, 1)}. As execuções com `_natural` no nome foram treinadas com a proporção do "
            "conjunto completo (ver \"Priori de treino\")."
        ),
        "",
    ]


def _faixas_entre_sementes(m):
    """A tabela com a faixa de cada medida global nas sementes, para as execuções repetidas."""
    if not m["repeticoes"]:
        return []
    medidas = (
        ("acuracia", "amostra"), ("acuracia", "original"), ("macro_f1", "amostra"), ("macro_f1", "original"),
        ("falso_positivo_benigno", "amostra"),
    )
    linhas = []
    for execucao in m["execucoes"]:
        repetidas = _em_cada_semente(m, execucao)
        if len(repetidas) > 1:
            faixas = ([e[distribuicao][chave] for e in repetidas] for chave, distribuicao in medidas)
            linhas.append([f"`{execucao['nome']}`", *(f"{_pct(min(v))} a {_pct(max(v))}" for v in faixas)])
    sementes = _sementes(m)
    return [
        (
            f"Faixa de cada medida nas {len(sementes)} sementes ({_enumerar(sementes)}), do menor ao maior valor. As "
            f"execuções de referência rodaram só com a semente {m['semente']}."
        ),
        "",
        *_tabela(
            [
                "Execução", "Acurácia na amostra", "Acurácia reponderada", "Macro-F1 na amostra",
                "Macro-F1 reponderado", "Benigno classificado como ataque",
            ],
            linhas,
        ),
        "",
    ]


def _secao_execucoes(m):
    globais, de_interesse = [], []
    for e in m["execucoes"]:
        a, o = e["amostra"], e["original"]
        globais.append([
            f"`{e['nome']}`", e["features"], NOME_DA_DIVISAO[e["divisao"]], NOME_DO_ALVO[e["alvo"]], e["priori"],
            _pct(a["acuracia"]), _pct(o["acuracia"]), _pct(a["macro_f1"]), _pct(o["macro_f1"]),
            _pct(a["f1_ponderado"]), _pct(o["f1_ponderado"]), _pct(a["teto"]),
        ])
        benigno = ALVOS[e["alvo"]].benigno
        ataque_como_benigno = tuple(e[d]["por_classe"][benigno]["taxa_falso_positivo"] for d in ("amostra", "original"))
        de_interesse.append([
            f"`{e['nome']}`", _par(_recalls(e, "DDoS")), _par(_recalls(e, "DoS")), _par(_recalls(e, FUSAO)),
            _pct(a["por_classe"][benigno]["recall"]), _pct(a["falso_positivo_benigno"]), _par(ataque_como_benigno),
        ])
    return [
        f"## As {len(m['execucoes'])} execuções",
        "",
        "Medidas globais nas linhas de teste. Em cada par de colunas, a primeira é na amostra e a segunda é",
        "reponderada para a distribuição original. A priori de treino é a da amostra ou a natural. O teto é o",
        "das linhas de teste, sem reponderar, e se compara com a acurácia na amostra (ver \"Como ler os números\").",
        "",
        *_tabela(
            [
                "Execução", "Features", "Divisão", "Alvo", "Priori de treino", "Acurácia na amostra",
                "Acurácia reponderada",
                "Macro-F1 na amostra", "Macro-F1 reponderado", "F1 ponderado na amostra", "F1 ponderado reponderado",
                "Teto nas linhas de teste",
            ],
            globais,
        ),
        "",
        *_faixas_entre_sementes(m),
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
            "conferidos no artigo antes de qualquer comparação. A comparação depende também do protocolo: o "
            "notebook de exemplo dos autores treina e avalia na proporção natural das classes, com divisão por "
            "arquivo, e aqui a priori de treino muda os resultados. Nenhuma coluna deste relatório repete esse "
            "protocolo."
            + (
                f" As execuções de 34 classes usam {m['parametros']['arvores_com_34_classes']} árvores, e as demais "
                f"usam {m['parametros']['arvores']} (ver \"Custo de cada execução\")."
                if m["parametros"]["arvores_com_34_classes"] != m["parametros"]["arvores"] else ""
            )
        ),
    ]


def _secao_por_classe(m):
    texto = [
        "## Resultados por classe",
        "",
        "Uma tabela para cada execução de 8 ou de 7 categorias. As colunas da esquerda são medidas na amostra, e as da direita",
        "são reponderadas. \"Falso positivo\" é a fração das linhas das outras classes que o modelo pôs na classe.",
        "\"Recall na regra do teto\" é o recall da classe na regra de maior acerto global nas linhas de teste,",
        "sem reponderar, e não um limite da classe (ver \"Como ler os números\"). As mesmas medidas, com as execuções de",
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
                ],
                linhas,
            ),
        ]
    return texto


def _da_grade(m, features=None, divisao=None, classes=None, priori="amostra"):
    """Execuções de 8 ou de 7 categorias que casam com o que foi pedido, na ordem em que rodaram.

    Sem dizer a priori, valem as da grade das três escolhas, treinadas com as proporções da
    amostra. `priori=None` traz também as treinadas com a proporção natural.
    """
    return [
        e for e in m["execucoes"]
        if e["alvo"] in ("8", "7")
        and features in (None, e["features"]) and divisao in (None, e["divisao"]) and classes in (None, e["alvo"])
        and priori in (None, e["priori"])
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
        execucoes = _da_grade(m, features=features, priori=None)
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
            f"As execuções de 34 classes usam {p['arvores_com_34_classes']} árvores, e não {p['arvores']}. Com 34 "
            "classes cada nó guarda 34 contagens e as árvores têm mais nós, e a floresta de "
            f"{p['arvores']} árvores não caberia na memória da máquina usada. As medidas dessas execuções não são "
            "diretamente comparáveis às das outras."
        ),
        "",
    ]


def _aviso_dos_tempos(m):
    """Por que os tempos da tabela de custo não se comparam entre execuções."""
    aviso = [
        "Os tempos não se comparam entre as linhas da tabela. Eles são da máquina em que o experimento rodou e",
        "mudam de uma medida para outra com o mesmo modelo, conforme o que mais a máquina faz na hora. Servem",
        "para a ordem de grandeza, e não para dizer que uma configuração é mais rápida do que outra.",
    ]
    repetidas = [e for e in (_em_cada_semente(m, execucao) for execucao in m["execucoes"]) if len(e) > 1]
    if repetidas:
        def variacao(medida):
            return max(max(valores) / min(valores) - 1 for valores in ([medida(e) for e in grupo] for grupo in repetidas))

        aviso.append(
            f"Entre as repetições de uma mesma configuração nas {len(_sementes(m))} sementes, cujos modelos diferem "
            f"em até {_pct(variacao(lambda e: e['nos_por_arvore']), 1)} na quantidade de nós, o tempo por 1.000 "
            "janelas com um núcleo variou até "
            f"{_pct(variacao(lambda e: e['inferencia_ms_por_mil_janelas']['um_nucleo']), 0)} e o de uma janela por "
            f"chamada, até {_pct(variacao(lambda e: e['inferencia_ms_por_janela_avulsa']), 0)}."
        )
    return aviso


def _secao_custo(m):
    linhas = [
        [
            f"`{e['nome']}`", e["arvores"], _decimal(e["treino_segundos"]), _decimal(e["teste_segundos"]),
            _decimal(e["inferencia_ms_por_mil_janelas"]["um_nucleo"]),
            _decimal(e["inferencia_ms_por_mil_janelas"]["todos_os_nucleos"]),
            _decimal(e["inferencia_ms_por_janela_avulsa"], 2),
            _decimal(e["modelo_bytes"] / 1e6), _milhar(e["nos_por_arvore"]), _decimal(e["profundidade_media"]),
        ]
        for e in m["execucoes"]
    ]
    return [
        "## Custo de cada execução",
        "",
        "O tempo de inferência sai de duas formas. \"1.000 janelas\" é a mediana de cinco classificações de um",
        f"lote de 1.000 janelas. \"Uma janela por chamada\" é a mediana de {JANELAS_AVULSAS} classificações de uma",
        "janela sozinha, e é o caso da operação, em que cada janela é classificada assim que o extrator a",
        "produz. O tamanho do modelo é o do arquivo gravado com `joblib`, sem compressão.",
        "",
        *_aviso_dos_tempos(m),
        "",
        *_tabela(
            [
                "Execução", "Árvores", "Treino (s)", "Classificar o teste inteiro, um núcleo (s)",
                "1.000 janelas, um núcleo (ms)", "1.000 janelas, todos os núcleos (ms)",
                "Uma janela por chamada, um núcleo (ms)", "Modelo (MB)",
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


def _global(chave):
    """Leitor de uma medida global: a função que a tira de uma execução, numa das duas distribuições."""
    return lambda execucao, distribuicao: execucao[distribuicao][chave]


def _teto_de_teste(execucao):
    return execucao["amostra"]["teto"]


def _diferencas(m, antes, depois, medida):
    """`medida(depois) - medida(antes)` em cada semente em que as duas configurações rodaram."""
    depois_na = {e["semente"]: e for e in _em_cada_semente(m, depois)}
    return [
        medida(depois_na[e["semente"]]) - medida(e) for e in _em_cada_semente(m, antes) if e["semente"] in depois_na
    ]


def _comparar(m, antes, depois, medida):
    """Células de uma comparação: os dois valores, a diferença e, havendo repetições, a faixa dela entre sementes."""
    a, d = medida(antes), medida(depois)
    celulas = [_pct(a), _pct(d), _pp(d - a)]
    if m["repeticoes"]:
        diferencas = _diferencas(m, antes, depois, medida)
        celulas.append(f"{_pp(min(diferencas))} a {_pp(max(diferencas))}" if len(diferencas) > 1 else "sem repetição")
    return celulas


def _colunas_da_comparacao(m, prefixo, nomes):
    """As colunas de `_comparar` para duas escolhas."""
    colunas = [f"{prefixo}{nomes[0]}", f"{prefixo}{nomes[1]}", "Diferença (p.p.)"]
    if m["repeticoes"]:
        colunas.append(f"Faixa da diferença nas {len(_sementes(m))} sementes (p.p.)")
    return colunas


def _variacao(m, antes, depois, medida):
    """Uma medida em duas execuções, na amostra e reponderada. `medida` lê a execução e a distribuição."""
    return [
        celula
        for distribuicao in ("amostra", "original")
        for celula in _comparar(m, antes, depois, lambda e, d=distribuicao: medida(e, d))
    ]


def _colunas_da_variacao(m, nomes):
    return [*_colunas_da_comparacao(m, "Na amostra, ", nomes), *_colunas_da_comparacao(m, "Reponderada, ", nomes)]


def _ruido(m, execucoes, medida):
    """A maior variação de uma mesma execução entre sementes: o maior valor menos o menor."""
    faixas = ([medida(e) for e in _em_cada_semente(m, execucao)] for execucao in execucoes)
    return max((max(valores) - min(valores) for valores in faixas if len(valores) > 1), default=0.0)


def _leitura(diferencas, ruido):
    """Como uma diferença entre duas escolhas, medida em várias comparações, fica frente ao ruído de semente."""
    menor, maior = min(diferencas), max(diferencas)
    if menor <= 0 <= maior:
        return "muda de sinal de uma comparação para outra: não se distingue do ruído de semente"
    if ruido <= 0:
        return "tem o mesmo sinal em todas as comparações, e a mesma execução não variou entre as sementes"
    tamanho = min(abs(menor), abs(maior))
    vezes = tamanho / ruido
    if vezes < FATOR_DE_DIFERENCA_PEQUENA:
        classe, razao = "é pequena e consistente", f"não chega a {FATOR_DE_DIFERENCA_PEQUENA}"
    elif vezes >= FATOR_DE_MUITO_ACIMA_DO_RUIDO:
        classe, razao = "está muito acima do ruído de semente", f"é {_decimal(vezes)}"
    else:
        classe, razao = "está acima do ruído de semente", f"é {_decimal(vezes)}"
    return (
        f"tem o mesmo sinal em todas as comparações; {classe}: a menor, de {_pp(tamanho).lstrip('+')} p.p., {razao} "
        f"vezes a maior variação de uma mesma execução entre sementes ({_pp(ruido).lstrip('+')} p.p.)"
    )


def _resumo_das_diferencas(m, titulo, pares, medida):
    """A frase que resume uma comparação em todos os pares e sementes, na amostra e reponderada."""
    pares = [par for par in pares if len(_em_cada_semente(m, par[0])) > 1 and len(_em_cada_semente(m, par[1])) > 1]
    if not pares:
        return []
    frases, quantas = [], 0
    for distribuicao, inicio in (("amostra", "Na amostra, a diferença vai de"), ("original", "Reponderada, vai de")):
        def valor(execucao, distribuicao=distribuicao):
            return medida(execucao, distribuicao)

        diferencas = [d for antes, depois in pares for d in _diferencas(m, antes, depois, valor)]
        ruido = _ruido(m, [e for par in pares for e in par], valor)
        quantas = len(diferencas)
        frases.append(f"{inicio} {_pp(min(diferencas))} a {_pp(max(diferencas))} p.p. e {_leitura(diferencas, ruido)}.")
    return [
        f"- {titulo}, nas {quantas} comparações ({len(pares)} pares de execuções, {len(_sementes(m))} sementes). "
        + " ".join(frases)
    ]


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
        [f"{NOME_DA_DIVISAO[com['divisao']]}, {NOME_DO_ALVO[com['alvo']]}", *_variacao(m, com, sem, _global("acuracia"))]
        for com, sem in pares
    ]
    macro = [
        [f"{NOME_DA_DIVISAO[com['divisao']]}, {NOME_DO_ALVO[com['alvo']]}", *_variacao(m, com, sem, _global("macro_f1"))]
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
    com_39 = _de_todas_as_sementes(m, _da_grade(m, features="39"))
    soma = [sum(e["importancias"][coluna] for coluna in DEPENDENTES_DA_JANELA) for e in com_39]
    posicao = [list(e["importancias"]).index("Number") + 1 for e in com_39]
    # Fração das linhas de teste que o modelo põe no grupo de janela certo, com e sem as seis colunas.
    separa = {
        features: [1 - _entre_janelas(e) for e in _de_todas_as_sementes(m, _da_grade(m, features=features))]
        for features in ("39", "33")
    }
    faixas = {features: _faixa(valores) for features, valores in separa.items()}
    if min(separa["33"]) >= SEPARACAO_QUE_MANTEM_O_ATALHO:
        atalho = (
            f"- **Tirar as seis colunas não tira o atalho.** Sem elas, o modelo ainda põe {faixas['33']} das "
            f"linhas de teste no grupo de janela certo (com as 39, {faixas['39']}){_nas_sementes(m)}. As 33 "
            "features que ficam "
            "continuam variando com o tamanho da janela: `Min`, `Max` e `Std` dependem dele, e as médias de uma "
            "janela de 100 têm passos de 0,01, contra 0,1 na de 10 (`dados/README.md`). Como na amostra a janela "
            "acompanha a classe, o experimento não separa o que o modelo aprende do tráfego do que aprende da "
            "janela."
        )
    else:
        atalho = (
            f"- Sem as seis colunas, o modelo põe {faixas['33']} das linhas de teste no grupo de janela certo "
            f"(com as 39, {faixas['39']}){_nas_sementes(m)}."
        )
    colunas = _colunas_da_variacao(m, ("39", "33"))
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
        f"classificado como ataque. Valores da semente {m['semente']}:",
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
        *_resumo_das_diferencas(m, "Acurácia, de 39 para 33 features", pares, _global("acuracia")),
        *_resumo_das_diferencas(m, "Macro-F1, de 39 para 33 features", pares, _global("macro_f1")),
        (
            f"- Nas {len(com_39)} execuções com 39 features e priori da amostra{_nas_sementes(m)}, as seis colunas "
            f"somam {_faixa(soma, 1)} da importância, e `Number` fica entre a {min(posicao)}ª e a "
            f"{max(posicao)}ª posição das 39."
        ),
        (
            "- `Number` é a quantidade de quadros da janela e não é função das colunas que ficam. As outras cinco "
            "(`Tot sum`, `ack_count`, `syn_count`, `fin_count` e `rst_count`) são o produto de uma coluna que fica "
            "por `Number` (`exploracao.md`, seção 7). O que sai é a leitura direta do tamanho da janela."
        ),
        atalho,
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
    colunas = _colunas_da_variacao(m, ("sorteio", "grupos"))

    def rotulo_do_par(e):
        return f"{e['features']} features, {NOME_DO_ALVO[e['alvo']]}"

    acuracia = [[rotulo_do_par(a), *_variacao(m, a, b, _global("acuracia"))] for a, b in pares]
    macro = [[rotulo_do_par(a), *_variacao(m, a, b, _global("macro_f1"))] for a, b in pares]
    teto = [[rotulo_do_par(a), *_comparar(m, a, b, _teto_de_teste)] for a, b in pares]
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
        "Teto nas linhas de teste:",
        "",
        *_tabela(["Features e alvo", *_colunas_da_comparacao(m, "Teto, ", ("sorteio", "grupos"))], teto),
        "",
        *_resumo_das_diferencas(
            m, "Acurácia, do sorteio estratificado para a divisão por grupos", pares, _global("acuracia")
        ),
        *_resumo_das_diferencas(
            m, "Macro-F1, do sorteio estratificado para a divisão por grupos", pares, _global("macro_f1")
        ),
        (
            f"- No sorteio estratificado da semente {m['semente']}, {_milhar(no_treino)} das "
            f"{_milhar(estratificada['teste'])} linhas de "
            f"teste ({_pct(no_treino / estratificada['teste'])}) têm o mesmo vetor de uma linha do treino, com as "
            "39 features. Na divisão por grupos, nenhuma."
        ),
        (
            f"- Na amostra, {_pct(amostra['linhas_repetidas']['39'] / amostra['linhas'])} das linhas repetem o "
            f"vetor de outra. No conjunto completo são {_pct(LINHAS_REPETIDAS_NO_CONJUNTO)} "
            f"({FONTE_DO_CONJUNTO_COMPLETO}). A diferença entre as duas divisões medida aqui é a da amostra, com "
            "menos repetição do que haveria no dataset inteiro."
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
    colunas = _colunas_da_variacao(m, ("8", "7"))

    def rotulo_do_par(e):
        return f"{e['features']} features, {NOME_DA_DIVISAO[e['divisao']]}"

    acuracia = [[rotulo_do_par(a), *_variacao(m, a, b, _global("acuracia"))] for a, b in pares]
    teto = [[rotulo_do_par(a), *_comparar(m, a, b, _teto_de_teste)] for a, b in pares]
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
        "Teto nas linhas de teste:",
        "",
        *_tabela(["Features e divisão", *_colunas_da_comparacao(m, "Teto, ", ("8", "7"))], teto),
        "",
        "Recall das duas categorias e peso das trocas entre elas. Em cada célula, o primeiro valor é na amostra",
        "e o segundo é reponderado. \"Trocas\" são as linhas de DDoS classificadas como DoS e as de DoS",
        "classificadas como DDoS. A penúltima coluna conta essas trocas como acerto no modelo de 8 categorias, e",
        f"a última é o modelo treinado com 7. Valores da semente {m['semente']}.",
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
        *_resumo_das_diferencas(m, "Acurácia, de 8 para 7 categorias", pares, _global("acuracia")),
        "- O macro-F1 de 8 categorias e o de 7 são médias sobre conjuntos de classes diferentes e não se comparam",
        "  diretamente. Os dois estão na tabela das execuções.",
        (
            "- Os tetos desta seção são os das linhas de teste de cada execução. No conjunto completo a diferença "
            "entre o teto de 8 e o de 7 categorias é bem maior do que a medida aqui: lá o teto de 8 categorias é "
            f"{_pct(TETO_DE_8_CATEGORIAS_NO_CONJUNTO)} ({FONTE_DO_CONJUNTO_COMPLETO}), e quase todo o erro mínimo "
            "está em linhas de DDoS e de DoS com o mesmo vetor, que a fusão deixa de contar como erro. O teto de 7 "
            "categorias do conjunto completo não foi calculado, e por isso essa diferença fica sem número aqui."
        ),
        "- Nenhum teto limita o recall de DoS: o recall de uma categoria depende da regra, e a regra do teto",
        "  maximiza o acerto global.",
        "- A terceira saída em análise, deixar o modelo dizer o tipo de flood e separar DDoS de DoS pela",
        "  quantidade de origens no alerta, não é medida aqui: as 39 features não trazem endereços de origem.",
    ]


def _pares_de_priori(m):
    """Pares de execuções que só diferem na priori de treino: a da amostra e a natural."""
    def chave(e):
        return e["features"], e["divisao"], e["alvo"]

    naturais = {chave(e): e for e in m["execucoes"] if e["priori"] == "natural"}
    return [(e, naturais[chave(e)]) for e in m["execucoes"] if e["priori"] == "amostra" and chave(e) in naturais]


def _ataque_como_benigno(execucao, distribuicao):
    return execucao[distribuicao]["por_classe"][ALVOS[execucao["alvo"]].benigno]["taxa_falso_positivo"]


def _benigno_como_ataque(execucao):
    return execucao["amostra"]["falso_positivo_benigno"]


def _linhas_sorteadas_por_arvore(m, natural):
    """A frase que diz quantas linhas das categorias pequenas cada árvore recebe com a priori natural.

    Cada árvore sorteia tantas linhas quantas há no treino, na proporção do conjunto completo:
    a categoria entra, em média, com as linhas de treino vezes a fração dela no conjunto completo.
    """
    definicao = ALVOS[natural["alvo"]]
    amostra, populacao = m["amostra"]["linhas_por_rotulo"], m["populacao"]
    completo = sum(populacao.values())
    por_classe = []
    for classe in definicao.classes:
        rotulos = [rotulo for rotulo in amostra if definicao.classe_do_rotulo[rotulo] == classe]
        if rotulos:
            sorteadas = natural["linhas_de_treino"] * sum(populacao[rotulo] for rotulo in rotulos) / completo
            de_treino = sum(amostra[rotulo] for rotulo in rotulos) - natural["amostra"]["por_classe"][classe]["suporte"]
            por_classe.append((sorteadas, classe, de_treino))
    menores = sorted(por_classe)[:2]
    return (
        f"- Com a priori natural, cada árvore sorteia {_milhar(natural['linhas_de_treino'])} linhas do treino, com "
        "reposição, na proporção do conjunto completo, e as categorias pequenas entram com poucas linhas: "
        + "; ".join(
            f"{classe} com cerca de {_milhar(sorteadas)} linhas sorteadas, contra {_milhar(de_treino)} linhas de "
            "treino na amostra"
            for sorteadas, classe, de_treino in menores
        )
        + "."
    )


def _tamanho_do_modelo_por_priori(m, pares):
    """A frase que compara o tamanho do modelo nas duas prioris, por alvo, na semente principal."""
    partes = []
    for nome_do_alvo in ("8", "7"):
        do_alvo = [par for par in pares if par[0]["alvo"] == nome_do_alvo]
        if do_alvo:
            megas = ([_decimal(par[i]["modelo_bytes"] / 1e6) for par in do_alvo] for i in (0, 1))
            da_amostra, naturais = (" e ".join(dict.fromkeys(valores)) for valores in megas)
            partes.append(
                f"com {NOME_DO_ALVO[nome_do_alvo]}, {da_amostra} MB com a {NOME_DA_PRIORI['amostra']} e {naturais} MB "
                f"com a {NOME_DA_PRIORI['natural']}"
            )
    if not partes:
        return []
    return [
        (
            f"- O tamanho do modelo também muda com a priori, na semente {m['semente']}: {'; '.join(partes)}. Os "
            "valores de cada alvo são os das execuções com 39 e com 33 features."
        ),
    ]


def _decisao_priori(m):
    pares = _pares_de_priori(m)
    if not pares:
        return []
    nomes = [NOME_DA_PRIORI[priori] for priori in PRIORIS]
    colunas = _colunas_da_variacao(m, nomes)
    benigno = [[f"`{a['nome']}`", *_comparar(m, a, n, _benigno_como_ataque)] for a, n in pares]
    ataque = [[f"`{a['nome']}`", *_variacao(m, a, n, _ataque_como_benigno)] for a, n in pares]
    acuracia = [[f"`{a['nome']}`", *_variacao(m, a, n, _global("acuracia"))] for a, n in pares]
    macro = [[f"`{a['nome']}`", *_variacao(m, a, n, _global("macro_f1"))] for a, n in pares]
    por_categoria = []
    for nome_do_alvo in ("8", "7"):
        do_alvo = [(a, n) for a, n in pares if a["alvo"] == nome_do_alvo]
        if not do_alvo:
            continue
        linhas = []
        for classe in ALVOS[nome_do_alvo].classes:
            celulas = [classe]
            for a, n in do_alvo:
                antes, depois = (e["original"]["por_classe"][classe]["recall"] for e in (a, n))
                if antes is None or depois is None:
                    celulas += [_pct(antes), _pct(depois), "sem linhas"]
                else:
                    celulas += [_pct(antes), _pct(depois), _pp(depois - antes)]
            linhas.append(celulas)
        por_categoria += [
            (
                f"Recall reponderado de cada classe nas execuções de {NOME_DO_ALVO[nome_do_alvo]}, na semente "
                f"{m['semente']}:"
            ),
            "",
            *_tabela(
                [
                    "Classe",
                    *(
                        coluna
                        for a, _ in do_alvo
                        for coluna in (
                            f"{a['features']} features, {nomes[0]}", f"{a['features']} features, {nomes[1]}",
                            "Diferença (p.p.)",
                        )
                    ),
                ],
                linhas,
            ),
            "",
        ]
    # As frases de resumo usam os pares de 8 e de 7 categorias, que são os da decisão, em todas as sementes.
    principais = [(a, n) for a, n in pares if a["alvo"] in ("8", "7")] or pares
    da_amostra, naturais = (_de_todas_as_sementes(m, [par[i] for par in principais]) for i in (0, 1))
    onde = f"nas execuções de 8 e de 7 categorias{_nas_sementes(m)}"
    resumo = [
        (
            f"- Com a {nomes[0]}, {_faixa([_benigno_como_ataque(e) for e in da_amostra])} do tráfego benigno de "
            f"teste é classificado como ataque {onde}. Com a {nomes[1]}, "
            f"{_faixa([_benigno_como_ataque(e) for e in naturais])}."
        ),
        (
            "- Nas mesmas execuções, o ataque classificado como benigno, reponderado, é "
            f"{_faixa([_ataque_como_benigno(e, 'original') for e in da_amostra])} com a {nomes[0]} e "
            f"{_faixa([_ataque_como_benigno(e, 'original') for e in naturais])} com a {nomes[1]}."
        ),
    ]
    if all(e["original"]["por_classe"].get("Recon", {}).get("recall") is not None for e in (*da_amostra, *naturais)):
        resumo.append(
            "- O recall reponderado de Recon é "
            f"{_faixa([e['original']['por_classe']['Recon']['recall'] for e in da_amostra])} com a {nomes[0]} e "
            f"{_faixa([e['original']['por_classe']['Recon']['recall'] for e in naturais])} com a {nomes[1]}."
        )
    de_8 = next((n for a, n in pares if a["alvo"] == "8"), None)
    if de_8 is not None:
        resumo.append(_linhas_sorteadas_por_arvore(m, de_8))
    resumo += _tamanho_do_modelo_por_priori(m, pares)
    de_uma_para_outra = f"da {nomes[0]} para a {nomes[1]}"
    return [
        "### Priori de treino",
        "",
        "O que muda das proporções da amostra para a proporção natural no treino, com as features, a divisão e o",
        "alvo fixos. As duas execuções de cada par são avaliadas nas mesmas linhas de teste.",
        "",
        "Tráfego benigno classificado como ataque, como fração das linhas benignas de teste. A medida é igual na",
        "amostra e reponderada:",
        "",
        *_tabela(["Execução", *_colunas_da_comparacao(m, "", [nome.capitalize() for nome in nomes])], benigno),
        "",
        "Ataque classificado como tráfego benigno, como fração das linhas de ataque de teste:",
        "",
        *_tabela(["Execução", *colunas], ataque),
        "",
        "Acurácia:",
        "",
        *_tabela(["Execução", *colunas], acuracia),
        "",
        "Macro-F1:",
        "",
        *_tabela(["Execução", *colunas], macro),
        "",
        *por_categoria,
        (
            "- A taxa de tráfego benigno classificado como ataque e os recalls reponderados dependem da priori de "
            "treino. A reponderação corrige só a avaliação: o modelo treinado com as proporções da amostra continua "
            "com a priori da amostra."
        ),
        *resumo,
        *_resumo_das_diferencas(m, f"Acurácia, {de_uma_para_outra}", pares, _global("acuracia")),
        *_resumo_das_diferencas(m, f"Macro-F1, {de_uma_para_outra}", pares, _global("macro_f1")),
        "- A priori natural usada aqui é a proporção das classes no conjunto completo do dataset. A proporção do",
        "  tráfego de uma rede em operação é outra e não é medida aqui.",
        "- O relatório não recomenda nenhuma das duas. Os dois lados estão nas tabelas acima e, classe a classe, em",
        "  \"Resultados por classe\".",
    ]


def _como_foram_obtidos(m):
    p = m["parametros"]
    return [
        "## Como os números foram obtidos",
        "",
        (
            f"- Comando: `{m['gerado_por']}`, a partir da raiz do repositório. Semente {m['semente']} na divisão e "
            "no modelo"
            + (
                f", e a grade repetida com {_outras_sementes(m)}."
                if m["repeticoes"] else "."
            )
        ),
        (
            f"- Amostra: `{m['amostra']['arquivo']}`, com SHA-256 do CSV descomprimido "
            f"`{m['amostra']['sha256_do_csv_descomprimido']}`, conferido com `manifesto_amostra.json` antes de treinar."
        ),
        (
            f"- Modelo: `RandomForestClassifier` do scikit-learn com os parâmetros padrão, {p['arvores']} árvores, "
            "`n_jobs=-1` e sem `StandardScaler`. Não houve busca de hiperparâmetros."
        ),
        "- Priori de treino: sem pesos nas execuções com as proporções da amostra. Nas de proporção natural, o",
        "  `sample_weight` de cada linha de treino é a contagem do rótulo no conjunto completo dividida pela",
        "  contagem dele no treino, levada à média 1.",
        "- As métricas saem da matriz de confusão de cada execução. As reponderadas usam a matriz que abre a",
        f"  classe real nos 34 rótulos (`{MATRIZES}/*_por_rotulo.csv`) e as contagens do conjunto completo.",
        "- A média macro é sobre as classes do alvo. Os percentuais das tabelas são arredondados, e os valores",
        f"  completos estão em `{MANIFESTO}`.",
        f"- `{METRICAS}` tem uma linha por execução, distribuição e classe. A distribuição `amostra` é a medida",
        "  nas linhas de teste, e `original` é a reponderada.",
        f"- `{METRICAS}`, `{IMPORTANCIAS}` e as matrizes trazem as execuções da semente {m['semente']}. As",
        f"  repetições com as outras sementes estão em `{MANIFESTO}`, com as mesmas medidas.",
        f"- Com a mesma amostra e as mesmas sementes, `{METRICAS}`, `{IMPORTANCIAS}` e as matrizes saem idênticos.",
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
            "Execuções do Random Forest sobre a amostra de treino do CICIoT2023 (Neto et al., 2023). A grade",
            "combina três escolhas que estão em aberto no `ROADMAP.md`: as colunas que dependem do tamanho da",
            "janela, a divisão entre treino e teste e a separação entre DDoS e DoS. As combinações do sorteio",
            "estratificado são treinadas também com a proporção natural das classes, porque a priori de treino muda",
            "os resultados. As execuções de 34 classes e de ataque ou benigno servem de referência para os cenários",
            "do artigo do dataset. O relatório traz os números e não recomenda nenhuma das saídas.",
            *(
                [
                    "",
                    (
                        f"As tabelas são da semente {m['semente']}. A grade e as execuções com a proporção natural "
                        f"foram repetidas com {_outras_sementes(m)}, e as comparações entre escolhas trazem a "
                        "faixa entre sementes."
                    ),
                ]
                if m["repeticoes"] else []
            ),
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
            "estimativa na distribuição original do dataset. As três primeiras subseções usam as execuções",
            "treinadas com as proporções da amostra. A quarta trata da priori de treino, uma escolha de método que",
            "este experimento expôs.",
            *(
                [
                    "",
                    (
                        f"Os valores das tabelas são da semente {m['semente']}. A coluna de faixa e as frases que "
                        f"resumem cada comparação usam as {len(_sementes(m))} sementes (ver \"Como ler os números\")."
                    ),
                ]
                if m["repeticoes"] else []
            ),
            "",
            *_decisao_janela(m),
            "",
            *_decisao_divisao(m),
            "",
            *_decisao_ddos_e_dos(m),
            "",
            *_decisao_priori(m),
        ],
        _como_foram_obtidos(m),
    ]
    return "\n".join("\n".join(secao) + "\n" for secao in secoes).rstrip("\n") + "\n"


def _relatar(resultado):
    print(
        f"{resultado['nome']}, semente {resultado['semente']}: {resultado['arvores']} árvores, treino em "
        f"{_decimal(resultado['treino_segundos'])} s, "
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
    analisador.add_argument("--semente", type=int, default=SEMENTE, help=f"semente principal (padrão: {SEMENTE})")
    analisador.add_argument(
        "--repeticoes", type=int, nargs="*", default=None, metavar="SEMENTE",
        help=(
            "sementes com que a grade é repetida (padrão: "
            f"{' '.join(map(str, REPETICOES))}; sem valores, não repete)"
        ),
    )
    analisador.add_argument("--arvores", type=_positivo, default=ARVORES, help=f"padrão: {ARVORES}")
    analisador.add_argument(
        "--modelos", default=None,
        help="pasta onde guardar os modelos treinados com a semente principal (padrão: não guardar)",
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
            sementes_das_repeticoes = (
                [semente for semente in REPETICOES if semente != argumentos.semente]
                if argumentos.repeticoes is None else argumentos.repeticoes
            )
            if len({argumentos.semente, *sementes_das_repeticoes}) != len(sementes_das_repeticoes) + 1:
                raise ValueError("as sementes das repetições precisam ser diferentes entre si e da semente principal")
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
            repeticoes = []
            for semente in sementes_das_repeticoes:
                # Os modelos das repetições não são guardados: só servem para medir a variação entre sementes.
                repetido = rodar(
                    quadro, populacao, execucoes=(*GRADE, *GRADE_NATURAL), semente=semente,
                    arvores=argumentos.arvores, sha256=sha256, ao_terminar=_relatar,
                )
                repeticoes.append(
                    {"semente": semente, "divisoes": repetido["divisoes"], "execucoes": repetido["execucoes"]}
                )
            manifesto = montar_manifesto(
                registro, populacao, argumentos.amostra, argumentos.manifesto_da_amostra, sha256,
                argumentos.semente, argumentos.arvores, repeticoes,
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
