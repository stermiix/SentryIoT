"""Teste direto do atalho da janela.

O CICIoT2023 agrega os quadros em janelas de 100 nas classes de DDoS, DoS e Mirai e de 10 nas
demais. O treino exploratório mostrou que o modelo separa os dois grupos de janela mesmo sem as
seis colunas que dependem dela. Na operação o extrator usa uma janela só para todo o tráfego.
Este experimento mede o que acontece quando uma captura chega agregada com a janela que o
modelo não viu naquela classe: um flood em janelas de 10, e uma varredura ou uma força bruta em
janelas de 100.

O que ele faz, em um comando:

1. Extração. Cada pcap de `CAPTURAS` é lido inteiro pelo extrator, em leitura contínua, como na
   operação, sem o fatiamento em pedaços de 10 MB dos autores do dataset. Uma vez com janela de
   10 e outra com janela de 100. A janela que o dataset usa na classe da captura é o controle, e
   a outra é o teste.
2. Treino. O Random Forest de 7 categorias, com DDoS e DoS fundidas, na parte de treino do
   sorteio estratificado da amostra. Quatro modelos: 39 ou 33 features, priori da amostra ou
   natural. São as configurações `f39_estratificada_c7`, `f33_estratificada_c7` e as duas
   `_natural` do treino exploratório, com a mesma semente.
3. Pontuação. Para cada captura, janela e modelo, a categoria prevista de cada janela e a
   fração das janelas na categoria esperada. Todas as janelas de uma captura levam o rótulo do
   ataque capturado.
4. Relatório. `teste_da_janela.md`, a tabela `teste_da_janela.csv` e o manifesto
   `manifesto_teste_da_janela.json`, de que os outros dois saem.

O que interessa é quanto a fração muda entre o controle e o teste, mais do que o valor de cada
um: as ressalvas estão no relatório. Ele traz os números e não recomenda nenhuma das saídas em
avaliação.

Com a mesma amostra, os mesmos pcaps e a mesma semente, os números são os mesmos a cada
execução. Só mudam a data e as medidas de tempo. Nenhum modelo fica no disco.

Uso, a partir da raiz do repositório:
    python -m codigo.classificador.janela
    python -m codigo.classificador.janela --nucleos 4 --trabalho pasta/das/extracoes
    python -m codigo.classificador.janela --refazer-relatorio
"""
import argparse
import datetime
import hashlib
import json
import platform
import sys
import tempfile
import time
import warnings
from dataclasses import dataclass
from pathlib import Path

import dpkt
import numpy as np
import pandas as pd
import sklearn

from codigo.captura.extrator import extrair, gravar_csv, ler_pcap
from codigo.classificador.avaliar import avaliar, contar, populacao_do_manifesto
from codigo.classificador.experimento import (
    JANELA_DE_100,
    NOME_DA_PRIORI,
    PRIORIS,
    Execucao,
    _campo,
    _decimal,
    _enumerar,
    _gravar_csv,
    _milhar,
    _pct,
    _pp,
    _tabela,
    pesos_de_treino,
)
from codigo.classificador.mapeamento import CATEGORIA_DO_ROTULO, ROTULOS
from codigo.classificador.preparar import (
    ALVOS,
    CONJUNTOS_DE_FEATURES,
    DEPENDENTES_DA_JANELA,
    FEATURES_39,
    FRACAO_DE_TESTE,
    SEMENTE,
    agrupar,
    alvo,
    carregar,
    dividir,
    impressao_digital,
    matriz,
)
from codigo.classificador.treinar import (
    ARVORES,
    TODOS_OS_NUCLEOS,
    _nucleos,
    _positivo,
    prever,
    treinar,
)

MANIFESTO = "manifesto_teste_da_janela.json"
RELATORIO = "teste_da_janela.md"
TABELA = "teste_da_janela.csv"

# O modelo do teste: 7 categorias, com DDoS e DoS fundidas (decisão de 04/10/2026 no ROADMAP.md),
# treinado na parte de treino do sorteio estratificado.
ALVO = "7"
DIVISAO = "estratificada"
# As duas janelas do dataset. Cada captura é extraída com as duas.
JANELAS = (10, 100)
# O treino exploratório registrou que, sem as seis colunas que dependem da janela, o modelo ainda
# põe ao menos esta fração das linhas de teste no grupo de janela certo. O número é citado na
# pergunta do relatório, e um teste o confere contra o texto versionado de `treino_exploratorio.md`.
SEPARACAO_SEM_AS_SEIS_COLUNAS = 0.998
# Quantos rótulos de treino o relatório mostra para os vetores repetidos na condição de teste.
MAIS_ROTULOS = 3


@dataclass(frozen=True)
class Captura:
    """Um pcap do dataset e o ataque que ele registra."""

    arquivo: str  # nome do pcap dentro da pasta do dataset
    rotulo: str  # o rótulo que o dataset dá a todas as janelas da captura, na grafia canônica

    @property
    def nome(self):
        return Path(self.arquivo).stem

    @property
    def categoria(self):
        return CATEGORIA_DO_ROTULO[self.rotulo]

    @property
    def esperada(self):
        """A categoria em que o modelo acerta a captura."""
        return ALVOS[ALVO].classe_do_rotulo[self.rotulo]

    @property
    def janela_oficial(self):
        """A janela com que o dataset agrega a classe da captura."""
        return 100 if self.categoria in JANELA_DE_100 else 10

    @property
    def janela_de_teste(self):
        return next(janela for janela in JANELAS if janela != self.janela_oficial)

    def condicao(self, janela):
        return "controle" if janela == self.janela_oficial else "teste"


# Os cinco pcaps que a calibração do extrator já usa (`experimentos/resultados/calibracao.md`).
CAPTURAS = (
    Captura("DDoS-HTTP_Flood-.pcap", "DDoS-HTTP_Flood"),
    Captura("DoS-HTTP_Flood1.pcap", "DoS-HTTP_Flood"),
    Captura("Mirai-greip_flood21.pcap", "Mirai-greip_flood"),
    Captura("Recon-PortScan.pcap", "Recon-PortScan"),
    Captura("DictionaryBruteForce.pcap", "DictionaryBruteForce"),
)
MODELOS = tuple(Execucao(features, DIVISAO, ALVO, priori) for features in ("39", "33") for priori in PRIORIS)


# --- extração --------------------------------------------------------------------------------


def resumo_do_arquivo(caminho):
    """Tamanho e SHA-256 de um arquivo, lido aos pedaços."""
    sha256, tamanho = hashlib.sha256(), 0
    with open(caminho, "rb") as arquivo:
        while pedaco := arquivo.read(1 << 20):
            sha256.update(pedaco)
            tamanho += len(pedaco)
    return {"bytes": tamanho, "sha256": sha256.hexdigest()}


def extrair_captura(pcap, janela, destino):
    """Roda o extrator sobre o pcap inteiro, como na operação, e grava o CSV das janelas.

    A leitura é contínua: o arquivo não é fatiado, e só a última janela pode ficar incompleta.
    Devolve o registro da extração: pacotes lidos, quadros IPv4 e ARP que entraram em janela,
    janelas gravadas e os avisos do leitor de pcap.
    """
    pcap, destino = Path(pcap), Path(destino)
    conta = {"pacotes": 0, "quadros": 0, "incompletas": 0}

    def lidos():
        for registro in ler_pcap(pcap):
            conta["pacotes"] += 1
            yield registro

    def linhas():
        for linha in extrair(lidos(), janela):
            conta["quadros"] += linha["Number"]
            conta["incompletas"] += linha["Number"] < janela
            yield linha

    destino.parent.mkdir(parents=True, exist_ok=True)
    inicio = time.perf_counter()
    with warnings.catch_warnings(record=True) as avisos:
        warnings.simplefilter("always")
        try:
            with open(destino, "w", encoding="utf-8", newline="") as saida:
                janelas = gravar_csv(linhas(), saida)
        except ValueError as erro:
            destino.unlink(missing_ok=True)
            raise ValueError(f"{pcap.name}: {erro}") from None
        except OSError:
            destino.unlink(missing_ok=True)
            raise
    return {
        "janela": janela,
        "pacotes": conta["pacotes"],
        "quadros": conta["quadros"],
        "janelas": janelas,
        "janelas_incompletas": conta["incompletas"],
        "segundos": time.perf_counter() - inicio,
        "avisos": [str(aviso.message) for aviso in avisos],
    }


def iguais_ao_treino(X_treino, rotulos_de_treino, X):
    """Quantas linhas de `X` têm o vetor de features de alguma linha de treino, e com que rótulos.

    Devolve o total em `janelas` e, em `por_rotulo`, quantas dessas linhas têm o vetor de uma linha
    de treino de cada rótulo. O mesmo vetor pode ter vários rótulos no treino, e a linha conta uma
    vez em cada um. A comparação é a da divisão por grupos: vetores iguais em 32 bits, com o vazio
    igual ao vazio.
    """
    grupos = agrupar(np.vstack([X_treino, X]))
    do_treino, das_janelas = grupos[:len(X_treino)], grupos[len(X_treino):]
    repetidas = np.isin(das_janelas, do_treino)
    janelas_do_grupo = pd.Series(das_janelas[repetidas]).value_counts()
    pares = pd.DataFrame({"grupo": do_treino, "rotulo": np.asarray(rotulos_de_treino, dtype=object)})
    pares = pares[pares["grupo"].isin(janelas_do_grupo.index)].drop_duplicates()
    por_rotulo = pares["grupo"].map(janelas_do_grupo).groupby(pares["rotulo"]).sum()
    return {
        "janelas": int(repetidas.sum()),
        "por_rotulo": {rotulo: int(por_rotulo[rotulo]) for rotulo in ROTULOS if rotulo in por_rotulo.index},
    }


# --- pontuação -------------------------------------------------------------------------------


def pontuar(modelo, features, quadro, captura):
    """Classifica as janelas de uma captura e conta as categorias previstas.

    `quadro` é a extração da captura, com as 39 colunas e o rótulo dela em `Label`. Devolve a
    quantidade de janelas, a contagem por categoria prevista, na ordem das tabelas, e a fração
    das janelas na categoria esperada.
    """
    previsto = prever(modelo, matriz(quadro, features))
    contagem = contar(quadro["Label"].to_numpy(), previsto, ALVOS[ALVO].classes).sum(axis=0)
    previstas = {classe: int(quantas) for classe, quantas in contagem.items()}
    return {
        "janelas": len(quadro),
        "previstas": previstas,
        "na_esperada": previstas[captura.esperada] / len(quadro),
    }


def rodar(quadro, populacao, dataset, trabalho, capturas=CAPTURAS, modelos=MODELOS, semente=SEMENTE,
          arvores=ARVORES, nucleos=TODOS_OS_NUCLEOS, ao_terminar=None):
    """Extrai as capturas com as duas janelas, treina os modelos e pontua. Devolve o registro.

    `quadro` é a amostra de treino, e `populacao`, as linhas de cada rótulo no conjunto completo,
    para a priori natural. Os CSVs das extrações ficam em `trabalho`. Os modelos são treinados um
    de cada vez e não são gravados. `ao_terminar` recebe uma linha de texto a cada extração e a
    cada modelo concluídos.
    """
    dataset, trabalho = Path(dataset), Path(trabalho)
    ausentes = [captura.arquivo for captura in capturas if not (dataset / captura.arquivo).is_file()]
    if ausentes:
        raise FileNotFoundError(f"pcap ausente em {dataset}: {', '.join(ausentes)}")
    avisar = ao_terminar or (lambda _texto: None)
    comeco = time.perf_counter()
    rotulos = quadro["Label"].to_numpy()
    treino, teste = dividir(quadro, DIVISAO, semente)
    y = alvo(rotulos, ALVO)
    registro = {
        "amostra": {
            "linhas": len(quadro),
            "linhas_de_treino": len(treino),
            "linhas_de_teste": len(teste),
            "sha256_do_teste": impressao_digital(teste),
        },
        "capturas": [],
        "modelos": [],
        "resultados": [],
    }

    # As linhas de treino com as 39 features, para contar as janelas extraídas que as repetem.
    treino_com_39 = matriz(quadro, FEATURES_39)[treino]
    extraidos = {}
    for captura in capturas:
        pcap = dataset / captura.arquivo
        item = {
            "nome": captura.nome,
            "arquivo": captura.arquivo,
            "rotulo": captura.rotulo,
            "categoria": captura.categoria,
            "esperada": captura.esperada,
            "janela_oficial": captura.janela_oficial,
            **resumo_do_arquivo(pcap),
            "extracoes": [],
        }
        for janela in JANELAS:
            arquivo = f"{captura.nome}_janela{janela}.csv"
            extracao = extrair_captura(pcap, janela, trabalho / arquivo)
            # A extração é lida de volta do CSV, como o comando avaliar a leria.
            capturado, sha256 = carregar(trabalho / arquivo, rotulo=captura.rotulo)
            extraidos[captura.nome, janela] = capturado
            repetidas = iguais_ao_treino(treino_com_39, rotulos[treino], matriz(capturado, FEATURES_39))
            item["extracoes"].append({
                "janela": janela,
                "condicao": captura.condicao(janela),
                **{chave: valor for chave, valor in extracao.items() if chave != "janela"},
                "csv": arquivo,
                "sha256_do_csv": sha256,
                # Janelas com as 39 features de uma linha de treino: quantas, quantas delas de uma linha
                # com o rótulo da captura, e os rótulos que o treino dá a esses vetores.
                "iguais_a_linha_de_treino": repetidas["janelas"],
                "iguais_a_linha_de_treino_do_mesmo_rotulo": repetidas["por_rotulo"].get(captura.rotulo, 0),
                "iguais_por_rotulo_de_treino": repetidas["por_rotulo"],
            })
            avisar(
                f"{captura.arquivo}, janela de {janela}: {_milhar(extracao['janelas'])} janelas em "
                f"{_decimal(extracao['segundos'])} s"
            )
        registro["capturas"].append(item)
    del treino_com_39
    extracao_segundos = time.perf_counter() - comeco

    treino_segundos = pontuacao_segundos = 0.0
    for execucao in modelos:
        features = CONJUNTOS_DE_FEATURES[execucao.features]
        X = matriz(quadro, features)
        pesos = pesos_de_treino(rotulos[treino], populacao) if execucao.priori == "natural" else None
        modelo, segundos_de_treino = treinar(X[treino], y[treino], semente, arvores, pesos, nucleos)
        inicio = time.perf_counter()
        # As medidas na parte de teste da amostra ligam o modelo ao do treino exploratório.
        no_teste = avaliar(prever(modelo, X[teste]), rotulos[teste], ALVO)["amostra"]
        del X
        for captura in capturas:
            for janela in JANELAS:
                registro["resultados"].append({
                    "captura": captura.nome,
                    "janela": janela,
                    "condicao": captura.condicao(janela),
                    "modelo": execucao.nome,
                    **pontuar(modelo, features, extraidos[captura.nome, janela], captura),
                })
        segundos_de_pontuacao = time.perf_counter() - inicio
        registro["modelos"].append({
            "nome": execucao.nome,
            "features": execucao.features,
            "priori": execucao.priori,
            "arvores": arvores,
            "linhas_de_treino": len(treino),
            "nos_por_arvore": float(np.mean([arvore.tree_.node_count for arvore in modelo.estimators_])),
            "no_teste_da_amostra": {
                "acuracia": no_teste["acuracia"],
                "recall": {classe: medida["recall"] for classe, medida in no_teste["por_classe"].items()},
            },
            "treino_segundos": segundos_de_treino,
            "pontuacao_segundos": segundos_de_pontuacao,
        })
        del modelo
        treino_segundos += segundos_de_treino
        pontuacao_segundos += segundos_de_pontuacao
        avisar(
            f"{execucao.nome}: treino em {_decimal(segundos_de_treino)} s e pontuação em "
            f"{_decimal(segundos_de_pontuacao)} s"
        )
    registro["duracao"] = {
        "extracao_segundos": extracao_segundos,
        "treino_segundos": treino_segundos,
        "pontuacao_segundos": pontuacao_segundos,
        "total_segundos": time.perf_counter() - comeco,
    }
    return registro


def montar_manifesto(registro, amostra, manifesto_da_amostra, sha256, dataset, semente, arvores, nucleos):
    """O registro do experimento: o que é preciso para refazê-lo e todos os números que ele produziu."""
    return {
        "descricao": (
            "Teste direto do atalho da janela: capturas do CICIoT2023 agregadas em janelas de 10 e de 100 "
            "quadros e pontuadas pelo Random Forest de 7 categorias"
        ),
        "gerado_por": "python -m codigo.classificador.janela",
        "gerado_em": datetime.datetime.now(tz=datetime.UTC).astimezone().strftime("%Y-%m-%d"),
        "semente": semente,
        "parametros": {
            "modelo": "sklearn.ensemble.RandomForestClassifier",
            "arvores": arvores,
            "n_jobs": nucleos,
            "demais_parametros": "padrão do scikit-learn",
            "escalonamento": "nenhum",
            "alvo": ALVO,
            "divisao": DIVISAO,
            "fracao_de_teste": FRACAO_DE_TESTE,
            "janelas": list(JANELAS),
            "extracao": "codigo.captura.extrator.extrair sobre o arquivo inteiro, em leitura contínua",
            "predicao": "votos somados em ordem fixa, com um núcleo",
        },
        "versoes": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit-learn": sklearn.__version__,
            "dpkt": dpkt.__version__,
        },
        "amostra": {
            "arquivo": Path(amostra).as_posix(),
            "manifesto": Path(manifesto_da_amostra).as_posix(),
            "sha256_do_csv_descomprimido": sha256,
            **registro["amostra"],
        },
        "dataset": Path(dataset).as_posix(),
        "classes": list(ALVOS[ALVO].classes),
        "capturas": registro["capturas"],
        "modelos": registro["modelos"],
        "resultados": registro["resultados"],
        "duracao": registro["duracao"],
    }


def gravar(manifesto, pasta):
    """Grava o manifesto e o que sai dele: o relatório e a tabela."""
    pasta = Path(pasta)
    pasta.mkdir(parents=True, exist_ok=True)
    (pasta / MANIFESTO).write_text(json.dumps(manifesto, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (pasta / RELATORIO).write_text(montar_relatorio(manifesto), encoding="utf-8")
    capturas = {captura["nome"]: captura for captura in manifesto["capturas"]}
    modelos = {modelo["nome"]: modelo for modelo in manifesto["modelos"]}
    _gravar_csv(
        pasta / TABELA,
        ["captura", "rotulo", "categoria_esperada", "janela", "janela_oficial", "condicao", "modelo", "features",
         "priori", "categoria_prevista", "e_a_esperada", "janelas_previstas", "janelas_da_captura", "fracao"],
        [
            [
                resultado["captura"], capturas[resultado["captura"]]["rotulo"],
                capturas[resultado["captura"]]["esperada"], resultado["janela"],
                capturas[resultado["captura"]]["janela_oficial"], resultado["condicao"], resultado["modelo"],
                modelos[resultado["modelo"]]["features"], modelos[resultado["modelo"]]["priori"], classe,
                int(classe == capturas[resultado["captura"]]["esperada"]), quantas, resultado["janelas"],
                _campo(quantas / resultado["janelas"]),
            ]
            for resultado in manifesto["resultados"]
            for classe, quantas in resultado["previstas"].items()
        ],
    )


# --- relatório -------------------------------------------------------------------------------


def _coluna(modelo):
    """O nome de um modelo no cabeçalho das tabelas."""
    return f"{modelo['features']} features, {NOME_DA_PRIORI[modelo['priori']]}"


def _resultado(m, captura, janela, modelo):
    return next(
        resultado for resultado in m["resultados"]
        if (resultado["captura"], resultado["janela"], resultado["modelo"]) == (captura["nome"], janela, modelo["nome"])
    )


def _fracoes(m, captura, janela, modelos=None):
    """A fração na categoria esperada, de cada modelo, para a captura agregada com a janela dada."""
    return [_resultado(m, captura, janela, modelo)["na_esperada"] for modelo in (modelos or m["modelos"])]


def _janela_de_teste(captura):
    return next(janela for janela in JANELAS if janela != captura["janela_oficial"])


def _extracao(captura, janela):
    return next(extracao for extracao in captura["extracoes"] if extracao["janela"] == janela)


def _de_a(valores, casas=2):
    """O menor e o maior de uma lista de frações: "1,00% a 2,00%", ou o valor só, se os dois coincidem."""
    menor, maior = _pct(min(valores), casas), _pct(max(valores), casas)
    return menor if menor == maior else f"{menor} a {maior}"


def _pp_de_a(diferencas):
    """O mesmo para diferenças em pontos percentuais, com sinal. O texto termina no ponto da abreviatura."""
    menor, maior = _pp(min(diferencas)), _pp(max(diferencas))
    return f"{menor} p.p." if menor == maior else f"de {menor} a {maior} p.p."


def _conforme_o_modelo(valores):
    """Complemento de frase para uma faixa: só faz sentido quando os modelos dão valores diferentes."""
    return " conforme o modelo" if _pct(min(valores)) != _pct(max(valores)) else ""


def _por_features(m):
    """Os modelos do teste reunidos pelo conjunto de features: os de cada grupo diferem pela priori de treino."""
    grupos = {}
    for modelo in m["modelos"]:
        grupos.setdefault(modelo["features"], []).append(modelo)
    return grupos


def _mais_prevista(m, captura, janela, modelos):
    """A categoria mais prevista para a captura nos modelos dados, em texto, com a fração das janelas."""
    por_classe = {}
    for modelo in modelos:
        resultado = _resultado(m, captura, janela, modelo)
        # No empate fica a primeira na ordem das tabelas.
        classe = max(resultado["previstas"], key=lambda nome: resultado["previstas"][nome])
        por_classe.setdefault(classe, []).append(resultado["previstas"][classe] / resultado["janelas"])
    return " ou ".join(f"{classe} ({_de_a(fracoes)} das janelas)" for classe, fracoes in por_classe.items())


def _ataques_sem_captura(m):
    """As categorias de ataque de que nenhuma captura do teste é exemplo."""
    esperadas = {captura["esperada"] for captura in m["capturas"]}
    return [classe for classe in m["classes"] if classe not in esperadas and classe != ALVOS[ALVO].benigno]


def _cabecalho(m):
    v = m["versoes"]
    data = datetime.date.fromisoformat(m["gerado_em"]).strftime("%d/%m/%Y")
    return [
        "# Teste direto do atalho da janela",
        "",
        (
            f"Gerado por `{m['gerado_por']}` em {data}, com Python {v['python']}, scikit-learn "
            f"{v['scikit-learn']}, pandas {v['pandas']}, numpy {v['numpy']} e dpkt {v['dpkt']}."
        ),
    ]


def _pergunta(m):
    return [
        "## A pergunta",
        "",
        "O CICIoT2023 (Neto et al., 2023) agrega os quadros em janelas de 100 nas classes de DDoS, DoS e Mirai",
        "e de 10 nas demais. O treino exploratório mostrou que, mesmo sem as seis colunas que dependem da",
        (
            f"janela, o modelo ainda põe mais de {_pct(SEPARACAO_SEM_AS_SEIS_COLUNAS, 1)} das linhas de teste "
            "no grupo de janela certo"
        ),
        "(`treino_exploratorio.md`). Na operação o extrator usa uma janela só para todo o tráfego. A pergunta",
        "deste teste é o que acontece com uma captura agregada com a janela que o modelo não viu naquela",
        "classe:",
        "",
        "- o modelo reconhece um flood agregado em janelas de 10?",
        "- o modelo reconhece uma varredura ou uma força bruta agregadas em janelas de 100?",
    ]


def _experimento(m):
    p, amostra, modelos = m["parametros"], m["amostra"], m["modelos"]
    medidas = [classe for classe in m["classes"] if classe in {captura["esperada"] for captura in m["capturas"]}]
    return [
        "## O experimento",
        "",
        (
            f"**Modelos.** Random Forest de 7 categorias, com DDoS e DoS fundidas, treinado nas "
            f"{_milhar(amostra['linhas_de_treino'])} linhas de treino do sorteio estratificado da amostra, com semente "
            f"{m['semente']} e {p['arvores']} árvores. São {len(modelos)} modelos: com as 39 features ou com 33, sem as "
            f"seis colunas que dependem da janela ({_enumerar(f'`{coluna}`' for coluna in DEPENDENTES_DA_JANELA)}), e com "
            "a priori da amostra ou a natural. São as mesmas configurações do treino exploratório. A tabela traz as "
            "medidas de cada modelo na parte de teste da amostra, para comparar com as daquele relatório."
        ),
        "",
        *_tabela(
            ["Modelo", "Features", "Priori de treino", "Acurácia no teste da amostra",
             *(f"Recall de {classe} no teste da amostra" for classe in medidas)],
            [
                [
                    f"`{modelo['nome']}`", modelo["features"], NOME_DA_PRIORI[modelo["priori"]].removeprefix("priori "),
                    _pct(modelo["no_teste_da_amostra"]["acuracia"]),
                    *(_pct(modelo["no_teste_da_amostra"]["recall"][classe]) for classe in medidas),
                ]
                for modelo in modelos
            ],
        ),
        "",
        (
            f"**Capturas.** {len(m['capturas'])} pcaps do dataset, os mesmos da calibração do extrator. Cada um foi "
            "lido inteiro pelo extrator (`codigo/captura/extrator.py`), em leitura contínua, como na operação, sem o "
            "fatiamento em pedaços de 10 MB com que os autores geraram os CSVs oficiais. Cada pcap foi extraído duas "
            "vezes, com janela de 10 e com janela de 100."
        ),
        "",
        *_tabela(
            ["Captura", "Rótulo", "Categoria esperada", "Janela do dataset", "Tamanho (MB)", "Pacotes",
             "Quadros IPv4 e ARP", "Janelas de 10", "Janelas de 100"],
            [
                [
                    f"`{captura['arquivo']}`", f"`{captura['rotulo']}`", captura["esperada"], captura["janela_oficial"],
                    _decimal(captura["bytes"] / 1e6), _milhar(_extracao(captura, 10)["pacotes"]),
                    _milhar(_extracao(captura, 10)["quadros"]), _milhar(_extracao(captura, 10)["janelas"]),
                    _milhar(_extracao(captura, 100)["janelas"]),
                ]
                for captura in m["capturas"]
            ],
        ),
        "",
        "**Condições.** A janela com que o dataset agrega a classe da captura é o **controle**. A outra é o",
        "**teste**: janela de 10 nas três capturas de flood, e de 100 na de varredura e na de força bruta.",
        "",
        "**Medida.** Para cada captura, janela e modelo, a categoria prevista de cada janela e a fração das",
        "janelas na categoria esperada. Todas as janelas de uma captura levam o rótulo do ataque capturado. O que",
        "interessa é quanto a fração muda do controle para o teste, mais do que o valor de cada um.",
    ]


def _ressalvas(m):
    def repetidas(captura, janela):
        extracao = _extracao(captura, janela)
        return [
            (
                f"{_milhar(extracao['iguais_a_linha_de_treino'])} de {_milhar(extracao['janelas'])} "
                f"({_pct(extracao['iguais_a_linha_de_treino'] / extracao['janelas'])})"
            ),
            _milhar(extracao["iguais_a_linha_de_treino_do_mesmo_rotulo"]),
        ]

    def rotulos_no_teste(captura):
        """Os rótulos que o treino dá aos vetores repetidos no teste, dos mais frequentes para os menos."""
        extracao = _extracao(captura, _janela_de_teste(captura))
        por_rotulo = sorted(extracao["iguais_por_rotulo_de_treino"].items(), key=lambda par: -par[1])
        if not por_rotulo:
            return None
        mostrados = [
            f"`{rotulo}` ({_milhar(quantas)} {'janela' if quantas == 1 else 'janelas'})"
            for rotulo, quantas in por_rotulo[:MAIS_ROTULOS]
        ]
        resto = len(por_rotulo) - MAIS_ROTULOS
        if resto > 0:
            mostrados.append(f"mais {resto} {'rótulo' if resto == 1 else 'rótulos'}")
        return f"- `{captura['arquivo']}`, janela de {extracao['janela']}: {_enumerar(mostrados)}."

    de_outros = [linha for linha in map(rotulos_no_teste, m["capturas"]) if linha is not None]

    esperadas = {captura["esperada"] for captura in m["capturas"]}
    sem_captura = _ataques_sem_captura(m)
    por_categoria = [
        f"{sum(captura['esperada'] == classe for captura in m['capturas'])} de {classe}"
        for classe in m["classes"] if classe in esperadas
    ]
    return [
        "## Ressalvas",
        "",
        "Valem para todas as tabelas, e por isso vêm antes dos números.",
        "",
        "**1. O controle contém dados parecidos com os de treino.** As linhas oficiais destes pcaps fazem parte",
        "do dataset de onde saiu a amostra de treino. A extração contínua do controle não é o CSV oficial, porque",
        "sem o fatiamento as janelas se alinham de outra forma depois do primeiro pedaço, mas parte das janelas",
        "sai igual. A tabela conta as janelas com as 39 features idênticas às de uma linha de treino, em 32 bits,",
        "e quantas delas repetem uma linha de treino do mesmo rótulo da captura. Por isso o valor do controle não",
        "é uma medida em dado novo. O teste é a outra janela.",
        "",
        *_tabela(
            ["Captura", "Controle: idênticas a uma linha de treino", "das quais, do mesmo rótulo",
             "Teste: idênticas a uma linha de treino", "das quais, do mesmo rótulo"],
            [
                [
                    f"`{captura['arquivo']}`", *repetidas(captura, captura["janela_oficial"]),
                    *repetidas(captura, _janela_de_teste(captura)),
                ]
                for captura in m["capturas"]
            ],
        ),
        *(
            [
                "",
                "Os rótulos que a amostra de treino dá aos vetores que se repetem na condição de teste. A janela conta",
                "uma vez em cada rótulo que o vetor dela tem no treino:",
                "",
                *de_outros,
            ]
            if de_outros else []
        ),
        "",
        "**2. O rótulo é da captura, e não da janela.** Todas as janelas de um pcap levam o rótulo do ataque, mas",
        "as janelas juntam quadros seguidos de todos os dispositivos da rede, e parte delas pode conter só tráfego de",
        "fundo de outros dispositivos. É uma hipótese levantada na revisão e registrada no `ROADMAP.md`, ainda sem",
        "medida versionada. Por isso o valor absoluto do controle não é 100%, e a leitura é pela diferença entre as",
        "duas janelas da mesma captura.",
        "",
        (
            f"**3. São {len(m['capturas'])} capturas.** Uma ou duas por categoria: {_enumerar(por_categoria)}. Não há "
            f"captura de tráfego benigno{''.join(f', nem de {classe}' for classe in sem_captura)}. Este teste não é "
            "uma avaliação das 34 classes, e nada nele mede o alarme falso sobre tráfego benigno."
        ),
        "",
        (
            f"**4. Uma semente.** Os modelos são os da semente {m['semente']}. O teste não foi repetido com outras "
            "sementes, e por isso não diz quanto de uma diferença pequena é ruído."
        ),
        "",
        "**5. O relatório não recomenda uma saída.** Ele entrega os números e diz, para cada saída em avaliação, o",
        "que ela ganharia ou perderia segundo eles.",
    ]


def _tabela_principal(m):
    modelos = m["modelos"]
    linhas = []
    for captura in m["capturas"]:
        for janela in (captura["janela_oficial"], _janela_de_teste(captura)):
            condicao = "controle" if janela == captura["janela_oficial"] else "teste"
            linhas.append([
                f"`{captura['arquivo']}`", captura["esperada"], janela, condicao,
                _milhar(_extracao(captura, janela)["janelas"]),
                *(_pct(fracao) for fracao in _fracoes(m, captura, janela)),
            ])
    diferencas = []
    for captura in m["capturas"]:
        controle = _fracoes(m, captura, captura["janela_oficial"])
        teste = _fracoes(m, captura, _janela_de_teste(captura))
        diferencas.append([
            f"`{captura['arquivo']}`", f"de {captura['janela_oficial']} para {_janela_de_teste(captura)}",
            *(_pp(depois - antes) for antes, depois in zip(controle, teste)),
        ])
    return [
        "## Tabela principal",
        "",
        "Fração das janelas de cada captura que o modelo põe na categoria esperada. Em cada captura, a primeira",
        "linha é o controle e a segunda é o teste.",
        "",
        *_tabela(
            ["Captura", "Categoria esperada", "Janela", "Condição", "Janelas", *(_coluna(modelo) for modelo in modelos)],
            linhas,
        ),
        "",
        "### Quanto muda",
        "",
        "A fração do teste menos a do controle, em pontos percentuais.",
        "",
        *_tabela(["Captura", "Janela", *(_coluna(modelo) for modelo in modelos)], diferencas),
    ]


def _distribuicao(m):
    linhas = [
        "## Para onde vão as janelas",
        "",
        "A distribuição das categorias previstas, como fração das janelas de cada captura. Uma tabela por modelo.",
    ]
    for modelo in m["modelos"]:
        corpo = []
        for captura in m["capturas"]:
            for janela in (captura["janela_oficial"], _janela_de_teste(captura)):
                resultado = _resultado(m, captura, janela, modelo)
                corpo.append([
                    f"`{captura['arquivo']}`", janela, resultado["condicao"],
                    *(_pct(resultado["previstas"][classe] / resultado["janelas"]) for classe in m["classes"]),
                ])
        linhas += [
            "",
            f"### `{modelo['nome']}`: {_coluna(modelo)}",
            "",
            *_tabela(["Captura", "Janela", "Condição", *m["classes"]], corpo),
        ]
    return linhas


def _no_controle(m, captura):
    fracoes = _fracoes(m, captura, captura["janela_oficial"])
    return (
        f"`{captura['arquivo']}`, com {_de_a(fracoes)} das janelas em {captura['esperada']}"
        f"{_conforme_o_modelo(fracoes)}"
    )


def _no_teste(m, captura):
    """O que acontece com a captura na outra janela, separado pelas features do modelo."""
    oficial, outra = captura["janela_oficial"], _janela_de_teste(captura)
    fracoes, destinos = [], []
    for features, modelos in _por_features(m).items():
        controle, teste = _fracoes(m, captura, oficial, modelos), _fracoes(m, captura, outra, modelos)
        diferencas = [depois - antes for antes, depois in zip(controle, teste)]
        fracoes.append(f"{_de_a(teste)} com as {features} features (diferença {_pp_de_a(diferencas)})")
        destinos.append(f"{_mais_prevista(m, captura, outra, modelos)} com as {features} features")
    return (
        f"  - `{captura['arquivo']}`: com a janela de {oficial}, {_de_a(_fracoes(m, captura, oficial))} das janelas "
        f"ficam em {captura['esperada']}. Com a de {outra}, {' e '.join(fracoes)}. A categoria mais prevista com a "
        f"janela de {outra} é {' e '.join(destinos)}."
    )


def _saida_de_janela_unica(m, janela):
    """O que os números dizem sobre usar na operação uma janela só, do tamanho dado."""
    no_controle = [captura for captura in m["capturas"] if captura["janela_oficial"] == janela]
    no_teste = [captura for captura in m["capturas"] if captura["janela_oficial"] != janela]
    outra = next(tamanho for tamanho in JANELAS if tamanho != janela)
    sem_captura = _ataques_sem_captura(m)
    fora = "o tráfego benigno" + (
        f" e as categorias de ataque sem captura ({_enumerar(sem_captura)})" if sem_captura else ""
    )
    linhas = [
        f"### Janela única de {janela} na operação",
        "",
        (
            f"Com o extrator fixo em {janela}, as classes que o dataset agrega em {janela} chegam ao modelo como no "
            f"treino, e as que ele agrega em {outra} chegam na condição de teste."
        ),
        "",
    ]
    if no_controle:
        linhas.append(f"- Ficam no controle: {'; '.join(_no_controle(m, captura) for captura in no_controle)}.")
    if no_teste:
        linhas.append("- Passam à condição de teste:")
        linhas += [_no_teste(m, captura) for captura in no_teste]
    if janela == 100 and no_teste:
        contagens = [
            f"`{captura['arquivo']}` dá {_milhar(_extracao(captura, 100)['janelas'])} janelas de 100, contra "
            f"{_milhar(_extracao(captura, 10)['janelas'])} de 10"
            for captura in no_teste
        ]
        linhas.append(
            f"- Uma janela de 100 leva dez vezes mais quadros para fechar: {'; '.join(contagens)}."
        )
    if janela == 10:
        linhas.append(
            f"- Fora desta medida: {fora}, que o dataset já agrega em 10. Para eles continuam valendo as medidas do "
            "treino exploratório."
        )
    else:
        linhas.append(
            f"- Fora desta medida: {fora}, agregados em 100. Nenhum dos pcaps é dessas classes, e o alarme falso sobre "
            "tráfego benigno em janelas de 100 fica sem número."
        )
    return linhas


def _descompasso(m, captura):
    """A faixa, entre os modelos, da diferença do controle para o teste na captura."""
    controle = _fracoes(m, captura, captura["janela_oficial"])
    teste = _fracoes(m, captura, _janela_de_teste(captura))
    return (
        f"`{captura['arquivo']}`, agregado em {_janela_de_teste(captura)}, "
        f"{_pp_de_a([depois - antes for antes, depois in zip(controle, teste)])}"
    )


def _leitura(m):
    # Captura por captura: uma faixa só juntaria capturas em que a diferença é quase total e capturas em que
    # ela é quase nula.
    medido = [_descompasso(m, captura) for captura in m["capturas"]]
    do_mesmo_rotulo = [
        _extracao(captura, captura["janela_oficial"])["iguais_a_linha_de_treino_do_mesmo_rotulo"]
        / _extracao(captura, captura["janela_oficial"])["janelas"]
        for captura in m["capturas"]
    ]
    grupos = _por_features(m)
    de_10 = [captura for captura in m["capturas"] if captura["janela_oficial"] == 10]
    um_decimo = [
        f"`{captura['arquivo']}` passa de {_milhar(_extracao(captura, 10)['janelas'])} linhas para "
        f"{_milhar(_extracao(captura, 100)['janelas'])}"
        for captura in de_10
    ]
    total = sum(captura["bytes"] for captura in m["capturas"])
    return [
        "## O que os números dizem sobre cada saída em avaliação",
        "",
        "Só o que cada saída ganharia ou perderia segundo as tabelas acima. As faixas vão do menor ao maior valor",
        (
            f"entre os modelos: os {len(m['modelos'])} no controle e, no teste, os de cada conjunto de features "
            f"({_enumerar(f'{len(modelos)} com {features}' for features, modelos in grupos.items())}), que diferem pela "
            "priori de treino. As ressalvas do começo valem para tudo o que segue."
        ),
        "",
        *_saida_de_janela_unica(m, 10),
        "",
        *_saida_de_janela_unica(m, 100),
        "",
        "### Janelas regeradas dos pcaps",
        "",
        "Nesta saída o treino muda: as janelas de todas as classes seriam geradas de novo, a partir dos pcaps, com",
        "um tamanho só, e treino e operação passariam a usar a mesma janela.",
        "",
        (
            "- Este teste não treina com janelas regeradas, e por isso não mede o que a saída entregaria. Ele mede o "
            "descompasso que ela teria de fechar, que é a diferença do controle para o teste, aqui na faixa entre os "
            f"{len(m['modelos'])} modelos: {'; '.join(medido)}"
        ),
        (
            f"- O extrator leu os {len(m['capturas'])} pcaps inteiros com as duas janelas, em "
            f"{_decimal(m['duracao']['extracao_segundos'])} s no total, e as extrações são as que a regeração usaria "
            "para estas capturas."
        ),
        *(
            [
                (
                    "- Com janela de 100, as classes hoje agregadas em 10 ficam com cerca de um décimo das linhas: "
                    f"{'; '.join(um_decimo)}."
                ),
            ]
            if um_decimo else []
        ),
        (
            f"- A regeração depende de ter o pcap de cada classe. Aqui são {len(m['capturas'])} pcaps, de 34 classes, "
            f"com {_decimal(total / 1e9)} GB somados."
        ),
        "- Fora desta medida: o desempenho de um modelo treinado com janelas regeradas, com qualquer das duas janelas.",
        "",
        "### Limitação declarada",
        "",
        "Nesta saída o treino e a extração ficam como estão, e o artigo declara o descompasso.",
        "",
        (
            f"- O que haveria a declarar é o que este teste mediu. Da janela do dataset para a outra, a fração das "
            f"janelas na categoria esperada muda, na faixa entre os {len(m['modelos'])} modelos: {'; '.join(medido)}"
        ),
        (
            f"- A declaração teria de trazer também os limites da medida: {len(m['capturas'])} capturas, uma semente e"
            + (
                f" um controle em que {_de_a(do_mesmo_rotulo)} das janelas, conforme a captura, repetem uma linha de "
                "treino do mesmo rótulo."
                if any(do_mesmo_rotulo) else " um controle tirado do mesmo dataset da amostra de treino."
            )
        ),
        "- A saída não mexe no treino nem na extração: o descompasso medido nestas capturas fica como está.",
        "",
        "O relatório não recomenda nenhuma das saídas.",
    ]


def _como_foram_obtidos(m):
    p, d = m["parametros"], m["duracao"]
    if p["n_jobs"] == TODOS_OS_NUCLEOS:
        nucleos = "todos os núcleos"
    else:
        nucleos = "1 núcleo" if p["n_jobs"] == 1 else f"{p['n_jobs']} núcleos"
    avisos = [
        f"`{captura['arquivo']}`, janela de {extracao['janela']}: {aviso}"
        for captura in m["capturas"] for extracao in captura["extracoes"] for aviso in extracao["avisos"]
    ]
    incompletas = sum(extracao["janelas_incompletas"] for captura in m["capturas"] for extracao in captura["extracoes"])
    extracoes = sum(len(captura["extracoes"]) for captura in m["capturas"])
    return [
        "## Como os números foram obtidos",
        "",
        (
            f"- Comando: `{m['gerado_por']}`, a partir da raiz do repositório. Ele refaz a extração, o treino, a "
            f"pontuação e este relatório. Semente {m['semente']} na divisão e nos modelos."
        ),
        (
            f"- Amostra: `{m['amostra']['arquivo']}`, com SHA-256 do CSV descomprimido "
            f"`{m['amostra']['sha256_do_csv_descomprimido']}`, conferido com `manifesto_amostra.json` antes de treinar."
        ),
        (
            f"- Modelos: `RandomForestClassifier` do scikit-learn com os parâmetros padrão, {p['arvores']} árvores e "
            f"sem `StandardScaler`, treinados com {nucleos}. A quantidade de núcleos muda o tempo, e não o modelo. Na "
            "priori natural, o `sample_weight` de cada linha de treino é a contagem do rótulo no conjunto completo "
            "dividida pela contagem dele no treino, como no treino exploratório."
        ),
        "- Predição: votos das árvores somados em ordem fixa, com um núcleo, para a mesma entrada dar sempre a",
        "  mesma resposta.",
        (
            f"- Extração: `codigo.captura.extrator.extrair` sobre o arquivo inteiro. Das {extracoes} extrações, "
            f"{incompletas} terminam em uma janela incompleta, a última do arquivo, que entra na conta como as outras."
        ),
        *([f"- Avisos do leitor de pcap: {'; '.join(avisos)}."] if avisos else []),
        "- Pcaps, com o tamanho e o SHA-256 de cada um:",
        *(
            f"  - `{captura['arquivo']}`: {_milhar(captura['bytes'])} bytes, `{captura['sha256']}`"
            for captura in m["capturas"]
        ),
        (
            f"- Tempo, na máquina em que rodou: {_decimal(d['extracao_segundos'])} s de extração, "
            f"{_decimal(d['treino_segundos'])} s de treino e {_decimal(d['pontuacao_segundos'])} s de pontuação, "
            f"em {_decimal(d['total_segundos'])} s no total."
        ),
        (
            f"- `{TABELA}` tem uma linha por captura, janela, modelo e categoria prevista. `{MANIFESTO}` traz os "
            "mesmos números, as contagens de cada extração e as medidas de cada modelo na parte de teste da amostra."
        ),
        "- Com a mesma amostra, os mesmos pcaps e a mesma semente, a tabela sai idêntica. Só mudam a data e os tempos.",
        "- Conferência por outro caminho: extrair uma captura com `python -m codigo.captura.extrator --janela N`,",
        "  treinar o modelo com `python -m codigo.classificador.treinar --alvo 7` e pontuar com",
        "  `python -m codigo.classificador.avaliar MODELO --csv CAPTURA.csv --rotulo ROTULO`. O recall da categoria",
        "  esperada é a fração da tabela principal.",
    ]


def montar_relatorio(m):
    """Monta o relatório do teste em Markdown, a partir do manifesto."""
    secoes = [
        _cabecalho(m), _pergunta(m), _experimento(m), _ressalvas(m), _tabela_principal(m), _distribuicao(m),
        _leitura(m), _como_foram_obtidos(m),
    ]
    return "\n".join("\n".join(secao) + "\n" for secao in secoes).rstrip("\n") + "\n"


# --- comando ---------------------------------------------------------------------------------


def _relatar(texto):
    print(texto, file=sys.stderr)


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.classificador.janela",
        description=(
            "Teste direto do atalho da janela: extrai os pcaps com janela de 10 e de 100, treina os modelos de 7 "
            "categorias, pontua e grava o relatório."
        ),
        allow_abbrev=False,
    )
    analisador.add_argument("--amostra", default="dados/processed/amostra.csv.gz")
    analisador.add_argument("--manifesto-da-amostra", default="experimentos/resultados/manifesto_amostra.json")
    analisador.add_argument("--dataset", default="CICIoT2023", help="pasta com os pcaps (padrão: CICIoT2023)")
    analisador.add_argument("--saida", default="experimentos/resultados", help="pasta dos resultados")
    analisador.add_argument(
        "--trabalho", default=None,
        help="pasta onde guardar os CSVs das extrações (padrão: pasta provisória, apagada no fim)",
    )
    analisador.add_argument("--semente", type=int, default=SEMENTE, help=f"padrão: {SEMENTE}")
    analisador.add_argument("--arvores", type=_positivo, default=ARVORES, help=f"padrão: {ARVORES}")
    analisador.add_argument(
        "--nucleos", type=_nucleos, default=TODOS_OS_NUCLEOS,
        help=f"núcleos usados no treino (padrão: {TODOS_OS_NUCLEOS}, todos). Os números são os mesmos com qualquer valor",
    )
    analisador.add_argument(
        "--refazer-relatorio", action="store_true",
        help="não extrai nem treina: refaz o relatório e a tabela a partir do manifesto do teste",
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
            with tempfile.TemporaryDirectory() as provisoria:
                registro = rodar(
                    quadro, populacao, argumentos.dataset, argumentos.trabalho or provisoria,
                    semente=argumentos.semente, arvores=argumentos.arvores, nucleos=argumentos.nucleos,
                    ao_terminar=_relatar,
                )
            manifesto = montar_manifesto(
                registro, argumentos.amostra, argumentos.manifesto_da_amostra, sha256, argumentos.dataset,
                argumentos.semente, argumentos.arvores, argumentos.nucleos,
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
