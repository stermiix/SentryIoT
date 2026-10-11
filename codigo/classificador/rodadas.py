"""Rodadas de teste do modelo de janela de 100 e comparação de capturas normalizadas.

O modelo do sistema é o Random Forest de 7 categorias treinado por `treinar_regerado` nos dados
regerados com janela de 100 quadros. O relatório dele (`regeracao.md`) mede uma divisão por tempo,
com uma semente e só nas janelas que têm o atacante. Este módulo refaz o treino com as mesmas
funções e mede o que aquela divisão não mostra, em rodadas:

a. reprodução: o modelo retreinado com a semente 42 dá as mesmas predições do modelo salvo;
b. sementes: o mesmo treino com cinco sementes, que mudam o teto e o Random Forest juntos;
c. rotação: nos rótulos com mais de um pcap, cada pcap fica inteiro fora do treino uma vez;
d. tráfego de fundo: o modelo nas janelas descartadas dos pcaps de ataque, sem nenhum quadro do
   atacante, separadas em parte de treino e parte de teste pelo mesmo corte por tempo;
e. pcap fora do treino: o recall de cada pcap quando nenhuma janela dele entra no treino;
f. atalhos da captura: quadros abaixo de 60 e acima de 1.514 bytes, o TTL e a importância por
   permutação;
g. ponto de operação: o limiar sobre a probabilidade de benigno e a regra de N janelas seguidas;
h. intervalos de confiança das classes raras, de Wilson e por blocos de janelas vizinhas;
i. custo: latência, vazão do extrator, tamanho, memória e o Random Forest de 50 árvores.

Com `--capturas`, compara cinco configurações nas rodadas c, d e e e no corte por tempo: (0) o
modelo atual; (1) os quadros menores que 60 bytes completados até 60; (2) o mesmo e os quadros
limitados a 1.514 bytes, como passam no fio; (3) a configuração 2 sem `Time_To_Live`; (4) a
configuração 2 com as janelas de fundo da parte de treino de cada pcap de ataque no treino como
benignas. As configurações 1 e 2 leem os dados regerados com as opções do extrator ligadas, cada
uma na sua pasta. O modelo do sistema não muda: o resultado é para a equipe decidir.

O que é gravado em `experimentos/resultados/`: o manifesto de cada modo, com as versões, o
comando, o SHA-256 das entradas e todos os números; o relatório, que sai do manifesto; e as
tabelas em CSV. Os resultados de cada treino ficam guardados em `dados/processed/rodadas/`, fora
do git, para que uma execução interrompida continue de onde parou; mudam as entradas, eles deixam
de valer.

Uso, a partir da raiz do repositório:
    python -m codigo.classificador.rodadas --nucleos 4 --modelo modelos/rf_regerado_janela_100.joblib
    python -m codigo.classificador.rodadas --rodadas a,b,c --nucleos 4
    python -m codigo.classificador.rodadas --capturas --nucleos 4
    python -m codigo.classificador.rodadas --refazer-relatorio
"""
import argparse
import datetime
import gzip
import hashlib
import io
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn

from codigo.captura.extrator import COLUNAS, Extrator, ler_pcap
from codigo.classificador.avaliar import avaliar
from codigo.classificador.experimento import (
    _campo,
    _decimal,
    _enumerar,
    _gravar_csv,
    _milhar,
    _pct,
    _pp,
    _tabela,
)
from codigo.classificador.preparar import (
    ALVOS,
    FEATURES_39,
    FRACAO_DE_TESTE_POR_TEMPO,
    alvo,
    carregar,
    impressao_digital,
    matriz,
    ordem_natural,
)
from codigo.classificador.regerar import CABECALHO, DESCARTADAS, nome_da_pasta
from codigo.classificador.treinar import (
    ARVORES,
    TODOS_OS_NUCLEOS,
    _nucleos,
    _positivo,
    carregar_modelo,
    prever,
    treinar,
)
from codigo.classificador.treinar_regerado import (
    ALVO,
    CLASSES,
    EXTRAS,
    EXTRAS_OPCIONAIS,
    TETO,
)
from codigo.classificador.treinar_regerado import MANIFESTO as MANIFESTO_DO_TREINO

MANIFESTO = "manifesto_rodadas.json"
RELATORIO = "rodadas_de_teste.md"
MANIFESTO_DAS_CAPTURAS = "manifesto_rodadas_normalizadas.json"
RELATORIO_DAS_CAPTURAS = "rodadas_normalizadas.md"
PREFIXO_DAS_TABELAS = "rodadas"
PREFIXO_DAS_TABELAS_DAS_CAPTURAS = "rodadas_normalizadas"
TRABALHO = "dados/processed/rodadas"
JANELA = 100
BENIGNO = ALVOS[ALVO].benigno
CATEGORIA = ALVOS[ALVO].classe_do_rotulo
RODADAS = tuple("abcdefghi")
# A rodada b usa as cinco sementes; as que treinam um modelo por pcap ou por rotação, as três primeiras.
SEMENTES = (42, 1, 2, 3, 4)
SEMENTES_DE_CONTROLE = 3
# Os pcaps que saem inteiros do treino na rodada e: os das categorias com mais de um pcap, o único
# de BruteForce, para medir se ele ainda é visto como ataque, e uma amostra dos floods.
PCAPS_FORA = (
    "Recon-HostDiscovery.pcap", "Recon-OSScan.pcap", "Recon-PingSweep.pcap", "Recon-PortScan.pcap",
    "VulnerabilityScan.pcap",
    "Backdoor_Malware.pcap", "BrowserHijacking.pcap", "CommandInjection.pcap", "SqlInjection.pcap",
    "Uploading_Attack.pcap", "XSS.pcap",
    "DNS_Spoofing.pcap", "MITM-ArpSpoofing.pcap",
    "Mirai-greeth_flood.pcap", "Mirai-greip_flood21.pcap", "Mirai-udpplain.pcap",
    "DictionaryBruteForce.pcap",
    "DDoS-ICMP_Flood.pcap", "DDoS-SlowLoris.pcap", "DoS-HTTP_Flood1.pcap", "DoS-UDP_Flood.pcap",
)
# As categorias da tabela-resumo das capturas, com o recall medido com o pcap fora do treino.
CATEGORIAS_DO_RESUMO = ("Recon", "Web", "BruteForce", "Spoofing")
LIMIARES = tuple(round(0.05 * i, 2) for i in range(1, 20))
# Alvos de benigno classificado como ataque com que os pontos candidatos do limiar são escolhidos.
ALVOS_DO_LIMIAR = (0.02, 0.01, 0.005)
JANELAS_SEGUIDAS = (1, 2, 3, 5)
# Faixas do TTL médio da janela benigna, como (maior que, até); None é sem limite.
FAIXAS_DE_TTL = ((None, 64), (64, 70), (70, 75), (75, 90), (90, None))
TTL_FIXADO = (64, 70, 80, 100)
REPETICOES_DA_PERMUTACAO = 10
SUBAMOSTRA_DA_PERMUTACAO = 3000
CATEGORIAS_DA_PERMUTACAO = ("Web", "BruteForce", "Recon", "Benign")
CLASSES_RARAS = ("Web", "BruteForce", "Recon", "Spoofing")
REAMOSTRAGENS = 5000
BLOCO = 10  # janelas consecutivas de um mesmo pcap, cerca de 1.000 quadros
ARVORES_MENOR = 50
JANELAS_DA_LATENCIA = 500
PCAP_DA_VAZAO = "Recon-PortScan.pcap"
# Menor e maior quadro Ethernet no fio, sem o FCS.
QUADRO_MINIMO, QUADRO_MAXIMO = 60, 1514
# Faixas de quadros do atacante numa janela mantida de 100, como (de, até).
FAIXAS_DE_QUADROS = ((1, 1), (2, 5), (6, 20), (21, 50), (51, 100))
Z = 1.959964  # quantil de 97,5% da normal, para os intervalos de 95%


@dataclass(frozen=True)
class Configuracao:
    """Uma configuração comparada: de onde vêm os dados e o que muda no treino."""

    nome: str
    descricao: str
    destino: str  # pasta dos dados regerados
    regeracao: str  # manifesto da regeração dessa pasta
    sem: tuple = ()  # features tiradas do treino
    fundo_como_benigno: bool = False  # janelas de fundo da parte de treino entram como benignas
    opcoes: tuple = ()  # opções do extrator que o manifesto da regeração tem de registrar


ATUAL = Configuracao(
    "0", "o modelo atual", "dados/processed/regerado", "experimentos/resultados/manifesto_regeracao.json",
)
PREENCHIDA = Configuracao(
    "1", "quadros menores que 60 bytes completados até 60", "dados/processed/regerado_preenchido",
    "experimentos/resultados/regeracao_preenchido/manifesto_regeracao.json", opcoes=(("preencher", True),),
)
NO_FIO = Configuracao(
    "2", "completados até 60 e limitados a 1.514 bytes", "dados/processed/regerado_no_fio",
    "experimentos/resultados/regeracao_no_fio/manifesto_regeracao.json",
    opcoes=(("limitar", True), ("preencher", True)),
)
CONFIGURACOES = (
    ATUAL,
    PREENCHIDA,
    NO_FIO,
    Configuracao("3", "a 2 sem `Time_To_Live`", NO_FIO.destino, NO_FIO.regeracao, sem=("Time_To_Live",),
                 opcoes=NO_FIO.opcoes),
    Configuracao("4", "a 2 com o fundo da parte de treino como Benign", NO_FIO.destino, NO_FIO.regeracao,
                 fundo_como_benigno=True, opcoes=NO_FIO.opcoes),
)


# --- os dados ----------------------------------------------------------------------------------


@dataclass
class Dados:
    """As janelas regeradas de uma pasta, na memória, como o modelo as vê.

    `X` tem as 39 features em 32 bits; `meta`, o rótulo, o pcap, o índice da janela e as colunas do
    atacante. `fundo_X` e `fundo_meta` são as janelas descartadas dos pcaps de ataque. `arquivos`
    guarda os CSVs de rótulo na ordem em que `ler_janela` os lê, com as linhas de cada um, para o
    teto sortear as mesmas linhas.
    """

    X: np.ndarray
    meta: pd.DataFrame
    fundo_X: np.ndarray
    fundo_meta: pd.DataFrame
    arquivos: list
    regeracao: dict
    entradas: dict

    @property
    def totais(self):
        """Janelas extraídas de cada pcap, mantidas e descartadas: a base do corte por tempo."""
        return {p["arquivo"]: p["janelas"][str(JANELA)]["extraidas"] for p in self.regeracao["pcaps"]}

    def do_pcap(self, arquivo, fundo=False):
        """Todas as janelas de um pcap, em ordem de índice: as mantidas ou as de fundo."""
        X, meta = (self.fundo_X, self.fundo_meta) if fundo else (self.X, self.meta)
        posicoes = np.flatnonzero(meta["arquivo"].to_numpy() == arquivo)
        posicoes = posicoes[np.argsort(meta["indice"].to_numpy()[posicoes], kind="stable")]
        return X[posicoes], meta.iloc[posicoes].reset_index(drop=True)


def _compactar(quadro):
    """O quadro de metadados com o rótulo e o pcap como categorias e as contagens em inteiros."""
    meta = pd.DataFrame({
        "Label": quadro["Label"].astype(str).to_numpy(dtype=object),
        "arquivo": quadro["arquivo"].astype(str).to_numpy(dtype=object),
    })
    for coluna in (*EXTRAS, *EXTRAS_OPCIONAIS):
        if coluna in quadro.columns:
            meta[coluna] = quadro[coluna].astype(np.int64).to_numpy()
    return meta


def _sha256(caminho):
    with open(caminho, "rb") as arquivo:
        return hashlib.file_digest(arquivo, "sha256").hexdigest()


def ler_dados(destino, regeracao, ao_ler=None):
    """Lê os CSVs regerados de janela de 100 de uma pasta e as janelas descartadas dela.

    Os CSVs de rótulo são lidos em ordem de nome, como `ler_janela` lê. Devolve `Dados`, com o
    SHA-256 de cada arquivo lido em `entradas`.
    """
    pasta = Path(destino) / nome_da_pasta(JANELA)
    rotulos = sorted(pasta.glob("*.csv.gz"))
    if not rotulos:
        raise ValueError(f"nenhum CSV regerado em {pasta}: rode python -m codigo.classificador.regerar")
    Xs, metas, arquivos, entradas = [], [], [], {}
    for caminho in rotulos:
        quadro, sha256 = carregar(caminho)
        if quadro["Label"].nunique() != 1:
            raise ValueError(f"{caminho.name}: o CSV de um rótulo tem mais de um rótulo")
        Xs.append(matriz(quadro, FEATURES_39))
        metas.append(_compactar(quadro))
        arquivos.append((caminho.name, len(quadro)))
        entradas[f"{nome_da_pasta(JANELA)}/{caminho.name}"] = sha256
        if ao_ler is not None:
            ao_ler(caminho.name, len(quadro))
        del quadro
    partes_do_fundo = sorted((pasta / DESCARTADAS).glob("*.csv.gz"))
    if not partes_do_fundo:
        raise ValueError(f"nenhuma janela descartada em {pasta / DESCARTADAS}: regere com a versão 2 da regra")
    fundo_Xs, fundo_metas = [], []
    tipos = {coluna: (np.float64 if coluna in COLUNAS else object) for coluna in CABECALHO}
    for caminho in partes_do_fundo:
        with gzip.open(caminho, "rb") as arquivo:
            bruto = arquivo.read()
        entradas[f"{nome_da_pasta(JANELA)}/{DESCARTADAS}/{caminho.name}"] = hashlib.sha256(bruto).hexdigest()
        if not bruto:
            continue
        parte = pd.read_csv(io.BytesIO(bruto), header=None, names=list(CABECALHO), dtype=tipos,
                            float_precision="round_trip")
        fundo_Xs.append(matriz(parte, FEATURES_39))
        fundo_metas.append(_compactar(parte))
    return Dados(
        X=np.concatenate(Xs), meta=pd.concat(metas, ignore_index=True),
        fundo_X=np.concatenate(fundo_Xs) if fundo_Xs else np.empty((0, len(FEATURES_39)), np.float32),
        fundo_meta=pd.concat(fundo_metas, ignore_index=True) if fundo_metas else pd.DataFrame(
            columns=["Label", "arquivo", *EXTRAS, *EXTRAS_OPCIONAIS]),
        arquivos=arquivos, regeracao=regeracao, entradas=entradas,
    )


def amostra(dados, semente, teto=TETO):
    """As posições da amostra com teto, na ordem em que `ler_janela` deixa as linhas.

    O sorteio é o de `treinar_regerado.limitar`: um gerador só, CSV a CSV em ordem de nome, e
    `choice` sobre as linhas do rótulo quando ele passa do teto. Depois, as linhas ficam em ordem
    de pcap e de índice, com ordenação estável.
    """
    gerador = np.random.default_rng(semente)
    manter, inicio = [], 0
    for _nome, linhas in dados.arquivos:
        posicoes = np.arange(inicio, inicio + linhas)
        if linhas > teto:
            posicoes = np.sort(gerador.choice(posicoes, teto, replace=False))
        manter.append(posicoes)
        inicio += linhas
    manter = np.concatenate(manter)
    meta = dados.meta.iloc[manter]
    ordem = np.lexsort((meta["indice"].to_numpy(), meta["arquivo"].to_numpy().astype(str)))
    return manter[ordem]


# --- a divisão ---------------------------------------------------------------------------------


def lados(regeracao, rotacao=0, fracao=FRACAO_DE_TESTE_POR_TEMPO):
    """Como cada pcap entra na divisão: "teste", "treino" ou o índice do corte por tempo.

    Num rótulo com mais de um pcap, um vai inteiro para o teste e os outros para o treino: na
    rotação 0, o último pela ordem natural, como em `dividir_por_tempo`; em cada rotação seguinte,
    o pcap de fora anda uma posição. Num rótulo de um pcap só, o corte é no total de janelas
    extraídas do arquivo.
    """
    totais = {p["arquivo"]: p["janelas"][str(JANELA)]["extraidas"] for p in regeracao["pcaps"]}
    saida = {}
    for registro in regeracao["rotulos"]:
        arquivos = sorted(registro["arquivos"], key=ordem_natural)
        if len(arquivos) > 1:
            fora = arquivos[(len(arquivos) - 1 + rotacao) % len(arquivos)]
            saida.update({arquivo: "teste" if arquivo == fora else "treino" for arquivo in arquivos})
        else:
            saida[arquivos[0]] = int((1 - fracao) * totais[arquivos[0]] + 0.5)
    return saida


def rotacoes(regeracao):
    """Quantas rotações cobrem todos os pcaps dos rótulos de vários pcaps: o maior número de pcaps num rótulo."""
    return max(len(registro["arquivos"]) for registro in regeracao["rotulos"])


def de_fora(lados_da_divisao):
    """Os pcaps que ficam inteiros no teste numa divisão."""
    return sorted(arquivo for arquivo, lado in lados_da_divisao.items() if lado == "teste")


def no_teste(meta, lados_da_divisao):
    """Se cada janela fica no teste, pelos lados de cada pcap."""
    arquivos, indices = meta["arquivo"].to_numpy(), meta["indice"].to_numpy()
    teste = np.zeros(len(meta), dtype=bool)
    for arquivo in pd.unique(arquivos):
        do_pcap = arquivos == arquivo
        lado = lados_da_divisao[arquivo]
        if lado == "teste":
            teste[do_pcap] = True
        elif lado != "treino":
            teste[do_pcap] = indices[do_pcap] >= lado
    return teste


# --- medidas -----------------------------------------------------------------------------------


def contagem(previsto):
    """Quantas janelas foram previstas em cada categoria, na ordem das tabelas."""
    valores, quantas = np.unique(np.asarray(previsto, dtype=object), return_counts=True)
    por_classe = dict(zip(valores.tolist(), quantas.tolist()))
    return {classe: int(por_classe.get(classe, 0)) for classe in CLASSES}


def resumo_das_medidas(previsto, rotulos):
    """As medidas do `avaliar` na distribuição do conjunto avaliado, só com o que as rodadas usam."""
    a = avaliar(previsto, rotulos, ALVO)["amostra"]
    return {
        "linhas": len(rotulos),
        "acuracia": a["acuracia"],
        "macro_f1": a["macro_f1"],
        "f1_ponderado": a["f1_ponderado"],
        "benigno_como_ataque": a["falso_positivo_benigno"],
        "ataque_como_benigno": a["por_classe"][BENIGNO]["taxa_falso_positivo"],
        "por_classe": {
            classe: {chave: m[chave] for chave in ("precisao", "recall", "f1", "suporte")}
            for classe, m in a["por_classe"].items()
        },
    }


def probabilidades(modelo, X):
    """`predict_proba` com um núcleo, pelo mesmo motivo de `prever`: a soma dos votos em ordem fixa."""
    nucleos = modelo.n_jobs
    modelo.n_jobs = 1
    try:
        return modelo.predict_proba(X)
    finally:
        modelo.n_jobs = nucleos


def aplicar_limiar(proba, classes, limiar):
    """Ataque quando 1 - P(Benign) passa do limiar, na categoria de ataque mais provável; senão Benign."""
    classes = np.asarray(classes, dtype=object)
    benigno = list(classes).index(BENIGNO)
    de_ataque = proba.copy()
    de_ataque[:, benigno] = -1.0
    return np.where(1.0 - proba[:, benigno] >= limiar - 1e-12, classes[de_ataque.argmax(axis=1)], BENIGNO).astype(object)


def alarmes(e_ataque, seguidas):
    """As posições em que um alarme dispara: a N-ésima janela seguida classificada como ataque.

    Uma sequência de janelas de ataque dispara um alarme só, na janela em que completa N seguidas;
    a próxima sequência que chegar a N dispara outro.
    """
    disparos, corrente = [], 0
    for posicao, ataque in enumerate(np.asarray(e_ataque, dtype=bool)):
        corrente = corrente + 1 if ataque else 0
        if corrente == seguidas:
            disparos.append(posicao)
    return disparos


def wilson(acertos, n, z=Z):
    """Intervalo de Wilson de 95% para uma proporção, ou (None, None) sem linhas."""
    if n == 0:
        return (None, None)
    p = acertos / n
    denominador = 1 + z * z / n
    centro = (p + z * z / (2 * n)) / denominador
    meia = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominador
    return (float(max(0.0, centro - meia)), float(min(1.0, centro + meia)))


def blocos(acerto, grupos, semente, reamostragens=REAMOSTRAGENS, bloco=BLOCO):
    """Intervalo de 95% do acerto por reamostragem de blocos de janelas vizinhas.

    `acerto` e `grupos` (o pcap de cada janela) vêm em ordem de índice dentro de cada pcap. Cada
    pcap é cortado em blocos de `bloco` janelas, e cada reamostragem sorteia, com reposição, a
    mesma quantidade de blocos dentro de cada pcap: janelas vizinhas erram juntas, e o intervalo
    leva isso em conta.
    """
    acerto, grupos = np.asarray(acerto, dtype=float), np.asarray(grupos, dtype=object)
    if len(acerto) == 0:
        return (None, None)
    gerador = np.random.default_rng(semente)
    soma, quantas = np.zeros(reamostragens), np.zeros(reamostragens)
    for grupo in pd.unique(grupos):
        valores = acerto[grupos == grupo]
        inicios = np.arange(0, len(valores), bloco)
        somas = np.add.reduceat(valores, inicios)
        tamanhos = np.diff(np.append(inicios, len(valores)))
        escolha = gerador.integers(0, len(somas), (reamostragens, len(somas)))
        soma += somas[escolha].sum(axis=1)
        quantas += tamanhos[escolha].sum(axis=1)
    taxas = soma / quantas
    return (float(np.percentile(taxas, 2.5)), float(np.percentile(taxas, 97.5)))


def autocorrelacao(acerto, grupos):
    """Correlação do acerto de uma janela com o da seguinte no mesmo pcap, e o tamanho efetivo n(1-r)/(1+r)."""
    acerto, grupos = np.asarray(acerto, dtype=float), np.asarray(grupos, dtype=object)
    antes, depois = [], []
    for grupo in pd.unique(grupos):
        valores = acerto[grupos == grupo]
        if len(valores) > 2:
            antes.append(valores[:-1])
            depois.append(valores[1:])
    if not antes:
        return None, None
    a, b = np.concatenate(antes), np.concatenate(depois)
    if a.std() == 0 or b.std() == 0:
        return None, None
    r = float(np.corrcoef(a, b)[0, 1])
    if r <= -1 + 1e-12:
        return r, None
    return r, float(len(acerto) * (1 - r) / (1 + r))


def permutacao(modelo, X, y, classe, nomes, gerador, repeticoes=REPETICOES_DA_PERMUTACAO,
               subamostra=SUBAMOSTRA_DA_PERMUTACAO):
    """Queda do recall de uma categoria quando cada feature é embaralhada com valores do próprio conjunto.

    As janelas da categoria são as medidas (até `subamostra`, sorteadas); o valor que entra no lugar
    vem de uma janela qualquer do conjunto. Devolve o recall de base e, por feature (`nomes`, na
    ordem das colunas de `X`), a média e o desvio da queda nas repetições.
    """
    posicoes = np.flatnonzero(y == classe)
    if len(posicoes) > subamostra:
        posicoes = np.sort(gerador.choice(posicoes, subamostra, replace=False))
    if len(posicoes) == 0:
        return {"janelas": 0, "base": None, "quedas": {}}
    da_classe = X[posicoes]
    base = float((prever(modelo, da_classe) == classe).mean())
    quedas = {}
    for coluna in range(X.shape[1]):
        valores = []
        for _ in range(repeticoes):
            embaralhado = da_classe.copy()
            embaralhado[:, coluna] = X[gerador.integers(0, len(X), len(posicoes)), coluna]
            valores.append(base - float((prever(modelo, embaralhado) == classe).mean()))
        quedas[nomes[coluna]] = (float(np.mean(valores)), float(np.std(valores)))
    return {"janelas": len(posicoes), "base": base, "quedas": quedas}


def macro_f1(y, previsto):
    """Média do F1 das categorias presentes em `y`, como o `avaliar` faz."""
    valores = []
    for classe in pd.unique(np.asarray(y, dtype=object)):
        reais, previstas = y == classe, previsto == classe
        acertos = int((reais & previstas).sum())
        precisao = acertos / previstas.sum() if previstas.sum() else 0.0
        recall = acertos / reais.sum()
        valores.append(2 * precisao * recall / (precisao + recall) if precisao + recall else 0.0)
    return float(np.mean(valores))


def latencia(funcao, X, repeticoes=JANELAS_DA_LATENCIA):
    """Milissegundos para classificar uma janela sozinha: mediana, p95 e p99, cada vez uma janela diferente."""
    funcao(X[:1])  # a primeira chamada paga o aquecimento
    tempos = []
    for i in range(repeticoes):
        janela = X[(i * 7919) % len(X)][np.newaxis, :]
        inicio = time.perf_counter()
        funcao(janela)
        tempos.append(1000 * (time.perf_counter() - inicio))
    return {
        "mediana_ms": float(np.median(tempos)), "p95_ms": float(np.percentile(tempos, 95)),
        "p99_ms": float(np.percentile(tempos, 99)),
    }


def em_lote(funcao, X, tamanho=1000, repeticoes=5):
    """Milissegundos para classificar `tamanho` janelas num lote só: a mediana das repetições."""
    lote = X[:tamanho]
    tempos = []
    for _ in range(repeticoes):
        inicio = time.perf_counter()
        funcao(lote)
        tempos.append(1000 * (time.perf_counter() - inicio))
    return float(statistics.median(tempos))


# --- os resultados guardados entre execuções ---------------------------------------------------


class Trabalho:
    """Os resultados de cada treino de uma configuração, guardados fora do git.

    O arquivo tem o nome da impressão digital das entradas e dos parâmetros: dados novos, outro
    teto ou outra quantidade de árvores caem em outro arquivo, e o resultado antigo não é usado.
    """

    def __init__(self, pasta, impressao):
        self.caminho = Path(pasta) / f"{impressao}.json"
        try:
            self.resultados = json.loads(self.caminho.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.resultados = {}

    def obter(self, chave, exige=()):
        """O resultado guardado, se existe e tem todas as partes exigidas."""
        resultado = self.resultados.get(chave)
        if resultado is None or any(parte not in resultado for parte in exige):
            return None
        return resultado

    def guardar(self, chave, resultado):
        self.resultados[chave] = resultado
        self.caminho.parent.mkdir(parents=True, exist_ok=True)
        provisorio = self.caminho.with_name(self.caminho.name + ".parcial")
        provisorio.write_text(json.dumps(self.resultados, ensure_ascii=False), encoding="utf-8")
        os.replace(provisorio, self.caminho)


def impressao_da_configuracao(configuracao, dados, arvores, teto):
    """SHA-256 do que decide os resultados de uma configuração: entradas, features, fundo, árvores e teto."""
    chave = {
        "entradas": dados.entradas, "sem": list(configuracao.sem), "fundo": configuracao.fundo_como_benigno,
        "arvores": arvores, "teto": teto, "janela": JANELA, "fracao": FRACAO_DE_TESTE_POR_TEMPO,
    }
    return hashlib.sha256(json.dumps(chave, sort_keys=True).encode("utf-8")).hexdigest()[:24]


# --- os treinos de uma configuração ------------------------------------------------------------


def _relatar(texto):
    print(f"{time.strftime('%H:%M:%S')} {texto}", file=sys.stderr, flush=True)


def _pcaps_de_ataque(regeracao):
    return [p for p in regeracao["pcaps"] if not p["benigno"]]


class Execucao:
    """Os treinos de uma configuração: a divisão por tempo, as rotações e os pcaps fora do treino.

    Cada treino vira um resultado guardado em `Trabalho`, com contagens e não só frações, para que
    o relatório some pcaps e sementes sem perder o peso de cada um.
    """

    def __init__(self, configuracao, dados, arvores=ARVORES, nucleos=TODOS_OS_NUCLEOS, teto=TETO, trabalho=TRABALHO):
        self.configuracao = configuracao
        self.dados = dados
        self.arvores, self.nucleos, self.teto = arvores, nucleos, teto
        self.colunas = [i for i, feature in enumerate(FEATURES_39) if feature not in configuracao.sem]
        self.features = [FEATURES_39[i] for i in self.colunas]
        self.trabalho = Trabalho(trabalho, impressao_da_configuracao(configuracao, dados, arvores, teto))
        self._amostra = (None, None)

    # O que serve a várias rodadas.

    def amostra(self, semente):
        if self._amostra[0] != semente:
            self._amostra = (semente, amostra(self.dados, semente, self.teto))
        return self._amostra[1]

    def _X(self, X):
        return X[:, self.colunas]

    def _treino(self, posicoes, teste, lados_da_divisao, sem_pcap=None):
        """As linhas de treino: a parte de treino da amostra, sem o pcap pedido, e o fundo, se a configuração pede."""
        meta = self.dados.meta.iloc[posicoes]
        fica = ~teste
        if sem_pcap is not None:
            fica &= meta["arquivo"].to_numpy() != sem_pcap
        X = self._X(self.dados.X[posicoes[fica]])
        y = alvo(meta["Label"].to_numpy()[fica], ALVO)
        if self.configuracao.fundo_como_benigno and len(self.dados.fundo_meta):
            do_fundo = ~no_teste(self.dados.fundo_meta, lados_da_divisao)
            if sem_pcap is not None:
                do_fundo &= self.dados.fundo_meta["arquivo"].to_numpy() != sem_pcap
            X = np.concatenate([X, self._X(self.dados.fundo_X[do_fundo])])
            y = np.concatenate([y, np.full(int(do_fundo.sum()), BENIGNO, dtype=object)])
        return X, y

    def _treinar(self, X, y, semente, arvores=None):
        return treinar(X, y, semente, arvores or self.arvores, nucleos=self.nucleos)

    def _no_pcap(self, modelo, arquivo):
        """As categorias previstas em todas as janelas mantidas de um pcap."""
        X, _ = self.dados.do_pcap(arquivo)
        return {"arquivo": arquivo, "janelas": len(X), "previstas": contagem(prever(modelo, self._X(X)))}

    def _de_fora(self, modelo, lados_da_divisao):
        """Os pcaps inteiros no teste, com as categorias previstas em todas as janelas de cada um."""
        rotulo = {p["arquivo"]: p["rotulo"] for p in self.dados.regeracao["pcaps"]}
        return [
            {**self._no_pcap(modelo, arquivo), "rotulo": rotulo[arquivo], "categoria": CATEGORIA[rotulo[arquivo]]}
            for arquivo in de_fora(lados_da_divisao)
        ]

    def _fundo(self, modelo, lados_da_divisao):
        """O modelo nas janelas descartadas de cada pcap de ataque, na parte de treino e na de teste."""
        meta = self.dados.fundo_meta
        if not len(meta):
            return []
        previsto = prever(modelo, self._X(self.dados.fundo_X))
        teste = no_teste(meta, lados_da_divisao)
        arquivos = meta["arquivo"].to_numpy()
        saida = []
        for p in _pcaps_de_ataque(self.dados.regeracao):
            do_pcap = arquivos == p["arquivo"]
            registro = {"arquivo": p["arquivo"], "rotulo": p["rotulo"], "categoria": CATEGORIA[p["rotulo"]]}
            for parte, lado in (("treino", ~teste), ("teste", teste)):
                registro[parte] = {"janelas": int((do_pcap & lado).sum()), "previstas": contagem(previsto[do_pcap & lado])}
            saida.append(registro)
        return saida

    def _ttl(self, modelo, arquivo):
        """No pcap benigno de fora: o alarme por faixa do TTL médio da janela e com o TTL trocado."""
        if "Time_To_Live" not in self.features:
            return None
        X, _ = self.dados.do_pcap(arquivo)
        ttl = X[:, FEATURES_39.index("Time_To_Live")]
        ataque = prever(modelo, self._X(X)) != BENIGNO
        faixas = []
        for acima, ate in FAIXAS_DE_TTL:
            na_faixa = np.ones(len(ttl), dtype=bool)
            if acima is not None:
                na_faixa &= ttl > acima
            if ate is not None:
                na_faixa &= ttl <= ate
            faixas.append({"acima_de": acima, "ate": ate, "janelas": int(na_faixa.sum()),
                           "como_ataque": int(ataque[na_faixa].sum())})
        trocado = {}
        for valor in TTL_FIXADO:
            outro = X.copy()
            outro[:, FEATURES_39.index("Time_To_Live")] = valor
            trocado[str(valor)] = int((prever(modelo, self._X(outro)) != BENIGNO).sum())
        return {"arquivo": arquivo, "janelas": len(X), "faixas": faixas, "fixado": trocado}

    def _por_quadros(self, meta, previsto):
        """Acerto por faixa de quadros do atacante na janela, por categoria de ataque, nas janelas de teste."""
        if "quadros_atacante" not in meta.columns:
            return None
        quadros = meta["quadros_atacante"].to_numpy()
        categoria = alvo(meta["Label"].to_numpy(), ALVO)
        saida = {}
        for classe in CLASSES:
            if classe == BENIGNO or not (categoria == classe).any():
                continue
            saida[classe] = {}
            for de, ate in FAIXAS_DE_QUADROS:
                na_faixa = (categoria == classe) & (quadros >= de) & (quadros <= ate)
                saida[classe][f"{de}-{ate}"] = {
                    "janelas": int(na_faixa.sum()), "na_categoria": int((previsto[na_faixa] == classe).sum()),
                    "como_ataque": int((previsto[na_faixa] != BENIGNO).sum()),
                }
        return saida

    def _alarmes_no_benigno(self, modelo, arquivo):
        """A regra de N janelas seguidas num pcap benigno inteiro: alarmes e a duração do pcap."""
        X, _ = self.dados.do_pcap(arquivo)
        e_ataque = prever(modelo, self._X(X)) != BENIGNO
        return {"arquivo": arquivo, "janelas": len(X), "segundos": float(_duracao(X).sum()),
                "alarmes": {str(n): len(alarmes(e_ataque, n)) for n in JANELAS_SEGUIDAS}}

    def _guardado(self, chave, funcao, exige=()):
        resultado = self.trabalho.obter(chave, exige)
        if resultado is None:
            inicio = time.perf_counter()
            resultado = funcao()
            self.trabalho.guardar(chave, resultado)
            _relatar(f"configuração {self.configuracao.nome}, {chave}: {_decimal(time.perf_counter() - inicio)} s")
        return resultado

    # Os treinos.

    def corte(self, semente, detalhe=None):
        """O treino da divisão por tempo publicada. Com `detalhe`, também as medidas das rodadas a, f, g e h."""
        exige = ("detalhe",) if detalhe is not None else ()
        return self._guardado(f"corte|{semente}", lambda: self._corte(semente, detalhe), exige)

    def _corte(self, semente, detalhe):
        posicoes = self.amostra(semente)
        lados_da_divisao = lados(self.dados.regeracao, 0)
        meta = self.dados.meta.iloc[posicoes]
        teste = no_teste(meta, lados_da_divisao)
        X, y = self._treino(posicoes, teste, lados_da_divisao)
        modelo, segundos = self._treinar(X, y, semente)
        X_teste = self._X(self.dados.X[posicoes[teste]])
        rotulos = meta["Label"].to_numpy()[teste]
        previsto = prever(modelo, X_teste)
        arquivos = meta["arquivo"].to_numpy()[teste]
        fora = self._de_fora(modelo, lados_da_divisao)
        benigno = next((p["arquivo"] for p in fora if p["categoria"] == BENIGNO), None)
        resultado = {
            "semente": semente,
            "linhas": {"amostra": len(posicoes), "treino": len(y), "teste": int(teste.sum())},
            "por_quadros_do_atacante": self._por_quadros(meta[teste], previsto),
            "divisao": {
                "treino_sha256": impressao_digital(np.flatnonzero(~teste)),
                "teste_sha256": impressao_digital(np.flatnonzero(teste)),
            },
            "treino_segundos": segundos,
            "medidas": resumo_das_medidas(previsto, rotulos),
            "por_pcap": {
                arquivo: {"janelas": int((arquivos == arquivo).sum()), "previstas": contagem(previsto[arquivos == arquivo])}
                for arquivo in sorted(pd.unique(arquivos))
            },
            "de_fora": fora,
            "fundo": self._fundo(modelo, lados_da_divisao),
            "ttl": self._ttl(modelo, benigno) if benigno else None,
            "alarmes_no_benigno": self._alarmes_no_benigno(modelo, benigno) if benigno else None,
        }
        if detalhe is not None:
            resultado["detalhe"] = detalhe(self, modelo, posicoes, teste, previsto)
        return resultado

    def rotacao(self, semente, rotacao):
        """O treino com outro pcap inteiro fora, nos rótulos de vários pcaps."""
        return self._guardado(f"rotacao|{rotacao}|{semente}", lambda: self._rotacao(semente, rotacao))

    def _rotacao(self, semente, rotacao, arvores=None):
        posicoes = self.amostra(semente)
        lados_da_divisao = lados(self.dados.regeracao, rotacao)
        meta = self.dados.meta.iloc[posicoes]
        teste = no_teste(meta, lados_da_divisao)
        X, y = self._treino(posicoes, teste, lados_da_divisao)
        modelo, segundos = self._treinar(X, y, semente, arvores)
        previsto = prever(modelo, self._X(self.dados.X[posicoes[teste]]))
        fora = self._de_fora(modelo, lados_da_divisao)
        limiar = None
        benigno = next((p["arquivo"] for p in fora if p["categoria"] == BENIGNO), None)
        if benigno is not None:
            X_benigno, _ = self.dados.do_pcap(benigno)
            proba = probabilidades(modelo, self._X(X_benigno))
            p_benigno = proba[:, list(modelo.classes_).index(BENIGNO)]
            limiar = {
                "arquivo": benigno,
                "como_ataque": {
                    str(t): int((aplicar_limiar(proba, modelo.classes_, t) != BENIGNO).sum()) for t in LIMIARES
                },
                "quantis_de_p_benigno": dict(zip(("5", "25", "50", "75", "95"),
                                                 np.quantile(p_benigno, [0.05, 0.25, 0.5, 0.75, 0.95]).tolist())),
            }
        return {
            "semente": semente, "rotacao": rotacao, "de_fora": fora, "treino_segundos": segundos,
            "medidas": resumo_das_medidas(previsto, meta["Label"].to_numpy()[teste]), "limiar_no_benigno": limiar,
            "alarmes_no_benigno": self._alarmes_no_benigno(modelo, benigno) if benigno is not None else None,
        }

    def fora(self, semente, arquivo):
        """O treino sem nenhuma janela de um pcap, medido nas janelas dele."""
        return self._guardado(f"fora|{arquivo}|{semente}", lambda: self._fora(semente, arquivo))

    def _fora(self, semente, arquivo):
        rotulo = next(p["rotulo"] for p in self.dados.regeracao["pcaps"] if p["arquivo"] == arquivo)
        if len(next(r["arquivos"] for r in self.dados.regeracao["rotulos"] if r["rotulo"] == rotulo)) > 1:
            raise ValueError(f"{arquivo}: o rótulo tem mais de um pcap, e a rotação (rodada c) já cobre esse caso")
        posicoes = self.amostra(semente)
        lados_da_divisao = lados(self.dados.regeracao, 0)
        meta = self.dados.meta.iloc[posicoes]
        teste = no_teste(meta, lados_da_divisao)
        X, y = self._treino(posicoes, teste, lados_da_divisao, sem_pcap=arquivo)
        modelo, segundos = self._treinar(X, y, semente)
        do_pcap = (meta["arquivo"].to_numpy() == arquivo) & teste
        previsto = prever(modelo, self._X(self.dados.X[posicoes[do_pcap]]))
        return {
            "semente": semente, "arquivo": arquivo, "rotulo": rotulo, "categoria": CATEGORIA[rotulo],
            "treino_segundos": segundos,
            "teste": {"janelas": int(do_pcap.sum()), "previstas": contagem(previsto)},
            "inteiro": self._no_pcap(modelo, arquivo),
        }


# --- as medidas da semente principal: rodadas a, f (permutação), g e h --------------------------


def _duracao(X):
    """Segundos que cada janela levou para fechar: `Number` / `Rate`, zero na janela sem duração."""
    numero, taxa = X[:, FEATURES_39.index("Number")].astype(float), X[:, FEATURES_39.index("Rate")].astype(float)
    with np.errstate(divide="ignore", invalid="ignore"):
        duracao = numero / taxa
    return np.where(np.isfinite(duracao), duracao, 0.0)


def _reproducao(caminho, publicado, X_teste, previsto, rotulos, teste):
    """O modelo salvo no conjunto de teste refeito, contra o retreino e contra o que foi publicado."""
    pacote = carregar_modelo(caminho)
    salvo = pacote["modelo"]
    do_salvo = prever(salvo, X_teste)
    avaliacao = avaliar(do_salvo, rotulos, ALVO)
    janela = next(j for j in publicado["janelas"] if j["janela"] == JANELA)
    a, p = avaliacao["amostra"], janela["avaliacao"]["amostra"]
    conferidos, diferentes = 0, []
    for classe, medida in a["por_classe"].items():
        for chave in ("precisao", "recall", "f1", "suporte", "taxa_falso_positivo"):
            conferidos += 1
            novo, antigo = medida[chave], p["por_classe"][classe][chave]
            if (novo is None) != (antigo is None) or (novo is not None and abs(novo - antigo) > 1e-12):
                diferentes.append([classe, chave, antigo, novo])
    for chave in ("acuracia", "macro_f1", "f1_ponderado", "falso_positivo_benigno"):
        conferidos += 1
        if abs(a[chave] - p[chave]) > 1e-12:
            diferentes.append(["global", chave, p[chave], a[chave]])
    return {
        "modelo": {"arquivo": Path(caminho).name, "sha256": _sha256(caminho), "bytes": Path(caminho).stat().st_size,
                   "semente": pacote.get("semente"), "arvores": pacote.get("arvores"), "janela": pacote.get("janela"),
                   "teto": pacote.get("teto")},
        "linhas_publicadas": janela["linhas"],
        "linhas": {"treino": int((~teste).sum()), "teste": int(teste.sum())},
        "divisao_igual": {
            "treino": impressao_digital(np.flatnonzero(~teste)) == janela["divisao"]["treino_sha256"],
            "teste": impressao_digital(np.flatnonzero(teste)) == janela["divisao"]["teste_sha256"],
            "treino_do_modelo": pacote.get("treino_sha256") == janela["divisao"]["treino_sha256"],
        },
        "medidas_conferidas": conferidos,
        "medidas_diferentes": diferentes,
        "matriz_por_rotulo_igual": avaliacao["matriz_por_rotulo"] == janela["avaliacao"]["matriz_por_rotulo"],
        "predicoes_diferentes_do_retreino": int((do_salvo != previsto).sum()),
        "janelas_de_teste": len(previsto),
    }


def _curva_do_limiar(proba, classes, rotulos, previsto):
    """Para cada limiar, e para o argmax de hoje: alarme falso, recall de ataque e as medidas do teste."""
    benigno = alvo(rotulos, ALVO) == BENIGNO
    linhas = []
    for limiar in ("argmax", *LIMIARES):
        prev = previsto if limiar == "argmax" else aplicar_limiar(proba, classes, limiar)
        m = resumo_das_medidas(prev, rotulos)
        linhas.append({
            "limiar": limiar,
            "benigno_como_ataque": m["benigno_como_ataque"],
            "recall_de_ataque": float((prev[~benigno] != BENIGNO).mean()),
            "ataque_como_benigno": m["ataque_como_benigno"],
            "macro_f1": m["macro_f1"],
            "recall": {classe: m["por_classe"][classe]["recall"] for classe in CLASSES},
        })
    return linhas


def _seguidas(execucao, modelo, lados_da_divisao):
    """A regra de N janelas seguidas no pcap benigno de fora e no trecho de teste de cada pcap de ataque.

    No pcap de ataque, o trecho de teste é a sequência de todas as janelas depois do corte, as com e
    as sem atacante, na ordem do arquivo: é o que o extrator entregaria na operação.
    """
    dados = execucao.dados
    benignos, ataques = [], []
    for p in dados.regeracao["pcaps"]:
        X, meta = dados.do_pcap(p["arquivo"])
        teste = no_teste(meta, lados_da_divisao)
        if p["benigno"]:
            if lados_da_divisao.get(p["arquivo"]) != "teste":
                continue
            e_ataque = prever(modelo, execucao._X(X)) != BENIGNO
            segundos = float(_duracao(X).sum())
            benignos.append({
                "arquivo": p["arquivo"], "janelas": len(X), "segundos": segundos,
                "alarmes": {str(n): len(alarmes(e_ataque, n)) for n in JANELAS_SEGUIDAS},
            })
            continue
        X_fundo, meta_fundo = dados.do_pcap(p["arquivo"], fundo=True)
        teste_fundo = no_teste(meta_fundo, lados_da_divisao) if len(meta_fundo) else np.zeros(0, dtype=bool)
        indices = np.concatenate([meta["indice"].to_numpy()[teste], meta_fundo["indice"].to_numpy()[teste_fundo]])
        if not len(indices):
            continue
        X_trecho = np.concatenate([X[teste], X_fundo[teste_fundo]])
        com_atacante = np.concatenate([np.ones(int(teste.sum()), bool), np.zeros(int(teste_fundo.sum()), bool)])
        ordem = np.argsort(indices, kind="stable")
        X_trecho, com_atacante = X_trecho[ordem], com_atacante[ordem]
        e_ataque = prever(modelo, execucao._X(X_trecho)) != BENIGNO
        acumulado = np.cumsum(_duracao(X_trecho))
        por_n = {}
        for n in JANELAS_SEGUIDAS:
            disparos = alarmes(e_ataque, n)
            primeiro = disparos[0] if disparos else None
            por_n[str(n)] = {
                "alarmes": len(disparos),
                "primeira_janela": None if primeiro is None else primeiro + 1,
                "primeiro_segundos": None if primeiro is None else float(acumulado[primeiro]),
            }
        ataques.append({
            "arquivo": p["arquivo"], "categoria": CATEGORIA[p["rotulo"]], "janelas": len(X_trecho),
            "com_atacante": int(com_atacante.sum()), "como_ataque": int(e_ataque.sum()),
            "segundos": float(acumulado[-1]), "seguidas": por_n,
        })
    return {"benignos": benignos, "ataques": ataques}


def _intervalos(previsto, y, arquivos, semente):
    """Recall e precisão das classes raras com o intervalo de Wilson, o intervalo por blocos e a autocorrelação."""
    saida = {}
    for classe in CLASSES_RARAS:
        da_classe = y == classe
        acerto = previsto[da_classe] == classe
        n, acertos = int(da_classe.sum()), int(acerto.sum())
        previstas = previsto == classe
        certas = int((previstas & da_classe).sum())
        r, efetivo = autocorrelacao(acerto, arquivos[da_classe])
        saida[classe] = {
            "janelas": n, "acertos": acertos, "recall_wilson": wilson(acertos, n),
            "recall_blocos": blocos(acerto, arquivos[da_classe], semente),
            "autocorrelacao": r, "n_efetivo": efetivo,
            "previstas": int(previstas.sum()), "certas": certas, "precisao_wilson": wilson(certas, int(previstas.sum())),
            "por_pcap": {
                arquivo: {"janelas": int((arquivos[da_classe] == arquivo).sum()),
                          "acertos": int(acerto[arquivos[da_classe] == arquivo].sum())}
                for arquivo in sorted(pd.unique(arquivos[da_classe]))
            },
        }
    return saida


def _permutacoes(modelo, X, y, nomes, semente):
    """A importância por permutação: queda do recall de algumas categorias e do macro-F1."""
    gerador = np.random.default_rng(semente)
    por_categoria = {classe: permutacao(modelo, X, y, classe, nomes, gerador) for classe in CATEGORIAS_DA_PERMUTACAO}
    # O macro-F1 numa subamostra com até a mesma quantidade de janelas de cada categoria.
    posicoes = np.concatenate([
        gerador.choice(np.flatnonzero(y == classe), min(SUBAMOSTRA_DA_PERMUTACAO, int((y == classe).sum())),
                       replace=False)
        for classe in CLASSES if (y == classe).any()
    ])
    X_sub, y_sub = X[posicoes], y[posicoes]
    base = macro_f1(y_sub, prever(modelo, X_sub))
    quedas = {}
    for coluna, nome in enumerate(nomes):
        valores = []
        for _ in range(REPETICOES_DA_PERMUTACAO // 2):
            embaralhado = X_sub.copy()
            embaralhado[:, coluna] = X_sub[gerador.permutation(len(X_sub)), coluna]
            valores.append(base - macro_f1(y_sub, prever(modelo, embaralhado)))
        quedas[nome] = (float(np.mean(valores)), float(np.std(valores)))
    impureza = dict(zip(nomes, modelo.feature_importances_.tolist()))
    return {"por_categoria": por_categoria,
            "macro_f1": {"janelas": len(posicoes), "base": base, "quedas": quedas}, "impureza": impureza}


def detalhar(modelo_salvo=None, publicado=None):
    """A função que mede, no treino da semente principal, as rodadas a, f (permutação), g e h."""

    def detalhe(execucao, modelo, posicoes, teste, previsto):
        dados = execucao.dados
        meta = dados.meta.iloc[posicoes]
        X_teste = execucao._X(dados.X[posicoes[teste]])
        rotulos = meta["Label"].to_numpy()[teste]
        arquivos = meta["arquivo"].to_numpy()[teste]
        y = alvo(rotulos, ALVO)
        semente = int(modelo.random_state)
        lados_da_divisao = lados(dados.regeracao, 0)
        proba = probabilidades(modelo, X_teste)
        fundo_de_teste = no_teste(dados.fundo_meta, lados_da_divisao) if len(dados.fundo_meta) else np.zeros(0, bool)
        limiar_no_fundo = {"janelas": int(fundo_de_teste.sum()), "como_ataque": {}}
        if fundo_de_teste.any():
            proba_do_fundo = probabilidades(modelo, execucao._X(dados.fundo_X[fundo_de_teste]))
            limiar_no_fundo["como_ataque"] = {
                "argmax": int((prever(modelo, execucao._X(dados.fundo_X[fundo_de_teste])) != BENIGNO).sum()),
                **{str(t): int((aplicar_limiar(proba_do_fundo, modelo.classes_, t) != BENIGNO).sum()) for t in LIMIARES},
            }
        return {
            "reproducao": (
                _reproducao(modelo_salvo, publicado, X_teste, previsto, rotulos, teste)
                if modelo_salvo is not None and publicado is not None else None
            ),
            "limiar": _curva_do_limiar(proba, modelo.classes_, rotulos, previsto),
            "limiar_no_fundo": limiar_no_fundo,
            "seguidas": _seguidas(execucao, modelo, lados_da_divisao),
            "intervalos": _intervalos(previsto, y, arquivos, semente),
            "permutacao": _permutacoes(modelo, X_teste, y, execucao.features, semente),
        }

    return detalhe


# --- rodada f: o tamanho dos quadros; rodada i: o custo -----------------------------------------


def tamanhos(dados):
    """Fração das janelas com quadro menor que 60 bytes (`Min`) e maior que 1.514 (`Max`), por categoria e por pcap."""
    minimo, maximo = dados.X[:, FEATURES_39.index("Min")], dados.X[:, FEATURES_39.index("Max")]
    categoria = alvo(dados.meta["Label"].to_numpy(), ALVO)
    arquivos = dados.meta["arquivo"].to_numpy()
    por_categoria = {
        classe: {"janelas": int((categoria == classe).sum()),
                 "abaixo_de_60": int((minimo[categoria == classe] < QUADRO_MINIMO).sum()),
                 "acima_de_1514": int((maximo[categoria == classe] > QUADRO_MAXIMO).sum())}
        for classe in CLASSES
    }
    por_pcap = {
        arquivo: {"categoria": CATEGORIA[dados.meta["Label"].to_numpy()[arquivos == arquivo][0]],
                  "janelas": int((arquivos == arquivo).sum()),
                  "abaixo_de_60": int((minimo[arquivos == arquivo] < QUADRO_MINIMO).sum()),
                  "acima_de_1514": int((maximo[arquivos == arquivo] > QUADRO_MAXIMO).sum())}
        for arquivo in sorted(pd.unique(arquivos), key=str)
    }
    return {"por_categoria": por_categoria, "por_pcap": por_pcap}


_MEDIR_A_CARGA = """
import json, resource, sys, time
inicio = time.perf_counter()
import joblib, sklearn.ensemble
importar = time.perf_counter() - inicio
escala = 1 if sys.platform == "darwin" else 1024
antes = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * escala
inicio = time.perf_counter()
from codigo.classificador.treinar import carregar_modelo
carregar_modelo(sys.argv[1])
carga = time.perf_counter() - inicio
depois = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * escala
print(json.dumps({"importar_s": importar, "carga_s": carga, "memoria_antes": antes, "memoria_depois": depois}))
"""


def carga_num_processo_novo(caminho, vezes=3):
    """Tempo de importar o scikit-learn e de ler o modelo, e a memória do processo antes e depois, num processo novo."""
    ambiente = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, [os.getcwd(), os.environ.get("PYTHONPATH")]))}
    medidas = []
    for _ in range(vezes):
        saida = subprocess.run([sys.executable, "-c", _MEDIR_A_CARGA, str(caminho)], capture_output=True, text=True,
                               check=True, env=ambiente)
        medidas.append(json.loads(saida.stdout))
    return {chave: float(statistics.median(m[chave] for m in medidas)) for chave in medidas[0]}


def _arvores(modelo):
    nos = [estimador.tree_.node_count for estimador in modelo.estimators_]
    profundidades = [estimador.tree_.max_depth for estimador in modelo.estimators_]
    return {"nos": int(sum(nos)), "profundidade_media": float(np.mean(profundidades)),
            "profundidade_maxima": int(max(profundidades))}


def _tamanho_gravado(modelo):
    with tempfile.TemporaryDirectory() as pasta:
        caminho = Path(pasta) / "modelo.joblib"
        joblib.dump({"modelo": modelo}, caminho)
        return caminho.stat().st_size


def vazao_do_extrator(caminho):
    """Pacotes e janelas por segundo do extrator de janela de 100, com os endereços, lendo um pcap inteiro."""
    extrator = Extrator(JANELA, enderecos=True)
    pacotes = janelas = 0
    inicio = time.perf_counter()
    for ts, quadro in ler_pcap(caminho):
        pacotes += 1
        janelas += extrator.alimentar(ts, quadro) is not None
    janelas += extrator.finalizar() is not None
    segundos = time.perf_counter() - inicio
    return {"arquivo": Path(caminho).name, "pacotes": pacotes, "janelas": janelas, "segundos": segundos}


def custo(execucao, semente, modelo_salvo=None, dataset=None):
    """Rodada i: tamanho, memória, latência e lote do modelo, vazão do extrator, duração da janela e o RF menor."""
    dados = execucao.dados
    posicoes = execucao.amostra(semente)
    lados_da_divisao = lados(dados.regeracao, 0)
    meta = dados.meta.iloc[posicoes]
    teste = no_teste(meta, lados_da_divisao)
    X_teste = execucao._X(dados.X[posicoes[teste]])
    saida = {}
    if modelo_salvo is not None:
        modelo = carregar_modelo(modelo_salvo)["modelo"]
        modelo.n_jobs = 1
        saida["modelo"] = {
            "arquivo": Path(modelo_salvo).name, "bytes": Path(modelo_salvo).stat().st_size, **_arvores(modelo),
            "carga": carga_num_processo_novo(modelo_salvo),
            "latencia_predict": latencia(modelo.predict, X_teste),
            "latencia_predict_proba": latencia(modelo.predict_proba, X_teste),
            "lote_de_1000_ms": em_lote(modelo.predict, X_teste),
        }
        del modelo
    if dataset is not None and (Path(dataset) / PCAP_DA_VAZAO).exists():
        saida["vazao"] = vazao_do_extrator(Path(dataset) / PCAP_DA_VAZAO)
    duracao = _duracao(dados.X[posicoes])
    categoria = alvo(meta["Label"].to_numpy(), ALVO)
    saida["duracao_da_janela"] = {
        classe: dict(zip(("mediana", "p90", "p99"), np.percentile(duracao[categoria == classe], [50, 90, 99]).tolist()))
        for classe in CLASSES if (categoria == classe).any()
    }
    # O Random Forest menor: a mesma divisão e a mesma semente, com menos árvores.
    X, y = execucao._treino(posicoes, teste, lados_da_divisao)
    menor, segundos = execucao._treinar(X, y, semente, ARVORES_MENOR)
    menor.n_jobs = 1
    saida["menor"] = {
        "arvores": ARVORES_MENOR, "treino_segundos": segundos, "bytes": _tamanho_gravado(menor), **_arvores(menor),
        "latencia_predict": latencia(menor.predict, X_teste), "lote_de_1000_ms": em_lote(menor.predict, X_teste),
        "medidas": resumo_das_medidas(prever(menor, X_teste), meta["Label"].to_numpy()[teste]),
    }
    del menor
    saida["menor"]["rotacao"] = {
        str(rotacao): execucao._rotacao(semente, rotacao, ARVORES_MENOR)["de_fora"]
        for rotacao in range(1, rotacoes(dados.regeracao))
    }
    return saida


# --- as execuções -----------------------------------------------------------------------------


def _ler_json(caminho):
    return json.loads(Path(caminho).read_text(encoding="utf-8"))


def _conferir_opcoes(configuracao, regeracao):
    """A pasta da configuração tem de ter sido regerada com as opções do extrator que ela pede."""
    registradas = regeracao.get("extrator", {}).get("opcoes", {})
    pedidas = dict(configuracao.opcoes)
    if {chave: valor for chave, valor in registradas.items() if valor} != pedidas:
        raise ValueError(
            f"configuração {configuracao.nome}: {configuracao.regeracao} registra as opções {registradas or 'nenhuma'}, "
            f"e a configuração pede {pedidas or 'nenhuma'}"
        )


def _por_semente(resultados):
    return {str(r["semente"]): r for r in resultados}


def rodar_sistema(dados, rodadas=RODADAS, sementes=SEMENTES, arvores=ARVORES, nucleos=TODOS_OS_NUCLEOS, teto=TETO,
                  trabalho=TRABALHO, modelo_salvo=None, publicado=None, dataset=None, pcaps_fora=PCAPS_FORA):
    """As rodadas pedidas sobre o modelo do sistema. Devolve os resultados, por rodada e por semente."""
    rodadas = set(rodadas)
    execucao = Execucao(ATUAL, dados, arvores, nucleos, teto, trabalho)
    principal, controle = sementes[0], list(sementes[:SEMENTES_DE_CONTROLE])
    detalhe = detalhar(modelo_salvo, publicado) if rodadas & set("afgh") else None
    if "b" in rodadas:
        sementes_do_corte = list(sementes)
    elif rodadas & set("cdefh"):
        sementes_do_corte = controle
    else:
        sementes_do_corte = [principal]
    saida = {"rodadas": sorted(rodadas), "corte": {}, "rotacao": {}, "fora": {}, "sem_ttl": {}}
    saida["corte"] = _por_semente(
        execucao.corte(semente, detalhe if semente == principal else None) for semente in sementes_do_corte
    )
    if rodadas & set("cg"):
        for rotacao in range(1, rotacoes(dados.regeracao)):
            saida["rotacao"][str(rotacao)] = _por_semente(
                execucao.rotacao(semente, rotacao) for semente in (controle if "c" in rodadas else [principal])
            )
    if "e" in rodadas:
        saida["fora"] = {
            arquivo: _por_semente(execucao.fora(semente, arquivo) for semente in controle) for arquivo in pcaps_fora
        }
    if "f" in rodadas:
        saida["tamanhos"] = tamanhos(dados)
        sem_ttl = Execucao(
            Configuracao("0", "sem Time_To_Live", ATUAL.destino, ATUAL.regeracao, sem=("Time_To_Live",)),
            dados, arvores, nucleos, teto, trabalho,
        )
        saida["sem_ttl"] = _por_semente(sem_ttl.corte(semente) for semente in controle)
    if "i" in rodadas:
        saida["custo"] = execucao._guardado(f"custo|{principal}", lambda: custo(execucao, principal, modelo_salvo, dataset))
    return saida


def rodar_capturas(configuracoes=CONFIGURACOES, sementes=SEMENTES, arvores=ARVORES, nucleos=TODOS_OS_NUCLEOS,
                   teto=TETO, trabalho=TRABALHO, pcaps_fora=PCAPS_FORA, ler=ler_dados, ao_ler=None):
    """O corte por tempo e as rodadas c, d e e em cada configuração, com as primeiras sementes de controle."""
    controle = list(sementes[:SEMENTES_DE_CONTROLE])
    saida, entradas, carregados = {}, {}, (None, None)
    for configuracao in configuracoes:
        regeracao = _ler_json(configuracao.regeracao)
        _conferir_opcoes(configuracao, regeracao)
        if carregados[0] != configuracao.destino:
            carregados = (None, None)  # libera a memória da pasta anterior antes de ler a próxima
            carregados = (configuracao.destino, ler(configuracao.destino, regeracao, ao_ler))
        dados = carregados[1]
        execucao = Execucao(configuracao, dados, arvores, nucleos, teto, trabalho)
        resultado = {"corte": {}, "rotacao": {}, "fora": {}}
        for semente in controle:
            resultado["corte"][str(semente)] = execucao.corte(semente)
            for rotacao in range(1, rotacoes(regeracao)):
                resultado["rotacao"].setdefault(str(rotacao), {})[str(semente)] = execucao.rotacao(semente, rotacao)
            for arquivo in pcaps_fora:
                resultado["fora"].setdefault(arquivo, {})[str(semente)] = execucao.fora(semente, arquivo)
        if configuracao.destino not in entradas:
            resultado["tamanhos"] = tamanhos(dados)
            entradas[configuracao.destino] = {
                "regeracao": {"manifesto": configuracao.regeracao, "sha256": _sha256(configuracao.regeracao),
                              "extrator": regeracao.get("extrator")},
                "arquivos": dados.entradas,
            }
        saida[configuracao.nome] = resultado
    return saida, entradas


# --- números para o relatório ------------------------------------------------------------------


def _fracao(parte, total):
    return parte / total if total else None


def _ataques(previstas):
    """Janelas previstas em alguma categoria de ataque."""
    return sum(quantas for classe, quantas in previstas.items() if classe != BENIGNO)


def _media(valores):
    valores = [v for v in valores if v is not None]
    return float(np.mean(valores)) if valores else None


def _desvio(valores):
    valores = [v for v in valores if v is not None]
    return float(np.std(valores, ddof=1)) if len(valores) > 1 else None


def _com_faixa(valores, casas=2):
    """A média e, com mais de um valor, o menor e o maior entre parênteses."""
    valores = [v for v in valores if v is not None]
    if not valores:
        return "sem valor"
    if len(valores) == 1:
        return _pct(valores[0], casas)
    return f"{_pct(float(np.mean(valores)), casas)} ({_pct(min(valores), casas)} a {_pct(max(valores), casas)})"


def passa_do_ruido(uns, outros):
    """Se a diferença entre duas condições passa do ruído de semente: as faixas das sementes não se cruzam."""
    uns, outros = [v for v in uns if v is not None], [v for v in outros if v is not None]
    if not uns or not outros:
        return False
    return max(uns) < min(outros) or max(outros) < min(uns)


def _leitura(uns, outros):
    """A diferença entre as médias de duas condições, em pontos, e se passa do ruído de semente."""
    diferenca = _media(outros) - _media(uns)
    if not passa_do_ruido(uns, outros):
        return f"{_pp(diferenca)} p.p., sem diferença"
    return f"{_pp(diferenca)} p.p., acima do ruído"


def _controle(m):
    return [str(s) for s in m["parametros"]["sementes"][:m["parametros"]["sementes_de_controle"]]]


def _nas_sementes(registros, sementes):
    return [registros[s] for s in sementes if s in registros]


def _benigno_de_fora(unidade):
    return next((p for p in unidade["de_fora"] if p["categoria"] == BENIGNO), None)


def rotacoes_do_benigno(resultado, sementes):
    """Para cada rotação, o pcap benigno de fora e, por semente, as janelas e as previstas nele."""
    saida = []
    rotacoes_ = [("0", resultado["corte"]), *sorted(resultado.get("rotacao", {}).items())]
    for rotacao, por_semente in rotacoes_:
        unidades = _nas_sementes(por_semente, sementes)
        if not unidades:
            continue
        benignos = [_benigno_de_fora(u) for u in unidades]
        saida.append({
            "rotacao": rotacao, "arquivo": benignos[0]["arquivo"], "janelas": benignos[0]["janelas"],
            "como_ataque": [_fracao(_ataques(b["previstas"]), b["janelas"]) for b in benignos],
            "previstas": [b["previstas"] for b in benignos],
            "outros": [[p for p in u["de_fora"] if p["categoria"] != BENIGNO] for u in unidades],
            "macro_f1": [u["medidas"]["macro_f1"] for u in unidades],
            "sementes": [str(u["semente"]) for u in unidades],
            "alarmes": [u.get("alarmes_no_benigno") for u in unidades],
        })
    return saida


def pior_benigno(resultado, sementes):
    """Por semente, a maior fração de benigno classificado como ataque entre os pcaps benignos de fora."""
    rotacoes_ = rotacoes_do_benigno(resultado, sementes)
    por_semente = {}
    for r in rotacoes_:
        for semente, fracao in zip(r["sementes"], r["como_ataque"]):
            por_semente.setdefault(semente, []).append(fracao)
    completas = [max(v) for v in por_semente.values() if len(v) == len(rotacoes_)]
    return completas


def benigno_no_total(resultado, sementes):
    """Por semente, as janelas benignas de todos os pcaps de fora somadas: a fração classificada como ataque."""
    rotacoes_ = rotacoes_do_benigno(resultado, sementes)
    somas = {}
    for r in rotacoes_:
        for semente, previstas in zip(r["sementes"], r["previstas"]):
            ataque, janelas = somas.get(semente, (0, 0))
            somas[semente] = (ataque + _ataques(previstas), janelas + r["janelas"])
    return [_fracao(a, n) for a, n in somas.values()]


def fundo_por_semente(resultado, sementes, parte="teste"):
    """Por semente, a fração das janelas de fundo de todos os pcaps de ataque, numa parte, classificada como ataque."""
    saida = []
    for unidade in _nas_sementes(resultado["corte"], sementes):
        janelas = sum(p[parte]["janelas"] for p in unidade["fundo"])
        saida.append(_fracao(sum(_ataques(p[parte]["previstas"]) for p in unidade["fundo"]), janelas))
    return saida


def recall_fora(resultado, sementes, categoria, medida="na_categoria", trecho="teste"):
    """Por semente, o acerto somado nos pcaps de uma categoria quando cada um sai do treino."""
    saida = []
    for semente in sementes:
        acertos = janelas = 0
        for por_semente in resultado.get("fora", {}).values():
            unidade = por_semente.get(semente)
            if unidade is None or unidade["categoria"] != categoria:
                continue
            previstas = unidade[trecho]["previstas"]
            acertos += previstas[categoria] if medida == "na_categoria" else _ataques(previstas)
            janelas += unidade[trecho]["janelas"]
        if janelas:
            saida.append(acertos / janelas)
    return saida


def recall_dentro(resultado, sementes, categoria, arquivos, medida="na_categoria"):
    """Por semente, o acerto do treino com o pcap dentro, nas mesmas janelas de teste dos pcaps dados."""
    saida = []
    for unidade in _nas_sementes(resultado["corte"], sementes):
        acertos = janelas = 0
        for arquivo in arquivos:
            p = unidade["por_pcap"].get(arquivo)
            if p is None:
                continue
            acertos += p["previstas"][categoria] if medida == "na_categoria" else _ataques(p["previstas"])
            janelas += p["janelas"]
        if janelas:
            saida.append(acertos / janelas)
    return saida


def _do_corte(resultado, sementes, funcao):
    return [funcao(u["medidas"]) for u in _nas_sementes(resultado["corte"], sementes)]


def _data(m):
    return datetime.date.fromisoformat(m["gerado_em"]).strftime("%d/%m/%Y")


def _versoes(m):
    v = m["versoes"]
    return f"Python {v['python']}, scikit-learn {v['scikit-learn']}, pandas {v['pandas']} e numpy {v['numpy']}"


# --- o relatório das rodadas do modelo do sistema ----------------------------------------------


def _cabecalho(m):
    r = m["resultados"]
    p = m["parametros"]
    return [
        "# Rodadas de teste do modelo de janela de 100",
        "",
        f"Gerado por `{m['gerado_por']}` em {_data(m)}, com {_versoes(m)}.",
        "",
        "O modelo do sistema é o Random Forest de 7 categorias treinado nos dados regerados com janela de 100",
        "quadros (`regeracao.md`). O relatório da regeração mede uma divisão por tempo, com uma semente e só nas",
        "janelas que têm um quadro do atacante. As rodadas abaixo refazem o treino com as mesmas funções (leitura",
        "com teto, divisão por tempo, treino e avaliação) e medem o que aquela divisão não mostra. Cada rodada diz",
        "o que foi feito, traz os números e diz o que eles mostram, sem recomendar uma saída.",
        "",
        (
            f"Rodadas feitas: {_enumerar(r['rodadas'])}. Em cada treino, a semente define ao mesmo tempo o sorteio do "
            f"teto de {_milhar(p['teto'])} linhas por rótulo e o Random Forest. A rodada b usa as sementes "
            f"{_enumerar(p['sementes'])}; as que treinam um modelo por rotação ou por pcap usam as "
            f"{p['sementes_de_controle']} primeiras. Nas tabelas, um valor com parênteses é a média das sementes, "
            "com o menor e o maior entre parênteses."
        ),
        "",
        "Uma diferença entre duas condições só é tratada como diferença quando as faixas das sementes não se",
        "cruzam; dentro delas, é \"sem diferença\".",
    ]


def _secao_a(m):
    unidade = m["resultados"]["corte"].get(str(m["parametros"]["sementes"][0]), {})
    reproducao = unidade.get("detalhe", {}).get("reproducao")
    if reproducao is None:
        return []
    publicadas = reproducao["linhas_publicadas"]
    iguais = reproducao["divisao_igual"]
    linhas = [
        ["Linhas de treino e de teste", f"{_milhar(reproducao['linhas']['treino'])} e {_milhar(reproducao['linhas']['teste'])}"
         + (" (iguais às publicadas)" if (reproducao["linhas"]["treino"], reproducao["linhas"]["teste"])
            == (publicadas["treino"], publicadas["teste"]) else " (diferentes das publicadas)")],
        ["SHA-256 das posições de treino e de teste", "iguais aos de `manifesto_treino_regerado.json`"
         if iguais["treino"] and iguais["teste"] else "diferentes dos de `manifesto_treino_regerado.json`"],
        ["`treino_sha256` gravado no modelo", "igual" if iguais["treino_do_modelo"] else "diferente"],
        ["Medidas do modelo salvo no teste refeito", (f"{reproducao['medidas_conferidas']} conferidas, "
                                                      f"{len(reproducao['medidas_diferentes'])} diferentes das publicadas")],
        ["Matriz de confusão por rótulo", "idêntica à publicada" if reproducao["matriz_por_rotulo_igual"] else "diferente"],
        ["Predições do retreino com a semente 42 contra as do modelo salvo",
         (f"{_milhar(reproducao['predicoes_diferentes_do_retreino'])} diferentes em "
          f"{_milhar(reproducao['janelas_de_teste'])} janelas")],
    ]
    modelo = reproducao["modelo"]
    return [
        "## a. Reprodução do modelo publicado",
        "",
        (
            f"**O que foi feito.** O modelo salvo `{modelo['arquivo']}` (SHA-256 `{modelo['sha256'][:16]}…`, semente "
            f"{modelo['semente']}, {modelo['arvores']} árvores) classificou a parte de teste refeita com a leitura, o "
            "teto e a divisão do repositório, e as medidas foram comparadas com as de `manifesto_treino_regerado.json`. "
            "O modelo foi treinado de novo com a semente 42 e as predições dos dois foram comparadas janela a janela."
        ),
        "",
        *_tabela(["Conferência", "Resultado"], linhas),
    ]


def _medidas_globais(medidas):
    return [
        ("Macro-F1", lambda a: a["macro_f1"]),
        ("Acurácia", lambda a: a["acuracia"]),
        ("Benigno classificado como ataque", lambda a: a["benigno_como_ataque"]),
        ("Ataque classificado como benigno", lambda a: a["ataque_como_benigno"]),
        *((f"Recall {classe}", lambda a, c=classe: a["por_classe"][c]["recall"]) for classe in CLASSES),
        *((f"F1 {classe}", lambda a, c=classe: a["por_classe"][c]["f1"]) for classe in CLASSES),
    ]


def _secao_b(m):
    corte = m["resultados"]["corte"]
    if len(corte) < 2:
        return []
    sementes = list(corte)
    linhas = []
    for nome, funcao in _medidas_globais(None):
        valores = [funcao(corte[s]["medidas"]) for s in sementes]
        desvio = _desvio(valores)
        linhas.append([
            nome, _pct(valores[0]), _pct(_media(valores)), "sem valor" if desvio is None else f"{_pp(desvio).lstrip('+')} p.p.",
            f"{_pct(min(valores))} a {_pct(max(valores))}",
        ])
    macro = [corte[s]["medidas"]["macro_f1"] for s in sementes]
    benigno = [corte[s]["medidas"]["benigno_como_ataque"] for s in sementes]
    return [
        "## b. Sementes",
        "",
        (
            f"**O que foi feito.** O treino da divisão por tempo com as sementes {_enumerar(sementes)}. A divisão por "
            "tempo não sorteia; a semente muda quais linhas dos rótulos acima do teto entram e o Random Forest. "
            "Desvio amostral (n − 1)."
        ),
        "",
        *_tabela(["Medida", f"Semente {sementes[0]}", "Média", "Desvio", "Menor a maior"], linhas),
        "",
        (
            f"**O que os números mostram.** O macro-F1 varia {_pp(max(macro) - min(macro)).lstrip('+')} p.p. entre as "
            f"sementes e o benigno classificado como ataque, {_pp(max(benigno) - min(benigno)).lstrip('+')} p.p. "
            "As categorias com poucas janelas de teste variam mais. É essa a faixa que as outras rodadas usam como "
            "ruído."
        ),
    ]


def _distribuicao(previstas_por_semente, janelas, classes):
    return [_com_faixa([_fracao(p[c], janelas) for p in previstas_por_semente]) for c in classes]


def _secao_c(m):
    r = m["resultados"]
    controle = _controle(m)
    rotacoes_ = rotacoes_do_benigno(r, controle)
    if len(rotacoes_) < 2:
        return []
    ataques = [c for c in CLASSES if c != BENIGNO and c in ("Recon", "DDoS+DoS", "Spoofing", "Web")]
    linhas = []
    for rot in rotacoes_:
        outros = {}
        for lista in rot["outros"]:
            for p in lista:
                outros.setdefault(p["arquivo"], []).append(_fracao(p["previstas"][p["categoria"]], p["janelas"]))
        linhas.append([
            rot["rotacao"] + (" (publicada)" if rot["rotacao"] == "0" else ""), f"`{rot['arquivo']}`",
            _milhar(rot["janelas"]), _com_faixa(rot["como_ataque"]),
            *_distribuicao(rot["previstas"], rot["janelas"], ataques),
            "; ".join(f"`{arquivo}` {_com_faixa(v)}" for arquivo, v in outros.items()) or "nenhum",
            _com_faixa(rot["macro_f1"]),
        ])
    total = benigno_no_total(r, controle)
    pior = pior_benigno(r, controle)
    medias = [(rot["arquivo"], _media(rot["como_ataque"])) for rot in rotacoes_]
    melhor, pior_pcap = min(medias, key=lambda par: par[1]), max(medias, key=lambda par: par[1])
    return [
        "## c. Rotação do pcap de fora do treino",
        "",
        (
            "**O que foi feito.** Nos rótulos com mais de um pcap (o benigno e os dois SYN), um pcap fica inteiro "
            "fora do treino. A divisão publicada deixa de fora o último pela ordem do nome; aqui o pcap de fora anda "
            "uma posição a cada rotação, até cada pcap benigno ficar de fora uma vez. Os rótulos de um pcap só "
            "mantêm o corte por tempo. A medida é no pcap de fora inteiro, com todas as janelas dele, e não só nas "
            "que o teto sorteou."
        ),
        "",
        *_tabela(
            ["Rotação", "Pcap benigno de fora", "Janelas", "Benigno como ataque",
             *(f"Como {c}" for c in ataques), "Outros pcaps de fora: na categoria", "Macro-F1 no teste com teto"],
            linhas,
        ),
        "",
        (
            f"Somando as janelas dos {len(rotacoes_)} pcaps benignos, cada um com o modelo que não o viu, "
            f"{_com_faixa(total)} viram ataque. O pior pcap benigno de fora, por semente, fica em {_com_faixa(pior)}."
        ),
        "",
        (
            f"**O que os números mostram.** O alarme falso do pcap benigno de fora vai de {_pct(melhor[1])} "
            f"(`{melhor[0]}`) a {_pct(pior_pcap[1])} (`{pior_pcap[0]}`), conforme o pcap que fica fora do treino. O "
            "número publicado é o de uma das rotações."
        ),
    ]


def _secao_d(m):
    r = m["resultados"]
    controle = _controle(m)
    unidades = _nas_sementes(r["corte"], controle)
    if not unidades or not unidades[0]["fundo"]:
        return []
    extraidas = m["entradas"]["regeracao"]["extraidas"]
    linhas = []
    por_pcap = {}
    for u in unidades:
        for p in u["fundo"]:
            por_pcap.setdefault(p["arquivo"], []).append(p)
    for arquivo, registros in sorted(por_pcap.items(), key=lambda par: -(par[1][0]["treino"]["janelas"]
                                                                       + par[1][0]["teste"]["janelas"])):
        primeiro = registros[0]
        total = primeiro["treino"]["janelas"] + primeiro["teste"]["janelas"]
        if total == 0:
            continue
        celulas = [f"`{arquivo}`", primeiro["categoria"], f"{_milhar(total)} / {_milhar(extraidas[arquivo])}"]
        for parte in ("treino", "teste"):
            janelas = primeiro[parte]["janelas"]
            celulas += [
                _milhar(janelas),
                _com_faixa([_fracao(_ataques(p[parte]["previstas"]), janelas) for p in registros], 1) if janelas else "-",
                _com_faixa([_fracao(p[parte]["previstas"][p["categoria"]], janelas) for p in registros], 1)
                if janelas else "-",
            ]
        soma = {c: sum(p["teste"]["previstas"][c] for p in registros) for c in CLASSES if c != BENIGNO}
        celulas.append(max(soma, key=soma.get) if sum(soma.values()) else "nenhum")
        linhas.append(celulas)
    teste, treino = fundo_por_semente(r, controle, "teste"), fundo_por_semente(r, controle, "treino")
    benigno = [_fracao(_ataques(_benigno_de_fora(u)["previstas"]), _benigno_de_fora(u)["janelas"]) for u in unidades]
    secao = [
        "## d. Tráfego de fundo dos pcaps de ataque",
        "",
        (
            "**O que foi feito.** As janelas que a regra de rótulo descarta, sem nenhum quadro de um MAC atacante, "
            "estão gravadas à parte desde a versão 2 da regeração (`descartadas/`). O modelo da divisão por tempo "
            "classificou todas elas. Cada janela fica na parte de treino ou na de teste do seu pcap pelo mesmo corte "
            "da divisão: o modelo nunca viu nenhuma delas, mas as da parte de treino são do mesmo trecho de captura "
            "das janelas com que ele treinou. Nos SYN, o pcap de fora é todo teste e o outro, todo treino."
        ),
        "",
        *_tabela(
            ["Pcap", "Categoria", "Fundo / janelas", "Treino: janelas", "Treino: como ataque",
             "Treino: na categoria do pcap", "Teste: janelas", "Teste: como ataque", "Teste: na categoria do pcap",
             "Ataque mais previsto no teste"],
            linhas,
        ),
        "",
        (
            f"Juntando os pcaps, na parte de teste {_com_faixa(teste)} das janelas de fundo viram ataque, e na "
            f"de treino, {_com_faixa(treino)}. No pcap benigno de fora da divisão publicada, {_com_faixa(benigno)}."
        ),
    ]
    detalhe = r["corte"].get(controle[0], {}).get("detalhe", {})
    limiar = detalhe.get("limiar_no_fundo", {})
    if limiar.get("janelas"):
        candidatos = [str(t) for t in (0.55, 0.65, 0.75) if str(t) in limiar["como_ataque"]]
        secao += [
            "",
            "Com o limiar da rodada g, na parte de teste e na semente principal: "
            + "; ".join(
                f"t = {t.replace('.', ',')}: {_pct(_fracao(limiar['como_ataque'][t], limiar['janelas']))}"
                for t in ["argmax", *candidatos]
            ).replace("t = argmax", "argmax") + ".",
        ]
    quadros = unidades[0].get("por_quadros_do_atacante")
    if quadros:
        faixas = [f"{de}-{ate}" for de, ate in FAIXAS_DE_QUADROS]
        por_categoria = []
        for classe, por_faixa in quadros.items():
            fundo = [p for p in unidades[0]["fundo"] if p["categoria"] == classe]
            janelas_fundo = sum(p["teste"]["janelas"] for p in fundo)
            celulas = [classe, (f"{_pct(_fracao(sum(p['teste']['previstas'][classe] for p in fundo), janelas_fundo), 0)} "
                                f"({_milhar(janelas_fundo)})") if janelas_fundo else "-"]
            celulas += [
                f"{_pct(_fracao(por_faixa[f]['na_categoria'], por_faixa[f]['janelas']), 0)} ({_milhar(por_faixa[f]['janelas'])})"
                if por_faixa[f]["janelas"] else "-"
                for f in faixas
            ]
            por_categoria.append(celulas)
        secao += [
            "",
            (
                "Quantos quadros do atacante há na janela, na parte de teste e na semente principal: a fração na "
                "categoria do pcap, com as janelas entre parênteses. A coluna 0 é o fundo."
            ),
            "",
            *_tabela(["Categoria", "0 (fundo)", *(str(de) if de == ate else f"{de} a {ate}" for de, ate in FAIXAS_DE_QUADROS)],
                     por_categoria),
        ]
    grandes = []
    for arquivo, registros in por_pcap.items():
        janelas = registros[0]["teste"]["janelas"]
        if janelas >= 100:
            grandes.append((_media([_fracao(p["teste"]["previstas"][p["categoria"]], janelas) for p in registros]),
                            arquivo, janelas))
    grandes.sort(reverse=True)
    secao += [
        "",
        (
            "Entre os pcaps com ao menos 100 janelas de fundo na parte de teste, as maiores frações na categoria do "
            "próprio pcap são as de " + _enumerar(f"`{arquivo}` ({_pct(fracao, 1)} de {_milhar(janelas)})"
                                               for fracao, arquivo, janelas in grandes[:4]) + "."
        ) if grandes else "",
    ]
    secao += [
        "",
        (
            "**O que os números mostram.** A coluna \"na categoria do pcap\" é a fração do fundo que o modelo põe na "
            "categoria do ataque daquela captura, sem nenhum quadro do atacante na janela. Onde ela fica perto do "
            "recall das janelas com atacante, a categoria acompanha a captura, e não o ataque. Parte do fundo pode "
            "conter efeito do ataque, então a fração de fundo classificada como ataque é uma estimativa pessimista do "
            "alarme falso durante um ataque."
        ),
    ]
    return secao


def _secao_e(m):
    r = m["resultados"]
    controle = _controle(m)
    if not r.get("fora"):
        return []
    linhas = []
    for arquivo, por_semente in r["fora"].items():
        unidades = _nas_sementes(por_semente, controle)
        if not unidades:
            continue
        categoria = unidades[0]["categoria"]
        janelas = unidades[0]["teste"]["janelas"]
        linhas.append([
            f"`{arquivo}`", categoria, _milhar(janelas),
            _com_faixa(recall_dentro(r, controle, categoria, [arquivo])),
            _com_faixa([_fracao(u["teste"]["previstas"][categoria], u["teste"]["janelas"]) for u in unidades]),
            _com_faixa(recall_dentro(r, controle, categoria, [arquivo], "como_ataque")),
            _com_faixa([_fracao(_ataques(u["teste"]["previstas"]), u["teste"]["janelas"]) for u in unidades]),
            _com_faixa([_fracao(u["inteiro"]["previstas"][categoria], u["inteiro"]["janelas"]) for u in unidades]),
        ])
    categorias = []
    for categoria in CLASSES:
        arquivos = [a for a, s in r["fora"].items() if next(iter(s.values()))["categoria"] == categoria]
        if not arquivos:
            continue
        dentro, fora = recall_dentro(r, controle, categoria, arquivos), recall_fora(r, controle, categoria)
        categorias.append([categoria, len(arquivos), _com_faixa(dentro), _com_faixa(fora), _leitura(dentro, fora)])
    quedas = []
    for arquivo, por_semente in r["fora"].items():
        unidades = _nas_sementes(por_semente, controle)
        categoria = unidades[0]["categoria"]
        fora = [_fracao(u["teste"]["previstas"][categoria], u["teste"]["janelas"]) for u in unidades]
        dentro = recall_dentro(r, controle, categoria, [arquivo])
        if categoria != "BruteForce" and passa_do_ruido(dentro, fora):
            quedas.append((_media(dentro) - _media(fora), arquivo))
    maiores = sorted(quedas, reverse=True)[:4]
    return [
        "## e. Pcap inteiro fora do treino",
        "",
        (
            "**O que foi feito.** Para cada pcap da lista, o modelo foi treinado sem nenhuma janela dele, com o resto "
            "igual à divisão publicada, e classificou as janelas dele. \"Dentro da captura\" é o modelo da divisão "
            "publicada, que treinou com o começo do mesmo pcap, nas mesmas janelas de teste. Cada pcap de Recon e de "
            "Web é uma técnica diferente, então tirar o pcap tira também a técnica do treino; o pcap de BruteForce é "
            "o único da categoria, e sem ele a categoria some do treino."
        ),
        "",
        *_tabela(
            ["Pcap", "Categoria", "Janelas de teste", "Na categoria, dentro da captura", "Na categoria, pcap fora",
             "Como ataque, dentro", "Como ataque, pcap fora", "Pcap inteiro fora: na categoria"],
            linhas,
        ),
        "",
        "Somando os pcaps de cada categoria, nas janelas de teste:",
        "",
        *_tabela(["Categoria", "Pcaps", "Recall dentro da captura", "Recall com o pcap fora", "Diferença"], categorias),
        "",
        (
            "**O que os números mostram.** O recall dentro da captura mede o reconhecimento de um trecho seguinte "
            "da mesma captura; o recall com o pcap fora mede o reconhecimento de uma captura que o modelo não viu. A "
            "distância entre os dois, por categoria, está na última coluna."
            + (" Fora BruteForce, as maiores quedas por pcap são em "
               + _enumerar(f"`{arquivo}` ({_pp(-queda)} p.p.)" for queda, arquivo in maiores) + "." if maiores else "")
        ),
    ]


def _secao_f(m):
    r = m["resultados"]
    controle = _controle(m)
    if "tamanhos" not in r:
        return []
    t = r["tamanhos"]
    linhas = [
        [classe, _milhar(v["janelas"]), _pct(_fracao(v["abaixo_de_60"], v["janelas"])),
         _pct(_fracao(v["acima_de_1514"], v["janelas"]))]
        for classe, v in t["por_categoria"].items()
    ]
    pcaps = [
        [f"`{arquivo}`", v["categoria"], _milhar(v["janelas"]), _pct(_fracao(v["abaixo_de_60"], v["janelas"])),
         _pct(_fracao(v["acima_de_1514"], v["janelas"]))]
        for arquivo, v in t["por_pcap"].items() if v["abaixo_de_60"] or v["categoria"] == BENIGNO
    ]
    secao = [
        "## f. Atalhos da captura",
        "",
        "### Tamanho dos quadros",
        "",
        (
            "**O que foi feito.** Em todas as janelas mantidas, a fração com algum quadro menor que 60 bytes (`Min`), "
            "que é o quadro sem o preenchimento do Ethernet, e com algum quadro maior que 1.514 bytes (`Max`), que só "
            "existe quando a captura é feita na máquina que envia, com segmentação feita pela placa de rede. Os dois "
            "dependem de como a captura foi gravada, e não do ataque."
        ),
        "",
        *_tabela(["Categoria", "Janelas", "Com quadro menor que 60 bytes", "Com quadro maior que 1.514 bytes"], linhas),
        "",
        "Os pcaps com algum quadro menor que 60 bytes, e os benignos:",
        "",
        *_tabela(["Pcap", "Categoria", "Janelas", "Com quadro menor que 60 bytes", "Com quadro maior que 1.514 bytes"],
                 pcaps),
    ]
    sem_ttl = r.get("sem_ttl", {})
    if sem_ttl:
        com, sem = _nas_sementes(r["corte"], controle), _nas_sementes(sem_ttl, controle)
        medidas = [
            ("Macro-F1", lambda a: a["macro_f1"]), ("Benigno classificado como ataque", lambda a: a["benigno_como_ataque"]),
            *((f"Recall {c}", lambda a, c=c: a["por_classe"][c]["recall"]) for c in CLASSES if c != BENIGNO),
        ]
        linhas = [[nome, _com_faixa([f(u["medidas"]) for u in com]), _com_faixa([f(u["medidas"]) for u in sem]),
                   _leitura([f(u["medidas"]) for u in com], [f(u["medidas"]) for u in sem])] for nome, f in medidas]
        fora_com = [_fracao(_ataques(_benigno_de_fora(u)["previstas"]), _benigno_de_fora(u)["janelas"]) for u in com]
        fora_sem = [_fracao(_ataques(_benigno_de_fora(u)["previstas"]), _benigno_de_fora(u)["janelas"]) for u in sem]
        linhas.append([f"Pcap benigno de fora (`{_benigno_de_fora(com[0])['arquivo']}`) como ataque", _com_faixa(fora_com),
                       _com_faixa(fora_sem), _leitura(fora_com, fora_sem)])
        secao += [
            "",
            "### TTL",
            "",
            "**Ablação.** O mesmo treino, nas mesmas sementes, sem a coluna `Time_To_Live`.",
            "",
            *_tabela(["Medida", "39 features", "Sem `Time_To_Live`", "Diferença"], linhas),
        ]
    ttls = [u["ttl"] for u in _nas_sementes(r["corte"], controle) if u.get("ttl")]
    if ttls:
        faixas = []
        for i, faixa in enumerate(ttls[0]["faixas"]):
            rotulo = ("até " + str(faixa["ate"])) if faixa["acima_de"] is None else (
                f"acima de {faixa['acima_de']}" if faixa["ate"] is None else f"{faixa['acima_de']} a {faixa['ate']}")
            janelas = faixa["janelas"]
            faixas.append([rotulo, _milhar(janelas),
                           _com_faixa([_fracao(t["faixas"][i]["como_ataque"], janelas) for t in ttls], 1)])
        fixado = [[valor, _com_faixa([_fracao(t["fixado"][valor], t["janelas"]) for t in ttls], 1)]
                  for valor in ttls[0]["fixado"]]
        secao += [
            "",
            (
                f"**Janelas benignas de TTL baixo.** As janelas de `{ttls[0]['arquivo']}`, que o modelo da divisão "
                "publicada não viu, pelo TTL médio da janela, e as mesmas janelas com o TTL trocado por um valor fixo:"
            ),
            "",
            *_tabela(["TTL médio da janela", "Janelas", "Como ataque"], faixas),
            "",
            *_tabela(["TTL de todas as janelas trocado por", "Como ataque"], fixado),
        ]
    detalhe = r["corte"].get(controle[0], {}).get("detalhe", {})
    permut = detalhe.get("permutacao")
    if permut:
        linhas = []
        for classe, registro in permut["por_categoria"].items():
            if registro["base"] is None:
                continue
            maiores = sorted(registro["quedas"].items(), key=lambda par: -par[1][0])[:5]
            linhas.append([classe, f"{_pct(registro['base'])} ({_milhar(registro['janelas'])})",
                           "; ".join(f"`{f}` {_pp(q[0]).lstrip('+')}" for f, q in maiores)])
        globais = sorted(permut["macro_f1"]["quedas"].items(), key=lambda par: -par[1][0])[:6]
        impureza = sorted(permut["impureza"].items(), key=lambda par: -par[1])[:6]
        secao += [
            "",
            "### Importância por permutação",
            "",
            (
                "**O que foi feito.** No modelo da semente principal, cada feature das janelas de teste de uma "
                f"categoria foi trocada pelo valor de uma janela de teste qualquer, {REPETICOES_DA_PERMUTACAO} vezes, "
                f"com até {_milhar(SUBAMOSTRA_DA_PERMUTACAO)} janelas da categoria. A queda é a do recall, em pontos."
            ),
            "",
            *_tabela(["Categoria", "Recall de base (janelas)", "Features que mais derrubam o recall (p.p.)"], linhas),
            "",
            (
                "No macro-F1, numa subamostra com até a mesma quantidade de janelas de cada categoria: "
                + "; ".join(f"`{f}` {_pp(q[0]).lstrip('+')}" for f, q in globais)
                + " p.p. Pela redução de impureza, a medida que o relatório da regeração lista: "
                + "; ".join(f"`{f}` {_pct(v, 1)}" for f, v in impureza) + "."
            ),
        ]
    return secao


def candidatos_do_limiar(curva, alvos=ALVOS_DO_LIMIAR):
    """Para cada alvo de benigno classificado como ataque, o menor limiar que fica dentro dele."""
    saida, escolhidos = [], set()
    for alvo_ in alvos:
        dentro = [linha for linha in curva if linha["limiar"] != "argmax" and linha["benigno_como_ataque"] <= alvo_]
        if dentro:
            linha = min(dentro, key=lambda linha: linha["limiar"])
            if linha["limiar"] not in escolhidos:
                escolhidos.add(linha["limiar"])
                saida.append((alvo_, linha))
    return saida


def _horas(alarmes_, segundos):
    return _fracao(alarmes_, segundos / 3600) if segundos else None


def _secao_g(m):
    r = m["resultados"]
    controle = _controle(m)
    detalhe = r["corte"].get(controle[0], {}).get("detalhe", {})
    curva = detalhe.get("limiar")
    if not curva:
        return []
    fundo = detalhe.get("limiar_no_fundo", {})
    pior = None
    for por_semente in r.get("rotacao", {}).values():
        unidade = por_semente.get(controle[0])
        if unidade and unidade.get("limiar_no_benigno"):
            limiar = unidade["limiar_no_benigno"]
            janelas = _benigno_de_fora(unidade)["janelas"]
            taxa = _fracao(_ataques(_benigno_de_fora(unidade)["previstas"]), janelas)
            if pior is None or taxa > pior[2]:
                pior = (limiar, janelas, taxa, limiar["arquivo"])
    linhas = []
    for linha in curva:
        chave = "argmax" if linha["limiar"] == "argmax" else str(linha["limiar"])
        celulas = [
            "argmax (hoje)" if chave == "argmax" else _decimal(linha["limiar"], 2), _pct(linha["benigno_como_ataque"]),
            _pct(linha["recall_de_ataque"]), _pct(linha["ataque_como_benigno"]), _pct(linha["macro_f1"]),
            _pct(linha["recall"]["Recon"]), _pct(linha["recall"]["Web"]), _pct(linha["recall"]["BruteForce"]),
            _pct(_fracao(fundo.get("como_ataque", {}).get(chave), fundo.get("janelas"))) if fundo.get("janelas") else "-",
        ]
        if pior is not None:
            celulas.append(_pct(pior[2]) if chave == "argmax" else _pct(_fracao(pior[0]["como_ataque"][chave], pior[1])))
        linhas.append(celulas)
    cabecalho = ["Limiar", "Benigno como ataque", "Recall de ataque", "Ataque como benigno", "Macro-F1",
                 "Recall Recon", "Recall Web", "Recall BruteForce", "Fundo de teste como ataque"]
    if pior is not None:
        cabecalho.append(f"`{pior[3]}` de fora como ataque")
    candidatos = candidatos_do_limiar(curva)
    secao = [
        "## g. Ponto de operação",
        "",
        "### Limiar sobre a probabilidade de benigno",
        "",
        (
            "**O que foi feito.** Com as probabilidades do modelo da semente principal no teste, a regra: se "
            "1 − P(Benign) ≥ t, a janela é ataque, na categoria de ataque mais provável; senão, é Benign. \"Recall de "
            "ataque\" é a fração das janelas de ataque postas em qualquer categoria de ataque. As duas últimas colunas "
            "aplicam a mesma regra ao fundo da parte de teste (rodada d) e ao pior pcap benigno de fora (rodada c)."
        ),
        "",
        *_tabela(cabecalho, linhas),
        "",
        "Pontos candidatos, o menor limiar que deixa o benigno classificado como ataque dentro de cada alvo:",
        "",
    ]
    secao += [
        f"- até {_pct(alvo_, 1)}: t = {_decimal(linha['limiar'], 2)}, benigno como ataque "
        f"{_pct(linha['benigno_como_ataque'])}, recall de ataque {_pct(linha['recall_de_ataque'])}, macro-F1 "
        f"{_pct(linha['macro_f1'])}, recall de Recon {_pct(linha['recall']['Recon'])} e de Web {_pct(linha['recall']['Web'])}."
        for alvo_, linha in candidatos
    ] or ["- nenhum limiar da curva chega aos alvos."]
    secao += [
        "",
        (
            "O argmax de hoje não é t = 0,5: ele dá Benign sempre que Benign é a classe mais provável, mesmo abaixo "
            "de 0,5. Os candidatos foram escolhidos no próprio teste, cujo benigno é um pcap só; a escolha final do "
            "limiar precisa sair de uma parte de validação, e não do teste."
        ),
    ]
    seguidas = detalhe.get("seguidas")
    if seguidas and seguidas["ataques"]:
        benignos = seguidas["benignos"]
        rotacoes_ = rotacoes_do_benigno(r, [controle[0]])
        linhas = []
        for n in map(str, JANELAS_SEGUIDAS):
            detectados = [a for a in seguidas["ataques"] if a["seguidas"][n]["primeira_janela"] is not None]
            janelas = [a["seguidas"][n]["primeira_janela"] for a in detectados]
            segundos = [a["seguidas"][n]["primeiro_segundos"] for a in detectados]
            celulas = [n]
            for b in benignos:
                celulas.append(f"{b['alarmes'][n]} ({_decimal(_horas(b['alarmes'][n], b['segundos']), 1)} por hora)")
            for rot in rotacoes_:
                alarme = rot["alarmes"][0]
                if alarme is not None and alarme["arquivo"] not in {b["arquivo"] for b in benignos}:
                    celulas.append(f"{alarme['alarmes'][n]} ({_decimal(_horas(alarme['alarmes'][n], alarme['segundos']), 1)}"
                                   " por hora)")
            celulas += [
                f"{len(detectados)} de {len(seguidas['ataques'])}",
                _decimal(float(np.median(janelas)), 0) if janelas else "-",
                _decimal(float(np.median(segundos)), 2) if segundos else "-",
                _decimal(float(np.max(segundos)), 1) if segundos else "-",
            ]
            linhas.append(celulas)
        cabecalho = ["N", *(f"Alarmes em `{b['arquivo']}`" for b in benignos)]
        cabecalho += [f"Alarmes em `{rot['alarmes'][0]['arquivo']}` (rotação {rot['rotacao']})" for rot in rotacoes_
                      if rot["alarmes"][0] is not None and rot["alarmes"][0]["arquivo"] not in {b["arquivo"] for b in benignos}]
        cabecalho += ["Pcaps de ataque com alarme no trecho de teste", "Janelas até o alarme (mediana)",
                      "Segundos até o alarme (mediana)", "Segundos até o alarme (maior)"]
        secao += [
            "",
            "### N janelas seguidas",
            "",
            (
                "**O que foi feito.** Um alarme dispara quando N janelas seguidas são classificadas como ataque; a "
                "sequência que continua não dispara outro. No pcap benigno de fora, a conta é sobre o pcap inteiro, e o "
                "tempo é a soma da duração das janelas. Em cada pcap de ataque, a sequência é o trecho de teste inteiro, "
                "com as janelas com e sem o atacante na ordem do arquivo, como o extrator as entregaria; o tempo até o "
                "alarme conta do começo do trecho. A semente é a principal, e a coluna da rotação usa o modelo daquela "
                "rotação."
            ),
            "",
            *_tabela(cabecalho, linhas),
        ]
    return secao


def _secao_h(m):
    r = m["resultados"]
    controle = _controle(m)
    detalhe = r["corte"].get(controle[0], {}).get("detalhe", {})
    intervalos = detalhe.get("intervalos")
    if not intervalos:
        return []
    def intervalo(par):
        return "sem valor" if par[0] is None else f"{_pct(par[0], 1)} a {_pct(par[1], 1)}"

    linhas = []
    for classe, v in intervalos.items():
        sementes = [u["medidas"]["por_classe"][classe]["recall"] for u in r["corte"].values()]
        linhas.append([
            classe, _milhar(v["janelas"]), _pct(_fracao(v["acertos"], v["janelas"]), 1), intervalo(v["recall_wilson"]),
            intervalo(v["recall_blocos"]), "sem valor" if v["autocorrelacao"] is None else _decimal(v["autocorrelacao"], 2),
            "sem valor" if v["n_efetivo"] is None else _milhar(v["n_efetivo"]),
            f"{_pct(_fracao(v['certas'], v['previstas']), 1)} ({_milhar(v['previstas'])})", intervalo(v["precisao_wilson"]),
            f"{_pct(min(sementes), 1)} a {_pct(max(sementes), 1)}",
        ])
    web = intervalos.get("Web", {}).get("por_pcap", {})
    return [
        "## h. Intervalos de confiança das classes raras",
        "",
        (
            "**O que foi feito.** No teste da semente principal: o intervalo de Wilson de 95%, que trata as janelas "
            f"como independentes; o intervalo por blocos de {BLOCO} janelas vizinhas do mesmo pcap, com "
            f"{_milhar(REAMOSTRAGENS)} reamostragens, porque janelas vizinhas erram juntas; a correlação do acerto "
            "entre uma janela e a seguinte; e o tamanho efetivo n(1 − r)/(1 + r)."
        ),
        "",
        *_tabela(
            ["Categoria", "Janelas de teste", "Recall", "Wilson", "Por blocos", "Autocorrelação", "n efetivo",
             "Precisão (previstas)", "Wilson da precisão", "Recall entre as sementes"],
            linhas,
        ),
        "",
        "Recall de Web por pcap, com o intervalo de Wilson: " + "; ".join(
            f"`{arquivo}` {_pct(_fracao(v['acertos'], v['janelas']), 1)} de {_milhar(v['janelas'])} "
            f"({intervalo(wilson(v['acertos'], v['janelas']))})" for arquivo, v in web.items()
        ) + ".",
        "",
        (
            "**O que os números mostram.** Quando a autocorrelação é alta, o tamanho efetivo é uma fração das janelas "
            "de teste e o intervalo por blocos é bem mais largo que o de Wilson; é ele que vale para comparar duas "
            "configurações. A precisão de uma categoria com poucas previsões vem de poucas janelas."
        ),
    ]


def _latencia(medida):
    return (f"mediana {_decimal(medida['mediana_ms'], 2)} ms, p95 {_decimal(medida['p95_ms'], 2)} ms, "
            f"p99 {_decimal(medida['p99_ms'], 2)} ms")


def _secao_i(m):
    r = m["resultados"]
    custo_ = r.get("custo")
    if not custo_:
        return []
    controle = _controle(m)
    linhas = []
    modelo = custo_.get("modelo")
    if modelo:
        carga = modelo["carga"]
        linhas += [
            ["Arquivo do modelo", (f"{_decimal(modelo['bytes'] / 1e6)} MB, {_milhar(modelo['nos'])} nós, profundidade "
                                   f"média {_decimal(modelo['profundidade_media'])} e máxima {modelo['profundidade_maxima']}")],
            ["Importar o scikit-learn e o joblib, num processo novo", f"{_decimal(carga['importar_s'], 2)} s"],
            ["Ler o modelo", f"{_decimal(carga['carga_s'], 2)} s, com o arquivo no cache do sistema"],
            ["Memória do processo", (f"{_decimal(carga['memoria_antes'] / 1e6, 0)} MB antes de ler o modelo e "
                                     f"{_decimal(carga['memoria_depois'] / 1e6, 0)} MB depois")],
            ["Uma janela, `predict`, um núcleo", _latencia(modelo["latencia_predict"])],
            ["Uma janela, `predict_proba`", _latencia(modelo["latencia_predict_proba"])],
            ["Lote de 1.000 janelas", f"{_decimal(modelo['lote_de_1000_ms'], 1)} ms"],
        ]
    vazao = custo_.get("vazao")
    if vazao:
        linhas.append([f"Extrator de janela de 100 em `{vazao['arquivo']}`",
                       (f"{_milhar(vazao['pacotes'])} pacotes em {_decimal(vazao['segundos'])} s: "
                        f"{_milhar(vazao['pacotes'] / vazao['segundos'])} pacotes/s e "
                        f"{_milhar(vazao['janelas'] / vazao['segundos'])} janelas/s")])
    duracao = [[classe, _decimal(v["mediana"], 3), _decimal(v["p90"], 3), _decimal(v["p99"], 3)]
               for classe, v in custo_["duracao_da_janela"].items()]
    menor = custo_["menor"]
    principal = r["corte"][controle[0]]["medidas"]
    def pior_da_rotacao(de_fora):
        benigno = next(p for p in de_fora if p["categoria"] == BENIGNO)
        return _fracao(_ataques(benigno["previstas"]), benigno["janelas"])

    rotacao_100 = {rot: por_semente[controle[0]] for rot, por_semente in r.get("rotacao", {}).items()
                   if controle[0] in por_semente}
    variantes = []
    if modelo:
        variantes.append([
            f"{m['parametros']['arvores']} árvores (o do sistema)", f"{_decimal(modelo['bytes'] / 1e6)} MB",
            _milhar(modelo["nos"]), f"{_decimal(modelo['latencia_predict']['mediana_ms'], 2)} ms",
            f"{_decimal(modelo['lote_de_1000_ms'], 1)} ms", _pct(principal["macro_f1"]), _pct(principal["benigno_como_ataque"]),
            _pct(principal["por_classe"]["Recon"]["recall"]), _pct(principal["por_classe"]["Web"]["recall"]),
            _pct(principal["por_classe"]["BruteForce"]["recall"]),
            "; ".join(_pct(pior_da_rotacao(u["de_fora"])) for u in rotacao_100.values()) or "-",
        ])
    variantes.append([
        f"{menor['arvores']} árvores", f"{_decimal(menor['bytes'] / 1e6)} MB", _milhar(menor["nos"]),
        f"{_decimal(menor['latencia_predict']['mediana_ms'], 2)} ms", f"{_decimal(menor['lote_de_1000_ms'], 1)} ms",
        _pct(menor["medidas"]["macro_f1"]), _pct(menor["medidas"]["benigno_como_ataque"]),
        _pct(menor["medidas"]["por_classe"]["Recon"]["recall"]), _pct(menor["medidas"]["por_classe"]["Web"]["recall"]),
        _pct(menor["medidas"]["por_classe"]["BruteForce"]["recall"]),
        "; ".join(_pct(pior_da_rotacao(de_fora)) for de_fora in menor["rotacao"].values()) or "-",
    ])
    return [
        "## i. Custo",
        "",
        (
            "**O que foi feito.** O modelo salvo foi lido num processo novo, três vezes, para medir o tempo e a "
            f"memória; a latência é de uma janela isolada, com um núcleo, em {JANELAS_DA_LATENCIA} janelas diferentes "
            "do teste, depois de uma de aquecimento. A vazão é a do extrator de janela de 100 com os endereços, lendo o "
            "pcap inteiro. Os tempos são desta máquina, dividida com outros processos, e mudam de uma execução para "
            "outra."
        ),
        "",
        *_tabela(["Medida", "Valor"], linhas),
        "",
        (
            "Quanto tempo uma janela de 100 quadros leva para fechar (`Number` / `Rate`), em segundos, na amostra da "
            "semente principal:"
        ),
        "",
        *_tabela(["Categoria", "Mediana", "P90", "P99"], duracao),
        "",
        f"O Random Forest de {menor['arvores']} árvores, na mesma divisão e na mesma semente:",
        "",
        *_tabela(
            ["Variante", "Arquivo", "Nós", "Latência (mediana)", "Lote de 1.000", "Macro-F1", "Benigno como ataque",
             "Recall Recon", "Recall Web", "Recall BruteForce", "Pcap benigno de fora nas rotações: como ataque"],
            variantes,
        ),
    ]


def _nucleos_em_texto(nucleos):
    if nucleos <= 0:
        return "todos os núcleos"
    return "1 núcleo" if nucleos == 1 else f"{nucleos} núcleos"


def _como_foram_obtidos(m):
    e = m["entradas"]
    linhas = [
        "## Como os números foram obtidos",
        "",
        f"- Comando: `{m['comando']}`, a partir da raiz do repositório, depois de `python -m codigo.classificador.regerar`.",
        (
            f"- Dados: `{e['regeracao']['destino']}/janela_{JANELA}/`, {len(e['arquivos'])} arquivos (os CSVs de rótulo "
            f"e as partes de `{DESCARTADAS}/`), com o SHA-256 de cada um em `{m['arquivo_do_manifesto']}`. Manifesto da "
            f"regeração `{e['regeracao']['manifesto']}`, SHA-256 `{e['regeracao']['sha256']}`; extrator com SHA-256 "
            f"`{e['regeracao']['extrator']['sha256']}` e opções {e['regeracao']['extrator']['opcoes'] or 'nenhuma'}."
        ),
    ]
    if e.get("modelo"):
        linhas.append(f"- Modelo salvo: `{e['modelo']['arquivo']}`, SHA-256 `{e['modelo']['sha256']}`.")
    p = m["parametros"]
    linhas += [
        (
            f"- Treinos: `RandomForestClassifier` do scikit-learn com {p['arvores']} árvores e os demais parâmetros "
            f"padrão, {_nucleos_em_texto(p['nucleos'])} (o modelo não depende disso), teto de "
            f"{_milhar(p['teto'])} linhas por rótulo e corte de {_pct(1 - p['fracao_de_teste'], 0)} das janelas de cada "
            "pcap, as mesmas funções de `treinar_regerado`. Predição com um núcleo, em ordem fixa."
        ),
        "- Os números das tabelas são arredondados; os valores completos, com as contagens, estão no manifesto, e as",
        f"  tabelas em CSV começam com `{m['prefixo']}_`.",
        f"- Tempo total, na máquina em que rodou: {_decimal(m['duracao_segundos'])} s.",
        "- Com as mesmas entradas e as mesmas sementes, os números saem iguais. Só mudam a data e os tempos.",
    ]
    return linhas


def _resumo(m):
    """Os números principais de cada rodada, numa lista curta no começo do relatório."""
    r = m["resultados"]
    controle = _controle(m)
    itens = []
    reproducao = r["corte"].get(controle[0], {}).get("detalhe", {}).get("reproducao")
    if reproducao:
        itens.append(
            f"a. O modelo salvo reproduz as medidas publicadas ({len(reproducao['medidas_diferentes'])} diferenças em "
            f"{reproducao['medidas_conferidas']}), e o retreino com a semente 42 dá "
            f"{_milhar(reproducao['predicoes_diferentes_do_retreino'])} predições diferentes das dele."
        )
    if len(r["corte"]) > 1:
        itens.append(
            f"b. Entre {len(r['corte'])} sementes, macro-F1 {_com_faixa(_do_corte(r, list(r['corte']), lambda a: a['macro_f1']))} "
            f"e benigno classificado como ataque {_com_faixa(_do_corte(r, list(r['corte']), lambda a: a['benigno_como_ataque']))}."
        )
    rotacoes_ = rotacoes_do_benigno(r, controle)
    if len(rotacoes_) > 1:
        itens.append(
            "c. Benigno classificado como ataque com cada pcap benigno fora do treino: "
            + "; ".join(f"`{rot['arquivo']}` {_com_faixa(rot['como_ataque'])}" for rot in rotacoes_)
            + f". No total dos três, {_com_faixa(benigno_no_total(r, controle))}."
        )
    if r["corte"] and next(iter(r["corte"].values()))["fundo"]:
        itens.append(
            f"d. Janelas de fundo dos pcaps de ataque, sem nenhum quadro do atacante, classificadas como ataque: "
            f"{_com_faixa(fundo_por_semente(r, controle))} na parte de teste."
        )
    if r.get("fora"):
        partes = []
        for categoria in CATEGORIAS_DO_RESUMO:
            arquivos = [a for a, s in r["fora"].items() if next(iter(s.values()))["categoria"] == categoria]
            if arquivos:
                partes.append(f"{categoria} {_com_faixa(recall_fora(r, controle, categoria))} contra "
                              f"{_com_faixa(recall_dentro(r, controle, categoria, arquivos))}")
        itens.append("e. Recall com o pcap inteiro fora do treino, contra dentro da captura: " + "; ".join(partes) + ".")
    if "tamanhos" in r:
        t = r["tamanhos"]["por_categoria"]
        itens.append(
            "f. Janelas com quadro menor que 60 bytes: "
            + ", ".join(f"{c} {_pct(_fracao(v['abaixo_de_60'], v['janelas']), 1)}" for c, v in t.items())
            + "; com quadro maior que 1.514 bytes: "
            + ", ".join(f"{c} {_pct(_fracao(v['acima_de_1514'], v['janelas']), 1)}" for c, v in t.items()) + "."
        )
    curva = r["corte"].get(controle[0], {}).get("detalhe", {}).get("limiar")
    if curva:
        itens.append(
            "g. Pontos candidatos do limiar: "
            + "; ".join(f"t = {_decimal(linha['limiar'], 2)} com {_pct(linha['benigno_como_ataque'])} de benigno como "
                        f"ataque e {_pct(linha['recall_de_ataque'])} de recall de ataque"
                        for _, linha in candidatos_do_limiar(curva)) + "."
        )
    intervalos = r["corte"].get(controle[0], {}).get("detalhe", {}).get("intervalos")
    if intervalos:
        itens.append(
            "h. Recall com o intervalo por blocos: "
            + "; ".join(f"{c} {_pct(_fracao(v['acertos'], v['janelas']), 1)} ({_pct(v['recall_blocos'][0], 1)} a "
                        f"{_pct(v['recall_blocos'][1], 1)})" for c, v in intervalos.items() if v["recall_blocos"][0] is not None)
            + "."
        )
    custo_ = r.get("custo", {})
    if custo_.get("modelo"):
        itens.append(
            f"i. Uma janela leva {_decimal(custo_['modelo']['latencia_predict']['mediana_ms'], 2)} ms para ser classificada "
            f"sozinha e {_decimal(custo_['modelo']['lote_de_1000_ms'] / 1000, 3)} ms num lote de 1.000; o modelo tem "
            f"{_decimal(custo_['modelo']['bytes'] / 1e6)} MB."
        )
    return ["## Resumo", "", *(f"- {item}" for item in itens)] if itens else []


def montar_relatorio(m):
    """O relatório das rodadas do modelo do sistema, a partir do manifesto."""
    secoes = [_cabecalho(m), _resumo(m), _secao_a(m), _secao_b(m), _secao_c(m), _secao_d(m), _secao_e(m), _secao_f(m),
              _secao_g(m), _secao_h(m), _secao_i(m), _como_foram_obtidos(m)]
    return "\n".join("\n".join(secao) + "\n" for secao in secoes if secao).rstrip("\n") + "\n"


# --- o relatório da comparação de capturas -----------------------------------------------------


def medidas_do_resumo(resultado, sementes):
    """As medidas da tabela-resumo de uma configuração, cada uma com o valor de cada semente."""
    medidas = {
        "macro_f1": _do_corte(resultado, sementes, lambda a: a["macro_f1"]),
        "pior_benigno": pior_benigno(resultado, sementes),
        "fundo": fundo_por_semente(resultado, sementes),
    }
    for categoria in CATEGORIAS_DO_RESUMO:
        medidas[f"fora_{categoria}"] = recall_fora(resultado, sementes, categoria)
        medidas[f"fora_{categoria}_como_ataque"] = recall_fora(resultado, sementes, categoria, "como_ataque")
    return medidas


ROTULOS_DO_RESUMO = {
    "macro_f1": "Macro-F1 no corte por tempo",
    "pior_benigno": "Benigno como ataque no pior pcap benigno de fora",
    "fundo": "Fundo virando ataque (parte de teste)",
    **{f"fora_{c}": f"Recall {c} com o pcap fora" for c in CATEGORIAS_DO_RESUMO},
}


def _celula(valores, referencia=None):
    texto = _com_faixa(valores, 1)
    if referencia is not None and passa_do_ruido(referencia, valores):
        texto += " *"
    return texto


def _cabecalho_das_capturas(m):
    p = m["parametros"]
    configuracoes = m["entradas"]["configuracoes"]
    return [
        "# Captura normalizada: comparação de configurações",
        "",
        f"Gerado por `{m['gerado_por']}` em {_data(m)}, com {_versoes(m)}.",
        "",
        "Os pcaps do CICIoT2023 não foram gravados todos do mesmo jeito: os de spoofing têm quadros menores que 60",
        "bytes, sem o preenchimento do Ethernet, e os benignos têm quadros maiores que 1.514 bytes, que só existem",
        "quando a placa da máquina que captura junta segmentos (`rodadas_de_teste.md`, rodada f). O extrator ganhou",
        "duas opções, desligadas por padrão, que medem o quadro como ele passa no fio: completar o quadro até 60 bytes e",
        "limitá-lo a 1.514. Este relatório regera os 38 pcaps com as opções ligadas e compara o modelo do sistema com",
        "quatro alternativas, no corte por tempo e nas rodadas c (rotação do pcap benigno de fora), d (tráfego de fundo)",
        "e e (pcap fora do treino). O modelo do sistema não muda: os números são para a equipe decidir.",
        "",
        *_tabela(
            ["Configuração", "O que muda", "Dados", "Opções do extrator"],
            [[c["nome"], c["descricao"], f"`{c['destino']}`", _enumerar(f"`{o}`" for o, _ in c["opcoes"]) if c["opcoes"]
              else "nenhuma"] for c in configuracoes],
        ),
        "",
        (
            f"Cada configuração foi treinada com as sementes {_enumerar(p['sementes'][:p['sementes_de_controle']])}, que "
            "definem ao mesmo tempo o sorteio do teto e o Random Forest. Os valores são a média das sementes, com o "
            "menor e o maior entre "
            "parênteses. Uma diferença para a configuração 0 só conta quando as faixas das sementes não se cruzam; "
            "dentro delas, é \"sem diferença\"."
        ),
    ]


def _tabela_resumo(m):
    r = m["resultados"]
    sementes = _controle(m)
    referencia = medidas_do_resumo(r["0"], sementes) if "0" in r else None
    linhas = []
    for nome, resultado in r.items():
        medidas = medidas_do_resumo(resultado, sementes)
        celulas = [nome]
        for chave in ROTULOS_DO_RESUMO:
            celula = _celula(medidas[chave], None if nome == "0" or referencia is None else referencia[chave])
            if chave == "fora_BruteForce":
                celula += f" (como ataque {_com_faixa(medidas['fora_BruteForce_como_ataque'], 1)})"
            celulas.append(celula)
        linhas.append(celulas)
    return [
        "## Tabela-resumo",
        "",
        *_tabela(["Configuração", *ROTULOS_DO_RESUMO.values()], linhas),
        "",
        (
            "Um asterisco marca a diferença para a configuração 0 que passa do ruído entre sementes. O pior pcap "
            "benigno de fora é, em cada semente, o de maior alarme entre as rotações da rodada c. O fundo é o das janelas "
            "sem nenhum quadro do atacante, na parte de teste dos pcaps de ataque. O recall com o pcap fora soma os pcaps "
            "da categoria, cada um medido nas suas janelas de teste com o modelo que não o viu. BruteForce tem um pcap "
            "só: com ele fora a categoria some do treino, o recall é zero por construção, e entre parênteses fica a "
            "fração vista como algum ataque."
        ),
    ]


def _diferencas_das_capturas(m):
    r = m["resultados"]
    sementes = _controle(m)
    if "0" not in r:
        return []
    referencia = medidas_do_resumo(r["0"], sementes)
    secao = ["## Quais diferenças passam do ruído", ""]
    rotulos = {
        "macro_f1": "macro-F1 no corte por tempo", "pior_benigno": "benigno como ataque no pior pcap benigno de fora",
        "fundo": "fundo virando ataque",
        **{f"fora_{c}": f"recall de {c} com o pcap fora" for c in CATEGORIAS_DO_RESUMO},
        **{f"fora_{c}_como_ataque": f"{c} visto como algum ataque com o pcap fora" for c in CATEGORIAS_DO_RESUMO},
    }
    for nome, resultado in r.items():
        if nome == "0":
            continue
        medidas = medidas_do_resumo(resultado, sementes)
        acima = [
            f"{rotulos[chave]} ({_pp(_media(medidas[chave]) - _media(referencia[chave]))} p.p.)"
            for chave in rotulos if passa_do_ruido(referencia[chave], medidas[chave])
        ]
        secao.append(
            f"- Configuração {nome}: " + (_enumerar(acima) + "." if acima else "nenhuma medida da tabela-resumo sai do ruído.")
        )
    return secao


def _corte_das_capturas(m):
    r = m["resultados"]
    sementes = _controle(m)
    medidas = [
        ("Macro-F1", lambda a: a["macro_f1"]), ("Acurácia", lambda a: a["acuracia"]),
        ("Benigno classificado como ataque", lambda a: a["benigno_como_ataque"]),
        ("Ataque classificado como benigno", lambda a: a["ataque_como_benigno"]),
        *((f"Recall {c}", lambda a, c=c: a["por_classe"][c]["recall"]) for c in CLASSES),
        *((f"Precisão {c}", lambda a, c=c: a["por_classe"][c]["precisao"]) for c in ("Spoofing", "Web", "BruteForce")),
    ]
    referencia = r.get("0")
    linhas = []
    for rotulo, funcao in medidas:
        base = _do_corte(referencia, sementes, funcao) if referencia else None
        linhas.append([rotulo, *(_celula(_do_corte(res, sementes, funcao), None if nome == "0" else base)
                                 for nome, res in r.items())])
    return [
        "## Corte por tempo",
        "",
        "A divisão publicada: o começo de cada pcap no treino e o fim no teste, e um pcap inteiro de fora nos rótulos de",
        "vários pcaps. O asterisco marca a diferença para a configuração 0 acima do ruído.",
        "",
        *_tabela(["Medida", *(f"Configuração {nome}" for nome in r)], linhas),
    ]


def _rotacao_das_capturas(m):
    r = m["resultados"]
    sementes = _controle(m)
    arquivos = [rot["arquivo"] for rot in rotacoes_do_benigno(next(iter(r.values())), sementes)]
    linhas = []
    referencia = r.get("0")
    for nome, resultado in r.items():
        rotacoes_ = {rot["arquivo"]: rot for rot in rotacoes_do_benigno(resultado, sementes)}
        base = {rot["arquivo"]: rot for rot in rotacoes_do_benigno(referencia, sementes)} if referencia else {}
        celulas = [nome]
        for arquivo in arquivos:
            celulas.append(_celula(rotacoes_[arquivo]["como_ataque"],
                                   None if nome == "0" else base[arquivo]["como_ataque"]))
        celulas.append(_celula(benigno_no_total(resultado, sementes),
                               None if nome == "0" else benigno_no_total(referencia, sementes)))
        celulas.append(_celula(pior_benigno(resultado, sementes),
                               None if nome == "0" else pior_benigno(referencia, sementes)))
        linhas.append(celulas)
    return [
        "## c. Rotação do pcap benigno de fora",
        "",
        "Tráfego benigno classificado como ataque em cada pcap benigno, com o modelo que deixou esse pcap inteiro fora",
        "do treino, no total dos três e no pior deles.",
        "",
        *_tabela(["Configuração", *(f"`{a}`" for a in arquivos), "Total", "Pior pcap"], linhas),
    ]


def _fundo_das_capturas(m):
    r = m["resultados"]
    sementes = _controle(m)
    referencia = r.get("0")
    if referencia is None:
        return []
    primeiro = _nas_sementes(referencia["corte"], sementes)[0]
    arquivos = [p["arquivo"] for p in sorted(primeiro["fundo"], key=lambda p: -p["teste"]["janelas"])
                if p["teste"]["janelas"] >= 50]
    totais = [[nome, _celula(fundo_por_semente(res, sementes, "teste"),
                             None if nome == "0" else fundo_por_semente(referencia, sementes, "teste")),
               _celula(fundo_por_semente(res, sementes, "treino"),
                       None if nome == "0" else fundo_por_semente(referencia, sementes, "treino"))]
              for nome, res in r.items()]

    def na_categoria(resultado, arquivo):
        valores = []
        for u in _nas_sementes(resultado["corte"], sementes):
            p = next(f for f in u["fundo"] if f["arquivo"] == arquivo)
            valores.append(_fracao(p["teste"]["previstas"][p["categoria"]], p["teste"]["janelas"]))
        return valores

    por_pcap = []
    for arquivo in arquivos:
        categoria = next(p["categoria"] for p in primeiro["fundo"] if p["arquivo"] == arquivo)
        janelas = next(p["teste"]["janelas"] for p in primeiro["fundo"] if p["arquivo"] == arquivo)
        por_pcap.append([f"`{arquivo}`", categoria, _milhar(janelas),
                         *(_celula(na_categoria(res, arquivo), None if nome == "0" else na_categoria(referencia, arquivo))
                           for nome, res in r.items())])
    return [
        "## d. Tráfego de fundo",
        "",
        "Fração das janelas sem nenhum quadro do atacante classificada como algum ataque, somando os pcaps de ataque.",
        "Na configuração 4 o fundo da parte de treino entra no treino como benigno, e a coluna da parte de treino",
        "deixa de ser uma medida fora da amostra.",
        "",
        *_tabela(["Configuração", "Parte de teste", "Parte de treino"], totais),
        "",
        "Por pcap, na parte de teste, a fração do fundo posta na categoria do próprio pcap (pcaps com ao menos 50 janelas",
        "de fundo na parte de teste):",
        "",
        *_tabela(["Pcap", "Categoria", "Janelas de fundo no teste", *(f"Configuração {nome}" for nome in r)], por_pcap),
    ]


def _fora_das_capturas(m):
    r = m["resultados"]
    sementes = _controle(m)
    referencia = r.get("0")
    if referencia is None or not referencia.get("fora"):
        return []

    def do_pcap(resultado, arquivo):
        unidades = _nas_sementes(resultado["fora"][arquivo], sementes)
        return [_fracao(u["teste"]["previstas"][u["categoria"]], u["teste"]["janelas"]) for u in unidades]

    linhas = []
    for arquivo, por_semente in referencia["fora"].items():
        unidade = next(iter(por_semente.values()))
        linhas.append([f"`{arquivo}`", unidade["categoria"], _milhar(unidade["teste"]["janelas"]),
                       *(_celula(do_pcap(res, arquivo), None if nome == "0" else do_pcap(referencia, arquivo))
                         for nome, res in r.items())])
    categorias = []
    for categoria in CLASSES:
        if not any(next(iter(s.values()))["categoria"] == categoria for s in referencia["fora"].values()):
            continue
        base = recall_fora(referencia, sementes, categoria)
        categorias.append([categoria, *(_celula(recall_fora(res, sementes, categoria), None if nome == "0" else base)
                                        for nome, res in r.items())])
    return [
        "## e. Pcap fora do treino",
        "",
        "Recall de cada pcap, nas janelas de teste dele, quando nenhuma janela dele entra no treino:",
        "",
        *_tabela(["Pcap", "Categoria", "Janelas de teste", *(f"Configuração {nome}" for nome in r)], linhas),
        "",
        "Somando os pcaps de cada categoria:",
        "",
        *_tabela(["Categoria", *(f"Configuração {nome}" for nome in r)], categorias),
    ]


def _tamanhos_das_capturas(m):
    r = m["resultados"]
    com_tamanhos = [(nome, res["tamanhos"]) for nome, res in r.items() if "tamanhos" in res]
    if not com_tamanhos:
        return []
    linhas = []
    for classe in CLASSES:
        celulas = [classe]
        for _, t in com_tamanhos:
            v = t["por_categoria"][classe]
            celulas += [_pct(_fracao(v["abaixo_de_60"], v["janelas"]), 1), _pct(_fracao(v["acima_de_1514"], v["janelas"]), 1)]
        linhas.append(celulas)
    cabecalho = ["Categoria"]
    for nome, _ in com_tamanhos:
        cabecalho += [f"Menor que 60 ({nome})", f"Maior que 1.514 ({nome})"]
    return [
        "## O tamanho dos quadros em cada pasta",
        "",
        "Fração das janelas mantidas com algum quadro menor que 60 bytes e maior que 1.514 bytes, por pasta de dados,",
        "para conferir o que as opções do extrator fizeram:",
        "",
        *_tabela(cabecalho, linhas),
    ]


def _como_foram_obtidos_das_capturas(m):
    p = m["parametros"]
    linhas = [
        "## Como os números foram obtidos",
        "",
        f"- Comando: `{m['comando']}`, a partir da raiz do repositório.",
        "- Dados de cada pasta, regerados por `python -m codigo.classificador.regerar --janelas 100` com as opções do",
        "  extrator de cada configuração:",
    ]
    for destino, entrada in m["entradas"]["pastas"].items():
        extrator = entrada["regeracao"]["extrator"] or {}
        linhas.append(
            f"  - `{destino}`: manifesto `{entrada['regeracao']['manifesto']}` (SHA-256 "
            f"`{entrada['regeracao']['sha256']}`), extrator com SHA-256 `{extrator.get('sha256')}` e opções "
            f"{extrator.get('opcoes') or 'nenhuma'}; {len(entrada['arquivos'])} arquivos lidos, com o SHA-256 de cada um "
            f"em `{m['arquivo_do_manifesto']}`."
        )
    linhas += [
        (
            f"- Treinos: `RandomForestClassifier` com {p['arvores']} árvores e os demais parâmetros padrão, teto de "
            f"{_milhar(p['teto'])} linhas por rótulo, corte de {_pct(1 - p['fracao_de_teste'], 0)} das janelas de cada "
            "pcap, as mesmas funções de `treinar_regerado`; a configuração 0 é o mesmo treino de `rodadas_de_teste.md`."
        ),
        f"- As tabelas em CSV começam com `{m['prefixo']}_`; os valores completos, com as contagens, estão no manifesto.",
        f"- Tempo total, na máquina em que rodou: {_decimal(m['duracao_segundos'])} s.",
        "- Com as mesmas entradas e as mesmas sementes, os números saem iguais. Só mudam a data e os tempos.",
    ]
    return linhas


def montar_relatorio_das_capturas(m):
    """O relatório da comparação de capturas, a partir do manifesto."""
    secoes = [_cabecalho_das_capturas(m), _tabela_resumo(m), _diferencas_das_capturas(m), _corte_das_capturas(m),
              _rotacao_das_capturas(m), _fundo_das_capturas(m), _fora_das_capturas(m), _tamanhos_das_capturas(m),
              _como_foram_obtidos_das_capturas(m)]
    return "\n".join("\n".join(secao) + "\n" for secao in secoes if secao).rstrip("\n") + "\n"


# --- manifesto e tabelas -----------------------------------------------------------------------


def montar_manifesto(capturas, resultados, entradas, parametros, comando, duracao):
    return {
        "descricao": (
            "Comparação do modelo de janela de 100 com dados regerados com as opções do extrator" if capturas
            else "Rodadas de teste do modelo de janela de 100 do sistema"
        ),
        "gerado_por": "python -m codigo.classificador.rodadas",
        "comando": comando,
        "gerado_em": datetime.datetime.now(tz=datetime.UTC).astimezone().strftime("%Y-%m-%d"),
        "versoes": {
            "python": platform.python_version(), "numpy": np.__version__, "pandas": pd.__version__,
            "scikit-learn": sklearn.__version__,
        },
        "arquivo_do_manifesto": MANIFESTO_DAS_CAPTURAS if capturas else MANIFESTO,
        "prefixo": PREFIXO_DAS_TABELAS_DAS_CAPTURAS if capturas else PREFIXO_DAS_TABELAS,
        "parametros": parametros,
        "entradas": entradas,
        "resultados": resultados,
        "duracao_segundos": duracao,
    }


def _linhas_do_corte(nome, resultado):
    linhas = []
    for semente, u in resultado["corte"].items():
        a = u["medidas"]
        for chave in ("macro_f1", "acuracia", "f1_ponderado", "benigno_como_ataque", "ataque_como_benigno"):
            linhas.append([nome, semente, chave, "", _campo(a[chave])])
        for classe, medida in a["por_classe"].items():
            for chave in ("precisao", "recall", "f1", "suporte"):
                linhas.append([nome, semente, chave, classe, _campo(medida[chave])])
    return linhas


def _linhas_da_rotacao(nome, resultado):
    rotacoes_ = [("0", resultado["corte"]), *sorted(resultado.get("rotacao", {}).items())]
    return [
        [nome, rotacao, semente, p["arquivo"], p["rotulo"], p["categoria"], p["janelas"],
         *(p["previstas"][c] for c in CLASSES)]
        for rotacao, por_semente in rotacoes_ for semente, u in por_semente.items() for p in u["de_fora"]
    ]


def _linhas_do_fundo(nome, resultado):
    return [
        [nome, semente, p["arquivo"], p["rotulo"], p["categoria"], parte, p[parte]["janelas"],
         *(p[parte]["previstas"][c] for c in CLASSES)]
        for semente, u in resultado["corte"].items() for p in u["fundo"] for parte in ("treino", "teste")
    ]


def _linhas_do_pcap_fora(nome, resultado):
    linhas = []
    for arquivo, por_semente in resultado.get("fora", {}).items():
        for semente, u in por_semente.items():
            for trecho in ("teste", "inteiro"):
                linhas.append([nome, semente, arquivo, u["categoria"], "pcap fora", trecho, u[trecho]["janelas"],
                               *(u[trecho]["previstas"][c] for c in CLASSES)])
            dentro = resultado["corte"].get(semente, {}).get("por_pcap", {}).get(arquivo)
            if dentro is not None:
                linhas.append([nome, semente, arquivo, u["categoria"], "divisão publicada", "teste", dentro["janelas"],
                               *(dentro["previstas"][c] for c in CLASSES)])
    return linhas


CABECALHOS = {
    "corte": ["configuracao", "semente", "medida", "classe", "valor"],
    "rotacao": ["configuracao", "rotacao", "semente", "arquivo", "rotulo", "categoria", "janelas", *CLASSES],
    "fundo": ["configuracao", "semente", "arquivo", "rotulo", "categoria", "parte", "janelas", *CLASSES],
    "pcap_fora": ["configuracao", "semente", "arquivo", "categoria", "treino", "trecho", "janelas", *CLASSES],
}


def gravar(manifesto, pasta):
    """Grava o manifesto e o que sai dele: o relatório e as tabelas."""
    pasta = Path(pasta)
    pasta.mkdir(parents=True, exist_ok=True)
    capturas = manifesto["arquivo_do_manifesto"] == MANIFESTO_DAS_CAPTURAS
    (pasta / manifesto["arquivo_do_manifesto"]).write_text(
        json.dumps(manifesto, indent=1, ensure_ascii=False) + "\n", encoding="utf-8",
    )
    relatorio = RELATORIO_DAS_CAPTURAS if capturas else RELATORIO
    (pasta / relatorio).write_text(
        montar_relatorio_das_capturas(manifesto) if capturas else montar_relatorio(manifesto), encoding="utf-8",
    )
    por_configuracao = manifesto["resultados"] if capturas else {"0": manifesto["resultados"]}
    prefixo = manifesto["prefixo"]
    for nome, montar in (("corte", _linhas_do_corte), ("rotacao", _linhas_da_rotacao), ("fundo", _linhas_do_fundo),
                         ("pcap_fora", _linhas_do_pcap_fora)):
        linhas = [linha for configuracao, res in por_configuracao.items() for linha in montar(configuracao, res)]
        _gravar_csv(pasta / f"{prefixo}_{nome}.csv", CABECALHOS[nome], linhas)
    if capturas:
        sementes = _controle(manifesto)
        _gravar_csv(
            pasta / f"{prefixo}_resumo.csv", ["configuracao", "medida", "semente", "valor"],
            [[nome, chave, semente, _campo(valor)]
             for nome, res in por_configuracao.items()
             for chave, valores in medidas_do_resumo(res, sementes).items()
             for semente, valor in zip(sementes, valores)],
        )
        return
    detalhe = manifesto["resultados"]["corte"].get(_controle(manifesto)[0], {}).get("detalhe", {})
    if detalhe.get("limiar"):
        fundo = detalhe["limiar_no_fundo"]
        _gravar_csv(
            pasta / f"{prefixo}_limiar.csv",
            ["limiar", "benigno_como_ataque", "recall_de_ataque", "ataque_como_benigno", "macro_f1",
             *(f"recall_{c}" for c in CLASSES), "fundo_de_teste_como_ataque"],
            [[linha["limiar"], _campo(linha["benigno_como_ataque"]), _campo(linha["recall_de_ataque"]),
              _campo(linha["ataque_como_benigno"]), _campo(linha["macro_f1"]),
              *(_campo(linha["recall"][c]) for c in CLASSES),
              _campo(_fracao(fundo["como_ataque"].get(str(linha["limiar"])), fundo["janelas"]))]
             for linha in detalhe["limiar"]],
        )
    if detalhe.get("permutacao"):
        p = detalhe["permutacao"]
        _gravar_csv(
            pasta / f"{prefixo}_permutacao.csv", ["alvo", "feature", "queda_media", "desvio"],
            [[f"recall {classe}", feature, _campo(q[0]), _campo(q[1])]
             for classe, registro in p["por_categoria"].items() for feature, q in registro["quedas"].items()]
            + [["macro-F1", feature, _campo(q[0]), _campo(q[1])] for feature, q in p["macro_f1"]["quedas"].items()],
        )
    if detalhe.get("intervalos"):
        _gravar_csv(
            pasta / f"{prefixo}_intervalos.csv",
            ["classe", "janelas", "acertos", "wilson_inferior", "wilson_superior", "blocos_inferior", "blocos_superior",
             "autocorrelacao", "n_efetivo", "previstas", "certas", "precisao_wilson_inferior", "precisao_wilson_superior"],
            [[classe, v["janelas"], v["acertos"], _campo(v["recall_wilson"][0]), _campo(v["recall_wilson"][1]),
              _campo(v["recall_blocos"][0]), _campo(v["recall_blocos"][1]), _campo(v["autocorrelacao"]),
              _campo(v["n_efetivo"]), v["previstas"], v["certas"], _campo(v["precisao_wilson"][0]),
              _campo(v["precisao_wilson"][1])]
             for classe, v in detalhe["intervalos"].items()],
        )


# --- comando -----------------------------------------------------------------------------------


def _lista_de_rodadas(texto):
    rodadas = [parte.strip() for parte in texto.split(",") if parte.strip()]
    desconhecidas = [r for r in rodadas if r not in RODADAS]
    if not rodadas or desconhecidas:
        raise argparse.ArgumentTypeError(f"as rodadas são letras de {RODADAS[0]} a {RODADAS[-1]}, separadas por vírgula")
    return tuple(rodadas)


def _lista_de_sementes(texto):
    try:
        sementes = tuple(int(parte) for parte in texto.split(","))
    except ValueError:
        raise argparse.ArgumentTypeError("as sementes precisam ser números inteiros separados por vírgula") from None
    if len(set(sementes)) != len(sementes):
        raise argparse.ArgumentTypeError("as sementes precisam ser diferentes entre si")
    return sementes


def _parametros(argumentos, pcaps_fora):
    return {
        "janela": JANELA, "teto": argumentos.teto, "arvores": argumentos.arvores, "nucleos": argumentos.nucleos,
        "sementes": list(argumentos.sementes), "sementes_de_controle": min(SEMENTES_DE_CONTROLE, len(argumentos.sementes)),
        "fracao_de_teste": FRACAO_DE_TESTE_POR_TEMPO, "limiares": list(LIMIARES), "janelas_seguidas": list(JANELAS_SEGUIDAS),
        "pcaps_fora": list(pcaps_fora), "permutacao": {"repeticoes": REPETICOES_DA_PERMUTACAO,
                                                      "subamostra": SUBAMOSTRA_DA_PERMUTACAO},
        "reamostragens": REAMOSTRAGENS, "bloco": BLOCO, "arvores_menor": ARVORES_MENOR,
    }


def _entrada_da_regeracao(caminho, regeracao):
    return {
        "manifesto": Path(caminho).as_posix(), "sha256": _sha256(caminho), "destino": regeracao["destino"],
        "extrator": regeracao.get("extrator"),
        "extraidas": {p["arquivo"]: p["janelas"][str(JANELA)]["extraidas"] for p in regeracao["pcaps"]},
    }


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.classificador.rodadas",
        description="Rodadas de teste do modelo de janela de 100 e comparação de capturas normalizadas.",
        allow_abbrev=False,
    )
    analisador.add_argument("--saida", default="experimentos/resultados", help="pasta dos resultados")
    analisador.add_argument("--trabalho", default=TRABALHO, help=f"pasta dos resultados parciais (padrão: {TRABALHO})")
    analisador.add_argument(
        "--manifesto-da-regeracao", default=ATUAL.regeracao, help=f"padrão: {ATUAL.regeracao}",
    )
    analisador.add_argument("--modelo", default="modelos/rf_regerado_janela_100.joblib",
                            help="modelo salvo do sistema, para as rodadas a e i")
    analisador.add_argument("--dataset", default="CICIoT2023", help="pasta dos pcaps, para a vazão do extrator")
    analisador.add_argument("--rodadas", type=_lista_de_rodadas, default=RODADAS,
                            help="rodadas, de a a i, separadas por vírgula (padrão: todas)")
    analisador.add_argument("--sementes", type=_lista_de_sementes, default=SEMENTES,
                            help="sementes, separadas por vírgula; a primeira é a principal (padrão: 42,1,2,3,4)")
    analisador.add_argument("--arvores", type=_positivo, default=ARVORES, help=f"padrão: {ARVORES}")
    analisador.add_argument("--teto", type=_positivo, default=TETO, help=f"linhas por rótulo (padrão: {TETO})")
    analisador.add_argument(
        "--nucleos", type=_nucleos, default=TODOS_OS_NUCLEOS,
        help=f"núcleos usados nos treinos (padrão: {TODOS_OS_NUCLEOS}, todos). Os números são os mesmos com qualquer valor",
    )
    analisador.add_argument("--capturas", action="store_true",
                            help="compara as configurações de captura nas rodadas c, d e e e no corte por tempo")
    analisador.add_argument("--refazer-relatorio", action="store_true",
                            help="não treina: refaz o relatório e as tabelas a partir do manifesto")
    try:
        argumentos = analisador.parse_args(argv)
    except SystemExit as encerramento:
        return encerramento.code
    saida = Path(argumentos.saida)
    comando = " ".join(["python -m codigo.classificador.rodadas", *(argv if argv is not None else sys.argv[1:])])
    inicio = time.perf_counter()
    try:
        arquivo = MANIFESTO_DAS_CAPTURAS if argumentos.capturas else MANIFESTO
        if argumentos.refazer_relatorio:
            manifesto = _ler_json(saida / arquivo)
        elif argumentos.capturas:
            resultados, pastas = rodar_capturas(
                CONFIGURACOES, sementes=argumentos.sementes, arvores=argumentos.arvores, nucleos=argumentos.nucleos,
                teto=argumentos.teto, trabalho=argumentos.trabalho, pcaps_fora=PCAPS_FORA,
                ao_ler=lambda nome, linhas: _relatar(f"{nome}: {_milhar(linhas)} janelas"),
            )
            entradas = {
                "configuracoes": [
                    {"nome": c.nome, "descricao": c.descricao, "destino": c.destino, "sem": list(c.sem),
                     "fundo_como_benigno": c.fundo_como_benigno, "opcoes": [list(o) for o in c.opcoes]}
                    for c in CONFIGURACOES
                ],
                "pastas": pastas,
            }
            manifesto = montar_manifesto(True, resultados, entradas, _parametros(argumentos, PCAPS_FORA), comando,
                                         time.perf_counter() - inicio)
        else:
            regeracao = _ler_json(argumentos.manifesto_da_regeracao)
            modelo = Path(argumentos.modelo)
            if set(argumentos.rodadas) & {"a", "i"} and not modelo.exists():
                raise ValueError(f"{modelo} não existe: as rodadas a e i precisam do modelo salvo (--modelo)")
            publicado_caminho = Path(argumentos.saida) / MANIFESTO_DO_TREINO
            publicado = _ler_json(publicado_caminho) if publicado_caminho.exists() else None
            dados = ler_dados(regeracao["destino"], regeracao,
                              ao_ler=lambda nome, linhas: _relatar(f"{nome}: {_milhar(linhas)} janelas"))
            resultados = rodar_sistema(
                dados, argumentos.rodadas, argumentos.sementes, argumentos.arvores, argumentos.nucleos, argumentos.teto,
                argumentos.trabalho, modelo if modelo.exists() else None, publicado, argumentos.dataset, PCAPS_FORA,
            )
            entradas = {
                "regeracao": _entrada_da_regeracao(argumentos.manifesto_da_regeracao, regeracao),
                "arquivos": dados.entradas,
                "modelo": ({"arquivo": modelo.name, "sha256": _sha256(modelo), "bytes": modelo.stat().st_size}
                           if modelo.exists() else None),
                "treino_publicado": ({"manifesto": publicado_caminho.as_posix(), "sha256": _sha256(publicado_caminho)}
                                     if publicado is not None else None),
            }
            manifesto = montar_manifesto(False, resultados, entradas, _parametros(argumentos, PCAPS_FORA), comando,
                                         time.perf_counter() - inicio)
        gravar(manifesto, saida)
    except (OSError, ValueError, KeyError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(f"interrompido: os treinos já feitos ficam em {argumentos.trabalho}/ e são reaproveitados", file=sys.stderr)
        return 130
    print(f"resultados em {saida}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
