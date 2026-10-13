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

Com `--capturas`, compara o modelo atual (configuração 0) com as alternativas da tabela
`CONFIGURACOES`, nas rodadas c, d e e e no corte por tempo; o comentário de cada configuração diz o
que ela muda. As diferenças entre configurações são pareadas por semente e medidas nas mesmas
janelas, com um intervalo que soma a variação entre sementes e a do conjunto de teste, por blocos
de janelas vizinhas (`comparar`).

O que é gravado em `experimentos/resultados/`: o manifesto de cada modo, com as versões, o
comando, o SHA-256 das entradas e do código e todos os números; o relatório
(`rodadas_relatorio`), que sai do manifesto; e as tabelas em CSV. Os resultados de cada treino,
com as predições janela a janela de que as comparações saem, ficam guardados em
`dados/processed/rodadas/`, fora do git, para que uma execução interrompida continue de onde
parou. A chave deles inclui o SHA-256 das entradas e do código que calcula: mudou qualquer um, o
resultado guardado deixa de valer. A tabela de configurações fica fora desse SHA-256 (ver
`codigo_da_chave`): acrescentar uma configuração não invalida os treinos guardados das outras.

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
import resource
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
    _decimal,
    _milhar,
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


# O trecho entre as duas marcas abaixo fica fora do SHA-256 do código na chave dos treinos guardados
# (`codigo_da_chave`). Cada configuração já entra na chave pelo que muda o cálculo: os arquivos da
# pasta de dados, as features tiradas e o fundo no treino. As opções do extrator são conferidas contra
# o manifesto da regeração, e o nome e a descrição só aparecem no relatório.
# --- início das configurações comparadas
# 0: o modelo atual.
ATUAL = Configuracao(
    "0", "o modelo atual", "dados/processed/regerado", "experimentos/resultados/manifesto_regeracao.json",
)
# 1: o quadro menor que 60 bytes contado como 60, o preenchimento que a placa de rede faz antes de
# transmitir; lê a pasta regerada antes por `regerar --preencher`.
PREENCHIDA = Configuracao(
    "1", "preenchimento até 60 bytes", "dados/processed/regerado_preenchido",
    "experimentos/resultados/regeracao_preenchido/manifesto_regeracao.json", opcoes=(("preencher", True),),
)
# 2: o preenchimento até 60 e o teto de 1.514 bytes no tamanho do quadro; lê a pasta regerada antes
# por `regerar --preencher --limitar`. As duas opções aproximam o tamanho do quadro no fio, sem
# reproduzi-lo: um quadro agregado de 64 KB seria, no fio, várias dezenas de quadros, e não um de
# 1.514 bytes, e a contagem de quadros e o ritmo da janela continuam os da captura.
LIMITADA = Configuracao(
    "2", "preenchimento até 60 e teto de 1.514 bytes", "dados/processed/regerado_preenchido_limitado",
    "experimentos/resultados/regeracao_preenchido_limitado/manifesto_regeracao.json",
    opcoes=(("limitar", True), ("preencher", True)),
)
CONFIGURACOES = (
    ATUAL,
    PREENCHIDA,
    LIMITADA,
    # 3: a configuração 2 sem `Time_To_Live`.
    Configuracao("3", "a 2 sem `Time_To_Live`", LIMITADA.destino, LIMITADA.regeracao, sem=("Time_To_Live",),
                 opcoes=LIMITADA.opcoes),
    # 4: a configuração 2 com as janelas de fundo da parte de treino de cada pcap de ataque no treino
    # como benignas.
    Configuracao("4", "a 2 com o fundo da parte de treino como Benign", LIMITADA.destino, LIMITADA.regeracao,
                 fundo_como_benigno=True, opcoes=LIMITADA.opcoes),
    # 5: o fundo da 4 sem a normalização do quadro: os dados da configuração 0, com as janelas de fundo
    # da parte de treino de cada pcap de ataque no treino como benignas.
    Configuracao("5", "a 0 com o fundo da parte de treino como Benign", ATUAL.destino, ATUAL.regeracao,
                 fundo_como_benigno=True),
)
# --- fim das configurações comparadas


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


def codigos(categorias):
    """O número de cada categoria na ordem das tabelas, para guardar as predições em pouco espaço."""
    return pd.Categorical(np.asarray(categorias, dtype=object), categories=CLASSES).codes.astype(np.int8)


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
    """Correlação do acerto de uma janela com o da seguinte, dentro de cada pcap, e o tamanho efetivo n(1-r)/(1+r).

    O acerto é centrado pela média do próprio pcap antes de formar os pares: a diferença de acerto
    entre um pcap e outro não é vizinhança, e sem o centro ela inflaria a correlação.
    """
    acerto, grupos = np.asarray(acerto, dtype=float), np.asarray(grupos, dtype=object)
    antes, depois = [], []
    for grupo in pd.unique(grupos):
        valores = acerto[grupos == grupo]
        if len(valores) > 2:
            valores = valores - valores.mean()
            antes.append(valores[:-1])
            depois.append(valores[1:])
    if not antes:
        return None, None
    a, b = np.concatenate(antes), np.concatenate(depois)
    escala = np.sqrt((a * a).sum() * (b * b).sum())
    if escala == 0:
        return None, None
    r = float((a * b).sum() / escala)
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

    O arquivo tem o nome da impressão digital das entradas, do código e dos parâmetros: dados
    novos, código novo, outro teto ou outra quantidade de árvores caem em outro arquivo, e o
    resultado antigo não é usado. As predições janela a janela de cada treino, de que as
    comparações saem, ficam numa pasta com o mesmo nome, um arquivo `.npz` por treino.
    """

    def __init__(self, pasta, impressao):
        self.caminho = Path(pasta) / f"{impressao}.json"
        self.pasta_das_predicoes = Path(pasta) / impressao
        try:
            self.resultados = json.loads(self.caminho.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.resultados = {}

    def _predicoes(self, chave):
        return self.pasta_das_predicoes / (chave.replace("|", "__") + ".npz")

    def obter(self, chave, exige=(), aceita=None):
        """O resultado guardado, se existe, tem as partes exigidas, passa em `aceita` e tem as predições."""
        resultado = self.resultados.get(chave)
        if resultado is None or any(parte not in resultado for parte in exige):
            return None
        if aceita is not None and not aceita(resultado):
            return None
        if not self._predicoes(chave).exists():
            return None
        return resultado

    def guardar(self, chave, resultado, predicoes):
        self.pasta_das_predicoes.mkdir(parents=True, exist_ok=True)
        provisorio = self._predicoes(chave).with_suffix(".parcial.npz")
        np.savez_compressed(provisorio, **predicoes)
        os.replace(provisorio, self._predicoes(chave))
        self.resultados[chave] = resultado
        provisorio = self.caminho.with_name(self.caminho.name + ".parcial")
        provisorio.write_text(json.dumps(self.resultados, ensure_ascii=False), encoding="utf-8")
        os.replace(provisorio, self.caminho)

    def predicoes(self, chave):
        """As predições janela a janela de um treino guardado."""
        with np.load(self._predicoes(chave)) as arquivo:
            return {nome: arquivo[nome] for nome in arquivo.files}


# Os módulos de que os números das rodadas saem. O SHA-256 deles entra na chave dos resultados
# guardados e no manifesto; o relatório (`rodadas_relatorio`) fica de fora, porque só formata.
MODULOS_DO_CALCULO = (
    "codigo/classificador/rodadas.py", "codigo/classificador/preparar.py", "codigo/classificador/treinar.py",
    "codigo/classificador/avaliar.py", "codigo/classificador/treinar_regerado.py",
    "codigo/classificador/regerar.py", "codigo/classificador/mapeamento.py", "codigo/captura/extrator.py",
)
RAIZ = Path(__file__).resolve().parents[2]


def codigo_do_calculo():
    """O SHA-256 de cada módulo de que os números saem e o commit em que o repositório está, se houver."""
    arquivos = {nome: _sha256(RAIZ / nome) for nome in MODULOS_DO_CALCULO}
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=RAIZ, capture_output=True, text=True,
                                check=True).stdout.strip()
        alterados = subprocess.run(["git", "status", "--porcelain", "--", *MODULOS_DO_CALCULO], cwd=RAIZ,
                                   capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit, alterados = None, ""
    return {"arquivos": arquivos, "commit": commit, "com_alteracoes_fora_do_commit": bool(alterados)}


INICIO_DAS_CONFIGURACOES = "# --- início das configurações comparadas"
FIM_DAS_CONFIGURACOES = "# --- fim das configurações comparadas"


def sem_as_configuracoes(texto):
    """O código do módulo sem as linhas entre as marcas da tabela de configurações, marcas incluídas.

    Só conta a linha que é a marca inteira: a marca citada dentro de um texto não corta nada. Sem as
    duas marcas, em ordem, o código fica inteiro.
    """
    linhas = texto.splitlines(keepends=True)
    marcas = [linha.strip() for linha in linhas]
    if INICIO_DAS_CONFIGURACOES not in marcas or FIM_DAS_CONFIGURACOES not in marcas:
        return texto
    inicio, fim = marcas.index(INICIO_DAS_CONFIGURACOES), marcas.index(FIM_DAS_CONFIGURACOES)
    if fim < inicio:
        return texto
    return "".join(linhas[:inicio] + linhas[fim + 1:])


def codigo_da_chave():
    """O SHA-256 de cada módulo de que os números saem, como entra na chave dos treinos guardados.

    É o de `codigo_do_calculo`, menos em `rodadas.py`, cujo SHA-256 deixa de fora a tabela de
    configurações (`sem_as_configuracoes`). O manifesto registra o SHA-256 do arquivo inteiro.
    """
    saida = {}
    for nome in MODULOS_DO_CALCULO:
        if nome == "codigo/classificador/rodadas.py":
            texto = sem_as_configuracoes((RAIZ / nome).read_text(encoding="utf-8"))
            saida[nome] = hashlib.sha256(texto.encode("utf-8")).hexdigest()
        else:
            saida[nome] = _sha256(RAIZ / nome)
    return saida


def impressao_da_configuracao(configuracao, dados, arvores, teto):
    """SHA-256 do que decide os resultados de uma configuração: entradas, código, features, fundo, árvores e teto."""
    chave = {
        "entradas": dados.entradas, "codigo": codigo_da_chave(), "sem": list(configuracao.sem),
        "fundo": configuracao.fundo_como_benigno, "arvores": arvores, "teto": teto, "janela": JANELA,
        "fracao": FRACAO_DE_TESTE_POR_TEMPO,
    }
    return hashlib.sha256(json.dumps(chave, sort_keys=True).encode("utf-8")).hexdigest()[:24]


def memoria_pico():
    """O pico de memória residente do processo até agora, em bytes (o macOS dá em bytes; o Linux, em KiB)."""
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == "darwin" else 1024)


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
        # Os pcaps em ordem de nome: o número de cada um identifica a janela nas predições guardadas.
        self.pcaps = sorted(p["arquivo"] for p in dados.regeracao["pcaps"])
        self.numero_do_pcap = {arquivo: i for i, arquivo in enumerate(self.pcaps)}

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
        """As categorias previstas em todas as janelas mantidas de um pcap, e a predição de cada janela."""
        X, meta = self.dados.do_pcap(arquivo)
        previsto = prever(modelo, self._X(X))
        registro = {"arquivo": arquivo, "janelas": len(X), "previstas": contagem(previsto)}
        return registro, {"previsto": codigos(previsto), "indice": meta["indice"].to_numpy(dtype=np.int32)}

    def _de_fora(self, modelo, lados_da_divisao):
        """Os pcaps inteiros no teste, com as categorias previstas, e as predições do pcap benigno de fora."""
        rotulo = {p["arquivo"]: p["rotulo"] for p in self.dados.regeracao["pcaps"]}
        registros, predicoes = [], {}
        for arquivo in de_fora(lados_da_divisao):
            registro, janela_a_janela = self._no_pcap(modelo, arquivo)
            registros.append({**registro, "rotulo": rotulo[arquivo], "categoria": CATEGORIA[rotulo[arquivo]]})
            if CATEGORIA[rotulo[arquivo]] == BENIGNO:
                predicoes = {f"benigno_{chave}": valor for chave, valor in janela_a_janela.items()}
        return registros, predicoes

    def _fundo(self, modelo, lados_da_divisao):
        """O modelo nas janelas descartadas de cada pcap de ataque, na parte de treino e na de teste."""
        meta = self.dados.fundo_meta
        if not len(meta):
            return [], {}
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
        predicoes = {
            "fundo_previsto": codigos(previsto), "fundo_teste": teste,
            "fundo_arquivo": np.array([self.numero_do_pcap[a] for a in arquivos], dtype=np.int16),
            "fundo_indice": meta["indice"].to_numpy(dtype=np.int32),
        }
        return saida, predicoes

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

    def _guardado(self, chave, funcao, exige=(), aceita=None):
        """O resultado guardado do treino, ou o treino feito agora e guardado com as predições janela a janela."""
        resultado = self.trabalho.obter(chave, exige, aceita)
        if resultado is None:
            inicio = time.perf_counter()
            resultado, predicoes = funcao()
            resultado["memoria_pico_bytes"] = memoria_pico()
            self.trabalho.guardar(chave, resultado, predicoes)
            _relatar(f"configuração {self.configuracao.nome}, {chave}: {_decimal(time.perf_counter() - inicio)} s")
        return resultado

    def predicoes(self, chave):
        return self.trabalho.predicoes(chave)

    # Os treinos.

    def corte(self, semente, detalhe=None):
        """O treino da divisão por tempo publicada. Com `detalhe`, também as medidas das rodadas a, f, g e h.

        O detalhe guardado só vale se veio do mesmo modelo salvo e do mesmo manifesto publicado.
        """
        if detalhe is None:
            return self._guardado(f"corte|{semente}", lambda: self._corte(semente, None))
        return self._guardado(f"corte|{semente}", lambda: self._corte(semente, detalhe), ("detalhe",),
                              lambda r: r["detalhe"].get("entradas") == detalhe.entradas)

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
        fora, predicoes_de_fora = self._de_fora(modelo, lados_da_divisao)
        fundo, predicoes_do_fundo = self._fundo(modelo, lados_da_divisao)
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
            "fundo": fundo,
            "ttl": self._ttl(modelo, benigno) if benigno else None,
            "alarmes_no_benigno": self._alarmes_no_benigno(modelo, benigno) if benigno else None,
        }
        if detalhe is not None:
            resultado["detalhe"] = detalhe(self, modelo, posicoes, teste, previsto)
        predicoes = {
            "teste_previsto": codigos(previsto), "teste_real": codigos(alvo(rotulos, ALVO)),
            "teste_arquivo": np.array([self.numero_do_pcap[a] for a in arquivos], dtype=np.int16),
            "teste_indice": meta["indice"].to_numpy(dtype=np.int32)[teste],
            **predicoes_de_fora, **predicoes_do_fundo,
        }
        return resultado, predicoes

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
        fora, predicoes = self._de_fora(modelo, lados_da_divisao)
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
        }, predicoes

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
            "inteiro": self._no_pcap(modelo, arquivo)[0],
        }, {"teste_previsto": codigos(previsto), "teste_indice": meta["indice"].to_numpy(dtype=np.int32)[do_pcap]}


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


def detalhar(modelo_salvo=None, publicado=None, caminho_publicado=None):
    """A função que mede, no treino da semente principal, as rodadas a, f (permutação), g e h.

    A função leva em `entradas` o SHA-256 do modelo salvo e do manifesto publicado com que a
    reprodução é conferida: o detalhe guardado com outros não é reaproveitado.
    """
    entradas = {
        "modelo_sha256": _sha256(modelo_salvo) if modelo_salvo is not None else None,
        "publicado_sha256": _sha256(caminho_publicado) if caminho_publicado is not None else None,
    }

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
            "entradas": entradas,
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

    detalhe.entradas = entradas
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
        str(rotacao): execucao._rotacao(semente, rotacao, ARVORES_MENOR)[0]["de_fora"]
        for rotacao in range(1, rotacoes(dados.regeracao))
    }
    return saida


# --- comparações pareadas ----------------------------------------------------------------------
#
# Duas condições (duas configurações, ou o modelo com e sem um pcap no treino) são comparadas nas
# mesmas janelas e com a mesma semente: o teto sorteia as mesmas posições em todas as pastas, e a
# divisão é a mesma. Em cada semente, a diferença da medida entre as duas condições ganha uma
# variância por reamostragem de blocos de janelas vizinhas do mesmo pcap, sorteados juntos para as
# duas condições. A diferença publicada é a média das sementes, e a variância dela soma a média das
# variâncias por blocos (a do conjunto de teste) e a variância da diferença entre as sementes
# dividida pela quantidade delas (a do treino). A diferença conta quando o intervalo de 95% não
# contém o zero.

REAMOSTRAGENS_DA_DIFERENCA = 2000
LOTE_DE_REAMOSTRAGENS = 200


def _blocos_das_janelas(grupo, indice, bloco=BLOCO):
    """O bloco de cada janela (janelas vizinhas do mesmo pcap, de `bloco` em `bloco`) e o pcap de cada bloco."""
    chave = np.asarray(grupo, dtype=np.int64) * (1 << 32) + np.asarray(indice, dtype=np.int64) // bloco
    unicos, inverso = np.unique(chave, return_inverse=True)
    return inverso, unicos >> 32


def proporcao(somas):
    """A fração, das somas por janela (acerto, 1)."""
    with np.errstate(divide="ignore", invalid="ignore"):
        return {"valor": somas[..., 0] / somas[..., 1]}


def medidas_da_confusao(somas):
    """As medidas do `avaliar` a partir da matriz de confusão achatada (categoria real x 7 + prevista).

    Aceita uma matriz ou várias (as das reamostragens), e devolve as medidas de cada uma.
    """
    n = len(CLASSES)
    confusao = somas.reshape(*somas.shape[:-1], n, n)
    certas = np.diagonal(confusao, axis1=-2, axis2=-1)
    suporte, previstas = confusao.sum(axis=-1), confusao.sum(axis=-2)
    total = suporte.sum(axis=-1)
    with np.errstate(divide="ignore", invalid="ignore"):
        recall = np.where(suporte > 0, certas / suporte, np.nan)
        precisao = np.where(previstas > 0, certas / previstas, np.where(suporte > 0, 0.0, np.nan))
        f1 = np.where(precisao + recall > 0, 2 * precisao * recall / (precisao + recall), 0.0)
        f1 = np.where(suporte > 0, f1, np.nan)
        benigno = CLASSES.index(BENIGNO)
        saida = {
            "macro_f1": np.nanmean(f1, axis=-1),
            "acuracia": certas.sum(axis=-1) / total,
            "benigno_como_ataque": 1 - recall[..., benigno],
            "ataque_como_benigno": (previstas[..., benigno] - certas[..., benigno]) / (total - suporte[..., benigno]),
        }
    for i, classe in enumerate(CLASSES):
        saida[f"recall_{classe}"] = recall[..., i]
        saida[f"precisao_{classe}"] = precisao[..., i]
        saida[f"f1_{classe}"] = f1[..., i]
    return saida


def _diferenca_por_blocos(grupo, indice, a, b, medidas, gerador, reamostragens, largura):
    """A diferença b − a de cada medida, e as diferenças nas reamostragens de blocos, numa semente."""
    inverso, grupo_do_bloco = _blocos_das_janelas(grupo, indice)
    m = len(grupo_do_bloco)

    def somas(valores):
        if largura == 2:  # proporção: o acerto e a contagem
            return np.stack([np.bincount(inverso, weights=valores, minlength=m),
                             np.bincount(inverso, minlength=m).astype(float)], axis=1)
        return np.bincount(inverso * largura + valores, minlength=m * largura).reshape(m, largura).astype(float)

    soma_a, soma_b = somas(a), somas(b)
    medida_a, medida_b = medidas(soma_a.sum(axis=0)), medidas(soma_b.sum(axis=0))
    pontual = {chave: float(medida_b[chave] - medida_a[chave]) for chave in medida_a}
    blocos_do_pcap = [np.flatnonzero(grupo_do_bloco == g) for g in np.unique(grupo_do_bloco)]
    reamostras = {chave: [] for chave in medida_a}
    for inicio in range(0, reamostragens, LOTE_DE_REAMOSTRAGENS):
        lote = min(LOTE_DE_REAMOSTRAGENS, reamostragens - inicio)
        linhas = np.arange(lote)[:, np.newaxis] * m
        sorteados = np.concatenate([
            (linhas + blocos[gerador.integers(0, len(blocos), (lote, len(blocos)))]).ravel() for blocos in blocos_do_pcap
        ])
        pesos = np.bincount(sorteados, minlength=lote * m).reshape(lote, m).astype(float)
        de_a, de_b = medidas(pesos @ soma_a), medidas(pesos @ soma_b)
        for chave, valores in reamostras.items():
            valores.append(de_b[chave] - de_a[chave])
    return pontual, {chave: np.concatenate(valores) for chave, valores in reamostras.items()}


def comparar(pares, medidas, largura, reamostragens=REAMOSTRAGENS_DA_DIFERENCA, semente=SEMENTES[0]):
    """A diferença pareada de cada medida entre duas condições, com o intervalo de 95%.

    `pares` tem, por semente, (grupo, índice, a, b): o pcap e o índice de cada janela e o valor dela
    nas duas condições; com `largura` 2, o valor é 0 ou 1 e a medida é uma proporção; com outra
    largura, é a célula da matriz de confusão. Devolve, por medida, a diferença média (b − a), a de
    cada semente, o intervalo e se ele deixa o zero de fora.
    """
    gerador = np.random.default_rng(semente)
    por_semente = [
        _diferenca_por_blocos(grupo, indice, a, b, medidas, gerador, reamostragens, largura)
        for grupo, indice, a, b in pares
    ]
    saida = {}
    for chave in por_semente[0][0]:
        diferencas = np.array([pontual[chave] for pontual, _ in por_semente])
        variancia = float(np.mean([np.nanvar(reamostras[chave]) for _, reamostras in por_semente]))
        if len(diferencas) > 1:
            variancia += float(np.var(diferencas, ddof=1)) / len(diferencas)
        media = float(np.mean(diferencas))
        if not np.isfinite(media) or not np.isfinite(variancia):
            saida[chave] = {"diferenca": None, "inferior": None, "superior": None, "por_semente": None, "acima": False}
            continue
        meia = Z * np.sqrt(variancia)
        saida[chave] = {
            "diferenca": media, "inferior": media - meia, "superior": media + meia,
            "por_semente": diferencas.tolist(), "acima": bool(abs(media) > meia),
        }
    return saida


def _alinhadas(a, b, campos, contexto):
    """As duas condições têm de ter as mesmas janelas, na mesma ordem."""
    for campo in campos:
        if not np.array_equal(a[campo], b[campo]):
            raise ValueError(f"{contexto}: as janelas das duas condições não são as mesmas ({campo})")


def comparar_cortes(execucao_a, execucao_b, sementes, chave_b="corte"):
    """O corte por tempo de duas condições, nas medidas da matriz de confusão e no pcap benigno de fora."""
    pares, benignos = [], []
    for semente in sementes:
        a, b = execucao_a.predicoes(f"corte|{semente}"), execucao_b.predicoes(f"{chave_b}|{semente}")
        _alinhadas(a, b, ("teste_arquivo", "teste_indice", "teste_real", "benigno_indice"), f"corte, semente {semente}")
        n = len(CLASSES)
        pares.append((a["teste_arquivo"], a["teste_indice"], a["teste_real"].astype(np.int64) * n + a["teste_previsto"],
                      a["teste_real"].astype(np.int64) * n + b["teste_previsto"]))
        benigno = CLASSES.index(BENIGNO)
        benignos.append((np.zeros(len(a["benigno_indice"])), a["benigno_indice"],
                         (a["benigno_previsto"] != benigno).astype(float), (b["benigno_previsto"] != benigno).astype(float)))
    saida = comparar(pares, medidas_da_confusao, len(CLASSES) ** 2)
    saida["benigno_de_fora"] = comparar(benignos, proporcao, 2)["valor"]
    return saida


def comparar_configuracoes(referencia, outra, sementes, rotacoes_, pcaps_fora):
    """Todas as comparações entre uma configuração e a de referência: corte, rotação, fundo e pcap fora."""
    benigno = CLASSES.index(BENIGNO)
    saida = {"corte": comparar_cortes(referencia, outra, sementes)}
    # Rotação: o pcap benigno de fora em cada rotação, e todos juntos.
    por_pcap, juntos = {}, [[] for _ in sementes]
    for rotacao in range(rotacoes_):
        for i, semente in enumerate(sementes):
            chave = f"corte|{semente}" if rotacao == 0 else f"rotacao|{rotacao}|{semente}"
            a, b = referencia.predicoes(chave), outra.predicoes(chave)
            _alinhadas(a, b, ("benigno_indice",), chave)
            arquivo = next(p["arquivo"] for p in referencia.trabalho.resultados[chave]["de_fora"]
                           if p["categoria"] == BENIGNO)
            par = (np.full(len(a["benigno_indice"]), referencia.numero_do_pcap[arquivo]), a["benigno_indice"],
                   (a["benigno_previsto"] != benigno).astype(float), (b["benigno_previsto"] != benigno).astype(float))
            por_pcap.setdefault(arquivo, []).append(par)
            juntos[i].append(par)
    saida["rotacao"] = {arquivo: comparar(pares, proporcao, 2)["valor"] for arquivo, pares in por_pcap.items()}
    saida["rotacao"]["total"] = comparar([tuple(np.concatenate(campo) for campo in zip(*partes)) for partes in juntos],
                                         proporcao, 2)["valor"]
    # Fundo: como ataque, nas partes de teste e de treino, e na categoria do pcap, por pcap.
    categoria_do_pcap = {
        referencia.numero_do_pcap[p["arquivo"]]: CLASSES.index(CATEGORIA[p["rotulo"]])
        for p in referencia.dados.regeracao["pcaps"]
    }
    fundo = {"teste": [], "treino": []}
    na_categoria = {}
    for semente in sementes:
        a, b = referencia.predicoes(f"corte|{semente}"), outra.predicoes(f"corte|{semente}")
        _alinhadas(a, b, ("fundo_arquivo", "fundo_indice", "fundo_teste"), f"fundo, semente {semente}")
        for parte, lado in (("teste", a["fundo_teste"]), ("treino", ~a["fundo_teste"])):
            fundo[parte].append((a["fundo_arquivo"][lado], a["fundo_indice"][lado],
                                 (a["fundo_previsto"][lado] != benigno).astype(float),
                                 (b["fundo_previsto"][lado] != benigno).astype(float)))
        categoria = np.array([categoria_do_pcap[g] for g in a["fundo_arquivo"]], dtype=np.int8)
        for numero in np.unique(a["fundo_arquivo"][a["fundo_teste"]]):
            do_pcap = a["fundo_teste"] & (a["fundo_arquivo"] == numero)
            na_categoria.setdefault(referencia.pcaps[numero], []).append((
                a["fundo_arquivo"][do_pcap], a["fundo_indice"][do_pcap],
                (a["fundo_previsto"][do_pcap] == categoria[do_pcap]).astype(float),
                (b["fundo_previsto"][do_pcap] == categoria[do_pcap]).astype(float),
            ))
    saida["fundo"] = {parte: comparar(pares, proporcao, 2)["valor"] for parte, pares in fundo.items()}
    saida["fundo"]["por_pcap"] = {arquivo: comparar(pares, proporcao, 2)["valor"] for arquivo, pares in na_categoria.items()}
    # Pcap fora do treino: cada pcap e cada categoria, na categoria e como ataque.
    saida["fora"] = _comparar_fora(
        lambda arquivo, semente: referencia.predicoes(f"fora|{arquivo}|{semente}"),
        lambda arquivo, semente: outra.predicoes(f"fora|{arquivo}|{semente}"),
        referencia, sementes, pcaps_fora,
    )
    return saida


def _comparar_fora(predicoes_a, predicoes_b, execucao, sementes, pcaps_fora):
    """O recall de cada pcap fora do treino e o de cada categoria, somando os pcaps dela, entre duas condições."""
    benigno = CLASSES.index(BENIGNO)
    categoria_do = {p["arquivo"]: CATEGORIA[p["rotulo"]] for p in execucao.dados.regeracao["pcaps"]}
    por_pcap, por_categoria = {}, {}
    for arquivo in pcaps_fora:
        categoria = CLASSES.index(categoria_do[arquivo])
        for i, semente in enumerate(sementes):
            a, b = predicoes_a(arquivo, semente), predicoes_b(arquivo, semente)
            _alinhadas(a, b, ("teste_indice",), f"{arquivo}, semente {semente}")
            grupo = np.full(len(a["teste_indice"]), execucao.numero_do_pcap[arquivo])
            na = (grupo, a["teste_indice"], (a["teste_previsto"] == categoria).astype(float),
                  (b["teste_previsto"] == categoria).astype(float))
            ataque = (grupo, a["teste_indice"], (a["teste_previsto"] != benigno).astype(float),
                      (b["teste_previsto"] != benigno).astype(float))
            por_pcap.setdefault(arquivo, []).append(na)
            listas = por_categoria.setdefault(categoria_do[arquivo], {"na_categoria": [[] for _ in sementes],
                                                                      "como_ataque": [[] for _ in sementes]})
            listas["na_categoria"][i].append(na)
            listas["como_ataque"][i].append(ataque)

    def juntar(partes):
        return [tuple(np.concatenate(campo) for campo in zip(*por_semente)) for por_semente in partes]

    return {
        "por_pcap": {arquivo: comparar(pares, proporcao, 2)["valor"] for arquivo, pares in por_pcap.items()},
        "por_categoria": {
            categoria: {medida: comparar(juntar(partes), proporcao, 2)["valor"] for medida, partes in listas.items()}
            for categoria, listas in por_categoria.items()
        },
    }


def comparar_dentro_e_fora(execucao, sementes, pcaps_fora):
    """O recall de cada pcap com o modelo da divisão publicada (dentro da captura) e com o pcap fora do treino."""

    def dentro(arquivo, semente):
        corte = execucao.predicoes(f"corte|{semente}")
        do_pcap = corte["teste_arquivo"] == execucao.numero_do_pcap[arquivo]
        return {"teste_previsto": corte["teste_previsto"][do_pcap], "teste_indice": corte["teste_indice"][do_pcap]}

    return _comparar_fora(dentro, lambda arquivo, semente: execucao.predicoes(f"fora|{arquivo}|{semente}"),
                          execucao, sementes, pcaps_fora)


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
                  trabalho=TRABALHO, modelo_salvo=None, publicado=None, dataset=None, pcaps_fora=PCAPS_FORA,
                  caminho_publicado=None):
    """As rodadas pedidas sobre o modelo do sistema. Devolve os resultados, por rodada e por semente."""
    rodadas = set(rodadas)
    execucao = Execucao(ATUAL, dados, arvores, nucleos, teto, trabalho)
    principal, controle = sementes[0], list(sementes[:SEMENTES_DE_CONTROLE])
    detalhe = detalhar(modelo_salvo, publicado, caminho_publicado) if rodadas & set("afgh") else None
    if "b" in rodadas:
        sementes_do_corte = list(sementes)
    elif rodadas & set("cdefh"):
        sementes_do_corte = controle
    else:
        sementes_do_corte = [principal]
    saida = {"rodadas": sorted(rodadas), "corte": {}, "rotacao": {}, "fora": {}, "sem_ttl": {}, "comparacoes": {}}
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
        saida["comparacoes"]["dentro_e_fora"] = comparar_dentro_e_fora(execucao, controle, pcaps_fora)
    if "f" in rodadas:
        saida["tamanhos"] = tamanhos(dados)
        sem_ttl = Execucao(
            Configuracao("0", "sem Time_To_Live", ATUAL.destino, ATUAL.regeracao, sem=("Time_To_Live",)),
            dados, arvores, nucleos, teto, trabalho,
        )
        saida["sem_ttl"] = _por_semente(sem_ttl.corte(semente) for semente in controle)
        saida["comparacoes"]["sem_ttl"] = comparar_cortes(execucao, sem_ttl, controle)
    if "i" in rodadas:
        saida["custo"] = execucao._guardado(
            f"custo|{principal}", lambda: (custo(execucao, principal, modelo_salvo, dataset), {}),
        )
    return saida


def rodar_capturas(configuracoes=CONFIGURACOES, sementes=SEMENTES, arvores=ARVORES, nucleos=TODOS_OS_NUCLEOS,
                   teto=TETO, trabalho=TRABALHO, pcaps_fora=PCAPS_FORA, ler=ler_dados, ao_ler=None):
    """O corte por tempo e as rodadas c, d e e em cada configuração, com as primeiras sementes de controle."""
    controle = list(sementes[:SEMENTES_DE_CONTROLE])
    saida, entradas, carregados, execucoes = {}, {}, (None, None), {}
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
        # As comparações só leem as predições guardadas: a execução fica só com o manifesto da regeração,
        # e os dados da pasta saem da memória quando a próxima configuração lê outra pasta.
        execucao.dados = SoRegeracao(dados.regeracao)
        execucoes[configuracao.nome] = execucao
        del dados
    carregados = (None, None)
    referencia = execucoes[configuracoes[0].nome]
    for nome, execucao in execucoes.items():
        if execucao is not referencia:
            saida[nome]["comparacao"] = comparar_configuracoes(
                referencia, execucao, controle, rotacoes(referencia.dados.regeracao), pcaps_fora,
            )
    return saida, entradas


@dataclass
class SoRegeracao:
    """O que as comparações usam dos dados de uma pasta: só o manifesto da regeração."""

    regeracao: dict


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
        "codigo": codigo_do_calculo(),
        "resultados": resultados,
        "duracao_segundos": duracao,
        "memoria_pico_bytes": memoria_pico(),
    }


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
        "reamostragens": REAMOSTRAGENS, "reamostragens_da_diferenca": REAMOSTRAGENS_DA_DIFERENCA, "bloco": BLOCO,
        "arvores_menor": ARVORES_MENOR,
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
                publicado_caminho if publicado is not None else None,
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
        # O relatório importa este módulo; a importação fica aqui para não haver ciclo.
        from codigo.classificador.rodadas_relatorio import gravar

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
