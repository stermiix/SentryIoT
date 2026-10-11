"""Preparação da amostra para o treino do classificador.

Reúne o que vem antes do treino: ler a amostra, escolher as features, escolher o alvo e separar
treino e teste. Nada aqui é decidido de uma vez por todas: os conjuntos de features, os alvos e
as duas divisões existem lado a lado para que o experimento compare as alternativas.

Features. As 39 do dataset ou 33, sem as seis colunas que dependem do tamanho da janela:
`Number`, que é a quantidade de quadros da janela, e cinco colunas que são o produto de uma
coluna que fica por `Number`. As 33 que ficam ainda variam com o tamanho da janela
(`dados/README.md`): tirar as seis não tira esse atalho.

Alvo. As 34 classes, as 8 categorias dos autores, 7 categorias com DDoS e DoS fundidas, ou
ataque e benigno.

Divisão. Sorteio estratificado de linhas ou divisão por grupos, em que todas as linhas com o
mesmo vetor de features ficam do mesmo lado. Nas duas, 20% das linhas vão para o teste. Para os
dados regerados dos pcaps há a divisão por tempo: dentro de cada arquivo, as primeiras janelas
vão para o treino e as últimas para o teste, e um rótulo com mais de um arquivo tem um arquivo
inteiro no teste.

Valores vazios e infinitos. A amostra traz `Std` e `Variance` vazios nas janelas de um só quadro
e `Rate` infinito nas janelas sem duração. As linhas são mantidas, porque o extrator produz os
mesmos valores em operação. O infinito vira vazio, e o Random Forest do scikit-learn trata o
vazio sem imputação.
"""
import gzip
import hashlib
import io
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from codigo.captura.extrator import COLUNAS
from codigo.classificador.mapeamento import (
    BINARIO_DO_ROTULO,
    CATEGORIA_DO_ROTULO,
    CATEGORIAS,
    ROTULOS,
    normalizar,
)

SEMENTE = 42
FRACAO_DE_TESTE = 0.2
FRACAO_DE_TESTE_POR_TEMPO = 0.3

FEATURES_39 = COLUNAS
# `Number` é a quantidade de quadros da janela, e as outras cinco são o produto de uma coluna
# que fica por `Number`.
DEPENDENTES_DA_JANELA = ("Number", "Tot sum", "ack_count", "syn_count", "fin_count", "rst_count")
FEATURES_33 = tuple(coluna for coluna in COLUNAS if coluna not in DEPENDENTES_DA_JANELA)
CONJUNTOS_DE_FEATURES = {"39": FEATURES_39, "33": FEATURES_33}
# As divisões por sorteio valem para a amostra do MERGED_CSV; a por tempo, para os dados regerados.
DIVISOES_POR_SORTEIO = ("estratificada", "grupos")
DIVISOES = (*DIVISOES_POR_SORTEIO, "tempo")

FUSAO = "DDoS+DoS"


@dataclass(frozen=True)
class Alvo:
    """O que o modelo aprende a responder."""

    classes: tuple  # na ordem em que aparecem nas tabelas
    classe_do_rotulo: dict  # rótulo canônico -> classe

    @property
    def benigno(self):
        """Como o tráfego benigno se chama neste alvo."""
        return self.classe_do_rotulo["BenignTraffic"]


ALVOS = {
    "34": Alvo(ROTULOS, {rotulo: rotulo for rotulo in ROTULOS}),
    "8": Alvo(CATEGORIAS, CATEGORIA_DO_ROTULO),
    "7": Alvo(
        (FUSAO, *(nome for nome in CATEGORIAS if nome not in ("DDoS", "DoS"))),
        {rotulo: FUSAO if nome in ("DDoS", "DoS") else nome for rotulo, nome in CATEGORIA_DO_ROTULO.items()},
    ),
    "2": Alvo(("Attack", "Benign"), BINARIO_DO_ROTULO),
}


def _faltantes(nome, colunas, pedidas):
    faltam = [coluna for coluna in pedidas if coluna not in colunas]
    if faltam:
        raise ValueError(f"{nome}faltam as colunas {', '.join(faltam)}")


def ler(caminho):
    """Lê um CSV com as 39 features, comprimido (.gz) ou não.

    Devolve o quadro, com as 39 colunas em ponto flutuante de 64 bits e as demais como texto, e
    o SHA-256 do CSV descomprimido. Campo vazio vira valor vazio, e `inf` vira infinito.
    """
    caminho = Path(caminho)
    nome = caminho.name
    with (gzip.open(caminho, "rb") if caminho.suffix == ".gz" else open(caminho, "rb")) as arquivo:
        bruto = arquivo.read()
    cabecalho = bruto.split(b"\n", 1)[0].decode("utf-8-sig", "replace").strip()
    if not cabecalho:
        raise ValueError(f"{nome}: arquivo vazio, sem a linha de cabeçalho")
    colunas = cabecalho.split(",")
    _faltantes(f"{nome}: ", colunas, COLUNAS)
    try:
        quadro = pd.read_csv(
            io.BytesIO(bruto),
            dtype={coluna: np.float64 if coluna in COLUNAS else object for coluna in colunas},
            # O conversor padrão do pandas erra o último dígito de alguns valores.
            float_precision="round_trip",
        )
    except ValueError as erro:
        raise ValueError(f"{nome}: valor que não é número ({erro})") from None
    return quadro, hashlib.sha256(bruto).hexdigest()


def carregar(caminho, rotulo=None):
    """Lê linhas com rótulo conhecido. Devolve o quadro, com `Label` na grafia canônica, e o SHA-256.

    O rótulo vem da coluna `Label`, como na amostra de treino, ou de `rotulo`, que vale para
    todas as linhas de um arquivo sem essa coluna, como a saída do extrator sobre uma captura.
    """
    quadro, sha256 = ler(caminho)
    nome = Path(caminho).name
    try:
        if rotulo is not None:
            if "Label" in quadro.columns:
                raise ValueError("o arquivo já traz a coluna Label, e um rótulo foi dado por fora")
            quadro["Label"] = normalizar(rotulo)
        elif "Label" not in quadro.columns:
            raise ValueError("falta a coluna Label")
        else:
            canonico = {grafia: normalizar(grafia) for grafia in quadro["Label"].unique()}
            quadro["Label"] = quadro["Label"].map(canonico)
        if quadro.empty:
            raise ValueError("nenhuma linha de dados")
    except ValueError as erro:
        raise ValueError(f"{nome}: {erro}") from None
    return quadro, sha256


def matriz(quadro, features):
    """As features pedidas, na ordem pedida, como o modelo as recebe.

    O scikit-learn converte as features para ponto flutuante de 32 bits antes de treinar, então
    a conversão é feita aqui: os vetores comparados na divisão por grupos e no cálculo do teto
    são os que o modelo de fato enxerga. Infinito vira vazio.
    """
    _faltantes("", quadro.columns, features)
    X = quadro[list(features)].to_numpy(dtype=np.float32)
    return np.where(np.isinf(X), np.float32(np.nan), X)


def alvo(rotulos, nome):
    """A classe de cada linha no alvo pedido: "34", "8", "7" ou "2"."""
    if nome not in ALVOS:
        raise ValueError(f"alvo desconhecido: {nome!r} (os alvos são {', '.join(ALVOS)})")
    classe_do_rotulo = ALVOS[nome].classe_do_rotulo
    posicao, unicos = pd.factorize(np.asarray(rotulos, dtype=object))
    return np.array([classe_do_rotulo[normalizar(rotulo)] for rotulo in unicos], dtype=object)[posicao]


def agrupar(X):
    """Número do grupo de cada linha: linhas com o mesmo vetor de features têm o mesmo número."""
    # A comparação é feita pelos bytes da linha. Somar zero desfaz o zero negativo, e reescrever
    # o vazio garante uma só representação para ele.
    iguais = np.ascontiguousarray(X + X.dtype.type(0))
    iguais[np.isnan(iguais)] = np.nan
    linhas = iguais.view(np.dtype((np.void, iguais.dtype.itemsize * iguais.shape[1]))).ravel()
    return np.unique(linhas, return_inverse=True)[1]


def _conferir_estratos(estratos, unidade):
    nomes, quantos = np.unique(estratos, return_counts=True)
    poucos = [str(nome) for nome, n in zip(nomes, quantos) if n < 2]
    if poucos:
        raise ValueError(
            f"classes com menos de {unidade} para dividir entre treino e teste: {', '.join(poucos)}"
        )


def _sortear(estratos, semente, fracao):
    """Posições sorteadas para o teste, com a mesma fração em cada estrato."""
    try:
        _, teste = train_test_split(
            np.arange(len(estratos)), test_size=fracao, random_state=semente, stratify=estratos
        )
    except ValueError as erro:
        raise ValueError(f"não foi possível dividir treino e teste ({erro})") from None
    return teste


def dividir_estratificada(rotulos, semente=SEMENTE, fracao=FRACAO_DE_TESTE):
    """Sorteio de linhas, com a mesma fração de cada rótulo no teste. Devolve (treino, teste).

    A estratificação é pelos rótulos, e não pelo alvo, para que a divisão seja a mesma em todos
    os alvos: quem tem a fração certa de cada rótulo tem a fração certa de cada categoria.
    """
    rotulos = np.asarray(rotulos, dtype=object)
    _conferir_estratos(rotulos, "duas linhas")
    no_teste = np.zeros(len(rotulos), dtype=bool)
    no_teste[_sortear(rotulos, semente, fracao)] = True
    return np.flatnonzero(~no_teste), np.flatnonzero(no_teste)


def dividir_por_grupos(grupos, rotulos, semente=SEMENTE, fracao=FRACAO_DE_TESTE):
    """Sorteio de grupos: todas as linhas de um grupo ficam do mesmo lado. Devolve (treino, teste).

    O sorteio é estratificado pelo rótulo mais frequente de cada grupo. Um grupo pode reunir
    linhas de vários rótulos, então a fração de cada rótulo no teste fica perto da pedida, e
    não exata.
    """
    contagem = pd.DataFrame({"grupo": grupos, "rotulo": np.asarray(rotulos, dtype=object)}).value_counts()
    contagem = contagem.reset_index(name="linhas")
    # No empate vale o primeiro rótulo em ordem alfabética, para o resultado não depender da ordem das linhas.
    contagem = contagem.sort_values(["grupo", "linhas", "rotulo"], ascending=[True, False, True])
    do_grupo = contagem.drop_duplicates("grupo")
    estratos = do_grupo["rotulo"].to_numpy()
    _conferir_estratos(estratos, "dois vetores distintos")
    de_teste = do_grupo["grupo"].to_numpy()[_sortear(estratos, semente, fracao)]
    no_teste = np.isin(grupos, de_teste)
    return np.flatnonzero(~no_teste), np.flatnonzero(no_teste)


def dividir_por_tempo(quadro, fracao=FRACAO_DE_TESTE_POR_TEMPO, janelas_por_arquivo=None):
    """Divisão por tempo dos dados regerados dos pcaps. Devolve (treino, teste).

    Exige as colunas `Label`, `arquivo` e `indice` dos CSVs regerados. Num rótulo com um só
    arquivo, as janelas de índice menor que (1 - fração) do total de janelas do arquivo vão para o
    treino, e as demais para o teste: janelas vizinhas não ficam dos dois lados, a não ser o par
    na fronteira. O total é o de `janelas_por_arquivo`, quando dado, e senão o maior índice
    presente mais um. Num rótulo com mais de um arquivo, o último em ordem de nome vai inteiro
    para o teste, e os outros para o treino.
    """
    _faltantes("", quadro.columns, ("Label", "arquivo", "indice"))
    rotulos = quadro["Label"].to_numpy()
    arquivos = quadro["arquivo"].to_numpy()
    indices = quadro["indice"].to_numpy().astype(np.int64)
    janelas_por_arquivo = janelas_por_arquivo or {}
    no_teste = np.zeros(len(quadro), dtype=bool)
    for rotulo in np.unique(rotulos):
        do_rotulo = rotulos == rotulo
        nomes = sorted(np.unique(arquivos[do_rotulo]).tolist())
        if len(nomes) > 1:
            no_teste[do_rotulo & (arquivos == nomes[-1])] = True
            continue
        do_arquivo = do_rotulo & (arquivos == nomes[0])
        total = janelas_por_arquivo.get(nomes[0], int(indices[do_arquivo].max()) + 1)
        corte = int((1 - fracao) * total + 0.5)
        no_teste[do_arquivo & (indices >= corte)] = True
    return np.flatnonzero(~no_teste), np.flatnonzero(no_teste)


def dividir(quadro, divisao, semente=SEMENTE, fracao=None):
    """Divide a amostra pelo método pedido, "estratificada", "grupos" ou "tempo". Devolve (treino, teste).

    Os grupos são os vetores idênticos nas 33 features. Linhas iguais nas 39 também são iguais
    nas 33, então a mesma divisão serve aos dois conjuntos de features sem deixar vetor repetido
    entre treino e teste, e as execuções são comparadas nas mesmas linhas. Sem `fracao`, vale a
    fração padrão da divisão: 20% nos sorteios e 30% na divisão por tempo, que não usa a semente.
    """
    rotulos = quadro["Label"].to_numpy()
    if divisao == "estratificada":
        return dividir_estratificada(rotulos, semente, FRACAO_DE_TESTE if fracao is None else fracao)
    if divisao == "grupos":
        grupos = agrupar(matriz(quadro, FEATURES_33))
        return dividir_por_grupos(grupos, rotulos, semente, FRACAO_DE_TESTE if fracao is None else fracao)
    if divisao == "tempo":
        return dividir_por_tempo(quadro, FRACAO_DE_TESTE_POR_TEMPO if fracao is None else fracao)
    raise ValueError(f"divisão desconhecida: {divisao!r} (as divisões são {', '.join(DIVISOES)})")


def impressao_digital(indices):
    """SHA-256 das posições, para registrar uma divisão e conferir se outra execução chegou à mesma."""
    return hashlib.sha256(np.sort(np.asarray(indices, dtype=np.int64)).tobytes()).hexdigest()
