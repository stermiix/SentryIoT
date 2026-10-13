"""Treino e avaliação do Random Forest sobre os dados regerados dos pcaps.

Os dados vêm de `codigo.classificador.regerar`: as janelas de cada pcap do CICIoT2023 extraídas
pelo nosso extrator, com um tamanho de janela só para todas as classes e o rótulo de ataque
apenas nas janelas em que aparece um Raspberry Pi atacante. As janelas sem nenhum quadro do
atacante, o tráfego de fundo dos pcaps de ataque, ficam em `descartadas/`.

O que ele faz, por padrão, para o modelo do sistema (janela de 100, decisões de 13/10/2026):

1. Lê os CSVs regerados de todos os rótulos e limita cada rótulo a um teto de linhas, sorteadas
   com semente fixa, como na amostra do treino exploratório.
2. Divide treino e teste por tempo: dentro de cada pcap, as primeiras 70% das janelas vão para o
   treino e as últimas 30% para o teste, para não deixar janelas vizinhas dos dois lados. Um
   rótulo com mais de um pcap tem o último arquivo, pelo sufixo numérico do nome, inteiro no teste.
3. Põe no treino, como Benign, as janelas de fundo da parte de treino de cada pcap de ataque (a
   configuração 5 de `rodadas_normalizadas.md`). O fundo da parte de teste não entra no teste.
4. Escolhe o ponto de operação numa parte de validação (`operacao.escolher_regra`): as últimas
   15% da parte de treino de cada pcap. Um modelo treinado no resto classifica as janelas da
   validação, e os candidatos são a categoria mais provável (argmax) e os limiares t sobre
   1 − P(Benign); vence, entre os que deixam no máximo 1% do benigno da validação como ataque, o de
   maior recall de ataque na validação. O incidente abre com 3 janelas de ataque seguidas.
5. Treina o Random Forest de 7 categorias, com DDoS e DoS juntos, nas 39 features, com os
   parâmetros padrão do scikit-learn, e salva o modelo em `modelos/`, fora do git, com a regra
   escolhida e o N num JSON ao lado do `.joblib`.
6. Mede na parte de teste, com o argmax e com o melhor limiar, e diz qual é o ponto de operação: precisão,
   recall e F1 por categoria, macro-F1, taxa de falso positivo do benigno, matriz de confusão e,
   por pcap, a fração das janelas de teste na categoria esperada. Resume também os IPs de origem
   distintos por janela nas classes de DDoS e DoS, que é a base da separação entre os dois fora do
   modelo.
7. Grava `regeracao.md`, as tabelas em CSV, as matrizes de confusão e o manifesto de que tudo sai.

Com `--sem-fundo`, refaz o treino de 10/10, que foi o do sistema até 13/10 e fica como referência:
sem o fundo no treino e com as duas janelas, 10 e 100. Tudo o que ele grava leva `_sem_fundo` no
nome (`regeracao_sem_fundo.md`, `rf_regerado_janela_100_sem_fundo.joblib`), e o do sistema não muda.

Uso, a partir da raiz do repositório:
    python -m codigo.classificador.treinar_regerado --nucleos 4
    python -m codigo.classificador.treinar_regerado --sem-fundo --nucleos 4
    python -m codigo.classificador.treinar_regerado --refazer-relatorio
"""
import argparse
import datetime
import gzip
import io
import json
import platform
import resource
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn

from codigo.captura.extrator import COLUNAS
from codigo.classificador.avaliar import (
    avaliar,
    contar,
    importancias,
    matriz_de_confusao,
    medir,
)
from codigo.classificador.experimento import (
    MATRIZES,
    _campo,
    _decimal,
    _enumerar,
    _gravar_csv,
    _milhar,
    _pct,
    _pp,
    _tabela,
)
from codigo.classificador.mapeamento import (
    CATEGORIA_DO_ROTULO,
    CATEGORIAS,
    ROTULOS,
    normalizar,
)
from codigo.classificador.operacao import (
    ALARME_FALSO_MAXIMO,
    FRACAO_DE_VALIDACAO,
    LIMIARES,
    SEGUIDAS,
    PontoDeOperacao,
    escolher_regra,
    para_a_escolha,
)
from codigo.classificador.operacao import gravar as gravar_ponto
from codigo.classificador.preparar import (
    ALVOS,
    FEATURES_39,
    FRACAO_DE_TESTE_POR_TEMPO,
    SEMENTE,
    agrupar,
    alvo,
    dividir_por_tempo,
    impressao_digital,
    matriz,
    ordem_natural,
    ultimo_arquivo,
)
from codigo.classificador.regerar import CABECALHO, DESCARTADAS, nome_da_pasta
from codigo.classificador.regerar import MANIFESTO as MANIFESTO_DA_REGERACAO
from codigo.classificador.treinar import (
    ARVORES,
    TODOS_OS_NUCLEOS,
    _nucleos,
    _positivo,
    prever,
    salvar,
    treinar,
)

MANIFESTO = "manifesto_treino_regerado.json"
RELATORIO = "regeracao.md"
# O relatório das rodadas de teste do modelo de 10/10, com os controles que este relatório não faz.
RODADAS = "rodadas_de_teste.md"
# A comparação das configurações, com a regra de adoção do fundo no treino, e o ponto de operação.
CAPTURAS = "rodadas_normalizadas.md"
PONTO_DE_OPERACAO = "ponto_de_operacao.md"
METRICAS = "regeracao_metricas.csv"
POR_ARQUIVO = "regeracao_por_arquivo.csv"
MODELOS = "modelos"
# A janela do modelo do sistema (decisão de 10/10/2026) e o sufixo do treino de referência, sem o fundo.
JANELA_DO_SISTEMA = 100
SUFIXO_DE_REFERENCIA = "_sem_fundo"
MANIFESTO_DE_REFERENCIA = "manifesto_treino_regerado_sem_fundo.json"
# O modelo: 7 categorias, com DDoS e DoS juntos (decisão de 04/10/2026 no ROADMAP.md), nas 39 features.
ALVO = "7"
DIVISAO = "tempo"
# Teto de linhas por rótulo, como na amostra do treino exploratório.
TETO = 50_000
CLASSES = tuple(ALVOS[ALVO].classes)
EXTRAS = ("indice", "ips_origem", "ips_destino", "atacante")
# Colunas que os CSVs regerados a partir da versão 2 da regra trazem e os anteriores não trazem.
EXTRAS_OPCIONAIS = ("quadros_atacante", "macs_atacante")
# Linhas lidas por vez de cada CSV regerado: o rótulo maior da janela de 10 tem 5,3 milhões.
PEDACO = 200_000
# Quantas features o relatório lista, das mais importantes.
FEATURES_LISTADAS = 10


def nomes(fundo_como_benigno=True):
    """Os arquivos que um treino grava: os do sistema, ou os de referência, com `_sem_fundo` no nome."""
    sufixo = "" if fundo_como_benigno else SUFIXO_DE_REFERENCIA
    return {
        "sufixo": sufixo, "manifesto": MANIFESTO if fundo_como_benigno else MANIFESTO_DE_REFERENCIA,
        "relatorio": f"regeracao{sufixo}.md", "metricas": f"regeracao{sufixo}_metricas.csv",
        "por_arquivo": f"regeracao{sufixo}_por_arquivo.csv",
    }


def nome_do_modelo(janela, fundo_como_benigno=True):
    """O arquivo do modelo de uma janela em `modelos/`: o do sistema, ou o de referência, sem o fundo."""
    return f"rf_regerado_janela_{janela}{'' if fundo_como_benigno else SUFIXO_DE_REFERENCIA}.joblib"


def lados_por_tempo(regeracao, janela, fracao=FRACAO_DE_TESTE_POR_TEMPO):
    """Como cada pcap entra na divisão por tempo: "teste", "treino" ou o índice do corte.

    É a divisão de `dividir_por_tempo`, por pcap: num rótulo com mais de um pcap, o último pela ordem
    natural fica inteiro no teste e os outros, no treino; num rótulo de um pcap só, o corte é no
    total de janelas extraídas. Vale também para as janelas de fundo, que `dividir_por_tempo` não vê.
    """
    totais = {p["arquivo"]: p["janelas"][str(janela)]["extraidas"] for p in regeracao["pcaps"]}
    saida = {}
    for registro in regeracao["rotulos"]:
        arquivos = sorted(registro["arquivos"], key=ordem_natural)
        if len(arquivos) > 1:
            saida.update({arquivo: "teste" if arquivo == arquivos[-1] else "treino" for arquivo in arquivos})
        else:
            saida[arquivos[0]] = int((1 - fracao) * totais[arquivos[0]] + 0.5)
    return saida


def antes_do_corte(quadro, lados):
    """Se cada janela fica na parte de treino: num pcap de treino, ou antes do corte do pcap."""
    arquivos, indices = quadro["arquivo"].to_numpy(), quadro["indice"].to_numpy()
    dentro = np.zeros(len(quadro), dtype=bool)
    for arquivo in pd.unique(arquivos):
        do_pcap = arquivos == arquivo
        lado = lados[arquivo]
        if lado == "treino":
            dentro[do_pcap] = True
        elif lado != "teste":
            dentro[do_pcap] = indices[do_pcap] < lado
    return dentro


def inicios_da_validacao(regeracao, janela, lados, fracao=FRACAO_DE_VALIDACAO):
    """O índice da primeira janela da validação de cada pcap com parte de treino, e o fim dela.

    A validação são as últimas `fracao` da parte de treino do pcap, contadas nas janelas extraídas:
    até o corte por tempo, ou até o fim do arquivo no pcap de treino de um rótulo de vários pcaps.
    É a mesma de `ponto_de_operacao`. Devolve {arquivo: (início, fim)}.
    """
    totais = {p["arquivo"]: p["janelas"][str(janela)]["extraidas"] for p in regeracao["pcaps"]}
    saida = {}
    for arquivo, lado in lados.items():
        if lado == "teste":
            continue
        fim = totais[arquivo] if lado == "treino" else lado
        saida[arquivo] = (int((1 - fracao) * fim + 0.5), fim)
    return saida


def ler_fundo(destino, janela):
    """As janelas descartadas de uma janela, as de fundo dos pcaps de ataque, em ordem de arquivo e de linha."""
    pasta = Path(destino) / nome_da_pasta(janela) / DESCARTADAS
    partes = sorted(pasta.glob("*.csv.gz"))
    if not partes:
        raise ValueError(f"nenhuma janela descartada em {pasta}: regere com a versão 2 da regra, ou use --sem-fundo")
    tipos = {coluna: (np.float64 if coluna in COLUNAS else object) for coluna in CABECALHO}
    quadros = []
    for caminho in partes:
        with gzip.open(caminho, "rb") as arquivo:
            bruto = arquivo.read()
        if bruto:
            quadros.append(pd.read_csv(io.BytesIO(bruto), header=None, names=list(CABECALHO), dtype=tipos,
                                       float_precision="round_trip"))
    if not quadros:
        return pd.DataFrame(columns=list(CABECALHO))
    fundo = pd.concat(quadros, ignore_index=True)
    fundo["indice"] = fundo["indice"].astype(np.int64)
    return fundo


def com_fundo(X, y, fundo, lados):
    """As linhas de treino com as janelas de fundo da parte de treino de cada pcap, como Benign, no fim."""
    if fundo is None or not len(fundo):
        return X, y, 0
    dentro = antes_do_corte(fundo, lados)
    X_fundo = matriz(fundo[dentro], FEATURES_39)
    return (np.concatenate([X, X_fundo]), np.concatenate([y, np.full(len(X_fundo), ALVOS[ALVO].benigno, dtype=object)]),
            len(X_fundo))


def probabilidades(modelo, X):
    """`predict_proba` com um núcleo, pelo mesmo motivo de `prever`: a soma dos votos em ordem fixa."""
    nucleos = modelo.n_jobs
    modelo.n_jobs = 1
    try:
        return modelo.predict_proba(X)
    finally:
        modelo.n_jobs = nucleos


def regra_na_validacao(modelo, regeracao, destino, janela, validacao):
    """A regra escolhida na validação: as janelas dos pcaps benignos e as com o atacante dos pcaps de ataque.

    Usa todas as janelas da validação, e não só as do teto, como as de `ponto_de_operacao`. Os CSVs
    são lidos em pedaços, e só as janelas da validação são classificadas.
    """
    pasta = Path(destino) / nome_da_pasta(janela)
    benignos = {p["arquivo"] for p in regeracao["pcaps"] if p["benigno"] and p["arquivo"] in validacao}
    de_ataque = {p["arquivo"] for p in regeracao["pcaps"] if not p["benigno"] and p["arquivo"] in validacao}
    rotulo = {p["arquivo"]: p["rotulo"] for p in regeracao["pcaps"]}
    partes = {"benignas": ([], []), "de_ataque": ([], [])}
    for rotulo_do_csv in sorted({rotulo[a] for a in benignos | de_ataque}):
        caminho = pasta / f"{rotulo_do_csv}.csv.gz"
        colunas = pd.read_csv(caminho, nrows=0).columns.tolist()
        tipos = {coluna: np.float64 if coluna in FEATURES_39 else object for coluna in colunas}
        for pedaco in pd.read_csv(caminho, dtype=tipos, float_precision="round_trip", chunksize=PEDACO):
            arquivos = pedaco["arquivo"].to_numpy()
            indices = pedaco["indice"].to_numpy().astype(np.int64)
            for arquivo in pd.unique(arquivos):
                if arquivo not in validacao:
                    continue
                inicio, fim = validacao[arquivo]
                dentro = (arquivos == arquivo) & (indices >= inicio) & (indices < fim)
                if not dentro.any():
                    continue
                proba = probabilidades(modelo, matriz(pedaco[dentro], FEATURES_39))
                p_ataque, argmax = para_a_escolha(proba, modelo.classes_, ALVOS[ALVO].benigno)
                destino_ = partes["benignas" if arquivo in benignos else "de_ataque"]
                destino_[0].append(p_ataque)
                destino_[1].append(argmax)
    juntas = {nome: tuple(np.concatenate(lista) if lista else np.zeros(0) for lista in listas)
              for nome, listas in partes.items()}
    if not len(juntas["benignas"][0]):
        raise ValueError(f"janela de {janela}: a validação não tem nenhuma janela benigna")
    escolha = escolher_regra(juntas["benignas"], juntas["de_ataque"])
    if escolha["regra"] is None:
        raise ValueError(f"janela de {janela}: nem o argmax nem um limiar da grade deixa no máximo "
                         f"{ALARME_FALSO_MAXIMO} do benigno da validação como ataque")
    return {**escolha, "seguidas": SEGUIDAS}


def ler_janela(destino, janela, teto=None, semente=SEMENTE):
    """Os CSVs regerados de uma janela, de todos os rótulos, em ordem de arquivo e de índice.

    Com `teto`, cada rótulo é limitado ao ser lido, arquivo a arquivo, para que os rótulos de
    milhões de janelas não fiquem inteiros na memória. Devolve o quadro e um resumo do que foi
    lido antes do teto: as linhas regeradas de cada rótulo e os IPs de origem por janela nas
    classes de DDoS e DoS.
    """
    pasta = Path(destino) / nome_da_pasta(janela)
    arquivos = sorted(pasta.glob("*.csv.gz"))
    if not arquivos:
        raise ValueError(f"nenhum CSV regerado em {pasta}: rode python -m codigo.classificador.regerar")
    gerador = np.random.default_rng(semente)
    partes, resumo = [], {"regeradas": {}, "ips_de_origem": []}
    for arquivo in arquivos:
        partes.append(_ler_limitado(arquivo, teto, gerador, resumo))
    quadro = pd.concat(partes, ignore_index=True)
    resumo["regeradas"] = {rotulo: resumo["regeradas"][rotulo] for rotulo in ROTULOS if rotulo in resumo["regeradas"]}
    resumo["ips_de_origem"].sort(key=lambda r: ROTULOS.index(r["rotulo"]))
    return quadro.sort_values(["arquivo", "indice"], kind="stable").reset_index(drop=True), resumo


def _canonicos(rotulos):
    """Os rótulos na grafia canônica, normalizando cada grafia uma vez, como `carregar` faz."""
    return rotulos.map({grafia: normalizar(grafia) for grafia in rotulos.unique()})


def _ler_limitado(arquivo, teto, gerador, resumo):
    """Um CSV regerado com no máximo `teto` linhas por rótulo, lido em pedaços.

    A primeira leitura passa só pelo rótulo e pelos IPs de origem, para contar as linhas e resumir
    os IPs; o sorteio é o de `limitar`, sobre as posições das linhas de cada rótulo; a segunda
    leitura guarda só as linhas sorteadas, com os tipos de `preparar.ler`. Assim o arquivo nunca
    fica inteiro na memória, e o resultado é o de ler tudo e chamar `limitar`.
    """
    colunas = pd.read_csv(arquivo, nrows=0).columns.tolist()
    faltam = [coluna for coluna in (*FEATURES_39, "Label", "arquivo", *EXTRAS) if coluna not in colunas]
    if faltam:
        raise ValueError(f"{arquivo.name}: faltam as colunas {', '.join(faltam)}")
    rotulos, ips = [], []
    for pedaco in pd.read_csv(arquivo, usecols=["Label", "ips_origem"], dtype={"Label": object}, chunksize=PEDACO):
        rotulos.append(_canonicos(pedaco["Label"]).to_numpy(dtype=object))
        ips.append(pedaco["ips_origem"].to_numpy(dtype=np.int64))
    rotulos, ips = np.concatenate(rotulos), np.concatenate(ips)
    manter = np.zeros(len(rotulos), dtype=bool)
    for rotulo in sorted(np.unique(rotulos).tolist()):
        posicoes = np.flatnonzero(rotulos == rotulo)
        resumo["regeradas"][rotulo] = resumo["regeradas"].get(rotulo, 0) + len(posicoes)
        if teto is not None and len(posicoes) > teto:
            posicoes = gerador.choice(posicoes, teto, replace=False)
        manter[posicoes] = True
    resumo["ips_de_origem"] += ips_de_origem(pd.DataFrame({"Label": rotulos, "ips_origem": ips}))
    del rotulos, ips
    tipos = {coluna: np.float64 if coluna in FEATURES_39 else object for coluna in colunas}
    partes, inicio = [], 0
    for pedaco in pd.read_csv(arquivo, dtype=tipos, float_precision="round_trip", chunksize=PEDACO):
        fim = inicio + len(pedaco)
        partes.append(pedaco[manter[inicio:fim]])
        inicio = fim
    parte = pd.concat(partes, ignore_index=True)
    parte["Label"] = _canonicos(parte["Label"])
    for coluna in (*EXTRAS, *(c for c in EXTRAS_OPCIONAIS if c in parte.columns)):
        parte[coluna] = parte[coluna].astype(np.int64)
    return parte


def limitar(quadro, teto=TETO, semente=SEMENTE):
    """No máximo `teto` linhas por rótulo, sorteadas. As linhas ficam na ordem original.

    `semente` é um número ou um gerador já criado, para que a leitura arquivo a arquivo sorteie
    como se fosse de uma vez só.
    """
    gerador = semente if isinstance(semente, np.random.Generator) else np.random.default_rng(semente)
    rotulos = quadro["Label"].to_numpy()
    manter = np.zeros(len(quadro), dtype=bool)
    for rotulo in sorted(np.unique(rotulos).tolist()):
        posicoes = np.flatnonzero(rotulos == rotulo)
        if len(posicoes) > teto:
            posicoes = gerador.choice(posicoes, teto, replace=False)
        manter[posicoes] = True
    return quadro[manter]


def ips_de_origem(quadro):
    """Resumo dos IPs de origem distintos por janela nas classes de DDoS e DoS presentes."""
    resumo = []
    for rotulo in ROTULOS:
        if CATEGORIA_DO_ROTULO[rotulo] not in ("DDoS", "DoS"):
            continue
        ips = quadro.loc[quadro["Label"] == rotulo, "ips_origem"].to_numpy()
        if len(ips) == 0:
            continue
        resumo.append({
            "rotulo": rotulo,
            "categoria": CATEGORIA_DO_ROTULO[rotulo],
            "janelas": len(ips),
            "minimo": int(ips.min()),
            "p25": float(np.percentile(ips, 25)),
            "mediana": float(np.median(ips)),
            "p75": float(np.percentile(ips, 75)),
            "maximo": int(ips.max()),
            "media": float(ips.mean()),
            "ate_1": float((ips <= 1).mean()),
        })
    return resumo


def arquivos_inteiros_no_teste(amostra):
    """Os pcaps que vão inteiros para o teste: o último, na ordem natural, de cada rótulo com mais de um.

    É a mesma escolha de `dividir_por_tempo`, que usa `ultimo_arquivo`.
    """
    return sorted(
        ultimo_arquivo(arquivos.tolist())
        for arquivos in amostra.groupby("Label")["arquivo"].unique().values if len(arquivos) > 1
    )


def _por_arquivo(amostra, teste, previsto, previsto_limiar=None):
    """Por pcap: as janelas de teste, a fração na categoria esperada e as categorias previstas, nas duas regras."""
    arquivos = amostra[["arquivo", "Label"]].drop_duplicates().sort_values("arquivo")
    de_teste = amostra.iloc[teste]
    por_arquivo = []
    for arquivo, rotulo in arquivos.itertuples(index=False):
        esperada = ALVOS[ALVO].classe_do_rotulo[rotulo]
        no_teste = (de_teste["arquivo"] == arquivo).to_numpy()
        quantas = int(no_teste.sum())
        registro = {"arquivo": arquivo, "rotulo": rotulo, "esperada": esperada, "janelas_de_teste": quantas}
        for sufixo, predicao in (("", previsto), ("_limiar", previsto_limiar)):
            if predicao is None:
                continue
            previstas = {classe: 0 for classe in CLASSES}
            if no_teste.any():
                contagem = contar(de_teste["Label"].to_numpy()[no_teste], predicao[no_teste], CLASSES).sum(axis=0)
                previstas = {classe: int(contagem[classe]) for classe in CLASSES}
            registro[f"na_esperada{sufixo}"] = previstas[esperada] / quantas if quantas else None
            registro[f"previstas{sufixo}"] = previstas
        por_arquivo.append(registro)
    return por_arquivo


def _por_rotulo(regeracao, resumo, amostra, treino, teste, arquivos_de_teste):
    de_treino, de_teste = amostra.iloc[treino], amostra.iloc[teste]
    arquivos_do_rotulo = {r["rotulo"]: r["arquivos"] for r in regeracao["rotulos"]}
    por_rotulo = []
    for rotulo, regeradas in resumo["regeradas"].items():
        no_teste = de_teste[de_teste["Label"] == rotulo]
        por_rotulo.append({
            "rotulo": rotulo,
            "categoria": CATEGORIA_DO_ROTULO[rotulo],
            "arquivos": sorted(arquivos_do_rotulo.get(rotulo, [])),
            "regeradas": regeradas,
            "amostra": int((amostra["Label"] == rotulo).sum()),
            "treino": int((de_treino["Label"] == rotulo).sum()),
            "teste": len(no_teste),
            "linhas_no_arquivo_de_teste": int(no_teste["arquivo"].isin(arquivos_de_teste).sum()),
        })
    return por_rotulo


def treinar_janela(regeracao, destino, janela, semente=SEMENTE, arvores=ARVORES, nucleos=TODOS_OS_NUCLEOS,
                   teto=TETO, modelos=MODELOS, fundo_como_benigno=True):
    """Lê, limita, divide, escolhe o ponto de operação, treina, avalia e salva o modelo de uma janela.

    Com `fundo_como_benigno`, as janelas de fundo da parte de treino de cada pcap de ataque entram no
    treino como Benign, depois das linhas com rótulo, como nas rodadas (configuração 5). O limiar sai
    de um modelo treinado só na parte de treino sem a validação; o modelo salvo é o do treino inteiro.
    Devolve o registro da janela.
    """
    amostra, resumo = ler_janela(destino, janela, teto, semente)
    totais = {p["arquivo"]: p["janelas"][str(janela)]["extraidas"] for p in regeracao["pcaps"]}
    treino, teste = dividir_por_tempo(amostra, FRACAO_DE_TESTE_POR_TEMPO, totais)
    if len(teste) == 0 or len(treino) == 0:
        raise ValueError(f"janela de {janela}: a divisão por tempo deixou o treino ou o teste vazio")
    arquivos_de_teste = arquivos_inteiros_no_teste(amostra)
    lados = lados_por_tempo(regeracao, janela)
    X = matriz(amostra, FEATURES_39)
    y = alvo(amostra["Label"].to_numpy(), ALVO)
    fundo = ler_fundo(destino, janela) if fundo_como_benigno else None
    # 1. O treino reduzido, sem a validação, e o limiar escolhido no benigno da validação.
    validacao = inicios_da_validacao(regeracao, janela, lados)
    reduzido = {arquivo: ("teste" if lado == "teste" else validacao[arquivo][0]) for arquivo, lado in lados.items()}
    no_reduzido = antes_do_corte(amostra, reduzido)
    X_reduzido, y_reduzido, fundo_reduzido = com_fundo(X[no_reduzido], y[no_reduzido], fundo, reduzido)
    modelo, segundos_reduzido = treinar(X_reduzido, y_reduzido, semente, arvores, nucleos=nucleos)
    linhas_reduzido = len(y_reduzido)
    del X_reduzido, y_reduzido
    escolha = regra_na_validacao(modelo, regeracao, destino, janela, validacao)
    ponto = PontoDeOperacao(escolha["limiar"], escolha["seguidas"])
    melhor_limiar = None if escolha["melhor_limiar"] is None else PontoDeOperacao(escolha["melhor_limiar"],
                                                                                  escolha["seguidas"])
    del modelo
    # 2. O treino inteiro, o do modelo salvo.
    X_treino, y_treino, fundo_no_treino = com_fundo(X[treino], y[treino], fundo, lados)
    modelo, segundos = treinar(X_treino, y_treino, semente, arvores, nucleos=nucleos)
    del X_treino, y_treino
    X_teste = X[teste]
    previsto = prever(modelo, X_teste)
    previsto_limiar = (None if melhor_limiar is None else
                       melhor_limiar.categorias(probabilidades(modelo, X_teste), modelo.classes_))
    rotulos_de_teste = amostra["Label"].to_numpy()[teste]
    avaliacao = avaliar(previsto, rotulos_de_teste, ALVO, grupos=agrupar(X_teste))
    avaliacao_limiar = None if previsto_limiar is None else avaliar(previsto_limiar, rotulos_de_teste, ALVO)
    # A medida nos arquivos inteiros de teste: pcaps que o modelo não viu em nenhuma janela.
    inteiros = amostra["arquivo"].to_numpy()[teste]
    nos_inteiros = np.isin(inteiros, arquivos_de_teste)
    avaliacao_inteiros = (
        avaliar(previsto[nos_inteiros], rotulos_de_teste[nos_inteiros], ALVO) if nos_inteiros.any() else None
    )
    caminho = Path(modelos) / nome_do_modelo(janela, fundo_como_benigno)
    tamanho = salvar(
        caminho, modelo, FEATURES_39, ALVO, divisao=DIVISAO, semente=semente, arvores=arvores, nucleos=nucleos,
        janela=janela, teto=teto, fracao_de_teste=FRACAO_DE_TESTE_POR_TEMPO, treino_sha256=impressao_digital(treino),
        fundo_como_benigno=fundo_como_benigno, linhas_de_fundo=fundo_no_treino,
    )
    json_do_ponto = gravar_ponto(
        caminho, ponto, configuracao="5" if fundo_como_benigno else "0", janela=janela, semente=semente,
        escolha={"fracao_de_validacao": FRACAO_DE_VALIDACAO, "alarme_falso_maximo": ALARME_FALSO_MAXIMO,
                 "grade": [LIMIARES[0], LIMIARES[-1], 0.01], "criterio": "maior recall de ataque na validação",
                 "janelas_benignas_da_validacao": escolha["janelas_benignas"],
                 "janelas_de_ataque_da_validacao": escolha["janelas_de_ataque"],
                 "argmax": escolha["argmax"], "melhor_limiar": escolha["melhor_limiar"],
                 "no_melhor_limiar": (escolha["curva"][str(escolha["melhor_limiar"])]
                                      if escolha["melhor_limiar"] is not None else None)},
        manifesto=f"experimentos/resultados/{nomes(fundo_como_benigno)['manifesto']}",
    )
    return {
        "janela": janela,
        "linhas": {"regeradas": sum(resumo["regeradas"].values()), "amostra": len(amostra), "treino": len(treino),
                   "teste": len(teste)},
        "fundo": None if fundo is None else {
            "descartadas": len(fundo), "no_treino": fundo_no_treino, "no_treino_reduzido": fundo_reduzido,
        },
        "por_rotulo": _por_rotulo(regeracao, resumo, amostra, treino, teste, arquivos_de_teste),
        "arquivos_de_teste": sorted(arquivos_de_teste),
        "divisao": {"treino_sha256": impressao_digital(treino), "teste_sha256": impressao_digital(teste)},
        "treino_segundos": segundos,
        "ponto_de_operacao": {
            **{chave: valor for chave, valor in escolha.items() if chave != "curva"},
            "validacao": {arquivo: list(par) for arquivo, par in validacao.items()},
            "linhas_do_treino_reduzido": linhas_reduzido, "treino_reduzido_segundos": segundos_reduzido,
            "curva": escolha["curva"], "arquivo": json_do_ponto.name,
        },
        "avaliacao": avaliacao,
        "avaliacao_limiar": avaliacao_limiar,
        "avaliacao_arquivos_inteiros": avaliacao_inteiros,
        "importancias": importancias(modelo, FEATURES_39),
        "por_arquivo": _por_arquivo(amostra, teste, previsto, previsto_limiar),
        "ips_de_origem": resumo["ips_de_origem"],
        "modelo": {"arquivo": caminho.name, "bytes": tamanho},
    }


def memoria_pico():
    """O pico de memória residente do processo até agora, em bytes (o macOS dá em bytes; o Linux, em KiB)."""
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == "darwin" else 1024)


def rodar(regeracao, destino, semente=SEMENTE, arvores=ARVORES, nucleos=TODOS_OS_NUCLEOS, teto=TETO,
          modelos=MODELOS, ao_terminar=None, janelas_pedidas=None, fundo_como_benigno=True):
    inicio = time.perf_counter()
    janelas = []
    for janela in janelas_pedidas or regeracao["janelas"]:
        registro = treinar_janela(regeracao, destino, janela, semente, arvores, nucleos, teto, modelos,
                                  fundo_como_benigno)
        janelas.append(registro)
        if ao_terminar is not None:
            ao_terminar(registro)
    return {"janelas": janelas, "duracao_segundos": time.perf_counter() - inicio, "memoria_pico_bytes": memoria_pico()}


def resumir_rodada(m):
    """O que fica de uma rodada quando outra a substitui: os pcaps, os rótulos e as medidas principais."""
    return {
        "gerado_em": m["gerado_em"],
        "pcaps": len(m["regeracao"]["pcaps"]),
        "rotulos": sorted(r["rotulo"] for r in m["regeracao"]["rotulos"]),
        "rotulos_sem_pcap": m["rotulos_sem_pcap"],
        "janelas": [
            {
                "janela": j["janela"],
                "teste": j["linhas"]["teste"],
                "acuracia": j["avaliacao"]["amostra"]["acuracia"],
                "macro_f1": j["avaliacao"]["amostra"]["macro_f1"],
                "falso_positivo_benigno": j["avaliacao"]["amostra"]["falso_positivo_benigno"],
                "por_classe": {
                    classe: {"precisao": me["precisao"], "recall": me["recall"], "f1": me["f1"], "suporte": me["suporte"]}
                    for classe, me in j["avaliacao"]["amostra"]["por_classe"].items()
                },
            }
            for j in m["janelas"]
        ],
    }


def _pcaps(regeracao):
    return [(p["arquivo"], p.get("sha256")) for p in regeracao["pcaps"]]


def rodadas_anteriores(caminho, regeracao=None, fundo_como_benigno=False, sem_ele=None):
    """As rodadas registradas no manifesto que está em `caminho`, mais ele próprio resumido.

    O manifesto anterior só vira rodada anterior quando os pcaps mudaram: com os mesmos pcaps, a
    mesma regeração dá os mesmos números, e repeti-la como rodada só alongaria o relatório. As
    rodadas são de um treino só, com ou sem o fundo: um manifesto do outro treino não entra. Sem
    manifesto em `caminho`, o treino sem o fundo herda as rodadas do manifesto em `sem_ele`, se
    ele for de antes de 13/10/2026, quando aquele arquivo era o do treino sem o fundo.
    """
    try:
        anterior = json.loads(Path(caminho).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        anterior = None
    if anterior is None and sem_ele is not None and not fundo_como_benigno:
        try:
            anterior = json.loads(Path(sem_ele).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            anterior = None
    if anterior is None or anterior.get("fundo_como_benigno", False) != fundo_como_benigno:
        return []
    try:
        if regeracao is not None and _pcaps(anterior["regeracao"]) == _pcaps(regeracao):
            return anterior.get("rodadas_anteriores", [])
        return [*anterior.get("rodadas_anteriores", []), resumir_rodada(anterior)]
    except KeyError:
        return anterior.get("rodadas_anteriores", [])


def modelo_anterior(caminho, fundo_como_benigno):
    """O modelo que este treino substitui, resumido: o do manifesto em `caminho`, se o fundo no treino mudou.

    Com a mesma configuração, o anterior registrado nele continua o mesmo.
    """
    try:
        anterior = json.loads(Path(caminho).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if anterior.get("fundo_como_benigno", False) != fundo_como_benigno:
        return {**resumir_rodada(anterior), "fundo_como_benigno": anterior.get("fundo_como_benigno", False)}
    return anterior.get("modelo_anterior")


def montar_manifesto(registro, regeracao, caminho_da_regeracao, destino, semente, arvores, nucleos, teto,
                     anteriores=(), fundo_como_benigno=True, anterior=None):
    presentes = {r["rotulo"] for r in regeracao["rotulos"]}
    categorias = {CATEGORIA_DO_ROTULO[rotulo] for rotulo in presentes}
    return {
        "descricao": (
            "Random Forest de 7 categorias treinado nos dados regerados dos pcaps do CICIoT2023, com janela de "
            + _enumerar([j["janela"] for j in registro["janelas"]]) + " quadros, divisão por tempo e teto de linhas por "
            "rótulo" + (", com o fundo da parte de treino dos pcaps de ataque como Benign" if fundo_como_benigno else
                        ", sem o fundo dos pcaps de ataque (referência)")
        ),
        "gerado_por": "python -m codigo.classificador.treinar_regerado",
        "gerado_em": datetime.datetime.now(tz=datetime.UTC).astimezone().strftime("%Y-%m-%d"),
        "fundo_como_benigno": fundo_como_benigno,
        "configuracao": "5" if fundo_como_benigno else "0",
        "semente": semente,
        "arvores": arvores,
        "nucleos": nucleos,
        "teto": teto,
        "alvo": ALVO,
        "features": len(FEATURES_39),
        "divisao": DIVISAO,
        "fracao_de_teste": FRACAO_DE_TESTE_POR_TEMPO,
        "parametros": {
            "modelo": "sklearn.ensemble.RandomForestClassifier",
            "demais_parametros": "padrão do scikit-learn",
            "escalonamento": "nenhum",
            "predicao": "votos somados em ordem fixa, com um núcleo",
        },
        "versoes": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit-learn": sklearn.__version__,
        },
        "regeracao": {
            "manifesto": Path(caminho_da_regeracao).as_posix(),
            "gerado_em": regeracao["gerado_em"],
            "dataset": regeracao["dataset"],
            "destino": str(destino),
            "regra": regeracao["regra"],
            "versao_da_regra": regeracao.get("versao_da_regra"),
            "extrator": regeracao.get("extrator"),
            "pcaps": regeracao["pcaps"],
            "rotulos": regeracao["rotulos"],
        },
        "classes": list(CLASSES),
        "categorias_sem_pcap": [c for c in CATEGORIAS if c not in categorias],
        "rotulos_sem_pcap": len(ROTULOS) - len(presentes),
        "janelas": registro["janelas"],
        "duracao_segundos": registro["duracao_segundos"],
        "memoria_pico_bytes": registro.get("memoria_pico_bytes"),
        "rodadas_anteriores": list(anteriores),
        "modelo_anterior": anterior,
    }


def _por_rotulo_do_alvo(avaliacao):
    matriz_por_rotulo = avaliacao["matriz_por_rotulo"]
    return pd.DataFrame(
        matriz_por_rotulo["contagem"], index=matriz_por_rotulo["rotulos"], columns=matriz_por_rotulo["classes"],
    )


def _avaliacao_do_ponto(j):
    """A avaliação da regra escolhida na validação: a do argmax ou a do melhor limiar."""
    po = j.get("ponto_de_operacao")
    if po is None:
        return None
    return j["avaliacao"] if po["regra"] == "argmax" else j["avaliacao_limiar"]


def _regras(j):
    """As avaliações de uma janela: a do argmax, a do melhor limiar e a do ponto de operação, a que venceu."""
    saida = [("argmax", j["avaliacao"])]
    if j.get("avaliacao_limiar"):
        saida.append(("limiar", j["avaliacao_limiar"]))
    if _avaliacao_do_ponto(j) is not None:
        saida.append(("ponto", _avaliacao_do_ponto(j)))
    return saida


def gravar(manifesto, pasta):
    """Grava o manifesto e o que sai dele: relatório, tabelas e matrizes de confusão."""
    pasta = Path(pasta)
    arquivos = nomes(manifesto.get("fundo_como_benigno", False))
    (pasta / MATRIZES).mkdir(parents=True, exist_ok=True)
    (pasta / arquivos["manifesto"]).write_text(json.dumps(manifesto, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (pasta / arquivos["relatorio"]).write_text(montar_relatorio(manifesto), encoding="utf-8")
    _gravar_csv(
        pasta / arquivos["metricas"],
        ["janela", "regra", "classe", "precisao", "recall", "f1", "suporte", "taxa_falso_positivo"],
        [
            [
                j["janela"], regra, classe, _campo(m["precisao"]), _campo(m["recall"]), _campo(m["f1"]),
                round(m["suporte"]), _campo(m["taxa_falso_positivo"]),
            ]
            for j in manifesto["janelas"] for regra, avaliacao in _regras(j)
            for classe, m in avaliacao["amostra"]["por_classe"].items()
        ],
    )
    _gravar_csv(
        pasta / arquivos["por_arquivo"],
        ["janela", "arquivo", "rotulo", "categoria_esperada", "janelas_de_teste", "na_esperada", "na_esperada_limiar",
         *CLASSES],
        [
            [
                j["janela"], p["arquivo"], p["rotulo"], p["esperada"], p["janelas_de_teste"], _campo(p["na_esperada"]),
                _campo(p.get("na_esperada_limiar")), *(p["previstas"][classe] for classe in CLASSES),
            ]
            for j in manifesto["janelas"] for p in j["por_arquivo"]
        ],
    )
    for j in manifesto["janelas"]:
        for regra, avaliacao in _regras(j):
            nome = f"regerado_janela_{j['janela']}{arquivos['sufixo']}" + ("" if regra == "argmax" else f"_{regra}")
            por_rotulo = _por_rotulo_do_alvo(avaliacao)
            por_rotulo.to_csv(pasta / MATRIZES / f"{nome}_por_rotulo.csv", index_label="rotulo", lineterminator="\n")
            matriz_de_confusao(por_rotulo, ALVO).to_csv(
                pasta / MATRIZES / f"{nome}.csv", index_label="classe_real", lineterminator="\n",
            )


# --- relatório -------------------------------------------------------------------------------


def _data(m):
    return datetime.date.fromisoformat(m["gerado_em"]).strftime("%d/%m/%Y")


def _janelas(m):
    return [str(j["janela"]) for j in m["janelas"]]


def _fundo_no_treino(m):
    return m.get("fundo_como_benigno", False)


def _cabecalho(m):
    v = m["versoes"]
    linhas = [
        "# Treino sobre os dados regerados" + ("" if _fundo_no_treino(m) else ": referência sem o fundo"),
        "",
        (
            f"Gerado por `{m['gerado_por']}` em {_data(m)}, com Python {v['python']}, scikit-learn "
            f"{v['scikit-learn']}, pandas {v['pandas']} e numpy {v['numpy']}."
        ),
        "",
        "O modelo treinado no `MERGED_CSV` oficial aprende o tamanho da janela, de 100 quadros nas classes de",
        "DDoS, DoS e Mirai e de 10 nas demais, em vez do comportamento do tráfego (`teste_da_janela.md`), e o",
        "rótulo oficial é dado ao arquivo inteiro, mesmo nas janelas sem nenhum quadro do atacante",
        "(`janelas_sem_atacante.md`). Por isso os dados de treino foram gerados de novo a partir dos pcaps, com o",
        "nosso extrator, em janela única e com o rótulo decidido janela a janela (decisão de 10/10/2026 no",
        "`ROADMAP.md`).",
        "",
    ]
    if _fundo_no_treino(m):
        linhas += [
            (
                "Este relatório traz o modelo do sistema: o Random Forest de 7 categorias com janela de "
                + _enumerar(_janelas(m)) + " quadros, treinado com as janelas de fundo da parte de treino de cada pcap "
                "de ataque como Benign (a configuração 5 de `" + CAPTURAS + "`) e com o ponto de operação escolhido "
                "numa parte de validação: entre a categoria mais provável (argmax) e os limiares t sobre "
                "1 − P(Benign), a regra de maior recall de ataque na validação com no máximo 1% do benigno dela "
                f"como ataque; o incidente abre com {SEGUIDAS} janelas de ataque seguidas (decisões de 13/10/2026). "
                "As medidas são as da parte de teste, com o argmax e com o melhor limiar, lado a lado."
            ),
            "",
            (
                f"Os controles estão em outros relatórios: a comparação com o modelo de 10/10, com o pcap inteiro fora "
                f"do treino, a rotação do pcap benigno de fora e o tráfego de fundo, em `{CAPTURAS}`; o ponto de "
                f"operação em três sementes, por janela e por alarme, em `{PONTO_DE_OPERACAO}`; os demais controles do "
                f"modelo de 10/10, que continuam valendo como referência, em `{RODADAS}`."
            ),
        ]
    else:
        linhas += [
            (
                "Este relatório refaz o treino de 10/10, que foi o do sistema até 13/10/2026 e fica como referência: "
                "sem o tráfego de fundo dos pcaps de ataque no treino, um modelo por janela, de "
                + _enumerar(_janelas(m)) + " quadros. É a configuração 0 de `" + CAPTURAS + "`, e o modelo de janela "
                f"de 100 é o que `{RODADAS}` mede. O modelo do sistema está em `regeracao.md`."
            ),
        ]
    return linhas


def _dados(m):
    r = m["regeracao"]
    janelas = _janelas(m)
    cabecalho = ["Arquivo", "Rótulo", "Categoria", "Pacotes"]
    for janela in janelas:
        cabecalho += [f"Janelas de {janela}", f"Mantidas ({janela})"]
    cabecalho.append("Extração (s)")
    linhas = []
    for p in r["pcaps"]:
        linha = [f"`{p['arquivo']}`", p["rotulo"], p["categoria"], _milhar(p["pacotes"])]
        for janela in janelas:
            c = p["janelas"][janela]
            fracao = c["mantidas"] / c["extraidas"] if c["extraidas"] else None
            linha += [_milhar(c["extraidas"]), f"{_milhar(c['mantidas'])} ({_pct(fracao, 1)})"]
        linha.append(_decimal(p["segundos"]))
        linhas.append(linha)
    por_rotulo = [
        [rot["rotulo"], rot["categoria"], _enumerar(f"`{a}`" for a in rot["arquivos"])]
        + [_milhar(rot["linhas"][janela]) for janela in janelas]
        for rot in r["rotulos"]
    ]
    secao = [
        "## Os dados regerados",
        "",
        f"Os pcaps da pasta do dataset em {datetime.date.fromisoformat(r['gerado_em']).strftime('%d/%m/%Y')}, lidos",
        "inteiros pelo extrator em leitura contínua, com os dois tamanhos de janela. Regra de rótulo: num pcap",
        "benigno toda janela é `BenignTraffic`; num pcap de ataque a janela recebe o rótulo do arquivo se tem",
        "quadro com MAC de um Raspberry Pi atacante na origem ou no destino, e é descartada se não tem.",
        "",
        *_frase_do_fundo(m),
        "",
        *_tabela(cabecalho, linhas),
        "",
        "Linhas regeradas por rótulo, somando os arquivos dele:",
        "",
        *_tabela(["Rótulo", "Categoria", "Arquivos", *(f"Linhas ({janela})" for janela in janelas)], por_rotulo),
        "",
    ]
    if m["categorias_sem_pcap"]:
        secao.append(
            f"Categorias que ainda não têm pcap: {_enumerar(m['categorias_sem_pcap'])}. "
            f"{m['rotulos_sem_pcap']} dos 34 rótulos ainda não têm pcap."
        )
    elif m["rotulos_sem_pcap"]:
        secao.append(
            f"Todas as {len(CLASSES)} categorias do modelo têm ao menos um pcap. {m['rotulos_sem_pcap']} dos 34 "
            "rótulos ainda não têm pcap."
        )
    else:
        secao.append(f"Todos os {len(ROTULOS)} rótulos têm pcap, de um a três arquivos cada.")
    if m["rotulos_sem_pcap"]:
        secao += [
            "Os números deste relatório são parciais até os outros pcaps chegarem: o modelo só conhece as variantes",
            "de cada categoria que estão na tabela.",
        ]
    secao += [
        "Com pcaps novos na pasta, `regerar` extrai só eles e este comando refaz o treino e o relatório.",
    ]
    return secao


def _frase_do_fundo(m):
    if not _fundo_no_treino(m):
        return [
            "No treino de referência, a janela descartada não vira benigna, porque o tráfego de fundo de uma captura",
            "de ataque pode conter efeito do ataque.",
        ]
    return [
        "A janela descartada, o tráfego de fundo do pcap de ataque, entra no treino como Benign quando está na parte",
        "de treino do pcap, e fica fora do teste. Até 13/10/2026 ela ficava fora do treino, porque pode conter efeito",
        f"do ataque; com ela no treino, o alarme falso no pcap benigno de fora e o fundo virando ataque caem (`{CAPTURAS}`).",
    ]


def _treino_e_teste(m):
    linhas = [
        [
            j["janela"], _milhar(j["linhas"]["regeradas"]), _milhar(j["linhas"]["amostra"]),
            _milhar(j["linhas"]["treino"]),
            _milhar(j["fundo"]["no_treino"]) if j.get("fundo") else "nenhuma",
            _milhar(j["linhas"]["teste"]),
            _enumerar(f"`{a}`" for a in j["arquivos_de_teste"]) if j["arquivos_de_teste"] else "nenhum",
            _decimal(j["treino_segundos"]),
        ]
        for j in m["janelas"]
    ]
    secao = [
        "## Treino e teste",
        "",
        f"Cada rótulo entra com no máximo {_milhar(m['teto'])} linhas, sorteadas com a semente {m['semente']}, como na",
        "amostra do treino exploratório. A divisão é por tempo: dentro de cada pcap, as primeiras",
        f"{_pct(1 - m['fracao_de_teste'], 0)} das janelas vão para o treino e as últimas {_pct(m['fracao_de_teste'], 0)}",
        "para o teste, com o corte no total de janelas do arquivo, para não deixar janelas vizinhas dos dois lados.",
        "Um rótulo com mais de um pcap tem o último arquivo, pelo sufixo numérico do nome, inteiro no teste.",
        f"O modelo é o `RandomForestClassifier` do scikit-learn com {m['arvores']} árvores e os demais parâmetros padrão,",
        f"sem `StandardScaler`, com as {m['features']} features e {len(CLASSES)} categorias (DDoS e DoS juntos).",
        "",
        *_tabela(
            ["Janela", "Linhas regeradas", "Após o teto", "Treino", "Janelas de fundo no treino, como Benign", "Teste",
             "Arquivos inteiros no teste", "Treino (s)"],
            linhas,
        ),
    ]
    secao += _validacao(m)
    primeira = m["janelas"][0]
    inteiros = set(primeira["arquivos_de_teste"])
    secao += [
        "",
        "Como cada rótulo foi dividido. O rótulo com mais de um pcap tem um arquivo inteiro no teste, e o modelo",
        "não vê nenhuma janela dele; nos demais, o teste é o fim do próprio pcap.",
        "",
        *_tabela(
            ["Rótulo", "Arquivos", "Divisão"],
            [
                [
                    r["rotulo"], _enumerar(f"`{a}`" for a in r["arquivos"]),
                    "por arquivo: " + _enumerar(f"`{a}`" for a in r["arquivos"] if a in inteiros) + " inteiro no teste"
                    if len(r["arquivos"]) > 1 else "por tempo",
                ]
                for r in primeira["por_rotulo"]
            ],
        ),
    ]
    for j in m["janelas"]:
        secao += [
            "",
            f"Linhas por rótulo com janela de {j['janela']}:",
            "",
            *_tabela(
                ["Rótulo", "Categoria", "Regeradas", "Após o teto", "Treino", "Teste"],
                [
                    [r["rotulo"], r["categoria"], _milhar(r["regeradas"]), _milhar(r["amostra"]), _milhar(r["treino"]),
                     _milhar(r["teste"])]
                    for r in j["por_rotulo"]
                ],
            ),
        ]
    return secao


def _nome_da_regra(po):
    return "argmax" if po["regra"] == "argmax" else f"limiar, t = {_decimal(po['limiar'], 2)}"


def _validacao(m):
    """Como o ponto de operação foi escolhido em cada janela: a validação, os candidatos e a regra que venceu."""
    com_ponto = [j for j in m["janelas"] if j.get("ponto_de_operacao")]
    if not com_ponto:
        return []
    linhas = []
    for j in com_ponto:
        po = j["ponto_de_operacao"]
        nb, na = po["janelas_benignas"], po["janelas_de_ataque"]
        melhor = po["curva"][str(po["melhor_limiar"])] if po["melhor_limiar"] is not None else None
        linhas.append([
            j["janela"], _milhar(po["linhas_do_treino_reduzido"]), _milhar(nb), _milhar(na),
            f"{_pct(po['argmax']['benigno_como_ataque'] / nb)} e {_pct(po['argmax']['ataque_reconhecido'] / na)}",
            (f"{_decimal(po['melhor_limiar'], 2)}: {_pct(melhor['benigno_como_ataque'] / nb)} e "
             f"{_pct(melhor['ataque_reconhecido'] / na)}") if melhor else "nenhum dentro da meta",
            _nome_da_regra(po), po["seguidas"],
        ])
    return [
        "",
        (
            f"O ponto de operação sai de uma parte de validação, nunca do teste. As últimas "
            f"{_pct(FRACAO_DE_VALIDACAO, 0)} da parte de treino de cada pcap, por tempo, são a validação, e um modelo "
            "treinado no resto (o treino reduzido, com a mesma semente"
            + (" e com o fundo da parte reduzida" if _fundo_no_treino(m) else "")
            + ") classifica todas as janelas da validação, e não só as do teto: as dos pcaps benignos e as com o "
            "atacante dos pcaps de ataque. Os candidatos são a categoria mais provável (argmax) e os limiares t sobre "
            "1 − P(Benign), de 0,01 em 0,01. Entre os que deixam no máximo "
            f"{_pct(ALARME_FALSO_MAXIMO, 0)} das janelas benignas como ataque, vence o de maior recall de ataque na "
            "validação. O melhor limiar é o que venceria entre os limiares; ele fica nas tabelas para comparação. O "
            "modelo salvo é o do treino inteiro, com a regra gravada ao lado."
        ),
        "",
        *_tabela(["Janela", "Treino reduzido", "Janelas benignas na validação", "Janelas de ataque na validação",
                  "Argmax: benigno como ataque e recall de ataque", "Melhor limiar: benigno como ataque e recall de ataque",
                  "Regra escolhida", "N"], linhas),
    ]


def _mais_prevista(previstas):
    classe, quantas = max(previstas.items(), key=lambda par: par[1])
    return classe if quantas else "nenhuma"


def populacao_regerada(j):
    """As janelas regeradas de cada rótulo, antes do teto: a mistura para a qual as medidas são reponderadas."""
    return {r["rotulo"]: r["regeradas"] for r in j["por_rotulo"]}


def reponderada(j):
    """As medidas da parte de teste com cada rótulo pesando o que pesa nas janelas regeradas.

    O teto muda a mistura dos rótulos no teste, e a mistura muda de uma janela para outra. O recall
    de um rótulo não muda com o peso; o de uma categoria que junta rótulos muda, e a precisão, o F1,
    a acurácia e o macro-F1 mudam com a mistura.
    """
    confusao = matriz_de_confusao(_por_rotulo_do_alvo(j["avaliacao"]), ALVO, populacao_regerada(j))
    return medir(confusao, ALVOS[ALVO].benigno)


def ataque_como_benigno(medidas):
    """A fração das janelas de ataque classificadas como benignas: o ataque perdido.

    É a taxa de falso positivo da categoria benigna, que conta as janelas das outras categorias
    previstas como benignas.
    """
    return medidas["por_classe"][ALVOS[ALVO].benigno]["taxa_falso_positivo"]


def _resultados(m, j):
    a = j["avaliacao"]["amostra"]
    r = reponderada(j)
    por_rotulo = _por_rotulo_do_alvo(j["avaliacao"])
    confusao = matriz_de_confusao(por_rotulo, ALVO)
    por_classe = [
        [classe, _milhar(me["suporte"]), _pct(me["precisao"]), _pct(me["recall"]), _pct(me["f1"]),
         _pct(me["taxa_falso_positivo"])]
        for classe, me in a["por_classe"].items()
    ]
    reponderadas = [
        [classe, _pct(me["precisao"]), _pct(r["por_classe"][classe]["precisao"]), _pct(me["recall"]),
         _pct(r["por_classe"][classe]["recall"]), _pct(me["f1"]), _pct(r["por_classe"][classe]["f1"])]
        for classe, me in a["por_classe"].items()
    ]
    matriz_linhas = [
        [classe, *(_milhar(confusao.loc[classe, prevista]) for prevista in CLASSES)] for classe in CLASSES
    ]
    limiar = j.get("avaliacao_limiar")
    por_arquivo = [
        [f"`{p['arquivo']}`", p["rotulo"], p["esperada"], _milhar(p["janelas_de_teste"]),
         _pct(p["na_esperada"]) if p["na_esperada"] is not None else "sem teste",
         *([_pct(p["na_esperada_limiar"]) if p.get("na_esperada_limiar") is not None else "sem teste"] if limiar else []),
         _mais_prevista(p["previstas"])]
        for p in j["por_arquivo"]
    ]
    importantes = list(j["importancias"].items())[:FEATURES_LISTADAS]
    inteiros = []
    if j["avaliacao_arquivos_inteiros"] is not None:
        ai = j["avaliacao_arquivos_inteiros"]["amostra"]
        inteiros = [
            "",
            f"### Nos arquivos inteiros de teste, com janela de {j['janela']}",
            "",
            _enumerar(f"`{a}`" for a in j["arquivos_de_teste"]) + ", pcaps de que o modelo não viu nenhuma janela, "
            "com as janelas que o teto sorteou de cada um. "
            f"{_milhar(j['avaliacao_arquivos_inteiros']['linhas'])} linhas, acurácia "
            f"{_pct(ai['acuracia'])}, macro-F1 {_pct(ai['macro_f1'])} entre as categorias presentes, tráfego benigno "
            f"classificado como ataque {_pct(ai['falso_positivo_benigno'])}. A precisão e o falso positivo de cada "
            "categoria valem só dentro desses arquivos. A medida depende de qual pcap fica de fora: a rotação do",
            f"pcap benigno de fora está em {_controles(m)}.",
            "",
            *_tabela(
                ["Categoria", "Linhas de teste", "Precisão", "Recall", "F1"],
                [
                    [classe, _milhar(me["suporte"]), _pct(me["precisao"]), _pct(me["recall"]), _pct(me["f1"])]
                    for classe, me in ai["por_classe"].items() if me["suporte"]
                ],
            ),
        ]
    return [
        f"## Resultados com janela de {j['janela']}",
        "",
        (
            f"Na parte de teste, de {_milhar(j['linhas']['teste'])} linhas: acurácia {_pct(a['acuracia'])}, macro-F1 "
            f"{_pct(a['macro_f1'])}, F1 ponderado {_pct(a['f1_ponderado'])}, teto destas linhas {_pct(a['teto'])}. "
            f"Tráfego benigno classificado como ataque: {_pct(a['falso_positivo_benigno'])}. Ataque classificado "
            f"como benigno: {_pct(ataque_como_benigno(a))}."
        ),
        "",
        *_tabela(
            ["Categoria", "Linhas de teste", "Precisão", "Recall", "F1", "Falso positivo da categoria"], por_classe,
        ),
        "",
        "O falso positivo de uma categoria é a fração das janelas das outras categorias que o modelo pôs nela.",
        "Na linha Benign, ele é o ataque classificado como benigno, isto é, o ataque perdido, e não o alarme",
        "falso; o alarme falso é o tráfego benigno classificado como ataque, dado acima.",
        "",
        (
            "As medidas acima estão na mistura do teste, que o teto deforma: cada rótulo entra com no máximo "
            f"{_milhar(m['teto'])} linhas. Reponderadas para a mistura das janelas regeradas, antes do teto, em que "
            f"cada rótulo pesa as janelas que tem: acurácia {_pct(r['acuracia'])}, macro-F1 {_pct(r['macro_f1'])}, "
            f"F1 ponderado {_pct(r['f1_ponderado'])}, ataque classificado como benigno "
            f"{_pct(ataque_como_benigno(r))}. O tráfego benigno classificado como ataque não muda, porque o benigno "
            "é um rótulo só."
        ),
        "",
        *_tabela(
            ["Categoria", "Precisão", "Precisão reponderada", "Recall", "Recall reponderado", "F1",
             "F1 reponderado"],
            reponderadas,
        ),
        "",
        "Matriz de confusão, com a categoria real nas linhas e a prevista nas colunas:",
        "",
        *_tabela(["Real \\ prevista", *CLASSES], matriz_linhas),
        "",
        *_com_o_ponto(j),
        "Por pcap, a fração das janelas de teste na categoria esperada"
        + (", com o argmax e com o melhor limiar," if limiar else "") + " e a categoria mais prevista"
        + (" pelo argmax:" if limiar else ":"),
        "",
        *_tabela(["Arquivo", "Rótulo", "Categoria esperada", "Janelas de teste",
                  *(["Na esperada, argmax", "Na esperada, limiar"] if limiar else ["Na esperada"]), "Mais prevista"],
                 por_arquivo),
        "",
        f"As {FEATURES_LISTADAS} features mais importantes (redução média de impureza): "
        + _enumerar(f"`{feature}` ({_pct(valor, 1)})" for feature, valor in importantes) + ".",
        *inteiros,
    ]


def _com_o_ponto(j):
    """As medidas da parte de teste com o argmax e com o melhor limiar, e qual dos dois é o ponto de operação."""
    po = j.get("ponto_de_operacao")
    if not po or not j.get("avaliacao_limiar"):
        return []
    a, b = j["avaliacao"]["amostra"], j["avaliacao_limiar"]["amostra"]
    t_ = _decimal(po["melhor_limiar"], 2)
    escolhido = lambda regra: " (ponto de operação)" if po["regra"] == regra else ""
    confusao = matriz_de_confusao(_por_rotulo_do_alvo(j["avaliacao_limiar"]), ALVO)
    globais = [
        ["Macro-F1", _pct(a["macro_f1"]), _pct(b["macro_f1"])],
        ["Acurácia", _pct(a["acuracia"]), _pct(b["acuracia"])],
        ["Benigno classificado como ataque", _pct(a["falso_positivo_benigno"]), _pct(b["falso_positivo_benigno"])],
        ["Ataque classificado como benigno", _pct(ataque_como_benigno(a)), _pct(ataque_como_benigno(b))],
    ]
    por_classe = [
        [classe, _milhar(me["suporte"]), _pct(me["precisao"]), _pct(b["por_classe"][classe]["precisao"]),
         _pct(me["recall"]), _pct(b["por_classe"][classe]["recall"]), _pct(me["f1"]), _pct(b["por_classe"][classe]["f1"])]
        for classe, me in a["por_classe"].items()
    ]
    return [
        f"### Argmax e limiar, janela de {j['janela']}",
        "",
        (
            f"A mesma parte de teste com as duas regras que concorreram na validação: o argmax e o melhor limiar, a "
            f"janela ataque se 1 − P(Benign) ≥ {t_}, na categoria de ataque mais provável. O limiar só decide entre "
            "Benign e ataque: a janela que é ataque pelas duas regras fica na mesma categoria. Na validação, venceu "
            f"o {_nome_da_regra(po)}, e ele é o ponto de operação do modelo; o teste não entra na escolha. A regra das "
            f"{po['seguidas']} janelas seguidas vale para o alarme, e não para a janela; os alarmes estão em "
            f"`{PONTO_DE_OPERACAO}`."
        ),
        "",
        *_tabela(["Medida", f"Argmax{escolhido('argmax')}", f"Limiar, t = {t_}{escolhido('limiar')}"], globais),
        "",
        *_tabela(["Categoria", "Linhas de teste", "Precisão, argmax", "Precisão, limiar", "Recall, argmax",
                  "Recall, limiar", "F1, argmax", "F1, limiar"], por_classe),
        "",
        f"Matriz de confusão com o limiar t = {t_}:",
        "",
        *_tabela(["Real \\ prevista", *CLASSES],
                 [[classe, *(_milhar(confusao.loc[classe, prevista]) for prevista in CLASSES)] for classe in CLASSES]),
        "",
    ]


def _o_que_mudou(m):
    """O modelo deste treino contra o que ele substituiu, na janela do sistema, e onde estão os controles."""
    anterior = m.get("modelo_anterior")
    if not anterior or not _fundo_no_treino(m):
        return []
    comuns = [j for j in m["janelas"] if any(a["janela"] == j["janela"] for a in anterior["janelas"])]
    if not comuns:
        return []
    janela = next((j for j in comuns if j["janela"] == JANELA_DO_SISTEMA), comuns[-1])
    antes = next(a for a in anterior["janelas"] if a["janela"] == janela["janela"])
    a, b = janela["avaliacao"]["amostra"], janela["avaliacao_limiar"]["amostra"]
    po = janela["ponto_de_operacao"]
    linhas = [
        ["Macro-F1", _pct(antes["macro_f1"]), _pct(a["macro_f1"]), _pct(b["macro_f1"])],
        ["Acurácia", _pct(antes["acuracia"]), _pct(a["acuracia"]), _pct(b["acuracia"])],
        ["Benigno classificado como ataque", _pct(antes["falso_positivo_benigno"]), _pct(a["falso_positivo_benigno"]),
         _pct(b["falso_positivo_benigno"])],
        *([f"Recall {classe}", _pct(antes["por_classe"][classe]["recall"]), _pct(a["por_classe"][classe]["recall"]),
           _pct(b["por_classe"][classe]["recall"])] for classe in CLASSES),
    ]
    data = datetime.date.fromisoformat(anterior["gerado_em"]).strftime("%d/%m/%Y")
    return [
        "## O que mudou em relação ao modelo anterior",
        "",
        (
            f"O modelo anterior, do treino gravado em {data}, com janela de {janela['janela']}, foi treinado sem o fundo "
            "e decidia pela categoria mais provável. Ele fica como referência: `python -m "
            "codigo.classificador.treinar_regerado --sem-fundo` o refaz em `regeracao_sem_fundo.md`. Na mesma parte de "
            "teste:"
        ),
        "",
        *_tabela(["Medida", "Modelo anterior", "Este modelo, argmax" + (" (ponto de operação)" if po["regra"] == "argmax" else ""),
                  f"Este modelo, limiar t = {_decimal(po['melhor_limiar'], 2)}"
                  + (" (ponto de operação)" if po["regra"] == "limiar" else "")], linhas),
        "",
        (
            "O corte por tempo não mostra o motivo da troca. Com o fundo no treino, cai o alarme falso no pcap benigno "
            "de fora do treino e o fundo dos pcaps de ataque classificado como ataque, e caem também o recall de Recon e "
            f"o de Spoofing, no corte por tempo e com o pcap fora do treino. As três sementes, as diferenças pareadas e a "
            f"regra com que a equipe adotou este modelo estão em `{CAPTURAS}`; o ponto de operação por janela e por "
            f"alarme, nas rotações do pcap benigno de fora e nos pcaps de ataque, em `{PONTO_DE_OPERACAO}`."
        ),
    ]


def _lado_a_lado(m):
    janelas = m["janelas"]
    rotulos = [str(j["janela"]) for j in janelas]
    linhas = []
    for classe in CLASSES:
        linha = [classe]
        for medida in ("recall", "f1"):
            linha += [_pct(j["avaliacao"]["amostra"]["por_classe"][classe][medida]) for j in janelas]
        linhas.append(linha)
    globais = [
        ["Macro-F1", *(_pct(j["avaliacao"]["amostra"]["macro_f1"]) for j in janelas)],
        ["Macro-F1 reponderado", *(_pct(reponderada(j)["macro_f1"]) for j in janelas)],
        ["Acurácia", *(_pct(j["avaliacao"]["amostra"]["acuracia"]) for j in janelas)],
        ["Benigno classificado como ataque", *(_pct(j["avaliacao"]["amostra"]["falso_positivo_benigno"]) for j in janelas)],
        ["Ataque classificado como benigno", *(_pct(ataque_como_benigno(j["avaliacao"]["amostra"])) for j in janelas)],
        ["Linhas de teste", *(_milhar(j["linhas"]["teste"]) for j in janelas)],
    ]
    melhor_f1 = max(janelas, key=lambda j: j["avaliacao"]["amostra"]["macro_f1"])
    # Janela sem benigno no teste não tem a taxa: fica fora da comparação, e não conta como 0%.
    com_benigno = [j for j in janelas if j["avaliacao"]["amostra"]["falso_positivo_benigno"] is not None]
    if com_benigno:
        menor_fp = min(com_benigno, key=lambda j: j["avaliacao"]["amostra"]["falso_positivo_benigno"])
        frase_do_benigno = f"a menor taxa de tráfego benigno classificado como ataque é a da janela de {menor_fp['janela']}"
    else:
        frase_do_benigno = "nenhuma janela tem tráfego benigno no teste, e a taxa de benigno classificado como ataque fica sem valor"
    return [
        "## As duas janelas lado a lado",
        "",
        *_tabela(["Medida", *(f"Janela de {r}" for r in rotulos)], globais),
        "",
        *_tabela(
            ["Categoria", *(f"Recall ({r})" for r in rotulos), *(f"F1 ({r})" for r in rotulos)], linhas,
        ),
        "",
        (
            f"O maior macro-F1 é o da janela de {melhor_f1['janela']}, e {frase_do_benigno}. Com janela de 100, cada "
            "pcap gera cerca de um décimo das janelas que gera com 10, e as classes raras ficam com poucas linhas de "
            "teste; na operação, a janela de 10 decide com menos quadros e responde mais vezes por segundo."
        ),
    ]


def _ips(m):
    secao = [
        "## IPs de origem por janela em DDoS e DoS",
        "",
        "O modelo não separa DDoS de DoS: as features descrevem os pacotes, não quantas máquinas atacam. A separação",
        "sai da quantidade de IPs de origem distintos das janelas do incidente, fora do modelo. A tabela resume essa",
        "quantidade nas janelas regeradas de cada classe de DDoS e DoS presente, antes do teto.",
    ]
    for j in m["janelas"]:
        if not j["ips_de_origem"]:
            continue
        secao += [
            "",
            f"Janela de {j['janela']}:",
            "",
            *_tabela(
                ["Rótulo", "Categoria", "Janelas", "Mínimo", "P25", "Mediana", "P75", "Máximo", "Média",
                 "Janelas com até 1 IP de origem"],
                [
                    [r["rotulo"], r["categoria"], _milhar(r["janelas"]), r["minimo"], _decimal(r["p25"]),
                     _decimal(r["mediana"]), _decimal(r["p75"]), r["maximo"], _decimal(r["media"], 2), _pct(r["ate_1"])]
                    for r in j["ips_de_origem"]
                ],
            ),
        ]
    if all(not j["ips_de_origem"] for j in m["janelas"]):
        secao += ["", "Nenhuma classe de DDoS ou DoS tem pcap ainda."]
        return secao
    secao += [""]
    for j in m["janelas"]:
        ddos = [r["mediana"] for r in j["ips_de_origem"] if r["categoria"] == "DDoS"]
        dos = [r["mediana"] for r in j["ips_de_origem"] if r["categoria"] == "DoS"]
        if not ddos or not dos:
            continue
        separa = min(ddos) > max(dos)
        secao.append(
            f"Com janela de {j['janela']}, a mediana de IPs de origem por janela vai de {_decimal(min(ddos))} a "
            f"{_decimal(max(ddos))} nas classes de DDoS e de {_decimal(min(dos))} a {_decimal(max(dos))} nas de DoS: "
            + ("as faixas não se cruzam." if separa else "as faixas se cruzam, e a contagem de uma janela isolada não "
               "separa as duas categorias.")
        )
    secao += [
        "",
        "A contagem inclui os IPs de origem de todos os quadros IPv4 da janela, também os da vítima e os do tráfego",
        "de fundo, e não só os das máquinas que atacam.",
    ]
    return secao


def _diferenca(novo, antigo):
    if novo is None or antigo is None:
        return "sem valor"
    return f"{_pct(antigo)} para {_pct(novo)} ({_pp(novo - antigo)} p.p.)"


def _rodadas_anteriores(m):
    anteriores = m.get("rodadas_anteriores", [])
    if not anteriores:
        return []
    secao = [
        "## Rodadas anteriores, como referência",
        "",
        "As medidas das rodadas parciais, antes de os outros pcaps chegarem. Cada rodada é o mesmo comando sobre",
        "os pcaps que havia na pasta na data.",
    ]
    for rodada in anteriores:
        rotulos = [str(j["janela"]) for j in rodada["janelas"]]
        secao += [
            "",
            (
                f"Rodada de {datetime.date.fromisoformat(rodada['gerado_em']).strftime('%d/%m/%Y')}: "
                f"{rodada['pcaps']} pcaps, {len(rodada['rotulos'])} rótulos ({rodada['rotulos_sem_pcap']} sem pcap)."
            ),
            "",
            *_tabela(
                ["Medida", *(f"Janela de {r}" for r in rotulos)],
                [
                    ["Macro-F1", *(_pct(j["macro_f1"]) for j in rodada["janelas"])],
                    ["Acurácia", *(_pct(j["acuracia"]) for j in rodada["janelas"])],
                    ["Benigno classificado como ataque", *(_pct(j["falso_positivo_benigno"]) for j in rodada["janelas"])],
                    ["Linhas de teste", *(_milhar(j["teste"]) for j in rodada["janelas"])],
                ],
            ),
            "",
            *_tabela(
                ["Categoria", *(f"Recall ({r})" for r in rotulos), *(f"F1 ({r})" for r in rotulos)],
                [
                    [classe, *(_pct(j["por_classe"][classe]["recall"]) for j in rodada["janelas"]),
                     *(_pct(j["por_classe"][classe]["f1"]) for j in rodada["janelas"])]
                    for classe in CLASSES
                ],
            ),
        ]
    ultima = anteriores[-1]
    presentes = sorted(r["rotulo"] for r in m["regeracao"]["rotulos"])
    entraram = [r for r in presentes if r not in ultima["rotulos"]]
    sairam = [r for r in ultima["rotulos"] if r not in presentes]
    secao += ["", "O que mudou da última rodada para esta:", ""]
    secao.append(
        f"- Pcaps: de {ultima['pcaps']} para {len(m['regeracao']['pcaps'])}. "
        + (f"Rótulos que entraram: {_enumerar(entraram)}." if entraram else "Nenhum rótulo entrou.")
        + (f" Rótulos que saíram: {_enumerar(sairam)}." if sairam else "")
    )
    for j in m["janelas"]:
        anterior = next((a for a in ultima["janelas"] if a["janela"] == j["janela"]), None)
        if anterior is None:
            continue
        a = j["avaliacao"]["amostra"]
        secao.append(
            f"- Janela de {j['janela']}: macro-F1 de {_diferenca(a['macro_f1'], anterior['macro_f1'])}; benigno "
            f"classificado como ataque de {_diferenca(a['falso_positivo_benigno'], anterior['falso_positivo_benigno'])}; "
            "recall por categoria: "
            + "; ".join(
                f"{classe} de {_diferenca(a['por_classe'][classe]['recall'], anterior['por_classe'][classe]['recall'])}"
                for classe in CLASSES
            ) + "."
        )
    return secao


def _benignas_com_atacante(m):
    """A fração das janelas dos pcaps benignos com ao menos um quadro de um MAC da lista, por janela."""
    benignos = [p for p in m["regeracao"]["pcaps"] if p["benigno"]]
    fracoes = {}
    for janela in _janelas(m):
        extraidas = sum(p["janelas"][janela]["extraidas"] for p in benignos)
        if extraidas:
            fracoes[janela] = sum(p["janelas"][janela]["com_atacante"] for p in benignos) / extraidas
    return fracoes


def _controles(m):
    """O relatório com as sementes, as rotações e o pcap fora do treino do modelo deste treino."""
    return f"`{CAPTURAS}` e `{PONTO_DE_OPERACAO}`" if _fundo_no_treino(m) else f"`{RODADAS}`"


def _ressalvas(m):
    if m["rotulos_sem_pcap"]:
        cobertura = [
            "- **Os números são parciais.** Faltam pcaps de " + (
                _enumerar(m["categorias_sem_pcap"]) + " e de " if m["categorias_sem_pcap"] else ""
            ) + f"{m['rotulos_sem_pcap']} rótulos. Uma categoria representada por uma ou duas variantes pode ficar",
            "  mais fácil do que será com todas.",
        ]
    else:
        cobertura = [
            "- **Uma a três capturas por rótulo.** Todos os 34 rótulos têm pcap, mas a variedade dentro de cada um",
            "  é a de poucas capturas da mesma rede. O que o modelo aprendeu de uma variante pode não valer para",
            "  outra captura dela.",
        ]
    return [
        "## Ressalvas",
        "",
        *cobertura,
        (
            "- **Uma semente neste relatório.** Divisão por tempo não sorteia, mas o teto por rótulo e o modelo usam "
            f"a semente {m['semente']}. A variação entre sementes está em {_controles(m)}."
        ),
        "- **O teste vem das mesmas capturas.** As janelas de teste são o fim de cada pcap, da mesma rede e do",
        "  mesmo dia das de treino. A medida vale para a captura, não para outra rede. Os rótulos com mais de",
        "  um pcap têm um arquivo inteiro no teste, que sai à parte e depende de qual arquivo fica de fora; nos",
        "  demais, as janelas na fronteira do corte são vizinhas das de treino. A rotação do arquivo de fora e o",
        f"  recall com o pcap inteiro fora do treino estão em {_controles(m)}.",
        *_ressalva_do_fundo(m),
        (
            "- **O atacante também gera tráfego benigno.** O MAC `dc:a6:32:dc:27:d5` aparece em cerca de 1% dos "
            "quadros dos pcaps benignos (`janelas_sem_atacante.md`), e "
            + _enumerar(
                f"{_pct(fracao, 1)} das janelas de {janela}" for janela, fracao in _benignas_com_atacante(m).items()
            )
            + " desses pcaps têm ao menos um quadro de um MAC da lista. A regra de rótulo não usa a lista nos pcaps "
            "benignos, então parte do tráfego comum desse dispositivo está no treino como benigno."
        ),
        "- **As seis colunas da janela deixaram de ser atalho.** Com uma janela só, `Number` vale o mesmo em todas",
        "  as classes, a não ser na última janela de cada pcap, que pode ficar incompleta.",
    ]


def _ressalva_do_fundo(m):
    if not _fundo_no_treino(m):
        return [
            "- **As janelas descartadas não são avaliadas aqui.** O tráfego de fundo dos pcaps de ataque fica fora do",
            f"  treino e do teste. O que o modelo faz com ele está em `{RODADAS}`.",
        ]
    return [
        "- **O fundo entra no treino como benigno.** Parte dele pode conter efeito do ataque, e o modelo aprende a",
        "  chamar de benigno o que se parece com ele; o recall de Recon e o de Spoofing caem por isso. O fundo da",
        f"  parte de teste não entra no teste deste relatório: o que o modelo faz com ele está em `{CAPTURAS}` e em",
        f"  `{PONTO_DE_OPERACAO}`.",
    ]


def _como_foram_obtidos(m):
    r = m["regeracao"]
    return [
        "## Como os números foram obtidos",
        "",
        (
            f"- Comando: `{m['gerado_por']}{'' if _fundo_no_treino(m) else ' --sem-fundo'}`, a partir da raiz do "
            "repositório, depois de `python -m "
            "codigo.classificador.regerar`. Ele refaz a leitura, o teto, a divisão, o treino, a avaliação e este "
            "relatório."
        ),
        (
            f"- Dados: `{r['destino']}/janela_<W>/<rotulo>.csv.gz`, registrados em `{Path(r['manifesto']).name}` "
            f"(gerado em {datetime.date.fromisoformat(r['gerado_em']).strftime('%d/%m/%Y')}, pcaps em "
            f"`{r['dataset']}`), com o SHA-256 de cada pcap"
            + (
                f", a versão {r['versao_da_regra']} da regra e o extrator de SHA-256 `{r['extrator']['sha256']}`."
                if r.get("extrator") else "."
            )
        ),
        "- Modelos: um por janela, em `modelos/`, fora do git, com o ponto de operação num JSON ao lado: "
        + _enumerar(f"`{j['modelo']['arquivo']}` ({_decimal(j['modelo']['bytes'] / 1e6)} MB)"
                    + (f" e `{j['ponto_de_operacao']['arquivo']}`" if j.get("ponto_de_operacao") else "")
                    for j in m["janelas"])
        + f". Treinados com {m['nucleos'] if m['nucleos'] > 0 else 'todos os'} núcleos; a quantidade de núcleos muda "
        "o tempo, e não o modelo. Predição com um núcleo, em ordem fixa.",
        (f"- Divisões: o SHA-256 das posições de treino e de teste de cada janela está em "
         f"`{nomes(_fundo_no_treino(m))['manifesto']}`."),
        (
            f"- `{nomes(_fundo_no_treino(m))['metricas']}` tem uma linha por janela, regra e categoria; "
            f"`{nomes(_fundo_no_treino(m))['por_arquivo']}`, uma por janela e pcap; "
            f"`{MATRIZES}/regerado_janela_<W>{nomes(_fundo_no_treino(m))['sufixo']}.csv` é a matriz de confusão com o "
            "argmax, `_limiar.csv` a com o melhor limiar, `_ponto.csv` a da regra escolhida na validação, e "
            "`_por_rotulo.csv` abre a classe real nos 34 rótulos."
        ),
        f"- Tempo total, na máquina em que rodou: {_decimal(m['duracao_segundos'])} s."
        + (f" Pico de memória do processo: {_decimal(m['memoria_pico_bytes'] / 1e9)} GB, que é o necessário para"
           " reproduzir." if m.get("memoria_pico_bytes") else ""),
        "- Com os mesmos CSVs regerados e a mesma semente, os números saem iguais. Só mudam a data e os tempos.",
    ]


def montar_relatorio(m):
    secoes = [_cabecalho(m), _o_que_mudou(m), _dados(m), _treino_e_teste(m)]
    secoes += [_resultados(m, j) for j in m["janelas"]]
    secoes += [_lado_a_lado(m) if len(m["janelas"]) > 1 else [], _ips(m), _rodadas_anteriores(m), _ressalvas(m),
               _como_foram_obtidos(m)]
    return "\n".join("\n".join(secao) + "\n" for secao in secoes if secao).rstrip("\n") + "\n"


# --- comando ---------------------------------------------------------------------------------


def _relatar(j):
    a = j["avaliacao"]["amostra"]
    print(
        f"janela de {j['janela']}: {_milhar(j['linhas']['treino'])} linhas de treino, {_milhar(j['linhas']['teste'])} de "
        f"teste, treino em {_decimal(j['treino_segundos'])} s; macro-F1 {_pct(a['macro_f1'])}, benigno como ataque "
        f"{_pct(a['falso_positivo_benigno'])}; regra escolhida: {_nome_da_regra(j['ponto_de_operacao'])}",
        file=sys.stderr,
    )


def _lista_de_janelas(texto):
    try:
        janelas = tuple(int(parte) for parte in texto.split(",") if parte.strip())
    except ValueError:
        raise argparse.ArgumentTypeError("as janelas precisam ser números inteiros separados por vírgula") from None
    if not janelas or any(janela < 1 for janela in janelas) or len(set(janelas)) != len(janelas):
        raise argparse.ArgumentTypeError("as janelas precisam ser inteiros positivos e diferentes entre si")
    return janelas


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.classificador.treinar_regerado",
        description="Treina e avalia o Random Forest de 7 categorias do sistema nos dados regerados, com o ponto de operação.",
        allow_abbrev=False,
    )
    analisador.add_argument("--saida", default="experimentos/resultados", help="pasta dos resultados")
    analisador.add_argument(
        "--manifesto-da-regeracao", default=None,
        help=f"manifesto gravado por regerar (padrão: {MANIFESTO_DA_REGERACAO} na pasta dos resultados)",
    )
    analisador.add_argument("--destino", default=None, help="pasta dos CSVs regerados (padrão: a do manifesto)")
    analisador.add_argument("--modelos", default=MODELOS, help=f"pasta dos modelos salvos (padrão: {MODELOS})")
    analisador.add_argument("--semente", type=int, default=SEMENTE, help=f"padrão: {SEMENTE}")
    analisador.add_argument("--arvores", type=_positivo, default=ARVORES, help=f"padrão: {ARVORES}")
    analisador.add_argument("--teto", type=_positivo, default=TETO, help=f"linhas por rótulo (padrão: {TETO})")
    analisador.add_argument(
        "--nucleos", type=_nucleos, default=TODOS_OS_NUCLEOS,
        help=f"núcleos usados no treino (padrão: {TODOS_OS_NUCLEOS}, todos). Os números são os mesmos com qualquer valor",
    )
    analisador.add_argument(
        "--sem-fundo", action="store_true",
        help="refaz o treino de 10/10, sem o fundo, como referência: grava com _sem_fundo no nome, nas janelas do manifesto",
    )
    analisador.add_argument(
        "--janelas", type=_lista_de_janelas, default=None,
        help=f"janelas a treinar, separadas por vírgula (padrão: {JANELA_DO_SISTEMA}; com --sem-fundo, as do manifesto)",
    )
    analisador.add_argument(
        "--refazer-relatorio", action="store_true",
        help="não treina: refaz o relatório e as tabelas a partir do manifesto do treino",
    )
    try:
        argumentos = analisador.parse_args(argv)
    except SystemExit as encerramento:
        return encerramento.code
    saida = Path(argumentos.saida)
    fundo = not argumentos.sem_fundo
    arquivos = nomes(fundo)
    try:
        if argumentos.refazer_relatorio:
            manifesto = json.loads((saida / arquivos["manifesto"]).read_text(encoding="utf-8"))
        else:
            caminho = Path(argumentos.manifesto_da_regeracao or saida / MANIFESTO_DA_REGERACAO)
            if not caminho.exists():
                raise ValueError(f"{caminho} não existe: rode python -m codigo.classificador.regerar antes")
            regeracao = json.loads(caminho.read_text(encoding="utf-8"))
            destino = argumentos.destino or regeracao["destino"]
            anteriores = rodadas_anteriores(saida / arquivos["manifesto"], regeracao, fundo, saida / MANIFESTO)
            anterior = modelo_anterior(saida / arquivos["manifesto"], fundo)
            janelas = argumentos.janelas or ((JANELA_DO_SISTEMA,) if fundo else tuple(regeracao["janelas"]))
            faltam = [janela for janela in janelas if janela not in regeracao["janelas"]]
            if faltam:
                raise ValueError(f"{caminho.name} não tem a janela de {_enumerar(faltam)}: as janelas regeradas são "
                                 f"{_enumerar(regeracao['janelas'])}")
            registro = rodar(
                regeracao, destino, argumentos.semente, argumentos.arvores, argumentos.nucleos, argumentos.teto,
                argumentos.modelos, ao_terminar=_relatar, janelas_pedidas=janelas, fundo_como_benigno=fundo,
            )
            manifesto = montar_manifesto(
                registro, regeracao, caminho, destino, argumentos.semente, argumentos.arvores, argumentos.nucleos,
                argumentos.teto, anteriores, fundo, anterior,
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
