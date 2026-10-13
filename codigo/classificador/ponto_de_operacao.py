"""Ponto de operação do classificador: o limiar escolhido numa parte de validação e o alarme por janelas seguidas.

A decisão da equipe: o limiar e a regra de janelas seguidas são escolhidos numa parte de validação,
nunca no teste. A regra é a de `operacao`: a janela é ataque se 1 − P(Benign) ≥ t, na categoria de
ataque mais provável, e um incidente só abre com 3 janelas de ataque seguidas, na ordem do pcap.

O que este módulo faz, em cada configuração pedida (das de `rodadas.CONFIGURACOES`), com as três
sementes de controle das rodadas:

1. Validação. Dentro da parte de treino de cada pcap (os primeiros 70% das janelas, pelo corte por
   tempo das rodadas), as últimas 15% dessas janelas, por tempo, são a validação, e o resto é o
   treino reduzido. Nos rótulos com um pcap inteiro no teste, a validação são as últimas 15% das
   janelas de cada pcap de treino. O teste não muda.
2. Limiar. O modelo treinado no treino reduzido (a mesma amostra com teto, a mesma semente e, na
   configuração com o fundo no treino, o fundo do treino reduzido) classifica todas as janelas da
   validação. O limiar é o menor t da grade de 0,01 em 0,01 que deixa no máximo 1% das janelas dos
   pcaps benignos da validação como ataque.
3. Teste. O modelo treinado no treino inteiro, o mesmo do corte por tempo das rodadas, com o t
   escolhido: as medidas por categoria no corte por tempo, o pcap benigno de fora por janela e por
   alarme, o fundo virando ataque e os pcaps de ataque que alarmam no trecho de teste. Nas rotações
   do pcap benigno de fora, cada rotação escolhe o seu t na sua própria validação, porque a
   validação da rotação 0 tem janelas do pcap que outra rotação deixa de fora.

As diferenças entre o limiar e o argmax de hoje, e entre duas configurações no limiar, são pareadas
como nas rodadas (`rodadas.comparar`). Os modelos salvos por `treinar_regerado` são conferidos contra
o retreino da semente principal: o do sistema (configuração 5, `rf_regerado_janela_100.joblib`) e o
de referência, de 10/10 (configuração 0, `rf_regerado_janela_100_sem_fundo.joblib`), com o t e o N
gravados no JSON ao lado de cada um. Este módulo não grava modelo nem ponto de operação.

Os resultados de cada treino ficam guardados em `dados/processed/ponto_de_operacao/`, com uma chave
que inclui a dos treinos das rodadas e o SHA-256 deste módulo e de `operacao`.

Uso, a partir da raiz do repositório:
    python -m codigo.classificador.ponto_de_operacao --nucleos 4
    python -m codigo.classificador.ponto_de_operacao --refazer-relatorio
"""
import argparse
import datetime
import hashlib
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn

from codigo.classificador import rodadas
from codigo.classificador.experimento import _decimal, _milhar
from codigo.classificador.operacao import (
    ALARME_FALSO_MAXIMO,
    FRACAO_DE_VALIDACAO,
    LIMIARES,
    SEGUIDAS,
    PontoDeOperacao,
    escolher_limiar,
)
from codigo.classificador.operacao import ler as ler_ponto
from codigo.classificador.preparar import (
    FEATURES_39,
    FRACAO_DE_TESTE_POR_TEMPO,
    alvo,
)
from codigo.classificador.rodadas import (
    ALVO,
    BENIGNO,
    CATEGORIA,
    CLASSES,
    JANELA,
    SEMENTES,
    SEMENTES_DE_CONTROLE,
    Execucao,
    Trabalho,
    _duracao,
    _ler_json,
    _sha256,
    codigos,
    comparar,
    comparar_cortes,
    de_fora,
    impressao_da_configuracao,
    lados,
    ler_dados,
    memoria_pico,
    no_teste,
    probabilidades,
    proporcao,
    resumo_das_medidas,
    rotacoes,
)
from codigo.classificador.rodadas_relatorio import regra_de_adocao
from codigo.classificador.treinar import (
    ARVORES,
    TODOS_OS_NUCLEOS,
    _nucleos,
    _positivo,
    carregar_modelo,
)
from codigo.classificador.treinar_regerado import TETO, nome_do_modelo

MANIFESTO = "manifesto_ponto_de_operacao.json"
RELATORIO = "ponto_de_operacao.md"
PREFIXO = "ponto_de_operacao"
TRABALHO = "dados/processed/ponto_de_operacao"
# Os modelos salvos por `treinar_regerado` que cada configuração reproduz na semente principal.
MODELOS_SALVOS = {"0": nome_do_modelo(JANELA, fundo_como_benigno=False), "5": nome_do_modelo(JANELA)}
# As duas regras medidas com o mesmo modelo: a do ponto de operação e a categoria mais provável de hoje.
REGRAS = ("limiar", "argmax")
MODULOS = ("codigo/classificador/ponto_de_operacao.py", "codigo/classificador/operacao.py")


# --- a divisão com a validação -----------------------------------------------------------------


def inicios_da_validacao(regeracao, rotacao=0, fracao=FRACAO_DE_VALIDACAO):
    """O índice da primeira janela da validação de cada pcap que tem parte de treino.

    A parte de treino de um pcap vai da janela 0 ao corte por tempo, ou ao fim do arquivo no pcap
    de treino de um rótulo de vários pcaps; a validação são as últimas `fracao` dela, contadas nas
    janelas extraídas, como o corte por tempo conta.
    """
    totais = {p["arquivo"]: p["janelas"][str(JANELA)]["extraidas"] for p in regeracao["pcaps"]}
    saida = {}
    for arquivo, lado in lados(regeracao, rotacao).items():
        if lado == "teste":
            continue
        fim = totais[arquivo] if lado == "treino" else lado
        saida[arquivo] = int((1 - fracao) * fim + 0.5)
    return saida


def lados_do_treino_reduzido(lados_da_divisao, inicios):
    """Os lados da divisão com a validação fora do treino: o corte de cada pcap de treino passa ao início da validação.

    Com estes lados, `no_teste` marca o teste e a validação juntos, e `Execucao._treino` monta o treino
    reduzido, com o fundo do treino reduzido na configuração que põe o fundo no treino.
    """
    return {arquivo: ("teste" if lado == "teste" else inicios[arquivo]) for arquivo, lado in lados_da_divisao.items()}


def na_validacao(meta, lados_da_divisao, inicios):
    """Se cada janela fica na validação: depois do início da validação do pcap e fora do teste."""
    arquivos, indices = meta["arquivo"].to_numpy(), meta["indice"].to_numpy()
    validacao = np.zeros(len(meta), dtype=bool)
    for arquivo in pd.unique(arquivos):
        if arquivo in inicios:
            do_pcap = arquivos == arquivo
            validacao[do_pcap] = indices[do_pcap] >= inicios[arquivo]
    return validacao & ~no_teste(meta, lados_da_divisao)


def _p_ataque(proba, classes):
    return 1.0 - proba[:, list(classes).index(BENIGNO)]


def _regras(ponto, proba, classes):
    """As categorias pelas duas regras, com as mesmas probabilidades: o limiar e o argmax de hoje."""
    classes = np.asarray(classes, dtype=object)
    return {"limiar": ponto.categorias(proba, classes), "argmax": classes[proba.argmax(axis=1)].astype(object)}


def _alarmes(ponto, categorias, X):
    """Os incidentes da regra numa sequência de janelas: quantos, a primeira janela e o tempo até ela."""
    disparos = ponto.incidentes(categorias)
    acumulado = np.cumsum(_duracao(X)) if len(X) else np.zeros(0)
    primeiro = disparos[0] if disparos else None
    return {
        "janelas": len(categorias), "segundos": float(acumulado[-1]) if len(acumulado) else 0.0,
        "como_ataque": int((np.asarray(categorias) != BENIGNO).sum()), "alarmes": len(disparos),
        "primeira_janela": None if primeiro is None else primeiro + 1,
        "primeiro_segundos": None if primeiro is None else float(acumulado[primeiro]),
    }


def _trecho(dados, arquivo, inicio=None, fim=None):
    """As janelas de um pcap de ataque entre dois índices, as com e as sem o atacante, na ordem do arquivo."""
    partes = []
    for fundo in (False, True):
        X, meta = dados.do_pcap(arquivo, fundo=fundo)
        if not len(meta):
            continue
        indices = meta["indice"].to_numpy()
        dentro = np.ones(len(indices), dtype=bool)
        if inicio is not None:
            dentro &= indices >= inicio
        if fim is not None:
            dentro &= indices < fim
        partes.append((X[dentro], indices[dentro], np.full(int(dentro.sum()), not fundo)))
    if not partes:
        return np.empty((0, len(FEATURES_39)), np.float32), np.zeros(0, bool)
    X = np.concatenate([p[0] for p in partes])
    ordem = np.argsort(np.concatenate([p[1] for p in partes]), kind="stable")
    return X[ordem], np.concatenate([p[2] for p in partes])[ordem]


# --- os treinos de uma configuração ------------------------------------------------------------


class Ponto:
    """O ponto de operação de uma configuração: em cada semente e rotação, o treino reduzido e o inteiro."""

    def __init__(self, configuracao, dados, arvores=ARVORES, nucleos=TODOS_OS_NUCLEOS, teto=TETO,
                 trabalho=TRABALHO, trabalho_das_rodadas=rodadas.TRABALHO):
        self.configuracao = configuracao
        self.execucao = Execucao(configuracao, dados, arvores, nucleos, teto, trabalho_das_rodadas)
        chave = {
            "rodadas": impressao_da_configuracao(configuracao, dados, arvores, teto),
            "codigo": {nome: _sha256(rodadas.RAIZ / nome) for nome in MODULOS},
            "validacao": FRACAO_DE_VALIDACAO, "alarme_falso": ALARME_FALSO_MAXIMO, "limiares": list(LIMIARES),
            "seguidas": SEGUIDAS,
        }
        self.trabalho = Trabalho(trabalho, hashlib.sha256(json.dumps(chave, sort_keys=True).encode()).hexdigest()[:24])

    @property
    def dados(self):
        return self.execucao.dados

    def medir(self, semente, rotacao, modelo_salvo=None):
        """O resultado guardado da semente e da rotação, ou os dois treinos feitos agora.

        Com `modelo_salvo`, o modelo gravado nesse caminho é conferido contra o do treino inteiro; o
        resultado guardado só vale se o arquivo continua o mesmo.
        """
        def aceita(resultado):
            if modelo_salvo is None:
                return True
            salvo = resultado.get("modelo_salvo")
            return salvo is not None and _sha256(modelo_salvo) == salvo["sha256"]

        chave = f"{rotacao}|{semente}"
        resultado = self.trabalho.obter(chave, aceita=aceita)
        if resultado is None:
            inicio = time.perf_counter()
            resultado, predicoes = self._medir(semente, rotacao, modelo_salvo)
            resultado["memoria_pico_bytes"] = memoria_pico()
            self.trabalho.guardar(chave, resultado, predicoes)
            rodadas._relatar(f"ponto de operação, configuração {self.configuracao.nome}, rotação {rotacao}, semente "
                             f"{semente}: t = {resultado['limiar']}, {_decimal(time.perf_counter() - inicio)} s")
        return resultado

    def predicoes(self, chave):
        return self.trabalho.predicoes(chave)

    def _medir(self, semente, rotacao, modelo_salvo):
        execucao, dados = self.execucao, self.dados
        regeracao = dados.regeracao
        posicoes = execucao.amostra(semente)
        meta = dados.meta.iloc[posicoes]
        lados_da_divisao = lados(regeracao, rotacao)
        inicios = inicios_da_validacao(regeracao, rotacao)
        reduzido = lados_do_treino_reduzido(lados_da_divisao, inicios)
        # 1. O treino reduzido e a escolha do limiar na validação.
        X, y = execucao._treino(posicoes, no_teste(meta, reduzido), reduzido)
        modelo, segundos_reduzido = execucao._treinar(X, y, semente)
        linhas_reduzido = len(y)
        del X, y
        validacao = self._validacao(modelo, lados_da_divisao, inicios, completa=rotacao == 0)
        del modelo
        if validacao["limiar"] is None:
            raise ValueError(f"configuração {self.configuracao.nome}, semente {semente}, rotação {rotacao}: nenhum "
                             f"limiar da grade deixa no máximo {ALARME_FALSO_MAXIMO} do benigno da validação como ataque")
        ponto = PontoDeOperacao(validacao["limiar"], SEGUIDAS)
        # 2. O treino inteiro, o do corte por tempo (rotação 0) ou o da rotação, com o limiar escolhido.
        teste = no_teste(meta, lados_da_divisao)
        X, y = execucao._treino(posicoes, teste, lados_da_divisao)
        modelo, segundos = execucao._treinar(X, y, semente)
        linhas = len(y)
        del X, y
        benigno = next(a for a in de_fora(lados_da_divisao) if CATEGORIA[self._rotulo(a)] == BENIGNO)
        X_benigno, meta_benigno = dados.do_pcap(benigno)
        proba = probabilidades(modelo, execucao._X(X_benigno))
        no_benigno = _regras(ponto, proba, modelo.classes_)
        resultado = {
            "semente": semente, "rotacao": rotacao, "limiar": ponto.limiar, "seguidas": ponto.seguidas,
            "linhas": {"treino_reduzido": linhas_reduzido, "treino": linhas},
            "treino_segundos": segundos_reduzido + segundos,
            "validacao": validacao,
            "benigno_de_fora": {"arquivo": benigno, **{r: _alarmes(ponto, no_benigno[r], X_benigno) for r in REGRAS}},
        }
        predicoes = {"benigno_indice": meta_benigno["indice"].to_numpy(dtype=np.int32),
                     **{f"benigno_{r}": codigos(no_benigno[r]) for r in REGRAS}}
        guardado = execucao.trabalho.obter("corte|" + str(semente) if rotacao == 0 else f"rotacao|{rotacao}|{semente}")
        if rotacao == 0:
            medidas, mais = self._no_teste(modelo, ponto, posicoes, meta, teste, lados_da_divisao)
            resultado.update(medidas)
            predicoes.update(mais)
        resultado["conferencia"] = self._conferencia(guardado, rotacao, semente, predicoes)
        if modelo_salvo is not None and rotacao == 0:
            del modelo
            resultado["modelo_salvo"] = self._conferir_o_salvo(modelo_salvo, ponto, posicoes, teste, predicoes)
        return resultado, predicoes

    def _rotulo(self, arquivo):
        return next(p["rotulo"] for p in self.dados.regeracao["pcaps"] if p["arquivo"] == arquivo)

    def _validacao(self, modelo, lados_da_divisao, inicios, completa):
        """O limiar escolhido no benigno da validação e, com `completa`, a regra no resto da validação."""
        dados, execucao = self.dados, self.execucao
        totais = dados.totais
        benignos, p_ataque, por_pcap = [], [], []
        for p in dados.regeracao["pcaps"]:
            arquivo = p["arquivo"]
            if arquivo not in inicios or not p["benigno"]:
                continue
            fim = totais[arquivo] if lados_da_divisao[arquivo] == "treino" else lados_da_divisao[arquivo]
            X, meta = dados.do_pcap(arquivo)
            dentro = (meta["indice"].to_numpy() >= inicios[arquivo]) & (meta["indice"].to_numpy() < fim)
            proba = probabilidades(modelo, execucao._X(X[dentro]))
            benignos.append((arquivo, X[dentro], proba))
            p_ataque.append(_p_ataque(proba, modelo.classes_))
        limiar, curva = escolher_limiar(np.concatenate(p_ataque))
        saida = {
            "inicios": inicios, "janelas_benignas": int(sum(len(p) for p in p_ataque)),
            "benigno_como_ataque": {str(t): n for t, n in curva.items()}, "limiar": limiar,
            "benigno_argmax": int(sum((prob.argmax(axis=1) != list(modelo.classes_).index(BENIGNO)).sum()
                                      for _, _, prob in benignos)),
        }
        if not completa or limiar is None:
            return saida
        ponto = PontoDeOperacao(limiar, SEGUIDAS)
        for arquivo, X, proba in benignos:
            por_pcap.append({"arquivo": arquivo, "categoria": BENIGNO, "com_atacante": 0,
                             **_alarmes(ponto, ponto.categorias(proba, modelo.classes_), X)})
        contagem = {classe: {"janelas": 0, "na_categoria": 0, "como_ataque": 0} for classe in CLASSES if classe != BENIGNO}
        fundo = {"janelas": 0, "como_ataque": 0}
        for p in dados.regeracao["pcaps"]:
            arquivo = p["arquivo"]
            if arquivo not in inicios or p["benigno"]:
                continue
            fim = totais[arquivo] if lados_da_divisao[arquivo] == "treino" else lados_da_divisao[arquivo]
            X, com_atacante = _trecho(dados, arquivo, inicios[arquivo], fim)
            if not len(X):
                continue
            categorias = ponto.categorias(probabilidades(modelo, execucao._X(X)), modelo.classes_)
            categoria = CATEGORIA[p["rotulo"]]
            contagem[categoria]["janelas"] += int(com_atacante.sum())
            contagem[categoria]["na_categoria"] += int((categorias[com_atacante] == categoria).sum())
            contagem[categoria]["como_ataque"] += int((categorias[com_atacante] != BENIGNO).sum())
            fundo["janelas"] += int((~com_atacante).sum())
            fundo["como_ataque"] += int((categorias[~com_atacante] != BENIGNO).sum())
            por_pcap.append({"arquivo": arquivo, "categoria": categoria, "com_atacante": int(com_atacante.sum()),
                             **_alarmes(ponto, categorias, X)})
        saida.update({"por_categoria": contagem, "fundo": fundo, "por_pcap": por_pcap})
        return saida

    def _no_teste(self, modelo, ponto, posicoes, meta, teste, lados_da_divisao):
        """Na rotação 0: o corte por tempo, o fundo e o trecho de teste de cada pcap de ataque, pelas duas regras."""
        dados, execucao = self.dados, self.execucao
        rotulos = meta["Label"].to_numpy()[teste]
        arquivos = meta["arquivo"].to_numpy()[teste]
        no_corte = _regras(ponto, probabilidades(modelo, execucao._X(dados.X[posicoes[teste]])), modelo.classes_)
        fundo_teste = no_teste(dados.fundo_meta, lados_da_divisao)
        no_fundo = _regras(ponto, probabilidades(modelo, execucao._X(dados.fundo_X)), modelo.classes_)
        fundo_arquivos = dados.fundo_meta["arquivo"].to_numpy()
        fundo = {
            r: {"janelas": int(fundo_teste.sum()), "como_ataque": int((no_fundo[r][fundo_teste] != BENIGNO).sum()),
                "por_pcap": {a: int(((no_fundo[r] != BENIGNO) & fundo_teste & (fundo_arquivos == a)).sum())
                             for a in sorted(pd.unique(fundo_arquivos[fundo_teste]))}}
            for r in REGRAS
        }
        trechos = []
        for p in dados.regeracao["pcaps"]:
            lado = lados_da_divisao[p["arquivo"]]
            if p["benigno"] or lado == "treino":
                continue
            X, com_atacante = _trecho(dados, p["arquivo"], None if lado == "teste" else lado)
            if not len(X):
                continue
            categorias = _regras(ponto, probabilidades(modelo, execucao._X(X)), modelo.classes_)
            trechos.append({"arquivo": p["arquivo"], "categoria": CATEGORIA[p["rotulo"]],
                            "com_atacante": int(com_atacante.sum()),
                            **{r: _alarmes(ponto, categorias[r], X) for r in REGRAS}})
        medidas = {
            "linhas_de_teste": int(teste.sum()),
            "medidas": {r: resumo_das_medidas(no_corte[r], rotulos) for r in REGRAS},
            "fundo": fundo, "trechos_de_ataque": trechos,
        }
        predicoes = {
            "teste_real": codigos(alvo(rotulos, ALVO)),
            "teste_arquivo": np.array([self.execucao.numero_do_pcap[a] for a in arquivos], dtype=np.int16),
            "teste_indice": meta["indice"].to_numpy(dtype=np.int32)[teste],
            "fundo_teste": fundo_teste,
            "fundo_arquivo": np.array([self.execucao.numero_do_pcap[a] for a in fundo_arquivos], dtype=np.int16),
            "fundo_indice": dados.fundo_meta["indice"].to_numpy(dtype=np.int32),
            **{f"teste_{r}": codigos(no_corte[r]) for r in REGRAS},
            **{f"fundo_{r}": codigos(no_fundo[r]) for r in REGRAS},
        }
        return medidas, predicoes

    def _conferencia(self, guardado, rotacao, semente, predicoes):
        """Predições do argmax diferentes das do mesmo treino guardado pelas rodadas, se ele está guardado."""
        if guardado is None:
            return None
        chave = "corte|" + str(semente) if rotacao == 0 else f"rotacao|{rotacao}|{semente}"
        antes = self.execucao.predicoes(chave)
        pares = [("benigno_previsto", "benigno_argmax")]
        if rotacao == 0:
            pares += [("teste_previsto", "teste_argmax"), ("fundo_previsto", "fundo_argmax")]
        return {nome: int((antes[nome] != predicoes[novo]).sum()) for nome, novo in pares}

    def _conferir_o_salvo(self, caminho, ponto, posicoes, teste, predicoes):
        """O modelo salvo no corte por tempo, pelas duas regras, contra o retreino da mesma semente."""
        salvo = carregar_modelo(caminho)["modelo"]
        proba = probabilidades(salvo, self.execucao._X(self.dados.X[posicoes[teste]]))
        regras = _regras(ponto, proba, salvo.classes_)
        return {"arquivo": Path(caminho).name, "caminho": Path(caminho).as_posix(), "sha256": _sha256(caminho),
                **{f"diferentes_{r}": int((codigos(regras[r]) != predicoes[f"teste_{r}"]).sum()) for r in REGRAS}}


# --- as comparações pareadas -------------------------------------------------------------------


class Vista:
    """As predições de um ponto de operação por uma das regras, com os nomes que `rodadas.comparar_cortes` lê."""

    def __init__(self, ponto, regra):
        self.ponto, self.regra = ponto, regra

    def predicoes(self, chave):
        partes = chave.split("|")
        rotacao, semente = (0, partes[1]) if partes[0] == "corte" else (partes[1], partes[2])
        guardadas = self.ponto.predicoes(f"{rotacao}|{semente}")
        saida = {nome: valor for nome, valor in guardadas.items() if not nome.endswith(REGRAS)}
        for nome in ("teste", "benigno", "fundo"):
            if f"{nome}_{self.regra}" in guardadas:
                saida[f"{nome}_previsto"] = guardadas[f"{nome}_{self.regra}"]
        return saida


def comparar_pontos(a, b, sementes, rotacoes_):
    """A diferença pareada b − a no corte por tempo, no pcap benigno de fora de cada rotação e no fundo de teste."""
    benigno = CLASSES.index(BENIGNO)
    saida = {"corte": comparar_cortes(a, b, sementes), "rotacao": {}}
    for rotacao in range(rotacoes_):
        pares = []
        for semente in sementes:
            chave = f"corte|{semente}" if rotacao == 0 else f"rotacao|{rotacao}|{semente}"
            x, y = a.predicoes(chave), b.predicoes(chave)
            rodadas._alinhadas(x, y, ("benigno_indice",), chave)
            pares.append((np.zeros(len(x["benigno_indice"])), x["benigno_indice"],
                          (x["benigno_previsto"] != benigno).astype(float), (y["benigno_previsto"] != benigno).astype(float)))
        saida["rotacao"][str(rotacao)] = comparar(pares, proporcao, 2)["valor"]
    pares = []
    for semente in sementes:
        x, y = a.predicoes(f"corte|{semente}"), b.predicoes(f"corte|{semente}")
        rodadas._alinhadas(x, y, ("fundo_arquivo", "fundo_indice", "fundo_teste"), f"fundo, semente {semente}")
        lado = x["fundo_teste"]
        pares.append((x["fundo_arquivo"][lado], x["fundo_indice"][lado], (x["fundo_previsto"][lado] != benigno).astype(float),
                      (y["fundo_previsto"][lado] != benigno).astype(float)))
    saida["fundo"] = comparar(pares, proporcao, 2)["valor"]
    return saida


# --- a execução --------------------------------------------------------------------------------


def rodar(configuracoes, dados, sementes=SEMENTES, arvores=ARVORES, nucleos=TODOS_OS_NUCLEOS, teto=TETO,
          trabalho=TRABALHO, trabalho_das_rodadas=rodadas.TRABALHO, modelos="modelos"):
    """Os treinos de cada configuração, as comparações e a conferência dos modelos salvos, num dicionário."""
    controle = list(sementes[:SEMENTES_DE_CONTROLE])
    principal = controle[0]
    rotacoes_ = rotacoes(dados.regeracao)
    referencia = configuracoes[0]
    pontos, saida = {}, {"configuracoes": {}, "comparacoes": {}, "modelos_salvos": {}}
    for configuracao in configuracoes:
        ponto = Ponto(configuracao, dados, arvores, nucleos, teto, trabalho, trabalho_das_rodadas)
        salvo = None
        if modelos is not None and configuracao.nome in MODELOS_SALVOS:
            salvo = Path(modelos) / MODELOS_SALVOS[configuracao.nome]
            salvo = salvo if salvo.exists() else None
        resultados = {}
        for semente in controle:
            for rotacao in range(rotacoes_):
                conferir = salvo if semente == principal and rotacao == 0 else None
                resultados.setdefault(str(rotacao), {})[str(semente)] = ponto.medir(semente, rotacao, conferir)
        pontos[configuracao.nome] = ponto
        saida["configuracoes"][configuracao.nome] = {
            "descricao": configuracao.descricao, "destino": configuracao.destino,
            "fundo_como_benigno": configuracao.fundo_como_benigno, "resultados": resultados,
        }
        if salvo is not None:
            saida["modelos_salvos"][configuracao.nome] = conferir_modelo_salvo(resultados["0"][str(principal)], salvo)
    for nome, ponto in pontos.items():
        saida["comparacoes"][f"{nome}:limiar-argmax"] = comparar_pontos(Vista(ponto, "argmax"), Vista(ponto, "limiar"),
                                                                        controle, rotacoes_)
        if nome != referencia.nome:
            saida["comparacoes"][f"{nome}-{referencia.nome}:limiar"] = comparar_pontos(
                Vista(pontos[referencia.nome], "limiar"), Vista(ponto, "limiar"), controle, rotacoes_)
    return saida


def conferir_modelo_salvo(unidade, caminho):
    """O modelo salvo contra o retreino da semente principal, e o ponto de operação gravado ao lado dele."""
    salvo = unidade["modelo_salvo"]
    try:
        gravado = ler_ponto(caminho)
        ponto = {"limiar": gravado.limiar, "seguidas": gravado.seguidas}
    except (OSError, ValueError, KeyError):
        ponto = None
    return {
        **salvo, "limiar_escolhido": unidade["limiar"], "seguidas": unidade["seguidas"], "ponto_gravado": ponto,
        "confere": (not any(salvo[f"diferentes_{r}"] for r in REGRAS) and ponto is not None
                    and ponto["limiar"] == unidade["limiar"] and ponto["seguidas"] == unidade["seguidas"]),
    }


def _codigo():
    """O código de que os números saem: o das rodadas e os módulos do ponto de operação, com o commit."""
    calculo = rodadas.codigo_do_calculo()
    calculo["arquivos"].update({nome: _sha256(rodadas.RAIZ / nome) for nome in MODULOS})
    try:
        alterados = subprocess.run(["git", "status", "--porcelain", "--", *MODULOS], cwd=rodadas.RAIZ,
                                   capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        alterados = ""
    calculo["com_alteracoes_fora_do_commit"] = calculo["com_alteracoes_fora_do_commit"] or bool(alterados)
    return calculo


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.classificador.ponto_de_operacao",
        description="Escolhe o limiar numa parte de validação e mede o ponto de operação no teste.",
        allow_abbrev=False,
    )
    analisador.add_argument("--saida", default="experimentos/resultados", help="pasta dos resultados")
    analisador.add_argument("--trabalho", default=TRABALHO, help=f"pasta dos resultados parciais (padrão: {TRABALHO})")
    analisador.add_argument("--trabalho-das-rodadas", default=rodadas.TRABALHO,
                            help=f"treinos guardados das rodadas, para a conferência (padrão: {rodadas.TRABALHO})")
    analisador.add_argument("--configuracoes", default="0,5",
                            help="configurações de rodadas.CONFIGURACOES, a de referência primeiro (padrão: 0,5)")
    analisador.add_argument("--modelos", default="modelos",
                            help="pasta dos modelos salvos por treinar_regerado, conferidos contra o retreino")
    analisador.add_argument("--sementes", type=rodadas._lista_de_sementes, default=SEMENTES,
                            help="sementes, separadas por vírgula; a primeira é a principal (padrão: 42,1,2,3,4)")
    analisador.add_argument("--arvores", type=_positivo, default=ARVORES, help=f"padrão: {ARVORES}")
    analisador.add_argument("--teto", type=_positivo, default=TETO, help=f"linhas por rótulo (padrão: {TETO})")
    analisador.add_argument("--nucleos", type=_nucleos, default=TODOS_OS_NUCLEOS,
                            help=f"núcleos usados nos treinos (padrão: {TODOS_OS_NUCLEOS}, todos)")
    analisador.add_argument("--refazer-relatorio", action="store_true",
                            help="não treina: refaz o relatório e as tabelas a partir do manifesto")
    try:
        argumentos = analisador.parse_args(argv)
    except SystemExit as encerramento:
        return encerramento.code
    saida = Path(argumentos.saida)
    comando = " ".join(["python -m codigo.classificador.ponto_de_operacao", *(argv if argv is not None else sys.argv[1:])])
    inicio = time.perf_counter()
    try:
        if argumentos.refazer_relatorio:
            manifesto = _ler_json(saida / MANIFESTO)
        else:
            por_nome = {c.nome: c for c in rodadas.CONFIGURACOES}
            nomes = [nome.strip() for nome in argumentos.configuracoes.split(",") if nome.strip()]
            if not nomes or any(nome not in por_nome for nome in nomes) or len(set(nomes)) != len(nomes):
                raise ValueError(f"configurações desconhecidas ou repetidas: {argumentos.configuracoes} "
                                 f"(as configurações são {', '.join(por_nome)})")
            configuracoes = [por_nome[nome] for nome in nomes]
            if len({(c.destino, c.regeracao) for c in configuracoes}) != 1:
                raise ValueError("as configurações comparadas precisam ler a mesma pasta de dados")
            regeracao = _ler_json(configuracoes[0].regeracao)
            for configuracao in configuracoes:
                rodadas._conferir_opcoes(configuracao, regeracao)
            dados = ler_dados(configuracoes[0].destino, regeracao,
                              ao_ler=lambda nome, linhas: rodadas._relatar(f"{nome}: {_milhar(linhas)} janelas"))
            resultados = rodar(configuracoes, dados, argumentos.sementes, argumentos.arvores, argumentos.nucleos,
                               argumentos.teto, argumentos.trabalho, argumentos.trabalho_das_rodadas, argumentos.modelos)
            # A regra de adoção da configuração 5, aplicada à comparação de capturas: diz qual configuração venceu.
            capturas = saida / rodadas.MANIFESTO_DAS_CAPTURAS
            resultados["regra"] = regra_de_adocao(_ler_json(capturas)) if capturas.exists() else None
            manifesto = {
                "descricao": "Ponto de operação: limiar escolhido numa parte de validação e alarme por janelas seguidas",
                "gerado_por": "python -m codigo.classificador.ponto_de_operacao",
                "comando": comando,
                "gerado_em": datetime.datetime.now(tz=datetime.UTC).astimezone().strftime("%Y-%m-%d"),
                "versoes": {"python": platform.python_version(), "numpy": np.__version__, "pandas": pd.__version__,
                            "scikit-learn": sklearn.__version__},
                "parametros": {
                    "janela": JANELA, "teto": argumentos.teto, "arvores": argumentos.arvores, "nucleos": argumentos.nucleos,
                    "sementes": list(argumentos.sementes[:SEMENTES_DE_CONTROLE]), "fracao_de_teste": FRACAO_DE_TESTE_POR_TEMPO,
                    "fracao_de_validacao": FRACAO_DE_VALIDACAO, "alarme_falso_maximo": ALARME_FALSO_MAXIMO,
                    "limiares": list(LIMIARES), "seguidas": SEGUIDAS, "configuracoes": nomes,
                    "reamostragens_da_diferenca": rodadas.REAMOSTRAGENS_DA_DIFERENCA, "bloco": rodadas.BLOCO,
                },
                "entradas": {
                    "regeracao": rodadas._entrada_da_regeracao(configuracoes[0].regeracao, regeracao),
                    "arquivos": dados.entradas,
                    "capturas": ({"manifesto": capturas.as_posix(), "sha256": _sha256(capturas)}
                                 if capturas.exists() else None),
                },
                "codigo": _codigo(),
                "resultados": resultados,
                "duracao_segundos": time.perf_counter() - inicio,
                "memoria_pico_bytes": memoria_pico(),
            }
        # O relatório importa este módulo; a importação fica aqui para não haver ciclo.
        from codigo.classificador.ponto_de_operacao_relatorio import gravar

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
