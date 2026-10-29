"""Ponto de operação do classificador: a regra que o sistema aplica às probabilidades do modelo.

Há duas regras para decidir uma janela. Na do argmax, a janela vai para a categoria de maior
probabilidade. Na do limiar, a janela é ataque quando 1 − P(Benign) ≥ t; sendo ataque, a categoria
é a de maior probabilidade entre as categorias de ataque; senão, é Benign. Nas duas, um incidente só
abre com N janelas de ataque seguidas, na ordem em que o extrator as entrega: abre na janela que
completa as N, a sequência que continua não abre outro, e a próxima sequência que chegar a N abre
um novo.

A regra de um modelo é escolhida numa parte de validação, nunca no teste (`escolher_regra`). Os
candidatos são o argmax e os limiares da grade; podem vencer os que deixam no máximo 1% das janelas
benignas da validação como ataque, e vence o de maior recall de ataque na validação; no empate, o
de menos benigno como ataque. Entre os limiares, o recall de ataque só cai com t, e o melhor deles é
o menor que cumpre a meta, a não ser que um maior reconheça o mesmo ataque com menos benigno.

A regra e o N ficam num JSON ao lado do `.joblib` (`ao_lado_do_modelo`), gravado por
`codigo.classificador.treinar_regerado` junto com o modelo, com o SHA-256 dele; `ler` recusa o
JSON de outro modelo.

Este módulo só depende do numpy, para que o sistema aplique a regra sem os módulos dos experimentos.
O limiar é o mesmo de `rodadas.aplicar_limiar`, e os incidentes, os de `rodadas.alarmes`.

Uso no sistema:
    pacote = carregar_modelo(caminho)                  # codigo.classificador.treinar
    ponto = ler(caminho)
    vigia = Vigia(ponto, pacote["modelo"].classes_)
    categoria, abre = vigia.alimentar(pacote["modelo"].predict_proba(janela)[0])
"""
import datetime
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

import numpy as np

BENIGNO = "Benign"
SUFIXO = ".ponto_de_operacao.json"
# A escolha do ponto de operação, decidida pela equipe em 13/10/2026: a validação são as últimas 15%
# da parte de treino de cada pcap, por tempo; a regra é a de maior recall de ataque na validação
# entre as que deixam no máximo 1% das janelas benignas dela como ataque. O incidente abre com 4
# janelas de ataque seguidas desde 28/10/2026 (eram 3): na comparação de 12 regras sem retreino, nas
# capturas fora do CICIoT2023 e no teste dele, 4 seguidas cortou os incidentes falsos de 14 para 6 em
# 150 h de tráfego benigno, sem perder captura de ataque e sem mudar a classificação de cada janela
# (ROADMAP de 28/10; experimentos/resultados/testes_fora_do_ciciot2023.md).
FRACAO_DE_VALIDACAO = 0.15
ALARME_FALSO_MAXIMO = 0.01
SEGUIDAS = 4
LIMIARES = tuple(round(i / 100, 2) for i in range(1, 101))
# O limiar é inclusivo mesmo com o arredondamento do ponto flutuante: 1 − 0,4 dá 0,6000000000000001.
TOLERANCIA = 1e-12
ARGMAX, LIMIAR = "argmax", "limiar"
REGRAS_DO_PONTO = {
    ARGMAX: "A janela vai para a categoria de maior probabilidade.",
    LIMIAR: "A janela é ataque se 1 − P(Benign) ≥ limiar, na categoria de ataque de maior probabilidade; senão, é Benign.",
}
INCIDENTE = "Um incidente abre com `seguidas` janelas de ataque seguidas, na janela que completa a sequência."


@dataclass(frozen=True)
class PontoDeOperacao:
    """A regra de decisão da janela, o argmax (`limiar` None) ou o limiar sobre 1 − P(Benign), e o N."""

    limiar: float | None
    seguidas: int
    benigno: str = BENIGNO

    def __post_init__(self):
        if self.limiar is not None and not 0 < self.limiar <= 1:
            raise ValueError(f"o limiar precisa estar entre 0 e 1, e não {self.limiar}")
        if int(self.seguidas) != self.seguidas or self.seguidas < 1:
            raise ValueError(f"as janelas seguidas precisam ser um inteiro de ao menos 1, e não {self.seguidas}")

    @property
    def regra(self):
        return ARGMAX if self.limiar is None else LIMIAR

    def categorias(self, probabilidades, classes):
        """A categoria de cada janela: uma linha de probabilidades por janela, com as colunas na ordem de `classes`."""
        proba = np.atleast_2d(np.asarray(probabilidades, dtype=float))
        classes = np.asarray(classes, dtype=object)
        if proba.ndim != 2 or proba.shape[1] != len(classes):
            raise ValueError(f"cada janela precisa de {len(classes)} probabilidades, uma por classe")
        if self.benigno not in set(classes.tolist()):
            raise ValueError(f"as classes do modelo não têm {self.benigno}")
        if self.limiar is None:
            return classes[proba.argmax(axis=1)].astype(object)
        benigno = classes.tolist().index(self.benigno)
        de_ataque = proba.copy()
        de_ataque[:, benigno] = -np.inf
        ataque = 1.0 - proba[:, benigno] >= self.limiar - TOLERANCIA
        return np.where(ataque, classes[de_ataque.argmax(axis=1)], self.benigno).astype(object)

    def categoria(self, probabilidades, classes):
        """A categoria de uma janela, pelo vetor de probabilidades dela."""
        probabilidades = np.asarray(probabilidades, dtype=float)
        if probabilidades.ndim != 1:
            raise ValueError("uma janela tem um vetor de probabilidades; para várias, use `categorias`")
        return str(self.categorias(probabilidades[np.newaxis, :], classes)[0])

    def incidentes(self, categorias):
        """As posições, na sequência de janelas, em que um incidente abre."""
        posicoes, corrente = [], 0
        for posicao, categoria in enumerate(categorias):
            corrente = corrente + 1 if categoria != self.benigno else 0
            if corrente == self.seguidas:
                posicoes.append(posicao)
        return posicoes

    def aplicar(self, probabilidades, classes):
        """A regra numa sequência de janelas, na ordem do extrator: a categoria de cada uma e onde abre incidente."""
        categorias = self.categorias(probabilidades, classes)
        return categorias, self.incidentes(categorias)


def escolher_limiar(p_ataque, alvo_=ALARME_FALSO_MAXIMO, limiares=LIMIARES):
    """O menor limiar da grade que deixa no máximo `alvo_` das janelas como ataque, e a curva da grade.

    `p_ataque` é 1 − P(Benign) de cada janela benigna da validação. Devolve (limiar, curva), com a
    curva em janelas como ataque por limiar; o limiar é None quando nenhum da grade atende.
    """
    p_ataque = np.asarray(p_ataque, dtype=float)
    if not len(p_ataque):
        raise ValueError("a validação não tem nenhuma janela benigna")
    curva = _acima(p_ataque, limiares)
    escolhido = next((t for t in limiares if curva[t] <= alvo_ * len(p_ataque)), None)
    return escolhido, curva


def _acima(p_ataque, limiares):
    """Quantas janelas têm 1 − P(Benign) ≥ t, para cada limiar da grade."""
    ordenado = np.sort(np.asarray(p_ataque, dtype=float))
    return {t: int(len(ordenado) - np.searchsorted(ordenado, t - TOLERANCIA, side="left")) for t in limiares}


def para_a_escolha(probabilidades, classes, benigno=BENIGNO):
    """O que a escolha da regra usa de cada janela: 1 − P(Benign) e se o argmax a põe numa categoria de ataque."""
    proba = np.atleast_2d(np.asarray(probabilidades, dtype=float))
    indice = list(classes).index(benigno)
    return 1.0 - proba[:, indice], proba.argmax(axis=1) != indice


def escolher_regra(benignas, de_ataque, alvo_=ALARME_FALSO_MAXIMO, limiares=LIMIARES):
    """A regra escolhida na validação, entre o argmax e os limiares da grade, e o que cada candidato fez.

    `benignas` e `de_ataque` são o `para_a_escolha` das janelas benignas e das janelas de ataque da
    validação. Podem vencer os candidatos com no máximo `alvo_` das benignas como ataque; vence o de
    mais janelas de ataque reconhecidas como ataque; no empate, o de menos benignas como ataque, e
    depois o argmax, que não tem parâmetro, e o menor limiar. Devolve a regra, o limiar dela (None no
    argmax), o melhor limiar pelo mesmo critério, que concorre com o argmax, e as contagens de cada
    candidato.
    """
    p_benignas, argmax_benignas = benignas
    p_ataque, argmax_ataque = de_ataque
    if not len(p_benignas):
        raise ValueError("a validação não tem nenhuma janela benigna")
    if not len(p_ataque):
        raise ValueError("a validação não tem nenhuma janela de ataque")
    benigno_como_ataque = _acima(p_benignas, limiares)
    reconhecidas = _acima(p_ataque, limiares)
    teto = alvo_ * len(p_benignas)
    candidatos = [
        (ARGMAX, None, int(np.sum(argmax_benignas)), int(np.sum(argmax_ataque))),
        *((LIMIAR, t, benigno_como_ataque[t], reconhecidas[t]) for t in limiares),
    ]
    elegiveis = [c for c in candidatos if c[2] <= teto]

    def ordem(c):
        # Mais ataque reconhecido; no empate, menos benigno como ataque; depois o argmax e o menor limiar.
        return (-c[3], c[2], c[0] != ARGMAX, c[1] or 0)

    vencedor = min(elegiveis, key=ordem) if elegiveis else None
    limiares_elegiveis = [c for c in elegiveis if c[0] == LIMIAR]
    melhor_limiar = min(limiares_elegiveis, key=ordem)[1] if limiares_elegiveis else None
    return {
        "regra": None if vencedor is None else vencedor[0],
        "limiar": None if vencedor is None else vencedor[1],
        "melhor_limiar": melhor_limiar,
        "janelas_benignas": len(p_benignas), "janelas_de_ataque": len(p_ataque),
        "argmax": {"benigno_como_ataque": candidatos[0][2], "ataque_reconhecido": candidatos[0][3]},
        "curva": {str(t): {"benigno_como_ataque": benigno_como_ataque[t], "ataque_reconhecido": reconhecidas[t]}
                  for t in limiares},
    }


class Vigia:
    """A regra janela a janela, como o sistema recebe as janelas do extrator: guarda a sequência em curso."""

    def __init__(self, ponto, classes):
        self.ponto = ponto
        self.classes = list(classes)
        self.seguidas = 0

    def alimentar(self, probabilidades):
        """A categoria da janela e se ela abre um incidente."""
        categoria = self.ponto.categoria(probabilidades, self.classes)
        self.seguidas = self.seguidas + 1 if categoria != self.ponto.benigno else 0
        return categoria, self.seguidas == self.ponto.seguidas


def _sha256(caminho):
    with open(caminho, "rb") as arquivo:
        return hashlib.file_digest(arquivo, "sha256").hexdigest()


def ao_lado_do_modelo(caminho_do_modelo):
    """O JSON do ponto de operação de um modelo: o mesmo nome, com `.ponto_de_operacao.json` no lugar de `.joblib`."""
    caminho = Path(caminho_do_modelo)
    return caminho.with_name(caminho.stem + SUFIXO)


def gravar(caminho_do_modelo, ponto, **registro):
    """Grava o ponto de operação ao lado do modelo, com o SHA-256 dele e o registro de onde o ponto saiu."""
    caminho = ao_lado_do_modelo(caminho_do_modelo)
    conteudo = {
        "regra": ponto.regra, "limiar": ponto.limiar, "seguidas": ponto.seguidas, "benigno": ponto.benigno,
        "descricao": f"{REGRAS_DO_PONTO[ponto.regra]} {INCIDENTE}",
        "modelo": {"arquivo": Path(caminho_do_modelo).name, "sha256": _sha256(caminho_do_modelo)},
        "gravado_em": datetime.datetime.now(tz=datetime.UTC).astimezone().strftime("%Y-%m-%d"),
        **registro,
    }
    provisorio = caminho.with_name(caminho.name + ".parcial")
    provisorio.write_text(json.dumps(conteudo, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(provisorio, caminho)
    return caminho


def ler(caminho_do_modelo, conferir=True):
    """O ponto de operação gravado ao lado do modelo. Com `conferir`, recusa o JSON gravado para outro arquivo."""
    caminho = ao_lado_do_modelo(caminho_do_modelo)
    conteudo = json.loads(caminho.read_text(encoding="utf-8"))
    if conferir and conteudo["modelo"]["sha256"] != _sha256(caminho_do_modelo):
        raise ValueError(f"{caminho.name}: o ponto de operação é de outro modelo (o SHA-256 não confere)")
    regra = conteudo.get("regra", LIMIAR)
    if regra not in REGRAS_DO_PONTO:
        raise ValueError(f"{caminho.name}: regra desconhecida, {regra!r} (as regras são {', '.join(REGRAS_DO_PONTO)})")
    limiar = None if regra == ARGMAX else float(conteudo["limiar"])
    return PontoDeOperacao(limiar, int(conteudo["seguidas"]), conteudo.get("benigno", BENIGNO))
