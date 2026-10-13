"""Ponto de operação do classificador: a regra que o sistema aplica às probabilidades do modelo.

Uma janela é ataque quando 1 − P(Benign) ≥ t, o limiar; sendo ataque, a categoria é a de maior
probabilidade entre as categorias de ataque; senão, é Benign. Um incidente só abre com N janelas de
ataque seguidas, na ordem em que o extrator as entrega: abre na janela que completa as N, a
sequência que continua não abre outro, e a próxima sequência que chegar a N abre um novo.

O limiar e o N de um modelo ficam num JSON ao lado do `.joblib` (`ao_lado_do_modelo`), gravado por
`codigo.classificador.ponto_de_operacao`, que os escolhe numa parte de validação. O JSON leva o
SHA-256 do modelo, e `ler` recusa o JSON de outro modelo.

Este módulo só depende do numpy, para que o sistema aplique a regra sem os módulos dos experimentos.
É a mesma regra de `rodadas.aplicar_limiar` e `rodadas.alarmes`, que mediram os candidatos no teste.

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
# O limiar é inclusivo mesmo com o arredondamento do ponto flutuante: 1 − 0,4 dá 0,6000000000000001.
TOLERANCIA = 1e-12
REGRA = (
    "A janela é ataque se 1 − P(Benign) ≥ limiar, na categoria de ataque de maior probabilidade; senão, é Benign. "
    "Um incidente abre com `seguidas` janelas de ataque seguidas, na janela que completa a sequência."
)


@dataclass(frozen=True)
class PontoDeOperacao:
    """O limiar sobre 1 − P(Benign) e quantas janelas de ataque seguidas abrem um incidente."""

    limiar: float
    seguidas: int
    benigno: str = BENIGNO

    def __post_init__(self):
        if not 0 < self.limiar <= 1:
            raise ValueError(f"o limiar precisa estar entre 0 e 1, e não {self.limiar}")
        if int(self.seguidas) != self.seguidas or self.seguidas < 1:
            raise ValueError(f"as janelas seguidas precisam ser um inteiro de ao menos 1, e não {self.seguidas}")

    def categorias(self, probabilidades, classes):
        """A categoria de cada janela: uma linha de probabilidades por janela, com as colunas na ordem de `classes`."""
        proba = np.atleast_2d(np.asarray(probabilidades, dtype=float))
        classes = np.asarray(classes, dtype=object)
        if proba.ndim != 2 or proba.shape[1] != len(classes):
            raise ValueError(f"cada janela precisa de {len(classes)} probabilidades, uma por classe")
        if self.benigno not in set(classes.tolist()):
            raise ValueError(f"as classes do modelo não têm {self.benigno}")
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
        "limiar": ponto.limiar, "seguidas": ponto.seguidas, "benigno": ponto.benigno, "regra": REGRA,
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
    return PontoDeOperacao(float(conteudo["limiar"]), int(conteudo["seguidas"]), conteudo.get("benigno", BENIGNO))
