"""Exploração do MERGED_CSV do CICIoT2023.

Lê o conjunto completo, e não a amostra, e grava `experimentos/resultados/exploracao.md`:
linhas por classe e por categoria, tamanho da janela por classe, valores vazios e infinitos,
faixa de valores, colunas redundantes, linhas repetidas e o que mais destoar. Os números do
relatório alimentam o artigo.

A leitura é em fluxo, em blocos de linhas. Ficam na memória os totais e, para achar as linhas
repetidas, um hash de 64 bits por linha: cerca de 400 MB para os 45 milhões de linhas, com
pico perto de 2 GB na hora de ordenar os hashes.

Uso, a partir da raiz do repositório:
    python -m codigo.classificador.explorar
"""
import argparse
import csv
import datetime
import io
import math
import platform
import statistics
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from codigo.captura.extrator import COLUNAS
from codigo.classificador.amostrar import Leitor, listar_arquivos, relatar_arquivo
from codigo.classificador.mapeamento import (
    CATEGORIA_DO_ROTULO,
    CATEGORIAS,
    ROTULOS,
    normalizar,
)

LINHAS_POR_BLOCO = 200_000
TOLERANCIA = 1e-9
TOLERANCIA_ABSOLUTA = 1e-12
COMBINACOES_NO_RELATORIO = 15


def _vezes_number(coluna):
    return lambda bloco: bloco[coluna] * bloco["Number"]


# Coluna, a expressão que a reproduz (em Markdown) e o cálculo da expressão sobre um bloco.
RELACOES = (
    ("Variance", "`Std`²", lambda bloco: bloco["Std"] ** 2),
    ("Tot size", "`AVG`", lambda bloco: bloco["AVG"]),
    ("LLC", "`IPv`", lambda bloco: bloco["IPv"]),
    ("ARP", "1 − `IPv`", lambda bloco: 1 - bloco["IPv"]),
    ("Tot sum", "`AVG` × `Number`", _vezes_number("AVG")),
    ("ack_count", "`ack_flag_number` × `Number`", _vezes_number("ack_flag_number")),
    ("syn_count", "`syn_flag_number` × `Number`", _vezes_number("syn_flag_number")),
    ("fin_count", "`fin_flag_number` × `Number`", _vezes_number("fin_flag_number")),
    ("rst_count", "`rst_flag_number` × `Number`", _vezes_number("rst_flag_number")),
)
# Valor de `Protocol Type` e o protocolo que ele indica. O extrator dá 0 aos quadros ARP.
PROTOCOLOS = {0: "ARP (sem protocolo IP)", 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE"}
# Arquivos do `MERGED_CSV` que já vêm da fonte oficial cortados no meio de uma linha, com o SHA-256
# de cada um. Em 04/10/2026 eles e os três CSVs por ataque de `DoS-UDP_Flood` com o mesmo defeito
# foram baixados de novo da fonte oficial e vieram idênticos byte a byte aos da cópia local.
CORTADOS_NA_ORIGEM = {
    "Merged42.csv": "2f8c6871ec1358154f0581d82ff2399b2928133e3e5e7eaed5bb602873fae906",
    "Merged44.csv": "8d9392669871b7fbfe5903a8f01991e7ec47618e066b5177b9f5c10abab0a137",
    "Merged46.csv": "7d0e575cd9c460a44622ce94c77e5e64f4e745898b0aaa3b5f3383f8b48d0e92",
    "Merged47.csv": "206212048ede7d584060031baad8267d2885ed1350a8806cbc7801f8a2527a78",
    "Merged48.csv": "0be517a673535e7338c51972627d636033e846c8a02aaa6b8dd7e43a201d66da",
    "Merged49.csv": "150d7108eaa35920860545e7adb273afbe417308f69e9276a30d7349083a3f80",
    "Merged50.csv": "9d30f0c62865f15529451cb6bd13d48f66b907ca9e2842dfb2d44f291844afb7",
    "Merged51.csv": "02f796c65566e2596dd45549993c05637fddb972126fec823eed0b4e6cb0d3d1",
    "Merged52.csv": "346b8e45c721bcc216d263acfa77a4acfbe6bd7ef874b6cbc186b8d92eb89705",
}

_CODIGO = {rotulo: codigo for codigo, rotulo in enumerate(ROTULOS)}
_CATEGORIA_DO_CODIGO = np.array(
    [CATEGORIAS.index(CATEGORIA_DO_ROTULO[rotulo]) for rotulo in ROTULOS], dtype=np.uint8
)


@dataclass
class Coluna:
    """O que foi medido em uma coluna. Mínimo e máximo ignoram vazios e infinitos."""

    vazios: int = 0
    infinitos: int = 0
    vazios_com_um_quadro: int = 0
    infinitos_com_um_quadro: int = 0
    minimo: float = math.inf
    maximo: float = -math.inf
    diferentes_de_zero: int = 0
    negativos: int = 0


@dataclass
class Relacao:
    """Conferência de uma coluna contra a expressão que deveria reproduzi-la."""

    expressao: str
    conferidas: int = 0
    fora: int = 0
    maior_desvio: float = 0.0


def _zeros():
    return dict.fromkeys(ROTULOS, 0)


def _sem_erros():
    return dict.fromkeys(CATEGORIAS, 0)


@dataclass
class Duplicatas:
    """Linhas com os mesmos valores nas 39 features."""

    distintas: int = 0  # combinações distintas das 39 features
    repetidas: int = 0  # linhas cuja combinação aparece mais de uma vez
    com_outro_rotulo: int = 0  # linhas cuja combinação também aparece com outro rótulo
    com_outra_categoria: int = 0
    maior_grupo: int = 0  # quantas linhas tem a combinação mais repetida
    repetidas_por_rotulo: dict = field(default_factory=_zeros)
    com_outro_rotulo_por_rotulo: dict = field(default_factory=_zeros)
    com_outra_categoria_por_rotulo: dict = field(default_factory=_zeros)
    combinacoes: dict = field(default_factory=dict)  # rótulos com a mesma combinação -> linhas
    # Linhas de cada categoria erradas pela regra de maior acerto global, que responde em cada
    # combinação a categoria mais frequente nela. Só a soma é um mínimo: outra regra erra menos
    # numa categoria e mais em outra.
    erro_por_categoria: dict = field(default_factory=_sem_erros)
    # O mesmo para a regra que responde uma categoria em toda combinação que tenha alguma linha
    # dela e, nas outras combinações, a mais frequente. Categoria favorecida -> categoria -> linhas.
    erro_ao_favorecer: dict = field(default_factory=lambda: {nome: _sem_erros() for nome in CATEGORIAS})


@dataclass
class Exploracao:
    """Tudo o que a exploração mediu."""

    arquivos: list = field(default_factory=list)  # o registro de cada arquivo, como o Leitor o entrega
    por_arquivo: list = field(default_factory=list)  # para cada arquivo, rótulo -> linhas
    por_rotulo: dict = field(default_factory=_zeros)
    grafias: dict = field(default_factory=lambda: {rotulo: [] for rotulo in ROTULOS})
    janela: dict = field(default_factory=lambda: {rotulo: {} for rotulo in ROTULOS})  # rótulo -> Number -> linhas
    colunas: dict = field(default_factory=lambda: {coluna: Coluna() for coluna in COLUNAS})
    identicas: list = field(default_factory=list)  # pares de colunas iguais em todas as linhas
    relacoes: dict = field(default_factory=lambda: {coluna: Relacao(texto) for coluna, texto, _ in RELACOES})
    fora_de_ordem: int = 0  # linhas que não respeitam Min <= AVG <= Max
    protocolos: dict = field(default_factory=dict)  # valor de Protocol Type -> linhas
    duplicatas: Duplicatas = field(default_factory=Duplicatas)

    @property
    def linhas(self):
        return sum(self.por_rotulo.values())

    @property
    def por_categoria(self):
        return {
            nome: sum(n for rotulo, n in self.por_rotulo.items() if CATEGORIA_DO_ROTULO[rotulo] == nome)
            for nome in CATEGORIAS
        }

    @property
    def constantes(self):
        """Colunas com um único valor em todas as linhas."""
        return [
            nome for nome, c in self.colunas.items()
            if self.linhas and c.minimo == c.maximo and not c.vazios and not c.infinitos
        ]


def _ler_bloco(nome, textos):
    """Converte as linhas de texto num quadro de 39 colunas de ponto flutuante."""
    try:
        return pd.read_csv(
            io.BytesIO(b"\n".join(textos)),
            header=None,
            names=list(COLUNAS),
            dtype=np.float64,
            # O conversor padrão do pandas erra o último dígito de alguns valores.
            float_precision="round_trip",
            quoting=csv.QUOTE_NONE,
        )
    except ValueError as erro:
        raise ValueError(f"{nome}: valor que não é número ({erro})") from None


def _inteiro_se_der(valor):
    return int(valor) if float(valor).is_integer() else float(valor)


def _somar_bloco(exploracao, pares, quadro, codigos):
    """Soma à exploração o que um bloco de linhas traz. Devolve os pares de colunas ainda iguais."""
    bloco = {coluna: quadro[coluna].to_numpy() for coluna in COLUNAS}
    number = bloco["Number"]
    um_quadro = number == 1

    for coluna, valores in bloco.items():
        medida = exploracao.colunas[coluna]
        finito = np.isfinite(valores)
        if not finito.all():
            vazio = np.isnan(valores)
            infinito = ~finito & ~vazio
            medida.vazios += int(vazio.sum())
            medida.infinitos += int(infinito.sum())
            medida.vazios_com_um_quadro += int((vazio & um_quadro).sum())
            medida.infinitos_com_um_quadro += int((infinito & um_quadro).sum())
            medida.diferentes_de_zero -= int(vazio.sum())
            finitos = valores[finito]
        else:
            finitos = valores
        medida.diferentes_de_zero += int(np.count_nonzero(valores))
        if len(finitos):
            medida.minimo = min(medida.minimo, float(finitos.min()))
            medida.maximo = max(medida.maximo, float(finitos.max()))
            if medida.minimo < 0:
                medida.negativos += int((finitos < 0).sum())

    pares = [(a, b) for a, b in pares if np.array_equal(bloco[a], bloco[b], equal_nan=True)]

    for coluna, _, calculo in RELACOES:
        relacao = exploracao.relacoes[coluna]
        relacao.conferidas += len(quadro)
        medido, esperado = bloco[coluna], calculo(bloco)
        if np.array_equal(medido, esperado):
            continue
        with np.errstate(invalid="ignore", divide="ignore"):
            diferenca = np.abs(medido - esperado)
            desvio = diferenca / np.maximum(np.abs(medido), np.abs(esperado))
        # Vazio só é igual a vazio, e infinito só é igual a infinito.
        vale = (
            (medido == esperado)
            | (np.isnan(medido) & np.isnan(esperado))
            | (desvio <= TOLERANCIA)
            | (diferenca <= TOLERANCIA_ABSOLUTA)
        )
        relacao.fora += int((~vale).sum())
        medidos = desvio[np.isfinite(desvio)]
        if len(medidos):
            relacao.maior_desvio = max(relacao.maior_desvio, float(medidos.max()))

    minimo, media, maximo = bloco["Min"], bloco["AVG"], bloco["Max"]
    folga = TOLERANCIA * np.abs(media)
    exploracao.fora_de_ordem += int(((minimo - media > folga) | (media - maximo > folga)).sum())

    valores, vezes = np.unique(bloco["Protocol Type"], return_counts=True)
    for valor, quantas in zip(valores.tolist(), vezes.tolist()):
        if math.isfinite(valor):
            chave = _inteiro_se_der(valor)
            exploracao.protocolos[chave] = exploracao.protocolos.get(chave, 0) + quantas

    por_janela = pd.Series(number).groupby(codigos).value_counts()
    for (codigo, quadros), quantas in por_janela.items():
        janela = exploracao.janela[ROTULOS[codigo]]
        chave = _inteiro_se_der(quadros)
        janela[chave] = janela.get(chave, 0) + int(quantas)
    return pares


def _por_rotulo(codigos, marcadas):
    """Quantas das linhas marcadas há em cada rótulo."""
    contagem = np.bincount(codigos[marcadas], minlength=len(ROTULOS))
    return dict(zip(ROTULOS, contagem.tolist()))


def _contar_repetidas(hashes, codigos):
    """Agrupa as linhas pelo hash das 39 features e conta as repetições e os rótulos de cada grupo."""
    total = len(hashes)
    if total == 0:
        return Duplicatas()
    ordem = np.argsort(hashes, kind="stable")
    ordenados = hashes[ordem]
    codigos = codigos[ordem]
    del ordem
    inicio = np.flatnonzero(np.concatenate(([True], ordenados[1:] != ordenados[:-1])))
    del ordenados
    tamanho = np.diff(np.append(inicio, total))
    # Um bit por rótulo: o "ou" dos bits de um grupo diz quais rótulos ele reúne.
    rotulos_do_grupo = np.bitwise_or.reduceat(np.left_shift(np.uint64(1), codigos.astype(np.uint64)), inicio)
    categorias_do_grupo = np.bitwise_or.reduceat(
        np.left_shift(np.uint8(1), _CATEGORIA_DO_CODIGO[codigos]), inicio
    )
    repetido = tamanho > 1
    varios_rotulos = rotulos_do_grupo & (rotulos_do_grupo - np.uint64(1)) != 0
    varias_categorias = categorias_do_grupo & (categorias_do_grupo - np.uint8(1)) != 0

    mascaras, posicao = np.unique(rotulos_do_grupo[varios_rotulos], return_inverse=True)
    linhas = np.bincount(posicao, weights=tamanho[varios_rotulos], minlength=len(mascaras))
    combinacoes = {
        tuple(rotulo for codigo, rotulo in enumerate(ROTULOS) if int(mascara) >> codigo & 1): int(quantas)
        for mascara, quantas in sorted(zip(mascaras.tolist(), linhas.tolist()), key=lambda par: -par[1])
    }

    # Quem só vê as 39 features dá uma resposta por combinação. A que mais acerta no conjunto é a
    # categoria mais frequente da combinação; as linhas das outras categorias são o erro que sobra.
    em_conflito = np.repeat(varias_categorias, tamanho)
    grupo = np.repeat(np.cumsum(varias_categorias) - 1, tamanho)[em_conflito]
    categoria = _CATEGORIA_DO_CODIGO[codigos[em_conflito]]
    por_grupo = np.bincount(
        grupo * len(CATEGORIAS) + categoria, minlength=int(varias_categorias.sum()) * len(CATEGORIAS)
    ).reshape(-1, len(CATEGORIAS))
    vencedora = por_grupo.argmax(axis=1)  # no empate, a primeira na ordem de CATEGORIAS
    da_vencedora = por_grupo.max(axis=1)

    def por_categoria(categorias, linhas):
        return np.bincount(categorias, weights=linhas, minlength=len(CATEGORIAS)).astype(np.int64)

    erro = por_grupo.sum(axis=0) - por_categoria(vencedora, da_vencedora)
    erro_ao_favorecer = {}
    for indice, nome in enumerate(CATEGORIAS):
        # Mudam de resposta as combinações que têm a categoria sem que ela seja a mais frequente:
        # as linhas dela passam a acerto, e as da que era a mais frequente passam a erro.
        mudam = (por_grupo[:, indice] > 0) & (vencedora != indice)
        favorecendo = erro + por_categoria(vencedora[mudam], da_vencedora[mudam])
        favorecendo[indice] -= por_grupo[mudam, indice].sum()
        erro_ao_favorecer[nome] = dict(zip(CATEGORIAS, favorecendo.tolist()))
    return Duplicatas(
        distintas=len(inicio),
        repetidas=int(tamanho[repetido].sum()),
        com_outro_rotulo=int(tamanho[varios_rotulos].sum()),
        com_outra_categoria=int(tamanho[varias_categorias].sum()),
        maior_grupo=int(tamanho.max()),
        repetidas_por_rotulo=_por_rotulo(codigos, np.repeat(repetido, tamanho)),
        com_outro_rotulo_por_rotulo=_por_rotulo(codigos, np.repeat(varios_rotulos, tamanho)),
        com_outra_categoria_por_rotulo=_por_rotulo(codigos, em_conflito),
        combinacoes=combinacoes,
        erro_por_categoria=dict(zip(CATEGORIAS, erro.tolist())),
        erro_ao_favorecer=erro_ao_favorecer,
    )


def explorar(arquivos, linhas_por_bloco=LINHAS_POR_BLOCO, ao_terminar_arquivo=None):
    """Percorre os arquivos do MERGED_CSV e devolve a Exploracao."""
    exploracao = Exploracao()
    pares = [(a, b) for i, a in enumerate(COLUNAS) for b in COLUNAS[i + 1:]]
    hashes, todos_os_codigos = [], []

    def fechar_bloco(nome, textos, codigos):
        quadro = _ler_bloco(nome, textos)
        codigos = np.array(codigos, dtype=np.uint8)
        hashes.append(pd.util.hash_pandas_object(quadro, index=False).to_numpy())
        todos_os_codigos.append(codigos)
        return _somar_bloco(exploracao, pares, quadro, codigos)

    for caminho in arquivos:
        leitor = Leitor(caminho)
        textos, codigos = [], []
        no_arquivo = Counter()
        for features, rotulo in leitor:
            textos.append(features)
            codigos.append(_CODIGO[rotulo])
            if len(textos) == linhas_por_bloco:
                no_arquivo.update(codigos)
                pares = fechar_bloco(leitor.caminho.name, textos, codigos)
                textos, codigos = [], []
        if textos:
            no_arquivo.update(codigos)
            pares = fechar_bloco(leitor.caminho.name, textos, codigos)
        exploracao.arquivos.append(leitor.registro)
        exploracao.por_arquivo.append({ROTULOS[codigo]: n for codigo, n in sorted(no_arquivo.items())})
        for codigo, quantas in no_arquivo.items():
            exploracao.por_rotulo[ROTULOS[codigo]] += quantas
        for grafia, rotulo in leitor.grafias.items():
            if grafia not in exploracao.grafias[rotulo]:
                exploracao.grafias[rotulo] = sorted([*exploracao.grafias[rotulo], grafia])
        if ao_terminar_arquivo is not None:
            ao_terminar_arquivo(leitor.registro)

    exploracao.identicas = pares if exploracao.linhas else []
    exploracao.janela = {
        rotulo: dict(sorted(janela.items(), reverse=True)) for rotulo, janela in exploracao.janela.items()
    }
    exploracao.protocolos = dict(sorted(exploracao.protocolos.items()))
    if hashes:
        exploracao.duplicatas = _contar_repetidas(np.concatenate(hashes), np.concatenate(todos_os_codigos))
    return exploracao


def _contar_linhas(caminho):
    """Linhas de dados de um CSV por ataque, sem rótulo, e se a última ficou incompleta."""
    quebras, resto = 0, b""
    with open(caminho, "rb") as arquivo:
        while bloco := arquivo.read(1 << 20):
            quebras += bloco.count(b"\n")
            corte = bloco.rfind(b"\n")
            resto = bloco[corte + 1:] if corte >= 0 else resto + bloco
    linhas = max(quebras - 1, 0)  # a primeira linha é o cabeçalho
    if quebras == 0 or not resto.strip():
        return linhas, False
    completa = resto.count(b",") == len(COLUNAS) - 1
    return linhas + completa, not completa


def contar_por_ataque(pasta):
    """Linhas dos CSVs por ataque, em que a classe é o nome da pasta.

    Devolve, para cada rótulo com pasta, a quantidade de arquivos e de linhas e os arquivos
    que terminam no meio de uma linha. Pastas cujo nome não é uma classe são ignoradas.
    """
    pasta = Path(pasta)
    contagem = {}
    for subpasta in sorted(pasta.iterdir()) if pasta.is_dir() else []:
        try:
            rotulo = normalizar(subpasta.name)
        except ValueError:
            continue
        registro = contagem.setdefault(rotulo, {"arquivos": 0, "linhas": 0, "incompletos": []})
        for arquivo in sorted(subpasta.glob("*.csv")):
            linhas, incompleto = _contar_linhas(arquivo)
            registro["arquivos"] += 1
            registro["linhas"] += linhas
            if incompleto:
                registro["incompletos"].append(arquivo.name)
    return {rotulo: contagem[rotulo] for rotulo in ROTULOS if rotulo in contagem}


def _milhar(numero):
    return f"{numero:,}".replace(",", ".")


def _pct(parte, total, casas=2):
    return f"{100 * parte / total if total else 0:.{casas}f}%".replace(".", ",")


def _decimal(valor, casas=1):
    """Número com separador de milhar e vírgula decimal: 1.754.940,5."""
    return f"{valor:,.{casas}f}".translate(str.maketrans(",.", ".,"))


def _numero(valor):
    if not math.isfinite(valor):
        return "sem valor"
    if float(valor).is_integer() and abs(valor) < 1e15:
        return _milhar(int(valor))
    if abs(valor) >= 1000:
        return _decimal(valor)
    if abs(valor) < 1e-4:
        return f"{valor:.1e}".replace(".", ",")
    return f"{valor:.6g}".replace(".", ",")


def _desvio(valor):
    return "0" if valor == 0 else f"{valor:.1e}".replace(".", ",")


def _plural(quantidade, singular, plural):
    return f"{_milhar(quantidade)} {singular if quantidade == 1 else plural}"


def _cerca_de(quantidade, singular, plural):
    """Quantidade arredondada para leitura: 2,0 milhões de linhas, 310 mil linhas, 47 linhas."""
    if quantidade >= 999_500:
        milhoes = round(quantidade / 1_000_000, 1)
        return f"{_decimal(milhoes)} {'milhão' if milhoes < 2 else 'milhões'} de {plural}"
    if quantidade >= 1000:
        return f"{round(quantidade / 1000)} mil {plural}"
    return _plural(round(quantidade), singular, plural)


def _cortados_na_origem(e):
    """Se todos os arquivos cortados são, byte a byte, os que já vêm cortados da fonte oficial."""
    cortados = [a for a in e.arquivos if a["final_incompleto"]]
    return bool(cortados) and all(CORTADOS_NA_ORIGEM.get(a["nome"]) == a["sha256"] for a in cortados)


def _e(itens):
    """Enumeração em português: "a", "a e b", "a, b e c"."""
    itens = list(itens)
    return " e ".join(filter(None, [", ".join(itens[:-1]), *itens[-1:]]))


def _nomes(colunas):
    return _e(f"`{coluna}`" for coluna in colunas)


def _maior_e_menor(e):
    """A classe com mais linhas e a com menos, entre as presentes."""
    presentes = sorted((rotulo for rotulo in ROTULOS if e.por_rotulo[rotulo]), key=lambda r: -e.por_rotulo[r])
    return (presentes[0], presentes[-1]) if presentes else None


def _classes_por_janela(e):
    """Tamanho da janela completa (o maior Number da classe) -> classes, da maior janela para a menor."""
    tamanhos = {}
    for rotulo in ROTULOS:
        if e.janela[rotulo]:
            tamanhos.setdefault(max(e.janela[rotulo]), []).append(rotulo)
    return dict(sorted(tamanhos.items(), reverse=True))


def _resumo(e):
    total = e.linhas
    cortados = sum(1 for a in e.arquivos if a["final_incompleto"])
    texto = [
        "## Resumo",
        "",
        (
            f"- {_plural(total, 'linha', 'linhas')} em {_plural(len(e.arquivos), 'arquivo', 'arquivos')}, com "
            "39 features e a coluna `Label`."
        ),
        (
            f"- DDoS e DoS somam {_pct(e.por_categoria['DDoS'] + e.por_categoria['DoS'], total)} das linhas, e o "
            f"tráfego benigno é {_pct(e.por_categoria['Benign'], total)}."
        ),
    ]
    extremos = _maior_e_menor(e)
    if extremos:
        maior, menor = extremos
        texto.append(
            f"- A maior classe (`{maior}`) tem {_decimal(e.por_rotulo[maior] / e.por_rotulo[menor])} vezes as "
            f"linhas da menor (`{menor}`)."
        )
    janelas = [
        f"de {_numero(tamanho)} quadros em {_plural(len(rotulos), 'classe', 'classes')}" if posicao == 0
        else f"de {_numero(tamanho)} em {len(rotulos)}"
        for posicao, (tamanho, rotulos) in enumerate(_classes_por_janela(e).items())
    ]
    if janelas:
        texto.append(f"- A janela completa é {_e(janelas)}.")
    vazios = [nome for nome, c in e.colunas.items() if c.vazios]
    infinitos = [nome for nome, c in e.colunas.items() if c.infinitos]
    if vazios or infinitos:
        partes = [f"vazios em {_nomes(vazios)}"] if vazios else []
        partes += [f"infinitos em {_nomes(infinitos)}"] if infinitos else []
        texto.append(f"- Há valores {_e(partes)}.")
    else:
        texto.append("- Não há valores vazios nem infinitos.")
    exatas = [coluna for coluna, r in e.relacoes.items() if r.conferidas and not r.fora]
    if exatas:
        texto.append(
            f"- {len(exatas)} das {len(COLUNAS)} colunas podem ser recalculadas a partir das outras em todas as "
            f"linhas: {_nomes(exatas)}."
        )
    texto.append(
        f"- {_pct(e.duplicatas.repetidas, total)} das linhas repetem as 39 features de outra linha, e "
        f"{_pct(e.duplicatas.com_outra_categoria, total)} têm uma combinação de valores que também aparece em "
        "outra categoria."
    )
    erro = sum(e.duplicatas.erro_por_categoria.values())
    if erro:
        texto.append(
            f"- Por causa dessas combinações, o acerto em 8 categorias não passa de {_pct(total - erro, total)} "
            "para quem vê só as 39 features e é avaliado no conjunto completo, na proporção natural das "
            "classes. Esse valor não é uma propriedade das 39 features: muda com o tamanho e com a mistura "
            "de classes do conjunto avaliado, e um modelo avaliado numa amostra pode passar dele de forma "
            "legítima (seção 8)."
        )
    if cortados:
        verbo = "termina" if cortados == 1 else "terminam"
        if _cortados_na_origem(e):
            motivo = "truncado já na fonte oficial" if cortados == 1 else "truncados já na fonte oficial"
        else:
            motivo = "sinal de arquivo truncado"
        texto.append(f"- {_plural(cortados, 'arquivo', 'arquivos')} {verbo} no meio de uma linha, {motivo}.")
    return texto


def _secao_arquivos(e):
    linhas_por_arquivo = [a["linhas"] for a in e.arquivos]
    texto = [
        "## 1. Arquivos",
        "",
        (
            f"{_plural(len(e.arquivos), 'arquivo lido', 'arquivos lidos')}, com "
            f"{_plural(e.linhas, 'linha', 'linhas')} de dados e {_milhar(sum(a['bytes'] for a in e.arquivos))} "
            "bytes no total."
        ),
    ]
    if linhas_por_arquivo:
        texto.append(
            f"O menor arquivo tem {_milhar(min(linhas_por_arquivo))} linhas, o maior tem "
            f"{_milhar(max(linhas_por_arquivo))} e a mediana é de "
            f"{_milhar(round(statistics.median(linhas_por_arquivo)))}."
        )
    cortados = [a for a in e.arquivos if a["final_incompleto"]]
    if cortados:
        verbo = "termina" if len(cortados) == 1 else "terminam"
        if _cortados_na_origem(e):
            origem = (
                "As linhas que viriam depois do corte não fazem parte deste relatório. O corte está na "
                "origem, e não na cópia local: baixados de novo da fonte oficial em 04/10/2026, os arquivos "
                "do `MERGED_CSV` com esse defeito e os três CSVs por ataque de `DoS-UDP_Flood` que também "
                "terminam no meio de uma linha vieram idênticos byte a byte."
            )
        else:
            origem = (
                "O corte indica arquivo truncado, na origem ou na cópia local, e as linhas que viriam depois "
                "dele não fazem parte deste relatório."
            )
        texto += [
            "",
            (
                f"{_plural(len(cortados), 'arquivo', 'arquivos')} {verbo} no meio de uma linha, sem a quebra "
                f"de linha final. A linha incompleta de cada um ficou fora de todas as contagens. {origem}"
            ),
            "",
            "| Arquivo | Linhas completas | Bytes |",
            "|---|---|---|",
            *(f"| `{a['nome']}` | {_milhar(a['linhas'])} | {_milhar(a['bytes'])} |" for a in cortados),
        ]
    else:
        texto += ["", "Todos os arquivos terminam em linha completa."]
    return texto


def _secao_categorias(e):
    total = e.linhas
    texto = [
        "## 2. Linhas por categoria",
        "",
        "| Categoria | Classes | Linhas | % do total | Menor % em um arquivo | Maior % em um arquivo |",
        "|---|---|---|---|---|---|",
    ]
    for nome, linhas in e.por_categoria.items():
        classes = sum(1 for rotulo in ROTULOS if CATEGORIA_DO_ROTULO[rotulo] == nome)
        fatias = [
            sum(n for rotulo, n in contagem.items() if CATEGORIA_DO_ROTULO[rotulo] == nome) / sum(contagem.values())
            for contagem in e.por_arquivo if contagem
        ]
        faixa = f"{_pct(min(fatias), 1)} | {_pct(max(fatias), 1)}" if fatias else "sem valor | sem valor"
        texto.append(f"| {nome} | {classes} | {_milhar(linhas)} | {_pct(linhas, total)} | {faixa} |")
    ataques = e.por_categoria["DDoS"] + e.por_categoria["DoS"]
    texto += [
        "",
        (
            f"DDoS e DoS somam {_pct(ataques, total)} das linhas. O tráfego benigno é "
            f"{_pct(e.por_categoria['Benign'], total)}, e as outras cinco categorias de ataque somam "
            f"{_pct(total - ataques - e.por_categoria['Benign'], total)}."
        ),
        "As duas últimas colunas mostram quanto a proporção muda de um arquivo para outro.",
    ]
    return texto


def _secao_classes(e):
    total = e.linhas
    presentes = sorted((rotulo for rotulo in ROTULOS if e.por_rotulo[rotulo]), key=lambda r: -e.por_rotulo[r])
    texto = ["## 3. Linhas por classe", "", "| Classe | Categoria | Linhas | % do total |", "|---|---|---|---|"]
    texto += [
        f"| `{rotulo}` | {CATEGORIA_DO_ROTULO[rotulo]} | {_milhar(e.por_rotulo[rotulo])} | "
        f"{_pct(e.por_rotulo[rotulo], total, casas=4)} |"
        for rotulo in presentes
    ]
    if presentes:
        maior, menor = _maior_e_menor(e)
        razao = _decimal(e.por_rotulo[maior] / e.por_rotulo[menor])
        texto += [
            "",
            (
                f"A razão entre a maior classe (`{maior}`, {_plural(e.por_rotulo[maior], 'linha', 'linhas')}) "
                f"e a menor (`{menor}`, {_plural(e.por_rotulo[menor], 'linha', 'linhas')}) é de {razao} para 1."
            ),
        ]
    ausentes = [rotulo for rotulo in ROTULOS if not e.por_rotulo[rotulo]]
    if ausentes:
        texto += ["", f"{len(ausentes)} das {len(ROTULOS)} classes não têm nenhuma linha: {_nomes(ausentes)}."]
    else:
        texto += ["", f"As {len(ROTULOS)} classes estão presentes."]
    return texto


def _secao_grafias(e):
    presentes = [rotulo for rotulo in ROTULOS if e.grafias[rotulo]]
    diferentes = [(grafia, rotulo) for rotulo in presentes for grafia in e.grafias[rotulo] if grafia != rotulo]
    outro_nome = [(grafia, rotulo) for grafia, rotulo in diferentes if grafia.casefold() != rotulo.casefold()]
    classes = len({rotulo for _, rotulo in diferentes})
    frase = (
        f"Nos arquivos, {classes} das {_plural(len(presentes), 'classe presente', 'classes presentes')} vêm "
        "com grafia diferente da canônica, que é a do dicionário dos autores do dataset."
    )
    if outro_nome:
        trocas = _e(f"`{grafia}` no lugar de `{rotulo}`" for grafia, rotulo in outro_nome)
        frase += (
            f" Na maioria só muda a caixa das letras. O nome é outro em: {trocas}. Passar o dicionário dos "
            "autores para maiúsculas, portanto, não basta para casar os rótulos."
        )
    elif diferentes:
        frase += " Em todas só muda a caixa das letras."
    return ["### Grafia dos rótulos", "", frase]


def _secao_janela(e):
    texto = [
        "## 4. Tamanho da janela por classe",
        "",
        "A coluna `Number` traz a quantidade de quadros agregados em cada linha. O maior valor de cada",
        "classe é o tamanho da janela completa, e os valores menores são janelas incompletas.",
        "",
        "| Classe | Categoria | Maior `Number` | Linhas com a janela completa | % da classe | Menor `Number` |",
        "|---|---|---|---|---|---|",
    ]
    tamanhos = _classes_por_janela(e)
    for rotulo in ROTULOS:
        janela = e.janela[rotulo]
        if not janela:
            continue
        maior = max(janela)
        texto.append(
            f"| `{rotulo}` | {CATEGORIA_DO_ROTULO[rotulo]} | {_numero(maior)} | {_milhar(janela[maior])} | "
            f"{_pct(janela[maior], e.por_rotulo[rotulo])} | {_numero(min(janela))} |"
        )
    texto.append("")
    for tamanho, rotulos in tamanhos.items():
        categorias = [nome for nome in CATEGORIAS if any(CATEGORIA_DO_ROTULO[r] == nome for r in rotulos)]
        completas = sum(e.janela[rotulo][tamanho] for rotulo in rotulos)
        linhas = sum(e.por_rotulo[rotulo] for rotulo in rotulos)
        texto.append(
            f"- Janela de {_numero(tamanho)}: {_plural(len(rotulos), 'classe', 'classes')}, em {_e(categorias)}. "
            f"{_pct(completas, linhas)} das linhas dessas classes têm a janela completa."
        )
    if len(tamanhos) == 2:
        menor, maior = sorted(tamanhos)
        grandes = tamanhos[maior]
        acima = {r: sum(n for quadros, n in e.janela[r].items() if quadros > menor) for r in ROTULOS}
        acima_nas_grandes = sum(acima[r] for r in grandes)
        linhas_das_grandes = sum(e.por_rotulo[r] for r in grandes)
        certas = acima_nas_grandes + (e.linhas - linhas_das_grandes) - (sum(acima.values()) - acima_nas_grandes)
        texto += [
            "",
            (
                f"Nenhuma linha das classes de janela {_numero(menor)} tem `Number` acima de {_numero(menor)}. "
                f"Nas classes de janela {_numero(maior)}, {_milhar(linhas_das_grandes - acima_nas_grandes)} "
                f"linhas ({_pct(linhas_das_grandes - acima_nas_grandes, linhas_das_grandes, casas=4)}) têm "
                f"`Number` de até {_numero(menor)}. A regra `Number` > {_numero(menor)} separa sozinha os dois "
                f"grupos de classes em {_pct(certas, e.linhas, casas=4)} das linhas do conjunto."
            ),
        ]
    return texto


def _secao_vazios(e):
    com_falta = {nome: c for nome, c in e.colunas.items() if c.vazios or c.infinitos}
    texto = ["## 5. Valores vazios e infinitos", ""]
    if not com_falta:
        return [*texto, "Nenhuma coluna tem valor vazio ou infinito."]
    texto += ["| Coluna | Vazios | Infinitos | Em linhas com `Number` = 1 |", "|---|---|---|---|"]
    texto += [
        f"| `{nome}` | {_milhar(c.vazios)} | {_milhar(c.infinitos)} | "
        f"{_milhar(c.vazios_com_um_quadro + c.infinitos_com_um_quadro)} |"
        for nome, c in com_falta.items()
    ]
    um_quadro = sum(janela.get(1, 0) for janela in e.janela.values())
    texto += [
        "",
        (
            f"As outras {len(e.colunas) - len(com_falta)} colunas não têm valor vazio nem infinito. O conjunto "
            f"tem {_plural(um_quadro, 'linha', 'linhas')} com `Number` = 1."
        ),
        "Uma janela com um só quadro não tem variância amostral nem duração, o que deixa `Std` e `Variance`",
        "vazios e `Rate` infinito. `Rate` também fica infinito quando todos os quadros da janela têm o mesmo",
        "instante.",
    ]
    return texto


def _secao_faixa(e):
    texto = [
        "## 6. Faixa de valores por coluna",
        "",
        "Mínimo e máximo ignoram valores vazios e infinitos.",
        "",
        "| Coluna | Mínimo | Máximo | Linhas diferentes de zero | % das linhas |",
        "|---|---|---|---|---|",
    ]
    texto += [
        f"| `{nome}` | {_numero(c.minimo)} | {_numero(c.maximo)} | {_milhar(c.diferentes_de_zero)} | "
        f"{_pct(c.diferentes_de_zero, e.linhas, casas=4)} |"
        for nome, c in e.colunas.items()
    ]
    constantes = e.constantes
    texto.append("")
    if constantes:
        texto.append(f"Colunas constantes, com o mesmo valor em todas as linhas: {_nomes(constantes)}.")
    else:
        texto.append("Nenhuma coluna é constante.")
    negativos = {nome: c.negativos for nome, c in e.colunas.items() if c.negativos}
    if len(negativos) == 1:
        (nome, linhas), = negativos.items()
        texto.append(f"Só `{nome}` tem valores negativos, em {_plural(linhas, 'linha', 'linhas')}.")
    elif negativos:
        partes = (f"`{nome}` ({_plural(linhas, 'linha', 'linhas')})" for nome, linhas in negativos.items())
        texto.append(f"Têm valores negativos: {_e(partes)}.")
    else:
        texto.append("Nenhuma coluna tem valor negativo.")
    if e.fora_de_ordem:
        fora = _plural(e.fora_de_ordem, "linha não respeita", "linhas não respeitam")
        texto.append(f"{fora} `Min` ≤ `AVG` ≤ `Max`.")
    else:
        texto.append("Todas as linhas respeitam `Min` ≤ `AVG` ≤ `Max`.")
    return texto


def _secao_redundancias(e):
    constantes = set(e.constantes)
    pares = [(a, b) for a, b in e.identicas if a not in constantes and b not in constantes]
    texto = ["## 7. Colunas redundantes", ""]
    if pares:
        texto.append(
            "Pares de colunas com valores idênticos em todas as linhas, procurados entre todos os pares "
            f"das 39 colunas: {'; '.join(f'`{a}` e `{b}`' for a, b in pares)}."
        )
    else:
        texto.append("Nenhum par de colunas não constantes tem valores idênticos em todas as linhas.")
    texto += [
        "",
        "Relações conferidas linha a linha:",
        "",
        "| Coluna | Igual a | Linhas conferidas | Linhas fora da tolerância | Maior desvio relativo |",
        "|---|---|---|---|---|",
    ]
    texto += [
        f"| `{coluna}` | {r.expressao} | {_milhar(r.conferidas)} | {_milhar(r.fora)} | {_desvio(r.maior_desvio)} |"
        for coluna, r in e.relacoes.items()
    ]
    exatas = [coluna for coluna, r in e.relacoes.items() if r.conferidas and not r.fora]
    texto += [
        "",
        (
            f"A tolerância é relativa, de {TOLERANCIA:g}, com piso absoluto de {TOLERANCIA_ABSOLUTA:g}. Vazio só "
            "é igual a vazio, e infinito só é igual a infinito."
        ),
    ]
    if exatas:
        texto.append(
            f"{_plural(len(exatas), 'coluna pode', 'colunas podem')} ser recalculadas a partir das outras em "
            f"todas as linhas: {_nomes(exatas)}."
        )
    return texto


def _limites_do_acerto(e):
    """O que a tabela de erros por categoria permite afirmar, e o que não permite."""
    d, total, linhas = e.duplicatas, e.linhas, e.por_categoria
    teto = _pct(total - sum(d.erro_por_categoria.values()), total)
    # O exemplo de outra regra favorece a categoria de menor acerto na tabela. A seção só existe
    # quando alguma combinação reúne categorias diferentes, e então alguma categoria tem erro.
    com_erro = [nome for nome in CATEGORIAS if d.erro_por_categoria[nome]]
    favorecida = max(com_erro, key=lambda nome: d.erro_por_categoria[nome] / linhas[nome])
    erros = d.erro_ao_favorecer[favorecida]
    # Das outras categorias, a que mais perde linhas quando a favorecida passa a ser a resposta.
    perdedora = max(
        (nome for nome in CATEGORIAS if nome != favorecida),
        key=lambda nome: erros[nome] - d.erro_por_categoria[nome],
    )
    return [
        (
            f"Só a linha Total é um limite superior: nenhuma regra que dependa só das 39 features acerta mais "
            f"que {teto} das linhas do conjunto completo. Os valores por categoria não são limites. São o "
            "recall de cada categoria na regra de maior acerto global, e outra regra os redistribui. Na regra "
            f"que responde {favorecida} em toda combinação que tenha alguma linha de {favorecida}, o acerto de "
            f"{favorecida} é de {_pct(linhas[favorecida] - erros[favorecida], linhas[favorecida])}, o de "
            f"{perdedora} é de {_pct(linhas[perdedora] - erros[perdedora], linhas[perdedora])} e o acerto "
            f"global é de {_pct(total - sum(erros.values()), total)}."
        ),
        "",
        (
            "O limite da linha Total vale para a avaliação no conjunto completo, na proporção natural das "
            "classes, e conta só a coincidência exata dos 39 valores. Não é uma propriedade das 39 features em "
            "si: muda com o tamanho e com a mistura de classes do conjunto avaliado. Um modelo avaliado numa "
            f"amostra pode passar de {teto} de forma legítima, e o limite de um conjunto de teste precisa ser "
            "calculado nesse conjunto."
        ),
    ]


def _secao_repetidas(e):
    d, total = e.duplicatas, e.linhas
    texto = [
        "## 8. Linhas repetidas",
        "",
        "Duas linhas são repetidas quando têm os mesmos valores nas 39 features. O rótulo não entra na",
        "comparação.",
        "",
        (
            f"- As {_plural(total, 'linha forma', 'linhas formam')} "
            f"{_plural(d.distintas, 'combinação distinta', 'combinações distintas')} das 39 features."
        ),
        (
            f"- {_plural(d.repetidas, 'linha', 'linhas')} ({_pct(d.repetidas, total)}) têm uma combinação que "
            "aparece mais de uma vez. A combinação mais repetida aparece em "
            f"{_plural(d.maior_grupo, 'linha', 'linhas')}."
        ),
        (
            f"- {_plural(d.com_outro_rotulo, 'linha', 'linhas')} ({_pct(d.com_outro_rotulo, total)}) têm uma "
            "combinação que também aparece com outro rótulo."
        ),
        (
            f"- {_plural(d.com_outra_categoria, 'linha', 'linhas')} ({_pct(d.com_outra_categoria, total)}) têm "
            "uma combinação que também aparece com outra categoria."
        ),
    ]
    presentes = [rotulo for rotulo in ROTULOS if e.por_rotulo[rotulo]]
    if d.repetidas:
        texto += [
            "",
            "| Classe | Categoria | Linhas | Repetidas | % da classe | Com outro rótulo | Com outra categoria |",
            "|---|---|---|---|---|---|---|",
        ]
        texto += [
            f"| `{rotulo}` | {CATEGORIA_DO_ROTULO[rotulo]} | {_milhar(e.por_rotulo[rotulo])} | "
            f"{_milhar(d.repetidas_por_rotulo[rotulo])} | "
            f"{_pct(d.repetidas_por_rotulo[rotulo], e.por_rotulo[rotulo])} | "
            f"{_milhar(d.com_outro_rotulo_por_rotulo[rotulo])} | "
            f"{_milhar(d.com_outra_categoria_por_rotulo[rotulo])} |"
            for rotulo in presentes
        ]
    if d.com_outra_categoria:
        erro = sum(d.erro_por_categoria.values())
        texto += [
            "",
            (
                "Um classificador que veja só as 39 features dá a mesma resposta para todas as linhas de uma "
                "combinação. A regra de maior acerto global responde, em cada combinação, a categoria mais "
                "frequente nela, e as linhas das outras categorias são erro. No empate vale a primeira "
                f"categoria na ordem da tabela, e por isso {CATEGORIAS[0]} tem preferência sobre {CATEGORIAS[1]}. "
                "A tabela dá os erros e o acerto de cada categoria nessa regra, medidos no conjunto completo."
            ),
            "",
            "| Categoria | Linhas | Erros na regra de maior acerto global | Acerto nessa regra |",
            "|---|---|---|---|",
        ]
        texto += [
            f"| {nome} | {_milhar(linhas)} | {_milhar(d.erro_por_categoria[nome])} | "
            f"{_pct(linhas - d.erro_por_categoria[nome], linhas)} |"
            for nome, linhas in e.por_categoria.items() if linhas
        ]
        texto.append(f"| Total | {_milhar(total)} | {_milhar(erro)} | {_pct(total - erro, total)} |")
        texto += ["", *_limites_do_acerto(e)]
    if d.combinacoes:
        mostradas = list(d.combinacoes.items())[:COMBINACOES_NO_RELATORIO]
        texto += [
            "",
            (
                f"Rótulos que dividem a mesma combinação de valores, em ordem de linhas envolvidas "
                f"({len(mostradas)} de {len(d.combinacoes)} conjuntos de rótulos):"
            ),
            "",
            "| Rótulos com a mesma combinação | Linhas |",
            "|---|---|",
            *(f"| {_nomes(rotulos)} | {_milhar(linhas)} |" for rotulos, linhas in mostradas),
        ]
    return texto


def _secao_protocolos(e):
    texto = [
        "## 9. Valores de `Protocol Type`",
        "",
        "`Protocol Type` é o número de protocolo IP mais frequente na janela.",
        "",
        "| `Protocol Type` | Protocolo | Linhas | % das linhas |",
        "|---|---|---|---|",
    ]
    texto += [
        f"| {_numero(valor)} | {PROTOCOLOS.get(valor, 'outro')} | {_milhar(linhas)} | "
        f"{_pct(linhas, e.linhas, casas=4)} |"
        for valor, linhas in e.protocolos.items()
    ]
    return texto


def _secao_por_ataque(e, por_ataque):
    texto = [
        "## 10. Conferência com os CSVs por ataque",
        "",
        "O dataset também traz uma pasta de CSVs por ataque, com as mesmas 39 colunas e sem rótulo: a",
        "classe é o nome da pasta. A tabela compara a quantidade de linhas dessas pastas com a do",
        "`MERGED_CSV`. A diferença é a quantidade nos CSVs por ataque menos a do `MERGED_CSV`.",
        "",
        (
            "| Classe | Arquivos | Linhas nos CSVs por ataque | Linhas no `MERGED_CSV` | Diferença "
            "| % dos CSVs por ataque |"
        ),
        "|---|---|---|---|---|---|",
    ]
    texto += [
        f"| `{rotulo}` | {registro['arquivos']} | {_milhar(registro['linhas'])} | {_milhar(e.por_rotulo[rotulo])} | "
        f"{_milhar(registro['linhas'] - e.por_rotulo[rotulo])} | "
        f"{_pct(registro['linhas'] - e.por_rotulo[rotulo], registro['linhas'])} |"
        for rotulo, registro in por_ataque.items()
    ]
    # Classe com CSV por ataque cortado tem a referência incompleta e fica fora do total: a
    # diferença dela mistura o que falta ao `MERGED_CSV` com o que falta à própria referência.
    inteiras = {rotulo: r for rotulo, r in por_ataque.items() if r["linhas"] and not r["incompletos"]}
    cortadas = [rotulo for rotulo, r in por_ataque.items() if r["incompletos"]]
    incompletos = [nome for r in por_ataque.values() for nome in r["incompletos"]]
    terminam = (
        f"{_plural(len(incompletos), 'arquivo por ataque', 'arquivos por ataque')} "
        f"{'termina' if len(incompletos) == 1 else 'terminam'} no meio de uma linha, e a linha incompleta não "
        f"foi contada: {_nomes(incompletos)}."
    )
    if not inteiras:
        texto += ["", "Nenhuma classe tem todos os CSVs por ataque inteiros, e por isso a tabela não tem linha de total."]
        return [*texto, "", terminam] if cortadas else texto

    la = sum(r["linhas"] for r in inteiras.values())
    no_merged = sum(e.por_rotulo[rotulo] for rotulo in inteiras)
    nome = "Total das classes com CSVs por ataque inteiros" if cortadas else "Total"
    texto.append(
        f"| {nome} | {sum(r['arquivos'] for r in inteiras.values())} | {_milhar(la)} | {_milhar(no_merged)} | "
        f"{_milhar(la - no_merged)} | {_pct(la - no_merged, la)} |"
    )
    fatias = [(r["linhas"] - e.por_rotulo[rotulo]) / r["linhas"] for rotulo, r in inteiras.items()]
    classes = _plural(len(inteiras), "classe", "classes")
    if cortadas:
        abertura = f"A linha de total soma só as {classes} cujos CSVs por ataque estão inteiros. Nelas, o"
    else:
        abertura = f"Nas {classes}, todas com os CSVs por ataque inteiros, o"
    frase = (
        f"{abertura} `MERGED_CSV` tem {_pct(abs(la - no_merged), la)} {'menos' if no_merged <= la else 'mais'} "
        f"linhas que os CSVs por ataque, e a diferença por classe vai de {_pct(min(fatias), 1)} a "
        f"{_pct(max(fatias), 1)}. O `MERGED_CSV` é embaralhado, então linhas perdidas em arquivos truncados "
        "faltam em todas as classes em proporção parecida."
    )
    if cortadas and 0 < no_merged < la:
        # Com a mesma perda em todas as classes, faltam linhas × perda / (1 − perda) ao conjunto todo.
        faltam = e.linhas * (la - no_merged) / no_merged
        frase += (
            " Aplicada a todas as classes, essa proporção corresponde a cerca de "
            f"{_cerca_de(faltam, 'linha', 'linhas')} a menos no `MERGED_CSV`."
        )
    texto += ["", frase]
    if cortadas:
        todas = sum(r["linhas"] for r in por_ataque.values())
        diferenca = todas - sum(e.por_rotulo[rotulo] for rotulo in por_ataque)
        dela = "dessa classe" if len(cortadas) == 1 else "dessas classes"
        texto += [
            "",
            (
                f"{_nomes(cortadas)} {'fica' if len(cortadas) == 1 else 'ficam'} fora do total porque {terminam} "
                f"Com a referência incompleta, a diferença {dela} não mede o que falta ao `MERGED_CSV`. Somadas "
                f"todas as classes, a diferença seria de {_plural(diferenca, 'linha', 'linhas')}, ou "
                f"{_pct(diferenca, todas)}."
            ),
        ]
    return texto


def montar_relatorio(e, por_ataque=None):
    """Monta o relatório da exploração em Markdown."""
    hoje = datetime.datetime.now(tz=datetime.UTC).astimezone().strftime("%d/%m/%Y")
    secoes = [
        [
            "# Exploração do MERGED_CSV",
            "",
            (
                f"Gerado por `python -m codigo.classificador.explorar` em {hoje}, com Python "
                f"{platform.python_version()}, pandas {pd.__version__} e numpy {np.__version__}."
            ),
            "",
            "Todos os números vêm da leitura completa do `MERGED_CSV` do CICIoT2023 (Neto et al., 2023), e não",
            "da amostra de treino. As classes estão na grafia dos autores do dataset, e as categorias são as de",
            "`codigo/classificador/mapeamento.py`.",
        ],
        _resumo(e),
        _secao_arquivos(e),
        _secao_categorias(e),
        [*_secao_classes(e), "", *_secao_grafias(e)],
        _secao_janela(e),
        _secao_vazios(e),
        _secao_faixa(e),
        _secao_redundancias(e),
        _secao_repetidas(e),
        _secao_protocolos(e),
    ]
    if por_ataque:
        secoes.append(_secao_por_ataque(e, por_ataque))
    secoes.append([
        "## Como os números foram obtidos",
        "",
        "- Os arquivos são lidos em ordem de nome, linha a linha. Linha em branco é ignorada, e rótulo",
        "  desconhecido ou linha com a quantidade errada de campos interrompe a execução.",
        "- Os valores são convertidos para ponto flutuante de 64 bits sem perda (`float_precision=\"round_trip\"`).",
        "- As linhas repetidas são encontradas por um hash de 64 bits das 39 colunas",
        "  (`pandas.util.hash_pandas_object`). Com dezenas de milhões de linhas, a chance de duas linhas",
        "  diferentes terem o mesmo hash é desprezível para estas contagens.",
        "- Os percentuais são sobre o total de linhas completas lidas, salvo quando a coluna diz outra coisa.",
        "",
    ])
    return "\n".join("\n".join(secao) + "\n" for secao in secoes).rstrip("\n") + "\n"


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.classificador.explorar",
        description="Explora o MERGED_CSV completo do CICIoT2023 e grava o relatório em Markdown.",
    )
    analisador.add_argument("--entrada", default="CICIoT2023/MERGED_CSV", help="pasta com os arquivos CSV")
    analisador.add_argument(
        "--por-ataque", default=None, help="pasta com as pastas de CSVs por ataque (padrão: a que contém a entrada)"
    )
    analisador.add_argument("--saida", default="experimentos/resultados/exploracao.md")
    try:
        argumentos = analisador.parse_args(argv)
    except SystemExit as encerramento:
        return encerramento.code
    try:
        arquivos = listar_arquivos(argumentos.entrada)
        exploracao = explorar(arquivos, ao_terminar_arquivo=relatar_arquivo)
        por_ataque = contar_por_ataque(argumentos.por_ataque or Path(argumentos.entrada).parent)
        relatorio = montar_relatorio(exploracao, por_ataque)
        destino = Path(argumentos.saida)
        destino.parent.mkdir(parents=True, exist_ok=True)
        destino.write_text(relatorio, encoding="utf-8")
    except (OSError, ValueError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrompido: nenhum relatório foi gravado", file=sys.stderr)
        return 130
    print(f"{_milhar(exploracao.linhas)} linhas lidas em {len(arquivos)} arquivos", file=sys.stderr)
    print(f"relatório em {destino}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
