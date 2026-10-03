"""Calibração do extrator contra os CSVs oficiais do CICIoT2023.

O CSV oficial de cada pcap foi gerado em pedaços: os autores fatiam o pcap com
`tcpdump -C 10`, processam cada pedaço em separado e juntam os resultados sem ordem definida.
Este módulo refaz esse caminho com o nosso extrator e compara as 39 colunas, linha a linha.

Uso, a partir da raiz do repositório:
    python -m codigo.captura.calibrar
"""
import csv
import math

from codigo.captura.extrator import COLUNAS

LIMITE_PEDACO = 10_000_000  # tcpdump -C 10: a unidade é 1.000.000 de bytes
TOLERANCIA = 1e-9
_CABECALHO_ARQUIVO, _CABECALHO_PACOTE = 24, 16


def fatiar(quadros, limite=LIMITE_PEDACO):
    """Agrupa os quadros em pedaços como o `tcpdump -C`.

    O tcpdump confere o tamanho do arquivo antes de gravar cada pacote e abre um arquivo novo
    quando o atual já passou do limite. Por isso um pedaço pode exceder o limite em um pacote.
    """
    pedaco, tamanho = [], _CABECALHO_ARQUIVO
    for ts, quadro in quadros:
        if tamanho > limite:
            yield pedaco
            pedaco, tamanho = [], _CABECALHO_ARQUIVO
        pedaco.append((ts, quadro))
        tamanho += _CABECALHO_PACOTE + len(quadro)
    if pedaco:
        yield pedaco


def ler_oficial(caminho):
    """Lê um CSV oficial como lista de dicionários de float. Campo vazio vira nan."""
    with open(caminho, newline="") as arquivo:
        leitor = csv.DictReader(arquivo)
        faltando = [c for c in COLUNAS if c not in (leitor.fieldnames or [])]
        if faltando:
            raise ValueError(f"{caminho}: faltam as colunas {', '.join(faltando)}")
        return [
            {c: math.nan if registro[c] == "" else float(registro[c]) for c in COLUNAS}
            for registro in leitor
        ]


def valores_iguais(a, b):
    """Compara dois valores com a tolerância da calibração. nan só é igual a nan."""
    if math.isnan(a) or math.isnan(b):
        return math.isnan(a) and math.isnan(b)
    if math.isinf(a) or math.isinf(b):
        return a == b
    return math.isclose(a, b, rel_tol=TOLERANCIA, abs_tol=1e-12)


def colunas_divergentes(minha, oficial):
    """Nomes das colunas em que a linha extraída difere da oficial."""
    return [c for c in COLUNAS if not valores_iguais(float(minha[c]), oficial[c])]


def _linha_igual(minha, oficial):
    return all(valores_iguais(float(minha[c]), oficial[c]) for c in COLUNAS)


def _linhas_iguais(bloco, trecho):
    """Quantas linhas do bloco batem com o trecho do oficial, posição a posição."""
    return sum(1 for minha, dele in zip(bloco, trecho) if _linha_igual(minha, dele))


def encaixar(blocos, oficial):
    """Põe os blocos na ordem em que aparecem no CSV oficial e devolve as linhas em sequência.

    A cada passo escolhe, entre os blocos ainda não usados, o que tem mais linhas iguais ao
    trecho seguinte do oficial. Assim uma linha divergente, mesmo a primeira do bloco, não
    impede o encaixe.
    """
    livres = list(range(len(blocos)))
    alinhadas = []
    while livres:
        trecho = oficial[len(alinhadas):]
        escolhido = max(livres, key=lambda i: (_linhas_iguais(blocos[i], trecho), -i))
        livres.remove(escolhido)
        alinhadas.extend(blocos[escolhido])
    return alinhadas
