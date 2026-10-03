"""Calibração do extrator contra os CSVs oficiais do CICIoT2023.

O CSV oficial de cada pcap foi gerado em pedaços: os autores fatiam o pcap com
`tcpdump -C 10`, processam cada pedaço em separado e juntam os resultados sem ordem definida.
Este módulo refaz esse caminho com o nosso extrator e compara as 39 colunas, linha a linha.

Uso, a partir da raiz do repositório:
    python -m codigo.captura.calibrar
"""
import argparse
import csv
import datetime
import math
import platform
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import dpkt

from codigo.captura.extrator import COLUNAS, extrair, ler_pcap

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


_NOMES_DE_TIPO = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x9000: "teste de enlace (loopback)"}


@dataclass
class Resultado:
    """O que a calibração mediu em um pcap."""

    nome: str
    pacotes: int = 0
    tipos: Counter = field(default_factory=Counter)
    pedacos: int = 0
    mantidos: int = 0
    linhas_extraidas: int = 0
    linhas_oficiais: int = 0
    linhas_iguais: int = 0
    divergencias: dict = field(default_factory=dict)
    maior_desvio: float = 0.0

    @property
    def aprovado(self):
        return self.linhas_extraidas == self.linhas_oficiais == self.linhas_iguais


def _tipo_ethernet(quadro):
    return struct.unpack(">H", quadro[12:14])[0] if len(quadro) >= 14 else -1


def _desvio_relativo(a, b):
    if not (math.isfinite(a) and math.isfinite(b)) or a == b:
        return 0.0
    return abs(a - b) / max(abs(a), abs(b))


def calibrar_pcap(pcap, csv_oficial, limite=LIMITE_PEDACO):
    """Extrai as features do pcap como os autores fizeram e compara com o CSV oficial."""
    resultado = Resultado(nome=Path(pcap).stem)
    blocos = []
    for pedaco in fatiar(ler_pcap(pcap), limite):
        resultado.pedacos += 1
        resultado.pacotes += len(pedaco)
        resultado.tipos.update(_tipo_ethernet(quadro) for _, quadro in pedaco)
        blocos.append(list(extrair(pedaco)))
    oficial = ler_oficial(csv_oficial)
    alinhadas = encaixar(blocos, oficial)
    resultado.linhas_extraidas = len(alinhadas)
    resultado.linhas_oficiais = len(oficial)
    resultado.mantidos = sum(linha["Number"] for linha in alinhadas)
    # A linha 1 do arquivo CSV é o cabeçalho, então a primeira linha de dados é a 2.
    for numero, (minha, dele) in enumerate(zip(alinhadas, oficial), start=2):
        ruins = colunas_divergentes(minha, dele)
        if not ruins:
            resultado.linhas_iguais += 1
        for coluna in ruins:
            registro = resultado.divergencias.setdefault(coluna, [0, (numero, minha[coluna], dele[coluna])])
            registro[0] += 1
        for coluna in COLUNAS:
            desvio = _desvio_relativo(float(minha[coluna]), dele[coluna])
            if coluna not in ruins and desvio > resultado.maior_desvio:
                resultado.maior_desvio = desvio
    return resultado


def _milhar(numero):
    return f"{numero:,}".replace(",", ".")


def _nome_do_tipo(tipo):
    if tipo in _NOMES_DE_TIPO:
        return _NOMES_DE_TIPO[tipo]
    if 0 <= tipo < 0x0600:
        return "IEEE 802.3 com LLC (STP e afins)"
    return f"0x{tipo:04x}"


def montar_relatorio(resultados):
    """Monta o relatório de calibração em Markdown."""
    hoje = datetime.datetime.now(tz=datetime.UTC).astimezone().strftime("%d/%m/%Y")
    linhas = [
        "# Calibração do extrator",
        "",
        (
            f"Gerado por `python -m codigo.captura.calibrar` em {hoje}, com Python "
            f"{platform.python_version()} e dpkt {dpkt.__version__}."
        ),
        "",
        "O extrator (`codigo/captura/extrator.py`) foi executado sobre os pcaps do CICIoT2023 e a",
        "saída foi comparada, coluna a coluna, com os CSVs publicados pelos autores do dataset.",
        "",
        "## Resultado",
        "",
        "| pcap | pacotes | quadros IPv4 e ARP | pedaços de 10 MB | linhas extraídas | linhas oficiais | linhas iguais |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in resultados:
        linhas.append(
            f"| `{r.nome}` | {_milhar(r.pacotes)} | {_milhar(r.mantidos)} | {r.pedacos} | "
            f"{_milhar(r.linhas_extraidas)} | {_milhar(r.linhas_oficiais)} | {_milhar(r.linhas_iguais)} |"
        )
    maior = max((r.maior_desvio for r in resultados), default=0.0)
    linhas += [
        "",
        (
            f"Tolerância usada nos valores decimais: {TOLERANCIA:g} (relativa). Maior desvio relativo "
            f"observado entre valores considerados iguais: {maior:.2e}. Valores inteiros são comparados "
            "sem tolerância."
        ),
        "",
        "## Quadros fora do filtro",
        "",
        "O extrator mantém apenas quadros Ethernet de tipo IPv4 ou ARP, como o código dos autores.",
        "",
        "| pcap | tipo do quadro | quadros |",
        "|---|---|---|",
    ]
    for r in resultados:
        fora = [(t, n) for t, n in r.tipos.most_common() if t not in (0x0800, 0x0806)]
        resumo = {}
        for tipo, quantidade in fora:
            resumo[_nome_do_tipo(tipo)] = resumo.get(_nome_do_tipo(tipo), 0) + quantidade
        for nome, quantidade in resumo.items():
            linhas.append(f"| `{r.nome}` | {nome} | {_milhar(quantidade)} |")
    linhas += ["", "## Divergências", ""]
    if all(not r.divergencias and r.aprovado for r in resultados):
        linhas.append("Nenhuma divergência: todas as linhas dos CSVs oficiais foram reproduzidas nas 39 colunas.")
    else:
        linhas += ["| pcap | coluna | linhas divergentes | exemplo (linha do CSV oficial) | extraído | oficial |", "|---|---|---|---|---|---|"]
        for r in resultados:
            for coluna, (quantas, (numero, meu, dele)) in r.divergencias.items():
                linhas.append(f"| `{r.nome}` | `{coluna}` | {_milhar(quantas)} | {numero} | {meu!r} | {dele!r} |")
            if r.linhas_extraidas != r.linhas_oficiais:
                linhas.append(
                    f"| `{r.nome}` | (quantidade de linhas) | | | {_milhar(r.linhas_extraidas)} | {_milhar(r.linhas_oficiais)} |"
                )
    linhas += [
        "",
        "## Como a comparação é feita",
        "",
        "1. O pcap é dividido em pedaços como faz o `tcpdump -C 10`: um pedaço novo começa quando o",
        "   atual já passou de 10.000.000 de bytes.",
        "2. Cada pedaço é processado por um extrator novo, de modo que a janela de 10 quadros e o",
        "   intervalo entre quadros recomeçam a cada pedaço, como no processamento original.",
        "3. Os autores juntam os CSVs dos pedaços sem ordem definida. Por isso os blocos de linhas são",
        "   encaixados no CSV oficial na ordem em que ele os traz, cada bloco usado uma vez.",
        "4. As 39 colunas são comparadas linha a linha. Campo vazio só é igual a campo vazio, e",
        "   infinito só é igual a infinito.",
        "",
        "## Particularidades do código dos autores reproduzidas pelo extrator",
        "",
        "O classificador é treinado com os CSVs oficiais, então o extrator repete estes comportamentos:",
        "",
        "- A coluna `IRC` é marcada pela porta TCP 21.",
        "- A coluna `LLC` vale 1 em todo quadro IPv4, igual à coluna `IPv`.",
        "- A coluna `SMTP` só é marcada em TCP; tráfego UDP na porta 25 não a ativa.",
        "- Quadros IPv6 não geram linha.",
        "- A última janela de cada pedaço pode ter menos de 10 quadros. Com um único quadro, `Std` e",
        "  `Variance` ficam vazios e `Rate` é infinito.",
        "",
    ]
    return "\n".join(linhas)


def main(argv=None):
    analisador = argparse.ArgumentParser(description="Compara o extrator com os CSVs oficiais do CICIoT2023.")
    analisador.add_argument("--dataset", default="CICIoT2023", help="pasta com NOME.pcap e NOME/NOME.pcap.csv")
    analisador.add_argument("--saida", default="experimentos/resultados/calibracao.md")
    argumentos = analisador.parse_args(argv)
    pasta = Path(argumentos.dataset)
    pares = [(p, pasta / p.stem / (p.name + ".csv")) for p in sorted(pasta.glob("*.pcap"))]
    pares = [(p, oficial) for p, oficial in pares if oficial.exists()]
    if not pares:
        print(
            f"erro: nenhum pcap com CSV oficial em {pasta}/ (esperado: NOME.pcap e NOME/NOME.pcap.csv)",
            file=sys.stderr,
        )
        return 2
    resultados = []
    for caminho_pcap, oficial in pares:
        print(f"calibrando {caminho_pcap.name}...", file=sys.stderr)
        resultados.append(calibrar_pcap(caminho_pcap, oficial))
    destino = Path(argumentos.saida)
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text(montar_relatorio(resultados), encoding="utf-8")
    for r in resultados:
        situacao = "igual ao oficial" if r.aprovado else "com divergências"
        print(f"{r.nome}: {r.linhas_iguais} de {r.linhas_oficiais} linhas iguais ({situacao})", file=sys.stderr)
    print(f"relatório em {destino}", file=sys.stderr)
    return 0 if all(r.aprovado for r in resultados) else 1


if __name__ == "__main__":
    sys.exit(main())
