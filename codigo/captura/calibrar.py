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
import re
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import dpkt

from codigo.captura.extrator import COLUNAS, JANELA_MAXIMA, extrair, ler_pcap

LIMITE_PEDACO = 10_000_000  # tcpdump -C 10: a unidade é 1.000.000 de bytes
TOLERANCIA = 1e-9
TOLERANCIA_ABSOLUTA = 1e-12
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
    return math.isclose(a, b, rel_tol=TOLERANCIA, abs_tol=TOLERANCIA_ABSOLUTA)


def colunas_divergentes(minha, oficial):
    """Nomes das colunas em que a linha extraída difere da oficial."""
    return [c for c in COLUNAS if not valores_iguais(float(minha[c]), oficial[c])]


def _linha_igual(minha, oficial):
    return all(valores_iguais(float(minha[c]), oficial[c]) for c in COLUNAS)


def _linhas_iguais(bloco, trecho):
    """Quantas linhas do bloco batem com o trecho do oficial, posição a posição."""
    return sum(1 for minha, dele in zip(bloco, trecho) if _linha_igual(minha, dele))


def _celulas_iguais(bloco, trecho):
    """Quantos valores do bloco batem com o trecho do oficial, posição a posição."""
    return sum(
        valores_iguais(float(minha[c]), dele[c]) for minha, dele in zip(bloco, trecho) for c in COLUNAS
    )


def encaixar(blocos, oficial):
    """Põe os blocos na ordem em que aparecem no CSV oficial e devolve as linhas em sequência.

    A cada passo escolhe, entre os blocos ainda não usados, o que tem mais linhas iguais ao
    trecho seguinte do oficial. Se menos da metade das linhas do melhor candidato bate, há um
    erro que atinge quase todas as linhas, e a escolha passa a ser feita pela quantidade de
    valores iguais. Assim uma coluna errada aparece sozinha no relatório.
    """
    livres = list(range(len(blocos)))
    alinhadas = []
    while livres:
        trecho = oficial[len(alinhadas):]
        pontos = {i: _linhas_iguais(blocos[i], trecho) for i in livres}
        escolhido = max(livres, key=lambda i: (pontos[i], -i))
        if 2 * pontos[escolhido] < len(blocos[escolhido]):
            escolhido = max(livres, key=lambda i: (_celulas_iguais(blocos[i], trecho), -i))
        livres.remove(escolhido)
        alinhadas.extend(blocos[escolhido])
    return alinhadas


def janela_do_oficial(oficial):
    """Tamanho da janela usado num CSV oficial: o maior valor da coluna Number.

    Só a última janela de cada pedaço fica incompleta, então o maior valor é o da janela cheia.
    """
    if not oficial:
        return 10
    maior = max(registro["Number"] for registro in oficial)
    if not (math.isfinite(maior) and 1 <= maior <= JANELA_MAXIMA):
        raise ValueError(f"coluna Number do CSV oficial fora do esperado (maior valor: {maior})")
    return int(maior)


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
    coluna_do_maior_desvio: str = ""
    janela: int = 10

    @property
    def aprovado(self):
        return self.linhas_extraidas == self.linhas_oficiais == self.linhas_iguais


def _tipo_ethernet(quadro):
    return struct.unpack(">H", quadro[12:14])[0] if len(quadro) >= 14 else -1


def _desvio_relativo(a, b):
    if not (math.isfinite(a) and math.isfinite(b)) or a == b:
        return 0.0
    return abs(a - b) / max(abs(a), abs(b))


def calibrar_pcap(pcap, csv_oficial, limite=LIMITE_PEDACO, janela=None):
    """Extrai as features do pcap como os autores fizeram e compara com o CSV oficial.

    Sem `janela`, usa o tamanho de janela do próprio CSV oficial (10 ou 100, conforme a classe).
    """
    oficial = ler_oficial(csv_oficial)
    resultado = Resultado(nome=Path(pcap).stem, janela=janela or janela_do_oficial(oficial))
    blocos = []
    for pedaco in fatiar(ler_pcap(pcap), limite):
        resultado.pedacos += 1
        resultado.pacotes += len(pedaco)
        resultado.tipos.update(_tipo_ethernet(quadro) for _, quadro in pedaco)
        blocos.append(list(extrair(pedaco, resultado.janela)))
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
                resultado.coluna_do_maior_desvio = coluna
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
    quantos = "1 pcap" if len(resultados) == 1 else f"{len(resultados)} pcaps"
    conferidos = ", ".join(f"`{r.nome}` (janela de {r.janela})" for r in resultados)
    linhas = [
        "# Calibração do extrator",
        "",
        (
            f"Gerado por `python -m codigo.captura.calibrar` em {hoje}, com Python "
            f"{platform.python_version()} e dpkt {dpkt.__version__}."
        ),
        "",
        "O extrator (`codigo/captura/extrator.py`) foi executado sobre pcaps do CICIoT2023 e a saída",
        "foi comparada, coluna a coluna, com os CSVs publicados pelos autores do dataset.",
        "",
        "## Escopo",
        "",
        (
            f"A comparação cobre {quantos}, os que estão disponíveis localmente com o CSV oficial "
            f"correspondente: {conferidos}."
        ),
        "",
        "O CICIoT2023 tem 34 classes. Os autores agregam os quadros em janelas de 10 em 15 delas e em",
        "janelas de 100 nas 19 classes de DDoS, DoS e Mirai. O resultado abaixo vale para os pcaps e",
        "para os tamanhos de janela listados. As classes sem pcap disponível não foram conferidas.",
        "",
        "## Resultado",
        "",
        (
            "| pcap | janela | pacotes | quadros IPv4 e ARP | pedaços de 10 MB | linhas extraídas "
            "| linhas oficiais | linhas iguais |"
        ),
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in resultados:
        linhas.append(
            f"| `{r.nome}` | {r.janela} | {_milhar(r.pacotes)} | {_milhar(r.mantidos)} | {r.pedacos} | "
            f"{_milhar(r.linhas_extraidas)} | {_milhar(r.linhas_oficiais)} | {_milhar(r.linhas_iguais)} |"
        )
    tolerancia = (
        f"As 39 colunas são comparadas com tolerância relativa de {TOLERANCIA:g} e absoluta de "
        f"{TOLERANCIA_ABSOLUTA:g}."
    )
    pior = max(resultados, key=lambda r: r.maior_desvio, default=None)
    if pior is not None and pior.maior_desvio > 0:
        tolerancia += (
            f" Maior desvio relativo observado entre valores considerados iguais: {pior.maior_desvio:.2e}, "
            f"na coluna `{pior.coluna_do_maior_desvio}` de `{pior.nome}`."
        )
    linhas += [
        "",
        tolerancia,
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
        linhas.append(
            "Nenhuma divergência: todas as linhas dos CSVs oficiais conferidos foram reproduzidas nas "
            "39 colunas."
        )
    else:
        linhas += [
            "| pcap | coluna | linhas divergentes | exemplo (linha do CSV oficial) | extraído | oficial |",
            "|---|---|---|---|---|---|",
        ]
        for r in resultados:
            for coluna, (quantas, (numero, meu, dele)) in r.divergencias.items():
                linhas.append(
                    f"| `{r.nome}` | `{coluna}` | {_milhar(quantas)} | {numero} | {meu!r} | {dele!r} |"
                )
            if r.linhas_extraidas != r.linhas_oficiais:
                linhas.append(
                    f"| `{r.nome}` | (quantidade de linhas) | | | {_milhar(r.linhas_extraidas)} | "
                    f"{_milhar(r.linhas_oficiais)} |"
                )
        incertos = [f"`{r.nome}`" for r in resultados if 2 * r.linhas_iguais < r.linhas_oficiais]
        if incertos:
            linhas += [
                "",
                (
                    f"Em {', '.join(incertos)}, menos da metade das linhas é igual. O encaixe dos blocos "
                    "foi feito pela quantidade de valores iguais e pode estar errado, então a contagem "
                    "por coluna deve ser lida com cautela."
                ),
            ]
    linhas += [
        "",
        "## Como a comparação é feita",
        "",
        "1. O tamanho da janela de cada pcap é lido do CSV oficial: é o maior valor da coluna",
        "   `Number`, o de uma janela completa.",
        "2. O pcap é dividido em pedaços como faz o `tcpdump -C 10`: um pedaço novo começa quando o",
        "   atual já passou de 10.000.000 de bytes.",
        "3. Cada pedaço é processado por um extrator novo, de modo que a janela e o intervalo entre",
        "   quadros recomeçam a cada pedaço, como no processamento original.",
        "4. Os autores juntam os CSVs dos pedaços sem ordem definida. Por isso os blocos de linhas são",
        "   encaixados no CSV oficial na ordem em que ele os traz, cada bloco usado uma vez.",
        "5. As 39 colunas são comparadas linha a linha. Campo vazio só é igual a campo vazio, e",
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
        "- A última janela de cada pedaço pode ficar incompleta. Com um único quadro, `Std` e",
        "  `Variance` ficam vazios e `Rate` é infinito.",
        "",
        "## Diferenças conhecidas em relação ao código dos autores",
        "",
        "- Quadro IPv4 com cabeçalho ilegível é ignorado pelo extrator. No código dos autores ele",
        "  interrompe o processamento do pedaço inteiro. Como a quantidade de linhas bate, isso não",
        "  ocorreu nos pcaps conferidos.",
        "- O código dos autores trata o instante 0 como ausência de quadro anterior. O extrator só",
        "  considera ausente o quadro anterior no início da leitura. A diferença só aparece em",
        "  capturas com instante exatamente igual a zero.",
        "- O extrator lê capturas com fração de tempo em nanossegundos. Não há referência dos autores",
        "  para esse formato.",
        "- O extrator decodifica só os primeiros 1600 bytes de cada quadro, o que cobre todos os",
        "  cabeçalhos usados na medição. Um quadro maior que isso cuja decodificação completa falhe",
        "  é descartado pelo código dos autores e mantido pelo extrator.",
        "",
    ]
    return "\n".join(linhas)


_NOME_SIMPLES = re.compile(r"[A-Za-z0-9._-]+")


def _csv_oficial(pasta, pcap):
    """CSV oficial de um pcap: NOME.pcap.csv em alguma subpasta do dataset.

    O nome entra num padrão de busca; quem chama garante que ele só tem caracteres simples.
    """
    candidatos = sorted(pasta.glob(f"*/{pcap.name}.csv"))
    return candidatos[0] if candidatos else None


def main(argv=None):
    analisador = argparse.ArgumentParser(description="Compara o extrator com os CSVs oficiais do CICIoT2023.")
    analisador.add_argument(
        "--dataset", default="CICIoT2023", help="pasta com NOME.pcap e, em alguma subpasta, NOME.pcap.csv"
    )
    analisador.add_argument("--saida", default="experimentos/resultados/calibracao.md")
    argumentos = analisador.parse_args(argv)
    pasta = Path(argumentos.dataset)
    pares, fora = [], []
    for caminho_pcap in sorted(pasta.glob("*.pcap")):
        # O nome do pcap vai para o relatório: só entram nomes simples, sem caracteres especiais.
        if not _NOME_SIMPLES.fullmatch(caminho_pcap.name):
            fora.append(f"{caminho_pcap.name} tem nome fora do padrão (letras, números, ponto, hífen e sublinhado)")
            continue
        oficial = _csv_oficial(pasta, caminho_pcap)
        if oficial is None:
            fora.append(f"{caminho_pcap.name} não tem CSV oficial em {pasta}/")
        else:
            pares.append((caminho_pcap, oficial))
    if not pares:
        print(
            f"erro: nenhum pcap com CSV oficial em {pasta}/ "
            "(esperado: NOME.pcap e, em alguma subpasta, NOME.pcap.csv)",
            file=sys.stderr,
        )
        return 2
    resultados, com_erro = [], False
    for caminho_pcap, oficial in pares:
        print(f"calibrando {caminho_pcap.name}...", file=sys.stderr)
        try:
            resultados.append(calibrar_pcap(caminho_pcap, oficial))
        except (OSError, ValueError, TypeError, OverflowError, csv.Error) as erro:
            # Um pcap ou CSV inválido não impede a calibração dos demais.
            print(f"erro: {caminho_pcap.name}: {erro}", file=sys.stderr)
            com_erro = True
    if not resultados:
        return 2
    destino = Path(argumentos.saida)
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text(montar_relatorio(resultados), encoding="utf-8")
    for r in resultados:
        situacao = "igual ao oficial" if r.aprovado else "com divergências"
        print(
            f"{r.nome}: {r.linhas_iguais} de {r.linhas_oficiais} linhas iguais, janela de {r.janela} ({situacao})",
            file=sys.stderr,
        )
    for motivo in fora:
        print(f"aviso: {motivo} e ficou fora da calibração", file=sys.stderr)
    print(f"relatório em {destino}", file=sys.stderr)
    if com_erro:
        return 2
    return 0 if all(r.aprovado for r in resultados) and not fora else 1


if __name__ == "__main__":
    sys.exit(main())
