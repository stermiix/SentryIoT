"""Extrator de features do SentryIoT.

Transforma quadros Ethernet nas 39 features do CICIoT2023 (Neto et al., 2023). Cada linha
resume uma janela de quadros IPv4 ou ARP consecutivos. As regras de medição seguem o que o
código publicado pelos autores do dataset faz, para que o classificador receba em operação
os mesmos números com que foi treinado.

Uso, a partir da raiz do repositório:
    python -m codigo.captura.extrator entrada.pcap saida.csv
    python -m codigo.captura.extrator --janela 100 entrada.pcap saida.csv
"""
import argparse
import csv
import math
import struct
import sys
import warnings
from collections import Counter

import dpkt

# Nome da coluna e bit correspondente no campo de flags do TCP.
FLAGS = (
    ("fin_flag_number", 0x01),
    ("syn_flag_number", 0x02),
    ("rst_flag_number", 0x04),
    ("psh_flag_number", 0x08),
    ("ack_flag_number", 0x10),
    ("ece_flag_number", 0x40),
    ("cwr_flag_number", 0x80),
)
# Indicador e porta TCP que o ativa. "IRC" olha a porta 21 porque é assim no código dos autores.
PORTAS_TCP = (("HTTP", 80), ("HTTPS", 443), ("Telnet", 23), ("SMTP", 25), ("SSH", 22), ("IRC", 21))
INDICADORES = (
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP",
    "ARP", "ICMP", "IGMP", "IPv", "LLC",
)
# Coluna de contagem e flag que ela soma dentro da janela.
CONTAGENS = (
    ("ack_count", "ack_flag_number"),
    ("syn_count", "syn_flag_number"),
    ("fin_count", "fin_flag_number"),
    ("rst_count", "rst_flag_number"),
)
COLUNAS = (
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
    *(nome for nome, _ in FLAGS),
    *(nome for nome, _ in CONTAGENS),
    *INDICADORES,
    "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number", "Variance",
)
# Colunas que a janela resume pela média dos quadros.
MEDIAS = (
    "Header_Length", "Time_To_Live", *(nome for nome, _ in FLAGS), *INDICADORES, "Tot size", "IAT",
)


def medir_quadro(ts, quadro, ts_anterior=None):
    """Mede um quadro Ethernet.

    Devolve um dicionário com as colunas de MEDIAS, mais "Protocol Type" e "ts". Devolve None
    se o quadro não entra na conta: não é IPv4 nem ARP, ou não pôde ser decodificado.
    """
    # Quadro que o dpkt não decodifica como Ethernet é descartado, qualquer que seja o erro:
    # um quadro malformado não pode derrubar a extração. O código dos autores também o descarta.
    try:
        eth = dpkt.ethernet.Ethernet(quadro)
    except Exception:  # noqa: BLE001
        return None
    medida = dict.fromkeys(MEDIAS, 0)
    medida["Protocol Type"] = 0
    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        ip = eth.data
        # IPv4 com cabeçalho ilegível: o dpkt devolve os bytes crus. Aqui o quadro é ignorado;
        # no código dos autores ele interrompe o processamento do pedaço inteiro.
        if not isinstance(ip, dpkt.ip.IP):
            return None
        medida["Protocol Type"] = ip.p
        medida["Time_To_Live"] = ip.ttl
        # No código dos autores "LLC" vale 1 em todo quadro IPv4, igual a "IPv".
        medida["IPv"] = medida["LLC"] = 1
        medida["ICMP"] = int(ip.p == 1)
        medida["IGMP"] = int(ip.p == 2)
        carga = ip.data
        if type(carga) is dpkt.udp.UDP:
            portas = (carga.sport, carga.dport)
            medida["UDP"] = 1
            medida["Header_Length"] = 8
            medida["DNS"] = int(53 in portas)
            medida["DHCP"] = int(portas in ((67, 68), (68, 67)))
        elif type(carga) is dpkt.tcp.TCP:
            portas = (carga.sport, carga.dport)
            medida["TCP"] = 1
            medida["Header_Length"] = 20 + len(carga.opts)
            for nome, bit in FLAGS:
                medida[nome] = int(carga.flags & bit != 0)
            for nome, porta in PORTAS_TCP:
                medida[nome] = int(porta in portas)
    elif eth.type == dpkt.ethernet.ETH_TYPE_ARP:
        medida["ARP"] = 1
    else:
        return None
    medida["Tot size"] = len(quadro)
    medida["IAT"] = 0.0 if ts_anterior is None else ts - ts_anterior
    medida["ts"] = ts
    return medida


def agregar(medidas):
    """Resume uma janela de medidas (ao menos uma) em uma linha com as 39 colunas."""
    n = len(medidas)
    linha = {coluna: sum(m[coluna] for m in medidas) / n for coluna in MEDIAS}

    contagem = Counter(m["Protocol Type"] for m in medidas)
    mais_frequente = max(contagem.values())
    linha["Protocol Type"] = min(p for p, vezes in contagem.items() if vezes == mais_frequente)

    for total, flag in CONTAGENS:
        linha[total] = sum(m[flag] for m in medidas)

    tamanhos = [m["Tot size"] for m in medidas]
    media = sum(tamanhos) / n
    # Variância amostral (n - 1). Com um só quadro não há variância, como no CSV oficial.
    variancia = sum((t - media) ** 2 for t in tamanhos) / (n - 1) if n > 1 else math.nan
    linha["Tot sum"] = sum(tamanhos)
    linha["Min"] = min(tamanhos)
    linha["Max"] = max(tamanhos)
    linha["AVG"] = media
    linha["Std"] = math.sqrt(variancia)
    linha["Variance"] = variancia
    linha["Number"] = n

    instantes = [m["ts"] for m in medidas]
    duracao = max(instantes) - min(instantes)
    linha["Rate"] = n / duracao if duracao else math.inf
    return {coluna: linha[coluna] for coluna in COLUNAS}


class Extrator:
    """Recebe quadros um a um e devolve uma linha de features a cada janela completa.

    Não sabe de onde os quadros vêm. Serve tanto para um arquivo pcap quanto para uma captura
    ao vivo que entregue (instante, quadro).
    """

    def __init__(self, janela=10):
        if janela < 1:
            raise ValueError("a janela precisa ter ao menos 1 quadro")
        self.janela = janela
        self.ignorados = 0
        self._pendentes = []
        self._ts_anterior = None

    def alimentar(self, ts, quadro):
        """Entrega um quadro. Devolve a linha da janela se ele a completou, senão None."""
        medida = medir_quadro(ts, quadro, self._ts_anterior)
        if medida is None:
            self.ignorados += 1
            return None
        self._ts_anterior = ts
        self._pendentes.append(medida)
        if len(self._pendentes) < self.janela:
            return None
        return self._fechar()

    def finalizar(self):
        """Devolve a linha da janela incompleta que sobrou, ou None se não sobrou nada."""
        return self._fechar() if self._pendentes else None

    def _fechar(self):
        linha = agregar(self._pendentes)
        self._pendentes = []
        return linha


def extrair(quadros, janela=10):
    """Gera as linhas de features de uma sequência de (instante, quadro)."""
    extrator = Extrator(janela)
    for ts, quadro in quadros:
        linha = extrator.alimentar(ts, quadro)
        if linha is not None:
            yield linha
    linha = extrator.finalizar()
    if linha is not None:
        yield linha


# Número mágico do pcap clássico: ordem dos bytes e divisor da fração de segundo.
_MAGICOS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6),
    b"\xa1\xb2\xc3\xd4": (">", 1e6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e9),
    b"\xa1\xb2\x3c\x4d": (">", 1e9),
}
_PCAPNG = b"\x0a\x0d\x0d\x0a"
_ETHERNET = 1
_AVISO_INCOMPLETO = (
    "pacote {} incompleto: a captura foi interrompida, e a leitura parou no último pacote inteiro"
)


def _ler_exato(fluxo, n):
    """Lê n bytes de um fluxo que pode entregar menos por chamada. Devolve menos só no fim."""
    partes = []
    while n > 0:
        parte = fluxo.read(n)
        if not parte:
            break
        partes.append(parte)
        n -= len(parte)
    return b"".join(partes)


def ler_pcap(origem):
    """Gera (instante, quadro) de um pcap, sem carregar o arquivo inteiro na memória.

    `origem` é um caminho ou um fluxo binário já aberto, como a entrada padrão. Se a captura
    foi interrompida no meio de um pacote, a leitura termina no último pacote completo e emite
    um aviso. Um registro com tamanho maior que o limite da captura indica arquivo corrompido.
    """
    if not hasattr(origem, "read"):
        with open(origem, "rb") as arquivo:
            yield from ler_pcap(arquivo)
        return
    cabecalho = _ler_exato(origem, 24)
    if cabecalho[:4] == _PCAPNG:
        raise ValueError(
            "a entrada está em pcapng; converta para pcap com: editcap -F pcap origem.pcapng destino.pcap"
        )
    if len(cabecalho) < 24 or cabecalho[:4] not in _MAGICOS:
        raise ValueError("a entrada não é um arquivo pcap")
    ordem, divisor = _MAGICOS[cabecalho[:4]]
    limite, enlace = struct.unpack(ordem + "II", cabecalho[16:24])
    if enlace != _ETHERNET:
        raise ValueError(f"a captura não é Ethernet (tipo de enlace {enlace}); capture em uma interface Ethernet ou Wi-Fi")
    numero = 0
    while True:
        registro = _ler_exato(origem, 16)
        if not registro:
            return
        numero += 1
        if len(registro) < 16:
            warnings.warn(_AVISO_INCOMPLETO.format(numero), stacklevel=2)
            return
        segundos, fracao, capturado, _ = struct.unpack(ordem + "IIII", registro)
        if limite and capturado > limite:
            raise ValueError(
                f"pacote {numero} com tamanho impossível ({capturado} bytes, limite da captura "
                f"{limite}): arquivo corrompido"
            )
        quadro = _ler_exato(origem, capturado)
        if len(quadro) < capturado:
            warnings.warn(_AVISO_INCOMPLETO.format(numero), stacklevel=2)
            return
        yield segundos + fracao / divisor, quadro


def _texto(valor):
    if isinstance(valor, float):
        return "" if math.isnan(valor) else repr(valor)
    return str(valor)


def gravar_csv(linhas, destino):
    """Grava as linhas no formato do CSV oficial e devolve quantas gravou."""
    escritor = csv.writer(destino, lineterminator="\n")
    escritor.writerow(COLUNAS)
    total = 0
    for linha in linhas:
        escritor.writerow([_texto(linha[coluna]) for coluna in COLUNAS])
        destino.flush()
        total += 1
    return total


def _mostrar_aviso(mensagem, *_resto, **_opcoes):
    print(f"aviso: {mensagem}", file=sys.stderr)


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.captura.extrator",
        description="Extrai as 39 features do CICIoT2023 de um arquivo pcap.",
    )
    analisador.add_argument("entrada", help="arquivo pcap, ou - para ler da entrada padrão")
    analisador.add_argument("saida", help="arquivo CSV de saída")
    analisador.add_argument(
        "--janela",
        type=int,
        default=10,
        help="quadros por linha: 10 (padrão) ou 100, como nas classes de flood do dataset",
    )
    try:
        argumentos = analisador.parse_args(argv)
    except SystemExit as encerramento:
        return encerramento.code
    entrada = sys.stdin.buffer if argumentos.entrada == "-" else argumentos.entrada
    with warnings.catch_warnings():
        warnings.simplefilter("always")
        warnings.showwarning = _mostrar_aviso
        try:
            with open(argumentos.saida, "w", newline="") as saida:
                total = gravar_csv(extrair(ler_pcap(entrada), argumentos.janela), saida)
        except (OSError, ValueError) as erro:
            print(f"erro: {erro}", file=sys.stderr)
            return 1
    print(f"{total} linhas gravadas em {argumentos.saida}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
