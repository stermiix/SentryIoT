"""Extrator de features do SentryIoT.

Transforma quadros Ethernet nas 39 features do CICIoT2023 (Neto et al., 2023). Cada linha
resume uma janela de quadros IPv4 ou ARP consecutivos. As regras de medição seguem o que o
código publicado pelos autores do dataset faz, para que o classificador receba em operação
os mesmos números com que foi treinado.

Uso, a partir da raiz do repositório:
    python -m codigo.captura.extrator entrada.pcap saida.csv
"""
import math
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
    # Quadro que o dpkt não decodifica é descartado, qualquer que seja o erro: um quadro
    # malformado não pode derrubar a extração. O código dos autores faz o mesmo.
    try:
        eth = dpkt.ethernet.Ethernet(quadro)
    except Exception:  # noqa: BLE001
        return None
    medida = dict.fromkeys(MEDIAS, 0)
    medida["Protocol Type"] = 0
    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        ip = eth.data
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
