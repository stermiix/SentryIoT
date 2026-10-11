"""Extrator de features do SentryIoT.

Transforma quadros Ethernet nas 39 features do CICIoT2023 (Neto et al., 2023). Cada linha
resume uma janela de quadros IPv4 ou ARP consecutivos. As regras de medição seguem o que o
código publicado pelos autores do dataset faz, para que o classificador receba em operação
os mesmos números com que foi treinado.

Com a opção `enderecos`, cada janela sai acompanhada dos endereços dos seus quadros: os MACs
e os IPs de origem e de destino, e os IPs que os quadros ARP anunciam como origem. É o que a
regeração dos dados de treino usa para saber se um atacante está na janela, e o que a resposta
precisa para saber quem bloquear. Sem a opção, a saída são só as 39 colunas.

As opções `preencher` e `limitar`, desligadas por padrão, medem o tamanho do quadro como ele
passa no fio, e não como a máquina que capturou o gravou (veja `como_no_fio`).

Uso, a partir da raiz do repositório:
    python -m codigo.captura.extrator entrada.pcap saida.csv
    python -m codigo.captura.extrator --janela 100 entrada.pcap saida.csv
    python -m codigo.captura.extrator --preencher --limitar entrada.pcap saida.csv
"""
import argparse
import csv
import itertools
import math
import operator
import os
import socket
import struct
import sys
import time
import warnings
from collections import Counter, namedtuple

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
# A medição só usa cabeçalhos, então basta decodificar o começo do quadro. Em alguns protocolos
# (SCTP, por exemplo) o dpkt gasta memória e tempo que crescem com o quadrado do tamanho do quadro.
PREFIXO_DECODIFICADO = 1600
JANELA_MAXIMA = 10_000
# Maior registro aceito num pcap: é o limite de captura mais alto do tcpdump e do Wireshark.
MAIOR_REGISTRO = 262_144
# O CSV é descarregado no disco a cada tantas linhas, ou depois de tantos segundos.
DESCARGA_LINHAS = 1000
DESCARGA_SEGUNDOS = 1.0
# Menor e maior quadro Ethernet no fio, sem o FCS e sem etiqueta de VLAN (MTU de 1500 bytes).
QUADRO_MINIMO = 60
QUADRO_MAXIMO = 1514
_CABECALHO_ETHERNET = 14

# Colunas que a janela resume pela média dos quadros.
MEDIAS = (
    "Header_Length", "Time_To_Live", *(nome for nome, _ in FLAGS), *INDICADORES, "Tot size", "IAT",
)

class Enderecos(namedtuple("Enderecos", ("macs_origem", "macs_destino", "conjunto_ips_origem",
                                         "conjunto_ips_destino", "ips_arp"), defaults=(frozenset(),))):
    """Os endereços de uma janela, cada campo um conjunto de textos.

    Os MACs vêm na grafia do Wireshark (minúsculas, separados por dois-pontos) e os IPs em
    notação decimal. `conjunto_ips_origem` e `conjunto_ips_destino` vêm do cabeçalho IPv4.
    `ips_arp` guarda à parte o IP de origem anunciado no corpo dos quadros ARP: no ARP spoofing
    é o IP que o atacante finge ser, e não o dele. As quantidades `ips_origem` e `ips_destino`,
    que a regeração grava, são derivadas dos conjuntos do IPv4.
    """

    __slots__ = ()

    @property
    def ips_origem(self):
        return len(self.conjunto_ips_origem)

    @property
    def ips_destino(self):
        return len(self.conjunto_ips_destino)


def como_no_fio(quadro, preencher=False, limitar=False):
    """O quadro com o tamanho que ele tem no fio, conforme as opções. Sem nenhuma, não muda nada.

    `preencher` completa com zeros até 60 bytes o quadro Ethernet menor que isso, como a placa de
    rede faz antes de transmitir. Quem captura na própria máquina que envia grava o quadro antes
    desse preenchimento. Os dois pcaps de spoofing do CICIoT2023 (DNS_Spoofing e
    MITM-ArpSpoofing) foram capturados assim: 84% das suas janelas de 100 quadros têm quadro
    menor que 60 bytes, contra nenhuma nos pcaps benignos (no Mirai-greip_flood21, 10%). Com
    isso o modelo pode reconhecer a configuração da captura, e não o ataque. Um registro com
    menos de 14 bytes não chega a ser um quadro Ethernet e fica como está.

    `limitar` faz o quadro maior que 1514 bytes contar como 1514. Quadro assim não existe no fio:
    é a placa da máquina que capturou juntando vários segmentos TCP num só (offload de
    segmentação). Ele aparece em 80% a 93% das janelas de 100 quadros dos pcaps benignos e em
    nenhuma das de spoofing. O quadro é cortado nos primeiros 1514 bytes, que trazem todos os
    cabeçalhos medidos.

    As duas opções juntas medem o quadro como ele passa no fio. Ficam desligadas por padrão
    porque o código dos autores não faz nenhuma das duas coisas, e o extrator precisa reproduzir
    os números com que o modelo publicado foi treinado. Ligar ou não no treino e na operação, e
    regerar os dados de treino com elas, é uma decisão da equipe ainda em aberto; o que importa é
    usar a mesma escolha nos dois lugares.
    """
    if preencher and _CABECALHO_ETHERNET <= len(quadro) < QUADRO_MINIMO:
        quadro = quadro + bytes(QUADRO_MINIMO - len(quadro))
    if limitar and len(quadro) > QUADRO_MAXIMO:
        quadro = quadro[:QUADRO_MAXIMO]
    return quadro


def medir_quadro(ts, quadro, ts_anterior=None, preencher=False, limitar=False):
    """Mede um quadro Ethernet.

    Devolve um dicionário com as colunas de MEDIAS, mais "Protocol Type", "ts" e os endereços
    do quadro: "mac_origem" e "mac_destino" em texto; "ip_origem" e "ip_destino" em bytes, ou
    None fora do IPv4; "ip_arp", o IP de origem anunciado num ARP de IPv4 sobre Ethernet, em
    bytes, ou None. Devolve None se o quadro não entra na conta: não é IPv4 nem ARP, ou não pôde
    ser decodificado. `preencher` e `limitar` são as opções de `como_no_fio`.
    """
    quadro = como_no_fio(quadro, preencher, limitar)
    # Quadro que o dpkt não decodifica como Ethernet é descartado, qualquer que seja o erro:
    # um quadro malformado não pode derrubar a extração. O código dos autores também o descarta.
    try:
        eth = dpkt.ethernet.Ethernet(quadro[:PREFIXO_DECODIFICADO])
    except Exception:  # noqa: BLE001
        return None
    medida = dict.fromkeys(MEDIAS, 0)
    medida["Protocol Type"] = 0
    medida["ip_origem"] = medida["ip_destino"] = medida["ip_arp"] = None
    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        ip = eth.data
        # IPv4 com cabeçalho ilegível: o dpkt devolve os bytes crus. Aqui o quadro é ignorado;
        # no código dos autores ele interrompe o processamento do pedaço inteiro.
        if not isinstance(ip, dpkt.ip.IP):
            return None
        medida["Protocol Type"] = ip.p
        medida["ip_origem"], medida["ip_destino"] = ip.src, ip.dst
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
        arp = eth.data
        # O dpkt lê os endereços do ARP em posições fixas, que só valem para Ethernet e IPv4.
        if isinstance(arp, dpkt.arp.ARP) and (arp.pro, arp.hln, arp.pln) == (dpkt.ethernet.ETH_TYPE_IP, 6, 4):
            medida["ip_arp"] = arp.spa
    else:
        return None
    medida["Tot size"] = len(quadro)
    medida["IAT"] = 0.0 if ts_anterior is None else ts - ts_anterior
    medida["ts"] = ts
    medida["mac_destino"], medida["mac_origem"] = quadro[:6].hex(":"), quadro[6:12].hex(":")
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


def _ips(medidas, campo):
    """Os IPs distintos de um campo das medidas, em texto. Converte cada IP uma vez só."""
    return frozenset(socket.inet_ntoa(ip) for ip in {m[campo] for m in medidas} - {None})


def enderecos(medidas):
    """Os endereços de uma janela de medidas: MACs e IPs de origem e de destino e IPs do ARP."""
    return Enderecos(
        frozenset(m["mac_origem"] for m in medidas),
        frozenset(m["mac_destino"] for m in medidas),
        _ips(medidas, "ip_origem"),
        _ips(medidas, "ip_destino"),
        _ips(medidas, "ip_arp"),
    )


class Extrator:
    """Recebe quadros um a um e devolve uma linha de features a cada janela completa.

    Não sabe de onde os quadros vêm. Serve tanto para um arquivo pcap quanto para uma captura
    ao vivo que entregue (instante, quadro). Com `enderecos`, cada janela sai como o par
    (linha, Enderecos), em vez de só a linha. `preencher` e `limitar` são as opções de
    `como_no_fio`, aplicadas a cada quadro entregue por `alimentar`; desligadas, o extrator
    reproduz o código dos autores.

    `ignorados` conta os quadros que ficaram fora do filtro, e `ignorados_por_tipo` os separa
    pelo tipo Ethernet, quando o quadro chega por `alimentar`.
    """

    def __init__(self, janela=10, enderecos=False, preencher=False, limitar=False):
        # A janela guarda os quadros até fechar, então a memória cresce com ela. Um número com
        # parte decimal ou um booleano não é tamanho de janela.
        if isinstance(janela, bool) or not hasattr(type(janela), "__index__"):
            raise TypeError("a janela precisa ser um número inteiro")
        janela = operator.index(janela)
        if not 1 <= janela <= JANELA_MAXIMA:
            raise ValueError(f"a janela precisa ter entre 1 e {JANELA_MAXIMA} quadros")
        self.janela = janela
        self.enderecos = enderecos
        self.preencher = preencher
        self.limitar = limitar
        self.ignorados = 0
        self.ignorados_por_tipo = Counter()
        self._pendentes = []
        self._ts_anterior = None

    def alimentar(self, ts, quadro):
        """Entrega um quadro. Devolve a janela se ele a completou, senão None."""
        ts = float(ts)
        if not math.isfinite(ts):
            raise ValueError("o instante do quadro precisa ser um número finito")
        medida = medir_quadro(ts, quadro, self._ts_anterior, self.preencher, self.limitar)
        if medida is None:
            self.ignorados_por_tipo[tipo_ethernet(quadro)] += 1
        return self.acumular(medida)

    def acumular(self, medida):
        """Entrega um quadro já medido por `medir_quadro`, ou None se ele ficou fora do filtro.

        Serve para alimentar vários extratores com uma medição só, quando um pcap é lido com
        mais de um tamanho de janela. Devolve a janela se o quadro a completou, senão None.
        """
        if medida is None:
            self.ignorados += 1
            return None
        self._ts_anterior = medida["ts"]
        self._pendentes.append(medida)
        if len(self._pendentes) < self.janela:
            return None
        return self._fechar()

    def finalizar(self):
        """Devolve a janela incompleta que sobrou, ou None se não sobrou nada."""
        return self._fechar() if self._pendentes else None

    def _fechar(self):
        linha = agregar(self._pendentes)
        if self.enderecos:
            linha = (linha, enderecos(self._pendentes))
        self._pendentes = []
        return linha


def extrair(quadros, janela=10, enderecos=False, preencher=False, limitar=False):
    """Gera as janelas de uma sequência de (instante, quadro): as linhas de features ou, com
    `enderecos`, os pares (linha, Enderecos). `preencher` e `limitar` são as de `como_no_fio`."""
    yield from _janelas(Extrator(janela, enderecos, preencher, limitar), quadros)


def _janelas(extrator, quadros):
    for ts, quadro in quadros:
        linha = extrator.alimentar(ts, quadro)
        if linha is not None:
            yield linha
    linha = extrator.finalizar()
    if linha is not None:
        yield linha


class CapturaIncompleta(UserWarning):
    """Aviso de `ler_pcap`: a captura terminou no meio de um pacote.

    Tem categoria própria para que quem lê um pcap registre só os avisos da leitura, e não os de
    outro código que por acaso cheguem no mesmo intervalo, como um ResourceWarning.
    """


# Número mágico do pcap clássico: ordem dos bytes e quantas unidades da fração de segundo formam
# um microssegundo.
_MAGICOS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1),
    b"\xa1\xb2\xc3\xd4": (">", 1),
    b"\x4d\x3c\xb2\xa1": ("<", 1000),
    b"\xa1\xb2\x3c\x4d": (">", 1000),
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


def ler_pcap(origem, contagem=None):
    """Gera (instante, quadro) de um pcap, sem carregar o arquivo inteiro na memória.

    `origem` é um caminho ou um fluxo binário já aberto, como a entrada padrão. Se a captura
    foi interrompida no meio de um pacote, a leitura termina no último pacote completo e emite
    um aviso `CapturaIncompleta`. Um registro maior que o limite de captura declarado no
    cabeçalho é entregue cortado nesse limite, como faz a libpcap. Acima do maior registro
    aceito, o arquivo é recusado.

    O instante de um pcap em nanossegundos é truncado para microssegundos, como o `tcpdump -r
    ... -w` com que os autores fatiaram os pcaps grava: o modelo foi treinado com instantes em
    microssegundos, e uma rajada dentro do mesmo microssegundo dá `Rate` infinito nos dois casos.

    Com `contagem`, um `collections.Counter`, a leitura soma nele "menor_que_o_original": os
    registros gravados com menos bytes que o quadro original, sinal de captura com limite curto
    (`tcpdump -s`). Nesses registros as colunas de tamanho saem menores do que seriam.
    """
    if not hasattr(origem, "read"):
        with open(origem, "rb") as arquivo:
            yield from ler_pcap(arquivo, contagem)
        return
    cabecalho = _ler_exato(origem, 24)
    if cabecalho[:4] == _PCAPNG:
        raise ValueError(
            "a entrada está em pcapng; converta para pcap com: editcap -F pcap origem.pcapng destino.pcap"
        )
    if len(cabecalho) < 24 or cabecalho[:4] not in _MAGICOS:
        raise ValueError("a entrada não é um arquivo pcap")
    ordem, por_microssegundo = _MAGICOS[cabecalho[:4]]
    limite, enlace = struct.unpack(ordem + "II", cabecalho[16:24])
    limite = min(limite or MAIOR_REGISTRO, MAIOR_REGISTRO)
    if enlace != _ETHERNET:
        raise ValueError(f"a captura não é Ethernet (tipo de enlace {enlace}); capture em uma interface Ethernet ou Wi-Fi")
    numero = 0
    while True:
        registro = _ler_exato(origem, 16)
        if not registro:
            return
        numero += 1
        if len(registro) < 16:
            warnings.warn(_AVISO_INCOMPLETO.format(numero), CapturaIncompleta, stacklevel=2)
            return
        segundos, fracao, capturado, original = struct.unpack(ordem + "IIII", registro)
        if capturado > MAIOR_REGISTRO:
            raise ValueError(
                f"pacote {numero} com tamanho impossível ({capturado} bytes, limite de {MAIOR_REGISTRO}): "
                "arquivo corrompido"
            )
        quadro = _ler_exato(origem, capturado)
        if len(quadro) < capturado:
            warnings.warn(_AVISO_INCOMPLETO.format(numero), CapturaIncompleta, stacklevel=2)
            return
        if contagem is not None and capturado < original:
            contagem["menor_que_o_original"] += 1
        # O tcpdump dos autores lê com a libpcap, que só entrega os bytes até o limite declarado.
        yield segundos + (fracao // por_microssegundo) / 1e6, quadro[:limite]


def _texto(valor):
    if isinstance(valor, float):
        return "" if math.isnan(valor) else repr(valor)
    return str(valor)


def gravar_csv(linhas, destino, a_cada=DESCARGA_LINHAS, segundos=DESCARGA_SEGUNDOS):
    """Grava as linhas no formato do CSV oficial e devolve quantas gravou.

    Descarrega o arquivo a cada `a_cada` linhas, ou na primeira linha depois de `segundos` sem
    descarregar, e no fim. Numa captura ao vivo lenta cada linha chega ao disco logo; num pcap
    grande o arquivo não é descarregado a cada linha, o que custava tempo.
    """
    escritor = csv.writer(destino, lineterminator="\n")
    escritor.writerow(COLUNAS)
    total = 0
    ultima_descarga = time.monotonic()
    for linha in linhas:
        escritor.writerow([_texto(linha[coluna]) for coluna in COLUNAS])
        total += 1
        agora = time.monotonic()
        if total % a_cada == 0 or agora - ultima_descarga >= segundos:
            destino.flush()
            ultima_descarga = agora
    destino.flush()
    return total


# Tipos Ethernet das etiquetas de VLAN: 802.1Q e 802.1ad (QinQ). O dpkt não as retira, e o quadro
# com etiqueta fica fora do filtro, como no código dos autores.
TIPOS_VLAN = (0x8100, 0x88A8)
NOMES_DE_TIPO = {
    0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "VLAN 802.1Q", 0x88A8: "VLAN 802.1ad (QinQ)",
    0x9000: "teste de enlace (loopback)",
}


def tipo_ethernet(quadro):
    """O tipo Ethernet do quadro, ou -1 se ele tem menos de 14 bytes."""
    return struct.unpack(">H", quadro[12:14])[0] if len(quadro) >= _CABECALHO_ETHERNET else -1


def nome_do_tipo(tipo):
    """Nome legível de um tipo Ethernet, para relatórios e mensagens."""
    if tipo in NOMES_DE_TIPO:
        return NOMES_DE_TIPO[tipo]
    if tipo < 0:
        return "quadro com menos de 14 bytes"
    if tipo < 0x0600:
        return "IEEE 802.3 com LLC (STP e afins)"
    return f"0x{tipo:04x}"


def _mostrar_avisos_da_leitura(mostrar_outros):
    """Mostra o aviso da leitura do pcap como "aviso: ..." e entrega os demais ao Python."""

    def mostrar(mensagem, categoria, *resto, **opcoes):
        if issubclass(categoria, CapturaIncompleta):
            print(f"aviso: {mensagem}", file=sys.stderr)
        else:
            mostrar_outros(mensagem, categoria, *resto, **opcoes)

    return mostrar


def _resumir_quadros(extrator, contagem):
    """Mensagens do fim da extração: quadros fora do filtro, VLAN e limite de captura curto."""
    mensagens = []
    if extrator.ignorados:
        partes = []
        for tipo, quantos in extrator.ignorados_por_tipo.most_common():
            nome = nome_do_tipo(tipo)
            if tipo in (dpkt.ethernet.ETH_TYPE_IP, dpkt.ethernet.ETH_TYPE_ARP):
                nome += " que não pôde ser decodificado"
            partes.append(f"{nome}: {quantos}")
        mensagens.append(
            f"{extrator.ignorados} quadros ficaram fora (só IPv4 e ARP entram na conta): " + "; ".join(partes)
        )
        com_vlan = sum(extrator.ignorados_por_tipo[tipo] for tipo in TIPOS_VLAN)
        if 2 * com_vlan > extrator.ignorados:
            mensagens.append(
                f"aviso: {com_vlan} dos {extrator.ignorados} quadros fora têm etiqueta de VLAN (802.1Q ou "
                "802.1ad), que o código dos autores também descarta; retire as etiquetas na captura "
                "(por exemplo, espelhando a porta sem a VLAN ou capturando na interface da VLAN)"
            )
    if contagem["menor_que_o_original"]:
        mensagens.append(
            f"aviso: {contagem['menor_que_o_original']} pacotes foram gravados com menos bytes que o quadro "
            "original (limite de captura curto), e as colunas de tamanho saem menores do que no treino; "
            "capture o quadro inteiro, com tcpdump -s 0"
        )
    return mensagens


def _janela(texto):
    try:
        valor = int(texto)
    except ValueError:
        raise argparse.ArgumentTypeError("a janela precisa ser um número inteiro") from None
    if not 1 <= valor <= JANELA_MAXIMA:
        raise argparse.ArgumentTypeError(f"a janela precisa estar entre 1 e {JANELA_MAXIMA}")
    return valor


def _mesmo_arquivo(entrada, saida):
    return entrada != "-" and os.path.exists(saida) and os.path.samefile(entrada, saida)


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.captura.extrator",
        description="Extrai as 39 features do CICIoT2023 de um arquivo pcap.",
    )
    analisador.add_argument("entrada", help="arquivo pcap, ou - para ler da entrada padrão")
    analisador.add_argument("saida", help="arquivo CSV de saída")
    analisador.add_argument(
        "--janela",
        type=_janela,
        default=10,
        help="quadros por linha: 10 (padrão) ou 100, como nas classes de flood do dataset",
    )
    analisador.add_argument(
        "--preencher",
        action="store_true",
        help=f"completa com zeros até {QUADRO_MINIMO} bytes o quadro menor que isso, como no fio "
        "(desligado por padrão, como no código dos autores)",
    )
    analisador.add_argument(
        "--limitar",
        action="store_true",
        help=f"conta como {QUADRO_MAXIMO} bytes o quadro maior que isso, que só existe com offload de "
        "segmentação na máquina que capturou (desligado por padrão, como no código dos autores)",
    )
    try:
        argumentos = analisador.parse_args(argv)
    except SystemExit as encerramento:
        return encerramento.code
    contagem = Counter()
    extrator = Extrator(argumentos.janela, preencher=argumentos.preencher, limitar=argumentos.limitar)
    with warnings.catch_warnings():
        # Só o aviso da leitura sai como "aviso: ..."; os de outro código seguem os filtros do Python.
        warnings.simplefilter("always", CapturaIncompleta)
        warnings.showwarning = _mostrar_avisos_da_leitura(warnings.showwarning)
        try:
            if _mesmo_arquivo(argumentos.entrada, argumentos.saida):
                raise ValueError("a entrada e a saída são o mesmo arquivo")
            entrada = sys.stdin.buffer if argumentos.entrada == "-" else argumentos.entrada
            # Lê o primeiro quadro antes de abrir a saída: se a entrada não existe ou não é um
            # pcap, o arquivo de saída não chega a ser criado nem sobrescrito.
            quadros = ler_pcap(entrada, contagem)
            primeiro = list(itertools.islice(quadros, 1))
            with open(argumentos.saida, "w", newline="") as saida:
                total = gravar_csv(_janelas(extrator, itertools.chain(primeiro, quadros)), saida)
        except (OSError, ValueError) as erro:
            print(f"erro: {erro}", file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            print("interrompido: as linhas já gravadas ficam no arquivo de saída", file=sys.stderr)
            return 130
    print(f"{total} linhas gravadas em {argumentos.saida}", file=sys.stderr)
    for mensagem in _resumir_quadros(extrator, contagem):
        print(mensagem, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
