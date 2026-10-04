"""Testes de robustez do extrator: entradas aleatórias ou adulteradas e propriedades das linhas.

Tudo é sorteado com semente fixa, então uma falha se repete igual em qualquer máquina.
"""
import io
import math
import random
import re
import struct
import tracemalloc
import warnings

import dpkt
import pytest

from codigo.captura.calibrar import ler_oficial
from codigo.captura.extrator import (
    COLUNAS,
    Extrator,
    agregar,
    extrair,
    gravar_csv,
    ler_pcap,
    medir_quadro,
)
from codigo.captura.test_extrator import (
    MACS,
    PCAP_BE,
    PCAP_LE,
    PCAP_NANO,
    eth,
    pcap,
    quadro_tcp,
    quadro_udp,
    tcp,
    udp,
)

FLAGS = tuple(c for c in COLUNAS if c.endswith("_flag_number"))
CONTAGENS = tuple(c for c in COLUNAS if c.endswith("_count"))
INDICADORES = (
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP",
    "ARP", "ICMP", "IGMP", "IPv", "LLC",
)
SO_EM_TCP = (*FLAGS, "HTTP", "HTTPS", "Telnet", "SMTP", "SSH", "IRC")
# Colunas que só existem na linha da janela. O resto, mais o instante, vem de cada quadro.
SO_NA_JANELA = ("Rate", *CONTAGENS, "Tot sum", "Min", "Max", "AVG", "Std", "Number", "Variance")
CHAVES_DA_MEDIDA = {*(c for c in COLUNAS if c not in SO_NA_JANELA), "ts"}

PCAP_NANO_BE = b"\xa1\xb2\x3c\x4d"
MAGICOS = (PCAP_LE, PCAP_BE, PCAP_NANO, PCAP_NANO_BE)
PORTAS = (21, 22, 23, 25, 53, 67, 68, 80, 443, 8080, 40000)
TIPOS = ("tcp", "udp", "icmp", "igmp", "arp", "ipv6", "llc", "vlan")
PESOS = (40, 22, 8, 4, 10, 6, 4, 6)


def pacote_ip(protocolo, carga, opcoes=b"", ttl=64, fragmento=0):
    """Pacote IPv4. `opcoes` tem tamanho múltiplo de 4; `fragmento` é o campo de flags e deslocamento."""
    cabecalho = struct.pack(
        ">BBHHHBBH4s4s", 0x40 | (5 + len(opcoes) // 4), 0, 20 + len(opcoes) + len(carga), 1, fragmento,
        ttl, protocolo, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
    )
    return cabecalho + opcoes + carga


def com_vlan(quadro, dupla=False):
    """Põe no quadro uma etiqueta 802.1Q, ou duas (QinQ, com 802.1ad por fora)."""
    etiqueta = b"\x81\x00" + struct.pack(">H", 100)
    if dupla:
        etiqueta = b"\x88\xa8" + struct.pack(">H", 200) + etiqueta
    return quadro[:12] + etiqueta + quadro[12:]


def quadro_sorteado(sorteio):
    """Quadro bem formado de um tipo sorteado. IPv6, 802.3 com LLC e VLAN ficam fora do filtro."""
    tipo = sorteio.choices(TIPOS, PESOS)[0]
    ttl = sorteio.choice((1, 64, 128, 255))
    opcoes_ip = bytes(4 * sorteio.choice((0, 0, 0, 1, 10)))
    dados = sorteio.randbytes(sorteio.choice((0, 0, 6, 100, 1400)))
    if tipo == "tcp":
        opcoes = sorteio.randbytes(4 * sorteio.choice((0, 0, 1, 3, 10)))
        carga = tcp(sorteio.choice(PORTAS), sorteio.choice(PORTAS), sorteio.randrange(256), opcoes, dados)
        return eth(0x0800, pacote_ip(6, carga, opcoes_ip, ttl))
    if tipo == "udp":
        carga = udp(sorteio.choice(PORTAS), sorteio.choice(PORTAS), dados)
        return eth(0x0800, pacote_ip(17, carga, opcoes_ip, ttl))
    if tipo == "icmp":
        return eth(0x0800, pacote_ip(1, b"\x08\x00\x00\x00\x00\x01\x00\x01" + dados, opcoes_ip, ttl))
    if tipo == "igmp":
        return eth(0x0800, pacote_ip(2, b"\x11\x64\x00\x00\x00\x00\x00\x00", opcoes_ip, ttl))
    if tipo == "arp":
        return eth(0x0806, struct.pack(">HHBBH", 1, 0x0800, 6, 4, sorteio.choice((1, 2))) + bytes(20))
    if tipo == "ipv6":
        return eth(0x86DD, b"\x60" + bytes(39))
    if tipo == "llc":
        return eth(0x0027, b"\x42\x42\x03" + bytes(36))
    return com_vlan(eth(0x0800, pacote_ip(17, udp(40000, 53, dados))), dupla=sorteio.random() < 0.5)


def registros_sorteados(sorteio, quantidade, voltar_no_tempo=True):
    """Registros (segundos, microssegundos, quadro) com intervalos variados, nulos e negativos.

    Os instantes ficam perto de 1,7 bilhão de segundos, como numa captura real, e nunca valem zero.
    """
    passos = (0, 1, 250, 10_000, 1_500_000) + ((-300_000,) if voltar_no_tempo else ())
    instante = 1_700_000_000_000_000
    registros = []
    for _ in range(quantidade):
        instante += sorteio.choice(passos)
        registros.append((instante // 1_000_000, instante % 1_000_000, quadro_sorteado(sorteio)))
    return registros


def como_quadros(registros):
    """Os pares (instante, quadro) que o leitor de pcap entrega para esses registros."""
    return [(segundos + micros / 1e6, quadro) for segundos, micros, quadro in registros]


def adulterar(sorteio, quadro):
    """Devolve o quadro com um defeito sorteado: bytes trocados, bit virado, corte, sobra ou campo extremo."""
    dados = bytearray(quadro)
    # Os defeitos caem quase sempre nos cabeçalhos, que é onde eles mudam a decodificação.
    alcance = min(len(dados), sorteio.choice((14, 34, 74, len(dados))))
    defeito = sorteio.randrange(5)
    if defeito == 0 and alcance:
        for _ in range(sorteio.randint(1, 4)):
            dados[sorteio.randrange(alcance)] = sorteio.randrange(256)
    elif defeito == 1 and alcance:
        dados[sorteio.randrange(alcance)] ^= 1 << sorteio.randrange(8)
    elif defeito == 2:
        del dados[sorteio.randrange(len(dados) + 1):]
    elif defeito == 3:
        dados += sorteio.randbytes(sorteio.randint(1, 40))
    elif alcance:
        posicao = sorteio.randrange(alcance)
        dados[posicao:posicao + 2] = sorteio.choice((b"\x00\x00", b"\xff\xff", b"\x00\x01", b"\x7f\xff"))
    return bytes(dados)


def conferir_medida(ts, quadro, ts_anterior=None):
    """Mede o quadro e confere o formato e as faixas do resultado. Devolve a medida, ou None."""
    medida = medir_quadro(ts, quadro, ts_anterior)
    if medida is None:
        return None
    assert set(medida) == CHAVES_DA_MEDIDA
    for nome in (*FLAGS, *INDICADORES):
        assert isinstance(medida[nome], int) and medida[nome] in (0, 1), (nome, quadro.hex())
    assert medida["Tot size"] == len(quadro)
    assert medida["ts"] == ts
    assert medida["IAT"] == (0.0 if ts_anterior is None else ts - ts_anterior)
    assert 0 <= medida["Protocol Type"] <= 255, quadro.hex()
    assert 0 <= medida["Time_To_Live"] <= 255, quadro.hex()
    assert medida["IPv"] + medida["ARP"] == 1, quadro.hex()
    assert medida["LLC"] == medida["IPv"], quadro.hex()
    assert medida["ICMP"] == int(medida["IPv"] == 1 and medida["Protocol Type"] == 1), quadro.hex()
    assert medida["IGMP"] == int(medida["IPv"] == 1 and medida["Protocol Type"] == 2), quadro.hex()
    if medida["TCP"]:
        assert medida["Protocol Type"] == 6 and 20 <= medida["Header_Length"] <= 60, quadro.hex()
    else:
        assert not any(medida[nome] for nome in SO_EM_TCP), quadro.hex()
    if medida["UDP"]:
        assert medida["Protocol Type"] == 17 and medida["Header_Length"] == 8, quadro.hex()
    else:
        assert medida["DNS"] == 0 and medida["DHCP"] == 0, quadro.hex()
    if not medida["TCP"] and not medida["UDP"]:
        assert medida["Header_Length"] == 0, quadro.hex()
    if medida["ARP"]:
        assert medida["Protocol Type"] == 0 and medida["Time_To_Live"] == 0, quadro.hex()
    return medida


TIPOS_DE_QUADRO = (0x0800, 0x0806, 0x8100, 0x88A8, 0x86DD, 0x8847, 0x8864, 0x2000, 0x0000, 0x05DC)
PROTOCOLOS_IP = (1, 2, 4, 6, 6, 6, 17, 17, 41, 47, 132)


def bytes_com_cara_de_quadro(sorteio):
    """Bytes aleatórios, na maior parte das vezes com alguns campos de cabeçalho plausíveis."""
    quadro = bytearray(sorteio.randbytes(sorteio.choice((0, 1, 13, 14, 20, 34, 54, 60, 200))))
    if sorteio.random() < 0.8:
        quadro[:0] = MACS + struct.pack(">H", sorteio.choice(TIPOS_DE_QUADRO))
    if sorteio.random() < 0.6 and len(quadro) >= 34:
        # Campos do IPv4: versão e tamanho do cabeçalho, sem fragmentação, protocolo conhecido.
        quadro[14] = 0x40 | sorteio.randint(5, 15)
        quadro[20:22] = sorteio.choice((b"\x00\x00", b"\x40\x00", b"\x20\x00", b"\x00\x01"))
        quadro[23] = sorteio.choice(PROTOCOLOS_IP)
    return bytes(quadro)


@pytest.mark.parametrize("semente", range(8))
def test_bytes_aleatorios_nunca_derrubam_a_medicao(semente):
    sorteio = random.Random(semente)
    vistos = set()
    for _ in range(2500):
        quadro = bytes_com_cara_de_quadro(sorteio)
        medida = conferir_medida(sorteio.uniform(1.0, 2e9), quadro, sorteio.uniform(1.0, 2e9))
        vistos.add(None if medida is None else (medida["TCP"], medida["UDP"], medida["ARP"]))
    # O sorteio tem de chegar a todos os desfechos: descartado, TCP, UDP, ARP e outro IPv4.
    assert vistos == {None, (1, 0, 0), (0, 1, 0), (0, 0, 1), (0, 0, 0)}


@pytest.mark.parametrize("semente", range(8))
def test_quadros_validos_adulterados_nunca_derrubam_a_medicao(semente):
    sorteio = random.Random(1000 + semente)
    vistos = set()
    for _ in range(1500):
        quadro = quadro_sorteado(sorteio)
        for _ in range(sorteio.randint(1, 3)):
            quadro = adulterar(sorteio, quadro)
        medida = conferir_medida(1.5, quadro)
        vistos.add(None if medida is None else (medida["TCP"], medida["UDP"], medida["ARP"]))
    assert vistos == {None, (1, 0, 0), (0, 1, 0), (0, 0, 1), (0, 0, 0)}


def ip_dentro_de_ip(niveis):
    """IPv4 que carrega IPv4 (protocolo 4), `niveis` vezes: o dpkt decodifica um dentro do outro."""
    pacote = b""
    for _ in range(niveis):
        pacote = pacote_ip(4, pacote)
    return pacote


ENCAPSULAMENTOS = {
    "ip_em_ip_3000_niveis": eth(0x0800, ip_dentro_de_ip(3000)),  # estoura a recursão do dpkt
    "ip_em_ip_40_niveis": eth(0x0800, ip_dentro_de_ip(40)),
    "gre_em_gre": eth(0x0800, pacote_ip(47, bytes(4) + pacote_ip(47, bytes(64)))),
    "ipv6_cortado_em_ipv4": eth(0x0800, pacote_ip(41, b"\x60" + bytes(7))),
    "sctp_com_pedacos_de_1_byte": eth(0x0800, pacote_ip(132, bytes(12) + b"\x00\x00\x00\x01" * 8)),
    "tcp_cortado_antes_das_flags": eth(0x0800, pacote_ip(6, tcp(1, 2, 0)[:13])),
    "tcp_com_offset_zero": eth(0x0800, pacote_ip(6, b"\x00\x50\x00\x50" + bytes(16))),
    "udp_com_3_bytes": eth(0x0800, pacote_ip(17, b"\x00\x35\x00")),
    "opcoes_ip_alem_do_fim": eth(0x0800, b"\x4f" + bytes(19)),
    "mpls_sem_rotulo": eth(0x8847, b""),
    "mpls_sem_carga": eth(0x8847, b"\x00\x00\x01\xff"),
    "tres_etiquetas_de_vlan": com_vlan(com_vlan(com_vlan(quadro_tcp()))),
    "cisco_isl": b"\x01\x00\x0c\x00\x00" + bytes(21) + quadro_tcp(),
    "novell_802_3_puro": MACS + b"\x00\x04\xff\xff",
    "snap_anunciando_ipv4": MACS + b"\x00\x08\xaa\xaa\x03\x00\x00\x00\x08\x00",
    "arp_sem_corpo": eth(0x0806, b""),
}


@pytest.mark.parametrize("nome", list(ENCAPSULAMENTOS))
def test_encapsulamentos_incomuns_nao_derrubam_a_medicao(nome):
    medida = conferir_medida(2.0, ENCAPSULAMENTOS[nome], 1.0)
    assert medida is None or medida["IAT"] == 1.0


def test_memoria_da_medicao_e_proporcional_ao_quadro():
    # Quadro de 16 kB com 4000 pedaços SCTP de 4 bytes (tipo DATA, tamanho declarado 1).
    quadro = eth(0x0800, pacote_ip(132, bytes(12) + b"\x00\x00\x00\x01" * 4000))
    tracemalloc.start()
    try:
        assert conferir_medida(1.0, quadro)["Protocol Type"] == 132
        _, pico = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert pico < 64 * len(quadro)


def limite_declarado(dados):
    """Limite de captura do cabeçalho, ou None se os bytes não começam como um pcap Ethernet."""
    if len(dados) < 24 or dados[:4] not in MAGICOS:
        return None
    ordem = ">" if dados[:1] == b"\xa1" else "<"
    limite, enlace = struct.unpack(ordem + "II", dados[16:24])
    return limite if enlace == 1 else None


def ler_tudo(fluxo):
    """Consome o leitor e devolve (quadros, avisos, erro). Só ValueError é aceito como erro."""
    quadros, erro = [], None
    with warnings.catch_warnings(record=True) as avisos:
        warnings.simplefilter("always")
        try:
            for ts, quadro in ler_pcap(fluxo):
                quadros.append((ts, quadro))
        except ValueError as falha:
            erro = falha
    return quadros, avisos, erro


def conferir_leitura(dados):
    """Lê os bytes como pcap e confere que o desfecho é um dos três previstos."""
    quadros, avisos, erro = ler_tudo(io.BytesIO(dados))
    limite = limite_declarado(dados)
    if limite is None:
        assert erro is not None and not quadros and not avisos, dados.hex()
        return quadros, avisos, erro
    assert all(issubclass(aviso.category, UserWarning) for aviso in avisos), dados.hex()
    assert len(avisos) + (erro is not None) <= 1, dados.hex()
    consumido = 24
    for ts, quadro in quadros:
        assert isinstance(ts, float) and math.isfinite(ts) and ts >= 0, dados.hex()
        assert isinstance(quadro, bytes), dados.hex()
        assert limite == 0 or len(quadro) <= limite, dados.hex()
        consumido += 16 + len(quadro)
    # Com aviso, sobrou um registro pela metade. No fim limpo, nada sobrou. Com erro, a leitura
    # parou depois do cabeçalho de um registro.
    if avisos:
        assert consumido < len(dados), dados.hex()
    elif erro is None:
        assert consumido == len(dados), dados.hex()
    else:
        assert consumido + 16 <= len(dados), dados.hex()
    return quadros, avisos, erro


def fluxo_sorteado(sorteio):
    """Bytes parecidos com um pcap: registros íntegros, cortados, com tamanho absurdo ou com lixo."""
    magico = sorteio.choice(MAGICOS)
    ordem = ">" if magico[:1] == b"\xa1" else "<"
    limite = sorteio.choice((0, 1, 60, 65535, 262144, 0x7FFFFFFF, 0xFFFFFFFF))
    enlace = sorteio.choice((1, 1, 1, 1, 1, 0, 113))
    dados = bytearray(magico + struct.pack(ordem + "HHiIII", 2, 4, 0, 0, limite, enlace))
    for _ in range(sorteio.randrange(8)):
        quadro = sorteio.randbytes(sorteio.choice((0, 1, 14, 60, 200)))
        declarado = sorteio.choice((len(quadro),) * 6 + (0, len(quadro) + 1, 61, 0x7FFFFFFF, 0xFFFFFFFF))
        instante = (sorteio.getrandbits(32), sorteio.getrandbits(32))
        dados += struct.pack(ordem + "IIII", *instante, declarado, sorteio.getrandbits(32)) + quadro
    defeito = sorteio.randrange(4)
    if defeito == 0:
        del dados[sorteio.randrange(len(dados) + 1):]
    elif defeito == 1:
        for _ in range(sorteio.randint(1, 4)):
            dados[sorteio.randrange(len(dados))] = sorteio.randrange(256)
    elif defeito == 2:
        dados += sorteio.randbytes(sorteio.randint(1, 40))
    return bytes(dados)


@pytest.mark.parametrize("semente", range(8))
def test_fluxos_aleatorios_terminam_em_fim_aviso_ou_erro_de_valor(semente):
    sorteio = random.Random(2000 + semente)
    desfechos = set()
    for _ in range(600):
        _, avisos, erro = conferir_leitura(fluxo_sorteado(sorteio))
        desfechos.add("erro" if erro else "aviso" if avisos else "fim")
    assert desfechos == {"fim", "aviso", "erro"}
    for _ in range(200):
        conferir_leitura(sorteio.randbytes(sorteio.randrange(64)))
        conferir_leitura(sorteio.choice(MAGICOS) + sorteio.randbytes(sorteio.randrange(64)))


@pytest.mark.parametrize("magico", MAGICOS)
def test_captura_cortada_em_qualquer_byte(magico):
    quadros = [quadro_tcp(), b"", quadro_udp(), bytes(14)]
    dados = pcap([(i + 1, 0, quadro) for i, quadro in enumerate(quadros)], magico=magico)
    fins = [24]
    for quadro in quadros:
        fins.append(fins[-1] + 16 + len(quadro))
    for corte in range(len(dados) + 1):
        lidos, avisos, erro = conferir_leitura(dados[:corte])
        if corte < 24:
            assert erro is not None
            continue
        inteiros = sum(fim <= corte for fim in fins[1:])
        assert erro is None
        assert [quadro for _, quadro in lidos] == quadros[:inteiros]
        assert len(avisos) == (0 if corte in fins else 1)


class FluxoIrregular:
    """Entrega a cada leitura uma quantidade sorteada de bytes, como um pipe ou um soquete."""

    def __init__(self, dados, sorteio):
        self._fluxo = io.BytesIO(dados)
        self._sorteio = sorteio

    def read(self, n):
        return self._fluxo.read(min(n, self._sorteio.randint(1, 9)))


@pytest.mark.parametrize("semente", range(4))
def test_leitura_nao_depende_de_como_o_fluxo_entrega_os_bytes(semente):
    sorteio = random.Random(3000 + semente)
    for _ in range(150):
        dados = fluxo_sorteado(sorteio)
        de_uma_vez, avisos_a, erro_a = ler_tudo(io.BytesIO(dados))
        aos_poucos, avisos_b, erro_b = ler_tudo(FluxoIrregular(dados, sorteio))
        assert aos_poucos == de_uma_vez
        assert [str(aviso.message) for aviso in avisos_b] == [str(aviso.message) for aviso in avisos_a]
        assert str(erro_b) == str(erro_a)


@pytest.mark.parametrize("semente", range(4))
def test_leitor_igual_ao_do_dpkt_em_capturas_integras(semente):
    sorteio = random.Random(4000 + semente)
    registros = registros_sorteados(sorteio, 60)
    for magico in (PCAP_LE, PCAP_BE):
        dados = pcap(registros, magico=magico)
        assert list(ler_pcap(io.BytesIO(dados))) == list(dpkt.pcap.Reader(io.BytesIO(dados)))
        assert list(ler_pcap(io.BytesIO(dados))) == como_quadros(registros)


def mesmo_valor(a, b):
    """Igualdade exata, com nan igual a nan."""
    return a == b or (math.isnan(a) and math.isnan(b))


def colunas_diferentes(a, b):
    return [coluna for coluna in COLUNAS if not mesmo_valor(a[coluna], b[coluna])]


def caso_sorteado(semente):
    """Fluxo de quadros, tamanho de janela e a lista de (posição, instante) dos quadros mantidos."""
    sorteio = random.Random(semente)
    quadros = como_quadros(registros_sorteados(sorteio, sorteio.randint(1, 150)))
    janela = sorteio.choice((1, 2, 3, 7, 10, 100))
    mantidos = [(i, ts) for i, (ts, quadro) in enumerate(quadros) if medir_quadro(ts, quadro) is not None]
    return sorteio, quadros, janela, mantidos


@pytest.mark.parametrize("semente", range(30))
def test_propriedades_das_linhas(semente):
    _, quadros, janela, mantidos = caso_sorteado(5000 + semente)
    linhas = list(extrair(quadros, janela))
    assert sum(linha["Number"] for linha in linhas) == len(mantidos)
    assert all(linha["Number"] == janela for linha in linhas[:-1])
    for linha in linhas:
        n = linha["Number"]
        assert list(linha) == list(COLUNAS)
        assert 1 <= n <= janela
        assert math.isclose(linha["Tot sum"], linha["AVG"] * n, rel_tol=1e-12)
        assert linha["AVG"] == linha["Tot size"]
        assert linha["Min"] <= linha["AVG"] <= linha["Max"]
        for contagem in CONTAGENS:
            flag = contagem.replace("_count", "_flag_number")
            assert math.isclose(linha[contagem], linha[flag] * n, rel_tol=1e-12, abs_tol=1e-9)
        if n == 1:
            assert math.isnan(linha["Std"]) and math.isnan(linha["Variance"])
        else:
            assert linha["Variance"] >= 0
            assert math.isclose(linha["Variance"], linha["Std"] ** 2, rel_tol=1e-12)
        assert all(0 <= linha[nome] <= 1 for nome in (*FLAGS, *INDICADORES))
        assert linha["Rate"] > 0
        assert linha["IPv"] == linha["LLC"]
        assert linha["TCP"] + linha["UDP"] <= linha["IPv"] + 1e-12
        assert math.isclose(linha["IPv"] + linha["ARP"], 1.0, rel_tol=1e-12)


@pytest.mark.parametrize("semente", range(30))
def test_alimentar_um_a_um_da_o_mesmo_que_extrair(semente):
    _, quadros, janela, mantidos = caso_sorteado(6000 + semente)
    esperadas = list(extrair(quadros, janela))

    extrator = Extrator(janela)
    linhas = [extrator.alimentar(ts, quadro) for ts, quadro in quadros]
    linhas = [linha for linha in (*linhas, extrator.finalizar()) if linha is not None]
    assert extrator.finalizar() is None
    assert extrator.ignorados == len(quadros) - len(mantidos)
    assert len(linhas) == len(esperadas)
    assert all(colunas_diferentes(a, b) == [] for a, b in zip(linhas, esperadas))

    # A mesma conta feita por fora: medidas encadeadas pelo instante anterior e agregadas em fatias.
    medidas, anterior = [], None
    for ts, quadro in quadros:
        medida = medir_quadro(ts, quadro, anterior)
        if medida is not None:
            medidas.append(medida)
            anterior = ts
    fatias = [agregar(medidas[i:i + janela]) for i in range(0, len(medidas), janela)]
    assert len(fatias) == len(esperadas)
    assert all(colunas_diferentes(a, b) == [] for a, b in zip(fatias, esperadas))


@pytest.mark.parametrize("semente", range(30))
def test_dividir_o_fluxo_no_fim_de_uma_janela_so_muda_o_iat_da_linha_seguinte(semente):
    sorteio, quadros, janela, mantidos = caso_sorteado(7000 + semente)
    inteiras = list(extrair(quadros, janela))
    # Posições do fluxo em que uma janela acabou de fechar. Só nelas a divisão é feita.
    fins = [posicao + 1 for ordem, (posicao, _) in enumerate(mantidos, start=1) if ordem % janela == 0]
    cortes = sorted(sorteio.sample(fins, sorteio.randint(min(1, len(fins)), len(fins))))

    juntas, primeiras, inicio = [], {}, 0
    for corte in (*cortes, len(quadros)):
        linhas = list(extrair(quadros[inicio:corte], janela))
        if inicio and linhas:
            primeiras[len(juntas)] = inicio
        juntas.extend(linhas)
        inicio = corte
    assert len(juntas) == len(inteiras)
    for numero, (junta, inteira) in enumerate(zip(juntas, inteiras)):
        if numero not in primeiras:
            assert colunas_diferentes(junta, inteira) == []
            continue
        # O primeiro quadro depois da divisão perde o intervalo até o quadro anterior a ela.
        antes = [ts for posicao, ts in mantidos if posicao < primeiras[numero]][-1]
        depois = next(ts for posicao, ts in mantidos if posicao >= primeiras[numero])
        assert set(colunas_diferentes(junta, inteira)) <= {"IAT"}
        diferenca = (depois - antes) / junta["Number"]
        assert math.isclose(inteira["IAT"] - junta["IAT"], diferenca, rel_tol=1e-9, abs_tol=1e-9)


CAMPO_NUMERICO = re.compile(r"-?(\d+(\.\d+)?(e[+-]?\d+)?|inf)")
VALORES_EXTREMOS = (
    0, -0.0, 5e-324, 1e-320, 0.1 + 0.2, 1 / 3, -1.5e-7, 123456789.12345679, 2**63,
    1.7976931348623157e308, math.inf, -math.inf, math.nan,
)


@pytest.mark.parametrize("semente", range(10))
def test_csv_gravado_volta_igual_pelo_leitor_do_calibrador(tmp_path, semente):
    sorteio = random.Random(8000 + semente)
    quadros = como_quadros(registros_sorteados(sorteio, 120))
    quadros = [
        (ts, adulterar(sorteio, quadro) if sorteio.random() < 0.3 else quadro) for ts, quadro in quadros
    ]
    linhas = list(extrair(quadros, sorteio.choice((1, 3, 10))))
    # Janela de um quadro: Std e Variance vazios e Rate infinito.
    linhas += list(extrair([(1.0, quadro_tcp())]))
    linhas += [dict.fromkeys(COLUNAS, valor) for valor in VALORES_EXTREMOS]

    caminho = tmp_path / "linhas.csv"
    with open(caminho, "w", newline="") as arquivo:
        assert gravar_csv(linhas, arquivo) == len(linhas)
    lidas = ler_oficial(caminho)
    assert len(lidas) == len(linhas)
    for gravada, lida in zip(linhas, lidas):
        assert [c for c in COLUNAS if not mesmo_valor(float(gravada[c]), lida[c])] == []

    # No arquivo só há números, "inf" e campos vazios, qualquer que seja o conteúdo dos quadros.
    cabecalho, *registros = caminho.read_text().splitlines()
    assert cabecalho == ",".join(COLUNAS)
    for registro in registros:
        campos = registro.split(",")
        assert len(campos) == len(COLUNAS)
        assert all(campo == "" or CAMPO_NUMERICO.fullmatch(campo) for campo in campos), registro
    unico = len(linhas) - len(VALORES_EXTREMOS) - 1
    assert registros[unico].split(",")[COLUNAS.index("Std")] == ""
    assert lidas[unico]["Rate"] == math.inf and math.isnan(lidas[unico]["Variance"])
