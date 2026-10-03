"""Teste diferencial: o extrator contra o código publicado pelos autores do CICIoT2023.

O código dos autores não tem licença, então nada dele é copiado para cá. Ele é importado, na
hora do teste, da pasta do dataset (CICIoT2023/pcap2csv), que não é versionada. Sem essa pasta,
sem o pcap do dataset ou sem o pandas, o arquivo inteiro é pulado. É o que acontece no CI.

Cada caso grava um pcap, roda as duas implementações sobre ele e compara as 39 colunas com a
tolerância do calibrador. As duas diferenças conhecidas ficam fora das entradas sorteadas e
são conferidas à parte, no fim: quadro IPv4 com cabeçalho ilegível e instante igual a zero.
"""
import importlib
import importlib.abc
import importlib.util
import itertools
import math
import random
import re
import struct
import sys
import types
from pathlib import Path

import dpkt
import pytest

from codigo.captura.calibrar import colunas_divergentes, ler_oficial
from codigo.captura.extrator import extrair, ler_pcap
from codigo.captura.test_extrator import eth, pcap, quadro_tcp, quadro_udp, tcp, udp
from codigo.captura.test_robustez import (
    ENCAPSULAMENTOS,
    adulterar,
    com_vlan,
    pacote_ip,
    registros_sorteados,
)

RAIZ = Path(__file__).resolve().parents[2]
PASTA_DOS_AUTORES = RAIZ / "CICIoT2023" / "pcap2csv"
CODIGO_DOS_AUTORES = PASTA_DOS_AUTORES / "Feature_extraction.py"
PCAP_REAL = RAIZ / "CICIoT2023" / "DictionaryBruteForce.pcap"

REQUISITOS = (
    ("CICIoT2023/pcap2csv/Feature_extraction.py", CODIGO_DOS_AUTORES.exists()),
    ("CICIoT2023/DictionaryBruteForce.pcap", PCAP_REAL.exists()),
    ("pandas", importlib.util.find_spec("pandas") is not None),
    ("scipy", importlib.util.find_spec("scipy") is not None),
)
FALTANDO = [nome for nome, presente in REQUISITOS if not presente]

pytestmark = [
    pytest.mark.skipif(bool(FALTANDO), reason="falta " + ", ".join(FALTANDO)),
    # Com todos os quadros da janela no mesmo instante, os autores dividem por zero e obtêm inf.
    pytest.mark.filterwarnings("ignore:divide by zero:RuntimeWarning"),
]


class _PacotesSemTipo:
    """Fica no lugar da lista de pacotes do scapy: toda posição devolve None."""

    def __getitem__(self, posicao):
        return None


def _modulos_substitutos():
    """Módulos mínimos para o que o código dos autores importa e o projeto não instala.

    Do scapy ele usa rdpcap e dois tipos de pacote (Bluetooth e Zigbee), só para comparar com o
    tipo de cada pacote lido. O tqdm é importado e não é usado na extração.
    """
    scapy = types.ModuleType("scapy")
    zigbee = types.SimpleNamespace(ZigbeeNWKCommandPayload=object())
    scapy.layers = types.SimpleNamespace(bluetooth=object(), zigbee=zigbee)
    scapy_all = types.ModuleType("scapy.all")
    scapy_all.scapy = scapy
    scapy_all.rdpcap = lambda caminho: _PacotesSemTipo()
    tqdm = types.ModuleType("tqdm")
    tqdm.tqdm = lambda iteravel, *args, **kwargs: iteravel
    return {"scapy": {"scapy": scapy, "scapy.all": scapy_all}, "tqdm": {"tqdm": tqdm}}


@pytest.fixture(scope="module")
def autores():
    """Módulo Feature_extraction dos autores, importado da pasta do dataset."""
    with pytest.MonkeyPatch.context() as remendo:
        remendo.syspath_prepend(str(PASTA_DOS_AUTORES))
        remendo.setattr(sys, "dont_write_bytecode", True)  # nada é gravado na pasta do dataset
        for pacote, modulos in _modulos_substitutos().items():
            if importlib.util.find_spec(pacote) is None:
                for nome, modulo in modulos.items():
                    remendo.setitem(sys.modules, nome, modulo)
        antes = set(sys.modules)
        try:
            yield importlib.import_module("Feature_extraction")
        finally:
            # Os módulos dos autores têm nomes genéricos e não ficam carregados depois dos testes.
            for nome in set(sys.modules) - antes:
                if str(PASTA_DOS_AUTORES) in str(getattr(sys.modules[nome], "__file__", "")):
                    del sys.modules[nome]


class _FonteComOutraJanela(importlib.abc.SourceLoader):
    """Carrega Feature_extraction.py com outro tamanho de janela.

    Nos autores o tamanho da janela é `n_rows = 10`, variável local de pcap_evaluation: não há
    atributo nem parâmetro para trocar por fora. Este carregador lê o arquivo deles do disco na
    hora do teste, troca o número dessa atribuição no texto em memória e entrega o resultado ao
    Python, que o compila como um módulo separado. O código continua só na pasta do dataset.
    """

    def __init__(self, janela):
        self.janela = janela

    def get_filename(self, fullname):
        return str(CODIGO_DOS_AUTORES)

    def get_data(self, path):
        fonte = CODIGO_DOS_AUTORES.read_bytes()
        troca = rb"\g<1>" + str(self.janela).encode()
        fonte, trocas = re.subn(rb"^(\s*n_rows\s*=\s*)10\s*$", troca, fonte, flags=re.MULTILINE)
        if trocas != 1:
            raise ImportError("a atribuição n_rows = 10 não foi achada no código dos autores")
        return fonte


@pytest.fixture(scope="module")
def autores_com_janela_de_100(autores):
    """O mesmo módulo dos autores, com a janela de 100 que eles usaram nas classes de flood."""
    carregador = _FonteComOutraJanela(100)
    especificacao = importlib.util.spec_from_loader("Feature_extraction_janela_100", carregador)
    modulo = importlib.util.module_from_spec(especificacao)
    carregador.exec_module(modulo)
    return modulo


def gravar_pcap(caminho, registros):
    partes = [pcap([])]
    for segundos, micros, quadro in registros:
        partes.append(struct.pack("<IIII", segundos, micros, len(quadro), len(quadro)) + quadro)
    caminho.write_bytes(b"".join(partes))


def comparar(pasta, modulo, registros, janela=10):
    """Roda as duas implementações sobre os registros e exige as 39 colunas iguais. Devolve as linhas."""
    caminho = pasta / "caso.pcap"
    gravar_pcap(caminho, registros)
    assert modulo.Feature_extraction().pcap_evaluation(str(caminho), str(pasta / "autores"))
    deles = ler_oficial(pasta / "autores.csv")
    minhas = list(extrair(ler_pcap(caminho), janela))
    assert len(minhas) == len(deles)
    for numero, (minha, dele) in enumerate(zip(minhas, deles), start=2):
        assert colunas_divergentes(minha, dele) == [], f"linha {numero} do CSV dos autores"
    return minhas


def em_sequencia(quadros):
    """Registros com os quadros na ordem dada, um a cada milissegundo."""
    inicio = 1_700_000_000_000
    return [((inicio + i) // 1000, (inicio + i) % 1000 * 1000, quadro) for i, quadro in enumerate(quadros)]


def ipv4_ilegivel(quadro):
    """Quadro IPv4 cujo cabeçalho IP o dpkt não decodifica: a primeira diferença conhecida."""
    try:
        decodificado = dpkt.ethernet.Ethernet(quadro)
    except Exception:  # noqa: BLE001
        return False
    return decodificado.type == dpkt.ethernet.ETH_TYPE_IP and not isinstance(decodificado.data, dpkt.ip.IP)


@pytest.mark.parametrize("semente", range(3))
def test_mistura_de_tcp_udp_icmp_igmp_e_arp(tmp_path, autores, semente):
    registros = registros_sorteados(random.Random(semente), 500, voltar_no_tempo=False)
    linhas = comparar(tmp_path, autores, registros)
    assert len(linhas) > 30
    assert {linha["Protocol Type"] for linha in linhas} >= {6, 17}


def test_etiquetas_de_vlan_e_qinq(tmp_path, autores):
    sorteio = random.Random(10)
    quadros = []
    for _ in range(300):
        quadro = eth(0x0800, pacote_ip(6, tcp(40000, sorteio.choice((22, 80, 443)), 0x18, dados=bytes(20))))
        etiquetas = sorteio.choice((0, 1, 2))
        quadros.append(com_vlan(quadro, dupla=etiquetas == 2) if etiquetas else quadro)
    linhas = comparar(tmp_path, autores, em_sequencia(quadros))
    # Quadro com etiqueta não é contado por nenhuma das duas implementações.
    assert 0 < sum(linha["Number"] for linha in linhas) < len(quadros)


def test_opcoes_ip(tmp_path, autores):
    sorteio = random.Random(11)
    quadros = []
    for palavras in range(11):
        for opcoes in (bytes(4 * palavras), sorteio.randbytes(4 * palavras)):
            quadros.append(eth(0x0800, pacote_ip(6, tcp(40000, 443, 0x10, sorteio.randbytes(8)), opcoes)))
            quadros.append(eth(0x0800, pacote_ip(17, udp(68, 67, bytes(30)), opcoes)))
            quadros.append(eth(0x0800, pacote_ip(1, b"\x08\x00\x00\x00\x00\x01\x00\x01", opcoes)))
    linhas = comparar(tmp_path, autores, em_sequencia(quadros))
    assert sum(linha["Number"] for linha in linhas) == len(quadros)


def test_fragmentos(tmp_path, autores):
    # Flags e deslocamento: sem fragmentação, DF, primeiro fragmento (MF), fragmentos seguintes
    # e o bit reservado.
    campos = (0x0000, 0x4000, 0x2000, 0x2001, 0x00B9, 0x1FFF, 0x8000, 0xFFFF)
    quadros = []
    for campo in campos:
        quadros.append(eth(0x0800, pacote_ip(6, tcp(40000, 80, 0x18, dados=bytes(40)), fragmento=campo)))
        quadros.append(eth(0x0800, pacote_ip(17, udp(40000, 53, bytes(40)), fragmento=campo)))
        quadros.append(eth(0x0800, pacote_ip(1, bytes(48), fragmento=campo)))
    linhas = comparar(tmp_path, autores, em_sequencia(quadros * 3))
    assert sum(linha["Number"] for linha in linhas) == 3 * len(quadros)


def test_cabecalhos_de_transporte_cortados(tmp_path, autores):
    inteiro_tcp = tcp(40000, 80, 0x12, opcoes=b"\x02\x04\x05\xb4" * 3)
    inteiro_udp = udp(53, 40000, bytes(12))
    quadros = [eth(0x0800, pacote_ip(6, inteiro_tcp[:corte])) for corte in range(len(inteiro_tcp) + 1)]
    quadros += [eth(0x0800, pacote_ip(17, inteiro_udp[:corte])) for corte in range(len(inteiro_udp) + 1)]
    quadros += [eth(0x0800, pacote_ip(1, bytes(corte))) for corte in range(9)]
    quadros += [eth(0x0800, pacote_ip(2, bytes(corte))) for corte in range(9)]
    # Campo de tamanho do cabeçalho TCP com todos os valores, inclusive os menores que 20 bytes.
    for palavras in range(16):
        cabecalho = bytearray(tcp(40000, 23, 0x02) + bytes(40))
        cabecalho[12] = palavras << 4
        quadros.append(eth(0x0800, pacote_ip(6, bytes(cabecalho))))
        quadros.append(eth(0x0800, pacote_ip(6, bytes(cabecalho[:24]))))
    # Tamanho total do IP maior e menor do que o quadro realmente traz.
    for total in (0, 20, 28, 40, 1500, 65535):
        pacote = bytearray(pacote_ip(6, tcp(40000, 22, 0x18, dados=bytes(10))))
        pacote[2:4] = struct.pack(">H", total)
        quadros.append(eth(0x0800, bytes(pacote)))
    assert not any(ipv4_ilegivel(quadro) for quadro in quadros)
    linhas = comparar(tmp_path, autores, em_sequencia(quadros))
    assert sum(linha["Number"] for linha in linhas) == len(quadros)


def test_quadros_curtos(tmp_path, autores):
    sorteio = random.Random(12)
    quadros = [sorteio.randbytes(tamanho) for tamanho in range(14)]              # sem cabeçalho Ethernet
    quadros += [eth(0x0806, bytes(tamanho)) for tamanho in range(29)]            # ARP cortado
    quadros += [eth(tipo, b"") for tipo in (0x0806, 0x86DD, 0x8100, 0x0000)]     # só o cabeçalho
    quadros += [quadro_tcp(), quadro_udp() + bytes(10), eth(0x0800, pacote_ip(6, b""))]
    sorteio.shuffle(quadros)
    assert not any(ipv4_ilegivel(quadro) for quadro in quadros)
    linhas = comparar(tmp_path, autores, em_sequencia(quadros))
    assert sum(linha["Number"] for linha in linhas) == 29 + 1 + 3


def test_encapsulamentos_incomuns(tmp_path, autores):
    # Só os quadros que cabem em um quadro Ethernet comum. O maior tem um teste próprio, abaixo.
    quadros = [quadro for quadro in ENCAPSULAMENTOS.values() if len(quadro) <= 1514]
    assert len(quadros) == len(ENCAPSULAMENTOS) - 1
    assert not any(ipv4_ilegivel(quadro) for quadro in quadros)
    linhas = comparar(tmp_path, autores, em_sequencia(quadros + [quadro_tcp()] * 5))
    assert 5 < sum(linha["Number"] for linha in linhas) < len(quadros) + 5


def test_instantes_que_voltam_no_tempo(tmp_path, autores):
    registros = registros_sorteados(random.Random(13), 400, voltar_no_tempo=True)
    linhas = comparar(tmp_path, autores, registros)
    assert any(linha["IAT"] < 0 for linha in linhas)


@pytest.mark.parametrize("quantidade", [1, 11, 21])
def test_janela_de_um_quadro(tmp_path, autores, quantidade):
    quadros = [quadro_tcp(flags=0x10, dados=bytes(i)) for i in range(quantidade)]
    linhas = comparar(tmp_path, autores, em_sequencia(quadros))
    ultima = linhas[-1]
    assert ultima["Number"] == 1 and ultima["Rate"] == math.inf
    assert math.isnan(ultima["Std"]) and math.isnan(ultima["Variance"])


def test_janela_com_todos_os_quadros_no_mesmo_instante(tmp_path, autores):
    registros = [(1_700_000_000, 5, quadro_udp()) for _ in range(25)]
    linhas = comparar(tmp_path, autores, registros)
    assert all(linha["Rate"] == math.inf and linha["IAT"] == 0 for linha in linhas)


def quadros_reais_adulterados(quantidade, semente):
    """Primeiros quadros do pcap do dataset, parte deles com defeitos sorteados."""
    sorteio = random.Random(semente)
    registros = []
    for ts, quadro in itertools.islice(ler_pcap(PCAP_REAL), quantidade):
        if sorteio.random() < 0.4:
            quadro = adulterar(sorteio, quadro)
        if not ipv4_ilegivel(quadro):
            micros = round(ts * 1e6)
            registros.append((micros // 1_000_000, micros % 1_000_000, quadro))
    return registros


def test_quadros_reais_adulterados(tmp_path, autores):
    registros = quadros_reais_adulterados(8000, semente=14)
    assert len(registros) > 7000
    linhas = comparar(tmp_path, autores, registros)
    assert len(linhas) > 600


def test_janela_de_100(tmp_path, autores_com_janela_de_100):
    sorteio = random.Random(15)
    registros = registros_sorteados(sorteio, 1200) + quadros_reais_adulterados(1500, semente=16)
    linhas = comparar(tmp_path, autores_com_janela_de_100, registros, janela=100)
    assert [linha["Number"] for linha in linhas[:-1]] == [100] * (len(linhas) - 1)
    assert len(linhas) > 20


def test_diferenca_conhecida_quadro_ipv4_ilegivel(tmp_path, autores):
    ilegivel = eth(0x0800, b"\x45\x00")
    assert ipv4_ilegivel(ilegivel)
    caminho = tmp_path / "caso.pcap"
    gravar_pcap(caminho, em_sequencia([quadro_tcp(), ilegivel, quadro_tcp()]))
    # Os autores param com erro no quadro ilegível e não geram CSV. O extrator o ignora e segue.
    with pytest.raises(AttributeError):
        autores.Feature_extraction().pcap_evaluation(str(caminho), str(tmp_path / "autores"))
    assert not (tmp_path / "autores.csv").exists()
    (linha,) = extrair(ler_pcap(caminho))
    assert linha["Number"] == 2


def test_diferenca_conhecida_instante_zero(tmp_path, autores):
    caminho = tmp_path / "caso.pcap"
    gravar_pcap(caminho, [(0, 0, quadro_tcp()), (5, 0, quadro_tcp()), (7, 0, quadro_tcp())])
    assert autores.Feature_extraction().pcap_evaluation(str(caminho), str(tmp_path / "autores"))
    (dele,) = ler_oficial(tmp_path / "autores.csv")
    (minha,) = extrair(ler_pcap(caminho))
    # Para os autores, instante anterior igual a zero é ausência de quadro anterior: o segundo
    # quadro fica com intervalo 0, e não 5. Só a coluna IAT muda.
    assert colunas_divergentes(minha, dele) == ["IAT"]
    assert math.isclose(minha["IAT"], (0 + 5 + 2) / 3)
    assert math.isclose(dele["IAT"], (0 + 0 + 2) / 3)


def test_diferenca_conhecida_quadro_grande_que_o_dpkt_nao_decodifica_inteiro(tmp_path, autores):
    # IPv4 dentro de IPv4, 3000 vezes (60 kB). Decodificado inteiro, o quadro estoura o limite de
    # recursão do dpkt, e os autores o descartam. O extrator decodifica só o começo e o mantém.
    quadros = [quadro_tcp(), ENCAPSULAMENTOS["ip_em_ip_3000_niveis"], quadro_tcp(), quadro_tcp()]
    caminho = tmp_path / "caso.pcap"
    gravar_pcap(caminho, em_sequencia(quadros))
    assert autores.Feature_extraction().pcap_evaluation(str(caminho), str(tmp_path / "autores"))
    deles = ler_oficial(tmp_path / "autores.csv")
    minhas = list(extrair(ler_pcap(caminho)))
    assert sum(linha["Number"] for linha in deles) == 3
    assert sum(linha["Number"] for linha in minhas) == 4
