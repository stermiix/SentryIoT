import io
import math
import struct
from collections import Counter
from decimal import Decimal
from pathlib import Path

import pytest

from codigo.captura.extrator import (
    COLUNAS,
    Enderecos,
    Extrator,
    agregar,
    enderecos,
    extrair,
    gravar_csv,
    ler_pcap,
    main,
    medir_quadro,
)

CABECALHO_OFICIAL = (
    "Header_Length,Protocol Type,Time_To_Live,Rate,fin_flag_number,syn_flag_number,"
    "rst_flag_number,psh_flag_number,ack_flag_number,ece_flag_number,cwr_flag_number,"
    "ack_count,syn_count,fin_count,rst_count,HTTP,HTTPS,DNS,Telnet,SMTP,SSH,IRC,TCP,UDP,"
    "DHCP,ARP,ICMP,IGMP,IPv,LLC,Tot sum,Min,Max,AVG,Std,Tot size,IAT,Number,Variance"
)


def test_colunas_na_ordem_do_csv_oficial():
    assert len(COLUNAS) == 39
    assert ",".join(COLUNAS) == CABECALHO_OFICIAL

MAC_DESTINO = b"\x02\x00\x00\x00\x00\x02"
MAC_ORIGEM = b"\x02\x00\x00\x00\x00\x01"
MACS = MAC_DESTINO + MAC_ORIGEM


def eth(tipo, carga, origem=MAC_ORIGEM, destino=MAC_DESTINO):
    return destino + origem + struct.pack(">H", tipo) + carga


def ipv4(protocolo, carga, ttl=64, fragmento=0, origem=bytes([10, 0, 0, 1]), destino=bytes([10, 0, 0, 2])):
    cabecalho = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 20 + len(carga), 1, fragmento, ttl, protocolo, 0, origem, destino,
    )
    return cabecalho + carga


def tcp(origem, destino, flags, opcoes=b"", dados=b""):
    deslocamento = (20 + len(opcoes)) // 4
    cabecalho = struct.pack(">HHIIBBHHH", origem, destino, 1, 0, deslocamento << 4, flags, 8192, 0, 0)
    return cabecalho + opcoes + dados


def udp(origem, destino, dados=b""):
    return struct.pack(">HHHH", origem, destino, 8 + len(dados), 0) + dados


def quadro_tcp(origem=40000, destino=80, flags=0x02, opcoes=b"", dados=b"", ttl=64):
    return eth(0x0800, ipv4(6, tcp(origem, destino, flags, opcoes, dados), ttl=ttl))


def quadro_udp(origem=40000, destino=53, dados=b"consulta"):
    return eth(0x0800, ipv4(17, udp(origem, destino, dados)))


def test_tcp_syn_com_opcoes():
    quadro = quadro_tcp(destino=80, flags=0x02, opcoes=b"\x02\x04\x05\xb4", ttl=57)
    m = medir_quadro(10.0, quadro)
    assert m["Header_Length"] == 24
    assert m["Protocol Type"] == 6
    assert m["Time_To_Live"] == 57
    assert (m["syn_flag_number"], m["ack_flag_number"], m["fin_flag_number"]) == (1, 0, 0)
    assert (m["TCP"], m["UDP"], m["IPv"], m["LLC"], m["ARP"]) == (1, 0, 1, 1, 0)
    assert (m["HTTP"], m["HTTPS"]) == (1, 0)
    assert m["Tot size"] == len(quadro)
    assert m["IAT"] == 0.0
    assert m["ts"] == 10.0


def test_flags_tcp():
    m = medir_quadro(0.0, quadro_tcp(flags=0x01 | 0x10))
    assert (m["fin_flag_number"], m["ack_flag_number"], m["syn_flag_number"]) == (1, 1, 0)
    m = medir_quadro(0.0, quadro_tcp(flags=0x04 | 0x08 | 0x40 | 0x80))
    assert [m[n] for n in ("rst_flag_number", "psh_flag_number", "ece_flag_number", "cwr_flag_number")] == [1, 1, 1, 1]
    m = medir_quadro(0.0, quadro_tcp(flags=0x20))  # URG não tem coluna
    assert sum(m[n] for n in COLUNAS if n.endswith("_flag_number")) == 0


@pytest.mark.parametrize("porta,coluna", [(80, "HTTP"), (443, "HTTPS"), (23, "Telnet"), (25, "SMTP"), (22, "SSH"), (21, "IRC")])
def test_indicadores_por_porta_tcp(porta, coluna):
    outros = {"HTTP", "HTTPS", "Telnet", "SMTP", "SSH", "IRC"} - {coluna}
    for quadro in (quadro_tcp(origem=porta, destino=50000), quadro_tcp(origem=50000, destino=porta)):
        m = medir_quadro(0.0, quadro)
        assert m[coluna] == 1
        assert all(m[o] == 0 for o in outros)


def test_udp_dns():
    m = medir_quadro(0.0, quadro_udp(destino=53))
    assert (m["UDP"], m["TCP"], m["DNS"], m["DHCP"]) == (1, 0, 1, 0)
    assert m["Header_Length"] == 8
    assert m["Protocol Type"] == 17
    assert sum(m[n] for n in COLUNAS if n.endswith("_flag_number")) == 0


def test_udp_dhcp_exige_o_par_67_68():
    assert medir_quadro(0.0, quadro_udp(origem=68, destino=67))["DHCP"] == 1
    assert medir_quadro(0.0, quadro_udp(origem=67, destino=68))["DHCP"] == 1
    assert medir_quadro(0.0, quadro_udp(origem=67, destino=67))["DHCP"] == 0


def test_smtp_so_e_marcado_em_tcp():
    assert medir_quadro(0.0, quadro_udp(destino=25))["SMTP"] == 0


def test_icmp_e_igmp():
    icmp = medir_quadro(0.0, eth(0x0800, ipv4(1, b"\x08\x00\x00\x00\x00\x01\x00\x01")))
    assert (icmp["ICMP"], icmp["IGMP"], icmp["TCP"], icmp["UDP"], icmp["IPv"]) == (1, 0, 0, 0, 1)
    assert (icmp["Header_Length"], icmp["Protocol Type"]) == (0, 1)
    igmp = medir_quadro(0.0, eth(0x0800, ipv4(2, b"\x11\x64\x00\x00\x00\x00\x00\x00")))
    assert (igmp["IGMP"], igmp["ICMP"], igmp["Protocol Type"]) == (1, 0, 2)


def test_arp():
    m = medir_quadro(0.0, eth(0x0806, b"\x00" * 28))
    assert (m["ARP"], m["IPv"], m["LLC"]) == (1, 0, 0)
    assert (m["Protocol Type"], m["Time_To_Live"], m["Header_Length"]) == (0, 0, 0)
    assert m["Tot size"] == 42


def test_fragmento_ip_nao_conta_como_tcp():
    m = medir_quadro(0.0, eth(0x0800, ipv4(6, b"\x00" * 24, fragmento=0x00B9)))
    assert (m["Protocol Type"], m["TCP"], m["Header_Length"]) == (6, 0, 0)


@pytest.mark.parametrize("quadro", [
    eth(0x86DD, b"\x60" + b"\x00" * 39),              # IPv6
    eth(0x0027, b"\x42\x42\x03" + b"\x00" * 36),      # 802.3 com LLC (STP)
    eth(0x0800, b"\x45\x00"),                         # IPv4 com cabeçalho ilegível
    b"\x00" * 10,                                     # menor que um cabeçalho Ethernet
])
def test_quadros_fora_do_filtro(quadro):
    assert medir_quadro(0.0, quadro) is None


def test_iat_e_o_tempo_desde_o_quadro_anterior():
    assert medir_quadro(10.5, quadro_tcp(), ts_anterior=10.0)["IAT"] == 0.5
    assert medir_quadro(10.5, quadro_tcp())["IAT"] == 0.0


def duas_medidas():
    primeiro = medir_quadro(100.0, quadro_tcp(flags=0x02, dados=b"\x00" * 6))            # 60 bytes
    segundo = medir_quadro(100.5, quadro_tcp(flags=0x10, dados=b"\x00" * 46), 100.0)     # 100 bytes
    return [primeiro, segundo]


def test_agregar_duas_medidas():
    linha = agregar(duas_medidas())
    assert list(linha) == list(COLUNAS)
    assert (linha["Tot sum"], linha["Min"], linha["Max"], linha["Number"]) == (160, 60, 100, 2)
    assert linha["AVG"] == 80.0
    assert linha["Tot size"] == 80.0
    assert linha["Variance"] == 800.0
    assert linha["Std"] == math.sqrt(800.0)
    assert linha["Rate"] == 4.0
    assert linha["IAT"] == 0.25
    assert (linha["syn_flag_number"], linha["ack_flag_number"]) == (0.5, 0.5)
    assert (linha["syn_count"], linha["ack_count"], linha["fin_count"], linha["rst_count"]) == (1, 1, 0, 0)
    assert linha["Protocol Type"] == 6
    assert (linha["Header_Length"], linha["Time_To_Live"]) == (20.0, 64.0)
    assert (linha["HTTP"], linha["TCP"], linha["IPv"], linha["LLC"], linha["UDP"]) == (1.0, 1.0, 1.0, 1.0, 0.0)


def test_janela_de_um_quadro():
    linha = agregar([medir_quadro(5.0, quadro_tcp())])
    assert linha["Number"] == 1
    assert math.isnan(linha["Std"]) and math.isnan(linha["Variance"])
    assert linha["Rate"] == math.inf


def test_janela_com_todos_os_quadros_no_mesmo_instante():
    medidas = [medir_quadro(7.0, quadro_tcp()), medir_quadro(7.0, quadro_tcp(), 7.0)]
    assert agregar(medidas)["Rate"] == math.inf


def test_protocolo_da_janela_e_a_moda_e_o_menor_no_empate():
    um_de_cada = [medir_quadro(0.0, quadro_udp()), medir_quadro(1.0, quadro_tcp(), 0.0)]
    assert agregar(um_de_cada)["Protocol Type"] == 6
    maioria_udp = um_de_cada + [medir_quadro(2.0, quadro_udp(), 1.0)]
    assert agregar(maioria_udp)["Protocol Type"] == 17


QUADRO_IPV6 = eth(0x86DD, b"\x60" + b"\x00" * 39)


def test_extrator_devolve_linha_a_cada_janela():
    extrator = Extrator()
    saidas = [extrator.alimentar(i * 0.1, quadro_tcp()) for i in range(25)]
    prontas = [i for i, linha in enumerate(saidas) if linha is not None]
    assert prontas == [9, 19]
    assert saidas[9]["Number"] == 10
    resto = extrator.finalizar()
    assert resto["Number"] == 5
    assert extrator.finalizar() is None
    assert extrator.ignorados == 0


def test_extrator_ignora_e_conta_o_que_esta_fora_do_filtro():
    extrator = Extrator(janela=2)
    assert extrator.alimentar(0.0, quadro_tcp()) is None
    assert extrator.alimentar(1.0, QUADRO_IPV6) is None
    linha = extrator.alimentar(2.0, quadro_tcp())
    assert extrator.ignorados == 1
    assert linha["IAT"] == 1.0  # média de 0 e 2: o quadro ignorado não entra no intervalo


def test_intervalo_entre_quadros_continua_de_uma_janela_para_a_outra():
    linhas = list(extrair([(float(i), quadro_tcp()) for i in range(4)], janela=2))
    assert [linha["IAT"] for linha in linhas] == [0.5, 1.0]


def test_extrair_sem_quadros_uteis():
    assert list(extrair([])) == []
    assert list(extrair([(0.0, QUADRO_IPV6), (1.0, QUADRO_IPV6)])) == []


def test_janela_invalida():
    with pytest.raises(ValueError):
        Extrator(janela=0)


PCAP_LE = b"\xd4\xc3\xb2\xa1"
PCAP_BE = b"\xa1\xb2\xc3\xd4"
PCAP_NANO = b"\x4d\x3c\xb2\xa1"


def pcap(registros, magico=PCAP_LE, rede=1):
    ordem = ">" if magico[:1] == b"\xa1" else "<"
    corpo = magico + struct.pack(ordem + "HHiIII", 2, 4, 0, 0, 262144, rede)
    for segundos, micros, quadro in registros:
        corpo += struct.pack(ordem + "IIII", segundos, micros, len(quadro), len(quadro)) + quadro
    return corpo


class FluxoAosPoucos:
    """Entrega no máximo 7 bytes por leitura, como um pipe pode fazer."""

    def __init__(self, dados):
        self._fluxo = io.BytesIO(dados)

    def read(self, n):
        return self._fluxo.read(min(n, 7))


def test_ler_pcap_de_fluxo_e_de_arquivo(tmp_path):
    a, b = quadro_tcp(), quadro_udp()
    dados = pcap([(1, 500000, a), (2, 0, b)])
    assert list(ler_pcap(io.BytesIO(dados))) == [(1.5, a), (2.0, b)]
    caminho = tmp_path / "captura.pcap"
    caminho.write_bytes(dados)
    assert list(ler_pcap(caminho)) == [(1.5, a), (2.0, b)]


def test_ler_pcap_big_endian_e_leituras_curtas():
    a = quadro_tcp()
    assert list(ler_pcap(io.BytesIO(pcap([(3, 250000, a)], magico=PCAP_BE)))) == [(3.25, a)]
    assert list(ler_pcap(FluxoAosPoucos(pcap([(3, 250000, a)])))) == [(3.25, a)]


@pytest.mark.parametrize("corte", [5, 40, 60])
def test_ler_pcap_de_captura_interrompida(corte):
    a, b = quadro_tcp(), quadro_udp()
    dados = pcap([(1, 0, a), (2, 0, b)])
    with pytest.warns(UserWarning, match="incompleto"):
        assert list(ler_pcap(io.BytesIO(dados[:-corte]))) == [(1.0, a)]


@pytest.mark.parametrize("dados,trecho", [
    (b"\x0a\x0d\x0d\x0a" + b"\x00" * 28, "pcapng"),
    (b"", "pcap"),
    (pcap([], rede=113), "Ethernet"),
])
def test_ler_pcap_recusa_o_que_nao_sabe_ler(dados, trecho):
    with pytest.raises(ValueError, match=trecho):
        list(ler_pcap(io.BytesIO(dados)))


def test_gravar_csv_segue_o_formato_oficial():
    quadros = [(0.0, quadro_tcp()), (0.5, quadro_tcp()), (1.0, quadro_tcp())]
    saida = io.StringIO()
    assert gravar_csv(extrair(quadros, janela=2), saida) == 2
    cabecalho, completa, parcial = saida.getvalue().splitlines()
    assert cabecalho == CABECALHO_OFICIAL
    assert completa.split(",")[COLUNAS.index("Number")] == "2"
    campos = parcial.split(",")
    assert campos[COLUNAS.index("Std")] == "" and campos[COLUNAS.index("Variance")] == ""
    assert campos[COLUNAS.index("Rate")] == "inf"


def test_main_converte_pcap_em_csv(tmp_path, capsys):
    entrada, saida = tmp_path / "entrada.pcap", tmp_path / "saida.csv"
    entrada.write_bytes(pcap([(i, 0, quadro_tcp()) for i in range(20)]))
    assert main([str(entrada), str(saida)]) == 0
    assert len(saida.read_text().splitlines()) == 3
    assert "2 linhas" in capsys.readouterr().err


def test_main_com_pcap_sem_quadros_uteis_grava_so_o_cabecalho(tmp_path):
    entrada, saida = tmp_path / "entrada.pcap", tmp_path / "saida.csv"
    entrada.write_bytes(pcap([(1, 0, QUADRO_IPV6)]))
    assert main([str(entrada), str(saida)]) == 0
    assert saida.read_text().splitlines() == [CABECALHO_OFICIAL]


def test_main_explica_erros_de_entrada(tmp_path, capsys):
    ruim = tmp_path / "captura.pcapng"
    ruim.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 28)
    assert main([str(ruim), str(tmp_path / "saida.csv")]) == 1
    assert "pcapng" in capsys.readouterr().err
    assert main([str(tmp_path / "nao_existe.pcap"), str(tmp_path / "saida.csv")]) == 1
    assert main([]) == 2


def test_contagens_de_fin_e_rst_somam_as_flags_certas():
    medidas = [
        medir_quadro(0.0, quadro_tcp(flags=0x01)),
        medir_quadro(1.0, quadro_tcp(flags=0x01), 0.0),
        medir_quadro(2.0, quadro_tcp(flags=0x04), 1.0),
    ]
    linha = agregar(medidas)
    assert (linha["fin_count"], linha["rst_count"], linha["syn_count"], linha["ack_count"]) == (2, 1, 0, 0)


def test_dns_vale_para_a_porta_de_origem_e_so_em_udp():
    assert medir_quadro(0.0, quadro_udp(origem=53, destino=40000))["DNS"] == 1
    assert medir_quadro(0.0, quadro_tcp(origem=40000, destino=53))["DNS"] == 0


def test_tamanho_inclui_o_preenchimento_ethernet():
    quadro = quadro_tcp() + b"\x00" * 6  # 54 bytes de cabeçalhos e 6 de preenchimento
    m = medir_quadro(0.0, quadro)
    assert m["Tot size"] == 60
    assert m["TCP"] == 1


def test_rate_usa_o_intervalo_entre_o_menor_e_o_maior_instante():
    medidas = [
        medir_quadro(10.0, quadro_tcp()),
        medir_quadro(9.0, quadro_tcp(), 10.0),
        medir_quadro(9.5, quadro_tcp(), 9.0),
    ]
    assert agregar(medidas)["Rate"] == 3.0


def test_ler_pcap_com_fracao_em_nanossegundos():
    a = quadro_tcp()
    assert list(ler_pcap(io.BytesIO(pcap([(7, 500_000_000, a)], magico=PCAP_NANO)))) == [(7.5, a)]


def test_ler_pcap_usa_o_tamanho_capturado_e_nao_o_original():
    a, b = quadro_tcp(), quadro_udp()
    dados = pcap([])
    dados += struct.pack("<IIII", 1, 0, len(a), len(a) + 100) + a
    dados += struct.pack("<IIII", 2, 0, len(b), len(b)) + b
    assert list(ler_pcap(io.BytesIO(dados))) == [(1.0, a), (2.0, b)]


def test_ler_pcap_recusa_registro_com_tamanho_impossivel():
    dados = pcap([(1, 0, quadro_tcp())]) + struct.pack("<IIII", 2, 0, 0x7FFFFFFF, 0x7FFFFFFF) + b"\x00" * 50
    with pytest.raises(ValueError, match="corrompido"):
        list(ler_pcap(io.BytesIO(dados)))


def test_main_le_da_entrada_padrao(tmp_path, monkeypatch):
    dados = pcap([(i, 0, quadro_tcp()) for i in range(10)])
    monkeypatch.setattr("sys.stdin", type("Entrada", (), {"buffer": io.BytesIO(dados)})())
    saida = tmp_path / "saida.csv"
    assert main(["-", str(saida)]) == 0
    assert len(saida.read_text().splitlines()) == 2


def test_main_aceita_o_tamanho_da_janela(tmp_path):
    entrada, saida = tmp_path / "entrada.pcap", tmp_path / "saida.csv"
    entrada.write_bytes(pcap([(i, 0, quadro_tcp()) for i in range(10)]))
    assert main(["--janela", "5", str(entrada), str(saida)]) == 0
    linhas = saida.read_text().splitlines()
    assert len(linhas) == 3
    assert linhas[1].split(",")[COLUNAS.index("Number")] == "5"


def test_main_avisa_captura_cortada_e_termina_bem(tmp_path, capsys):
    entrada, saida = tmp_path / "entrada.pcap", tmp_path / "saida.csv"
    entrada.write_bytes(pcap([(i, 0, quadro_tcp()) for i in range(12)])[:-5])
    assert main([str(entrada), str(saida)]) == 0
    assert "aviso" in capsys.readouterr().err
    assert len(saida.read_text().splitlines()) == 3


def test_main_nao_toca_na_saida_quando_a_entrada_e_invalida(tmp_path):
    captura, csv_antigo = tmp_path / "captura.pcap", tmp_path / "features.csv"
    conteudo = pcap([(1, 0, quadro_tcp())])
    captura.write_bytes(conteudo)
    csv_antigo.write_text("conteudo anterior\n")
    assert main([str(csv_antigo), str(captura)]) == 1  # argumentos trocados
    assert captura.read_bytes() == conteudo
    assert main([str(tmp_path / "nao_existe.pcap"), str(csv_antigo)]) == 1
    assert csv_antigo.read_text() == "conteudo anterior\n"


def test_main_recusa_entrada_e_saida_no_mesmo_arquivo(tmp_path, capsys):
    captura = tmp_path / "captura.pcap"
    conteudo = pcap([(1, 0, quadro_tcp())])
    captura.write_bytes(conteudo)
    assert main([str(captura), str(captura)]) == 1
    assert captura.read_bytes() == conteudo
    assert "mesmo arquivo" in capsys.readouterr().err


@pytest.mark.parametrize("janela", ["0", "-3", "abc", "100000000"])
def test_main_recusa_janela_invalida_sem_abrir_a_saida(tmp_path, janela):
    entrada, saida = tmp_path / "entrada.pcap", tmp_path / "saida.csv"
    entrada.write_bytes(pcap([(1, 0, quadro_tcp())]))
    assert main(["--janela", janela, str(entrada), str(saida)]) == 2
    assert not saida.exists()


def test_main_interrompido_pelo_teclado_sai_com_130(tmp_path, monkeypatch, capsys):
    def leitura_interrompida(origem):
        yield 1.0, quadro_tcp()
        raise KeyboardInterrupt

    monkeypatch.setattr("codigo.captura.extrator.ler_pcap", leitura_interrompida)
    assert main([str(tmp_path / "qualquer.pcap"), str(tmp_path / "saida.csv")]) == 130
    assert "interrompid" in capsys.readouterr().err


def test_ler_pcap_limita_o_registro_mesmo_sem_limite_declarado():
    cabecalho = PCAP_LE + struct.pack("<HHiIII", 2, 4, 0, 0, 0, 1)  # limite de captura igual a 0
    dados = cabecalho + struct.pack("<IIII", 1, 0, 300_000, 300_000) + b"\x00" * 64
    with pytest.raises(ValueError, match="corrompido"):
        list(ler_pcap(io.BytesIO(dados)))


def test_ler_pcap_corta_no_limite_declarado_o_registro_maior_que_ele():
    # A libpcap entrega só os bytes até o limite de captura declarado no cabeçalho, e é com ela
    # que o tcpdump dos autores fatia o pcap. O Mirai-greip_flood21.pcap oficial declara 1500
    # bytes e traz quadros de 1514.
    cabecalho = PCAP_LE + struct.pack("<HHiIII", 2, 4, 0, 0, 60, 1)  # limite de captura de 60 bytes
    longo, curto = bytes(range(200)), bytes(range(50))
    dados = cabecalho + struct.pack("<IIII", 1, 0, len(longo), len(longo)) + longo
    dados += struct.pack("<IIII", 2, 0, len(curto), len(curto)) + curto
    assert list(ler_pcap(io.BytesIO(dados))) == [(1.0, longo[:60]), (2.0, curto)]


def test_ler_pcap_recusa_registro_acima_do_maior_aceito_mesmo_com_limite_declarado_menor():
    cabecalho = PCAP_LE + struct.pack("<HHiIII", 2, 4, 0, 0, 60, 1)
    dados = cabecalho + struct.pack("<IIII", 1, 0, 300_000, 300_000) + b"\x00" * 64
    with pytest.raises(ValueError, match="corrompido"):
        list(ler_pcap(io.BytesIO(dados)))


def cabecalho_pcap(limite):
    """Cabeçalho de um pcap Ethernet, com o limite de captura declarado."""
    return PCAP_LE + struct.pack("<HHiIII", 2, 4, 0, 0, limite, 1)


def registro_pcap(segundos, quadro):
    return struct.pack("<IIII", segundos, 0, len(quadro), len(quadro)) + quadro


QUADRO_DE_262144_BYTES = bytes(range(256)) * 1024


def test_ler_pcap_aceita_registro_de_exatamente_262144_bytes():
    assert len(QUADRO_DE_262144_BYTES) == 262_144
    dados = cabecalho_pcap(262_144) + registro_pcap(1, QUADRO_DE_262144_BYTES) + registro_pcap(2, quadro_tcp())
    assert list(ler_pcap(io.BytesIO(dados))) == [(1.0, QUADRO_DE_262144_BYTES), (2.0, quadro_tcp())]


def test_ler_pcap_recusa_registro_de_262145_bytes():
    dados = cabecalho_pcap(262_144) + registro_pcap(1, QUADRO_DE_262144_BYTES + b"\x00")
    with pytest.raises(ValueError, match=r"pacote 1 com tamanho impossível \(262145 bytes, limite de 262144\)"):
        list(ler_pcap(io.BytesIO(dados)))


def test_ler_pcap_com_limite_declarado_zero_entrega_o_quadro_inteiro():
    # Limite 0 no cabeçalho quer dizer que nenhum limite foi declarado, e não que o quadro tem 0 bytes.
    a, b = quadro_tcp(), quadro_udp()
    dados = cabecalho_pcap(0) + registro_pcap(1, a) + registro_pcap(2, b)
    assert list(ler_pcap(io.BytesIO(dados))) == [(1.0, a), (2.0, b)]


@pytest.mark.parametrize("limite", [262_145, 300_000, 0x7FFFFFFF, 0xFFFFFFFF])
def test_ler_pcap_com_limite_declarado_acima_de_262144_se_comporta_como_262144(limite):
    a = quadro_tcp()
    dados = cabecalho_pcap(limite) + registro_pcap(1, a) + registro_pcap(2, QUADRO_DE_262144_BYTES)
    assert list(ler_pcap(io.BytesIO(dados))) == [(1.0, a), (2.0, QUADRO_DE_262144_BYTES)]
    # O registro de 262.145 bytes é recusado mesmo cabendo no limite declarado.
    com_maior = dados + registro_pcap(3, QUADRO_DE_262144_BYTES + b"\x00")
    with pytest.raises(ValueError, match=r"pacote 3 com tamanho impossível \(262145 bytes, limite de 262144\)"):
        list(ler_pcap(io.BytesIO(com_maior)))


PCAP_DE_MIRAI = Path(__file__).resolve().parents[2] / "CICIoT2023" / "Mirai-greip_flood21.pcap"


@pytest.mark.skipif(not PCAP_DE_MIRAI.exists(), reason="dataset ausente")
def test_mirai_greip_flood21_real_nenhum_quadro_entregue_passa_de_1500_bytes():
    # Varredura à parte, só dos cabeçalhos: o arquivo declara 1500 bytes e traz registros maiores.
    with open(PCAP_DE_MIRAI, "rb") as arquivo:
        cabecalho = arquivo.read(24)
        assert cabecalho[:4] == PCAP_LE
        assert struct.unpack("<II", cabecalho[16:24]) == (1500, 1)
        registros = maiores = 0
        while len(registro := arquivo.read(16)) == 16:
            capturado = struct.unpack("<I", registro[8:12])[0]
            registros += 1
            maiores += capturado > 1500
            arquivo.seek(capturado, 1)
    assert maiores > 0
    tamanhos = Counter(len(quadro) for _, quadro in ler_pcap(PCAP_DE_MIRAI))
    assert sum(tamanhos.values()) == registros
    assert max(tamanhos) == 1500
    assert tamanhos[1500] >= maiores


def test_instante_precisa_ser_um_numero_finito():
    for instante in (math.nan, math.inf):
        with pytest.raises(ValueError, match="instante"):
            Extrator().alimentar(instante, quadro_tcp())
    assert Extrator(janela=1).alimentar(Decimal("1.5"), quadro_tcp())["Number"] == 1


# --- endereços de cada janela ----------------------------------------------------------------


def quadro_de(mac_origem, mac_destino, ip_origem=(10, 0, 0, 1), ip_destino=(10, 0, 0, 2)):
    """Quadro TCP com os endereços pedidos. Os MACs vêm como texto, na grafia do Wireshark."""
    return eth(
        0x0800, ipv4(6, tcp(40000, 80, 0x02), origem=bytes(ip_origem), destino=bytes(ip_destino)),
        origem=bytes.fromhex(mac_origem.replace(":", "")), destino=bytes.fromhex(mac_destino.replace(":", "")),
    )


def test_medir_quadro_registra_os_enderecos_do_quadro():
    m = medir_quadro(0.0, quadro_de("DC:A6:32:DC:27:D5", "3c:18:a0:41:c3:a0", (192, 168, 1, 7), (8, 8, 8, 8)))
    assert (m["mac_origem"], m["mac_destino"]) == ("dc:a6:32:dc:27:d5", "3c:18:a0:41:c3:a0")
    assert (m["ip_origem"], m["ip_destino"]) == (bytes([192, 168, 1, 7]), bytes([8, 8, 8, 8]))


def test_quadro_arp_tem_macs_e_nao_tem_ip():
    m = medir_quadro(0.0, eth(0x0806, b"\x00" * 28))
    assert (m["mac_origem"], m["mac_destino"]) == ("02:00:00:00:00:01", "02:00:00:00:00:02")
    assert (m["ip_origem"], m["ip_destino"]) == (None, None)


def test_enderecos_da_janela_sao_conjuntos_de_macs_e_contagens_de_ips():
    medidas = [
        medir_quadro(0.0, quadro_de("aa:00:00:00:00:01", "aa:00:00:00:00:02", (10, 0, 0, 1), (10, 0, 0, 9))),
        medir_quadro(1.0, quadro_de("aa:00:00:00:00:03", "aa:00:00:00:00:02", (10, 0, 0, 2), (10, 0, 0, 9)), 0.0),
        medir_quadro(2.0, quadro_de("aa:00:00:00:00:01", "aa:00:00:00:00:04", (10, 0, 0, 1), (10, 0, 0, 8)), 1.0),
        medir_quadro(3.0, eth(0x0806, b"\x00" * 28), 2.0),
    ]
    e = enderecos(medidas)
    assert isinstance(e, Enderecos)
    assert e.macs_origem == frozenset({"aa:00:00:00:00:01", "aa:00:00:00:00:03", "02:00:00:00:00:01"})
    assert e.macs_destino == frozenset({"aa:00:00:00:00:02", "aa:00:00:00:00:04", "02:00:00:00:00:02"})
    # O ARP não tem cabeçalho IPv4, então não entra na contagem de IPs.
    assert (e.ips_origem, e.ips_destino) == (2, 2)
    # A agregação das 39 colunas não muda com os endereços registrados.
    assert list(agregar(medidas)) == list(COLUNAS)


def test_extrator_com_enderecos_devolve_a_linha_e_os_enderecos():
    extrator = Extrator(janela=2, enderecos=True)
    assert extrator.alimentar(0.0, quadro_de("aa:00:00:00:00:01", "aa:00:00:00:00:02")) is None
    linha, e = extrator.alimentar(1.0, quadro_de("aa:00:00:00:00:03", "aa:00:00:00:00:02"))
    assert list(linha) == list(COLUNAS) and linha["Number"] == 2
    assert e == Enderecos(
        frozenset({"aa:00:00:00:00:01", "aa:00:00:00:00:03"}), frozenset({"aa:00:00:00:00:02"}), 1, 1,
    )
    assert extrator.finalizar() is None
    extrator.alimentar(2.0, quadro_de("aa:00:00:00:00:05", "aa:00:00:00:00:06"))
    linha, e = extrator.finalizar()
    assert linha["Number"] == 1 and e.macs_origem == frozenset({"aa:00:00:00:00:05"})


def test_sem_a_opcao_a_saida_do_extrator_continua_igual():
    quadros = [(float(i), quadro_de("aa:00:00:00:00:01", "aa:00:00:00:00:02")) for i in range(4)]
    so_linhas = list(extrair(quadros, janela=2))
    com_enderecos = list(extrair(quadros, janela=2, enderecos=True))
    assert len(so_linhas) == len(com_enderecos) == 2
    assert all(isinstance(linha, dict) and list(linha) == list(COLUNAS) for linha in so_linhas)
    assert [linha for linha, _ in com_enderecos] == so_linhas
    assert all(isinstance(e, Enderecos) for _, e in com_enderecos)


def test_acumular_recebe_um_quadro_ja_medido():
    # Uma medida serve a vários extratores: quem lê um pcap com duas janelas mede cada quadro uma vez.
    de_dois, de_tres = Extrator(janela=2), Extrator(janela=3)
    ts_anterior = None
    saidas = []
    for i in range(6):
        medida = medir_quadro(float(i), quadro_tcp(), ts_anterior)
        ts_anterior = medida["ts"]
        saidas.append((de_dois.acumular(medida), de_tres.acumular(medida)))
    assert [i for i, (linha, _) in enumerate(saidas) if linha is not None] == [1, 3, 5]
    assert [i for i, (_, linha) in enumerate(saidas) if linha is not None] == [2, 5]
    assert saidas[5][0]["Number"] == 2 and saidas[5][1]["Number"] == 3
    assert saidas[5][0]["IAT"] == 1.0
    assert de_dois.finalizar() is None and de_tres.finalizar() is None
    # `alimentar` é medir e acumular.
    um = Extrator(janela=1)
    assert um.alimentar(7.0, quadro_tcp())["Number"] == 1
    assert um.acumular(None) is None and um.ignorados == 1
