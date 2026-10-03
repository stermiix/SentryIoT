import struct

import pytest

from codigo.captura.extrator import COLUNAS, medir_quadro

CABECALHO_OFICIAL = (
    "Header_Length,Protocol Type,Time_To_Live,Rate,fin_flag_number,syn_flag_number,"
    "rst_flag_number,psh_flag_number,ack_flag_number,ece_flag_number,cwr_flag_number,"
    "ack_count,syn_count,fin_count,rst_count,HTTP,HTTPS,DNS,Telnet,SMTP,SSH,IRC,TCP,UDP,"
    "DHCP,ARP,ICMP,IGMP,IPv,LLC,Tot sum,Min,Max,AVG,Std,Tot size,IAT,Number,Variance"
)


def test_colunas_na_ordem_do_csv_oficial():
    assert len(COLUNAS) == 39
    assert ",".join(COLUNAS) == CABECALHO_OFICIAL

MACS = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01"


def eth(tipo, carga):
    return MACS + struct.pack(">H", tipo) + carga


def ipv4(protocolo, carga, ttl=64, fragmento=0):
    cabecalho = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 20 + len(carga), 1, fragmento, ttl, protocolo, 0,
        bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
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
