"""Testes do reprodutor, com um pcap montado no teste e um modelo de mentira.

O modelo de mentira chama de DDoS+DoS toda janela com maioria de SYN, de Recon toda janela com
maioria de ICMP e de benigna o resto: assim cada regra da política de acionamento e dos papéis é
conferida com janelas escolhidas a dedo.
"""

import asyncio
import datetime
import json
import socket
import sys
from pathlib import Path

import dpkt
import numpy as np
import pytest

from codigo.captura.extrator import COLUNAS
from codigo.classificador.operacao import PontoDeOperacao
from codigo.mcp.acoes import reconstruir
from codigo.mcp.cenarios import ler_cenarios
from codigo.mcp.eventos import Registro, ler
from codigo.mcp.stub import Stub
from codigo.reprodutor import reprodutor
from codigo.reprodutor.reprodutor import (
    JANELA,
    Classificador,
    PcapInvalido,
    caminho_dos_cenarios,
    cenarios_da_reproducao,
    gravar,
    inicio_do_teste,
    ler_referencia,
    reproduzir,
    resumo,
)

VITIMA = "192.168.1.50"
ATACANTE = "192.168.1.66"
AGORA = datetime.datetime(2026, 10, 19, 21, 0, 0, tzinfo=datetime.UTC)


class ModeloFalso:
    classes_ = np.array(["Benign", "DDoS+DoS", "Recon"])
    feature_importances_ = np.array([1.0 if coluna == "syn_flag_number" else 0.01 for coluna in COLUNAS])

    def predict_proba(self, X):
        syn = (X[:, COLUNAS.index("syn_flag_number")] > 0.5).astype(float)
        icmp = (X[:, COLUNAS.index("ICMP")] > 0.5).astype(float) * (1 - syn)
        return np.column_stack([1 - syn - icmp, syn * 0.9, syn * 0.1 + icmp])


class ModeloArp(ModeloFalso):
    classes_ = np.array(["Benign", "Spoofing"])

    def predict_proba(self, X):
        de_arp = (X[:, COLUNAS.index("ARP")] > 0.5).astype(float)
        return np.column_stack([1 - de_arp, de_arp])


def classificador(seguidas=3):
    return Classificador(ModeloFalso(), tuple(COLUNAS), PontoDeOperacao(None, seguidas), "falso.joblib")


def _eth(ip):
    return bytes(dpkt.ethernet.Ethernet(
        src=b"\x02\x00\x00\x00\x00\x01", dst=b"\x02\x00\x00\x00\x00\x02", type=dpkt.ethernet.ETH_TYPE_IP, data=ip,
    ))


def tcp(origem, destino, flags, porta=80):
    segmento = dpkt.tcp.TCP(sport=40000, dport=porta, flags=flags)
    return _eth(dpkt.ip.IP(src=socket.inet_aton(origem), dst=socket.inet_aton(destino), p=dpkt.ip.IP_PROTO_TCP, data=segmento, ttl=64))


def udp(origem, destino, porta):
    datagrama = dpkt.udp.UDP(sport=40000, dport=porta, data=b"x")
    return _eth(dpkt.ip.IP(src=socket.inet_aton(origem), dst=socket.inet_aton(destino), p=dpkt.ip.IP_PROTO_UDP, data=datagrama, ttl=64))


def icmp(origem, destino):
    eco = dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1))
    return _eth(dpkt.ip.IP(src=socket.inet_aton(origem), dst=socket.inet_aton(destino), p=dpkt.ip.IP_PROTO_ICMP, data=eco, ttl=64))


def arp(anunciado, mac_do_atacante=b"\x02\x00\x00\x00\x00\x66"):
    resposta = dpkt.arp.ARP(op=dpkt.arp.ARP_OP_REPLY, sha=mac_do_atacante, spa=socket.inet_aton(anunciado),
                            tha=b"\xff" * 6, tpa=socket.inet_aton("192.168.1.255"))
    return bytes(dpkt.ethernet.Ethernet(src=mac_do_atacante, dst=b"\xff" * 6, type=dpkt.ethernet.ETH_TYPE_ARP, data=resposta))


def escrever_pcap(caminho, blocos, passo=0.01):
    """`blocos`: (janelas, gerador de quadro por posição, pausa_antes_s). Cada janela tem 100 quadros."""
    ts = 1_700_000_000.0
    with open(caminho, "wb") as arquivo:
        escritor = dpkt.pcap.Writer(arquivo)
        for janelas, gerar, pausa in blocos:
            ts += pausa
            for i in range(int(janelas * JANELA)):
                escritor.writepkt(gerar(i), ts=ts)
                ts += passo
    return caminho


def benigno(janelas, pausa=0.0):
    return (janelas, lambda i: tcp(("192.168.1.10", "192.168.1.11")[i % 2], VITIMA, dpkt.tcp.TH_ACK), pausa)


def ataque(janelas, origens=(ATACANTE,), pausa=0.0, destino=VITIMA, respostas=0):
    """SYN das origens para o destino; com `respostas`, a vítima manda tantos SYN-ACK por SYN."""
    ciclo = 1 + respostas

    def gerar(i):
        origem = origens[(i // ciclo) % len(origens)]
        if i % ciclo == 0:
            return tcp(origem, destino, dpkt.tcp.TH_SYN)
        return tcp(destino, origem, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)

    return (janelas, gerar, pausa)


def varredura(janelas, scanner, alvos, pausa=0.0):
    return (janelas, lambda i: icmp(scanner, alvos[i % len(alvos)]), pausa)


def test_trafego_benigno_nao_abre_incidente(tmp_path):
    r = reproduzir(escrever_pcap(tmp_path / "b.pcap", [benigno(6)]), classificador())

    assert (r.janelas, r.quadros, dict(r.por_categoria), r.incidentes) == (6, 600, {"Benign": 6}, [])


def test_incidente_abre_na_terceira_janela_de_ataque_seguida(tmp_path):
    r = reproduzir(escrever_pcap(tmp_path / "a.pcap", [benigno(2), ataque(5), benigno(10)]), classificador())

    assert len(r.incidentes) == 1
    incidente = r.incidentes[0]
    assert [j.indice for j in incidente.ataque] == [2, 3, 4, 5, 6]
    assert [j.indice for j in incidente.abertura.ataque] == [2, 3, 4]
    assert incidente.aberto_em - incidente.primeira_janela_de_ataque == pytest.approx(2.99, abs=1e-4)


def test_duas_janelas_de_ataque_nao_bastam(tmp_path):
    r = reproduzir(escrever_pcap(tmp_path / "a.pcap", [benigno(2), ataque(2), benigno(2)]), classificador())

    assert r.incidentes == []
    assert r.por_categoria["DDoS+DoS"] == 2


def test_janelas_benignas_curtas_no_meio_ficam_no_mesmo_incidente(tmp_path):
    r = reproduzir(escrever_pcap(tmp_path / "a.pcap", [ataque(4), benigno(2), ataque(3), benigno(12)]), classificador())

    assert len(r.incidentes) == 1
    assert dict(r.incidentes[0].por_categoria) == {"DDoS+DoS": 7, "Benign": 2}


def test_fecha_apos_janelas_benignas_e_reagrupa_o_mesmo_ataque(tmp_path):
    caminho = escrever_pcap(tmp_path / "a.pcap", [ataque(4), benigno(10), ataque(3)])

    junto = reproduzir(caminho, classificador())
    separado = reproduzir(caminho, classificador(), reagrupa_s=0)

    assert len(junto.incidentes) == 1 and junto.incidentes[0].reaberturas == 1
    assert len(separado.incidentes) == 2


def test_mesmo_alvo_com_outra_origem_se_junta_e_sem_endereco_em_comum_nao(tmp_path):
    mesmo_alvo = escrever_pcap(tmp_path / "a.pcap", [ataque(4, ("10.0.0.1",)), benigno(10), ataque(3, ("10.0.0.9",))])
    outro_alvo = escrever_pcap(
        tmp_path / "b.pcap",
        [ataque(4, ("10.0.0.1",)), benigno(10), ataque(3, ("10.0.0.9",), destino="10.0.0.200")],
    )

    assert len(reproduzir(mesmo_alvo, classificador()).incidentes) == 1
    assert len(reproduzir(outro_alvo, classificador()).incidentes) == 2


def test_reagrupamento_olha_alem_do_incidente_encerrado_mais_novo(tmp_path):
    # A (flood de P contra X), B (varredura de Q) e de novo A depois que B se encerrou: a nova
    # rajada de A reabre A, mesmo com B encerrado depois dele.
    p, x, q = "10.0.0.1", "10.0.0.20", "10.0.0.7"
    caminho = escrever_pcap(tmp_path / "a.pcap", [
        ataque(4, (p,), destino=x), benigno(10), varredura(4, q, ["10.0.0.30", "10.0.0.31"]), benigno(10),
        ataque(4, (p,), destino=x), benigno(10),
    ])

    r = reproduzir(caminho, classificador())

    assert [i.categoria_principal() for i in r.incidentes] == ["DDoS+DoS", "Recon"]
    assert r.incidentes[0].reaberturas == 1


def test_dois_ataques_ao_mesmo_tempo_ficam_em_incidentes_diferentes(tmp_path):
    # Flood de P e varredura de Q intercalados janela a janela.
    p, q = "10.0.0.1", "10.0.0.7"

    def gerar(i):
        if (i // JANELA) % 2 == 0:
            return tcp(p, VITIMA, dpkt.tcp.TH_SYN)
        return icmp(q, f"10.0.1.{i % 50}")

    r = reproduzir(escrever_pcap(tmp_path / "a.pcap", [(12, gerar, 0.0), benigno(12)]), classificador())

    assert sorted(i.categoria_principal() for i in r.incidentes) == ["DDoS+DoS", "Recon"]
    assert all(len(i.ataque) == 6 for i in r.incidentes)


def test_pausa_na_captura_encerra_o_incidente_e_nao_entra_no_atraso(tmp_path):
    caminho = escrever_pcap(tmp_path / "a.pcap", [ataque(4), ataque(4, pausa=3600)])

    r = reproduzir(caminho, classificador(), reagrupa_s=0)

    assert len(r.incidentes) == 2
    segundo = r.incidentes[1]
    assert segundo.aberto_em - segundo.primeira_janela_de_ataque < 60
    assert r.janelas == 8


def test_teto_de_incidentes_conta_uma_vez_por_sequencia(tmp_path):
    caminho = escrever_pcap(tmp_path / "a.pcap", [
        ataque(4), benigno(10), ataque(40, destino="10.0.0.200", origens=("10.0.0.9",)), benigno(10),
    ])

    r = reproduzir(caminho, classificador(), reagrupa_s=0, teto=1)

    assert len(r.incidentes) == 1
    assert r.alem_do_teto == 1


def test_ultima_janela_incompleta_e_descartada(tmp_path):
    r = reproduzir(escrever_pcap(tmp_path / "a.pcap", [ataque(2.5)]), classificador())

    assert (r.janelas, r.incompletas, sum(r.por_categoria.values())) == (2, 1, 2)


def test_so_o_trecho_a_partir_de_uma_janela(tmp_path):
    caminho = escrever_pcap(tmp_path / "a.pcap", [ataque(4), benigno(10), ataque(4)])

    r = reproduzir(caminho, classificador(), a_partir_da_janela=14)

    assert r.puladas == 14
    assert sum(r.por_categoria.values()) == 4
    assert [j.indice for j in r.incidentes[0].ataque] == [14, 15, 16, 17]


def test_inicio_do_teste_vem_do_manifesto_da_regeracao(tmp_path):
    manifesto = tmp_path / "m.json"
    manifesto.write_text(json.dumps({
        "pcaps": [{"arquivo": "A.pcap", "janelas": {"100": {"extraidas": 100}}},
                  {"arquivo": "B1.pcap", "janelas": {"100": {"extraidas": 10}}},
                  {"arquivo": "B2.pcap", "janelas": {"100": {"extraidas": 10}}}],
        "rotulos": [{"arquivos": ["A.pcap"]}, {"arquivos": ["B1.pcap", "B2.pcap"]}],
    }))

    assert inicio_do_teste("A.pcap", manifesto) == 70
    assert inicio_do_teste("/x/B2.pcap", manifesto) == 0
    assert inicio_do_teste("B1.pcap", manifesto) is None
    assert inicio_do_teste("C.pcap", manifesto) is None


def test_arquivo_que_nao_e_pcap_vira_pcap_invalido(tmp_path):
    caminho = tmp_path / "x.pcap"
    caminho.write_bytes(b"isto nao e um pcap, so texto qualquer")

    with pytest.raises(PcapInvalido, match="não é um arquivo pcap"):
        reproduzir(caminho, classificador())


# --- Papéis: quem ataca e quem é atacado ------------------------------------------------------


def _cenario(tmp_path, blocos, c=None):
    c = c or classificador()
    return cenarios_da_reproducao(reproduzir(escrever_pcap(tmp_path / "a.pcap", blocos), c), c)[0]


@pytest.mark.parametrize("respostas", [0, 1, 2])
def test_respostas_da_vitima_nao_poem_o_atacante_entre_os_destinos(tmp_path, respostas):
    incidente = _cenario(tmp_path, [ataque(6, respostas=respostas), benigno(10)]).incidente

    assert incidente.origens[0].endereco == ATACANTE
    assert incidente.destinos[0].endereco == VITIMA
    assert ATACANTE not in [d.endereco for d in incidente.destinos]
    assert (incidente.categoria, incidente.distribuido, incidente.origens_distintas) == ("DoS", False, 1)


def test_ddos_com_respostas_continua_distribuido(tmp_path):
    incidente = _cenario(tmp_path, [ataque(6, origens=("10.9.0.1", "10.9.0.2"), respostas=3), benigno(10)]).incidente

    assert (incidente.categoria, incidente.distribuido) == ("DDoS", True)
    assert {o.endereco for o in incidente.origens} == {"10.9.0.1", "10.9.0.2"}


def test_varredura_poe_o_scanner_na_origem_e_os_alvos_nos_destinos(tmp_path):
    alvos = [f"10.0.1.{i}" for i in range(1, 61)]

    def gerar(i):
        # Pedido do scanner seguido da resposta do alvo, para 60 alvos.
        alvo = alvos[(i // 2) % len(alvos)]
        return icmp("10.0.0.7", alvo) if i % 2 == 0 else icmp(alvo, "10.0.0.7")

    incidente = _cenario(tmp_path, [(5, gerar, 0.0), benigno(10)]).incidente

    assert incidente.categoria == "Recon"
    assert [o.endereco for o in incidente.origens] == ["10.0.0.7"]
    assert "10.0.0.7" not in [d.endereco for d in incidente.destinos]


def test_gateway_falando_com_todos_nao_vira_o_scanner(tmp_path):
    # O gateway da política (192.168.137.1) manda pouco a muitos dispositivos; o scanner pinga 40 alvos.
    alvos = [f"192.168.137.{i}" for i in range(100, 140)]
    dispositivos = [f"192.168.137.{i}" for i in range(10, 90)]

    def gerar(i):
        if i % 4 == 3:
            return icmp("192.168.137.1", dispositivos[i % len(dispositivos)])
        return icmp("192.168.137.178", alvos[i % len(alvos)])

    incidente = _cenario(tmp_path, [(5, gerar, 0.0), benigno(10)]).incidente

    assert [o.endereco for o in incidente.origens] == ["192.168.137.178"]


def test_multicast_que_recebe_de_todos_nao_vira_o_alvo_de_um_flood(tmp_path):
    # Flood ICMP de 2 origens contra a vítima, com anúncios de SSDP de 30 dispositivos no meio.
    def gerar(i):
        if i % 5 == 4:
            return icmp(f"192.168.1.{100 + i % 30}", "239.255.255.250")
        return icmp(("10.9.0.1", "10.9.0.2")[i % 2], VITIMA)

    c = Classificador(ModeloSemSyn(), tuple(COLUNAS), PontoDeOperacao(None, 3), "icmp.joblib")
    incidente = _cenario(tmp_path, [(5, gerar, 0.0), benigno(10)], c).incidente

    assert incidente.destinos[0].endereco == VITIMA
    assert {o.endereco for o in incidente.origens} == {"10.9.0.1", "10.9.0.2"}
    assert incidente.categoria == "DDoS"


class ModeloSemSyn(ModeloFalso):
    """ICMP vira DDoS+DoS, como num flood ICMP."""

    def predict_proba(self, X):
        de_icmp = (X[:, COLUNAS.index("ICMP")] > 0.5).astype(float)
        return np.column_stack([1 - de_icmp, de_icmp, np.zeros(len(X))])


def test_arp_spoofing_lista_os_anunciados_e_obter_janelas_nao_quebra(tmp_path):
    c = Classificador(ModeloArp(), tuple(COLUNAS), PontoDeOperacao(None, 3), "arp.joblib")
    caminho = escrever_pcap(tmp_path / "a.pcap", [(5, lambda i: arp(("192.168.1.1", "192.168.1.20")[i % 2]), 0.0)])
    reproducao = reproduzir(caminho, c)
    log = tmp_path / "eventos.jsonl"

    cenarios, _ = gravar(reproducao, c, log, relogio=lambda: AGORA)

    incidente = cenarios[0].incidente
    assert incidente.categoria == "Spoofing"
    assert {o.endereco for o in incidente.origens} == {"192.168.1.1", "192.168.1.20"}
    assert incidente.destinos == [] and incidente.origens_distintas == 2
    fatia = Stub(Registro(log), agente="triagem", cenarios=cenarios).chamar("obter_janelas", id="inc-0001", limite=5)
    assert fatia.janelas == []


def test_incidente_lista_as_portas_atacadas_so_nos_destinos_listados(tmp_path):
    # As respostas da vítima vão para a porta 80 do atacante, que não é destino do incidente.
    incidente = _cenario(tmp_path, [ataque(6, respostas=1), benigno(10)]).incidente

    assert [(p.destino, p.porta, p.protocolo, p.quadros) for p in incidente.portas] == [(VITIMA, 80, "tcp", 300)]


def test_portas_do_tcp_e_do_udp_saem_da_mais_atacada_para_a_menos(tmp_path):
    def gerar(i):
        # Em cada 10 quadros, 6 SYN para a porta 23, 1 para a 2323 e 3 datagramas para a 1900.
        resto = i % 10
        if resto < 6:
            return tcp(ATACANTE, VITIMA, dpkt.tcp.TH_SYN, porta=23)
        return tcp(ATACANTE, VITIMA, dpkt.tcp.TH_SYN, porta=2323) if resto == 6 else udp(ATACANTE, VITIMA, 1900)

    incidente = _cenario(tmp_path, [(5, gerar, 0.0), benigno(10)]).incidente

    assert [(p.porta, p.protocolo, p.quadros) for p in incidente.portas] == [
        (23, "tcp", 300), (1900, "udp", 150), (2323, "tcp", 50),
    ]


def test_flood_icmp_e_arp_spoofing_nao_tem_porta(tmp_path):
    c = Classificador(ModeloSemSyn(), tuple(COLUNAS), PontoDeOperacao(None, 3), "icmp.joblib")
    assert _cenario(tmp_path, [(5, lambda i: icmp(ATACANTE, VITIMA), 0.0), benigno(10)], c).incidente.portas == []
    c = Classificador(ModeloArp(), tuple(COLUNAS), PontoDeOperacao(None, 3), "arp.joblib")
    caminho = escrever_pcap(tmp_path / "b.pcap", [(5, lambda i: arp(("192.168.1.1", "192.168.1.20")[i % 2]), 0.0)])
    assert cenarios_da_reproducao(reproduzir(caminho, c), c)[0].incidente.portas == []


def test_agente_de_decisao_le_as_portas_com_o_rotulo_do_destino(tmp_path):
    c = classificador()
    reproducao = reproduzir(escrever_pcap(tmp_path / "a.pcap", [ataque(6), benigno(10)]), c)
    log = tmp_path / "eventos.jsonl"
    cenarios, _ = gravar(reproducao, c, log, relogio=lambda: AGORA)

    resumo_do_incidente = Stub(Registro(log), agente="decisao", cenarios=cenarios).chamar("obter_resumo", id="inc-0001")

    assert [(p.destino, p.porta, p.protocolo) for p in resumo_do_incidente.portas] == [("destino-1", 80, "tcp")]
    assert VITIMA not in resumo_do_incidente.model_dump_json()


# --- Do incidente ao log e ao servidor --------------------------------------------------------


def test_incidente_no_formato_do_contrato_com_features_e_janelas_reais(tmp_path):
    cenario = _cenario(tmp_path, [benigno(1), ataque(5), benigno(10)])

    incidente = cenario.incidente
    assert (incidente.id, incidente.janelas, incidente.confianca) == ("inc-0001", 5, 0.9)
    assert incidente.features_principais[0].nome == "syn_flag_number"
    assert incidente.features_principais[0].valor == 1.0
    assert incidente.features_principais[0].referencia_benigno == ler_referencia()["syn_flag_number"]
    assert [j.indice for j in cenario.janelas_reais] == [0, 1, 2, 3, 4]
    assert cenario.janelas_reais[0].origem == ATACANTE
    assert cenario.lote.por_categoria == {"DDoS+DoS": 5}


def test_indice_da_janela_guardada_e_a_posicao_dela_no_incidente(tmp_path, monkeypatch):
    monkeypatch.setattr(reprodutor, "JANELAS_GUARDADAS", 2)

    cenario = _cenario(tmp_path, [ataque(5), benigno(10)])

    assert cenario.incidente.janelas == 5
    assert [j.indice for j in cenario.janelas_reais] == [0, 3]


def test_log_na_ordem_dos_fatos_com_a_abertura_do_momento_e_o_relogio_de_reproducao(tmp_path):
    c = classificador()
    reproducao = reproduzir(escrever_pcap(tmp_path / "a.pcap", [benigno(3), ataque(5), benigno(10)]), c)
    log = tmp_path / "eventos.jsonl"

    cenarios, deslocamento = gravar(reproducao, c, log, relogio=lambda: AGORA)

    eventos = ler(log)
    assert [e.tipo for e in eventos] == ["janelas_classificadas", "incidente_aberto", "incidente_atualizado", "janelas_classificadas"]
    aberto, atualizado = eventos[1].dados, eventos[2].dados
    assert (aberto.janelas, atualizado.janelas) == (3, 5)
    assert sum(e.dados.janelas for e in eventos if e.tipo == "janelas_classificadas") == reproducao.janelas
    # A última janela do pcap acontece agora; a abertura, no fim da terceira janela de ataque.
    assert eventos[-1].instante == AGORA
    assert eventos[1].instante == datetime.datetime.fromtimestamp(reproducao.incidentes[0].aberto_em + deslocamento, tz=datetime.UTC)
    assert atualizado.inicio < atualizado.fim <= AGORA
    assert reconstruir(eventos).incidentes["inc-0001"] == cenarios[0].incidente


def test_segunda_reproducao_no_mesmo_log_continua_a_numeracao_e_o_relogio(tmp_path):
    c = classificador()
    log = tmp_path / "eventos.jsonl"
    primeira = reproduzir(escrever_pcap(tmp_path / "a.pcap", [ataque(5), benigno(10)]), c)
    gravar(primeira, c, log, relogio=lambda: AGORA)
    segunda = reproduzir(escrever_pcap(tmp_path / "b.pcap", [ataque(4), benigno(10)]), c)

    gravar(segunda, c, log, relogio=lambda: AGORA)

    assert list(reconstruir(ler(log)).incidentes) == ["inc-0001", "inc-0002"]
    assert [x.incidente.id for x in ler_cenarios(caminho_dos_cenarios(log))] == ["inc-0001", "inc-0002"]


def test_cenarios_ao_lado_do_log_voltam_iguais_e_so_o_dono_le(tmp_path):
    c = classificador()
    reproducao = reproduzir(escrever_pcap(tmp_path / "a.pcap", [ataque(5), benigno(10)]), c)
    log = tmp_path / "eventos.jsonl"

    cenarios, _ = gravar(reproducao, c, log, relogio=lambda: AGORA)

    arquivo = caminho_dos_cenarios(log)
    assert arquivo.name == "eventos.cenarios.json"
    assert arquivo.stat().st_mode & 0o777 == 0o600
    lidos = ler_cenarios(arquivo)
    assert [x.incidente for x in lidos] == [x.incidente for x in cenarios]
    assert lidos[0].janelas_reais == cenarios[0].janelas_reais


def test_incidente_fica_no_relogio_de_reproducao_e_nao_dura_anos(tmp_path):
    c = classificador()
    reproducao = reproduzir(escrever_pcap(tmp_path / "a.pcap", [ataque(5), benigno(10)]), c)
    log = tmp_path / "eventos.jsonl"
    cenarios, _ = gravar(reproducao, c, log)

    resumo_do_servidor = Stub(Registro(log), agente="decisao", cenarios=cenarios).chamar("obter_resumo", id="inc-0001")

    assert resumo_do_servidor.duracao_s < 60
    assert abs((cenarios[0].incidente.fim - datetime.datetime.now(tz=datetime.UTC)).total_seconds()) < 60


def test_incidente_conta_todas_as_janelas_de_ataque_e_a_categoria_e_a_mais_frequente(tmp_path):
    # Uma janela de varredura seguida de duas de flood contra o mesmo alvo.
    def gerar(i):
        return icmp(ATACANTE, VITIMA) if i < JANELA else tcp(ATACANTE, VITIMA, dpkt.tcp.TH_SYN)

    cenario = _cenario(tmp_path, [benigno(1), (3, gerar, 0.0), benigno(10)])

    assert cenario.incidente.categoria_do_modelo == "DDoS+DoS"
    assert cenario.incidente.janelas == 3
    assert [j.categoria_do_modelo for j in cenario.janelas_reais] == ["Recon", "DDoS+DoS", "DDoS+DoS"]


def test_resumo_traz_o_atraso_o_relogio_e_a_politica(tmp_path):
    c = classificador()
    reproducao = reproduzir(escrever_pcap(tmp_path / "a.pcap", [ataque(3)]), c, nome="captura.pcap")
    log = tmp_path / "eventos.jsonl"
    cenarios, deslocamento = gravar(reproducao, c, log, relogio=lambda: AGORA)

    saida = resumo(reproducao, cenarios, c, deslocamento)

    assert saida["arquivo"] == "captura.pcap"
    assert saida["incidentes"][0]["atraso_de_deteccao_s"] == pytest.approx(2.99, abs=1e-3)
    assert saida["ponto_de_operacao"] == {"regra": "argmax", "limiar": None, "seguidas": 3}
    assert saida["relogio"]["deslocamento_s"] == pytest.approx(deslocamento)
    assert saida["trecho"] == {"a_partir_da_janela": 0, "so_teste": False}


def test_cliente_mcp_le_o_incidente_real_do_servidor_subido_com_os_cenarios(tmp_path):
    from mcp import Client, StdioServerParameters

    c = classificador()
    reproducao = reproduzir(escrever_pcap(tmp_path / "a.pcap", [benigno(2), ataque(5), benigno(10)]), c)
    log = tmp_path / "eventos.jsonl"
    gravar(reproducao, c, log)
    raiz = Path(__file__).resolve().parents[2]

    def conversar(agente, roteiro):
        parametros = StdioServerParameters(
            command=sys.executable,
            args=["-m", "codigo.mcp.stub", "--agente", agente, "--log", str(log), "--cenarios", str(caminho_dos_cenarios(log))],
            cwd=raiz,
        )

        async def sessao():
            async with Client(parametros) as cliente:
                return await roteiro(cliente)

        return asyncio.run(asyncio.wait_for(sessao(), timeout=60))

    async def triagem(cliente):
        incidente = await cliente.call_tool("obter_incidente", {"id": "inc-0001"})
        janelas = await cliente.call_tool("obter_janelas", {"id": "inc-0001", "limite": 3})
        exemplo = await cliente.call_tool("obter_incidente", {"id": "inc-0004"})
        return incidente.structured_content, janelas.structured_content, exemplo.content[0].text

    async def decisao(cliente):
        return (await cliente.call_tool("obter_resumo", {"id": "inc-0001"})).structured_content

    incidente, janelas, exemplo = conversar("triagem", triagem)
    resumo_da_decisao = conversar("decisao", decisao)

    assert incidente["categoria"] == "DoS"
    assert incidente["origens"][0]["endereco"] == ATACANTE
    assert [j["indice"] for j in janelas["janelas"]] == [0, 2, 4]
    assert janelas["janelas"][0]["origem"] == ATACANTE
    # O servidor não abriu os incidentes de exemplo: o inc-0004 não existe neste log.
    assert "Não existe incidente" in exemplo
    assert ATACANTE not in str(resumo_da_decisao) and VITIMA not in str(resumo_da_decisao)
    assert [evento.tipo for evento in ler(log)].count("incidente_aberto") == 1


def test_endereco_que_manda_para_si_mesmo_nao_quebra_os_papeis(tmp_path):
    def gerar(i):
        if i % 2:
            return tcp(ATACANTE, ATACANTE, dpkt.tcp.TH_SYN)
        return tcp(ATACANTE, VITIMA, dpkt.tcp.TH_SYN)

    incidente = _cenario(tmp_path, [(5, gerar, 0.0), benigno(10)]).incidente

    assert incidente.categoria in ("DoS", "DDoS")
    assert incidente.origens
