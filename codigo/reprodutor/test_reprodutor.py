"""Testes do reprodutor, com um pcap montado no teste e um modelo de mentira.

O modelo de mentira chama de ataque (DDoS+DoS) toda janela com maioria de SYN, e de benigna o
resto: assim cada regra da política de acionamento é conferida com janelas escolhidas a dedo.
"""

import socket

import dpkt
import numpy as np
import pytest

from codigo.captura.extrator import COLUNAS
from codigo.classificador.operacao import PontoDeOperacao
from codigo.mcp.acoes import reconstruir
from codigo.mcp.eventos import ler
from codigo.mcp.stub import Stub
from codigo.reprodutor.reprodutor import (
    JANELA,
    Classificador,
    cenarios_da_reproducao,
    gravar,
    ler_referencia,
    reproduzir,
    resumo,
)

VITIMA = "192.168.1.50"
ATACANTE = "192.168.1.66"


class ModeloFalso:
    classes_ = np.array(["Benign", "DDoS+DoS", "Recon"])
    feature_importances_ = np.array([1.0 if coluna == "syn_flag_number" else 0.01 for coluna in COLUNAS])

    def predict_proba(self, X):
        ataque = (X[:, COLUNAS.index("syn_flag_number")] > 0.5).astype(float)
        return np.column_stack([1 - ataque, ataque * 0.9, ataque * 0.1])


def classificador(seguidas=3):
    return Classificador(ModeloFalso(), tuple(COLUNAS), PontoDeOperacao(None, seguidas), "falso.joblib")


def quadro(origem, destino, syn):
    tcp = dpkt.tcp.TCP(sport=40000, dport=80, flags=dpkt.tcp.TH_SYN if syn else dpkt.tcp.TH_ACK)
    ip = dpkt.ip.IP(src=socket.inet_aton(origem), dst=socket.inet_aton(destino), p=dpkt.ip.IP_PROTO_TCP, data=tcp, ttl=64)
    eth = dpkt.ethernet.Ethernet(src=b"\x02\x00\x00\x00\x00\x01", dst=b"\x02\x00\x00\x00\x00\x02", type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    return bytes(eth)


def escrever_pcap(caminho, blocos, passo=0.01):
    """`blocos`: (janelas, de_ataque, origens, pausa_antes_s, destino). Cada janela tem 100 quadros."""
    ts = 1_700_000_000.0
    with open(caminho, "wb") as arquivo:
        escritor = dpkt.pcap.Writer(arquivo)
        for janelas, de_ataque, origens, pausa, destino in blocos:
            ts += pausa
            for i in range(janelas * JANELA):
                origem = origens[i % len(origens)]
                escritor.writepkt(quadro(origem, destino, de_ataque), ts=ts)
                ts += passo
    return caminho


def benigno(janelas, pausa=0.0):
    return (janelas, False, ["192.168.1.10", "192.168.1.11"], pausa, VITIMA)


def ataque(janelas, origens=(ATACANTE,), pausa=0.0, destino=VITIMA):
    return (janelas, True, list(origens), pausa, destino)


def test_trafego_benigno_nao_abre_incidente(tmp_path):
    r = reproduzir(escrever_pcap(tmp_path / "b.pcap", [benigno(6)]), classificador())

    assert r.janelas == 6
    assert r.quadros == 600
    assert dict(r.por_categoria) == {"Benign": 6}
    assert r.incidentes == []


def test_incidente_abre_na_terceira_janela_de_ataque_seguida(tmp_path):
    r = reproduzir(escrever_pcap(tmp_path / "a.pcap", [benigno(2), ataque(5), benigno(10)]), classificador())

    assert len(r.incidentes) == 1
    incidente = r.incidentes[0]
    assert [j.indice for j in incidente.ataque] == [2, 3, 4, 5, 6]
    # Abriu no fim da terceira janela de ataque: 300 quadros depois do primeiro, a 10 ms cada.
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

    assert len(junto.incidentes) == 1
    assert junto.incidentes[0].reaberturas == 1
    assert len(separado.incidentes) == 2


def test_mesmo_alvo_com_outra_origem_se_junta_e_sem_endereco_em_comum_nao(tmp_path):
    mesmo_alvo = escrever_pcap(tmp_path / "a.pcap", [ataque(4, ("10.0.0.1",)), benigno(10), ataque(3, ("10.0.0.9",))])
    outro_alvo = escrever_pcap(
        tmp_path / "b.pcap", [ataque(4, ("10.0.0.1",)), benigno(10), ataque(3, ("10.0.0.9",), destino="10.0.0.200")],
    )

    assert len(reproduzir(mesmo_alvo, classificador()).incidentes) == 1
    assert len(reproduzir(outro_alvo, classificador()).incidentes) == 2


def test_pausa_na_captura_encerra_o_incidente_e_nao_entra_no_atraso(tmp_path):
    caminho = escrever_pcap(tmp_path / "a.pcap", [ataque(4), ataque(4, pausa=3600)])

    r = reproduzir(caminho, classificador(), reagrupa_s=0)

    assert len(r.incidentes) == 2
    # A janela que contém a pausa não entra em sequência: a segunda abre três janelas depois dela.
    segundo = r.incidentes[1]
    assert segundo.aberto_em - segundo.primeira_janela_de_ataque < 60
    assert r.janelas == 8


def test_teto_de_incidentes(tmp_path):
    caminho = escrever_pcap(tmp_path / "a.pcap", [ataque(4), benigno(10), ataque(4), benigno(10), ataque(4)])

    r = reproduzir(caminho, classificador(), reagrupa_s=0, teto=2)

    assert len(r.incidentes) == 2
    assert r.alem_do_teto == 1


@pytest.mark.parametrize(("origens", "categoria", "distribuido"), [
    ((ATACANTE,), "DoS", False),
    ((f"10.9.0.{i}" for i in range(1, 8)), "DDoS", True),
])
def test_regra_das_origens_separa_dos_de_ddos(tmp_path, origens, categoria, distribuido):
    caminho = escrever_pcap(tmp_path / "a.pcap", [ataque(5, tuple(origens))])
    c = classificador()

    cenario = cenarios_da_reproducao(reproduzir(caminho, c), c)[0]

    assert cenario.incidente.categoria_do_modelo == "DDoS+DoS"
    assert cenario.incidente.categoria == categoria
    assert cenario.incidente.distribuido is distribuido
    assert cenario.incidente.destinos[0].endereco == VITIMA


def test_incidente_no_formato_do_contrato_com_features_e_janelas_reais(tmp_path):
    c = classificador()
    reproducao = reproduzir(escrever_pcap(tmp_path / "a.pcap", [benigno(1), ataque(5), benigno(10)]), c)

    cenario = cenarios_da_reproducao(reproducao, c)[0]

    incidente = cenario.incidente
    assert incidente.id == "inc-0001"
    assert incidente.janelas == 5
    assert incidente.confianca == 0.9
    assert incidente.origens[0].endereco == ATACANTE
    assert incidente.features_principais[0].nome == "syn_flag_number"
    assert incidente.features_principais[0].valor == 1.0
    assert incidente.features_principais[0].referencia_benigno == ler_referencia()["syn_flag_number"]
    assert [j.indice for j in cenario.janelas_reais] == [0, 1, 2, 3, 4]
    assert cenario.janelas_reais[0].origem == ATACANTE
    assert cenario.lote.por_categoria == {"DDoS+DoS": 5}


def test_log_gravado_e_lido_pelo_servidor_com_as_janelas_reais(tmp_path):
    c = classificador()
    reproducao = reproduzir(escrever_pcap(tmp_path / "a.pcap", [benigno(3), ataque(5), benigno(10)]), c)
    cenarios = cenarios_da_reproducao(reproducao, c)
    log = tmp_path / "eventos.jsonl"

    registro = gravar(cenarios, reproducao, log)

    tipos = [evento.tipo for evento in ler(log)]
    assert tipos == ["janelas_classificadas", "incidente_aberto", "janelas_classificadas"]
    assert list(reconstruir(ler(log)).incidentes) == ["inc-0001"]
    stub = Stub(registro, agente="triagem", cenarios=cenarios)
    fatia = stub.chamar("obter_janelas", id="inc-0001", limite=2)
    assert fatia.total == 5
    assert [j.indice for j in fatia.janelas] == [0, 4]
    assert fatia.janelas[0].origem == ATACANTE


def test_resumo_traz_o_atraso_de_deteccao_e_a_politica(tmp_path):
    c = classificador()
    reproducao = reproduzir(escrever_pcap(tmp_path / "a.pcap", [ataque(3)]), c, nome="captura.pcap")
    cenarios = cenarios_da_reproducao(reproducao, c)

    saida = resumo(reproducao, cenarios, c)

    assert saida["arquivo"] == "captura.pcap"
    assert saida["incidentes"][0]["atraso_de_deteccao_s"] == pytest.approx(2.99, abs=1e-3)
    assert saida["ponto_de_operacao"] == {"regra": "argmax", "limiar": None, "seguidas": 3}
    assert saida["acionamento"]["fecha_apos"] == 10
