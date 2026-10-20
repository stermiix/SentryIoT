"""Testes da avaliação do reprodutor contra a verdade de campo, com pcaps montados no teste."""

import json

import dpkt

from codigo.reprodutor import avaliar
from codigo.reprodutor.test_reprodutor import (
    ATACANTE,
    VITIMA,
    benigno,
    classificador,
    escrever_pcap,
    tcp,
)

MAC_DO_TESTE = "02:00:00:00:00:01"


def _manifesto(tmp_path, arquivo, categoria, benigno_=False):
    caminho = tmp_path / "manifesto.json"
    caminho.write_text(json.dumps({
        "pcaps": [{"arquivo": arquivo, "rotulo": "X", "categoria": categoria, "benigno": benigno_, "janelas": {"100": {"extraidas": 20}}}],
        "rotulos": [{"arquivos": [arquivo]}],
    }))
    return caminho


def test_incidente_conferido_com_os_quadros_do_atacante(tmp_path, monkeypatch):
    # Os quadros montados no teste saem do MAC 02:00:00:00:00:01; ele faz o papel do atacante.
    monkeypatch.setattr(avaliar, "ATACANTES", frozenset({MAC_DO_TESTE}))
    pcap = escrever_pcap(tmp_path / "DoS-X.pcap", [(4, lambda i: tcp(ATACANTE, VITIMA, dpkt.tcp.TH_SYN), 0.0), benigno(10)])

    resultado = avaliar.avaliar_pcap(pcap, classificador(), _manifesto(tmp_path, "DoS-X.pcap", "DoS"))

    (incidente,) = resultado["incidentes"]
    assert incidente["categoria"] == "DoS" and avaliar._categoria_certa(resultado, incidente)
    assert incidente["origem_1_e_atacante"] is True
    assert incidente["janelas_com_atacante"] == 4
    assert incidente["janelas_no_teste"] == 0
    assert resultado["corte"] == 14


def test_relatorio_soma_os_pcaps_de_ataque_e_conta_os_alarmes_dos_benignos(tmp_path, monkeypatch):
    monkeypatch.setattr(avaliar, "ATACANTES", frozenset({MAC_DO_TESTE}))
    pcap = escrever_pcap(tmp_path / "DoS-X.pcap", [(4, lambda i: tcp(ATACANTE, VITIMA, dpkt.tcp.TH_SYN), 0.0), benigno(10)])
    de_ataque = avaliar.avaliar_pcap(pcap, classificador(), _manifesto(tmp_path, "DoS-X.pcap", "DoS"))
    benigno_ = {"arquivo": "BenignTraffic9.pcap", "benigno": True, "janelas": 100, "duracao_s": 7200.0, "incidentes": [], "processamento_s": 1.0}

    texto = avaliar.relatorio([de_ataque, benigno_])

    assert "| `DoS-X.pcap` | DoS | 14 | 1 | 100,0% | 0 | 1/1 | 0/1 | 1/1 |" in texto
    assert "a regra das origens deu a categoria do arquivo em 1 de 1" in texto
    assert "| `BenignTraffic9.pcap` | 100 | 2,0 | 0 | 0,00 | — |" in texto
