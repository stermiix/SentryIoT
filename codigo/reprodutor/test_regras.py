import numpy as np
import pytest

from codigo.classificador.operacao import PontoDeOperacao
from codigo.reprodutor import regras
from codigo.reprodutor.regras import (
    Captura,
    PontoPorCategoria,
    extrair,
    medir,
    reproduzir_guardado,
    resumir,
)
from codigo.reprodutor.reprodutor import reproduzir
from codigo.reprodutor.test_reprodutor import (
    ataque,
    benigno,
    classificador,
    escrever_pcap,
)


@pytest.mark.parametrize("seguidas", [3, 4])
def test_reproduzir_com_janelas_guardadas_da_o_mesmo_que_ler_o_pcap(tmp_path, seguidas):
    caminho = escrever_pcap(tmp_path / "a.pcap", [benigno(5), ataque(6), benigno(12), ataque(3), benigno(2)])
    cl = classificador(seguidas)

    lido = reproduzir(caminho, cl)
    guardado = reproduzir_guardado(caminho, extrair(caminho), cl)

    assert (guardado.janelas, dict(guardado.por_categoria), dict(guardado.nao_julgadas)) == (
        lido.janelas, dict(lido.por_categoria), dict(lido.nao_julgadas))
    assert [(i.primeira_janela_de_ataque, i.aberto_em, i.categoria_principal()) for i in guardado.incidentes] == [
        (i.primeira_janela_de_ataque, i.aberto_em, i.categoria_principal()) for i in lido.incidentes]


def test_mais_janelas_seguidas_nao_abrem_incidente_com_uma_sequencia_curta(tmp_path):
    caminho = escrever_pcap(tmp_path / "a.pcap", [benigno(5), ataque(3), benigno(12)])
    janelas = extrair(caminho)

    com_3 = reproduzir_guardado(caminho, janelas, classificador(3))
    com_4 = reproduzir_guardado(caminho, janelas, classificador(4))

    assert (len(com_3.incidentes), len(com_4.incidentes)) == (1, 0)


def test_limiar_por_categoria_so_vale_para_a_categoria_dele():
    ponto = PontoPorCategoria((("Spoofing", 0.8),), 3)
    classes = ["Benign", "DDoS+DoS", "Spoofing"]

    assert ponto.categoria([0.3, 0.0, 0.7], classes) == "Benign"  # 1 − P(Benign) = 0,7 < 0,8
    assert ponto.categoria([0.1, 0.0, 0.9], classes) == "Spoofing"
    assert ponto.categoria([0.4, 0.6, 0.0], classes) == "DDoS+DoS"  # fora dos limiares: argmax
    assert list(ponto.categorias(np.array([[0.3, 0.0, 0.7], [0.1, 0.0, 0.9]]), classes)) == ["Benign", "Spoofing"]


def test_a_primeira_regra_e_a_do_sistema():
    nome, ponto = regras.regras()[0]
    assert nome.startswith("sistema") and ponto == PontoDeOperacao(None, regras.SEGUIDAS)


def test_resumo_conta_falsos_nas_benignas_e_alarmes_nas_de_ataque(tmp_path):
    caminho = escrever_pcap(tmp_path / "a.pcap", [benigno(5), ataque(6), benigno(12)])
    rep = reproduzir(caminho, classificador(3))
    linhas = [
        medir(Captura("Casa", str(caminho), True), rep, "r"),
        medir(Captura("CICIoT2023 ataque (teste)", str(caminho), False, "DDoS+DoS"), rep, "r"),
    ]

    r = resumir(linhas)["r"]

    assert (r["falsos"], r["detectadas"], r["de_ataque"]) == (1, 1, 1)
    assert r["grupos"]["CICIoT2023 ataque (teste)"]["categoria_certa"] == 1
