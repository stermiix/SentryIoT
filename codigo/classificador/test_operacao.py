import json

import numpy as np
import pytest

from codigo.classificador.operacao import (
    SUFIXO,
    PontoDeOperacao,
    Vigia,
    ao_lado_do_modelo,
    gravar,
    ler,
)
from codigo.classificador.rodadas import alarmes, aplicar_limiar

CLASSES = ["Benign", "DDoS+DoS", "Recon", "Web"]


def test_uma_janela_e_ataque_quando_1_menos_p_benigno_alcanca_o_limiar():
    ponto = PontoDeOperacao(0.6, 3)
    # 1 − 0,40 = 0,60: ataque, na categoria de ataque mais provável, mesmo com Benign na frente.
    assert ponto.categoria([0.40, 0.35, 0.05, 0.20], CLASSES) == "DDoS+DoS"
    assert ponto.categoria([0.41, 0.35, 0.04, 0.20], CLASSES) == "Benign"
    assert ponto.categoria([0.10, 0.20, 0.30, 0.40], CLASSES) == "Web"
    # A ordem das colunas é a das classes do modelo.
    assert ponto.categoria([0.35, 0.40, 0.05, 0.20], ["DDoS+DoS", "Benign", "Recon", "Web"]) == "DDoS+DoS"
    with pytest.raises(ValueError, match="vetor"):
        ponto.categoria([[0.4, 0.6, 0.0, 0.0]], CLASSES)
    with pytest.raises(ValueError, match="4 probabilidades"):
        ponto.categorias([[0.4, 0.6]], CLASSES)
    with pytest.raises(ValueError, match="Benign"):
        ponto.categorias([[0.4, 0.6]], ["DDoS+DoS", "Recon"])


def test_limiar_e_janelas_seguidas_validos():
    for limiar in (0, -0.1, 1.5):
        with pytest.raises(ValueError, match="limiar"):
            PontoDeOperacao(limiar, 3)
    for seguidas in (0, 2.5):
        with pytest.raises(ValueError, match="seguidas"):
            PontoDeOperacao(0.5, seguidas)
    assert PontoDeOperacao(1.0, 1).categoria([0.0, 1.0, 0.0, 0.0], CLASSES) == "DDoS+DoS"


def test_incidente_abre_na_n_esima_janela_de_ataque_seguida_uma_vez_por_sequencia():
    ponto = PontoDeOperacao(0.5, 3)
    sequencia = ["Recon", "Recon", "Benign", "Recon", "Web", "Recon", "Recon", "Benign", "DDoS+DoS", "DDoS+DoS",
                 "DDoS+DoS"]
    # As categorias de ataque podem variar dentro da sequência.
    assert ponto.incidentes(sequencia) == [5, 10]
    assert PontoDeOperacao(0.5, 1).incidentes(sequencia) == [0, 3, 8]
    assert PontoDeOperacao(0.5, 5).incidentes(sequencia) == []
    assert ponto.incidentes([]) == []


def test_vigia_janela_a_janela_da_o_mesmo_que_a_sequencia():
    gerador = np.random.default_rng(0)
    proba = gerador.dirichlet([2, 1, 1, 1], 300)
    ponto = PontoDeOperacao(0.55, 3)
    categorias, incidentes = ponto.aplicar(proba, CLASSES)
    vigia = Vigia(ponto, CLASSES)
    passo_a_passo = [vigia.alimentar(linha) for linha in proba]
    assert [c for c, _ in passo_a_passo] == categorias.tolist()
    assert [i for i, (_, abre) in enumerate(passo_a_passo) if abre] == incidentes and incidentes


def test_a_regra_e_a_que_as_rodadas_mediram():
    gerador = np.random.default_rng(1)
    proba = gerador.dirichlet([1, 1, 1, 1], 2000)
    proba[:50] = np.array([0.4, 0.6, 0.0, 0.0])  # no limiar exato
    for limiar in (0.05, 0.5, 0.6, 0.75, 1.0):
        ponto = PontoDeOperacao(limiar, 3)
        categorias = ponto.categorias(proba, CLASSES)
        assert categorias.tolist() == aplicar_limiar(proba, CLASSES, limiar).tolist()
        assert ponto.incidentes(categorias) == alarmes(categorias != "Benign", 3)


def test_o_json_fica_ao_lado_do_modelo_e_so_vale_para_ele(tmp_path):
    modelo = tmp_path / "rf_teste.joblib"
    modelo.write_bytes(b"modelo")
    assert ao_lado_do_modelo(modelo) == tmp_path / f"rf_teste{SUFIXO}"
    caminho = gravar(modelo, PontoDeOperacao(0.62, 3), configuracao="5", alvo=0.01)
    conteudo = json.loads(caminho.read_text(encoding="utf-8"))
    assert (conteudo["limiar"], conteudo["seguidas"], conteudo["configuracao"]) == (0.62, 3, "5")
    assert conteudo["modelo"]["arquivo"] == "rf_teste.joblib" and len(conteudo["modelo"]["sha256"]) == 64
    assert ler(modelo) == PontoDeOperacao(0.62, 3)
    modelo.write_bytes(b"outro modelo")
    with pytest.raises(ValueError, match="outro modelo"):
        ler(modelo)
    assert ler(modelo, conferir=False) == PontoDeOperacao(0.62, 3)
