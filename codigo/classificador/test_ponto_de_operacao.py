import csv
import json
from pathlib import Path

import numpy as np
import pytest

from codigo.classificador.operacao import PontoDeOperacao, ao_lado_do_modelo, ler
from codigo.classificador.ponto_de_operacao import (
    MANIFESTO,
    RELATORIO,
    escolher_limiar,
    inicios_da_validacao,
    lados_do_treino_reduzido,
    main,
    na_validacao,
)
from codigo.classificador.ponto_de_operacao_relatorio import montar_relatorio
from codigo.classificador.regerar import MANIFESTO as MANIFESTO_DA_REGERACAO
from codigo.classificador.rodadas import (
    CLASSES,
    MANIFESTO_DAS_CAPTURAS,
    Configuracao,
    Execucao,
    amostra,
    lados,
    ler_dados,
    no_teste,
)
from codigo.classificador.rodadas import main as rodadas
from codigo.classificador.test_rodadas import FORA, preparar_regerado
from codigo.classificador.treinar_regerado import main as treinar_regerado

ARGUMENTOS = ("--sementes", "42,1,2", "--arvores", "5", "--teto", "30", "--nucleos", "1")


def configuracoes(regeracao, pasta):
    caminho = str(pasta / "resultados" / MANIFESTO_DA_REGERACAO)
    return (
        Configuracao("0", "o modelo atual", regeracao["destino"], caminho),
        Configuracao("5", "a 0 com o fundo da parte de treino como Benign", regeracao["destino"], caminho,
                     fundo_como_benigno=True),
    )


# --- a divisão com a validação ------------------------------------------------------------------


def test_a_validacao_sao_as_ultimas_15_por_cento_da_parte_de_treino(tmp_path):
    regeracao = preparar_regerado(tmp_path)
    inicios = inicios_da_validacao(regeracao, 0)
    # Recon-PortScan: 48 janelas, corte por tempo na 34; a validação começa em 85% de 34, na 29.
    assert lados(regeracao, 0)["Recon-PortScan.pcap"] == 34 and inicios["Recon-PortScan.pcap"] == 29
    # Pcap de treino de um rótulo de vários pcaps: as últimas 15% do arquivo inteiro (40 janelas, a partir da 34).
    assert inicios["BenignTraffic.pcap"] == 34 and inicios["DDoS-SYN_Flood.pcap"] == 34
    # O pcap inteiro no teste não tem validação, e cada rotação tem a sua.
    assert "BenignTraffic2.pcap" not in inicios and "DDoS-SYN_Flood1.pcap" not in inicios
    assert "BenignTraffic.pcap" not in inicios_da_validacao(regeracao, 1)
    assert inicios_da_validacao(regeracao, 1)["BenignTraffic2.pcap"] == 34


def test_treino_reduzido_validacao_e_teste_nao_se_cruzam(tmp_path):
    regeracao = preparar_regerado(tmp_path)
    dados = ler_dados(regeracao["destino"], regeracao)
    lados_da_divisao = lados(regeracao, 0)
    inicios = inicios_da_validacao(regeracao, 0)
    reduzido = lados_do_treino_reduzido(lados_da_divisao, inicios)
    meta = dados.meta
    teste = no_teste(meta, lados_da_divisao)
    validacao = na_validacao(meta, lados_da_divisao, inicios)
    fora_do_reduzido = no_teste(meta, reduzido)
    # O teste não muda; a validação sai do treino e não toca o teste.
    assert not (validacao & teste).any()
    assert np.array_equal(fora_do_reduzido, teste | validacao)
    portscan = (meta["arquivo"] == "Recon-PortScan.pcap").to_numpy()
    indices = meta["indice"].to_numpy()
    assert set(indices[portscan & validacao]) == {i for i in range(29, 34)} - set(range(3, 48, 6))
    assert (indices[portscan & ~fora_do_reduzido] < 29).all()


def test_o_fundo_da_validacao_fica_fora_do_treino_reduzido(tmp_path):
    regeracao = preparar_regerado(tmp_path)
    dados = ler_dados(regeracao["destino"], regeracao)
    configuracao = configuracoes(regeracao, tmp_path)[1]
    execucao = Execucao(configuracao, dados, teto=30, trabalho=tmp_path / "t")
    lados_da_divisao = lados(regeracao, 0)
    reduzido = lados_do_treino_reduzido(lados_da_divisao, inicios_da_validacao(regeracao, 0))
    posicoes = amostra(dados, 42, 30)
    meta = dados.meta.iloc[posicoes]
    _, y_inteiro = execucao._treino(posicoes, no_teste(meta, lados_da_divisao), lados_da_divisao)
    _, y_reduzido = execucao._treino(posicoes, no_teste(meta, reduzido), reduzido)
    fundo_inteiro = int((~no_teste(dados.fundo_meta, lados_da_divisao)).sum())
    fundo_reduzido = int((~no_teste(dados.fundo_meta, reduzido)).sum())
    assert fundo_reduzido < fundo_inteiro
    linhas_reduzido = int((~no_teste(meta, reduzido)).sum())
    assert len(y_reduzido) == linhas_reduzido + fundo_reduzido
    assert (y_reduzido[linhas_reduzido:] == "Benign").all()
    assert len(y_inteiro) == int((~no_teste(meta, lados_da_divisao)).sum()) + fundo_inteiro


def test_o_limiar_e_o_menor_da_grade_dentro_do_alvo():
    p = np.r_[np.zeros(95), [0.5, 0.6, 0.7, 0.8, 0.9]]
    # Com 2% de 100 janelas, cabem 2 como ataque: 0,71 deixa 0,8 e 0,9; 0,70 deixaria também o 0,7 (inclusivo).
    limiar, curva = escolher_limiar(p, 0.02)
    assert limiar == 0.71 and curva[0.70] == 3 and curva[0.71] == 2
    assert escolher_limiar(p, 0.05)[0] == 0.01  # cinco de cem, todas acima de 0
    assert escolher_limiar(np.zeros(10), 0.01)[0] == 0.01
    assert escolher_limiar(np.ones(10), 0.01)[0] is None
    with pytest.raises(ValueError, match="benigna"):
        escolher_limiar([])


# --- de ponta a ponta --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def caso(tmp_path_factory):
    """O caso sintético: o modelo do sistema salvo, a comparação de capturas com a 0 e a 5 e o ponto de operação."""
    import codigo.classificador.rodadas as modulo

    pasta = tmp_path_factory.mktemp("ponto")
    regeracao = preparar_regerado(pasta)
    assert treinar_regerado(["--saida", str(pasta / "resultados"), "--modelos", str(pasta / "modelos"),
                             "--arvores", "5", "--nucleos", "1", "--teto", "30"]) == 0
    originais = modulo.CONFIGURACOES, modulo.PCAPS_FORA
    modulo.CONFIGURACOES, modulo.PCAPS_FORA = configuracoes(regeracao, pasta), FORA
    try:
        assert rodadas(["--capturas", "--saida", str(pasta / "resultados"), "--trabalho", str(pasta / "rodadas"),
                        *ARGUMENTOS]) == 0
        assert executar(pasta) == 0
    finally:
        modulo.CONFIGURACOES, modulo.PCAPS_FORA = originais
    return pasta


def executar(pasta, *extras):
    return main(["--saida", str(pasta / "resultados"), "--trabalho", str(pasta / "ponto"),
                 "--trabalho-das-rodadas", str(pasta / "rodadas"), "--modelos", str(pasta / "modelos"),
                 "--modelo-do-sistema", str(pasta / "modelos" / "rf_regerado_janela_100.joblib"), *ARGUMENTOS, *extras])


def ler_manifesto(pasta):
    return json.loads((pasta / "resultados" / MANIFESTO).read_text(encoding="utf-8"))


def test_ponto_de_operacao_grava_manifesto_relatorio_e_tabelas(caso):
    m = ler_manifesto(caso)
    r = m["resultados"]
    assert list(r["configuracoes"]) == ["0", "5"]
    assert set(r["configuracoes"]["5"]["resultados"]) == {"0", "1", "2"}
    assert set(r["configuracoes"]["5"]["resultados"]["1"]) == {"42", "1", "2"}
    assert set(r["comparacoes"]) == {"0:limiar-argmax", "5:limiar-argmax", "5-0:limiar"}
    assert r["regra"] is not None and set(r["regra"]["condicoes"]) == {"a", "b", "c"}
    texto = (caso / "resultados" / RELATORIO).read_text(encoding="utf-8")
    assert texto == montar_relatorio(m)
    for secao in ("## Resumo", "## O limiar escolhido na validação", "## No teste: corte por tempo",
                  "## Benigno de fora: por janela e por alarme", "## Fundo virando ataque",
                  "## Pcaps de ataque no trecho de teste", "## Quais diferenças contam", "## Conferência",
                  "## O ponto de operação guardado", "## Como os números foram obtidos"):
        assert secao in texto, secao
    for tabela in ("limiar", "curva", "teste", "benigno", "trechos", "diferencas"):
        assert (caso / "resultados" / f"ponto_de_operacao_{tabela}.csv").exists(), tabela


def test_o_limiar_escolhido_atende_ao_alvo_na_validacao_e_e_o_menor(caso):
    m = ler_manifesto(caso)
    for c in m["resultados"]["configuracoes"].values():
        for por_semente in c["resultados"].values():
            for u in por_semente.values():
                v = u["validacao"]
                curva = {float(t): n for t, n in v["benigno_como_ataque"].items()}
                assert curva[u["limiar"]] <= 0.01 * v["janelas_benignas"]
                assert all(n > 0.01 * v["janelas_benignas"] for t, n in curva.items() if t < u["limiar"])


def test_o_treino_inteiro_e_o_mesmo_das_rodadas_e_o_modelo_salvo_confere(caso):
    m = ler_manifesto(caso)
    for c in m["resultados"]["configuracoes"].values():
        for por_semente in c["resultados"].values():
            for u in por_semente.values():
                assert u["conferencia"] is not None and not any(u["conferencia"].values())
    salvo = m["resultados"]["configuracoes"]["0"]["resultados"]["0"]["42"]["modelo_do_sistema"]
    assert salvo["diferentes_argmax"] == 0 and salvo["diferentes_limiar"] == 0
    # O argmax do ponto de operação dá as medidas do corte das rodadas.
    capturas = json.loads((caso / "resultados" / MANIFESTO_DAS_CAPTURAS).read_text(encoding="utf-8"))
    for nome in ("0", "5"):
        for semente in ("42", "1", "2"):
            corte = capturas["resultados"][nome]["corte"][semente]["medidas"]
            argmax = m["resultados"]["configuracoes"][nome]["resultados"]["0"][semente]["medidas"]["argmax"]
            assert argmax["macro_f1"] == pytest.approx(corte["macro_f1"])


def test_o_ponto_fica_ao_lado_de_cada_modelo(caso):
    m = ler_manifesto(caso)
    gravados = m["resultados"]["gravados"]
    assert set(gravados) == {"0", "5"}
    sistema = caso / "modelos" / "rf_regerado_janela_100.joblib"
    quinta = caso / "modelos" / "rf_regerado_janela_100_configuracao_5.joblib"
    for nome, modelo in (("0", sistema), ("5", quinta)):
        unidade = m["resultados"]["configuracoes"][nome]["resultados"]["0"]["42"]
        assert ler(modelo) == PontoDeOperacao(unidade["limiar"], 3)
        conteudo = json.loads(ao_lado_do_modelo(modelo).read_text(encoding="utf-8"))
        assert conteudo["configuracao"] == nome and conteudo["semente"] == 42
    with open(caso / "resultados" / "ponto_de_operacao_limiar.csv", encoding="utf-8", newline="") as arquivo:
        linhas = list(csv.DictReader(arquivo))
    assert len(linhas) == 2 * 3 * 3


def test_o_limiar_so_decide_entre_benign_e_ataque(caso):
    # Sendo ataque pelas duas regras, a janela fica na mesma categoria: a mais provável entre as de ataque.
    benigno = list(CLASSES).index("Benign")
    arquivos = sorted((caso / "ponto").glob("*/0__42.npz"))
    assert len(arquivos) == 2
    for caminho in arquivos:
        with np.load(caminho) as d:
            for parte in ("teste", "fundo", "benigno"):
                argmax, limiar = d[f"{parte}_argmax"], d[f"{parte}_limiar"]
                ataque = (argmax != benigno) & (limiar != benigno)
                assert np.array_equal(argmax[ataque], limiar[ataque])


def test_execucao_interrompida_continua_sem_treinar_de_novo(caso, monkeypatch):
    import codigo.classificador.ponto_de_operacao as ponto
    import codigo.classificador.rodadas as modulo

    regeracao = json.loads((caso / "resultados" / MANIFESTO_DA_REGERACAO).read_text(encoding="utf-8"))
    monkeypatch.setattr(modulo, "CONFIGURACOES", configuracoes(regeracao, caso))
    antes = ler_manifesto(caso)
    monkeypatch.setattr(modulo, "treinar", lambda *a, **k: pytest.fail("treinou de novo"))
    assert executar(caso) == 0
    depois = ler_manifesto(caso)
    assert depois["resultados"]["configuracoes"] == antes["resultados"]["configuracoes"]
    monkeypatch.setattr(ponto, "ler_dados", lambda *a, **k: pytest.fail("leu os dados"))
    assert executar(caso, "--refazer-relatorio") == 0


def test_configuracoes_que_leem_pastas_diferentes_sao_recusadas(caso, capsys):
    assert main(["--configuracoes", "0,4", "--saida", str(caso / "resultados")]) == 1
    assert "mesma pasta" in capsys.readouterr().err
    assert main(["--configuracoes", "0,9", "--saida", str(caso / "resultados")]) == 1


# --- os resultados versionados -----------------------------------------------------------------

RESULTADOS = Path(__file__).resolve().parents[2] / "experimentos" / "resultados"


@pytest.mark.skipif(not (RESULTADOS / MANIFESTO).exists(), reason="ponto de operação ainda não medido")
def test_relatorio_versionado_sai_do_manifesto():
    m = json.loads((RESULTADOS / MANIFESTO).read_text(encoding="utf-8"))
    assert (RESULTADOS / RELATORIO).read_text(encoding="utf-8") == montar_relatorio(m)
    for c in m["resultados"]["configuracoes"].values():
        for por_semente in c["resultados"].values():
            for u in por_semente.values():
                v = u["validacao"]
                assert v["benigno_como_ataque"][str(u["limiar"])] <= 0.01 * v["janelas_benignas"]
                assert u["conferencia"] is not None and not any(u["conferencia"].values())
    assert set(m["resultados"]["gravados"]) == set(m["resultados"]["configuracoes"])
