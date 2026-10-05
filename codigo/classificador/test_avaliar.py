import json

import numpy as np
import pandas as pd
import pytest
from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support

from codigo.captura.extrator import COLUNAS
from codigo.classificador.avaliar import (
    avaliar,
    contar,
    importancias,
    main,
    matriz_de_confusao,
    medir,
    pesos,
    tempo_por_mil,
    teto,
)
from codigo.classificador.mapeamento import CATEGORIAS, ROTULOS
from codigo.classificador.preparar import (
    ALVOS,
    FEATURES_33,
    FEATURES_39,
    FUSAO,
    alvo,
    dividir,
    matriz,
)
from codigo.classificador.test_preparar import gravar_amostra, quadro_sintetico
from codigo.classificador.treinar import prever, salvar, treinar


def colunas(*pares):
    """Rótulos e classes previstas a partir de (rótulo, classe prevista, quantas linhas)."""
    rotulos = [rotulo for rotulo, _, vezes in pares for _ in range(vezes)]
    previsto = [classe for _, classe, vezes in pares for _ in range(vezes)]
    return np.array(rotulos, dtype=object), np.array(previsto, dtype=object)


# 20 linhas: 10 benignas, 6 de um flood DDoS e 4 de varredura de portas.
CASO_FEITO_A_MAO = (
    ("BenignTraffic", "Benign", 7), ("BenignTraffic", "Recon", 2), ("BenignTraffic", "DDoS", 1),
    ("DDoS-ICMP_Flood", "DDoS", 5), ("DDoS-ICMP_Flood", "Benign", 1),
    ("Recon-PortScan", "Recon", 3), ("Recon-PortScan", "DDoS", 1),
)
# 30 linhas, com dois rótulos de DDoS em que o modelo acerta em proporções diferentes.
CASO_DA_PONDERACAO = (
    ("DDoS-ICMP_Flood", "DDoS", 9), ("DDoS-ICMP_Flood", "Benign", 1),
    ("DDoS-SlowLoris", "DDoS", 5), ("DDoS-SlowLoris", "Benign", 5),
    ("BenignTraffic", "Benign", 8), ("BenignTraffic", "DDoS", 2),
)
POPULACAO_DA_PONDERACAO = {"DDoS-ICMP_Flood": 9000, "DDoS-SlowLoris": 100, "BenignTraffic": 900}


def medidas(pares, nome_do_alvo="8", populacao=None):
    rotulos, previsto = colunas(*pares)
    por_rotulo = contar(rotulos, previsto, ALVOS[nome_do_alvo].classes)
    return medir(matriz_de_confusao(por_rotulo, nome_do_alvo, populacao), ALVOS[nome_do_alvo].benigno)


def test_contar_cruza_o_rotulo_real_com_a_classe_prevista():
    rotulos, previsto = colunas(*CASO_FEITO_A_MAO)
    por_rotulo = contar(rotulos, previsto, CATEGORIAS)
    # As linhas seguem a ordem dos rótulos do projeto, e só entram os rótulos presentes.
    assert list(por_rotulo.index) == ["DDoS-ICMP_Flood", "Recon-PortScan", "BenignTraffic"]
    assert list(por_rotulo.columns) == list(CATEGORIAS)
    assert por_rotulo.loc["BenignTraffic", ["DDoS", "Recon", "Benign"]].tolist() == [1, 2, 7]
    assert por_rotulo.loc["DDoS-ICMP_Flood", ["DDoS", "Benign"]].tolist() == [5, 1]
    assert int(por_rotulo.to_numpy().sum()) == 20
    with pytest.raises(ValueError, match="classe prevista fora do alvo: Flood"):
        contar(rotulos, np.array(["Flood"] * 20, dtype=object), CATEGORIAS)


def test_matriz_de_confusao_junta_os_rotulos_na_classe_do_alvo():
    rotulos, previsto = colunas(*CASO_DA_PONDERACAO)
    confusao = matriz_de_confusao(contar(rotulos, previsto, CATEGORIAS), "8")
    assert list(confusao.index) == list(confusao.columns) == list(CATEGORIAS)
    assert confusao.loc["DDoS", "DDoS"] == 14 and confusao.loc["DDoS", "Benign"] == 6
    assert confusao.loc["Benign", "Benign"] == 8 and confusao.loc["Benign", "DDoS"] == 2
    assert confusao.to_numpy().sum() == 30


def test_metricas_do_caso_feito_a_mao():
    m = medidas(CASO_FEITO_A_MAO)
    assert m["acuracia"] == pytest.approx(15 / 20)
    ddos, recon, benigno = m["por_classe"]["DDoS"], m["por_classe"]["Recon"], m["por_classe"]["Benign"]
    assert (ddos["suporte"], recon["suporte"], benigno["suporte"]) == (6, 4, 10)
    assert ddos["precisao"] == pytest.approx(5 / 7) and ddos["recall"] == pytest.approx(5 / 6)
    assert recon["precisao"] == pytest.approx(3 / 5) and recon["recall"] == pytest.approx(3 / 4)
    assert benigno["precisao"] == pytest.approx(7 / 8) and benigno["recall"] == pytest.approx(7 / 10)
    f1 = [2 * p * r / (p + r) for p, r in ((5 / 7, 5 / 6), (3 / 5, 3 / 4), (7 / 8, 7 / 10))]
    assert [ddos["f1"], recon["f1"], benigno["f1"]] == pytest.approx(f1)
    # A média macro é sobre as classes com linhas no conjunto avaliado.
    assert m["macro_f1"] == pytest.approx(sum(f1) / 3)
    assert m["f1_ponderado"] == pytest.approx((6 * f1[0] + 4 * f1[1] + 10 * f1[2]) / 20)


def test_taxa_de_falso_positivo_do_caso_feito_a_mao():
    m = medidas(CASO_FEITO_A_MAO)
    # Das 10 linhas benignas, 3 foram classificadas como algum ataque.
    assert m["falso_positivo_benigno"] == pytest.approx(3 / 10)
    por_classe = m["por_classe"]
    # Por classe: linhas de outras classes que o modelo pôs nesta, sobre as linhas das outras classes.
    assert por_classe["DDoS"]["taxa_falso_positivo"] == pytest.approx(2 / 14)
    assert por_classe["Recon"]["taxa_falso_positivo"] == pytest.approx(2 / 16)
    assert por_classe["Benign"]["taxa_falso_positivo"] == pytest.approx(1 / 10)
    assert por_classe["Mirai"]["taxa_falso_positivo"] == 0.0


def test_classe_sem_linhas_fica_sem_recall_e_fora_da_media():
    por_classe = medidas(CASO_FEITO_A_MAO)["por_classe"]
    assert list(por_classe) == list(CATEGORIAS)
    assert por_classe["Mirai"] == {
        "precisao": None, "recall": None, "f1": None, "suporte": 0, "taxa_falso_positivo": 0.0,
    }
    # Sem tráfego benigno no conjunto, a taxa de falso positivo não existe.
    assert medidas(CASO_FEITO_A_MAO[3:])["falso_positivo_benigno"] is None


def test_classe_que_o_modelo_nunca_responde_tem_precisao_e_f1_zero():
    m = medidas((("XSS", "Benign", 3), ("BenignTraffic", "Benign", 5)))
    assert m["por_classe"]["Web"] == {
        "precisao": 0.0, "recall": 0.0, "f1": 0.0, "suporte": 3, "taxa_falso_positivo": 0.0,
    }
    assert m["macro_f1"] == pytest.approx((0 + 2 * (5 / 8) / (5 / 8 + 1)) / 2)


def test_alvo_binario_e_de_34_classes_usam_o_nome_certo_do_benigno():
    binario = medidas((("BenignTraffic", "Attack", 1), ("BenignTraffic", "Benign", 3), ("XSS", "Attack", 2)), "2")
    assert binario["falso_positivo_benigno"] == pytest.approx(1 / 4)
    completo = medidas((("BenignTraffic", "XSS", 1), ("BenignTraffic", "BenignTraffic", 1), ("XSS", "XSS", 2)), "34")
    assert completo["falso_positivo_benigno"] == pytest.approx(1 / 2)
    assert list(completo["por_classe"]) == list(ROTULOS)


def test_pesos_levam_cada_rotulo_ao_tamanho_que_tem_no_conjunto_completo():
    rotulos, _ = colunas(*CASO_DA_PONDERACAO)
    w = pesos(rotulos, POPULACAO_DA_PONDERACAO)
    assert w[rotulos == "DDoS-ICMP_Flood"].tolist() == [900.0] * 10
    assert w[rotulos == "DDoS-SlowLoris"].tolist() == [10.0] * 10
    assert w[rotulos == "BenignTraffic"].tolist() == [90.0] * 10
    assert w.sum() == 10_000
    with pytest.raises(ValueError, match="sem contagem no conjunto completo: XSS"):
        pesos(np.array(["XSS"], dtype=object), POPULACAO_DA_PONDERACAO)


def test_reponderacao_com_contagens_conhecidas():
    amostra = medidas(CASO_DA_PONDERACAO)
    original = medidas(CASO_DA_PONDERACAO, populacao=POPULACAO_DA_PONDERACAO)
    assert amostra["acuracia"] == pytest.approx(22 / 30)
    # 9.000 linhas com 90% de acerto, 100 com 50% e 900 com 80%.
    assert original["acuracia"] == pytest.approx((8100 + 50 + 720) / 10_000)
    assert original["por_classe"]["DDoS"]["suporte"] == pytest.approx(9100)
    assert original["por_classe"]["Benign"]["suporte"] == pytest.approx(900)
    assert original["por_classe"]["DDoS"]["precisao"] == pytest.approx(8150 / (8150 + 180))
    assert original["por_classe"]["Benign"]["precisao"] == pytest.approx(720 / (720 + 900 + 50))
    # O tráfego benigno é um rótulo só: o recall e a taxa de falso positivo não mudam.
    assert amostra["por_classe"]["Benign"]["recall"] == original["por_classe"]["Benign"]["recall"] == 0.8
    assert amostra["falso_positivo_benigno"] == pytest.approx(0.2)
    assert original["falso_positivo_benigno"] == pytest.approx(0.2)


def test_recall_de_categoria_com_varios_rotulos_muda_com_a_ponderacao():
    amostra = medidas(CASO_DA_PONDERACAO)
    original = medidas(CASO_DA_PONDERACAO, populacao=POPULACAO_DA_PONDERACAO)
    # Na amostra os dois rótulos de DDoS pesam o mesmo; no conjunto completo um deles é 90 vezes maior.
    assert amostra["por_classe"]["DDoS"]["recall"] == pytest.approx(14 / 20)
    assert original["por_classe"]["DDoS"]["recall"] == pytest.approx(8150 / 9100)


def test_recall_por_classe_nao_muda_com_a_ponderacao_quando_a_classe_e_o_rotulo():
    pares = (
        ("DDoS-ICMP_Flood", "DDoS-ICMP_Flood", 9), ("DDoS-ICMP_Flood", "BenignTraffic", 1),
        ("DDoS-SlowLoris", "DDoS-SlowLoris", 5), ("DDoS-SlowLoris", "DDoS-ICMP_Flood", 5),
        ("BenignTraffic", "BenignTraffic", 8), ("BenignTraffic", "DDoS-SlowLoris", 2),
    )
    amostra = medidas(pares, "34")
    original = medidas(pares, "34", populacao=POPULACAO_DA_PONDERACAO)
    for rotulo in POPULACAO_DA_PONDERACAO:
        assert original["por_classe"][rotulo]["recall"] == pytest.approx(amostra["por_classe"][rotulo]["recall"])
    assert original["acuracia"] != pytest.approx(amostra["acuracia"])


@pytest.mark.parametrize("nome_do_alvo", ["34", "8", "7", "2"])
def test_metricas_iguais_as_do_scikit_learn_com_e_sem_pesos(nome_do_alvo):
    gerador = np.random.default_rng(11)
    classes = ALVOS[nome_do_alvo].classes
    rotulos = np.array(ROTULOS, dtype=object)[gerador.integers(0, len(ROTULOS), 3000)]
    # Todos os rótulos presentes, para que as duas contas façam a média sobre as mesmas classes.
    rotulos[: len(ROTULOS)] = ROTULOS
    real = alvo(rotulos, nome_do_alvo)
    previsto = np.where(gerador.random(3000) < 0.6, real, np.array(classes, dtype=object)[gerador.integers(0, len(classes), 3000)])
    populacao = {rotulo: int(n) for rotulo, n in zip(ROTULOS, gerador.integers(50, 100_000, len(ROTULOS)))}
    por_rotulo = contar(rotulos, previsto, classes)
    for populacao_usada, w in ((None, None), (populacao, pesos(rotulos, populacao))):
        m = medir(matriz_de_confusao(por_rotulo, nome_do_alvo, populacao_usada), ALVOS[nome_do_alvo].benigno)
        assert m["acuracia"] == pytest.approx(accuracy_score(real, previsto, sample_weight=w))
        for media, chave in (("macro", "macro_f1"), ("weighted", "f1_ponderado")):
            esperado = f1_score(real, previsto, labels=list(classes), average=media, sample_weight=w)
            assert m[chave] == pytest.approx(esperado)
        precisao, recall, f1, suporte = precision_recall_fscore_support(
            real, previsto, labels=list(classes), sample_weight=w, zero_division=0
        )
        for i, classe in enumerate(classes):
            medida = m["por_classe"][classe]
            assert (medida["precisao"], medida["recall"], medida["f1"], medida["suporte"]) == pytest.approx(
                (precisao[i], recall[i], f1[i], suporte[i])
            )


# 11 linhas em 4 vetores. O número é o grupo, isto é, o vetor de features.
TETO_FEITO_A_MAO = (
    (0, "DDoS-ICMP_Flood"), (0, "DDoS-ICMP_Flood"), (0, "DDoS-ICMP_Flood"), (0, "DoS-SYN_Flood"),
    (1, "DoS-SYN_Flood"), (1, "DoS-SYN_Flood"), (1, "DDoS-SYN_Flood"), (1, "DDoS-SYN_Flood"),
    (2, "BenignTraffic"),
    (3, "XSS"), (3, "BenignTraffic"),
)


def caso_do_teto():
    grupos = np.array([grupo for grupo, _ in TETO_FEITO_A_MAO])
    rotulos = np.array([rotulo for _, rotulo in TETO_FEITO_A_MAO], dtype=object)
    return grupos, rotulos


def test_teto_do_caso_feito_a_mao():
    grupos, rotulos = caso_do_teto()
    limite = teto(grupos, rotulos, "8")
    # Vetor 0: 3 de DDoS e 1 de DoS, acerta 3. Vetor 1: 2 a 2, acerta 2. Vetor 2: acerta 1.
    # Vetor 3: uma linha Web e uma benigna, acerta 1.
    assert limite["acuracia"] == pytest.approx(7 / 11)
    # No empate vale a primeira classe na ordem das tabelas: DDoS antes de DoS, Web antes de Benign.
    assert limite["recall_na_regra"]["DDoS"] == 1.0
    assert limite["recall_na_regra"]["Web"] == 1.0
    assert limite["recall_na_regra"]["Benign"] == pytest.approx(1 / 2)
    assert limite["recall_na_regra"]["Mirai"] is None
    # O recall por classe é o da regra de maior acerto global, e não um limite da classe: quem
    # respondesse DoS nos vetores 0 e 1 acertaria as 3 linhas de DoS, com menos acerto no total.
    assert limite["recall_na_regra"]["DoS"] == 0.0
    assert set(limite) == {"acuracia", "recall_na_regra"}


def test_teto_sobe_quando_ddos_e_dos_viram_uma_classe():
    grupos, rotulos = caso_do_teto()
    limite = teto(grupos, rotulos, "7")
    assert limite["acuracia"] == pytest.approx(10 / 11)
    assert limite["recall_na_regra"][FUSAO] == 1.0


def test_teto_e_100_por_cento_sem_vetor_repetido_com_classes_diferentes():
    _, rotulos = caso_do_teto()
    assert teto(np.arange(11), rotulos, "8")["acuracia"] == 1.0
    assert teto(np.zeros(11, dtype=int), rotulos, "8")["acuracia"] == pytest.approx(5 / 11)


def test_teto_reponderado_escolhe_a_classe_de_maior_peso_em_cada_vetor():
    grupos, rotulos = caso_do_teto()
    populacao = {
        "DDoS-ICMP_Flood": 300, "DoS-SYN_Flood": 600, "DDoS-SYN_Flood": 200, "BenignTraffic": 20, "XSS": 1,
    }
    limite = teto(grupos, rotulos, "8", populacao)
    # Pesos por linha: 100, 200, 100, 10 e 1. Vetor 0: DDoS 300 contra DoS 200. Vetor 1: DoS 400
    # contra DDoS 200. Vetor 2: benigno 10. Vetor 3: benigno 10 contra Web 1.
    assert limite["acuracia"] == pytest.approx((300 + 400 + 10 + 10) / 1121)
    assert limite["recall_na_regra"]["DDoS"] == pytest.approx(300 / 500)
    assert limite["recall_na_regra"]["DoS"] == pytest.approx(400 / 600)
    assert limite["recall_na_regra"]["Benign"] == 1.0
    assert limite["recall_na_regra"]["Web"] == 0.0


def modelo_do_caso(nome_do_alvo="8", features=FEATURES_39, arvores=10):
    quadro = quadro_sintetico(por_classe=40)
    treino, teste = dividir(quadro, "estratificada")
    X, rotulos = matriz(quadro, features), quadro["Label"].to_numpy()
    modelo, _ = treinar(X[treino], alvo(rotulos, nome_do_alvo)[treino], arvores=arvores)
    return modelo, X[teste], rotulos[teste]


def test_avaliar_reune_as_medidas_na_amostra_e_reponderadas():
    modelo, X, rotulos = modelo_do_caso()
    previsto = prever(modelo, X)
    populacao = {rotulo: 1000 * (i + 1) for i, rotulo in enumerate(ROTULOS)}
    grupos = np.arange(len(X))
    resultado = avaliar(previsto, rotulos, "8", grupos=grupos, populacao=populacao)
    assert resultado["linhas"] == len(X) == 72
    assert resultado["amostra"]["acuracia"] == pytest.approx((previsto == alvo(rotulos, "8")).mean())
    assert resultado["original"]["acuracia"] == pytest.approx(
        accuracy_score(alvo(rotulos, "8"), previsto, sample_weight=pesos(rotulos, populacao))
    )
    assert resultado["amostra"]["teto"] == resultado["original"]["teto"] == 1.0
    assert resultado["amostra"]["por_classe"]["Benign"]["recall_na_regra_do_teto"] == 1.0
    assert "teto" not in resultado["amostra"]["por_classe"]["Benign"]
    por_rotulo = resultado["matriz_por_rotulo"]
    assert por_rotulo["classes"] == list(CATEGORIAS)
    assert len(por_rotulo["rotulos"]) == len(por_rotulo["contagem"]) == 9
    assert sum(map(sum, por_rotulo["contagem"])) == 72
    json.dumps(resultado)  # precisa ser serializável


def test_avaliar_calcula_o_teto_reponderado_com_os_pesos_do_conjunto_completo():
    grupos, rotulos = caso_do_teto()
    populacao = {
        "DDoS-ICMP_Flood": 300, "DoS-SYN_Flood": 600, "DDoS-SYN_Flood": 200, "BenignTraffic": 20, "XSS": 1,
    }
    # As predições não entram no teto: qualquer resposta serve.
    resultado = avaliar(alvo(rotulos, "8"), rotulos, "8", grupos=grupos, populacao=populacao)
    # Os mesmos valores de `teto` chamado direto, sem pesos na amostra e com pesos na reponderada.
    assert resultado["amostra"]["teto"] == pytest.approx(7 / 11)
    assert resultado["original"]["teto"] == pytest.approx((300 + 400 + 10 + 10) / 1121)
    assert resultado["amostra"]["por_classe"]["DoS"]["recall_na_regra_do_teto"] == 0.0
    assert resultado["original"]["por_classe"]["DoS"]["recall_na_regra_do_teto"] == pytest.approx(400 / 600)


def test_avaliar_sem_populacao_e_sem_grupos_mede_so_o_conjunto_dado():
    modelo, X, rotulos = modelo_do_caso()
    resultado = avaliar(prever(modelo, X), rotulos, "8")
    assert "original" not in resultado
    assert "teto" not in resultado["amostra"]


def test_importancias_tem_o_nome_das_features_em_ordem_decrescente():
    modelo, _, _ = modelo_do_caso(features=FEATURES_33)
    medidas_das_features = importancias(modelo, FEATURES_33)
    assert set(medidas_das_features) == set(FEATURES_33)
    valores = list(medidas_das_features.values())
    assert valores == sorted(valores, reverse=True)
    assert sum(valores) == pytest.approx(1.0)
    # No caso sintético, das 33 só o tamanho médio dos quadros e a taxa variam.
    assert {feature for feature, valor in medidas_das_features.items() if valor > 0} <= {"AVG", "Tot size", "Rate"}
    assert next(iter(medidas_das_features)) in ("AVG", "Tot size")
    with pytest.raises(ValueError, match="39 features"):
        importancias(modelo, FEATURES_39)


def test_tempo_por_mil_mede_um_lote_de_mil_janelas():
    modelo, X, _ = modelo_do_caso()
    chamadas = []

    def predicao(lote):
        chamadas.append(len(lote))
        return prever(modelo, lote)

    grande = np.tile(X, (20, 1))
    assert tempo_por_mil(predicao, grande, repeticoes=3) > 0
    assert chamadas == [1000, 1000, 1000]
    # Com menos de mil linhas, o tempo é levado à proporção de mil.
    chamadas.clear()
    assert tempo_por_mil(predicao, X, repeticoes=2) > 0
    assert chamadas == [72, 72]


def preparar_arquivos(tmp_path, nome_do_alvo="8", divisao="grupos"):
    """Amostra, manifesto e modelo de mentira, como os comandos do projeto os gravam."""
    quadro = quadro_sintetico(por_classe=40)
    sha256 = gravar_amostra(tmp_path / "amostra.csv.gz", quadro)
    presentes = quadro["Label"].value_counts()
    manifesto = {
        "saida": {"sha256_do_csv_descomprimido": sha256, "linhas": len(quadro)},
        "classes": [
            {"rotulo": rotulo, "populacao": 100 * int(presentes.get(rotulo, 0)), "amostra": int(presentes.get(rotulo, 0))}
            for rotulo in ROTULOS
        ],
    }
    (tmp_path / "manifesto.json").write_text(json.dumps(manifesto), encoding="utf-8")
    treino, teste = dividir(quadro, divisao, semente=3)
    X, rotulos = matriz(quadro, FEATURES_39), quadro["Label"].to_numpy()
    modelo, _ = treinar(X[treino], alvo(rotulos, nome_do_alvo)[treino], semente=3, arvores=10)
    salvar(
        tmp_path / "rf.joblib", modelo, FEATURES_39, nome_do_alvo,
        divisao=divisao, semente=3, arvores=10, amostra_sha256=sha256,
    )
    return quadro, teste, modelo


def executar(tmp_path, *extras):
    return main([
        str(tmp_path / "rf.joblib"), "--amostra", str(tmp_path / "amostra.csv.gz"),
        "--manifesto", str(tmp_path / "manifesto.json"), *extras,
    ])


def test_main_avalia_na_parte_de_teste_da_divisao_registrada_no_modelo(tmp_path, capsys):
    quadro, teste, modelo = preparar_arquivos(tmp_path)
    assert executar(tmp_path, "--saida", str(tmp_path / "avaliacao.json")) == 0
    resultado = json.loads((tmp_path / "avaliacao.json").read_text(encoding="utf-8"))
    rotulos = quadro["Label"].to_numpy()[teste]
    previsto = prever(modelo, matriz(quadro, FEATURES_39)[teste])
    assert resultado["linhas"] == len(teste)
    assert resultado["amostra"]["acuracia"] == pytest.approx((previsto == alvo(rotulos, "8")).mean())
    assert "original" in resultado and "teto" in resultado["amostra"]
    assert resultado["modelo"]["bytes"] == (tmp_path / "rf.joblib").stat().st_size
    assert set(resultado["importancias"]) == set(FEATURES_39)
    saida = capsys.readouterr().out
    assert "parte de teste da amostra" in saida and "Benign" in saida
    assert "Reponderada para a distribuição do conjunto completo" in saida


def test_main_recusa_amostra_diferente_da_que_treinou_o_modelo(tmp_path, capsys):
    preparar_arquivos(tmp_path)
    gravar_amostra(tmp_path / "amostra.csv.gz", quadro_sintetico(por_classe=40, semente=1))
    assert executar(tmp_path) == 1
    assert "não é a amostra com que o modelo foi treinado" in capsys.readouterr().err


def escrever_captura(caminho, quadro, com_rotulo):
    """CSV como o extrator grava: as 39 colunas, campo vazio no lugar de valor vazio e `inf`."""
    captura = quadro[[*COLUNAS, "Label"]] if com_rotulo else quadro[list(COLUNAS)]
    captura.to_csv(caminho, index=False)
    return caminho


def test_main_pontua_um_csv_externo_com_o_rotulo_dado_na_linha_de_comando(tmp_path, capsys):
    quadro, _, modelo = preparar_arquivos(tmp_path)
    benignas = quadro[quadro["Label"] == "BenignTraffic"].copy()
    benignas.loc[benignas.index[0], "Rate"] = np.inf
    benignas.loc[benignas.index[1], ["Std", "Variance"]] = np.nan
    captura = escrever_captura(tmp_path / "captura.csv", benignas, com_rotulo=False)
    codigo = executar(tmp_path, "--csv", str(captura), "--rotulo", "BENIGN", "--saida", str(tmp_path / "a.json"))
    assert codigo == 0
    resultado = json.loads((tmp_path / "a.json").read_text(encoding="utf-8"))
    previsto = prever(modelo, matriz(benignas, FEATURES_39))
    assert resultado["linhas"] == 40
    assert resultado["amostra"]["acuracia"] == pytest.approx((previsto == "Benign").mean())
    assert resultado["amostra"]["falso_positivo_benigno"] == pytest.approx((previsto != "Benign").mean())
    # Fora da amostra não há contagem do conjunto completo para reponderar.
    assert "original" not in resultado
    assert "captura.csv" in capsys.readouterr().out


def test_main_pontua_um_csv_externo_que_traz_a_coluna_label(tmp_path, capsys):
    quadro, _, _ = preparar_arquivos(tmp_path)
    captura = escrever_captura(tmp_path / "captura.csv", quadro.iloc[::3], com_rotulo=True)
    assert executar(tmp_path, "--csv", str(captura), "--saida", str(tmp_path / "a.json")) == 0
    resultado = json.loads((tmp_path / "a.json").read_text(encoding="utf-8"))
    assert resultado["linhas"] == len(quadro.iloc[::3])
    assert len(resultado["matriz_por_rotulo"]["rotulos"]) == 9


def test_main_exige_o_rotulo_do_csv_externo_e_recusa_rotulo_em_dobro(tmp_path, capsys):
    quadro, _, _ = preparar_arquivos(tmp_path)
    sem = escrever_captura(tmp_path / "sem.csv", quadro, com_rotulo=False)
    assert executar(tmp_path, "--csv", str(sem)) == 1
    assert "sem.csv: falta a coluna Label" in capsys.readouterr().err
    com = escrever_captura(tmp_path / "com.csv", quadro, com_rotulo=True)
    assert executar(tmp_path, "--csv", str(com), "--rotulo", "XSS") == 1
    assert "já traz a coluna Label" in capsys.readouterr().err
    assert executar(tmp_path, "--csv", str(sem), "--rotulo", "Exfiltracao") == 1
    assert "rótulo desconhecido" in capsys.readouterr().err
    assert executar(tmp_path, "--rotulo", "XSS") == 1
    assert "--csv" in capsys.readouterr().err


def test_main_com_csv_externo_sem_alguma_coluna_ou_modelo_ausente(tmp_path, capsys):
    quadro, _, _ = preparar_arquivos(tmp_path)
    faltando = tmp_path / "faltando.csv"
    quadro.drop(columns=["IAT"]).to_csv(faltando, index=False)
    assert executar(tmp_path, "--csv", str(faltando)) == 1
    assert "faltando.csv: faltam as colunas IAT" in capsys.readouterr().err
    assert main([str(tmp_path / "ausente.joblib")]) == 1
    assert "erro:" in capsys.readouterr().err


def test_modelo_de_33_features_ignora_as_colunas_da_janela_do_csv_externo(tmp_path, capsys):
    quadro = quadro_sintetico(por_classe=40)
    X, rotulos = matriz(quadro, FEATURES_33), quadro["Label"].to_numpy()
    modelo, _ = treinar(X, alvo(rotulos, "8"), arvores=10)
    salvar(tmp_path / "rf.joblib", modelo, FEATURES_33, "8")
    # A mesma captura com outra janela: só mudam as seis colunas que o modelo não recebe.
    outra_janela = quadro.assign(Number=37.0, **{"Tot sum": quadro["AVG"] * 37})
    for nome, captura in (("a", quadro), ("b", outra_janela)):
        escrever_captura(tmp_path / f"{nome}.csv", captura, com_rotulo=True)
        assert main([str(tmp_path / "rf.joblib"), "--csv", str(tmp_path / f"{nome}.csv"), "--saida", str(tmp_path / f"{nome}.json")]) == 0
    a, b = (json.loads((tmp_path / f"{nome}.json").read_text(encoding="utf-8")) for nome in "ab")
    assert a["matriz_por_rotulo"] == b["matriz_por_rotulo"]


def test_carregar_csv_de_dataframe_vazio_nao_e_aceito(tmp_path, capsys):
    preparar_arquivos(tmp_path)
    vazio = tmp_path / "vazio.csv"
    pd.DataFrame(columns=list(COLUNAS)).to_csv(vazio, index=False)
    assert executar(tmp_path, "--csv", str(vazio), "--rotulo", "XSS") == 1
    assert "nenhuma linha" in capsys.readouterr().err
