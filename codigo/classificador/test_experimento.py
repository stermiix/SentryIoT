import csv
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from codigo.classificador import experimento as experimento_do_treino
from codigo.classificador.avaliar import main as avaliar_modelo
from codigo.classificador.avaliar import teto
from codigo.classificador.experimento import (
    ARVORES_COM_34_CLASSES,
    GRADE,
    GRADE_NATURAL,
    REFERENCIAS,
    REPETICOES,
    Execucao,
    main,
    montar_relatorio,
    pesos_de_treino,
    rodar,
)
from codigo.classificador.mapeamento import ROTULOS
from codigo.classificador.preparar import (
    ALVOS,
    CONJUNTOS_DE_FEATURES,
    FEATURES_33,
    FEATURES_39,
    agrupar,
    alvo,
    dividir,
    impressao_digital,
    matriz,
)
from codigo.classificador.test_preparar import gravar_amostra, quadro_sintetico, vetores
from codigo.classificador.test_treinar import mesmas_arvores
from codigo.classificador.treinar import carregar_modelo, treinar

RESULTADOS = Path(__file__).resolve().parents[2] / "experimentos" / "resultados"
ARQUIVOS = ("treino_exploratorio.md", "metricas_classificador.csv", "importancia_features.csv")
# O que muda de uma execução para outra sem que os resultados mudem: data e medidas de tempo.
VARIAVEIS = (
    "gerado_em", "treino_segundos", "teste_segundos", "inferencia_ms_por_mil_janelas",
    "inferencia_ms_por_janela_avulsa", "duracao_segundos",
)


def preparar_entrada(pasta, semente=0):
    """Amostra e manifesto de mentira, no formato que a amostragem grava."""
    quadro = quadro_sintetico(por_classe=40, semente=semente)
    sha256 = gravar_amostra(pasta / "amostra.csv.gz", quadro)
    presentes = quadro["Label"].value_counts()
    manifesto = {
        "saida": {"sha256_do_csv_descomprimido": sha256, "linhas": len(quadro)},
        "classes": [
            {
                "rotulo": rotulo,
                # No conjunto completo de mentira, cada rótulo presente tem um tamanho diferente.
                "populacao": 1000 * (i + 1) * int(rotulo in presentes),
                "amostra": int(presentes.get(rotulo, 0)),
            }
            for i, rotulo in enumerate(ROTULOS)
        ],
    }
    (pasta / "manifesto_amostra.json").write_text(json.dumps(manifesto), encoding="utf-8")
    return quadro


POPULACAO = {rotulo: 1000 * (i + 1) for i, rotulo in enumerate(ROTULOS)}
EXECUCOES = (*GRADE, *GRADE_NATURAL, *REFERENCIAS)


def com_gemeas_de_outra_janela(quadro, de="XSS", para="BenignTraffic"):
    """Dá a cada linha de um rótulo uma gêmea de outra categoria, igual nas 33 features e diferente nas 39.

    A gêmea só muda nas colunas que dependem da janela: é o mesmo vetor para o modelo de 33
    features, com outra classe, e um vetor diferente para o de 39.
    """
    gemeas = quadro[quadro["Label"] == de].copy()
    gemeas["Number"] = gemeas["Number"] - 1
    gemeas["Tot sum"] = gemeas["AVG"] * gemeas["Number"]
    gemeas["Label"] = para
    return pd.concat([quadro, gemeas], ignore_index=True)


def executar(pasta, *extras, saida=None, repeticoes=()):
    """Roda o experimento. Sem dizer as sementes das repetições, roda só a semente principal."""
    return main([
        "--amostra", str(pasta / "amostra.csv.gz"), "--manifesto-da-amostra", str(pasta / "manifesto_amostra.json"),
        "--saida", str(saida or pasta / "resultados"), "--arvores", "5",
        *(() if repeticoes is None else ("--repeticoes", *map(str, repeticoes))), *extras,
    ])


def tabela_depois_de(texto, marca):
    """As linhas da primeira tabela do relatório que aparece depois de `marca`."""
    linhas = texto.split(marca, 1)[1].splitlines()
    inicio = next(i for i, linha in enumerate(linhas) if linha.startswith("|"))
    fim = next((i for i in range(inicio, len(linhas)) if not linhas[i].startswith("|")), len(linhas))
    return linhas[inicio:fim]


def pct(valor):
    return f"{100 * valor:.2f}%".replace(".", ",")


def pp(diferenca):
    texto = f"{100 * diferenca:+.2f}".replace(".", ",")
    return "0,00" if texto in ("+0,00", "-0,00") else texto


def ler_manifesto(pasta):
    return json.loads((pasta / "manifesto_treino_exploratorio.json").read_text(encoding="utf-8"))


def ler_csv(caminho):
    with open(caminho, encoding="utf-8", newline="") as arquivo:
        return list(csv.DictReader(arquivo))


def ler_matriz(caminho):
    """Matriz de confusão gravada: nomes das linhas, nomes das colunas e contagens."""
    with open(caminho, encoding="utf-8", newline="") as arquivo:
        cabecalho, *linhas = list(csv.reader(arquivo))
    return [linha[0] for linha in linhas], cabecalho[1:], np.array([linha[1:] for linha in linhas], dtype=float)


def sem_variaveis(valor):
    """O mesmo registro sem a data e sem as medidas de tempo."""
    if isinstance(valor, dict):
        return {chave: sem_variaveis(item) for chave, item in valor.items() if chave not in VARIAVEIS}
    if isinstance(valor, list):
        return [sem_variaveis(item) for item in valor]
    return valor


@pytest.fixture(scope="module")
def experimento(tmp_path_factory):
    pasta = tmp_path_factory.mktemp("experimento")
    quadro = preparar_entrada(pasta)
    # Com as sementes padrão das repetições, como o comando roda sem opções.
    assert executar(pasta, repeticoes=None) == 0
    return pasta, quadro


@pytest.fixture(scope="module")
def sem_repeticoes(tmp_path_factory):
    pasta = tmp_path_factory.mktemp("uma_semente")
    preparar_entrada(pasta)
    assert executar(pasta) == 0
    return pasta


def test_grade_tem_as_oito_combinacoes_e_as_referencias():
    assert len(GRADE) == 8 == len(set(GRADE))
    assert {(e.features, e.divisao, e.alvo, e.priori) for e in GRADE} == {
        (features, divisao, alvo, "amostra")
        for features in ("39", "33") for divisao in ("estratificada", "grupos") for alvo in ("8", "7")
    }
    assert Execucao("33", "grupos", "7").nome == "f33_grupos_c7"


def test_priori_natural_entra_nas_combinacoes_do_sorteio_estratificado_e_nas_referencias():
    # A priori de treino é o quarto fator: as proporções da amostra ou a proporção natural das classes.
    assert Execucao("39", "grupos", "8").priori == "amostra"
    assert set(GRADE_NATURAL) == {
        Execucao(features, "estratificada", alvo, "natural") for features in ("39", "33") for alvo in ("8", "7")
    }
    assert len(GRADE_NATURAL) == 4
    assert set(REFERENCIAS) == {
        Execucao("39", "estratificada", alvo, priori) for alvo in ("34", "2") for priori in ("amostra", "natural")
    }
    assert len(REFERENCIAS) == 4
    # O nome das execuções que já existiam não muda, e a priori natural aparece no nome.
    assert Execucao("33", "estratificada", "7", "natural").nome == "f33_estratificada_c7_natural"
    nomes = [execucao.nome for execucao in EXECUCOES]
    assert len(set(nomes)) == 16
    assert [nome for nome in nomes if nome.endswith("_natural")] == [
        "f39_estratificada_c8_natural", "f39_estratificada_c7_natural",
        "f33_estratificada_c8_natural", "f33_estratificada_c7_natural",
        "f39_estratificada_c34_natural", "f39_estratificada_c2_natural",
    ]


def test_pesos_de_treino_dao_a_cada_rotulo_o_peso_que_ele_tem_no_conjunto_completo():
    rotulos = np.array(["DDoS-ICMP_Flood"] * 6 + ["XSS"] * 3 + ["BenignTraffic"], dtype=object)
    populacao = {"DDoS-ICMP_Flood": 9000, "XSS": 300, "BenignTraffic": 700}
    w = pesos_de_treino(rotulos, populacao)
    # A soma dos pesos de cada rótulo é a fração dele no conjunto completo, e a média dos pesos é 1.
    assert w.sum() == pytest.approx(10)
    for rotulo, linhas in populacao.items():
        assert w[rotulos == rotulo].sum() / w.sum() == pytest.approx(linhas / 10_000)
        assert len(set(w[rotulos == rotulo].tolist())) == 1
    with pytest.raises(ValueError, match="sem contagem no conjunto completo: XSS"):
        pesos_de_treino(rotulos, {"DDoS-ICMP_Flood": 9000, "BenignTraffic": 700})


def test_main_grava_o_relatorio_as_tabelas_as_matrizes_e_o_manifesto(experimento):
    pasta, _ = experimento
    resultados = pasta / "resultados"
    assert sorted(p.name for p in resultados.iterdir()) == sorted(
        [*ARQUIVOS, "manifesto_treino_exploratorio.json", "matrizes_confusao"]
    )
    nomes = [execucao.nome for execucao in EXECUCOES]
    assert sorted(p.name for p in (resultados / "matrizes_confusao").iterdir()) == sorted(
        [f"{nome}.csv" for nome in nomes] + [f"{nome}_por_rotulo.csv" for nome in nomes]
    )
    # Nenhum modelo fica na pasta de resultados, que é versionada.
    assert not list(resultados.rglob("*.joblib"))


def test_manifesto_registra_sementes_parametros_versoes_e_o_hash_da_amostra(experimento):
    pasta, quadro = experimento
    manifesto = ler_manifesto(pasta / "resultados")
    entrada = json.loads((pasta / "manifesto_amostra.json").read_text(encoding="utf-8"))
    assert manifesto["semente"] == 42
    assert [execucao["semente"] for execucao in manifesto["execucoes"]] == [42] * 16
    assert manifesto["parametros"]["arvores"] == 5 and manifesto["parametros"]["fracao_de_teste"] == 0.2
    assert manifesto["parametros"]["arvores_com_34_classes"] == min(5, ARVORES_COM_34_CLASSES)
    assert set(manifesto["versoes"]) == {"python", "numpy", "pandas", "scikit-learn", "joblib"}
    assert manifesto["amostra"]["sha256_do_csv_descomprimido"] == entrada["saida"]["sha256_do_csv_descomprimido"]
    assert manifesto["amostra"]["linhas"] == len(quadro) == 360
    assert manifesto["features"] == {"39": list(FEATURES_39), "33": list(FEATURES_33)}
    assert [execucao["nome"] for execucao in manifesto["execucoes"]] == [e.nome for e in EXECUCOES]
    assert [execucao["priori"] for execucao in manifesto["execucoes"]] == [e.priori for e in EXECUCOES]
    json.dumps(manifesto)


def test_manifesto_registra_as_duas_divisoes(experimento):
    pasta, quadro = experimento
    divisoes = ler_manifesto(pasta / "resultados")["divisoes"]
    assert set(divisoes) == {"estratificada", "grupos"}
    for nome, registro in divisoes.items():
        treino, teste = dividir(quadro, nome)
        assert (registro["treino"], registro["teste"]) == (len(treino), len(teste))
        assert registro["sha256_do_teste"] == impressao_digital(teste)
    # Na divisão por grupos nenhuma linha do teste tem o vetor de uma linha do treino.
    assert divisoes["grupos"]["teste_com_vetor_no_treino"] == {"39": 0, "33": 0}
    assert divisoes["estratificada"]["teste_com_vetor_no_treino"]["39"] > 0


def test_manifesto_registra_o_teto_da_amostra_inteira(experimento):
    pasta, quadro = experimento
    manifesto = ler_manifesto(pasta / "resultados")
    rotulos = quadro["Label"].to_numpy()
    assert set(manifesto["amostra"]["teto"]) == {"39", "33"}
    for features, por_alvo in manifesto["amostra"]["teto"].items():
        grupos = agrupar(matriz(quadro, CONJUNTOS_DE_FEATURES[features]))
        assert set(por_alvo) == set(ALVOS)
        for nome_do_alvo, medidas in por_alvo.items():
            for distribuicao, populacao in (("amostra", None), ("original", manifesto["populacao"])):
                esperado = teto(grupos, rotulos, nome_do_alvo, populacao)["acuracia"]
                assert medidas[distribuicao] == pytest.approx(esperado), (features, nome_do_alvo, distribuicao)
    # Com mais linhas há mais vetores repetidos com classes diferentes: o teto da amostra inteira
    # não passa do teto das linhas de teste de uma execução.
    principal = manifesto["execucoes"][0]
    assert manifesto["amostra"]["teto"]["39"]["8"]["amostra"] <= principal["amostra"]["teto"]


def test_cada_execucao_traz_as_medidas_nas_duas_distribuicoes_e_o_custo(experimento):
    pasta, _ = experimento
    for execucao in ler_manifesto(pasta / "resultados")["execucoes"]:
        classes = list(ALVOS[execucao["alvo"]].classes)
        for distribuicao in ("amostra", "original"):
            medidas = execucao[distribuicao]
            assert 0 <= medidas["acuracia"] <= medidas["teto"] <= 1, execucao["nome"]
            assert 0 <= medidas["macro_f1"] <= 1 and 0 <= medidas["f1_ponderado"] <= 1
            assert list(medidas["por_classe"]) == classes
        assert execucao["treino_segundos"] > 0 and execucao["modelo_bytes"] > 0
        assert set(execucao["inferencia_ms_por_mil_janelas"]) == {"um_nucleo", "todos_os_nucleos"}
        assert all(valor > 0 for valor in execucao["inferencia_ms_por_mil_janelas"].values())
        assert execucao["inferencia_ms_por_janela_avulsa"] > 0
        assert len(execucao["importancias"]) == int(execucao["features"])
        assert execucao["arvores"] == 5
        assert execucao["linhas_de_teste"] == sum(map(sum, execucao["matriz_por_rotulo"]["contagem"]))


def test_execucao_de_34_classes_usa_menos_arvores(tmp_path):
    preparar_entrada(tmp_path)
    assert executar(tmp_path, "--arvores", "30") == 0
    arvores = {e["nome"]: e["arvores"] for e in ler_manifesto(tmp_path / "resultados")["execucoes"]}
    assert ARVORES_COM_34_CLASSES == 25
    assert arvores["f39_estratificada_c34"] == arvores["f39_estratificada_c34_natural"] == 25
    assert sorted(arvores.values()) == [25, 25] + [30] * 14


def test_metricas_em_formato_longo(experimento):
    pasta, _ = experimento
    linhas = ler_csv(pasta / "resultados" / "metricas_classificador.csv")
    assert list(linhas[0]) == [
        "execucao", "distribuicao", "classe", "precisao", "recall", "f1", "suporte",
        "taxa_falso_positivo", "recall_na_regra_do_teto",
    ]
    manifesto = ler_manifesto(pasta / "resultados")
    esperadas = sum(2 * len(ALVOS[execucao["alvo"]].classes) for execucao in manifesto["execucoes"])
    assert len(linhas) == esperadas == 2 * (6 * 8 + 6 * 7 + 2 * 34 + 2 * 2)
    assert {linha["distribuicao"] for linha in linhas} == {"amostra", "original"}
    principal = manifesto["execucoes"][0]
    benigno = next(
        linha for linha in linhas
        if (linha["execucao"], linha["distribuicao"], linha["classe"]) == (principal["nome"], "amostra", "Benign")
    )
    medida = principal["amostra"]["por_classe"]["Benign"]
    assert float(benigno["recall"]) == pytest.approx(medida["recall"], abs=1e-6)
    assert float(benigno["suporte"]) == medida["suporte"] == 8
    # Classe sem linhas no teste fica com os campos vazios.
    ausente = next(linha for linha in linhas if linha["classe"] == "Uploading_Attack")
    assert ausente["recall"] == "" and ausente["suporte"] == "0"


def test_importancias_em_formato_longo(experimento):
    pasta, _ = experimento
    linhas = ler_csv(pasta / "resultados" / "importancia_features.csv")
    assert list(linhas[0]) == ["execucao", "feature", "importancia"]
    assert len(linhas) == 10 * 39 + 6 * 33
    de_uma = [float(linha["importancia"]) for linha in linhas if linha["execucao"] == "f33_grupos_c7"]
    assert len(de_uma) == 33 and sum(de_uma) == pytest.approx(1.0, abs=1e-4)
    assert de_uma == sorted(de_uma, reverse=True)


def test_acuracia_do_manifesto_sai_das_matrizes_gravadas(experimento):
    pasta, _ = experimento
    resultados = pasta / "resultados"
    manifesto = ler_manifesto(resultados)
    for execucao in manifesto["execucoes"]:
        classes = list(ALVOS[execucao["alvo"]].classes)
        reais, previstas, contagem = ler_matriz(resultados / "matrizes_confusao" / f"{execucao['nome']}.csv")
        assert reais == previstas == classes
        assert np.trace(contagem) / contagem.sum() == pytest.approx(execucao["amostra"]["acuracia"])
        # A reponderada sai da matriz por rótulo e das contagens do conjunto completo.
        rotulos, previstas, contagem = ler_matriz(
            resultados / "matrizes_confusao" / f"{execucao['nome']}_por_rotulo.csv"
        )
        classe_do_rotulo = ALVOS[execucao["alvo"]].classe_do_rotulo
        certas = np.array([linha[previstas.index(classe_do_rotulo[rotulo])] for rotulo, linha in zip(rotulos, contagem)])
        completo = np.array([manifesto["populacao"][rotulo] for rotulo in rotulos], dtype=float)
        acuracia = (completo * certas / contagem.sum(axis=1)).sum() / completo.sum()
        assert acuracia == pytest.approx(execucao["original"]["acuracia"])


def test_duas_execucoes_dao_os_mesmos_resultados(experimento, tmp_path):
    pasta, _ = experimento
    assert executar(pasta, saida=tmp_path / "de_novo", repeticoes=None) == 0
    primeira, segunda = pasta / "resultados", tmp_path / "de_novo"
    assert sem_variaveis(ler_manifesto(primeira)) == sem_variaveis(ler_manifesto(segunda))
    iguais = ["metricas_classificador.csv", "importancia_features.csv"]
    iguais += [f"matrizes_confusao/{p.name}" for p in (primeira / "matrizes_confusao").iterdir()]
    for nome in iguais:
        assert (primeira / nome).read_bytes() == (segunda / nome).read_bytes(), nome


def test_outra_semente_muda_a_divisao_e_os_modelos(experimento, tmp_path):
    pasta, _ = experimento
    assert executar(pasta, "--semente", "7", saida=tmp_path / "outra") == 0
    padrao, outra = ler_manifesto(pasta / "resultados"), ler_manifesto(tmp_path / "outra")
    assert outra["semente"] == 7
    assert outra["divisoes"]["grupos"]["sha256_do_teste"] != padrao["divisoes"]["grupos"]["sha256_do_teste"]


def test_grade_e_repetida_com_as_sementes_7_e_2026(experimento):
    pasta, quadro = experimento
    manifesto = ler_manifesto(pasta / "resultados")
    assert REPETICOES == (7, 2026)
    assert [repeticao["semente"] for repeticao in manifesto["repeticoes"]] == [7, 2026]
    repetidas = [execucao.nome for execucao in (*GRADE, *GRADE_NATURAL)]
    for repeticao in manifesto["repeticoes"]:
        semente = repeticao["semente"]
        # A grade das três escolhas e as execuções com a priori natural; as referências rodam uma vez.
        assert [execucao["nome"] for execucao in repeticao["execucoes"]] == repetidas
        assert {execucao["semente"] for execucao in repeticao["execucoes"]} == {semente}
        # A semente da repetição vale para a divisão e para o modelo.
        for nome, registro in repeticao["divisoes"].items():
            _, teste = dividir(quadro, nome, semente=semente)
            assert registro["sha256_do_teste"] == impressao_digital(teste)
            assert registro["sha256_do_teste"] != manifesto["divisoes"][nome]["sha256_do_teste"]
    json.dumps(manifesto)


def test_repeticao_da_os_numeros_de_rodar_o_experimento_com_aquela_semente(experimento, tmp_path):
    pasta, _ = experimento
    assert executar(pasta, "--semente", "7", saida=tmp_path / "sete") == 0
    sozinha = {execucao["nome"]: execucao for execucao in ler_manifesto(tmp_path / "sete")["execucoes"]}
    repeticao = ler_manifesto(pasta / "resultados")["repeticoes"][0]
    assert repeticao["semente"] == 7
    for execucao in repeticao["execucoes"]:
        assert sem_variaveis(execucao) == sem_variaveis(sozinha[execucao["nome"]]), execucao["nome"]
    assert sem_variaveis(repeticao["divisoes"]) == sem_variaveis(ler_manifesto(tmp_path / "sete")["divisoes"])


def test_sementes_das_repeticoes_sao_escolhidas_na_linha_de_comando(tmp_path, capsys):
    preparar_entrada(tmp_path)
    assert executar(tmp_path, repeticoes=(3,)) == 0
    assert [repeticao["semente"] for repeticao in ler_manifesto(tmp_path / "resultados")["repeticoes"]] == [3]
    # Sem repetições, o manifesto diz que não houve nenhuma.
    assert executar(tmp_path, saida=tmp_path / "uma") == 0
    assert ler_manifesto(tmp_path / "uma")["repeticoes"] == []
    # A semente principal sai das repetições padrão, para não rodar duas vezes a mesma coisa.
    assert executar(tmp_path, "--semente", "2026", saida=tmp_path / "outra", repeticoes=None) == 0
    outra = ler_manifesto(tmp_path / "outra")
    assert outra["semente"] == 2026 and [repeticao["semente"] for repeticao in outra["repeticoes"]] == [7]
    capsys.readouterr()
    # Pedir a mesma semente duas vezes é erro, e nada é gravado.
    for sementes in ((42,), (5, 5)):
        assert executar(tmp_path, saida=tmp_path / "erro", repeticoes=sementes) == 1
        assert "sementes das repetições precisam ser diferentes" in capsys.readouterr().err
    assert not (tmp_path / "erro").exists()


def test_semente_pedida_chega_ao_modelo(tmp_path):
    quadro = preparar_entrada(tmp_path)
    assert executar(tmp_path, "--semente", "7", "--modelos", str(tmp_path / "modelos")) == 0
    pacote = carregar_modelo(tmp_path / "modelos" / "rf_f39_estratificada_c8.joblib")
    assert pacote["semente"] == 7 and pacote["modelo"].random_state == 7
    # O modelo é o que sai da divisão e do treino feitos com a semente pedida.
    treino, _ = dividir(quadro, "estratificada", semente=7)
    X, y = matriz(quadro, FEATURES_39), alvo(quadro["Label"].to_numpy(), "8")
    esperado, _ = treinar(X[treino], y[treino], semente=7, arvores=5)
    assert mesmas_arvores(pacote["modelo"], esperado)


def test_rodar_treina_o_modelo_so_com_as_linhas_de_treino(tmp_path):
    quadro = quadro_sintetico(por_classe=40)
    rotulos = quadro["Label"].to_numpy()
    execucoes = (Execucao("39", "estratificada", "8"), Execucao("33", "grupos", "7"))
    rodar(quadro, POPULACAO, execucoes=execucoes, arvores=5, pasta_dos_modelos=tmp_path)
    for execucao in execucoes:
        treino, _ = dividir(quadro, execucao.divisao)
        X, y = matriz(quadro, CONJUNTOS_DE_FEATURES[execucao.features]), alvo(rotulos, execucao.alvo)
        esperado, _ = treinar(X[treino], y[treino], arvores=5)
        pacote = carregar_modelo(tmp_path / f"rf_{execucao.nome}.joblib")
        # Com uma linha de teste a mais no treino, as árvores já seriam outras.
        assert mesmas_arvores(pacote["modelo"], esperado), execucao.nome
        de_todas, _ = treinar(X, y, arvores=5)
        assert not mesmas_arvores(pacote["modelo"], de_todas), execucao.nome


def test_rodar_treina_com_a_proporcao_natural_quando_a_priori_e_natural(tmp_path):
    quadro = quadro_sintetico(por_classe=40)
    rotulos = quadro["Label"].to_numpy()
    execucoes = (Execucao("39", "estratificada", "8"), Execucao("39", "estratificada", "8", "natural"))
    registro = rodar(quadro, POPULACAO, execucoes=execucoes, arvores=5, pasta_dos_modelos=tmp_path)
    assert [resultado["priori"] for resultado in registro["execucoes"]] == ["amostra", "natural"]
    treino, _ = dividir(quadro, "estratificada")
    X, y = matriz(quadro, FEATURES_39), alvo(rotulos, "8")
    # O peso de cada linha de treino: linhas do rótulo no conjunto completo sobre as linhas dele no treino.
    no_treino = pd.Series(rotulos[treino]).value_counts()
    pesos = np.array([POPULACAO[rotulo] / no_treino[rotulo] for rotulo in rotulos[treino]])
    com_pesos, _ = treinar(X[treino], y[treino], arvores=5, pesos=pesos)
    sem_pesos, _ = treinar(X[treino], y[treino], arvores=5)
    natural = carregar_modelo(tmp_path / "rf_f39_estratificada_c8_natural.joblib")
    da_amostra = carregar_modelo(tmp_path / "rf_f39_estratificada_c8.joblib")
    assert (natural["priori"], da_amostra["priori"]) == ("natural", "amostra")
    assert mesmas_arvores(natural["modelo"], com_pesos) and not mesmas_arvores(natural["modelo"], sem_pesos)
    assert mesmas_arvores(da_amostra["modelo"], sem_pesos)
    # As duas execuções são avaliadas nas mesmas linhas de teste.
    assert registro["execucoes"][0]["amostra"]["por_classe"]["Benign"]["suporte"] == (
        registro["execucoes"][1]["amostra"]["por_classe"]["Benign"]["suporte"]
    )


def test_rodar_recusa_priori_desconhecida():
    quadro = quadro_sintetico(por_classe=40)
    with pytest.raises(ValueError, match="priori de treino desconhecida: 'uniforme'"):
        rodar(quadro, POPULACAO, execucoes=(Execucao("39", "estratificada", "8", "uniforme"),), arvores=5)


def test_teto_de_cada_execucao_usa_os_vetores_das_features_dela():
    quadro = com_gemeas_de_outra_janela(quadro_sintetico(por_classe=40))
    rotulos = quadro["Label"].to_numpy()
    execucoes = (Execucao("39", "grupos", "8"), Execucao("33", "grupos", "8"))
    registro = rodar(quadro, POPULACAO, execucoes=execucoes, arvores=5)
    _, teste = dividir(quadro, "grupos")
    tetos = {}
    for execucao, resultado in zip(execucoes, registro["execucoes"]):
        grupos = agrupar(matriz(quadro, CONJUNTOS_DE_FEATURES[execucao.features]))[teste]
        for distribuicao, populacao in (("amostra", None), ("original", POPULACAO)):
            esperado = teto(grupos, rotulos[teste], "8", populacao)["acuracia"]
            assert resultado[distribuicao]["teto"] == pytest.approx(esperado), (execucao.nome, distribuicao)
        tetos[execucao.features] = resultado["amostra"]["teto"]
    # As gêmeas são o mesmo vetor com classes diferentes só para o modelo de 33 features.
    assert tetos["33"] < tetos["39"]


def test_rodar_conta_as_linhas_de_teste_com_vetor_no_treino_em_cada_conjunto_de_features():
    quadro = com_gemeas_de_outra_janela(quadro_sintetico(por_classe=40))
    registro = rodar(quadro, POPULACAO, execucoes=(), arvores=5)
    contagem = registro["divisoes"]["estratificada"]["teste_com_vetor_no_treino"]
    treino, teste = dividir(quadro, "estratificada")
    for nome, features in CONJUNTOS_DE_FEATURES.items():
        X = matriz(quadro, features)
        no_treino = vetores(X, treino)
        assert contagem[nome] == sum(linha.tobytes() in no_treino for linha in X[teste]), nome
    # Com as 33, entram também as gêmeas que o sorteio separou.
    assert contagem["33"] > contagem["39"] > 0
    assert registro["divisoes"]["grupos"]["teste_com_vetor_no_treino"] == {"39": 0, "33": 0}


def test_refazer_o_relatorio_nao_treina_de_novo(experimento, tmp_path, capsys):
    pasta, _ = experimento
    copia = tmp_path / "resultados"
    copia.mkdir()
    (copia / "manifesto_treino_exploratorio.json").write_bytes(
        (pasta / "resultados" / "manifesto_treino_exploratorio.json").read_bytes()
    )
    # Sem a amostra: só o manifesto do experimento é lido.
    assert main(["--saida", str(copia), "--amostra", str(tmp_path / "ausente.csv.gz"), "--refazer-relatorio"]) == 0
    for nome in ARQUIVOS:
        assert (copia / nome).read_bytes() == (pasta / "resultados" / nome).read_bytes(), nome
    assert len(list((copia / "matrizes_confusao").iterdir())) == 32


def test_amostra_que_nao_e_a_do_manifesto_e_recusada(tmp_path, capsys):
    preparar_entrada(tmp_path)
    gravar_amostra(tmp_path / "amostra.csv.gz", quadro_sintetico(por_classe=40, semente=3))
    assert executar(tmp_path) == 1
    assert "não é a amostra registrada no manifesto" in capsys.readouterr().err
    assert not (tmp_path / "resultados").exists()


def test_main_sem_a_amostra_ou_com_opcao_invalida(tmp_path, capsys):
    assert executar(tmp_path) == 1
    assert "erro:" in capsys.readouterr().err
    preparar_entrada(tmp_path)
    assert executar(tmp_path, "--arvores", "0") == 2
    assert not (tmp_path / "resultados").exists()


def test_modelos_ficam_na_pasta_pedida_e_fora_dos_resultados(tmp_path):
    preparar_entrada(tmp_path)
    # Só os modelos da semente principal são guardados: os das repetições ocupariam o triplo do disco.
    assert executar(tmp_path, "--modelos", str(tmp_path / "modelos"), repeticoes=(7,)) == 0
    assert sorted(p.name for p in (tmp_path / "modelos").iterdir()) == sorted(
        f"rf_{execucao.nome}.joblib" for execucao in EXECUCOES
    )
    # O modelo guardado, avaliado pelo comando de avaliação, dá os números do experimento.
    codigo = avaliar_modelo([
        str(tmp_path / "modelos" / "rf_f33_grupos_c7.joblib"), "--amostra", str(tmp_path / "amostra.csv.gz"),
        "--manifesto", str(tmp_path / "manifesto_amostra.json"), "--saida", str(tmp_path / "avaliacao.json"),
    ])
    assert codigo == 0
    avaliacao = json.loads((tmp_path / "avaliacao.json").read_text(encoding="utf-8"))
    execucao = next(e for e in ler_manifesto(tmp_path / "resultados")["execucoes"] if e["nome"] == "f33_grupos_c7")
    for distribuicao in ("amostra", "original"):
        assert avaliacao[distribuicao] == execucao[distribuicao]
    assert avaliacao["matriz_por_rotulo"] == execucao["matriz_por_rotulo"]


def test_relatorio_tem_as_tabelas_e_as_tres_decisoes(experimento):
    pasta, _ = experimento
    relatorio = (pasta / "resultados" / "treino_exploratorio.md").read_text(encoding="utf-8")
    assert relatorio == montar_relatorio(ler_manifesto(pasta / "resultados"))
    assert relatorio.startswith("# Treino exploratório do classificador\n")
    for titulo in (
        "## Como ler os números",
        "## As 16 execuções",
        "## Resultados por classe",
        "## Importância das features",
        "## Custo de cada execução",
        "## O que os números dizem sobre cada decisão em aberto",
        "### Janela de 10 ou de 100 pacotes",
        "### Divisão entre treino e teste",
        "### DDoS e DoS",
        "### Priori de treino",
    ):
        assert f"\n{titulo}\n" in relatorio, titulo
    for execucao in EXECUCOES:
        assert f"`{execucao.nome}`" in relatorio
    # A última seção é a das decisões.
    assert relatorio.index("## O que os números dizem") > relatorio.index("## Custo de cada execução")
    assert "reponderad" in relatorio and "na amostra" in relatorio


def test_relatorio_trata_o_teto_como_limite_do_conjunto_de_teste(experimento):
    pasta, _ = experimento
    relatorio = (pasta / "resultados" / "treino_exploratorio.md").read_text(encoding="utf-8")
    assert "limite por coincidência exata de vetores, calculado nas linhas de teste de cada execução" in relatorio
    # O recall por classe na regra do teto não é apresentado como limite da classe.
    assert "Recall na regra do teto" in relatorio and "não é um limite por classe" in relatorio
    assert "ecall máximo" not in relatorio
    # O teto das linhas de teste só aparece sem reponderar: reponderado, ele não estima o limite do conjunto completo.
    assert "Teto nas linhas de teste" in relatorio
    assert "Teto reponderado" not in relatorio and "Recall na regra do teto (repond.)" not in relatorio
    for secao in ("### Divisão entre treino e teste", "### DDoS e DoS"):
        tabela = relatorio.split(secao)[1].split("\nTeto nas linhas de teste:\n\n")[1].split("\n\n")[0]
        assert "Reponderad" not in tabela and len(tabela.splitlines()) == 6
    # O recall de DoS da exploração segue fora: não é limite de nada aqui.
    assert not hasattr(experimento_do_treino, "RECALL_MAXIMO_DE_DOS_NO_CONJUNTO")


def test_relatorio_da_o_teto_do_conjunto_completo_como_limite_da_acuracia_reponderada(experimento):
    pasta, _ = experimento
    relatorio = (pasta / "resultados" / "treino_exploratorio.md").read_text(encoding="utf-8")
    assert "não é o limite destas execuções" not in relatorio
    trecho = next(linha for linha in relatorio.splitlines() if linha.startswith("**Limite da acurácia reponderada.**"))
    assert "No sorteio estratificado, a acurácia reponderada estima a acurácia do modelo no conjunto completo" in trecho
    assert "em 8 categorias, 92,87% com as 39 features (`exploracao.md`, seção 8)" in trecho
    assert "não mediu o teto do conjunto completo em 7 categorias" in trecho
    # O teto cai com o tamanho do conjunto: linhas de teste, amostra inteira e conjunto completo.
    manifesto = ler_manifesto(pasta / "resultados")
    principal = manifesto["execucoes"][0]
    da_amostra = manifesto["amostra"]["teto"]["39"]["8"]["original"]
    assert (
        f"ele é {100 * principal['original']['teto']:.2f}% nas 72 linhas de teste de `f39_estratificada_c8` e "
        f"{100 * da_amostra:.2f}% nas 360 linhas da amostra inteira"
    ).replace(".", ",") in trecho
    # Na comparação entre 8 e 7 categorias, a diferença do conjunto completo é dita maior, sem número inventado.
    ddos_e_dos = relatorio.split("### DDoS e DoS")[1]
    assert "No conjunto completo a diferença entre o teto de 8 e o de 7 categorias é bem maior do que a medida aqui" in ddos_e_dos
    assert "O teto de 7 categorias do conjunto completo não foi calculado" in ddos_e_dos
    assert "não se compara com" not in ddos_e_dos


def test_relatorio_nao_atribui_o_sorteio_estratificado_aos_autores_do_dataset(experimento):
    pasta, _ = experimento
    relatorio = (pasta / "resultados" / "treino_exploratorio.md").read_text(encoding="utf-8")
    assert "método dos autores" not in relatorio
    assert "- **Sorteio estratificado de linhas**: " in relatorio
    # O que os autores fazem é dito à parte, como outra divisão.
    assert "O notebook de exemplo dos autores do dataset divide de outra forma: por arquivo" in relatorio


def test_relatorio_diz_o_que_sao_as_seis_colunas_que_saem(experimento):
    pasta, _ = experimento
    relatorio = (pasta / "resultados" / "treino_exploratorio.md").read_text(encoding="utf-8")
    trecho = relatorio.split("### Janela de 10 ou de 100 pacotes")[1].split("\n### ")[0]
    # `Number` não sai das colunas que ficam; as outras cinco são o produto de uma delas por `Number`.
    assert "são função de colunas que ficam" not in relatorio
    assert "`Number` é a quantidade de quadros da janela e não é função das colunas que ficam" in trecho
    assert "são o produto de uma coluna que fica por `Number`" in trecho
    assert "guardam a mesma informação" not in trecho


def com_as_33_features_assim(manifesto, previsao):
    """O manifesto com outra resposta do modelo de 33 features: `previsao` dá a classe de cada rótulo."""
    repetidas = [execucao for repeticao in manifesto["repeticoes"] for execucao in repeticao["execucoes"]]
    for execucao in (*manifesto["execucoes"], *repetidas):
        if execucao["features"] == "33" and execucao["alvo"] in ("8", "7"):
            tabela = execucao["matriz_por_rotulo"]
            for rotulo, linha in zip(tabela["rotulos"], tabela["contagem"]):
                total = sum(linha)
                linha[:] = [0] * len(linha)
                linha[tabela["classes"].index(previsao(rotulo, execucao["alvo"]))] = total
    return manifesto


def test_relatorio_diz_que_tirar_as_seis_colunas_nao_tira_o_atalho(experimento):
    pasta, _ = experimento
    # O modelo de 33 features acerta todas as linhas: os dois grupos de janela continuam separados.
    manifesto = com_as_33_features_assim(
        ler_manifesto(pasta / "resultados"), lambda rotulo, nome: ALVOS[nome].classe_do_rotulo[rotulo]
    )
    trecho = montar_relatorio(manifesto).split("### Janela de 10 ou de 100 pacotes")[1].split("\n### ")[0]
    # A resposta à pergunta da decisão, com o número que a sustenta.
    assert (
        "- **Tirar as seis colunas não tira o atalho.** Sem elas, o modelo ainda põe 100,00% das linhas de teste "
        "no grupo de janela certo"
    ) in trecho


def test_relatorio_so_afirma_que_o_atalho_fica_quando_o_modelo_de_33_ainda_separa_as_janelas(experimento):
    pasta, _ = experimento

    def flood_vira_varredura(rotulo, nome):
        return "Recon" if rotulo == "DDoS-ICMP_Flood" else ALVOS[nome].classe_do_rotulo[rotulo]

    # Um modelo de 33 features que pusesse um flood inteiro numa categoria de janela de 10.
    manifesto = com_as_33_features_assim(ler_manifesto(pasta / "resultados"), flood_vira_varredura)
    relatorio = montar_relatorio(manifesto)
    assert "Tirar as seis colunas não tira o atalho" not in relatorio
    frase = next(linha for linha in relatorio.splitlines() if linha.startswith("- Sem as seis colunas, o modelo põe "))
    # No sorteio estratificado o flood é 8 das 72 linhas de teste.
    assert "88,89%" in frase and "das linhas de teste no grupo de janela certo" in frase


def test_medidas_do_conjunto_completo_sao_as_da_exploracao_versionada():
    # O relatório cita medidas que não saem deste experimento: o teste as prende ao texto de onde vêm.
    exploracao = (RESULTADOS / "exploracao.md").read_text(encoding="utf-8")
    secao = exploracao.split("\n## 8. Linhas repetidas\n")[1].split("\n## ")[0]
    repetidas = f"{100 * experimento_do_treino.LINHAS_REPETIDAS_NO_CONJUNTO:.2f}%".replace(".", ",")
    assert f"linhas ({repetidas}) têm uma combinação que aparece mais de uma vez" in secao
    teto_de_8 = f"{100 * experimento_do_treino.TETO_DE_8_CATEGORIAS_NO_CONJUNTO:.2f}%".replace(".", ",")
    total = next(linha for linha in secao.splitlines() if linha.startswith("| Total |"))
    assert total.endswith(f"| {teto_de_8} |") and "em 8 categorias, medido no conjunto\ncompleto" in secao
    assert experimento_do_treino.FONTE_DO_CONJUNTO_COMPLETO == "`exploracao.md`, seção 8"


def test_relatorio_diz_de_onde_vem_a_medida_do_conjunto_completo(experimento):
    pasta, _ = experimento
    relatorio = (pasta / "resultados" / "treino_exploratorio.md").read_text(encoding="utf-8")
    assert relatorio.count("58,78% (`exploracao.md`, seção 8)") == 2


def test_relatorio_da_o_tempo_de_uma_janela_e_avisa_que_os_tempos_nao_se_comparam(experimento):
    pasta, _ = experimento
    manifesto = ler_manifesto(pasta / "resultados")
    relatorio = (pasta / "resultados" / "treino_exploratorio.md").read_text(encoding="utf-8")
    custo = relatorio.split("## Custo de cada execução")[1].split("\n## ")[0]
    cabecalho = next(linha for linha in custo.splitlines() if linha.startswith("| Execução |"))
    assert "| Uma janela por chamada, um núcleo (ms) |" in cabecalho
    principal = manifesto["execucoes"][0]
    linha = next(linha for linha in custo.splitlines() if linha.startswith(f"| `{principal['nome']}` |"))
    assert f"| {principal['inferencia_ms_por_janela_avulsa']:.2f} |".replace(".", ",") in linha
    assert "é o caso da operação" in custo
    assert "Os tempos não se comparam entre as linhas da tabela" in custo
    # A variação medida entre as repetições da mesma configuração, do manifesto.
    variacao = max(
        max(tempos) / min(tempos) - 1
        for nome in {execucao["nome"] for repeticao in manifesto["repeticoes"] for execucao in repeticao["execucoes"]}
        for tempos in [[e["inferencia_ms_por_mil_janelas"]["um_nucleo"] for e in em_cada_semente(manifesto, nome)]]
    )
    assert f"o tempo por 1.000 janelas com um núcleo variou até {100 * variacao:.0f}%" in custo


def em_cada_semente(manifesto, nome):
    """A execução de mesmo nome na semente principal e em cada repetição."""
    todas = [*manifesto["execucoes"], *(e for repeticao in manifesto["repeticoes"] for e in repeticao["execucoes"])]
    return [execucao for execucao in todas if execucao["nome"] == nome]


def test_relatorio_traz_a_faixa_de_cada_execucao_entre_as_sementes(experimento):
    pasta, _ = experimento
    manifesto = ler_manifesto(pasta / "resultados")
    relatorio = (pasta / "resultados" / "treino_exploratorio.md").read_text(encoding="utf-8")
    assert "\n**Sementes.** " in relatorio and "**Uma semente.**" not in relatorio
    assert "repetidas com as sementes 7 e 2026" in relatorio
    tabela = tabela_depois_de(relatorio, "\nFaixa de cada medida nas 3 sementes (42, 7 e 2026), do menor ao maior valor.")
    linhas = {linha.split(" | ")[0]: linha for linha in tabela[2:]}
    # As execuções repetidas, e só elas.
    assert list(linhas) == [f"| `{execucao.nome}`" for execucao in (*GRADE, *GRADE_NATURAL)]
    for nome in ("f39_estratificada_c8", "f33_estratificada_c7_natural"):
        execucoes = em_cada_semente(manifesto, nome)
        assert len(execucoes) == 3
        celulas = []
        for chave, distribuicao in (
            ("acuracia", "amostra"), ("acuracia", "original"), ("macro_f1", "amostra"), ("macro_f1", "original"),
            ("falso_positivo_benigno", "amostra"),
        ):
            valores = [execucao[distribuicao][chave] for execucao in execucoes]
            celulas.append(f"{pct(min(valores))} a {pct(max(valores))}")
        assert linhas[f"| `{nome}`"] == f"| `{nome}` | " + " | ".join(celulas) + " |"


def test_tabelas_de_decisao_trazem_a_faixa_da_diferenca_entre_as_sementes(experimento):
    pasta, _ = experimento
    manifesto = ler_manifesto(pasta / "resultados")
    relatorio = (pasta / "resultados" / "treino_exploratorio.md").read_text(encoding="utf-8")
    decisoes = relatorio.split("## O que os números dizem sobre cada decisão em aberto")[1]

    def diferencas(antes, depois, medida):
        return [medida(d) - medida(a) for a, d in zip(em_cada_semente(manifesto, antes), em_cada_semente(manifesto, depois))]

    def celulas(antes, depois, chave):
        resultado = []
        for distribuicao in ("amostra", "original"):
            medidas = diferencas(antes, depois, lambda e, d=distribuicao: e[d][chave])
            a, d = (em_cada_semente(manifesto, nome)[0][distribuicao][chave] for nome in (antes, depois))
            assert medidas[0] == d - a and len(medidas) == 3
            resultado += [pct(a), pct(d), pp(d - a), f"{pp(min(medidas))} a {pp(max(medidas))}"]
        return " | ".join(resultado)

    casos = (
        ("### Janela de 10 ou de 100 pacotes", "\nAcurácia:\n", "sorteio estratificado, 8 categorias",
         "f39_estratificada_c8", "f33_estratificada_c8", "acuracia"),
        ("### Divisão entre treino e teste", "\nMacro-F1:\n", "33 features, 7 categorias",
         "f33_estratificada_c7", "f33_grupos_c7", "macro_f1"),
        ("### DDoS e DoS", "\nAcurácia:\n", "39 features, divisão por grupos",
         "f39_grupos_c8", "f39_grupos_c7", "acuracia"),
        ("### Priori de treino", "\nAcurácia:\n", "`f39_estratificada_c8`",
         "f39_estratificada_c8", "f39_estratificada_c8_natural", "acuracia"),
    )
    for secao, titulo, rotulo, antes, depois, chave in casos:
        tabela = tabela_depois_de(decisoes.split(secao)[1], titulo)
        assert tabela[0].count("| Diferença (p.p.) | Faixa da diferença nas 3 sementes (p.p.) |") == 2, secao
        linha = next(linha for linha in tabela if linha.startswith(f"| {rotulo} |"))
        assert linha == f"| {rotulo} | {celulas(antes, depois, chave)} |", secao
    # As referências não foram repetidas.
    tabela = tabela_depois_de(decisoes.split("### Priori de treino")[1], "\nAcurácia:\n")
    linha = next(linha for linha in tabela if linha.startswith("| `f39_estratificada_c2` |"))
    assert linha.count("| sem repetição |") == 2


def test_leitura_da_diferenca_frente_ao_ruido_de_semente():
    leitura = experimento_do_treino._leitura
    # A diferença muda de sinal de uma comparação para outra.
    assert "não se distingue do ruído de semente" in leitura([-0.0011, 0.0013, 0.0002], 0.002)
    assert "não se distingue do ruído de semente" in leitura([0.0, 0.0013], 0.002)
    # Mesmo sinal em todas, e do tamanho da variação de uma mesma execução entre sementes.
    pequena = leitura([-0.0026, -0.0013, -0.0018], 0.0019)
    assert "tem o mesmo sinal em todas as comparações" in pequena and "pequena e consistente" in pequena
    assert "a menor, de 0,13 p.p., não chega a 2 vezes" in pequena and "(0,19 p.p.)" in pequena
    # Uma diferença que quase zera numa das comparações segue pequena, sem razão de "0,0 vezes".
    assert "vezes a maior" in leitura([-0.0059, -0.0001], 0.0051) and "0,0 vezes" not in leitura([-0.0059, -0.0001], 0.0051)
    # Mesmo sinal em todas, e muitas vezes maior do que essa variação.
    grande = leitura([0.0923, 0.0931, 0.0926], 0.0019)
    assert "muito acima do ruído de semente" in grande and "48,6 vezes" in grande
    # Entre uma coisa e outra.
    media = leitura([0.0100, 0.0080], 0.002)
    assert "acima do ruído de semente" in media and "muito acima" not in media and "pequena" not in media
    # Sem variação entre sementes não há com o que comparar o tamanho.
    assert "não variou entre as sementes" in leitura([0.01, 0.02], 0.0)


def test_cada_decisao_diz_como_a_diferenca_se_compara_com_o_ruido_de_semente(experimento):
    pasta, _ = experimento
    relatorio = (pasta / "resultados" / "treino_exploratorio.md").read_text(encoding="utf-8")
    decisoes = relatorio.split("## O que os números dizem sobre cada decisão em aberto")[1]
    for secao, comparacoes in (
        ("### Janela de 10 ou de 100 pacotes", "12 comparações (4 pares de execuções, 3 sementes)"),
        ("### Divisão entre treino e teste", "12 comparações (4 pares de execuções, 3 sementes)"),
        ("### DDoS e DoS", "12 comparações (4 pares de execuções, 3 sementes)"),
        ("### Priori de treino", "12 comparações (4 pares de execuções, 3 sementes)"),
    ):
        trecho = decisoes.split(secao)[1].split("\n### ")[0]
        frase = next(linha for linha in trecho.splitlines() if linha.startswith("- Acurácia"))
        assert comparacoes in frase, secao
        assert "Na amostra, a diferença vai de " in frase and "Reponderada, vai de " in frase, secao


def test_relatorio_de_uma_semente_nao_traz_faixas(sem_repeticoes):
    relatorio = (sem_repeticoes / "resultados" / "treino_exploratorio.md").read_text(encoding="utf-8")
    assert "\n**Uma semente.** " in relatorio and "**Sementes.**" not in relatorio
    assert "Faixa" not in relatorio and "comparações" not in relatorio and "sem repetição" not in relatorio
    assert relatorio == montar_relatorio(ler_manifesto(sem_repeticoes / "resultados"))


def test_relatorio_mostra_os_dois_lados_da_priori_de_treino(experimento):
    pasta, _ = experimento
    manifesto = ler_manifesto(pasta / "resultados")
    relatorio = (pasta / "resultados" / "treino_exploratorio.md").read_text(encoding="utf-8")
    execucoes = {execucao["nome"]: execucao for execucao in manifesto["execucoes"]}
    # Como ler: o que é cada priori e por que a reponderação não a corrige.
    assert "\n**Priori de treino.** " in relatorio
    assert "- **proporções da amostra**: " in relatorio and "- **proporção natural**: " in relatorio
    assert "muda o peso das linhas na avaliação, e não o que o modelo aprendeu" in relatorio
    # A frase antiga dizia que a taxa do benigno não muda; ela não muda com a ponderação, mas muda com a priori.
    assert "não muda com a ponderação, porque o tráfego benigno é um rótulo só. Ela muda com a priori de treino" in relatorio
    secao = relatorio.split("\n### Priori de treino\n")[1].split("\n## ")[0]
    # Os dois lados, com o custo de cada um: benigno como ataque, ataque como benigno e recall por categoria.
    benigno_como_ataque = tabela_depois_de(secao, "\nTráfego benigno classificado como ataque, como fração")
    ataque_como_benigno = tabela_depois_de(secao, "\nAtaque classificado como tráfego benigno, como fração")
    assert benigno_como_ataque[0].startswith("| Execução | Priori da amostra | Priori natural | Diferença (p.p.) |")
    for nome in ("f39_estratificada_c8", "f33_estratificada_c7", "f39_estratificada_c34", "f39_estratificada_c2"):
        da_amostra, natural = execucoes[nome], execucoes[f"{nome}_natural"]
        benigno = ALVOS[da_amostra["alvo"]].benigno
        taxas = [execucao["amostra"]["falso_positivo_benigno"] for execucao in (da_amostra, natural)]
        linha = next(linha for linha in benigno_como_ataque if linha.startswith(f"| `{nome}` |"))
        assert linha.startswith(f"| `{nome}` | {pct(taxas[0])} | {pct(taxas[1])} | {pp(taxas[1] - taxas[0])} |")
        linha = next(linha for linha in ataque_como_benigno if linha.startswith(f"| `{nome}` |"))
        for distribuicao in ("amostra", "original"):
            taxas = [e[distribuicao]["por_classe"][benigno]["taxa_falso_positivo"] for e in (da_amostra, natural)]
            assert f"| {pct(taxas[0])} | {pct(taxas[1])} | {pp(taxas[1] - taxas[0])} |" in linha
    for categoria in ALVOS["8"].classes:
        da_amostra, natural = execucoes["f39_estratificada_c8"], execucoes["f39_estratificada_c8_natural"]
        recalls = [pct(execucao["original"]["por_classe"][categoria]["recall"]) for execucao in (da_amostra, natural)]
        assert f"\n| {categoria} | {recalls[0]} | {recalls[1]} |" in secao
    assert "dependem da priori de treino" in secao
    # Quantas linhas das categorias pequenas cada árvore recebe com a priori natural.
    natural = execucoes["f39_estratificada_c8_natural"]
    populacao, na_amostra = manifesto["populacao"], manifesto["amostra"]["linhas_por_rotulo"]
    esperadas = {
        categoria: natural["linhas_de_treino"] * sum(
            populacao[rotulo] for rotulo in na_amostra if ALVOS["8"].classe_do_rotulo[rotulo] == categoria
        ) / sum(populacao.values())
        for categoria in ALVOS["8"].classes
    }
    menor = min(esperadas, key=esperadas.get)
    de_treino = sum(
        linhas for rotulo, linhas in na_amostra.items() if ALVOS["8"].classe_do_rotulo[rotulo] == menor
    ) - natural["amostra"]["por_classe"][menor]["suporte"]
    frase = next(linha for linha in secao.splitlines() if linha.startswith("- Com a priori natural, cada árvore sorteia"))
    assert f": {menor} com cerca de {round(esperadas[menor])} linhas sorteadas, contra {de_treino} linhas de treino na amostra; " in frase
    # O tamanho do modelo também muda com a priori.
    frase = next(linha for linha in secao.splitlines() if linha.startswith("- O tamanho do modelo"))
    megas = [execucoes[nome]["modelo_bytes"] / 1e6 for nome in ("f39_estratificada_c8", "f39_estratificada_c8_natural")]
    for valor in megas:
        assert f"{valor:.1f}".replace(".", ",") in frase
    assert "O relatório não recomenda nenhuma das duas" in secao
    for palavra in ("recomenda-se", "deve-se", "o melhor", "preferível"):
        assert palavra not in secao.lower()


def test_faixa_de_um_valor_so_nao_repete_o_valor():
    faixa = experimento_do_treino._faixa
    assert faixa([0.4606, 0.4722, 0.4618]) == "de 46,06% a 47,22%"
    assert faixa([0.00101, 0.00099]) == "0,10%"
    assert faixa([0.248, 0.312], 1) == "de 24,8% a 31,2%"


def test_relatorio_nao_diz_qual_coluna_se_compara_com_o_artigo_do_dataset(experimento):
    pasta, _ = experimento
    relatorio = (pasta / "resultados" / "treino_exploratorio.md").read_text(encoding="utf-8")
    assert "coluna comparável" not in relatorio
    assert "Nenhuma coluna deste relatório repete esse protocolo" in relatorio


def test_relatorio_mostra_para_onde_vai_o_trafego_benigno(experimento):
    pasta, _ = experimento
    manifesto = ler_manifesto(pasta / "resultados")
    relatorio = (pasta / "resultados" / "treino_exploratorio.md").read_text(encoding="utf-8")
    assert "Para onde vai o tráfego benigno" in relatorio
    trecho = relatorio.split("Para onde vai o tráfego benigno")[1].split("\n## ")[0]
    # Uma coluna por execução de 8 categorias e uma linha por categoria.
    for execucao in manifesto["execucoes"]:
        assert (f"`{execucao['nome']}`" in trecho) == (execucao["alvo"] == "8")
    for categoria in ALVOS["8"].classes:
        assert f"\n| {categoria} |" in trecho
    principal = manifesto["execucoes"][0]
    assert f"| Benign | {100 * principal['amostra']['por_classe']['Benign']['recall']:.2f}%".replace(".", ",") in trecho


def test_relatorio_segue_o_estilo_dos_textos_do_projeto(experimento):
    pasta, _ = experimento
    relatorio = (pasta / "resultados" / "treino_exploratorio.md").read_text(encoding="utf-8")
    assert "—" not in relatorio and "–" not in relatorio
    assert not re.search(r"\b(nan|None|inf)\b", relatorio)
    assert relatorio.endswith("\n") and not relatorio.endswith("\n\n")


def test_relatorio_da_os_numeros_do_manifesto(experimento):
    pasta, _ = experimento
    manifesto = ler_manifesto(pasta / "resultados")
    relatorio = (pasta / "resultados" / "treino_exploratorio.md").read_text(encoding="utf-8")
    principal = manifesto["execucoes"][0]
    for distribuicao in ("amostra", "original"):
        for chave in ("acuracia", "macro_f1", "teto"):
            esperado = f"{100 * principal[distribuicao][chave]:.2f}%".replace(".", ",")
            assert esperado in relatorio, (distribuicao, chave)


@pytest.mark.skipif(not (RESULTADOS / "manifesto_treino_exploratorio.json").exists(), reason="experimento ainda não rodado")
def test_resultados_versionados_sao_coerentes_entre_si():
    manifesto = ler_manifesto(RESULTADOS)
    assert len(manifesto["execucoes"]) == 16
    assert manifesto["semente"] == 42 and [repeticao["semente"] for repeticao in manifesto["repeticoes"]] == [7, 2026]
    assert all(len(repeticao["execucoes"]) == 12 for repeticao in manifesto["repeticoes"])
    assert (RESULTADOS / "treino_exploratorio.md").read_text(encoding="utf-8") == montar_relatorio(manifesto)
    relatorio = (RESULTADOS / "treino_exploratorio.md").read_text(encoding="utf-8")
    assert "- **Tirar as seis colunas não tira o atalho.**" in relatorio
    amostra = json.loads((RESULTADOS / "manifesto_amostra.json").read_text(encoding="utf-8"))
    assert manifesto["amostra"]["sha256_do_csv_descomprimido"] == amostra["saida"]["sha256_do_csv_descomprimido"]
    for execucao in manifesto["execucoes"]:
        _, _, contagem = ler_matriz(RESULTADOS / "matrizes_confusao" / f"{execucao['nome']}.csv")
        assert contagem.sum() == execucao["linhas_de_teste"]
        assert np.trace(contagem) / contagem.sum() == pytest.approx(execucao["amostra"]["acuracia"])
