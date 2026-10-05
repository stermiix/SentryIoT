import csv
import json
import re
from pathlib import Path

import numpy as np
import pytest

from codigo.classificador.avaliar import main as avaliar_modelo
from codigo.classificador.experimento import (
    ARVORES_COM_34_CLASSES,
    GRADE,
    REFERENCIAS,
    Execucao,
    main,
    montar_relatorio,
)
from codigo.classificador.mapeamento import ROTULOS
from codigo.classificador.preparar import (
    ALVOS,
    FEATURES_33,
    FEATURES_39,
    dividir,
    impressao_digital,
)
from codigo.classificador.test_preparar import gravar_amostra, quadro_sintetico

RESULTADOS = Path(__file__).resolve().parents[2] / "experimentos" / "resultados"
ARQUIVOS = ("treino_exploratorio.md", "metricas_classificador.csv", "importancia_features.csv")
# O que muda de uma execução para outra sem que os resultados mudem: data e medidas de tempo.
VARIAVEIS = ("gerado_em", "treino_segundos", "teste_segundos", "inferencia_ms_por_mil_janelas", "duracao_segundos")


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


def executar(pasta, *extras, saida=None):
    return main([
        "--amostra", str(pasta / "amostra.csv.gz"), "--manifesto-da-amostra", str(pasta / "manifesto_amostra.json"),
        "--saida", str(saida or pasta / "resultados"), "--arvores", "5", *extras,
    ])


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
    assert executar(pasta) == 0
    return pasta, quadro


def test_grade_tem_as_oito_combinacoes_e_as_duas_referencias():
    assert len(GRADE) == 8 == len(set(GRADE))
    assert {(e.features, e.divisao, e.alvo) for e in GRADE} == {
        (features, divisao, alvo)
        for features in ("39", "33") for divisao in ("estratificada", "grupos") for alvo in ("8", "7")
    }
    assert REFERENCIAS == (Execucao("39", "estratificada", "34"), Execucao("39", "estratificada", "2"))
    nomes = [execucao.nome for execucao in (*GRADE, *REFERENCIAS)]
    assert len(set(nomes)) == 10
    assert Execucao("33", "grupos", "7").nome == "f33_grupos_c7"


def test_main_grava_o_relatorio_as_tabelas_as_matrizes_e_o_manifesto(experimento):
    pasta, _ = experimento
    resultados = pasta / "resultados"
    assert sorted(p.name for p in resultados.iterdir()) == sorted(
        [*ARQUIVOS, "manifesto_treino_exploratorio.json", "matrizes_confusao"]
    )
    nomes = [execucao.nome for execucao in (*GRADE, *REFERENCIAS)]
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
    assert manifesto["parametros"]["arvores"] == 5 and manifesto["parametros"]["fracao_de_teste"] == 0.2
    assert manifesto["parametros"]["arvores_com_34_classes"] == min(5, ARVORES_COM_34_CLASSES)
    assert set(manifesto["versoes"]) == {"python", "numpy", "pandas", "scikit-learn", "joblib"}
    assert manifesto["amostra"]["sha256_do_csv_descomprimido"] == entrada["saida"]["sha256_do_csv_descomprimido"]
    assert manifesto["amostra"]["linhas"] == len(quadro) == 360
    assert manifesto["features"] == {"39": list(FEATURES_39), "33": list(FEATURES_33)}
    assert [execucao["nome"] for execucao in manifesto["execucoes"]] == [e.nome for e in (*GRADE, *REFERENCIAS)]
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
        assert len(execucao["importancias"]) == int(execucao["features"])
        assert execucao["arvores"] == 5
        assert execucao["linhas_de_teste"] == sum(map(sum, execucao["matriz_por_rotulo"]["contagem"]))


def test_execucao_de_34_classes_usa_menos_arvores(tmp_path):
    preparar_entrada(tmp_path)
    assert executar(tmp_path, "--arvores", "30") == 0
    arvores = {e["nome"]: e["arvores"] for e in ler_manifesto(tmp_path / "resultados")["execucoes"]}
    assert ARVORES_COM_34_CLASSES == 25
    assert arvores["f39_estratificada_c34"] == 25
    assert set(arvores.values()) == {25, 30}


def test_metricas_em_formato_longo(experimento):
    pasta, _ = experimento
    linhas = ler_csv(pasta / "resultados" / "metricas_classificador.csv")
    assert list(linhas[0]) == [
        "execucao", "distribuicao", "classe", "precisao", "recall", "f1", "suporte",
        "taxa_falso_positivo", "recall_maximo",
    ]
    manifesto = ler_manifesto(pasta / "resultados")
    esperadas = sum(2 * len(ALVOS[execucao["alvo"]].classes) for execucao in manifesto["execucoes"])
    assert len(linhas) == esperadas == 2 * (4 * 8 + 4 * 7 + 34 + 2)
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
    assert len(linhas) == 6 * 39 + 4 * 33
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
    assert executar(pasta, saida=tmp_path / "de_novo") == 0
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
    assert len(list((copia / "matrizes_confusao").iterdir())) == 20


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
    assert executar(tmp_path, "--modelos", str(tmp_path / "modelos")) == 0
    assert sorted(p.name for p in (tmp_path / "modelos").iterdir()) == sorted(
        f"rf_{execucao.nome}.joblib" for execucao in (*GRADE, *REFERENCIAS)
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
        "## As 10 execuções",
        "## Resultados por classe",
        "## Importância das features",
        "## Custo de cada execução",
        "## O que os números dizem sobre cada decisão em aberto",
        "### Janela de 10 ou de 100 pacotes",
        "### Divisão entre treino e teste",
        "### DDoS e DoS",
    ):
        assert f"\n{titulo}\n" in relatorio, titulo
    for execucao in (*GRADE, *REFERENCIAS):
        assert f"`{execucao.nome}`" in relatorio
    # A última seção é a das decisões.
    assert relatorio.index("## O que os números dizem") > relatorio.index("## Custo de cada execução")
    assert "reponderad" in relatorio and "na amostra" in relatorio


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
    assert len(manifesto["execucoes"]) == 10
    assert (RESULTADOS / "treino_exploratorio.md").read_text(encoding="utf-8") == montar_relatorio(manifesto)
    amostra = json.loads((RESULTADOS / "manifesto_amostra.json").read_text(encoding="utf-8"))
    assert manifesto["amostra"]["sha256_do_csv_descomprimido"] == amostra["saida"]["sha256_do_csv_descomprimido"]
    for execucao in manifesto["execucoes"]:
        _, _, contagem = ler_matriz(RESULTADOS / "matrizes_confusao" / f"{execucao['nome']}.csv")
        assert contagem.sum() == execucao["linhas_de_teste"]
        assert np.trace(contagem) / contagem.sum() == pytest.approx(execucao["amostra"]["acuracia"])
