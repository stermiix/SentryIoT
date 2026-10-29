import csv
import gzip
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from codigo.captura.extrator import COLUNAS
from codigo.classificador.mapeamento import CATEGORIA_DO_ROTULO, ROTULOS
from codigo.classificador.operacao import (
    SEGUIDAS,
    PontoDeOperacao,
    ao_lado_do_modelo,
    ler,
)
from codigo.classificador.preparar import ALVOS
from codigo.classificador.regerar import CABECALHO, DESCARTADAS, nome_da_pasta
from codigo.classificador.regerar import MANIFESTO as MANIFESTO_DA_REGERACAO
from codigo.classificador.regerar import montar_manifesto as manifesto_da_regeracao
from codigo.classificador.test_janela import sem_variaveis
from codigo.classificador.test_preparar import quadro_sintetico
from codigo.classificador.treinar import carregar_modelo
from codigo.classificador.treinar_regerado import (
    ALVO,
    CLASSES,
    MANIFESTO,
    MANIFESTO_DE_REFERENCIA,
    METRICAS,
    POR_ARQUIVO,
    RELATORIO,
    TETO,
    arquivos_inteiros_no_teste,
    ataque_como_benigno,
    ips_de_origem,
    ler_janela,
    limitar,
    main,
    montar_relatorio,
    reponderada,
)

JANELAS = (2, 5)
# Rótulo -> arquivos e quantas janelas cada um tem no caso sintético. Sem a categoria Web.
ARQUIVOS = {
    "DDoS-ICMP_Flood": {"DDoS-ICMP_Flood.pcap": 40},
    "DDoS-SYN_Flood": {"DDoS-SYN_Flood.pcap": 40},
    "DoS-SYN_Flood": {"DoS-SYN_Flood.pcap": 40},
    "Mirai-udpplain": {"Mirai-udpplain.pcap": 40},
    "Recon-PortScan": {"Recon-PortScan.pcap": 40},
    "MITM-ArpSpoofing": {"MITM-ArpSpoofing.pcap": 40},
    "DictionaryBruteForce": {"DictionaryBruteForce.pcap": 40},
    "BenignTraffic": {"BenignTraffic.pcap": 25, "BenignTraffic1.pcap": 15},
}
IPS = {"DDoS-ICMP_Flood": 6, "DDoS-SYN_Flood": 5}


def quadro_regerado():
    """O caso sintético de `test_preparar`, sem XSS, com as colunas dos CSVs regerados."""
    quadro = quadro_sintetico(por_classe=40)
    quadro = quadro[quadro["Label"] != "XSS"].reset_index(drop=True)
    arquivo, indice = [], []
    for rotulo in quadro["Label"].unique():
        for nome, janelas in ARQUIVOS[rotulo].items():
            arquivo += [nome] * janelas
            indice += list(range(janelas))
    quadro["arquivo"], quadro["indice"] = arquivo, indice
    quadro["ips_origem"] = quadro["Label"].map(lambda rotulo: IPS.get(rotulo, 1))
    quadro["ips_destino"] = 1
    quadro["atacante"] = (quadro["Label"] != "BenignTraffic").astype(int)
    quadro["quadros_atacante"] = quadro["atacante"] * 3
    quadro["macs_atacante"] = quadro["atacante"]
    return quadro[list(CABECALHO)]


def preparar_regeracao(pasta):
    """A pasta dos dados regerados e o manifesto da regeração, como o regerar.py os deixa."""
    destino = pasta / "regerado"
    quadro = quadro_regerado()
    for janela in JANELAS:
        pasta_da_janela = destino / nome_da_pasta(janela)
        (pasta_da_janela / DESCARTADAS).mkdir(parents=True)
        for rotulo, parte in quadro.groupby("Label", sort=False):
            parte = parte.copy()
            parte["Number"] = float(janela)
            with gzip.open(pasta_da_janela / f"{rotulo}.csv.gz", "wt", encoding="utf-8", newline="") as arquivo:
                parte.to_csv(arquivo, index=False, lineterminator="\n")
            if rotulo == "BenignTraffic":
                continue
            # As 3 janelas de fundo de cada pcap de ataque, depois das mantidas, como o regerar as deixa.
            for nome, janelas in ARQUIVOS[rotulo].items():
                fundo = parte[parte["arquivo"] == nome].head(3).copy()
                fundo["indice"] = range(janelas, janelas + 3)
                fundo[["atacante", "quadros_atacante", "macs_atacante"]] = 0
                with gzip.open(pasta_da_janela / DESCARTADAS / f"{Path(nome).stem}.csv.gz", "wt", encoding="utf-8",
                               newline="") as arquivo:
                    fundo.to_csv(arquivo, index=False, header=False, lineterminator="\n")
    registros = [
        {
            "arquivo": nome, "rotulo": rotulo, "categoria": CATEGORIA_DO_ROTULO[rotulo],
            "benigno": rotulo == "BenignTraffic", "bytes": 1000, "modificado_ns": 1, "sha256": "0" * 64,
            "pacotes": janelas * 10, "segundos": 0.5, "avisos": [],
            "janelas": {
                str(janela): {
                    "extraidas": janelas + 3, "mantidas": janelas, "descartadas": 3, "com_atacante": janelas,
                    "incompletas": 0,
                } for janela in JANELAS
            },
        }
        for rotulo, arquivos in ARQUIVOS.items() for nome, janelas in arquivos.items()
    ]
    rotulos = [
        {
            "rotulo": rotulo, "categoria": CATEGORIA_DO_ROTULO[rotulo], "arquivos": list(arquivos),
            "linhas": {str(janela): sum(arquivos.values()) for janela in JANELAS},
        }
        for rotulo, arquivos in ARQUIVOS.items()
    ]
    resultados = pasta / "resultados"
    resultados.mkdir()
    manifesto = manifesto_da_regeracao(registros, rotulos, pasta / "dataset", JANELAS, str(destino))
    (resultados / MANIFESTO_DA_REGERACAO).write_text(json.dumps(manifesto, ensure_ascii=False), encoding="utf-8")
    return pasta


def executar(pasta, *extras):
    return main([
        "--saida", str(pasta / "resultados"), "--modelos", str(pasta / "modelos"), "--arvores", "5", "--nucleos", "1",
        "--janelas", ",".join(str(janela) for janela in JANELAS), *extras,
    ])


def pct(valor):
    return f"{100 * valor:.2f}%".replace(".", ",")


def ler_csv(caminho):
    with open(caminho, encoding="utf-8", newline="") as arquivo:
        return list(csv.DictReader(arquivo))


@pytest.fixture(scope="module")
def treino(tmp_path_factory):
    pasta = preparar_regeracao(tmp_path_factory.mktemp("regerado"))
    assert executar(pasta, "--teto", "30") == 0
    return pasta


def ler_manifesto(pasta):
    return json.loads((pasta / "resultados" / MANIFESTO).read_text(encoding="utf-8"))


def test_constantes():
    assert ALVO == "7" and TETO == 50_000


def test_ler_janela_junta_os_csvs_do_rotulo_em_ordem_de_arquivo_e_indice(tmp_path):
    pasta = preparar_regeracao(tmp_path)
    quadro, resumo = ler_janela(pasta / "regerado", 2)
    assert len(quadro) == 320
    assert resumo["regeradas"] == {rotulo: sum(arquivos.values()) for rotulo, arquivos in ARQUIVOS.items()}
    assert list(resumo["regeradas"]) == [r for r in ROTULOS if r in ARQUIVOS]
    assert list(COLUNAS) == [coluna for coluna in quadro.columns if coluna in COLUNAS]
    assert quadro["Label"].nunique() == 8
    benigno = quadro[quadro["Label"] == "BenignTraffic"]
    assert benigno["arquivo"].tolist() == ["BenignTraffic.pcap"] * 25 + ["BenignTraffic1.pcap"] * 15
    assert benigno["indice"].astype(int).tolist() == list(range(25)) + list(range(15))


def test_ler_janela_le_os_csvs_de_antes_das_colunas_novas(tmp_path):
    pasta = preparar_regeracao(tmp_path)
    novo, _ = ler_janela(pasta / "regerado", 2)
    assert novo["quadros_atacante"].dtype == np.int64 and novo["macs_atacante"].max() == 1
    # Os CSVs gravados antes da versão 2 da regra não têm as duas colunas, e são lidos como antes.
    for caminho in (pasta / "regerado" / "janela_2").glob("*.csv.gz"):
        quadro = pd.read_csv(caminho, dtype=str)
        with gzip.open(caminho, "wt", encoding="utf-8", newline="") as arquivo:
            quadro.drop(columns=["quadros_atacante", "macs_atacante"]).to_csv(arquivo, index=False, lineterminator="\n")
    antigo, _ = ler_janela(pasta / "regerado", 2)
    assert "quadros_atacante" not in antigo.columns
    assert antigo.equals(novo.drop(columns=["quadros_atacante", "macs_atacante"]))


def test_limitar_sorteia_ate_o_teto_por_rotulo_com_semente(tmp_path):
    quadro, _ = ler_janela(preparar_regeracao(tmp_path) / "regerado", 2)
    amostra = limitar(quadro, teto=30, semente=42)
    assert amostra["Label"].value_counts().max() == 30
    assert len(amostra) == 8 * 30
    # Linhas na ordem original, e o mesmo sorteio a cada chamada.
    assert amostra.index.is_monotonic_increasing
    assert amostra.index.equals(limitar(quadro, teto=30, semente=42).index)
    assert not amostra.index.equals(limitar(quadro, teto=30, semente=7).index)
    assert limitar(quadro, teto=1000, semente=42).index.equals(quadro.index)
    # Com o teto na leitura, arquivo a arquivo, o sorteio é o mesmo que o de uma vez só.
    na_leitura, resumo = ler_janela(tmp_path / "regerado", 2, teto=30, semente=42)
    assert len(na_leitura) == 240 and resumo["regeradas"]["BenignTraffic"] == 40
    chave = ["arquivo", "indice"]
    assert na_leitura[chave].reset_index(drop=True).equals(amostra.sort_values(chave)[chave].reset_index(drop=True))


def test_ips_de_origem_resume_as_classes_de_ddos_e_dos(tmp_path):
    quadro, lido = ler_janela(preparar_regeracao(tmp_path) / "regerado", 2)
    resumo = ips_de_origem(quadro)
    assert lido["ips_de_origem"] == resumo
    assert [r["rotulo"] for r in resumo] == ["DDoS-ICMP_Flood", "DDoS-SYN_Flood", "DoS-SYN_Flood"]
    ddos = resumo[1]
    assert (ddos["janelas"], ddos["minimo"], ddos["mediana"], ddos["maximo"]) == (40, 5, 5.0, 5)
    assert ddos["ate_1"] == 0.0 and resumo[2]["ate_1"] == 1.0


def test_treina_e_avalia_nas_duas_janelas(treino):
    m = ler_manifesto(treino)
    assert [j["janela"] for j in m["janelas"]] == [2, 5]
    assert m["teto"] == 30 and m["semente"] == 42 and m["alvo"] == "7" and m["divisao"] == "tempo"
    assert m["categorias_sem_pcap"] == ["Web"]
    assert m["rotulos_sem_pcap"] == 34 - 8
    assert m["rodadas_anteriores"] == []
    de_dois = m["janelas"][0]
    assert de_dois["linhas"]["regeradas"] == 320 and de_dois["linhas"]["amostra"] == 240
    assert de_dois["linhas"]["treino"] + de_dois["linhas"]["teste"] == 240
    # O rótulo com dois arquivos tem um arquivo inteiro no teste; os outros, os últimos 30% das janelas.
    assert de_dois["arquivos_de_teste"] == ["BenignTraffic1.pcap"]
    benigno = next(r for r in de_dois["por_rotulo"] if r["rotulo"] == "BenignTraffic")
    assert benigno["teste"] == benigno["linhas_no_arquivo_de_teste"] and benigno["teste"] > 0
    recon = next(r for r in de_dois["por_rotulo"] if r["rotulo"] == "Recon-PortScan")
    assert recon["amostra"] == 30 and recon["treino"] + recon["teste"] == 30 and recon["teste"] >= 8
    assert len(de_dois["divisao"]["treino_sha256"]) == 64
    # A avaliação é a do avaliar.py, na parte de teste, nas 7 categorias.
    avaliacao = de_dois["avaliacao"]
    assert set(avaliacao["amostra"]["por_classe"]) == set(ALVOS[ALVO].classes)
    assert 0 <= avaliacao["amostra"]["macro_f1"] <= 1
    assert avaliacao["amostra"]["por_classe"]["Web"]["suporte"] == 0
    assert avaliacao["amostra"]["falso_positivo_benigno"] is not None
    assert de_dois["treino_segundos"] > 0
    assert len(de_dois["importancias"]) == 39
    assert [p["arquivo"] for p in de_dois["por_arquivo"]] == sorted(p["arquivo"] for p in de_dois["por_arquivo"])
    assert all(p["na_esperada"] is None or 0 <= p["na_esperada"] <= 1 for p in de_dois["por_arquivo"])
    sem_teste = next(p for p in de_dois["por_arquivo"] if p["arquivo"] == "BenignTraffic.pcap")
    assert sem_teste["janelas_de_teste"] == 0 and sem_teste["na_esperada"] is None
    assert [r["rotulo"] for r in de_dois["ips_de_origem"]] == ["DDoS-ICMP_Flood", "DDoS-SYN_Flood", "DoS-SYN_Flood"]


def test_salva_um_modelo_por_janela(treino):
    for janela in JANELAS:
        pacote = carregar_modelo(treino / "modelos" / f"rf_regerado_janela_{janela}.joblib")
        assert pacote["alvo"] == ALVO and len(pacote["features"]) == 39
        assert pacote["divisao"] == "tempo" and pacote["janela"] == janela and pacote["teto"] == 30
        assert len(pacote["modelo"].estimators_) == 5
    m = ler_manifesto(treino)
    assert m["janelas"][0]["modelo"]["arquivo"] == "rf_regerado_janela_2.joblib"
    assert m["janelas"][0]["modelo"]["bytes"] > 0


def test_grava_as_tabelas_e_as_matrizes(treino):
    resultados = treino / "resultados"
    metricas = ler_csv(resultados / METRICAS)
    assert len(metricas) == 2 * 3 * 7
    assert {l["janela"] for l in metricas} == {"2", "5"}
    assert {l["regra"] for l in metricas} == {"argmax", "limiar", "ponto"}
    recon = next(l for l in metricas if l["janela"] == "2" and l["classe"] == "Recon")
    assert set(recon) == {"janela", "regra", "classe", "precisao", "recall", "f1", "suporte", "taxa_falso_positivo"}
    assert 0 <= float(recon["recall"]) <= 1
    web = next(l for l in metricas if l["janela"] == "2" and l["classe"] == "Web")
    assert web["suporte"] == "0" and web["recall"] == ""
    por_arquivo = ler_csv(resultados / POR_ARQUIVO)
    assert len(por_arquivo) == 2 * 9
    assert set(por_arquivo[0]) >= {"janela", "arquivo", "rotulo", "categoria_esperada", "janelas_de_teste", "na_esperada"}
    for janela, sufixo in ((janela, sufixo) for janela in JANELAS for sufixo in ("", "_limiar", "_ponto")):
        confusao = pd.read_csv(resultados / "matrizes_confusao" / f"regerado_janela_{janela}{sufixo}.csv", index_col=0)
        assert list(confusao.index) == list(ALVOS[ALVO].classes) == list(confusao.columns)
        por_rotulo = pd.read_csv(resultados / "matrizes_confusao" / f"regerado_janela_{janela}{sufixo}_por_rotulo.csv",
                                 index_col=0)
        assert len(por_rotulo) == 8


def test_relatorio_traz_os_dados_as_duas_janelas_e_o_que_falta(treino):
    texto = (treino / "resultados" / RELATORIO).read_text(encoding="utf-8")
    assert texto.startswith("# Treino sobre os dados regerados")
    for secao in (
        "## Os dados regerados", "## Treino e teste", "## Resultados com janela de 2", "## Resultados com janela de 5",
        "## As duas janelas lado a lado", "## IPs de origem por janela em DDoS e DoS", "## Ressalvas",
        "## Como os números foram obtidos",
    ):
        assert secao in texto, secao
    assert "`BenignTraffic1.pcap`" in texto and "Web" in texto
    assert "ainda não têm pcap" in texto or "sem pcap" in texto
    assert "26 dos 34 rótulos" in texto
    assert montar_relatorio(ler_manifesto(treino)) == texto


def test_os_numeros_sao_os_mesmos_em_outra_execucao(treino):
    antes = ler_manifesto(treino)
    assert executar(treino, "--teto", "30") == 0
    depois = ler_manifesto(treino)
    # Com os mesmos pcaps, a execução anterior não vira rodada anterior, e nada muda.
    assert depois["rodadas_anteriores"] == antes["rodadas_anteriores"] == []
    assert depois.pop("memoria_pico_bytes") > 0 and antes.pop("memoria_pico_bytes") > 0
    assert sem_variaveis(depois) == sem_variaveis(antes)
    texto = (treino / "resultados" / RELATORIO).read_text(encoding="utf-8")
    assert "## Rodadas anteriores, como referência" not in texto
    assert "Pico de memória do processo" in texto


def test_a_rodada_anterior_fica_registrada_quando_os_pcaps_mudam(tmp_path):
    pasta = preparar_regeracao(tmp_path)
    assert executar(pasta, "--teto", "30") == 0
    antes = ler_manifesto(pasta)
    caminho = pasta / "resultados" / MANIFESTO_DA_REGERACAO
    regeracao = json.loads(caminho.read_text(encoding="utf-8"))
    regeracao["pcaps"][0]["sha256"] = "1" * 64  # um pcap trocado por outro com o mesmo nome
    caminho.write_text(json.dumps(regeracao, ensure_ascii=False), encoding="utf-8")
    assert executar(pasta, "--teto", "30") == 0
    depois = ler_manifesto(pasta)
    assert len(depois["rodadas_anteriores"]) == 1
    resumo = depois["rodadas_anteriores"][0]
    assert resumo["pcaps"] == 9 and len(resumo["rotulos"]) == 8 and resumo["rotulos_sem_pcap"] == 26
    assert resumo["janelas"][0]["macro_f1"] == antes["janelas"][0]["avaliacao"]["amostra"]["macro_f1"]
    assert set(resumo["janelas"][0]["por_classe"]) == set(ALVOS[ALVO].classes)
    texto = (pasta / "resultados" / RELATORIO).read_text(encoding="utf-8")
    assert "## Rodadas anteriores, como referência" in texto
    assert "Nenhum rótulo entrou" in texto and "Pcaps: de 9 para 9" in texto
    # Refazer o relatório não acrescenta rodada.
    assert executar(pasta, "--refazer-relatorio") == 0
    assert len(ler_manifesto(pasta)["rodadas_anteriores"]) == 1


def test_ler_janela_em_pedacos_da_o_mesmo_que_ler_tudo(tmp_path, monkeypatch):
    import codigo.classificador.treinar_regerado as modulo

    pasta = preparar_regeracao(tmp_path)
    inteiro, resumo_inteiro = ler_janela(pasta / "regerado", 2, teto=30, semente=7)
    # Pedaços de 7 linhas: cortam os rótulos e os arquivos em lugares quaisquer.
    monkeypatch.setattr(modulo, "PEDACO", 7)
    em_pedacos, resumo = ler_janela(pasta / "regerado", 2, teto=30, semente=7)
    assert em_pedacos.equals(inteiro) and resumo == resumo_inteiro
    assert list(em_pedacos.dtypes[list(COLUNAS)].unique()) == [np.float64]
    assert em_pedacos["indice"].dtype == np.int64


def test_avaliacao_nos_arquivos_inteiros_de_teste(treino):
    m = ler_manifesto(treino)
    for j in m["janelas"]:
        inteiros = j["avaliacao_arquivos_inteiros"]
        assert inteiros["linhas"] == sum(
            p["janelas_de_teste"] for p in j["por_arquivo"] if p["arquivo"] in j["arquivos_de_teste"]
        )
        por_classe = inteiros["amostra"]["por_classe"]
        assert por_classe["Benign"]["suporte"] == inteiros["linhas"]
        assert all(me["suporte"] == 0 for classe, me in por_classe.items() if classe != "Benign")
    texto = (treino / "resultados" / RELATORIO).read_text(encoding="utf-8")
    assert "### Nos arquivos inteiros de teste, com janela de 2" in texto
    assert "| BenignTraffic | `BenignTraffic.pcap` e `BenignTraffic1.pcap` | por arquivo: `BenignTraffic1.pcap` inteiro no teste |" in texto
    assert "| Recon-PortScan | `Recon-PortScan.pcap` | por tempo |" in texto


def test_refazer_relatorio_nao_treina(treino, monkeypatch):
    import codigo.classificador.treinar_regerado as modulo

    monkeypatch.setattr(modulo, "treinar", lambda *a, **k: pytest.fail("treinou"))
    antes = (treino / "resultados" / RELATORIO).read_text(encoding="utf-8")
    assert executar(treino, "--refazer-relatorio") == 0
    assert (treino / "resultados" / RELATORIO).read_text(encoding="utf-8") == antes


def test_main_explica_a_falta_do_manifesto_da_regeracao(tmp_path, capsys):
    assert main(["--saida", str(tmp_path), "--modelos", str(tmp_path / "m")]) == 1
    assert MANIFESTO_DA_REGERACAO in capsys.readouterr().err


def test_main_recusa_janela_sem_csv(tmp_path, capsys):
    pasta = preparar_regeracao(tmp_path)
    for caminho in (pasta / "regerado" / "janela_5").glob("*.csv.gz"):
        caminho.unlink()
    assert executar(pasta) == 1
    assert "janela_5" in capsys.readouterr().err


def test_teto_padrao_vale_quando_nao_e_dado(tmp_path):
    pasta = preparar_regeracao(tmp_path)
    assert executar(pasta) == 0
    m = ler_manifesto(pasta)
    assert m["teto"] == TETO and m["janelas"][0]["linhas"]["amostra"] == 320
    assert np.isclose(sum(r["amostra"] for r in m["janelas"][0]["por_rotulo"]), 320)


def test_arquivos_inteiros_no_teste_seguem_o_sufixo_numerico():
    amostra = pd.DataFrame({
        "Label": ["BenignTraffic"] * 3 + ["Recon-PortScan"] + ["DoS-SYN_Flood"] * 2,
        "arquivo": ["BenignTraffic.pcap", "BenignTraffic2.pcap", "BenignTraffic10.pcap", "Recon-PortScan.pcap",
                    "DoS-SYN_Flood.pcap", "DoS-SYN_Flood1.pcap"],
    })
    assert arquivos_inteiros_no_teste(amostra) == ["BenignTraffic10.pcap", "DoS-SYN_Flood1.pcap"]


def test_o_corte_e_sobre_o_total_de_janelas_extraidas_e_nao_sobre_as_mantidas(tmp_path):
    # Recon-PortScan tem 40 janelas mantidas (índices 0 a 39) de 50 extraídas: o corte de 70% fica na
    # janela 35, e vão 5 para o teste. Com o corte nas mantidas, iriam 12 (índices 28 a 39).
    pasta = preparar_regeracao(tmp_path)
    caminho = pasta / "resultados" / MANIFESTO_DA_REGERACAO
    regeracao = json.loads(caminho.read_text(encoding="utf-8"))
    recon = next(p for p in regeracao["pcaps"] if p["arquivo"] == "Recon-PortScan.pcap")
    for contagem in recon["janelas"].values():
        contagem["extraidas"], contagem["descartadas"] = 50, 10
    caminho.write_text(json.dumps(regeracao, ensure_ascii=False), encoding="utf-8")
    assert executar(pasta, "--teto", "1000") == 0
    for j in ler_manifesto(pasta)["janelas"]:
        linha = next(r for r in j["por_rotulo"] if r["rotulo"] == "Recon-PortScan")
        assert (linha["treino"], linha["teste"]) == (35, 5)
        # Os outros pcaps têm 3 janelas descartadas além das 40 mantidas: corte em int(0,7 x 43 + 0,5) = 30.
        outro = next(r for r in j["por_rotulo"] if r["rotulo"] == "Mirai-udpplain")
        assert (outro["treino"], outro["teste"]) == (30, 10)


def janela_de_mentira(contagem, regeradas):
    """O registro de uma janela no manifesto do treino, só com a matriz por rótulo e as linhas regeradas."""
    rotulos = list(contagem)
    return {
        "avaliacao": {"matriz_por_rotulo": {"classes": list(CLASSES), "rotulos": rotulos,
                                            "contagem": [contagem[r] for r in rotulos]}},
        "por_rotulo": [{"rotulo": r, "regeradas": regeradas[r]} for r in rotulos],
    }


def test_reponderada_pesa_cada_rotulo_pelas_janelas_regeradas():
    # Colunas na ordem de CLASSES: DDoS+DoS, Mirai, Recon, Spoofing, Web, BruteForce, Benign.
    j = janela_de_mentira(
        {
            "Recon-PortScan": [0, 0, 8, 0, 0, 0, 2],
            "VulnerabilityScan": [0, 0, 1, 0, 0, 0, 9],
            "BenignTraffic": [0, 0, 1, 0, 0, 0, 9],
        },
        {"Recon-PortScan": 10, "VulnerabilityScan": 100, "BenignTraffic": 10},
    )
    r = reponderada(j)
    # Recon junta dois rótulos: (8 + 10 x 1) / (10 + 100), contra 9 / 20 na mistura do teste.
    assert np.isclose(r["por_classe"]["Recon"]["recall"], 18 / 110)
    # O benigno é um rótulo só: o recall e o benigno classificado como ataque não mudam.
    assert np.isclose(r["por_classe"]["Benign"]["recall"], 0.9)
    assert np.isclose(r["falso_positivo_benigno"], 0.1)
    # Ataque classificado como benigno: das 110 janelas de ataque reponderadas, 2 + 90 viram Benign.
    assert np.isclose(ataque_como_benigno(r), 92 / 110)


def test_relatorio_traz_o_ataque_perdido_com_o_nome_certo_e_as_medidas_reponderadas(treino):
    m = ler_manifesto(treino)
    texto = montar_relatorio(m)
    j = m["janelas"][0]
    a = j["avaliacao"]["amostra"]
    assert "| Categoria | Linhas de teste | Precisão | Recall | F1 | Falso positivo da categoria |" in texto
    assert "Na linha Benign, ele é o ataque classificado como benigno" in texto
    perdido = a["por_classe"]["Benign"]["taxa_falso_positivo"]
    assert ataque_como_benigno(a) == perdido
    assert f"Ataque classificado como benigno: {pct(perdido)}." in texto
    r = reponderada(j)
    assert f"macro-F1 {pct(r['macro_f1'])}" in texto
    assert "| Macro-F1 reponderado |" in texto and "| Ataque classificado como benigno |" in texto
    assert "Recall reponderado" in texto


def test_janela_sem_benigno_no_teste_nao_conta_como_zero(treino):
    m = ler_manifesto(treino)
    m["janelas"][1]["avaliacao"]["amostra"]["falso_positivo_benigno"] = 0.5
    m["janelas"][0]["avaliacao"]["amostra"]["falso_positivo_benigno"] = None
    texto = " ".join(montar_relatorio(m).split())
    # Com o "or 0" antigo, a janela de 2, sem valor, seria a de menor taxa.
    assert "a menor taxa de tráfego benigno classificado como ataque é a da janela de 5" in texto
    m["janelas"][1]["avaliacao"]["amostra"]["falso_positivo_benigno"] = None
    texto = " ".join(montar_relatorio(m).split())
    assert "nenhuma janela tem tráfego benigno no teste" in texto


# --- os resultados versionados ---------------------------------------------------------------

RESULTADOS = Path(__file__).resolve().parents[2] / "experimentos" / "resultados"


@pytest.mark.skipif(not (RESULTADOS / MANIFESTO).exists(), reason="treino regerado ainda não rodado")
def test_resultados_versionados_da_regeracao_saem_do_manifesto():
    m = json.loads((RESULTADOS / MANIFESTO).read_text(encoding="utf-8"))
    assert (RESULTADOS / RELATORIO).read_text(encoding="utf-8") == montar_relatorio(m)
    metricas = {(linha["janela"], linha["regra"], linha["classe"]): linha for linha in ler_csv(RESULTADOS / METRICAS)}
    assert m["fundo_como_benigno"] and [j["janela"] for j in m["janelas"]] == [100]
    for j in m["janelas"]:
        for classe, medida in j["avaliacao"]["amostra"]["por_classe"].items():
            linha = metricas[(str(j["janela"]), "argmax", classe)]
            assert linha["recall"] == ("" if medida["recall"] is None else f"{medida['recall']:.6f}")
            assert int(linha["suporte"]) == medida["suporte"]
        confusao = pd.read_csv(RESULTADOS / "matrizes_confusao" / f"regerado_janela_{j['janela']}_por_rotulo.csv",
                               index_col=0)
        assert confusao.to_numpy().tolist() == j["avaliacao"]["matriz_por_rotulo"]["contagem"]
        por_arquivo = [l for l in ler_csv(RESULTADOS / POR_ARQUIVO) if l["janela"] == str(j["janela"])]
        assert [l["arquivo"] for l in por_arquivo] == [p["arquivo"] for p in j["por_arquivo"]]
        assert sum(int(l["janelas_de_teste"]) for l in por_arquivo) == j["linhas"]["teste"]


def mover_para_o_fundo(pasta, arquivo, indices):
    """Tira janelas mantidas de um pcap e as põe nas descartadas, como janelas sem nenhum quadro do atacante."""
    rotulo = next(r for r, arquivos in ARQUIVOS.items() if arquivo in arquivos)
    for janela in JANELAS:
        pasta_da_janela = pasta / "regerado" / nome_da_pasta(janela)
        caminho = pasta_da_janela / f"{rotulo}.csv.gz"
        quadro = pd.read_csv(caminho, dtype=str)
        sai = (quadro["arquivo"] == arquivo) & quadro["indice"].astype(int).isin(indices)
        fundo = quadro[sai].copy()
        fundo[["atacante", "quadros_atacante", "macs_atacante"]] = "0"
        with gzip.open(caminho, "wt", encoding="utf-8", newline="") as saida:
            quadro[~sai].to_csv(saida, index=False, lineterminator="\n")
        with gzip.open(pasta_da_janela / DESCARTADAS / f"{Path(arquivo).stem}.csv.gz", "at", encoding="utf-8",
                       newline="") as saida:
            fundo.to_csv(saida, index=False, header=False, lineterminator="\n")
    caminho = pasta / "resultados" / MANIFESTO_DA_REGERACAO
    regeracao = json.loads(caminho.read_text(encoding="utf-8"))
    for contagem in next(p for p in regeracao["pcaps"] if p["arquivo"] == arquivo)["janelas"].values():
        contagem["mantidas"] -= len(indices)
        contagem["descartadas"] += len(indices)
    caminho.write_text(json.dumps(regeracao, ensure_ascii=False), encoding="utf-8")


def test_o_fundo_da_parte_de_treino_entra_no_treino_como_benign(tmp_path):
    # Recon-PortScan: 43 janelas extraídas, corte na 30 e validação a partir da 26. As janelas 3, 10 e 20 vão
    # para o treino reduzido e para o inteiro; a 35 é do teste; as 40 a 42 de cada pcap de ataque, também.
    pasta = preparar_regeracao(tmp_path)
    mover_para_o_fundo(pasta, "Recon-PortScan.pcap", [3, 10, 20, 35])
    assert executar(pasta, "--teto", "1000") == 0
    m = ler_manifesto(pasta)
    assert m["fundo_como_benigno"] and m["configuracao"] == "5"
    for j in m["janelas"]:
        assert j["fundo"] == {"descartadas": 7 * 3 + 4, "no_treino": 3, "no_treino_reduzido": 3}
        recon = next(r for r in j["por_rotulo"] if r["rotulo"] == "Recon-PortScan")
        assert (recon["treino"], recon["teste"]) == (27, 9)
        pacote = carregar_modelo(pasta / "modelos" / f"rf_regerado_janela_{j['janela']}.joblib")
        assert pacote["fundo_como_benigno"] and pacote["linhas_de_fundo"] == 3
    # Sem o fundo, nada dele entra, e o treino de referência grava com outro nome.
    assert executar(pasta, "--teto", "1000", "--sem-fundo") == 0
    referencia = json.loads((pasta / "resultados" / MANIFESTO_DE_REFERENCIA).read_text(encoding="utf-8"))
    assert not referencia["fundo_como_benigno"] and all(j["fundo"] is None for j in referencia["janelas"])
    pacote = carregar_modelo(pasta / "modelos" / "rf_regerado_janela_2_sem_fundo.joblib")
    assert not pacote["fundo_como_benigno"] and pacote["linhas_de_fundo"] == 0


def test_o_ponto_de_operacao_sai_da_validacao_e_fica_ao_lado_do_modelo(treino):
    m = ler_manifesto(treino)
    for j in m["janelas"]:
        po = j["ponto_de_operacao"]
        # A validação do pcap benigno de treino: 28 janelas extraídas, de 24 em diante; só a 24 foi mantida.
        assert po["validacao"]["BenignTraffic.pcap"] == [24, 28] and po["janelas_benignas"] == 1
        assert "BenignTraffic1.pcap" not in po["validacao"]
        assert po["validacao"]["Recon-PortScan.pcap"] == [26, 30]
        # As janelas de ataque da validação: as mantidas de cada pcap de ataque, do início da validação ao corte.
        assert po["janelas_de_ataque"] == 7 * 4 and po["seguidas"] == SEGUIDAS
        # A regra vencedora cumpre a meta e reconhece pelo menos tanto ataque quanto o outro candidato.
        meta = 0.01 * po["janelas_benignas"]
        candidatos = {"argmax": po["argmax"]}
        if po["melhor_limiar"] is not None:
            candidatos["limiar"] = po["curva"][str(po["melhor_limiar"])]
        dentro = {regra: c for regra, c in candidatos.items() if c["benigno_como_ataque"] <= meta}
        assert po["regra"] in dentro
        assert dentro[po["regra"]]["ataque_reconhecido"] == max(c["ataque_reconhecido"] for c in dentro.values())
        assert po["limiar"] == (None if po["regra"] == "argmax" else po["melhor_limiar"])
        modelo = treino / "modelos" / f"rf_regerado_janela_{j['janela']}.joblib"
        assert ler(modelo) == PontoDeOperacao(po["limiar"], SEGUIDAS)
        assert ao_lado_do_modelo(modelo).name == po["arquivo"]
        # As regras avaliam as mesmas janelas de teste.
        argmax, limiar = j["avaliacao"]["amostra"]["por_classe"], j["avaliacao_limiar"]["amostra"]["por_classe"]
        assert all(argmax[c]["suporte"] == limiar[c]["suporte"] for c in CLASSES)
    texto = (treino / "resultados" / RELATORIO).read_text(encoding="utf-8")
    assert "### Argmax e limiar, janela de 2" in texto and "Janelas de ataque na validação" in texto
    assert "(ponto de operação)" in texto


def test_o_treino_de_referencia_nao_mexe_no_do_sistema(tmp_path):
    pasta = preparar_regeracao(tmp_path)
    assert executar(pasta, "--teto", "30") == 0
    antes = {caminho.name: caminho.read_bytes() for caminho in (pasta / "resultados").rglob("*") if caminho.is_file()}
    assert executar(pasta, "--teto", "30", "--sem-fundo") == 0
    for nome, conteudo in antes.items():
        assert next((pasta / "resultados").rglob(nome)).read_bytes() == conteudo, nome
    assert (pasta / "resultados" / "regeracao_sem_fundo.md").exists()
    assert (pasta / "resultados" / "matrizes_confusao" / "regerado_janela_5_sem_fundo_limiar.csv").exists()
    assert (pasta / "resultados" / "matrizes_confusao" / "regerado_janela_5_sem_fundo_ponto.csv").exists()
    texto = (pasta / "resultados" / "regeracao_sem_fundo.md").read_text(encoding="utf-8")
    assert texto.startswith("# Treino sobre os dados regerados: referência sem o fundo")
    assert "a janela descartada não vira benigna" in texto
    # Refazer o relatório de referência lê o manifesto dele.
    assert executar(pasta, "--sem-fundo", "--refazer-relatorio") == 0
    assert (pasta / "resultados" / "regeracao_sem_fundo.md").read_text(encoding="utf-8") == texto


def test_o_relatorio_diz_o_que_mudou_em_relacao_ao_modelo_sem_o_fundo(tmp_path):
    pasta = preparar_regeracao(tmp_path)
    assert executar(pasta, "--teto", "30") == 0
    # Um manifesto de antes de 13/10 não diz se o fundo entrou: era o treino sem ele.
    caminho = pasta / "resultados" / MANIFESTO
    antigo = json.loads(caminho.read_text(encoding="utf-8"))
    antigo.pop("fundo_como_benigno")
    antigo["gerado_em"] = "2026-10-10"
    caminho.write_text(json.dumps(antigo, ensure_ascii=False), encoding="utf-8")
    assert executar(pasta, "--teto", "30") == 0
    m = ler_manifesto(pasta)
    assert m["modelo_anterior"]["gerado_em"] == "2026-10-10" and not m["modelo_anterior"]["fundo_como_benigno"]
    texto = (pasta / "resultados" / RELATORIO).read_text(encoding="utf-8")
    assert "## O que mudou em relação ao modelo anterior" in texto and "do treino gravado em 10/10/2026" in texto
    assert pct(antigo["janelas"][1]["avaliacao"]["amostra"]["macro_f1"]) in texto
    # Outra execução com o fundo guarda o mesmo modelo anterior.
    assert executar(pasta, "--teto", "30") == 0
    assert ler_manifesto(pasta)["modelo_anterior"] == m["modelo_anterior"]


def test_janela_que_a_regeracao_nao_tem_e_recusada(tmp_path, capsys):
    pasta = preparar_regeracao(tmp_path)
    assert main(["--saida", str(pasta / "resultados"), "--modelos", str(pasta / "modelos")]) == 1
    assert "janela de 100" in capsys.readouterr().err


def test_as_rodadas_anteriores_ficam_com_o_treino_sem_o_fundo(tmp_path):
    # Antes de 13/10, o manifesto do sistema era o do treino sem o fundo, com as rodadas parciais dele.
    pasta = preparar_regeracao(tmp_path)
    assert executar(pasta, "--teto", "30") == 0
    caminho = pasta / "resultados" / MANIFESTO
    antigo = json.loads(caminho.read_text(encoding="utf-8"))
    antigo.pop("fundo_como_benigno")
    rodada = {"gerado_em": "2026-10-09", "pcaps": 5, "rotulos": ["BenignTraffic"], "rotulos_sem_pcap": 33, "janelas": []}
    antigo["rodadas_anteriores"] = [rodada]
    caminho.write_text(json.dumps(antigo, ensure_ascii=False), encoding="utf-8")
    # O treino de referência herda as rodadas; o do sistema, com o fundo, não as compara com ele.
    assert executar(pasta, "--teto", "30", "--sem-fundo") == 0
    referencia = json.loads((pasta / "resultados" / MANIFESTO_DE_REFERENCIA).read_text(encoding="utf-8"))
    assert referencia["rodadas_anteriores"] == [rodada]
    assert executar(pasta, "--teto", "30") == 0
    m = ler_manifesto(pasta)
    assert m["rodadas_anteriores"] == [] and m["modelo_anterior"] is not None
