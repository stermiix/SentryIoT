import csv
import gzip
import json

import numpy as np
import pandas as pd
import pytest

from codigo.captura.extrator import COLUNAS
from codigo.classificador.mapeamento import CATEGORIA_DO_ROTULO, ROTULOS
from codigo.classificador.preparar import ALVOS
from codigo.classificador.regerar import CABECALHO, nome_da_pasta
from codigo.classificador.regerar import MANIFESTO as MANIFESTO_DA_REGERACAO
from codigo.classificador.regerar import montar_manifesto as manifesto_da_regeracao
from codigo.classificador.test_janela import sem_variaveis
from codigo.classificador.test_preparar import quadro_sintetico
from codigo.classificador.treinar import carregar_modelo
from codigo.classificador.treinar_regerado import (
    ALVO,
    MANIFESTO,
    METRICAS,
    POR_ARQUIVO,
    RELATORIO,
    TETO,
    ips_de_origem,
    ler_janela,
    limitar,
    main,
    montar_relatorio,
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
    return quadro[list(CABECALHO)]


def preparar_regeracao(pasta):
    """A pasta dos dados regerados e o manifesto da regeração, como o regerar.py os deixa."""
    destino = pasta / "regerado"
    quadro = quadro_regerado()
    for janela in JANELAS:
        pasta_da_janela = destino / nome_da_pasta(janela)
        pasta_da_janela.mkdir(parents=True)
        for rotulo, parte in quadro.groupby("Label", sort=False):
            parte = parte.copy()
            parte["Number"] = float(janela)
            with gzip.open(pasta_da_janela / f"{rotulo}.csv.gz", "wt", encoding="utf-8", newline="") as arquivo:
                parte.to_csv(arquivo, index=False, lineterminator="\n")
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
        *extras,
    ])


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
    assert len(metricas) == 2 * 7
    assert {l["janela"] for l in metricas} == {"2", "5"}
    recon = next(l for l in metricas if l["janela"] == "2" and l["classe"] == "Recon")
    assert set(recon) == {"janela", "classe", "precisao", "recall", "f1", "suporte", "taxa_falso_positivo"}
    assert 0 <= float(recon["recall"]) <= 1
    web = next(l for l in metricas if l["janela"] == "2" and l["classe"] == "Web")
    assert web["suporte"] == "0" and web["recall"] == ""
    por_arquivo = ler_csv(resultados / POR_ARQUIVO)
    assert len(por_arquivo) == 2 * 9
    assert set(por_arquivo[0]) >= {"janela", "arquivo", "rotulo", "categoria_esperada", "janelas_de_teste", "na_esperada"}
    for janela in JANELAS:
        confusao = pd.read_csv(resultados / "matrizes_confusao" / f"regerado_janela_{janela}.csv", index_col=0)
        assert list(confusao.index) == list(ALVOS[ALVO].classes) == list(confusao.columns)
        por_rotulo = pd.read_csv(resultados / "matrizes_confusao" / f"regerado_janela_{janela}_por_rotulo.csv", index_col=0)
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
    # A rodada anterior fica registrada como referência; fora isso, nada muda.
    assert len(depois["rodadas_anteriores"]) == len(antes["rodadas_anteriores"]) + 1
    resumo = depois["rodadas_anteriores"][-1]
    assert resumo["pcaps"] == 9 and len(resumo["rotulos"]) == 8 and resumo["rotulos_sem_pcap"] == 26
    assert resumo["janelas"][0]["macro_f1"] == antes["janelas"][0]["avaliacao"]["amostra"]["macro_f1"]
    assert set(resumo["janelas"][0]["por_classe"]) == set(ALVOS[ALVO].classes)
    rodadas = len(depois["rodadas_anteriores"])
    depois.pop("rodadas_anteriores"), antes.pop("rodadas_anteriores")
    assert sem_variaveis(depois) == sem_variaveis(antes)
    texto = (treino / "resultados" / RELATORIO).read_text(encoding="utf-8")
    assert "## Rodadas anteriores, como referência" in texto
    assert "Nenhum rótulo entrou" in texto and "Pcaps: de 9 para 9" in texto
    # Refazer o relatório não acrescenta rodada.
    assert executar(treino, "--refazer-relatorio") == 0
    assert len(ler_manifesto(treino)["rodadas_anteriores"]) == rodadas


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
