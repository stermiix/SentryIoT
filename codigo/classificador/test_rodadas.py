import csv
import gzip
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier

from codigo.captura.extrator import COLUNAS
from codigo.classificador.mapeamento import CATEGORIA_DO_ROTULO
from codigo.classificador.preparar import ALVOS, FEATURES_39, dividir_por_tempo
from codigo.classificador.regerar import CABECALHO, DESCARTADAS, nome_da_pasta
from codigo.classificador.regerar import MANIFESTO as MANIFESTO_DA_REGERACAO
from codigo.classificador.rodadas import (
    ATUAL,
    MANIFESTO,
    MANIFESTO_DAS_CAPTURAS,
    RELATORIO,
    RELATORIO_DAS_CAPTURAS,
    Configuracao,
    Execucao,
    alarmes,
    amostra,
    aplicar_limiar,
    autocorrelacao,
    blocos,
    candidatos_do_limiar,
    de_fora,
    lados,
    ler_dados,
    macro_f1,
    main,
    montar_relatorio,
    montar_relatorio_das_capturas,
    no_teste,
    passa_do_ruido,
    permutacao,
    rodar_capturas,
    wilson,
)
from codigo.classificador.test_atacantes import captura_de_teste
from codigo.classificador.treinar_regerado import ler_janela
from codigo.classificador.treinar_regerado import main as treinar_regerado

RAIZ = Path(__file__).resolve().parents[2]
RESULTADOS = RAIZ / "experimentos" / "resultados"
REGERADO = RAIZ / "dados" / "processed" / "regerado"

# O caso sintético: pcap -> (rótulo, janelas extraídas, índices descartados). Os rótulos com mais de
# um pcap (o benigno e o SYN) exercitam a rotação, e os de um pcap só, o pcap fora do treino.
PCAPS = {
    "BenignTraffic.pcap": ("BenignTraffic", 40, ()),
    "BenignTraffic1.pcap": ("BenignTraffic", 40, ()),
    "BenignTraffic2.pcap": ("BenignTraffic", 40, ()),
    "DDoS-SYN_Flood.pcap": ("DDoS-SYN_Flood", 40, (5, 17)),
    "DDoS-SYN_Flood1.pcap": ("DDoS-SYN_Flood", 40, (33,)),
    "Recon-PortScan.pcap": ("Recon-PortScan", 48, tuple(range(3, 48, 6))),
    "Recon-OSScan.pcap": ("Recon-OSScan", 44, tuple(range(2, 44, 11))),
    "XSS.pcap": ("XSS", 44, (1, 30, 40)),
    "SqlInjection.pcap": ("SqlInjection", 44, (0, 20, 41)),
    "MITM-ArpSpoofing.pcap": ("MITM-ArpSpoofing", 50, tuple(range(0, 50, 5))),
    "DictionaryBruteForce.pcap": ("DictionaryBruteForce", 44, (10, 36)),
    "Mirai-udpplain.pcap": ("Mirai-udpplain", 40, ()),
}
# Tamanho médio do quadro e TTL de cada categoria, para que o modelo tenha o que aprender.
PERFIL = {
    "Benign": (1300.0, 120.0), "DDoS+DoS": (60.0, 64.0), "Recon": (700.0, 90.0), "Web": (1000.0, 100.0),
    "Spoofing": (850.0, 95.0), "BruteForce": (1150.0, 89.0), "Mirai": (560.0, 64.0),
}
FORA = ("Recon-PortScan.pcap", "XSS.pcap", "MITM-ArpSpoofing.pcap", "DictionaryBruteForce.pcap")


def janelas_do_pcap(arquivo, gerador):
    rotulo, extraidas, descartadas = PCAPS[arquivo]
    categoria = ALVOS["7"].classe_do_rotulo[rotulo]
    tamanho, ttl = PERFIL[categoria]
    quadro = pd.DataFrame(1.0, index=range(extraidas), columns=list(COLUNAS))
    quadro["Tot size"] = tamanho + gerador.normal(0, 40, extraidas)
    quadro["Time_To_Live"] = ttl + gerador.normal(0, 3, extraidas)
    quadro["Min"] = 42.0 if categoria == "Spoofing" else 60.0
    quadro["Max"] = 4000.0 if categoria == "Benign" else 1500.0
    quadro["Number"], quadro["Rate"] = 100.0, 50.0 + gerador.uniform(0, 10, extraidas)
    quadro["Label"], quadro["arquivo"], quadro["indice"] = rotulo, arquivo, range(extraidas)
    quadro["ips_origem"], quadro["ips_destino"] = 2, 1
    mantida = ~quadro["indice"].isin(descartadas)
    quadro["atacante"] = (mantida & (categoria != "Benign")).astype(int)
    quadro["quadros_atacante"] = np.where(quadro["atacante"] == 1, 1 + quadro["indice"] % 7, 0)
    quadro["macs_atacante"] = quadro["atacante"]
    # O fundo de um pcap de ataque se parece com o tráfego benigno.
    quadro.loc[~mantida, "Tot size"] = PERFIL["Benign"][0] + gerador.normal(0, 40, int((~mantida).sum()))
    return quadro[list(CABECALHO)], mantida.to_numpy()


def preparar_regerado(pasta, gerador=None):
    """Uma pasta de dados regerados de janela de 100 e o manifesto da regeração, como o regerar deixa."""
    gerador = gerador or np.random.default_rng(0)
    destino = pasta / "regerado"
    janela = destino / nome_da_pasta(100)
    (janela / DESCARTADAS).mkdir(parents=True)
    por_rotulo, registros = {}, []
    for arquivo in sorted(PCAPS):
        quadro, mantida = janelas_do_pcap(arquivo, gerador)
        por_rotulo.setdefault(quadro["Label"].iloc[0], []).append(quadro[mantida])
        with gzip.open(janela / DESCARTADAS / f"{Path(arquivo).stem}.csv.gz", "wt", encoding="utf-8", newline="") as saida:
            quadro[~mantida].to_csv(saida, index=False, header=False, lineterminator="\n")
        rotulo, extraidas, _ = PCAPS[arquivo]
        registros.append({
            "arquivo": arquivo, "rotulo": rotulo, "categoria": CATEGORIA_DO_ROTULO[rotulo],
            "benigno": rotulo == "BenignTraffic", "pacotes": extraidas * 100, "segundos": 0.1,
            "janelas": {"100": {"extraidas": extraidas, "mantidas": int(mantida.sum()),
                                "descartadas": int((~mantida).sum()), "com_atacante": int(mantida.sum()),
                                "incompletas": 0}},
        })
    for rotulo, partes in por_rotulo.items():
        with gzip.open(janela / f"{rotulo}.csv.gz", "wt", encoding="utf-8", newline="") as saida:
            pd.concat(partes).to_csv(saida, index=False, lineterminator="\n")
    manifesto = {
        "gerado_em": "2026-10-11", "dataset": "CICIoT2023", "destino": str(destino), "janelas": [100],
        "regra": "a de regerar", "extrator": {"sha256": "0" * 64, "opcoes": {}},
        "pcaps": registros,
        "rotulos": [
            {"rotulo": rotulo, "categoria": CATEGORIA_DO_ROTULO[rotulo],
             "arquivos": sorted(a for a, (r, _, _) in PCAPS.items() if r == rotulo),
             "linhas": {"100": sum(len(p) for p in partes)}}
            for rotulo, partes in sorted(por_rotulo.items())
        ],
    }
    resultados = pasta / "resultados"
    resultados.mkdir(parents=True, exist_ok=True)
    (resultados / MANIFESTO_DA_REGERACAO).write_text(json.dumps(manifesto, ensure_ascii=False), encoding="utf-8")
    return manifesto


@pytest.fixture(scope="module")
def caso(tmp_path_factory):
    """O caso sintético, o modelo salvo pelo treino regerado e as rodadas do modelo do sistema."""
    pasta = tmp_path_factory.mktemp("rodadas")
    preparar_regerado(pasta)
    assert treinar_regerado([
        "--saida", str(pasta / "resultados"), "--modelos", str(pasta / "modelos"), "--arvores", "5", "--nucleos", "1",
        "--teto", "30",
    ]) == 0
    (pasta / "dataset").mkdir()
    captura_de_teste(pasta / "dataset" / "Recon-PortScan.pcap")
    assert executar(pasta) == 0
    return pasta


def executar(pasta, *extras):
    import codigo.classificador.rodadas as modulo

    original = modulo.PCAPS_FORA
    modulo.PCAPS_FORA = FORA
    try:
        return main([
            "--saida", str(pasta / "resultados"), "--trabalho", str(pasta / "trabalho"),
            "--manifesto-da-regeracao", str(pasta / "resultados" / MANIFESTO_DA_REGERACAO),
            "--modelo", str(pasta / "modelos" / "rf_regerado_janela_100.joblib"), "--dataset", str(pasta / "dataset"),
            "--sementes", "42,1,2", "--arvores", "5", "--teto", "30", "--nucleos", "1", *extras,
        ])
    finally:
        modulo.PCAPS_FORA = original


def ler_manifesto(pasta, nome=MANIFESTO):
    return json.loads((pasta / "resultados" / nome).read_text(encoding="utf-8"))


# --- os dados e a divisão --------------------------------------------------------------------


def test_amostra_sorteia_as_mesmas_linhas_que_ler_janela_na_mesma_ordem(tmp_path):
    regeracao = preparar_regerado(tmp_path)
    dados = ler_dados(regeracao["destino"], regeracao)
    for semente, teto in ((42, 30), (7, 30), (42, 1000)):
        quadro, _ = ler_janela(regeracao["destino"], 100, teto, semente)
        posicoes = amostra(dados, semente, teto)
        meta = dados.meta.iloc[posicoes]
        assert meta["arquivo"].tolist() == quadro["arquivo"].tolist()
        assert meta["indice"].tolist() == quadro["indice"].tolist()
        assert np.array_equal(dados.X[posicoes][:, FEATURES_39.index("Tot size")], quadro["Tot size"].to_numpy(np.float32))


def test_ler_dados_traz_as_descartadas_e_o_hash_de_cada_arquivo(tmp_path):
    regeracao = preparar_regerado(tmp_path)
    dados = ler_dados(regeracao["destino"], regeracao)
    assert len(dados.meta) == sum(p["janelas"]["100"]["mantidas"] for p in regeracao["pcaps"])
    assert len(dados.fundo_meta) == sum(p["janelas"]["100"]["descartadas"] for p in regeracao["pcaps"])
    assert (dados.fundo_meta["atacante"] == 0).all()
    _, meta = dados.do_pcap("Recon-PortScan.pcap", fundo=True)
    assert meta["indice"].tolist() == list(range(3, 48, 6))
    assert len(dados.entradas) == 9 + len(PCAPS)  # os CSVs dos 9 rótulos e uma parte de descartadas por pcap
    assert all(len(sha) == 64 for sha in dados.entradas.values())
    assert dados.totais["Recon-PortScan.pcap"] == 48


def test_a_divisao_da_rotacao_0_e_a_do_repositorio(tmp_path):
    regeracao = preparar_regerado(tmp_path)
    dados = ler_dados(regeracao["destino"], regeracao)
    posicoes = amostra(dados, 42, 30)
    meta = dados.meta.iloc[posicoes].reset_index(drop=True)
    _, teste = dividir_por_tempo(meta, janelas_por_arquivo=dados.totais)
    assert np.array_equal(np.flatnonzero(no_teste(meta, lados(regeracao, 0))), teste)
    assert de_fora(lados(regeracao, 0)) == ["BenignTraffic2.pcap", "DDoS-SYN_Flood1.pcap"]
    # O corte é no total de janelas extraídas: 70% de 48 é a janela 34.
    assert lados(regeracao, 0)["Recon-PortScan.pcap"] == 34


def test_a_rotacao_tira_cada_pcap_dos_rotulos_de_varios_pcaps_uma_vez(tmp_path):
    regeracao = preparar_regerado(tmp_path)
    benignos = [fora for r in range(3) for fora in de_fora(lados(regeracao, r)) if fora.startswith("Benign")]
    assert benignos == ["BenignTraffic2.pcap", "BenignTraffic.pcap", "BenignTraffic1.pcap"]
    assert de_fora(lados(regeracao, 1)) == ["BenignTraffic.pcap", "DDoS-SYN_Flood.pcap"]
    assert lados(regeracao, 1)["BenignTraffic2.pcap"] == "treino"


# --- as medidas ------------------------------------------------------------------------------


def test_aplicar_limiar_decide_pela_probabilidade_de_benigno():
    classes = ["Benign", "DDoS+DoS", "Recon"]
    proba = np.array([[0.40, 0.35, 0.25], [0.90, 0.02, 0.08], [0.20, 0.30, 0.50]])
    # Com 0,5, a primeira vira ataque (1 - 0,40 = 0,60), na categoria de ataque mais provável.
    assert aplicar_limiar(proba, classes, 0.5).tolist() == ["DDoS+DoS", "Benign", "Recon"]
    assert aplicar_limiar(proba, classes, 0.7).tolist() == ["Benign", "Benign", "Recon"]
    # O limiar é inclusivo, mesmo com o arredondamento do ponto flutuante.
    assert aplicar_limiar(np.array([[0.4, 0.6, 0.0]]), classes, 0.6).tolist() == ["DDoS+DoS"]


def test_alarmes_disparam_na_n_esima_janela_seguida_uma_vez_por_sequencia():
    sequencia = [1, 1, 0, 1, 1, 1, 1, 0, 1]
    assert alarmes(sequencia, 1) == [0, 3, 8]
    assert alarmes(sequencia, 2) == [1, 4]
    assert alarmes(sequencia, 3) == [5]
    assert alarmes(sequencia, 5) == []


def test_wilson_e_os_blocos():
    assert wilson(0, 0) == (None, None)
    baixo, alto = wilson(5, 10)
    assert np.isclose(baixo + alto, 1.0) and 0.23 < baixo < 0.24
    assert wilson(10, 10)[1] == pytest.approx(1.0) and wilson(0, 10)[0] == pytest.approx(0.0)
    # Acerto todo igual dá intervalo de um ponto; a mesma semente dá o mesmo intervalo.
    assert blocos(np.ones(40), ["a"] * 40, semente=1, reamostragens=200) == (1.0, 1.0)
    acerto = np.r_[np.ones(20), np.zeros(20)]
    assert blocos(acerto, ["a"] * 40, 3, 300) == blocos(acerto, ["a"] * 40, 3, 300)
    # Com acertos em sequência, os blocos dão um intervalo mais largo que o de Wilson.
    bloco = blocos(acerto, ["a"] * 40, 3, 2000, bloco=10)
    assert bloco[1] - bloco[0] > wilson(20, 40)[1] - wilson(20, 40)[0]


def test_autocorrelacao_e_tamanho_efetivo():
    r, efetivo = autocorrelacao(np.r_[np.ones(10), np.zeros(10)], ["a"] * 20)
    assert r > 0.8 and efetivo < 2
    r, efetivo = autocorrelacao([1, 0] * 10, ["a"] * 20)
    assert r == pytest.approx(-1.0) and efetivo is None
    # Cada pcap conta separado: a troca de pcap não é vizinhança.
    r, _ = autocorrelacao([1, 1, 1, 0, 0, 0], ["a", "a", "a", "b", "b", "b"])
    assert r == pytest.approx(1.0)
    assert autocorrelacao([1, 1, 1, 0, 0, 0], ["a"] * 6)[0] < 0.7


def test_permutacao_derruba_o_recall_so_na_feature_que_separa():
    gerador = np.random.default_rng(0)
    X = gerador.normal(0, 1, (400, 3)).astype(np.float32)
    y = np.where(X[:, 0] > 0, "Web", "Benign").astype(object)
    modelo = RandomForestClassifier(n_estimators=10, random_state=0).fit(X, y)
    registro = permutacao(modelo, X, y, "Web", ["a", "b", "c"], np.random.default_rng(1), repeticoes=3)
    assert registro["base"] == 1.0 and registro["janelas"] == int((y == "Web").sum())
    assert registro["quedas"]["a"][0] > 0.3
    assert abs(registro["quedas"]["b"][0]) < 0.05 and abs(registro["quedas"]["c"][0]) < 0.05


def test_macro_f1_e_o_ruido_entre_sementes():
    y = np.array(["A", "A", "B", "B"], dtype=object)
    assert macro_f1(y, y) == 1.0
    assert macro_f1(y, np.array(["A", "A", "A", "A"], dtype=object)) == pytest.approx((2 / 3 + 0) / 2)
    assert passa_do_ruido([0.80, 0.81, 0.82], [0.83, 0.84])
    assert not passa_do_ruido([0.80, 0.83], [0.82, 0.84])
    assert not passa_do_ruido([], [0.5])


def test_candidatos_do_limiar_sao_os_menores_limiares_dentro_de_cada_alvo():
    curva = [
        {"limiar": "argmax", "benigno_como_ataque": 0.019},
        {"limiar": 0.5, "benigno_como_ataque": 0.04},
        {"limiar": 0.6, "benigno_como_ataque": 0.019},
        {"limiar": 0.7, "benigno_como_ataque": 0.009},
        {"limiar": 0.8, "benigno_como_ataque": 0.004},
    ]
    escolhidos = candidatos_do_limiar(curva, (0.02, 0.01, 0.005, 0.001))
    assert [(alvo_, linha["limiar"]) for alvo_, linha in escolhidos] == [(0.02, 0.6), (0.01, 0.7), (0.005, 0.8)]
    # O mesmo limiar que atende dois alvos aparece uma vez só.
    assert [linha["limiar"] for _, linha in candidatos_do_limiar(curva[:3] + curva[4:], (0.02, 0.01, 0.005))] == [0.6, 0.8]


# --- as rodadas do modelo do sistema, de ponta a ponta ----------------------------------------


def test_rodadas_gravam_manifesto_relatorio_e_tabelas(caso):
    m = ler_manifesto(caso)
    r = m["resultados"]
    assert r["rodadas"] == list("abcdefghi")
    assert list(r["corte"]) == ["42", "1", "2"]
    assert set(r["rotacao"]) == {"1", "2"} and set(r["rotacao"]["1"]) == {"42", "1", "2"}
    assert set(r["fora"]) == set(FORA) and set(r["sem_ttl"]) == {"42", "1", "2"}
    assert m["entradas"]["modelo"]["arquivo"] == "rf_regerado_janela_100.joblib"
    assert len(m["entradas"]["arquivos"]) == 9 + len(PCAPS)
    relatorio = (caso / "resultados" / RELATORIO).read_text(encoding="utf-8")
    assert relatorio == montar_relatorio(m)
    for secao in ("## Resumo", "## a. Reprodução do modelo publicado", "## b. Sementes", "## c. Rotação",
                  "## d. Tráfego de fundo", "## e. Pcap inteiro fora do treino", "## f. Atalhos da captura",
                  "## g. Ponto de operação", "## h. Intervalos de confiança", "## i. Custo",
                  "## Como os números foram obtidos"):
        assert secao in relatorio, secao
    for tabela in ("corte", "rotacao", "fundo", "pcap_fora", "limiar", "permutacao", "intervalos"):
        assert (caso / "resultados" / f"rodadas_{tabela}.csv").exists(), tabela


def test_reproducao_confere_o_modelo_salvo_com_o_retreino(caso):
    reproducao = ler_manifesto(caso)["resultados"]["corte"]["42"]["detalhe"]["reproducao"]
    assert reproducao["predicoes_diferentes_do_retreino"] == 0
    assert reproducao["medidas_diferentes"] == [] and reproducao["matriz_por_rotulo_igual"]
    assert all(reproducao["divisao_igual"].values())
    publicado = json.loads((caso / "resultados" / "manifesto_treino_regerado.json").read_text(encoding="utf-8"))
    assert reproducao["linhas"]["teste"] == publicado["janelas"][0]["linhas"]["teste"]


def test_rotacao_mede_cada_pcap_benigno_de_fora_inteiro(caso):
    r = ler_manifesto(caso)["resultados"]
    por_rotacao = {
        rotacao: next(p for p in por_semente["42"]["de_fora"] if p["categoria"] == "Benign")
        for rotacao, por_semente in [("0", r["corte"]), *r["rotacao"].items()]
    }
    assert {p["arquivo"] for p in por_rotacao.values()} == {"BenignTraffic.pcap", "BenignTraffic1.pcap",
                                                            "BenignTraffic2.pcap"}
    assert all(p["janelas"] == 40 and sum(p["previstas"].values()) == 40 for p in por_rotacao.values())


def test_fundo_separa_a_parte_de_treino_e_a_de_teste_pelo_mesmo_corte(caso):
    fundo = {p["arquivo"]: p for p in ler_manifesto(caso)["resultados"]["corte"]["42"]["fundo"]}
    # Recon-PortScan: descartadas nos índices 3, 9, ..., 45; corte na janela 34.
    recon = fundo["Recon-PortScan.pcap"]
    assert (recon["treino"]["janelas"], recon["teste"]["janelas"]) == (6, 2)
    # DDoS-SYN_Flood1 é o pcap de fora: todo o fundo dele é teste; o do outro SYN, todo treino.
    assert fundo["DDoS-SYN_Flood1.pcap"]["treino"]["janelas"] == 0 and fundo["DDoS-SYN_Flood1.pcap"]["teste"]["janelas"] == 1
    assert fundo["DDoS-SYN_Flood.pcap"]["teste"]["janelas"] == 0
    assert "BenignTraffic.pcap" not in fundo


def test_relatorio_mede_cada_semente_nas_janelas_dela(caso):
    # Recon-PortScan passa do teto: cada semente sorteia outras janelas de teste, e nenhuma fração passa de 100%.
    texto = (caso / "resultados" / RELATORIO).read_text(encoding="utf-8")
    linha = next(l for l in texto.splitlines() if l.startswith("| `Recon-PortScan.pcap` | Recon |"))
    valores = [float(v.replace(",", ".")) for v in re.findall(r"(\d+,\d+)%", linha)]
    assert valores and max(valores) <= 100.0


def test_pcap_fora_mede_as_janelas_de_teste_e_o_pcap_inteiro(caso):
    r = ler_manifesto(caso)["resultados"]
    xss = r["fora"]["XSS.pcap"]["42"]
    dentro = r["corte"]["42"]["por_pcap"]["XSS.pcap"]
    assert xss["teste"]["janelas"] == dentro["janelas"] > 0
    assert xss["inteiro"]["janelas"] == 41 and xss["categoria"] == "Web"
    # Sem o único pcap de BruteForce, a categoria some do treino e nenhuma janela vai para ela.
    assert r["fora"]["DictionaryBruteForce.pcap"]["42"]["teste"]["previstas"]["BruteForce"] == 0


def test_execucao_interrompida_continua_sem_treinar_de_novo(caso, monkeypatch):
    import codigo.classificador.rodadas as modulo

    antes = ler_manifesto(caso)
    monkeypatch.setattr(modulo, "treinar", lambda *a, **k: pytest.fail("treinou de novo"))
    assert executar(caso) == 0
    depois = ler_manifesto(caso)
    assert depois["resultados"]["corte"] == antes["resultados"]["corte"]
    # Refazer o relatório não lê os dados nem treina.
    monkeypatch.setattr(modulo, "ler_dados", lambda *a, **k: pytest.fail("leu os dados"))
    assert executar(caso, "--refazer-relatorio") == 0


def test_rodadas_pedidas_sem_o_modelo_salvo_sao_recusadas(caso, capsys):
    assert main(["--saida", str(caso / "resultados"), "--manifesto-da-regeracao",
                 str(caso / "resultados" / MANIFESTO_DA_REGERACAO), "--modelo", str(caso / "nao_existe.joblib"),
                 "--rodadas", "a"]) == 1
    assert "nao_existe.joblib" in capsys.readouterr().err
    assert main(["--rodadas", "z"]) == 2


# --- a comparação de capturas ----------------------------------------------------------------


def test_comparacao_de_capturas_com_o_fundo_no_treino_e_sem_ttl(tmp_path, monkeypatch):
    import codigo.classificador.rodadas as modulo

    regeracao = preparar_regerado(tmp_path)
    caminho = str(tmp_path / "resultados" / MANIFESTO_DA_REGERACAO)
    configuracoes = (
        Configuracao("0", "o modelo atual", regeracao["destino"], caminho),
        Configuracao("3", "sem TTL", regeracao["destino"], caminho, sem=("Time_To_Live",)),
        Configuracao("4", "fundo como benigno", regeracao["destino"], caminho, fundo_como_benigno=True),
    )
    monkeypatch.setattr(modulo, "CONFIGURACOES", configuracoes)
    monkeypatch.setattr(modulo, "PCAPS_FORA", FORA)
    assert main(["--capturas", "--saida", str(tmp_path / "resultados"), "--trabalho", str(tmp_path / "trabalho"),
                 "--sementes", "42,1,2", "--arvores", "3", "--teto", "30", "--nucleos", "1"]) == 0
    m = ler_manifesto(tmp_path, MANIFESTO_DAS_CAPTURAS)
    assert list(m["resultados"]) == ["0", "3", "4"]
    assert list(m["entradas"]["pastas"]) == [regeracao["destino"]]
    texto = (tmp_path / "resultados" / RELATORIO_DAS_CAPTURAS).read_text(encoding="utf-8")
    assert texto == montar_relatorio_das_capturas(m)
    for secao in ("## Tabela-resumo", "## Quais diferenças passam do ruído", "## Corte por tempo",
                  "## c. Rotação do pcap benigno de fora", "## d. Tráfego de fundo", "## e. Pcap fora do treino"):
        assert secao in texto, secao
    with open(tmp_path / "resultados" / "rodadas_normalizadas_resumo.csv", encoding="utf-8", newline="") as arquivo:
        resumo = list(csv.DictReader(arquivo))
    assert {linha["configuracao"] for linha in resumo} == {"0", "3", "4"}


def test_o_fundo_entra_no_treino_como_benigno_so_na_parte_de_treino(tmp_path):
    regeracao = preparar_regerado(tmp_path)
    dados = ler_dados(regeracao["destino"], regeracao)
    caminho = str(tmp_path / "resultados" / MANIFESTO_DA_REGERACAO)
    com = Execucao(Configuracao("4", "fundo", regeracao["destino"], caminho, fundo_como_benigno=True), dados,
                   trabalho=tmp_path / "t")
    sem = Execucao(ATUAL, dados, trabalho=tmp_path / "t")
    posicoes = amostra(dados, 42, 30)
    lados_da_divisao = lados(regeracao, 0)
    teste = no_teste(dados.meta.iloc[posicoes], lados_da_divisao)
    _, y_com = com._treino(posicoes, teste, lados_da_divisao)
    _, y_sem = sem._treino(posicoes, teste, lados_da_divisao)
    fundo_de_treino = int((~no_teste(dados.fundo_meta, lados_da_divisao)).sum())
    assert len(y_com) - len(y_sem) == fundo_de_treino
    assert (y_com[len(y_sem):] == "Benign").all()
    # Com o pcap fora, o fundo dele também sai.
    _, y_fora = com._treino(posicoes, teste, lados_da_divisao, sem_pcap="MITM-ArpSpoofing.pcap")
    _, meta_mitm = dados.do_pcap("MITM-ArpSpoofing.pcap", fundo=True)
    mitm_de_treino = int((~no_teste(meta_mitm, lados_da_divisao)).sum())
    mitm_na_amostra = int(((dados.meta.iloc[posicoes]["arquivo"] == "MITM-ArpSpoofing.pcap").to_numpy() & ~teste).sum())
    assert len(y_com) - len(y_fora) == mitm_de_treino + mitm_na_amostra


def test_configuracao_que_pede_opcao_que_a_regeracao_nao_registra_e_recusada(tmp_path):
    regeracao = preparar_regerado(tmp_path)
    caminho = str(tmp_path / "resultados" / MANIFESTO_DA_REGERACAO)
    pedida = Configuracao("2", "no fio", regeracao["destino"], caminho, opcoes=(("limitar", True), ("preencher", True)))
    with pytest.raises(ValueError, match="opções"):
        rodar_capturas((pedida,), sementes=(42,), arvores=2, nucleos=1, teto=30, trabalho=tmp_path / "t", pcaps_fora=())


# --- os resultados versionados e os dados reais -----------------------------------------------


@pytest.mark.skipif(not (RESULTADOS / MANIFESTO).exists(), reason="rodadas ainda não rodadas")
def test_relatorio_das_rodadas_versionado_sai_do_manifesto():
    m = json.loads((RESULTADOS / MANIFESTO).read_text(encoding="utf-8"))
    assert (RESULTADOS / RELATORIO).read_text(encoding="utf-8") == montar_relatorio(m)
    reproducao = m["resultados"]["corte"]["42"]["detalhe"]["reproducao"]
    assert reproducao["predicoes_diferentes_do_retreino"] == 0 and reproducao["medidas_diferentes"] == []
    regeracao = json.loads((RESULTADOS / MANIFESTO_DA_REGERACAO).read_text(encoding="utf-8"))
    assert m["entradas"]["regeracao"]["extraidas"] == {
        p["arquivo"]: p["janelas"]["100"]["extraidas"] for p in regeracao["pcaps"]
    }


@pytest.mark.skipif(not (RESULTADOS / MANIFESTO_DAS_CAPTURAS).exists(), reason="comparação ainda não rodada")
def test_relatorio_das_capturas_versionado_sai_do_manifesto():
    m = json.loads((RESULTADOS / MANIFESTO_DAS_CAPTURAS).read_text(encoding="utf-8"))
    assert (RESULTADOS / RELATORIO_DAS_CAPTURAS).read_text(encoding="utf-8") == montar_relatorio_das_capturas(m)
    assert list(m["resultados"]) == ["0", "1", "2", "3", "4"]


@pytest.mark.skipif(
    not (REGERADO / nome_da_pasta(100) / DESCARTADAS / "Recon-PortScan.csv.gz").exists(),
    reason="dados regerados com as janelas descartadas ausentes",
)
def test_mantidas_e_descartadas_do_portscan_real_cobrem_todas_as_janelas_extraidas():
    regeracao = json.loads((RESULTADOS / MANIFESTO_DA_REGERACAO).read_text(encoding="utf-8"))
    registro = next(p for p in regeracao["pcaps"] if p["arquivo"] == "Recon-PortScan.pcap")["janelas"]["100"]
    pasta = REGERADO / nome_da_pasta(100)
    mantidas, descartadas = (
        pd.read_csv(pasta / subpasta / "Recon-PortScan.csv.gz", header=None, names=list(CABECALHO),
                    usecols=["indice", "atacante", "quadros_atacante"])
        for subpasta in ("partes", DESCARTADAS)
    )
    assert (len(mantidas), len(descartadas)) == (registro["mantidas"], registro["descartadas"])
    assert sorted([*mantidas["indice"], *descartadas["indice"]]) == list(range(registro["extraidas"]))
    assert (mantidas["quadros_atacante"] > 0).all() and (descartadas["quadros_atacante"] == 0).all()
