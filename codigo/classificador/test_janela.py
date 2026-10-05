import csv
import hashlib
import io
import json
import random
import re
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from codigo.captura.extrator import COLUNAS, extrair, gravar_csv, ler_pcap
from codigo.captura.test_extrator import QUADRO_IPV6, pcap, quadro_tcp
from codigo.classificador import janela as teste_da_janela
from codigo.classificador.avaliar import avaliar
from codigo.classificador.avaliar import main as avaliar_modelo
from codigo.classificador.experimento import Execucao, pesos_de_treino
from codigo.classificador.janela import (
    ALVO,
    CAPTURAS,
    DIVISAO,
    JANELAS,
    MANIFESTO,
    MODELOS,
    RELATORIO,
    SEPARACAO_SEM_AS_SEIS_COLUNAS,
    TABELA,
    Captura,
    extrair_captura,
    iguais_ao_treino,
    main,
    montar_relatorio,
    pontuar,
    resumo_do_arquivo,
    rodar,
)
from codigo.classificador.preparar import (
    ALVOS,
    CONJUNTOS_DE_FEATURES,
    FEATURES_33,
    FEATURES_39,
    FUSAO,
    alvo,
    carregar,
    dividir,
    impressao_digital,
    matriz,
)
from codigo.classificador.test_experimento import POPULACAO, preparar_entrada
from codigo.classificador.test_preparar import quadro_sintetico
from codigo.classificador.treinar import main as treinar_modelo
from codigo.classificador.treinar import prever, treinar

RAIZ = Path(__file__).resolve().parents[2]
RESULTADOS = RAIZ / "experimentos" / "resultados"
DATASET = RAIZ / "CICIoT2023"
# O que muda de uma execução para outra sem que os resultados mudem: a data e as medidas de tempo.
VARIAVEIS = ("gerado_em",)
CLASSES = list(ALVOS[ALVO].classes)
# Tamanho dos quadros de cada captura de mentira: cai na faixa de tamanho médio que a amostra
# sintética dá à categoria esperada (`test_preparar.CLASSES_DO_CASO`).
TAMANHO_DO_QUADRO = {
    "DDoS-HTTP_Flood-.pcap": 80,
    "DoS-HTTP_Flood1.pcap": 90,
    "Mirai-greip_flood21.pcap": 580,
    "Recon-PortScan.pcap": 720,
    "DictionaryBruteForce.pcap": 1170,
}
QUADROS_POR_CAPTURA = 230


def quadro_de(tamanho):
    """Um quadro TCP com o tamanho pedido, em bytes."""
    vazio = len(quadro_tcp())
    return quadro_tcp(dados=b"x" * (tamanho - vazio))


def gravar_pcap(caminho, tamanho, quadros=QUADROS_POR_CAPTURA, estranhos=7):
    """Captura de mentira: quadros TCP de tamanhos próximos de `tamanho` e alguns quadros IPv6 no meio.

    Os quadros IPv6 não entram em janela nenhuma, como no extrator. O tamanho e o intervalo entre
    os quadros saem de um sorteio com semente fixa, para que duas janelas não tenham as mesmas
    features e o arquivo seja o mesmo a cada vez.
    """
    sorteio = random.Random(tamanho)
    registros = []
    for i in range(quadros):
        instante = (1 + i // 50, (i % 50) * 20_000 + sorteio.randrange(900))
        registros.append((*instante, quadro_de(tamanho + sorteio.randrange(40))))
        if i < estranhos:
            registros.append((*instante, QUADRO_IPV6))
    caminho.write_bytes(pcap(registros))
    return caminho


def preparar_dataset(pasta):
    """Pasta de dataset de mentira, com os cinco pcaps que o teste da janela lê."""
    pasta.mkdir(parents=True, exist_ok=True)
    for arquivo, tamanho in TAMANHO_DO_QUADRO.items():
        gravar_pcap(pasta / arquivo, tamanho)
    return pasta


def executar(pasta, *extras, saida=None):
    return main([
        "--amostra", str(pasta / "amostra.csv.gz"), "--manifesto-da-amostra", str(pasta / "manifesto_amostra.json"),
        "--dataset", str(pasta / "dataset"), "--saida", str(saida or pasta / "resultados"), "--arvores", "5",
        "--nucleos", "1", *extras,
    ])


def ler_manifesto(pasta):
    return json.loads((pasta / MANIFESTO).read_text(encoding="utf-8"))


def ler_tabela(pasta):
    with open(pasta / TABELA, encoding="utf-8", newline="") as arquivo:
        return list(csv.DictReader(arquivo))


def sem_variaveis(valor):
    """O mesmo registro sem a data e sem as medidas de tempo."""
    if isinstance(valor, dict):
        return {
            chave: sem_variaveis(item) for chave, item in valor.items()
            if chave not in VARIAVEIS and not chave.endswith("segundos")
        }
    if isinstance(valor, list):
        return [sem_variaveis(item) for item in valor]
    return valor


def pct(valor):
    return f"{100 * valor:.2f}%".replace(".", ",")


def tabela_depois_de(texto, marca):
    """As linhas da primeira tabela do relatório que aparece depois de `marca`."""
    linhas = texto.split(marca, 1)[1].splitlines()
    inicio = next(i for i, linha in enumerate(linhas) if linha.startswith("|"))
    fim = next((i for i in range(inicio, len(linhas)) if not linhas[i].startswith("|")), len(linhas))
    return linhas[inicio:fim]


@pytest.fixture(scope="module")
def experimento(tmp_path_factory):
    """O comando inteiro sobre dados de mentira: amostra sintética e cinco pcaps pequenos."""
    pasta = tmp_path_factory.mktemp("janela")
    quadro = preparar_entrada(pasta)
    preparar_dataset(pasta / "dataset")
    assert executar(pasta, "--trabalho", str(pasta / "trabalho")) == 0
    return pasta, quadro


# --- o desenho do experimento ----------------------------------------------------------------


def test_capturas_sao_os_cinco_pcaps_com_o_rotulo_a_categoria_esperada_e_a_janela_oficial():
    assert [(c.arquivo, c.rotulo, c.esperada, c.janela_oficial) for c in CAPTURAS] == [
        ("DDoS-HTTP_Flood-.pcap", "DDoS-HTTP_Flood", FUSAO, 100),
        ("DoS-HTTP_Flood1.pcap", "DoS-HTTP_Flood", FUSAO, 100),
        ("Mirai-greip_flood21.pcap", "Mirai-greip_flood", "Mirai", 100),
        ("Recon-PortScan.pcap", "Recon-PortScan", "Recon", 10),
        ("DictionaryBruteForce.pcap", "DictionaryBruteForce", "BruteForce", 10),
    ]
    assert JANELAS == (10, 100)
    # A janela oficial é o controle, e a outra é o teste.
    assert [c.janela_de_teste for c in CAPTURAS] == [10, 10, 10, 100, 100]
    assert [c.condicao(100) for c in CAPTURAS] == ["controle", "controle", "controle", "teste", "teste"]
    assert [c.condicao(10) for c in CAPTURAS] == ["teste", "teste", "teste", "controle", "controle"]
    assert Captura("pasta/Recon-PortScan.pcap", "Recon-PortScan").nome == "Recon-PortScan"
    assert set(TAMANHO_DO_QUADRO) == {c.arquivo for c in CAPTURAS}


def test_modelos_sao_as_quatro_combinacoes_de_features_e_de_priori_em_7_categorias():
    assert (ALVO, DIVISAO) == ("7", "estratificada")
    assert set(MODELOS) == {
        Execucao(features, "estratificada", "7", priori) for features in ("39", "33") for priori in ("amostra", "natural")
    }
    # Os nomes são os das mesmas configurações no treino exploratório.
    assert [modelo.nome for modelo in MODELOS] == [
        "f39_estratificada_c7", "f39_estratificada_c7_natural", "f33_estratificada_c7", "f33_estratificada_c7_natural",
    ]


# --- extração em modo de operação ------------------------------------------------------------


@pytest.mark.parametrize("janela,linhas,incompleta", [(10, 23, 0), (100, 3, 1), (230, 1, 0), (7, 33, 1)])
def test_extrair_captura_le_o_arquivo_inteiro_em_leitura_continua(tmp_path, janela, linhas, incompleta):
    captura = gravar_pcap(tmp_path / "captura.pcap", 300)
    destino = tmp_path / "saida" / "captura.csv"
    registro = extrair_captura(captura, janela, destino)
    assert {chave: valor for chave, valor in registro.items() if not chave.endswith("segundos")} == {
        "janela": janela, "pacotes": QUADROS_POR_CAPTURA + 7, "quadros": QUADROS_POR_CAPTURA, "janelas": linhas,
        "janelas_incompletas": incompleta, "avisos": [],
    }
    assert registro["segundos"] > 0
    # O CSV é o que o extrator produz sobre o arquivo inteiro, sem fatiar: uma janela atravessa o
    # ponto em que o fatiamento de 10 MB dos autores cortaria, e só a última pode ficar incompleta.
    esperado = io.StringIO()
    gravar_csv(extrair(ler_pcap(captura), janela), esperado)
    assert destino.read_text(encoding="utf-8") == esperado.getvalue()
    quadro, _ = carregar(destino, rotulo="Recon-PortScan")
    assert len(quadro) == linhas and quadro["Number"].sum() == QUADROS_POR_CAPTURA
    assert (quadro["Number"].iloc[:-1] == janela).all()


def test_extrair_captura_registra_o_aviso_de_captura_interrompida(tmp_path):
    inteira = gravar_pcap(tmp_path / "inteira.pcap", 300, quadros=40, estranhos=0)
    cortada = tmp_path / "cortada.pcap"
    cortada.write_bytes(inteira.read_bytes()[:-9])
    registro = extrair_captura(cortada, 10, tmp_path / "cortada.csv")
    assert (registro["pacotes"], registro["janelas"], registro["janelas_incompletas"]) == (39, 4, 1)
    assert len(registro["avisos"]) == 1 and "incompleto" in registro["avisos"][0]


def test_extrair_captura_explica_entrada_que_nao_e_pcap(tmp_path):
    ruim = tmp_path / "captura.pcap"
    ruim.write_bytes(b"isto nao e um pcap")
    with pytest.raises(ValueError, match="captura.pcap: a entrada não é um arquivo pcap"):
        extrair_captura(ruim, 10, tmp_path / "saida.csv")
    with pytest.raises(FileNotFoundError):
        extrair_captura(tmp_path / "ausente.pcap", 10, tmp_path / "saida.csv")


def test_resumo_do_arquivo_traz_o_tamanho_e_o_hash(tmp_path):
    arquivo = tmp_path / "dados.bin"
    conteudo = bytes(range(256)) * 5000
    arquivo.write_bytes(conteudo)
    assert resumo_do_arquivo(arquivo) == {"bytes": len(conteudo), "sha256": hashlib.sha256(conteudo).hexdigest()}
    vazio = tmp_path / "vazio.bin"
    vazio.write_bytes(b"")
    assert resumo_do_arquivo(vazio) == {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}


# --- pontuação -------------------------------------------------------------------------------


class ModeloDoAtalho:
    """Modelo de mentira que só olha o tamanho da janela: flood se a janela tem 100 quadros."""

    n_jobs = 1

    def __init__(self, features):
        self.coluna = list(features).index("Number")

    def predict(self, X):
        return np.where(X[:, self.coluna] == 100, FUSAO, "Recon").astype(object)


def test_pontuar_conta_as_categorias_previstas_e_a_fracao_na_esperada(tmp_path):
    captura = Captura("flood.pcap", "DDoS-SYN_Flood")
    gravar_pcap(tmp_path / "flood.pcap", 80)
    de_100, _ = carregar(_extraido(tmp_path, 100), rotulo=captura.rotulo)
    de_10, _ = carregar(_extraido(tmp_path, 10), rotulo=captura.rotulo)
    modelo = ModeloDoAtalho(FEATURES_39)
    # Com a janela oficial, o modelo do atalho acerta as janelas completas. A última, incompleta, não tem 100 quadros.
    no_controle = pontuar(modelo, FEATURES_39, de_100, captura)
    assert no_controle == {
        "janelas": 3,
        "previstas": {classe: {FUSAO: 2, "Recon": 1}.get(classe, 0) for classe in CLASSES},
        "na_esperada": 2 / 3,
    }
    # Com a outra janela, o mesmo flood deixa de ser reconhecido: é o que o teste da janela procura.
    no_teste = pontuar(modelo, FEATURES_39, de_10, captura)
    assert (no_teste["janelas"], no_teste["previstas"]["Recon"], no_teste["na_esperada"]) == (23, 23, 0.0)
    assert list(no_teste["previstas"]) == CLASSES and sum(no_teste["previstas"].values()) == 23


def _extraido(pasta, janela):
    destino = pasta / f"flood_janela{janela}.csv"
    extrair_captura(pasta / "flood.pcap", janela, destino)
    return destino


def test_pontuar_usa_so_as_features_do_modelo_e_recusa_classe_fora_do_alvo(tmp_path):
    captura = Captura("flood.pcap", "DDoS-SYN_Flood")
    gravar_pcap(tmp_path / "flood.pcap", 80)
    quadro, _ = carregar(_extraido(tmp_path, 10), rotulo=captura.rotulo)

    class Espia:
        n_jobs = 1

        def predict(self, X):
            self.forma = X.shape
            return np.full(len(X), "Mirai", dtype=object)

    espia = Espia()
    assert pontuar(espia, FEATURES_33, quadro, captura)["previstas"]["Mirai"] == 23
    assert espia.forma == (23, 33)

    class DeOutroAlvo(Espia):
        def predict(self, X):
            return np.full(len(X), "DDoS", dtype=object)

    with pytest.raises(ValueError, match="classe prevista fora do alvo"):
        pontuar(DeOutroAlvo(), FEATURES_39, quadro, captura)


def test_iguais_ao_treino_conta_as_janelas_com_o_vetor_de_uma_linha_de_treino_e_os_rotulos_dela():
    treino = np.array([[1.0, 2.0], [3.0, np.nan], [0.0, 5.0], [1.0, 2.0], [1.0, 2.0]], dtype=np.float32)
    rotulos = ["XSS", "Recon-PortScan", "BenignTraffic", "Recon-PortScan", "XSS"]
    capturadas = np.array([[1.0, 2.0], [1.0, 2.5], [3.0, np.nan], [-0.0, 5.0], [9.0, 9.0], [1.0, 2.0]], dtype=np.float32)
    # O vazio é igual ao vazio, e o zero negativo é igual ao zero, como na divisão por grupos.
    # A janela conta uma vez no total e uma vez em cada rótulo que o vetor dela tem no treino.
    assert iguais_ao_treino(treino, rotulos, capturadas) == {
        "janelas": 4, "por_rotulo": {"Recon-PortScan": 3, "XSS": 2, "BenignTraffic": 1},
    }
    # Os rótulos saem na ordem das tabelas do projeto.
    assert list(iguais_ao_treino(treino, rotulos, capturadas)["por_rotulo"]) == ["Recon-PortScan", "XSS", "BenignTraffic"]
    assert iguais_ao_treino(treino, rotulos, capturadas[4:5]) == {"janelas": 0, "por_rotulo": {}}
    assert iguais_ao_treino(treino, rotulos, treino)["janelas"] == 5


# --- o experimento inteiro, com dados de mentira ---------------------------------------------


def test_rodar_pontua_cada_captura_em_cada_janela_com_cada_modelo(tmp_path):
    quadro = quadro_sintetico(por_classe=40)
    dataset = preparar_dataset(tmp_path / "dataset")
    progresso = []
    registro = rodar(
        quadro, POPULACAO, dataset, tmp_path / "trabalho", arvores=5, nucleos=1, ao_terminar=progresso.append,
    )
    treino, teste = dividir(quadro, DIVISAO)
    assert registro["amostra"] == {
        "linhas": len(quadro), "linhas_de_treino": len(treino), "linhas_de_teste": len(teste),
        "sha256_do_teste": impressao_digital(teste),
    }
    assert [captura["arquivo"] for captura in registro["capturas"]] == [c.arquivo for c in CAPTURAS]
    assert [modelo["nome"] for modelo in registro["modelos"]] == [m.nome for m in MODELOS]
    chaves = [(r["captura"], r["janela"], r["modelo"]) for r in registro["resultados"]]
    assert len(chaves) == len(set(chaves)) == 5 * 2 * 4
    assert set(chaves) == {(c.nome, janela, m.nome) for c in CAPTURAS for janela in JANELAS for m in MODELOS}
    assert len(progresso) == 5 * 2 + 4

    rotulos = quadro["Label"].to_numpy()
    y = alvo(rotulos, ALVO)
    for modelo in MODELOS:
        # O modelo é o do treino exploratório: a parte de treino do sorteio estratificado, com a priori pedida.
        features = CONJUNTOS_DE_FEATURES[modelo.features]
        X = matriz(quadro, features)
        pesos = pesos_de_treino(rotulos[treino], POPULACAO) if modelo.priori == "natural" else None
        esperado, _ = treinar(X[treino], y[treino], arvores=5, pesos=pesos, nucleos=1)
        registrado = next(m for m in registro["modelos"] if m["nome"] == modelo.nome)
        no_teste = avaliar(prever(esperado, X[teste]), rotulos[teste], ALVO)["amostra"]
        assert (registrado["features"], registrado["priori"], registrado["arvores"]) == (modelo.features, modelo.priori, 5)
        assert registrado["no_teste_da_amostra"]["acuracia"] == no_teste["acuracia"]
        assert registrado["no_teste_da_amostra"]["recall"] == {
            classe: medida["recall"] for classe, medida in no_teste["por_classe"].items()
        }
        for captura in CAPTURAS:
            for janela in JANELAS:
                capturado, _ = carregar(tmp_path / "trabalho" / f"{captura.nome}_janela{janela}.csv", rotulo=captura.rotulo)
                previsto = prever(esperado, matriz(capturado, features))
                resultado = next(
                    r for r in registro["resultados"]
                    if (r["captura"], r["janela"], r["modelo"]) == (captura.nome, janela, modelo.nome)
                )
                assert resultado["janelas"] == len(capturado) == (23 if janela == 10 else 3)
                assert resultado["previstas"] == {classe: int((previsto == classe).sum()) for classe in CLASSES}
                assert resultado["na_esperada"] == (previsto == captura.esperada).mean()
                assert resultado["condicao"] == captura.condicao(janela)


def test_rodar_registra_cada_captura_com_o_tamanho_o_hash_e_as_duas_extracoes(tmp_path):
    quadro = quadro_sintetico(por_classe=20)
    dataset = preparar_dataset(tmp_path / "dataset")
    capturas = (Captura("Recon-PortScan.pcap", "Recon-PortScan"), Captura("DoS-HTTP_Flood1.pcap", "DoS-SYN_Flood"))
    registro = rodar(
        quadro, POPULACAO, dataset, tmp_path / "trabalho", capturas=capturas, modelos=MODELOS[:1], arvores=3, nucleos=1,
    )
    recon, flood = registro["capturas"]
    conteudo = (dataset / "Recon-PortScan.pcap").read_bytes()
    assert {chave: recon[chave] for chave in ("nome", "arquivo", "rotulo", "esperada", "janela_oficial", "bytes", "sha256")} == {
        "nome": "Recon-PortScan", "arquivo": "Recon-PortScan.pcap", "rotulo": "Recon-PortScan", "esperada": "Recon",
        "janela_oficial": 10, "bytes": len(conteudo), "sha256": hashlib.sha256(conteudo).hexdigest(),
    }
    assert (flood["esperada"], flood["janela_oficial"]) == (FUSAO, 100)
    assert [(e["janela"], e["condicao"], e["janelas"]) for e in recon["extracoes"]] == [(10, "controle", 23), (100, "teste", 3)]
    assert [(e["janela"], e["condicao"], e["janelas"]) for e in flood["extracoes"]] == [(10, "teste", 23), (100, "controle", 3)]
    for extracao in (*recon["extracoes"], *flood["extracoes"]):
        assert (extracao["pacotes"], extracao["quadros"]) == (QUADROS_POR_CAPTURA + 7, QUADROS_POR_CAPTURA)
        arquivo = tmp_path / "trabalho" / extracao["csv"]
        assert extracao["sha256_do_csv"] == hashlib.sha256(arquivo.read_bytes()).hexdigest()
        # Nenhuma janela das capturas de mentira repete uma linha da amostra sintética.
        assert extracao["iguais_a_linha_de_treino"] == extracao["iguais_a_linha_de_treino_do_mesmo_rotulo"] == 0
        assert extracao["iguais_por_rotulo_de_treino"] == {}
    assert len(registro["resultados"]) == 2 * 2 * 1


def test_rodar_conta_as_janelas_que_repetem_uma_linha_de_treino(tmp_path):
    # Uma amostra feita das próprias janelas da captura: no controle, toda janela é linha de treino ou de teste.
    dataset = preparar_dataset(tmp_path / "dataset")
    capturas = (Captura("Recon-PortScan.pcap", "Recon-PortScan"),)
    extrair_captura(dataset / "Recon-PortScan.pcap", 10, tmp_path / "base.csv")
    da_captura, _ = carregar(tmp_path / "base.csv", rotulo="Recon-PortScan")
    quadro = quadro_sintetico(por_classe=20)
    amostra = quadro[quadro["Label"] != "Recon-PortScan"]
    amostra = pd.concat([amostra, da_captura], ignore_index=True)
    registro = rodar(
        amostra, POPULACAO, dataset, tmp_path / "trabalho", capturas=capturas, modelos=MODELOS[:1], arvores=3, nucleos=1,
    )
    treino, _ = dividir(amostra, DIVISAO)
    de_treino = int((amostra["Label"].to_numpy()[treino] == "Recon-PortScan").sum())
    de_10, de_100 = registro["capturas"][0]["extracoes"]
    assert 0 < de_treino < 23
    assert (de_10["iguais_a_linha_de_treino"], de_100["iguais_a_linha_de_treino"]) == (de_treino, 0)
    assert de_10["iguais_a_linha_de_treino_do_mesmo_rotulo"] == de_treino
    assert de_10["iguais_por_rotulo_de_treino"] == {"Recon-PortScan": de_treino}

    # A mesma captura com outro rótulo: as janelas continuam repetindo linhas de treino, mas de outro rótulo.
    # É o que acontece quando a amostra dá ao mesmo vetor o rótulo de outra classe.
    de_outro_rotulo = (Captura("Recon-PortScan.pcap", "DictionaryBruteForce"),)
    registro = rodar(
        amostra, POPULACAO, dataset, tmp_path / "outro", capturas=de_outro_rotulo, modelos=MODELOS[:1], arvores=3,
        nucleos=1,
    )
    de_10 = registro["capturas"][0]["extracoes"][0]
    assert (de_10["iguais_a_linha_de_treino"], de_10["iguais_a_linha_de_treino_do_mesmo_rotulo"]) == (de_treino, 0)
    assert de_10["iguais_por_rotulo_de_treino"] == {"Recon-PortScan": de_treino}


def test_rodar_recusa_pcap_ausente_antes_de_treinar(tmp_path, monkeypatch):
    dataset = preparar_dataset(tmp_path / "dataset")
    (dataset / "Recon-PortScan.pcap").unlink()
    (dataset / "DictionaryBruteForce.pcap").unlink()
    monkeypatch.setattr(teste_da_janela, "treinar", lambda *a, **k: pytest.fail("não deveria treinar"))
    with pytest.raises(FileNotFoundError, match="Recon-PortScan.pcap, DictionaryBruteForce.pcap"):
        rodar(quadro_sintetico(por_classe=20), POPULACAO, dataset, tmp_path / "trabalho", arvores=3)
    assert not (tmp_path / "trabalho").exists()


# --- o comando -------------------------------------------------------------------------------


def test_main_grava_o_relatorio_a_tabela_e_o_manifesto_e_guarda_as_extracoes_na_pasta_de_trabalho(experimento):
    pasta, _ = experimento
    assert sorted(p.name for p in (pasta / "resultados").iterdir()) == sorted([RELATORIO, TABELA, MANIFESTO])
    assert (RELATORIO, TABELA, MANIFESTO) == (
        "teste_da_janela.md", "teste_da_janela.csv", "manifesto_teste_da_janela.json",
    )
    assert sorted(p.name for p in (pasta / "trabalho").iterdir()) == sorted(
        f"{captura.nome}_janela{janela}.csv" for captura in CAPTURAS for janela in JANELAS
    )
    # Nenhum modelo fica no disco.
    assert not list(pasta.rglob("*.joblib"))


def test_manifesto_registra_semente_parametros_versoes_hash_da_amostra_e_de_cada_pcap(experimento):
    pasta, quadro = experimento
    m = ler_manifesto(pasta / "resultados")
    assert m["gerado_por"] == "python -m codigo.classificador.janela"
    assert m["semente"] == 42
    assert m["parametros"] == {
        "modelo": "sklearn.ensemble.RandomForestClassifier", "arvores": 5, "n_jobs": 1,
        "demais_parametros": "padrão do scikit-learn", "escalonamento": "nenhum", "alvo": "7",
        "divisao": "estratificada", "fracao_de_teste": 0.2, "janelas": [10, 100],
        "extracao": "codigo.captura.extrator.extrair sobre o arquivo inteiro, em leitura contínua",
        "predicao": "votos somados em ordem fixa, com um núcleo",
    }
    assert set(m["versoes"]) == {"python", "numpy", "pandas", "scikit-learn", "dpkt"}
    da_amostra = json.loads((pasta / "manifesto_amostra.json").read_text(encoding="utf-8"))
    assert m["amostra"]["sha256_do_csv_descomprimido"] == da_amostra["saida"]["sha256_do_csv_descomprimido"]
    assert m["amostra"]["linhas"] == len(quadro)
    assert m["amostra"]["arquivo"].endswith("amostra.csv.gz")
    for captura, registrada in zip(CAPTURAS, m["capturas"], strict=True):
        conteudo = (pasta / "dataset" / captura.arquivo).read_bytes()
        assert (registrada["arquivo"], registrada["bytes"]) == (captura.arquivo, len(conteudo))
        assert registrada["sha256"] == hashlib.sha256(conteudo).hexdigest()
    assert len(m["resultados"]) == 40 and len(m["modelos"]) == 4
    assert m["duracao"]["total_segundos"] >= m["duracao"]["extracao_segundos"] > 0


def test_tabela_tem_uma_linha_por_captura_janela_modelo_e_categoria_prevista(experimento):
    pasta, _ = experimento
    m, linhas = ler_manifesto(pasta / "resultados"), ler_tabela(pasta / "resultados")
    assert list(linhas[0]) == [
        "captura", "rotulo", "categoria_esperada", "janela", "janela_oficial", "condicao", "modelo", "features",
        "priori", "categoria_prevista", "e_a_esperada", "janelas_previstas", "janelas_da_captura", "fracao",
    ]
    assert len(linhas) == 5 * 2 * 4 * 7
    for resultado in m["resultados"]:
        do_caso = [
            linha for linha in linhas
            if (linha["captura"], int(linha["janela"]), linha["modelo"])
            == (resultado["captura"], resultado["janela"], resultado["modelo"])
        ]
        assert [linha["categoria_prevista"] for linha in do_caso] == CLASSES
        assert {linha["categoria_prevista"]: int(linha["janelas_previstas"]) for linha in do_caso} == resultado["previstas"]
        assert {int(linha["janelas_da_captura"]) for linha in do_caso} == {resultado["janelas"]}
        assert sum(float(linha["fracao"]) for linha in do_caso) == pytest.approx(1, abs=1e-5)
        esperada = [linha for linha in do_caso if linha["e_a_esperada"] == "1"]
        assert len(esperada) == 1 and esperada[0]["categoria_prevista"] == esperada[0]["categoria_esperada"]
        assert float(esperada[0]["fracao"]) == pytest.approx(resultado["na_esperada"], abs=1e-6)
        assert {linha["condicao"] for linha in do_caso} == {resultado["condicao"]}


def test_numero_principal_confere_com_o_comando_avaliar_sobre_a_extracao(experimento, tmp_path, capsys):
    # O caminho independente: o modelo treinado pelo comando treinar e a captura pontuada pelo comando
    # avaliar, com --csv e --rotulo, dão a fração que o teste da janela registrou.
    pasta, _ = experimento
    m = ler_manifesto(pasta / "resultados")
    modelo = tmp_path / "rf.joblib"
    assert treinar_modelo([
        "--amostra", str(pasta / "amostra.csv.gz"), "--features", "33", "--alvo", "7", "--arvores", "5",
        "--nucleos", "1", "--saida", str(modelo),
    ]) == 0
    for captura in CAPTURAS:
        for janela in JANELAS:
            saida = tmp_path / f"{captura.nome}_{janela}.json"
            assert avaliar_modelo([
                str(modelo), "--csv", str(pasta / "trabalho" / f"{captura.nome}_janela{janela}.csv"),
                "--rotulo", captura.rotulo, "--saida", str(saida),
            ]) == 0
            avaliado = json.loads(saida.read_text(encoding="utf-8"))
            resultado = next(
                r for r in m["resultados"]
                if (r["captura"], r["janela"], r["modelo"]) == (captura.nome, janela, "f33_estratificada_c7")
            )
            assert avaliado["amostra"]["por_classe"][captura.esperada]["recall"] == resultado["na_esperada"]
            assert avaliado["matriz_por_rotulo"]["contagem"] == [list(resultado["previstas"].values())]
    capsys.readouterr()


def test_mesma_entrada_da_os_mesmos_numeros_e_sem_pasta_de_trabalho_nada_sobra(experimento, tmp_path):
    pasta, _ = experimento
    assert executar(pasta, saida=tmp_path / "de_novo") == 0
    assert sem_variaveis(ler_manifesto(tmp_path / "de_novo")) == sem_variaveis(ler_manifesto(pasta / "resultados"))
    assert (tmp_path / "de_novo" / TABELA).read_bytes() == (pasta / "resultados" / TABELA).read_bytes()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["de_novo"]


def test_refazer_relatorio_parte_do_manifesto_sem_extrair_nem_treinar(experimento, tmp_path, monkeypatch):
    pasta, _ = experimento
    copia = tmp_path / "resultados"
    copia.mkdir()
    (copia / MANIFESTO).write_bytes((pasta / "resultados" / MANIFESTO).read_bytes())
    monkeypatch.setattr(teste_da_janela, "rodar", lambda *a, **k: pytest.fail("não deveria rodar o experimento"))
    assert main(["--saida", str(copia), "--refazer-relatorio"]) == 0
    for arquivo in (RELATORIO, TABELA, MANIFESTO):
        assert (copia / arquivo).read_bytes() == (pasta / "resultados" / arquivo).read_bytes()
    assert main(["--saida", str(tmp_path / "vazia"), "--refazer-relatorio"]) == 1


@pytest.mark.parametrize("extras", [
    ("--arvores", "0"), ("--nucleos", "0"), ("--semente", "x"), ("--janelas", "10"), ("--opcao-que-nao-existe",),
])
def test_main_recusa_opcao_invalida(tmp_path, capsys, extras):
    assert executar(tmp_path, *extras) == 2
    assert capsys.readouterr().err
    assert not (tmp_path / "resultados").exists()


def test_main_explica_o_que_falta_e_nao_grava_nada(tmp_path, capsys):
    # Sem a amostra.
    assert executar(tmp_path) == 1
    assert "erro:" in capsys.readouterr().err
    # Com a amostra, sem os pcaps.
    preparar_entrada(tmp_path)
    assert executar(tmp_path) == 1
    erro = capsys.readouterr().err
    assert erro.startswith("erro: ") and "DDoS-HTTP_Flood-.pcap" in erro and "Traceback" not in erro
    # Com uma amostra que não é a do manifesto.
    preparar_dataset(tmp_path / "dataset")
    manifesto = json.loads((tmp_path / "manifesto_amostra.json").read_text(encoding="utf-8"))
    manifesto["saida"]["sha256_do_csv_descomprimido"] = "0" * 64
    (tmp_path / "manifesto_amostra.json").write_text(json.dumps(manifesto), encoding="utf-8")
    assert executar(tmp_path) == 1
    assert "não é a amostra registrada" in capsys.readouterr().err
    assert not (tmp_path / "resultados").exists()


def test_main_interrompido_pelo_teclado_sai_com_130_e_nao_grava_resultado(tmp_path, capsys, monkeypatch):
    preparar_entrada(tmp_path)
    preparar_dataset(tmp_path / "dataset")

    def interrompido(*_a, **_k):
        raise KeyboardInterrupt

    monkeypatch.setattr(teste_da_janela, "rodar", interrompido)
    assert executar(tmp_path) == 130
    assert "interrompido" in capsys.readouterr().err
    assert not (tmp_path / "resultados").exists()


# --- o relatório -----------------------------------------------------------------------------


def test_relatorio_traz_a_tabela_principal_com_os_numeros_do_manifesto(experimento):
    pasta, _ = experimento
    m = ler_manifesto(pasta / "resultados")
    relatorio = (pasta / "resultados" / RELATORIO).read_text(encoding="utf-8")
    assert relatorio == montar_relatorio(m)
    assert relatorio.startswith("# Teste direto do atalho da janela\n")
    tabela = tabela_depois_de(relatorio, "## Tabela principal")
    assert tabela[0].startswith("| Captura | Categoria esperada | Janela | Condição | Janelas |")
    corpo = tabela[2:]
    assert len(corpo) == 10
    for linha in corpo:
        celulas = [celula.strip() for celula in linha.strip("|").split("|")]
        captura = next(c for c in CAPTURAS if f"`{c.arquivo}`" == celulas[0])
        janela = int(celulas[2])
        assert celulas[1] == captura.esperada and celulas[3] == captura.condicao(janela)
        for modelo, celula in zip(MODELOS, celulas[5:], strict=True):
            resultado = next(
                r for r in m["resultados"]
                if (r["captura"], r["janela"], r["modelo"]) == (captura.nome, janela, modelo.nome)
            )
            assert celula == pct(resultado["na_esperada"])
            assert celulas[4] == f"{resultado['janelas']:,}".replace(",", ".")
    # Em cada captura, a linha do controle vem antes da linha do teste.
    assert [linha.split("|")[4].strip() for linha in corpo] == ["controle", "teste"] * 5


def test_relatorio_traz_a_diferenca_entre_o_controle_e_o_teste(experimento):
    pasta, _ = experimento
    m = ler_manifesto(pasta / "resultados")
    relatorio = (pasta / "resultados" / RELATORIO).read_text(encoding="utf-8")
    corpo = tabela_depois_de(relatorio, "### Quanto muda")[2:]
    assert len(corpo) == 5
    for captura, linha in zip(CAPTURAS, corpo, strict=True):
        celulas = [celula.strip() for celula in linha.strip("|").split("|")]
        assert celulas[0] == f"`{captura.arquivo}`"
        assert celulas[1] == f"de {captura.janela_oficial} para {captura.janela_de_teste}"
        for modelo, celula in zip(MODELOS, celulas[2:], strict=True):
            fracao = {
                r["janela"]: r["na_esperada"] for r in m["resultados"]
                if (r["captura"], r["modelo"]) == (captura.nome, modelo.nome)
            }
            diferenca = 100 * (fracao[captura.janela_de_teste] - fracao[captura.janela_oficial])
            assert float(celula.replace(",", ".")) == pytest.approx(diferenca, abs=0.006)


def test_relatorio_traz_a_distribuicao_das_previsoes_de_cada_modelo(experimento):
    pasta, _ = experimento
    m = ler_manifesto(pasta / "resultados")
    relatorio = (pasta / "resultados" / RELATORIO).read_text(encoding="utf-8")
    for modelo in MODELOS:
        tabela = tabela_depois_de(relatorio, f"### `{modelo.nome}`")
        assert [celula.strip() for celula in tabela[0].strip("|").split("|")][3:] == CLASSES
        assert len(tabela[2:]) == 10
        for linha in tabela[2:]:
            celulas = [celula.strip() for celula in linha.strip("|").split("|")]
            captura = next(c for c in CAPTURAS if f"`{c.arquivo}`" == celulas[0])
            resultado = next(
                r for r in m["resultados"]
                if (r["captura"], r["janela"], r["modelo"]) == (captura.nome, int(celulas[1]), modelo.nome)
            )
            assert celulas[3:] == [pct(resultado["previstas"][classe] / resultado["janelas"]) for classe in CLASSES]


def test_relatorio_traz_as_ressalvas_e_a_leitura_de_cada_saida_sem_recomendar(experimento):
    pasta, _ = experimento
    relatorio = (pasta / "resultados" / RELATORIO).read_text(encoding="utf-8")
    titulos = [linha for linha in relatorio.splitlines() if linha.startswith("#")]
    assert titulos[:6] == [
        "# Teste direto do atalho da janela", "## A pergunta", "## O experimento", "## Ressalvas",
        "## Tabela principal", "### Quanto muda",
    ]
    assert "## Para onde vão as janelas" in titulos
    posicao = titulos.index("## O que os números dizem sobre cada saída em avaliação")
    assert titulos[posicao + 1:posicao + 5] == [
        "### Janela única de 10 na operação", "### Janela única de 100 na operação",
        "### Janelas regeradas dos pcaps", "### Limitação declarada",
    ]
    assert titulos[-1] == "## Como os números foram obtidos"
    # O texto corrido, sem as quebras de linha do arquivo.
    ressalvas = " ".join(relatorio.split("## Ressalvas", 1)[1].split("## Tabela principal", 1)[0].split())
    # As quatro ressalvas que o relatório precisa dizer sem rodeio.
    assert "fazem parte do dataset de onde saiu a amostra" in ressalvas
    assert "tráfego de fundo" in ressalvas and "hipótese" in ressalvas
    assert "não é uma avaliação das 34 classes" in ressalvas
    assert "não recomenda" in ressalvas
    # A ressalva do controle traz a medida: quantas janelas repetem uma linha de treino, e de que rótulo.
    assert "idênticas às de uma linha de treino" in ressalvas
    assert "do mesmo rótulo" in ressalvas
    # O relatório entrega os números e não escolhe uma saída.
    minusculas = " ".join(relatorio.casefold().split())
    assert minusculas.count("recomend") == minusculas.count("não recomenda")
    for palavra in ("deve-se", "devemos", "o melhor é", "a melhor saída", "sugere-se", "convém"):
        assert palavra not in minusculas
    # Sem travessão.
    assert "—" not in relatorio and "–" not in relatorio


def test_relatorio_conta_as_janelas_que_repetem_linhas_de_treino_e_diz_de_que_rotulos(experimento):
    pasta, _ = experimento
    m = ler_manifesto(pasta / "resultados")
    # Nas capturas de mentira nenhuma janela repete linha de treino. O manifesto ganha os números de um caso
    # em que o controle repete linhas do mesmo rótulo e o teste repete linhas de outros.
    flood = m["capturas"][1]
    de_10, de_100 = flood["extracoes"]
    de_100 |= {
        "iguais_a_linha_de_treino": 2, "iguais_a_linha_de_treino_do_mesmo_rotulo": 1,
        "iguais_por_rotulo_de_treino": {"DDoS-HTTP_Flood": 1, "DoS-HTTP_Flood": 1},
    }
    de_10 |= {
        "iguais_a_linha_de_treino": 9, "iguais_a_linha_de_treino_do_mesmo_rotulo": 0,
        "iguais_por_rotulo_de_treino": {"Recon-OSScan": 8, "VulnerabilityScan": 1, "Recon-PortScan": 7, "XSS": 2},
    }
    relatorio = montar_relatorio(m)
    tabela = tabela_depois_de(relatorio, "## Ressalvas")
    assert [celula.strip() for celula in tabela[0].strip("|").split("|")] == [
        "Captura", "Controle: idênticas a uma linha de treino", "das quais, do mesmo rótulo",
        "Teste: idênticas a uma linha de treino", "das quais, do mesmo rótulo",
    ]
    linha = next(linha for linha in tabela[2:] if f"`{flood['arquivo']}`" in linha)
    assert [celula.strip() for celula in linha.strip("|").split("|")][1:] == [
        "2 de 3 (66,67%)", "1", "9 de 23 (39,13%)", "0",
    ]
    ressalvas = " ".join(relatorio.split("## Ressalvas", 1)[1].split("## Tabela principal", 1)[0].split())
    # Os rótulos de treino dos vetores repetidos no teste, do mais frequente para o menos, com os três primeiros.
    assert (
        f"`{flood['arquivo']}`, janela de 10: `Recon-OSScan` (8 janelas), `Recon-PortScan` (7 janelas), `XSS` "
        "(2 janelas) e mais 1 rótulo"
    ) in ressalvas
    # Sem janela repetida no teste, a lista não aparece.
    original = montar_relatorio(ler_manifesto(pasta / "resultados"))
    assert "Os rótulos que a amostra de treino dá" in ressalvas
    assert "Os rótulos que a amostra de treino dá" not in " ".join(original.split())


def test_relatorio_separa_a_condicao_de_teste_pelas_features_do_modelo(experimento):
    pasta, _ = experimento
    m = ler_manifesto(pasta / "resultados")
    leitura = " ".join(
        montar_relatorio(m).split("## O que os números dizem sobre cada saída em avaliação", 1)[1]
        .split("## Como os números foram obtidos", 1)[0].split()
    )
    for captura in CAPTURAS:
        # No teste, uma faixa para os modelos de 39 features e outra para os de 33: é a diferença que mais pesa.
        fracoes = {
            features: [
                r["na_esperada"] for r in m["resultados"]
                if (r["captura"], r["janela"]) == (captura.nome, captura.janela_de_teste) and r["modelo"].startswith(f"f{features}_")
            ]
            for features in ("39", "33")
        }
        for features, valores in fracoes.items():
            menor, maior = pct(min(valores)), pct(max(valores))
            faixa = menor if menor == maior else f"{menor} a {maior}"
            assert f"{faixa} com as {features} features (diferença" in leitura.split(f"`{captura.arquivo}`: com a janela de")[1]
    # O descompasso vem captura por captura, e não numa faixa só que juntaria capturas diferentes.
    regeradas = leitura.split("### Janelas regeradas dos pcaps", 1)[1].split("### Limitação declarada", 1)[0]
    for captura in CAPTURAS:
        assert f"`{captura.arquivo}`, " in regeradas
    assert "p.p.." not in leitura


def test_relatorio_diz_como_os_numeros_foram_obtidos(experimento):
    pasta, _ = experimento
    m = ler_manifesto(pasta / "resultados")
    relatorio = (pasta / "resultados" / RELATORIO).read_text(encoding="utf-8")
    fim = " ".join(relatorio.split("## Como os números foram obtidos", 1)[1].split())
    assert "`python -m codigo.classificador.janela`" in fim
    assert m["amostra"]["sha256_do_csv_descomprimido"] in fim
    for captura in m["capturas"]:
        assert captura["sha256"] in fim and f"`{captura['arquivo']}`" in fim
    assert f"`{TABELA}`" in fim and f"`{MANIFESTO}`" in fim
    assert "`python -m codigo.classificador.avaliar MODELO --csv CAPTURA.csv --rotulo ROTULO`" in fim


def test_relatorio_sai_do_manifesto_e_muda_com_ele(experimento):
    pasta, _ = experimento
    m = ler_manifesto(pasta / "resultados")
    alterado = json.loads(json.dumps(m))
    resultado = alterado["resultados"][0]
    captura = next(c for c in CAPTURAS if c.nome == resultado["captura"])
    resultado["previstas"] = dict.fromkeys(CLASSES, 0) | {"Benign": resultado["janelas"]}
    resultado["na_esperada"] = 0.0
    assert montar_relatorio(alterado) != montar_relatorio(m)
    linha = next(
        linha for linha in tabela_depois_de(montar_relatorio(alterado), "## Tabela principal")[2:]
        if f"`{captura.arquivo}`" in linha and f"| {resultado['janela']} |" in linha
    )
    assert linha.split("|")[6].strip() == "0,00%"


def test_separacao_citada_na_pergunta_e_a_que_o_treino_exploratorio_registrou(experimento):
    # O relatório cita um número de outro experimento. Ele é conferido contra o texto versionado de lá.
    exploratorio = (RESULTADOS / "treino_exploratorio.md").read_text(encoding="utf-8")
    achado = re.search(r"ainda põe de ([\d,]+)% a ([\d,]+)% das linhas de teste no grupo de janela certo", exploratorio)
    assert achado, "a frase do treino exploratório sobre o atalho mudou"
    menor = float(achado.group(1).replace(",", ".")) / 100
    assert menor > SEPARACAO_SEM_AS_SEIS_COLUNAS == 0.998
    pasta, _ = experimento
    relatorio = (pasta / "resultados" / RELATORIO).read_text(encoding="utf-8")
    assert "mais de 99,8% das linhas de teste" in " ".join(relatorio.split())


# --- os resultados versionados ---------------------------------------------------------------


@pytest.mark.skipif(not (RESULTADOS / MANIFESTO).exists(), reason="teste da janela ainda não rodado")
def test_resultados_versionados_sao_coerentes_entre_si():
    m = ler_manifesto(RESULTADOS)
    assert (RESULTADOS / RELATORIO).read_text(encoding="utf-8") == montar_relatorio(m)
    assert (m["semente"], m["parametros"]["arvores"], m["parametros"]["alvo"]) == (42, 100, "7")
    amostra = json.loads((RESULTADOS / "manifesto_amostra.json").read_text(encoding="utf-8"))
    assert m["amostra"]["sha256_do_csv_descomprimido"] == amostra["saida"]["sha256_do_csv_descomprimido"]
    assert [captura["arquivo"] for captura in m["capturas"]] == [c.arquivo for c in CAPTURAS]
    assert [modelo["nome"] for modelo in m["modelos"]] == [modelo.nome for modelo in MODELOS]
    assert len(m["resultados"]) == 40
    linhas = ler_tabela(RESULTADOS)
    assert len(linhas) == 280
    for resultado in m["resultados"]:
        assert sum(resultado["previstas"].values()) == resultado["janelas"]
        captura = next(c for c in m["capturas"] if c["nome"] == resultado["captura"])
        extracao = next(e for e in captura["extracoes"] if e["janela"] == resultado["janela"])
        assert resultado["janelas"] == extracao["janelas"]
        assert resultado["na_esperada"] == resultado["previstas"][captura["esperada"]] / resultado["janelas"]
    for captura in m["capturas"]:
        de_10, de_100 = captura["extracoes"]
        # As duas extrações leem os mesmos quadros.
        assert (de_10["pacotes"], de_10["quadros"]) == (de_100["pacotes"], de_100["quadros"])
        assert de_10["janelas"] == -(-de_10["quadros"] // 10) and de_100["janelas"] == -(-de_100["quadros"] // 100)


@pytest.mark.skipif(
    not (RESULTADOS / MANIFESTO).exists() or not (RESULTADOS / "manifesto_treino_exploratorio.json").exists(),
    reason="falta o teste da janela ou o treino exploratório",
)
def test_modelos_do_teste_da_janela_sao_os_do_treino_exploratorio():
    # Mesma amostra, mesma divisão, mesma semente e mesmas árvores: as medidas na parte de teste da
    # amostra têm de ser as que o treino exploratório registrou para a mesma configuração.
    m = ler_manifesto(RESULTADOS)
    exploratorio = json.loads((RESULTADOS / "manifesto_treino_exploratorio.json").read_text(encoding="utf-8"))
    assert m["amostra"]["sha256_do_csv_descomprimido"] == exploratorio["amostra"]["sha256_do_csv_descomprimido"]
    assert m["amostra"]["sha256_do_teste"] == exploratorio["divisoes"]["estratificada"]["sha256_do_teste"]
    for modelo in m["modelos"]:
        execucao = next(e for e in exploratorio["execucoes"] if e["nome"] == modelo["nome"])
        assert modelo["no_teste_da_amostra"]["acuracia"] == execucao["amostra"]["acuracia"]
        for classe, recall in modelo["no_teste_da_amostra"]["recall"].items():
            assert recall == execucao["amostra"]["por_classe"][classe]["recall"]
        assert modelo["nos_por_arvore"] == execucao["nos_por_arvore"]


@pytest.mark.skipif(
    not (RESULTADOS / MANIFESTO).exists() or not all((DATASET / captura.arquivo).exists() for captura in CAPTURAS),
    reason="falta o teste da janela ou o dataset",
)
def test_pcaps_do_dataset_tem_o_tamanho_registrado_no_manifesto():
    m = ler_manifesto(RESULTADOS)
    for captura in m["capturas"]:
        assert (DATASET / captura["arquivo"]).stat().st_size == captura["bytes"]


def test_colunas_da_extracao_sao_as_39_do_dataset(tmp_path):
    gravar_pcap(tmp_path / "captura.pcap", 300)
    extrair_captura(tmp_path / "captura.pcap", 10, tmp_path / "captura.csv")
    assert (tmp_path / "captura.csv").read_text(encoding="utf-8").splitlines()[0].split(",") == list(COLUNAS)
