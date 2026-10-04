import gzip
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from codigo.captura.extrator import COLUNAS
from codigo.classificador.mapeamento import CATEGORIA_DO_ROTULO, CATEGORIAS, ROTULOS
from codigo.classificador.preparar import (
    ALVOS,
    CONJUNTOS_DE_FEATURES,
    DEPENDENTES_DA_JANELA,
    DIVISOES,
    FEATURES_33,
    FEATURES_39,
    FRACAO_DE_TESTE,
    FUSAO,
    SEMENTE,
    agrupar,
    alvo,
    carregar,
    dividir,
    dividir_estratificada,
    dividir_por_grupos,
    impressao_digital,
    ler,
    matriz,
)

RAIZ = Path(__file__).resolve().parents[2]
AMOSTRA = RAIZ / "dados" / "processed" / "amostra.csv.gz"
MANIFESTO_DA_AMOSTRA = RAIZ / "experimentos" / "resultados" / "manifesto_amostra.json"

# Rótulo, tamanho da janela e tamanho médio dos quadros de cada classe do caso sintético.
CLASSES_DO_CASO = (
    ("DDoS-ICMP_Flood", 100, 60.0),
    ("DDoS-SYN_Flood", 100, 200.0),
    ("DoS-SYN_Flood", 100, 200.0),
    ("Mirai-udpplain", 100, 560.0),
    ("Recon-PortScan", 10, 700.0),
    ("MITM-ArpSpoofing", 10, 850.0),
    ("XSS", 10, 1000.0),
    ("DictionaryBruteForce", 10, 1150.0),
    ("BenignTraffic", 10, 1300.0),
)


def quadro_sintetico(por_classe=40, semente=0):
    """Amostra de mentira, com 9 rótulos das 8 categorias, separáveis pelo tamanho médio do quadro.

    A metade das linhas de DoS-SYN_Flood repete os vetores de DDoS-SYN_Flood, como acontece no
    dataset com o mesmo flood rotulado das duas formas.
    """
    gerador = np.random.default_rng(semente)
    partes = []
    for rotulo, janela, centro in CLASSES_DO_CASO:
        media = centro + gerador.integers(0, 50, por_classe)
        parte = pd.DataFrame(0.0, index=range(por_classe), columns=list(COLUNAS))
        parte["AVG"] = parte["Tot size"] = media
        parte["Number"] = float(janela)
        parte["Tot sum"] = media * janela
        parte["Rate"] = gerador.integers(1, 10_000, por_classe).astype(float)
        parte["Label"] = rotulo
        partes.append(parte)
    quadro = pd.concat(partes, ignore_index=True)
    ddos = np.flatnonzero(quadro["Label"] == "DDoS-SYN_Flood")[: por_classe // 2]
    dos = np.flatnonzero(quadro["Label"] == "DoS-SYN_Flood")[: por_classe // 2]
    quadro.loc[dos, list(COLUNAS)] = quadro.loc[ddos, list(COLUNAS)].to_numpy()
    return quadro


def gravar_amostra(caminho, quadro):
    """Grava o quadro como a amostragem grava: CSV comprimido, com Label e Categoria no fim."""
    saida = quadro.assign(Categoria=quadro["Label"].map(CATEGORIA_DO_ROTULO))
    texto = saida.to_csv(index=False, lineterminator="\n").encode()
    caminho.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(caminho, "wb") as arquivo:
        arquivo.write(texto)
    return hashlib.sha256(texto).hexdigest()


def vetores(X, indices):
    """Os vetores de features das linhas indicadas, como conjunto."""
    return {linha.tobytes() for linha in X[indices]}


def test_as_33_features_sao_as_39_sem_as_que_dependem_da_janela():
    assert FEATURES_39 == COLUNAS
    assert DEPENDENTES_DA_JANELA == ("Number", "Tot sum", "ack_count", "syn_count", "fin_count", "rst_count")
    assert len(FEATURES_33) == 33
    assert not set(FEATURES_33) & set(DEPENDENTES_DA_JANELA)
    assert list(FEATURES_33) == [coluna for coluna in COLUNAS if coluna not in DEPENDENTES_DA_JANELA]
    assert CONJUNTOS_DE_FEATURES == {"39": FEATURES_39, "33": FEATURES_33}


def test_matriz_traz_so_as_colunas_pedidas_na_ordem_pedida():
    quadro = quadro_sintetico(por_classe=4)
    X = matriz(quadro, FEATURES_33)
    assert X.shape == (36, 33) and X.dtype == np.float32
    assert np.array_equal(X[:, FEATURES_33.index("AVG")], quadro["AVG"].to_numpy(dtype=np.float32))
    completa = matriz(quadro, FEATURES_39)
    assert completa.shape == (36, 39)
    assert np.array_equal(completa[:, COLUNAS.index("Number")], quadro["Number"].to_numpy(dtype=np.float32))
    # As 33 são as 39 sem as seis colunas, e nada mais muda.
    mantidas = [COLUNAS.index(coluna) for coluna in FEATURES_33]
    assert np.array_equal(completa[:, mantidas], X)


def test_matriz_troca_infinito_por_vazio_e_mantem_o_vazio():
    quadro = quadro_sintetico(por_classe=2)
    quadro.loc[0, "Rate"] = np.inf
    quadro.loc[1, "Rate"] = -np.inf
    quadro.loc[2, "Std"] = np.nan
    X = matriz(quadro, FEATURES_39)
    rate, std = COLUNAS.index("Rate"), COLUNAS.index("Std")
    assert np.isnan(X[0, rate]) and np.isnan(X[1, rate]) and np.isnan(X[2, std])
    assert int(np.isnan(X).sum()) == 3
    assert not np.isinf(X).any()
    # O quadro de origem não é alterado.
    assert np.isinf(quadro.loc[0, "Rate"])


def test_matriz_recusa_quadro_sem_alguma_das_colunas():
    quadro = quadro_sintetico(por_classe=2).drop(columns=["IAT", "Min"])
    with pytest.raises(ValueError, match="faltam as colunas Min, IAT"):
        matriz(quadro, FEATURES_39)


def test_alvo_de_8_categorias_e_o_agrupamento_dos_autores():
    assert ALVOS["8"].classes == CATEGORIAS
    rotulos = np.array(["DDoS-ICMP_Flood", "DoS-SYN_Flood", "XSS", "BenignTraffic"], dtype=object)
    assert alvo(rotulos, "8").tolist() == ["DDoS", "DoS", "Web", "Benign"]


def test_alvo_de_7_categorias_funde_ddos_e_dos():
    assert FUSAO == "DDoS+DoS"
    assert ALVOS["7"].classes == (FUSAO, "Mirai", "Recon", "Spoofing", "Web", "BruteForce", "Benign")
    y = alvo(np.array(ROTULOS, dtype=object), "7")
    for rotulo, classe in zip(ROTULOS, y):
        categoria = CATEGORIA_DO_ROTULO[rotulo]
        assert classe == (FUSAO if categoria in ("DDoS", "DoS") else categoria)
    assert sorted(set(y)) == sorted(ALVOS["7"].classes)
    assert (y == FUSAO).sum() == 16  # 12 rótulos de DDoS e 4 de DoS


def test_alvos_de_34_classes_e_binario():
    rotulos = np.array(ROTULOS, dtype=object)
    assert ALVOS["34"].classes == ROTULOS
    assert alvo(rotulos, "34").tolist() == list(ROTULOS)
    assert ALVOS["2"].classes == ("Attack", "Benign")
    binario = alvo(rotulos, "2")
    assert (binario == "Benign").sum() == 1 and (binario == "Attack").sum() == 33


def test_cada_alvo_sabe_como_chama_o_trafego_benigno():
    assert {nome: definicao.benigno for nome, definicao in ALVOS.items()} == {
        "34": "BenignTraffic", "8": "Benign", "7": "Benign", "2": "Benign",
    }


def test_alvo_recusa_rotulo_fora_das_34_classes_e_alvo_desconhecido():
    with pytest.raises(ValueError, match="rótulo desconhecido"):
        alvo(np.array(["DDoS-ICMP_Flood", "Exfiltracao"], dtype=object), "8")
    with pytest.raises(ValueError, match="alvo desconhecido"):
        alvo(np.array(["XSS"], dtype=object), "5")


def test_agrupar_da_o_mesmo_numero_a_vetores_identicos():
    X = np.array([[1.0, 2.0], [3.0, 4.0], [1.0, 2.0], [1.0, 2.5], [3.0, 4.0]], dtype=np.float32)
    grupos = agrupar(X)
    assert grupos[0] == grupos[2] and grupos[1] == grupos[4]
    assert len({grupos[0], grupos[1], grupos[3]}) == 3
    assert sorted(set(grupos.tolist())) == [0, 1, 2]


def test_agrupar_trata_vazio_como_igual_a_vazio_e_zero_negativo_como_zero():
    X = np.array([[np.nan, 1.0], [np.nan, 1.0], [0.0, 1.0], [-0.0, 1.0], [np.nan, 2.0]], dtype=np.float32)
    grupos = agrupar(X)
    assert grupos[0] == grupos[1]
    assert grupos[2] == grupos[3]
    assert len(set(grupos.tolist())) == 3
    # A matriz de entrada não é alterada.
    assert np.signbit(X[3, 0])


def test_divisao_estratificada_guarda_20_por_cento_de_cada_classe():
    quadro = quadro_sintetico(por_classe=50)
    rotulos = quadro["Label"].to_numpy()
    treino, teste = dividir_estratificada(rotulos, semente=7)
    assert FRACAO_DE_TESTE == 0.2
    assert len(teste) == 90 and len(treino) == 360
    assert not set(treino) & set(teste)
    assert sorted([*treino, *teste]) == list(range(450))
    assert list(treino) == sorted(treino) and list(teste) == sorted(teste)
    for rotulo, _, _ in CLASSES_DO_CASO:
        assert (rotulos[teste] == rotulo).sum() == 10
        assert (rotulos[treino] == rotulo).sum() == 40


def test_divisao_estratificada_respeita_classes_de_tamanhos_diferentes():
    rotulos = np.array(["DDoS-ICMP_Flood"] * 1000 + ["XSS"] * 50 + ["BenignTraffic"] * 200, dtype=object)
    _, teste = dividir_estratificada(rotulos, semente=1)
    assert [(rotulos[teste] == r).sum() for r in ("DDoS-ICMP_Flood", "XSS", "BenignTraffic")] == [200, 10, 40]


def test_divisao_estratificada_e_a_mesma_com_a_mesma_semente():
    rotulos = quadro_sintetico(por_classe=50)["Label"].to_numpy()
    primeira, segunda = dividir_estratificada(rotulos, semente=7), dividir_estratificada(rotulos, semente=7)
    assert np.array_equal(primeira[0], segunda[0]) and np.array_equal(primeira[1], segunda[1])
    outra = dividir_estratificada(rotulos, semente=8)
    assert not np.array_equal(primeira[1], outra[1])
    padrao = dividir_estratificada(rotulos)
    assert np.array_equal(padrao[1], dividir_estratificada(rotulos, semente=SEMENTE)[1])


def test_divisao_por_grupos_nao_deixa_o_mesmo_vetor_dos_dois_lados():
    quadro = quadro_sintetico(por_classe=50)
    # Cada linha ganha duas cópias: sem os grupos, as cópias cairiam dos dois lados.
    quadro = pd.concat([quadro, quadro, quadro], ignore_index=True)
    rotulos = quadro["Label"].to_numpy()
    X = matriz(quadro, FEATURES_33)
    grupos = agrupar(X)
    treino, teste = dividir_por_grupos(grupos, rotulos, semente=7)
    assert not set(grupos[treino]) & set(grupos[teste])
    assert not vetores(X, treino) & vetores(X, teste)
    assert not set(treino) & set(teste)
    assert sorted([*treino, *teste]) == list(range(len(quadro)))
    # O sorteio de linhas, na mesma amostra, deixa vetores repetidos entre os dois lados.
    treino_e, teste_e = dividir_estratificada(rotulos, semente=7)
    assert vetores(X, treino_e) & vetores(X, teste_e)


def test_divisao_por_grupos_vale_para_as_39_quando_os_grupos_sao_das_33():
    quadro = quadro_sintetico(por_classe=50)
    # Cópias que só diferem em colunas dependentes da janela: iguais nas 33, diferentes nas 39.
    copia = quadro.copy()
    copia["Number"] = copia["Number"] - 1
    copia["Tot sum"] = copia["AVG"] * copia["Number"]
    quadro = pd.concat([quadro, copia], ignore_index=True)
    rotulos = quadro["Label"].to_numpy()
    X33, X39 = matriz(quadro, FEATURES_33), matriz(quadro, FEATURES_39)
    assert agrupar(X39).max() > agrupar(X33).max()
    treino, teste = dividir_por_grupos(agrupar(X33), rotulos, semente=3)
    assert not vetores(X33, treino) & vetores(X33, teste)
    assert not vetores(X39, treino) & vetores(X39, teste)


def test_divisao_por_grupos_fica_perto_de_20_por_cento_em_cada_classe():
    quadro = quadro_sintetico(por_classe=200)
    rotulos = quadro["Label"].to_numpy()
    grupos = agrupar(matriz(quadro, FEATURES_33))
    _, teste = dividir_por_grupos(grupos, rotulos, semente=7)
    assert 0.18 <= len(teste) / len(quadro) <= 0.22
    for rotulo, _, _ in CLASSES_DO_CASO:
        no_teste = (rotulos[teste] == rotulo).sum()
        assert 25 <= no_teste <= 55, rotulo  # 40 seriam os 20% exatos; a faixa cobre os grupos de vários rótulos


def test_divisao_por_grupos_e_a_mesma_com_a_mesma_semente():
    quadro = quadro_sintetico(por_classe=50)
    rotulos = quadro["Label"].to_numpy()
    grupos = agrupar(matriz(quadro, FEATURES_33))
    primeira, segunda = dividir_por_grupos(grupos, rotulos, semente=7), dividir_por_grupos(grupos, rotulos, semente=7)
    assert np.array_equal(primeira[0], segunda[0]) and np.array_equal(primeira[1], segunda[1])
    assert not np.array_equal(primeira[1], dividir_por_grupos(grupos, rotulos, semente=8)[1])


def test_divisao_recusa_classe_pequena_demais_para_ter_treino_e_teste():
    rotulos = np.array(["DDoS-ICMP_Flood"] * 20 + ["XSS"], dtype=object)
    with pytest.raises(ValueError, match="XSS"):
        dividir_estratificada(rotulos)
    X = np.arange(21, dtype=np.float32).reshape(-1, 1)
    with pytest.raises(ValueError, match="XSS"):
        dividir_por_grupos(agrupar(X), rotulos)


def test_dividir_escolhe_o_metodo_pelo_nome_e_agrupa_pelas_33_features():
    quadro = quadro_sintetico(por_classe=50)
    copia = quadro.copy()
    copia["Number"] = copia["Number"] - 1
    copia["Tot sum"] = copia["AVG"] * copia["Number"]
    quadro = pd.concat([quadro, copia], ignore_index=True)
    rotulos = quadro["Label"].to_numpy()
    assert DIVISOES == ("estratificada", "grupos")
    treino, teste = dividir(quadro, "estratificada", semente=5)
    esperado = dividir_estratificada(rotulos, semente=5)
    assert np.array_equal(treino, esperado[0]) and np.array_equal(teste, esperado[1])
    treino, teste = dividir(quadro, "grupos", semente=5)
    esperado = dividir_por_grupos(agrupar(matriz(quadro, FEATURES_33)), rotulos, semente=5)
    assert np.array_equal(treino, esperado[0]) and np.array_equal(teste, esperado[1])
    with pytest.raises(ValueError, match="divisão desconhecida"):
        dividir(quadro, "temporal")


def test_impressao_digital_muda_com_a_divisao():
    assert impressao_digital(np.array([1, 5, 9])) == impressao_digital(np.array([1, 5, 9], dtype=np.int32))
    assert impressao_digital(np.array([1, 5, 9])) != impressao_digital(np.array([1, 5, 8]))
    assert len(impressao_digital(np.array([1, 5, 9]))) == 64


def test_ler_devolve_as_39_colunas_em_ponto_flutuante_e_o_hash_do_csv(tmp_path):
    quadro = quadro_sintetico(por_classe=3)
    resumo = gravar_amostra(tmp_path / "amostra.csv.gz", quadro)
    lido, sha256 = ler(tmp_path / "amostra.csv.gz")
    assert sha256 == resumo
    assert list(lido.columns) == [*COLUNAS, "Label", "Categoria"]
    assert all(lido[coluna].dtype == np.float64 for coluna in COLUNAS)
    assert np.array_equal(lido[list(COLUNAS)].to_numpy(), quadro[list(COLUNAS)].to_numpy())


def test_ler_aceita_csv_sem_compressao_e_nao_perde_digitos(tmp_path):
    caminho = tmp_path / "captura.csv"
    valores = dict.fromkeys(COLUNAS, "0") | {"Rate": "0.1234567890123456789", "IAT": "inf", "Std": ""}
    caminho.write_text(",".join(COLUNAS) + "\n" + ",".join(valores[coluna] for coluna in COLUNAS) + "\n")
    lido, sha256 = ler(caminho)
    assert sha256 == hashlib.sha256(caminho.read_bytes()).hexdigest()
    assert lido.loc[0, "Rate"] == float("0.1234567890123456789")
    assert np.isinf(lido.loc[0, "IAT"]) and np.isnan(lido.loc[0, "Std"])
    assert "Label" not in lido.columns


def test_ler_recusa_arquivo_sem_as_39_colunas_ou_com_texto_no_lugar_de_numero(tmp_path):
    caminho = tmp_path / "a.csv"
    caminho.write_text("Rate,Label\n1.0,XSS\n")
    with pytest.raises(ValueError, match="a.csv: faltam as colunas Header_Length"):
        ler(caminho)
    valores = dict.fromkeys(COLUNAS, "0") | {"Rate": "muito"}
    caminho.write_text(",".join(COLUNAS) + "\n" + ",".join(valores[coluna] for coluna in COLUNAS) + "\n")
    with pytest.raises(ValueError, match="a.csv: valor que não é número"):
        ler(caminho)
    caminho.write_text("")
    with pytest.raises(ValueError, match="a.csv: arquivo vazio"):
        ler(caminho)


def test_carregar_normaliza_os_rotulos_e_exige_a_coluna_label(tmp_path):
    quadro = quadro_sintetico(por_classe=2)
    quadro["Label"] = quadro["Label"].str.upper().replace("BENIGNTRAFFIC", "BENIGN")
    caminho = tmp_path / "amostra.csv.gz"
    with gzip.open(caminho, "wb") as arquivo:
        arquivo.write(quadro.to_csv(index=False).encode())
    lido, _ = carregar(caminho)
    assert sorted(set(lido["Label"])) == sorted(rotulo for rotulo, _, _ in CLASSES_DO_CASO)
    with gzip.open(caminho, "wb") as arquivo:
        arquivo.write(quadro.drop(columns="Label").to_csv(index=False).encode())
    with pytest.raises(ValueError, match="falta a coluna Label"):
        carregar(caminho)


def test_carregar_recusa_rotulo_desconhecido_e_amostra_sem_linhas(tmp_path):
    quadro = quadro_sintetico(por_classe=2)
    quadro.loc[0, "Label"] = "Exfiltracao"
    caminho = tmp_path / "amostra.csv.gz"
    gravar_amostra(caminho, quadro.assign(Label=quadro["Label"]).drop(index=0))
    assert len(carregar(caminho)[0]) == 17
    with gzip.open(caminho, "wb") as arquivo:
        arquivo.write(quadro.to_csv(index=False).encode())
    with pytest.raises(ValueError, match="rótulo desconhecido: 'Exfiltracao'"):
        carregar(caminho)
    with gzip.open(caminho, "wb") as arquivo:
        arquivo.write(quadro.iloc[:0].to_csv(index=False).encode())
    with pytest.raises(ValueError, match="nenhuma linha"):
        carregar(caminho)


def test_carregar_aceita_o_rotulo_de_fora_quando_o_arquivo_nao_tem_label(tmp_path):
    # A saída do extrator traz só as 39 colunas: o rótulo da captura é dito por quem a gravou.
    quadro = quadro_sintetico(por_classe=2)
    caminho = tmp_path / "captura.csv"
    quadro[list(COLUNAS)].to_csv(caminho, index=False)
    lido, _ = carregar(caminho, rotulo="ddos-http_flood")
    assert set(lido["Label"]) == {"DDoS-HTTP_Flood"} and len(lido) == 18
    with pytest.raises(ValueError, match="captura.csv: falta a coluna Label"):
        carregar(caminho)
    with pytest.raises(ValueError, match="rótulo desconhecido"):
        carregar(caminho, rotulo="Exfiltracao")
    quadro.to_csv(caminho, index=False)
    with pytest.raises(ValueError, match="captura.csv: o arquivo já traz a coluna Label"):
        carregar(caminho, rotulo="XSS")


@pytest.mark.skipif(not AMOSTRA.exists(), reason="amostra ausente")
def test_amostra_real_e_a_do_manifesto_e_a_divisao_por_grupos_nao_repete_vetor():
    quadro, sha256 = carregar(AMOSTRA)
    manifesto = json.loads(MANIFESTO_DA_AMOSTRA.read_text(encoding="utf-8"))
    assert sha256 == manifesto["saida"]["sha256_do_csv_descomprimido"]
    assert len(quadro) == manifesto["saida"]["linhas"]
    assert quadro["Label"].value_counts().to_dict() == {
        classe["rotulo"]: classe["amostra"] for classe in manifesto["classes"]
    }
    rotulos = quadro["Label"].to_numpy()
    X33, X39 = matriz(quadro, FEATURES_33), matriz(quadro, FEATURES_39)
    treino, teste = dividir_por_grupos(agrupar(X33), rotulos)
    assert 0.19 <= len(teste) / len(quadro) <= 0.21
    grupos39 = agrupar(X39)
    assert not np.isin(grupos39[teste], grupos39[treino]).any()
    # O sorteio de linhas deixa parte do teste com vetor que também está no treino.
    treino_e, teste_e = dividir_estratificada(rotulos)
    assert np.isin(grupos39[teste_e], grupos39[treino_e]).mean() > 0.01
