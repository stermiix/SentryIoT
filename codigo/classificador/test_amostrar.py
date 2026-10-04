import gzip
import hashlib
import json
import platform
from collections import Counter
from pathlib import Path

import pytest

from codigo.captura.extrator import COLUNAS
from codigo.classificador.amostrar import (
    CABECALHO,
    SEMENTE,
    TETO,
    amostrar,
    gravar,
    listar_arquivos,
    main,
    montar_manifesto,
)
from codigo.classificador.mapeamento import CATEGORIA_DO_ROTULO, ROTULOS

DATASET = Path(__file__).resolve().parents[2] / "CICIoT2023"
MERGED = DATASET / "MERGED_CSV"
MANIFESTO = Path(__file__).resolve().parents[2] / "experimentos" / "resultados" / "manifesto_amostra.json"


def linha(numero, rotulo, trocas=None):
    """Linha de CSV com as 39 features. O número fica em Header_Length e identifica a linha."""
    valores = dict.fromkeys(COLUNAS, "0") | {"Header_Length": str(numero)} | (trocas or {})
    return ",".join(valores[coluna] for coluna in COLUNAS) + "," + rotulo


def escrever(caminho, linhas, cabecalho=CABECALHO):
    caminho.write_text(",".join(cabecalho) + "\n" + "".join(texto + "\n" for texto in linhas))
    return caminho


def ler_saida(caminho):
    """Cabeçalho e linhas da amostra gravada, cada linha como lista de campos."""
    with gzip.open(caminho, "rt", encoding="utf-8", newline="") as arquivo:
        cabecalho, *linhas = arquivo.read().splitlines()
    return cabecalho.split(","), [texto.split(",") for texto in linhas]


def numeros(amostra, rotulo):
    """Números (Header_Length) das linhas sorteadas de um rótulo, na ordem da amostra."""
    return [int(features.split(b",")[0]) for features, dele in amostra.linhas if dele == rotulo]


def caso_simples(tmp_path):
    """Dois arquivos: 500 linhas de um flood, intercaladas com 7 de XSS e 3 de tráfego benigno."""
    a = [linha(i, "DDOS-ICMP_FLOOD") for i in range(300)]
    a[10:10] = [linha(1000 + i, "XSS") for i in range(4)]
    b = [linha(i, "DDOS-ICMP_FLOOD") for i in range(300, 500)]
    b[50:50] = [linha(1004 + i, "XSS") for i in range(3)] + [linha(2000 + i, "BENIGN") for i in range(3)]
    pasta = tmp_path / "MERGED_CSV"
    pasta.mkdir()
    return [escrever(pasta / "Merged01.csv", a), escrever(pasta / "Merged02.csv", b)]


def test_padroes():
    assert TETO == 50_000
    assert isinstance(SEMENTE, int)
    assert CABECALHO == (*COLUNAS, "Label")


def test_classe_rara_fica_inteira_e_classe_grande_para_no_teto(tmp_path):
    amostra = amostrar(caso_simples(tmp_path), teto=20, semente=1)
    assert Counter(rotulo for _, rotulo in amostra.linhas) == {
        "DDoS-ICMP_Flood": 20, "XSS": 7, "BenignTraffic": 3,
    }
    assert numeros(amostra, "XSS") == list(range(1000, 1007))
    assert numeros(amostra, "BenignTraffic") == [2000, 2001, 2002]


def test_classe_com_exatamente_o_teto_fica_inteira(tmp_path):
    amostra = amostrar(caso_simples(tmp_path), teto=7, semente=1)
    assert numeros(amostra, "XSS") == list(range(1000, 1007))
    assert len(numeros(amostra, "DDoS-ICMP_Flood")) == 7


def test_populacao_conta_todas_as_linhas_e_as_34_classes(tmp_path):
    amostra = amostrar(caso_simples(tmp_path), teto=20, semente=1)
    assert list(amostra.populacao) == list(ROTULOS)
    assert amostra.populacao["DDoS-ICMP_Flood"] == 500
    assert amostra.populacao["XSS"] == 7
    assert amostra.populacao["BenignTraffic"] == 3
    assert sum(amostra.populacao.values()) == 510
    assert amostra.selecionadas["DDoS-ICMP_Flood"] == 20
    assert amostra.selecionadas["Recon-PortScan"] == 0


def test_mesma_semente_da_a_mesma_amostra(tmp_path):
    arquivos = caso_simples(tmp_path)
    assert amostrar(arquivos, teto=20, semente=5).linhas == amostrar(arquivos, teto=20, semente=5).linhas


def test_sementes_diferentes_dao_amostras_diferentes(tmp_path):
    arquivos = caso_simples(tmp_path)
    assert amostrar(arquivos, teto=20, semente=5).linhas != amostrar(arquivos, teto=20, semente=6).linhas


def test_sorteio_nao_fica_preso_ao_comeco_do_conjunto(tmp_path):
    amostra = amostrar(caso_simples(tmp_path), teto=20, semente=1)
    sorteadas = numeros(amostra, "DDoS-ICMP_Flood")
    assert max(sorteadas) >= 300  # alcança o segundo arquivo
    assert sorteadas != list(range(20))


def test_sorteio_e_uniforme(tmp_path):
    # 100 linhas, teto de 10: cada linha deve sair em cerca de 10% dos sorteios, onde quer que esteja.
    arquivo = escrever(tmp_path / "a.csv", [linha(i, "DOS-UDP_FLOOD") for i in range(100)])
    vezes = Counter()
    for semente in range(400):
        vezes.update(numeros(amostrar([arquivo], teto=10, semente=semente), "DoS-UDP_Flood"))
    assert sum(vezes.values()) == 4000
    assert len(vezes) == 100
    # Esperado: 40 por linha, com desvio padrão de 6. A faixa abaixo fica a 4 desvios.
    assert 16 <= min(vezes.values()) and max(vezes.values()) <= 64


def test_amostra_segue_a_ordem_dos_arquivos_e_das_linhas(tmp_path):
    amostra = amostrar(caso_simples(tmp_path), teto=20, semente=1)
    flood = numeros(amostra, "DDoS-ICMP_Flood")
    assert flood == sorted(flood)
    rotulos = [rotulo for _, rotulo in amostra.linhas]
    # As 4 primeiras linhas de XSS estão logo depois da décima linha do primeiro arquivo.
    primeiro_xss = rotulos.index("XSS")
    assert rotulos[primeiro_xss:primeiro_xss + 4] == ["XSS"] * 4
    assert rotulos.index("BenignTraffic") > primeiro_xss + 4


def test_amostra_de_uma_classe_nao_depende_das_outras_classes(tmp_path):
    so_flood = escrever(tmp_path / "a.csv", [linha(i, "DDOS-TCP_FLOOD") for i in range(200)])
    misturado = [linha(i, "DDOS-TCP_FLOOD") for i in range(200)]
    for posicao in range(190, 0, -7):
        misturado.insert(posicao, linha(5000 + posicao, "DOS-TCP_FLOOD"))
    com_outra = escrever(tmp_path / "b.csv", misturado)
    esperado = numeros(amostrar([so_flood], teto=15, semente=3), "DDoS-TCP_Flood")
    assert numeros(amostrar([com_outra], teto=15, semente=3), "DDoS-TCP_Flood") == esperado


def test_grafias_do_mesmo_rotulo_contam_como_uma_classe(tmp_path):
    linhas = [linha(i, "BENIGN" if i % 2 else "BenignTraffic") for i in range(40)]
    amostra = amostrar([escrever(tmp_path / "a.csv", linhas)], teto=10, semente=1)
    assert amostra.populacao["BenignTraffic"] == 40
    assert len(amostra.linhas) == 10


def test_features_atravessam_como_texto_sem_conversao(tmp_path):
    # Infinito, campo vazio e notação científica do Spark saem exatamente como entraram.
    especial = linha(
        1, "DDOS-PSHACK_FLOOD", {"Rate": "inf", "Std": "", "Variance": "", "IAT": "3.861904144287109E-5"}
    )
    comum = linha(2, "RECON-PORTSCAN", {"Rate": "261.6648262868622", "AVG": "222.30", "Tot size": "-0.0"})
    amostra = amostrar([escrever(tmp_path / "a.csv", [especial, comum])], teto=5, semente=1)
    assert amostra.linhas == [
        (especial.rsplit(",", 1)[0].encode(), "DDoS-PSHACK_Flood"),
        (comum.rsplit(",", 1)[0].encode(), "Recon-PortScan"),
    ]
    assert b",inf," in amostra.linhas[0][0] and b",," in amostra.linhas[0][0]


def test_gravar_acrescenta_a_categoria_e_normaliza_o_rotulo(tmp_path):
    especial = linha(1, "DDOS-PSHACK_FLOOD", {"Rate": "inf", "Std": "", "Variance": ""})
    amostra = amostrar(
        [escrever(tmp_path / "a.csv", [especial, linha(2, "BENIGN"), linha(3, "DICTIONARYBRUTEFORCE")])],
        teto=5, semente=1,
    )
    destino = tmp_path / "amostra.csv.gz"
    gravar(amostra, destino)
    cabecalho, linhas = ler_saida(destino)
    assert cabecalho == [*COLUNAS, "Label", "Categoria"]
    assert [campos[-2:] for campos in linhas] == [
        ["DDoS-PSHACK_Flood", "DDoS"], ["BenignTraffic", "Benign"], ["DictionaryBruteForce", "BruteForce"],
    ]
    assert linhas[0][:39] == especial.split(",")[:39]
    assert all(len(campos) == 41 for campos in linhas)


def test_gravar_devolve_o_hash_do_csv_descomprimido(tmp_path):
    amostra = amostrar(caso_simples(tmp_path), teto=20, semente=1)
    destino = tmp_path / "amostra.csv.gz"
    resumo = gravar(amostra, destino)
    assert resumo == hashlib.sha256(gzip.decompress(destino.read_bytes())).hexdigest()


def test_arquivo_gravado_e_identico_em_duas_execucoes(tmp_path):
    arquivos = caso_simples(tmp_path)
    um, outro = tmp_path / "um.csv.gz", tmp_path / "outro.csv.gz"
    gravar(amostrar(arquivos, teto=20, semente=9), um)
    gravar(amostrar(arquivos, teto=20, semente=9), outro)
    assert um.read_bytes() == outro.read_bytes()


def test_rotulo_desconhecido_da_erro_com_arquivo_e_linha(tmp_path):
    linhas = [linha(1, "XSS"), linha(2, "DDOS-NOVO_ATAQUE"), linha(3, "XSS")]
    arquivo = escrever(tmp_path / "Merged07.csv", linhas)
    with pytest.raises(ValueError, match=r"Merged07\.csv, linha 3: rótulo desconhecido: 'DDOS-NOVO_ATAQUE'"):
        amostrar([arquivo])


def test_rotulo_vazio_da_erro(tmp_path):
    arquivo = escrever(tmp_path / "a.csv", [linha(1, "XSS"), linha(2, "")])
    with pytest.raises(ValueError, match="linha 3: rótulo desconhecido"):
        amostrar([arquivo])


def test_arquivo_sem_a_coluna_label_da_erro(tmp_path):
    arquivo = escrever(tmp_path / "a.csv", [",".join(["0"] * 39)], cabecalho=COLUNAS)
    with pytest.raises(ValueError, match=r"a\.csv: falta a coluna Label"):
        amostrar([arquivo])


def test_arquivo_com_label_em_minusculas_da_erro(tmp_path):
    # É como vem a versão antiga do dataset, com 46 features: outro conjunto de colunas.
    arquivo = escrever(tmp_path / "a.csv", [linha(1, "XSS")], cabecalho=(*COLUNAS, "label"))
    with pytest.raises(ValueError, match="falta a coluna Label"):
        amostrar([arquivo])


def test_arquivo_vazio_da_erro(tmp_path):
    vazio = tmp_path / "Merged02.csv"
    vazio.write_bytes(b"")
    bom = escrever(tmp_path / "Merged01.csv", [linha(1, "XSS")])
    with pytest.raises(ValueError, match=r"Merged02\.csv: arquivo vazio"):
        amostrar([bom, vazio])


def test_arquivo_so_com_cabecalho_nao_tem_linhas(tmp_path):
    so_cabecalho = escrever(tmp_path / "Merged01.csv", [])
    bom = escrever(tmp_path / "Merged02.csv", [linha(1, "XSS")])
    amostra = amostrar([so_cabecalho, bom])
    assert [(a["nome"], a["linhas"]) for a in amostra.arquivos] == [("Merged01.csv", 0), ("Merged02.csv", 1)]
    assert len(amostra.linhas) == 1


def test_colunas_diferentes_das_39_features_dao_erro(tmp_path):
    trocado = ("flow_duration", *COLUNAS[1:], "Label")
    arquivo = escrever(tmp_path / "a.csv", [linha(1, "XSS")], cabecalho=trocado)
    with pytest.raises(ValueError, match="colunas diferentes"):
        amostrar([arquivo])


def test_linha_com_campos_a_menos_ou_a_mais_da_erro(tmp_path):
    curta = escrever(tmp_path / "curta.csv", [linha(1, "XSS"), "1,2,3,XSS"])
    with pytest.raises(ValueError, match=r"curta\.csv, linha 3: 4 campos"):
        amostrar([curta])
    longa = escrever(tmp_path / "longa.csv", [linha(1, "XSS") + ",0"])
    with pytest.raises(ValueError, match=r"longa\.csv, linha 2: 41 campos"):
        amostrar([longa])


def test_linha_em_branco_e_fim_de_linha_do_windows_sao_tolerados(tmp_path):
    arquivo = tmp_path / "a.csv"
    texto = ",".join(CABECALHO) + "\r\n" + linha(1, "XSS") + "\r\n\r\n" + linha(2, "XSS") + "\r\n\n"
    arquivo.write_bytes(texto.encode())
    amostra = amostrar([arquivo])
    assert amostra.linhas == [(linha(n, "XSS").rsplit(",", 1)[0].encode(), "XSS") for n in (1, 2)]
    assert amostra.arquivos[0]["linhas"] == 2


def test_ultima_linha_sem_quebra_e_lida(tmp_path):
    arquivo = tmp_path / "a.csv"
    arquivo.write_text(",".join(CABECALHO) + "\n" + linha(1, "XSS"))
    assert len(amostrar([arquivo]).linhas) == 1


def cortar_no_fim(caminho, resto):
    """Acrescenta ao arquivo uma linha cortada, sem quebra de linha no fim."""
    with open(caminho, "a") as arquivo:
        arquivo.write(resto)


@pytest.mark.parametrize("resto", [
    "20.0,6,64.0,96067.4301420064,0.0,1.0,",  # cortada depois de uma vírgula
    "20.04,6,63.36,22035.8516339",  # cortada no meio de um número
    linha(9, "DDOS-ICMP_FLOOD")[:-3],  # cortada no meio do rótulo: os 40 campos estão lá
    linha(9, "DDOS-ICMP_FLOOD").rsplit(",", 1)[0] + ",",  # cortada antes do rótulo
])
def test_linha_final_cortada_fica_de_fora_e_e_registrada(tmp_path, resto):
    arquivo = escrever(tmp_path / "Merged42.csv", [linha(1, "XSS"), linha(2, "XSS")])
    cortar_no_fim(arquivo, resto)
    amostra = amostrar([arquivo])
    assert numeros(amostra, "XSS") == [1, 2] and len(amostra.linhas) == 2
    assert amostra.arquivos[0]["linhas"] == 2
    assert amostra.arquivos[0]["final_incompleto"] is True
    assert amostra.arquivos[0]["sha256"] == hashlib.sha256(arquivo.read_bytes()).hexdigest()


def test_linha_cortada_so_e_tolerada_no_fim_do_arquivo(tmp_path):
    arquivo = escrever(tmp_path / "a.csv", [linha(1, "XSS"), "20.04,6,63.36,22035.8516339", linha(2, "XSS")])
    with pytest.raises(ValueError, match=r"a\.csv, linha 3: 4 campos"):
        amostrar([arquivo])


def test_arquivo_inteiro_nao_tem_final_incompleto(tmp_path):
    amostra = amostrar(caso_simples(tmp_path), teto=20, semente=1)
    assert [a["final_incompleto"] for a in amostra.arquivos] == [False, False]
    sem_quebra = tmp_path / "a.csv"
    sem_quebra.write_text(",".join(CABECALHO) + "\n" + linha(1, "XSS"))
    assert amostrar([sem_quebra]).arquivos[0]["final_incompleto"] is False


def test_arquivos_registram_linhas_tamanho_e_hash(tmp_path):
    arquivos = caso_simples(tmp_path)
    amostra = amostrar(arquivos, teto=20, semente=1)
    assert [a["nome"] for a in amostra.arquivos] == ["Merged01.csv", "Merged02.csv"]
    assert [a["linhas"] for a in amostra.arquivos] == [304, 206]
    for registro, caminho in zip(amostra.arquivos, arquivos):
        assert registro["bytes"] == caminho.stat().st_size
        assert registro["sha256"] == hashlib.sha256(caminho.read_bytes()).hexdigest()


def test_teto_precisa_ser_positivo(tmp_path):
    with pytest.raises(ValueError, match="teto"):
        amostrar(caso_simples(tmp_path), teto=0)


def test_listar_arquivos_em_ordem_de_nome(tmp_path):
    for nome in ("Merged10.csv", "Merged02.csv", "Merged01.csv", "notas.txt"):
        (tmp_path / nome).write_text("")
    assert [c.name for c in listar_arquivos(tmp_path)] == ["Merged01.csv", "Merged02.csv", "Merged10.csv"]


def test_listar_arquivos_sem_csv_da_erro(tmp_path):
    with pytest.raises(ValueError, match="nenhum arquivo CSV"):
        listar_arquivos(tmp_path)
    with pytest.raises(ValueError, match="nenhum arquivo CSV"):
        listar_arquivos(tmp_path / "ausente")


def test_manifesto_tem_o_que_e_preciso_para_reproduzir(tmp_path):
    arquivos = caso_simples(tmp_path)
    amostra = amostrar(arquivos, teto=20, semente=11)
    destino = tmp_path / "amostra.csv.gz"
    resumo = gravar(amostra, destino)
    manifesto = montar_manifesto(amostra, entrada=arquivos[0].parent, saida=destino, sha256=resumo)
    assert manifesto["semente"] == 11 and manifesto["teto_por_classe"] == 20
    assert manifesto["versoes"] == {"python": platform.python_version()}
    assert manifesto["entrada"]["linhas"] == 510 and manifesto["entrada"]["arquivos"] == amostra.arquivos
    assert manifesto["entrada"]["arquivos_com_final_incompleto"] == []
    assert manifesto["saida"]["linhas"] == 30
    assert manifesto["saida"]["sha256_do_csv_descomprimido"] == resumo
    assert manifesto["saida"]["colunas"] == [*COLUNAS, "Label", "Categoria"]
    assert [classe["rotulo"] for classe in manifesto["classes"]] == list(ROTULOS)
    icmp = next(classe for classe in manifesto["classes"] if classe["rotulo"] == "DDoS-ICMP_Flood")
    assert icmp == {"rotulo": "DDoS-ICMP_Flood", "categoria": "DDoS", "populacao": 500, "amostra": 20}
    assert manifesto["categorias"]["Web"] == {"populacao": 7, "amostra": 7}
    assert manifesto["categorias"]["DoS"] == {"populacao": 0, "amostra": 0}
    assert sum(c["amostra"] for c in manifesto["classes"]) == 30
    assert all(c["categoria"] == CATEGORIA_DO_ROTULO[c["rotulo"]] for c in manifesto["classes"])
    json.dumps(manifesto)  # precisa ser serializável


def executar(tmp_path, *extras, pasta=None):
    saida, manifesto = tmp_path / "saida" / "amostra.csv.gz", tmp_path / "saida" / "manifesto.json"
    codigo = main([
        "--entrada", str(pasta or tmp_path / "MERGED_CSV"), "--saida", str(saida),
        "--manifesto", str(manifesto), *extras,
    ])
    return codigo, saida, manifesto


def test_main_grava_a_amostra_e_o_manifesto(tmp_path, capsys):
    caso_simples(tmp_path)
    codigo, saida, manifesto = executar(tmp_path, "--teto", "20", "--semente", "4")
    assert codigo == 0
    cabecalho, linhas = ler_saida(saida)
    assert len(linhas) == 30 and cabecalho[-2:] == ["Label", "Categoria"]
    registro = json.loads(manifesto.read_text(encoding="utf-8"))
    assert registro["semente"] == 4 and registro["teto_por_classe"] == 20
    assert registro["saida"]["sha256_do_csv_descomprimido"] == hashlib.sha256(
        gzip.decompress(saida.read_bytes())
    ).hexdigest()
    assert "30 linhas" in capsys.readouterr().err


def test_main_usa_o_teto_e_a_semente_padrao(tmp_path, capsys):
    caso_simples(tmp_path)
    codigo, _, manifesto = executar(tmp_path)
    registro = json.loads(manifesto.read_text(encoding="utf-8"))
    assert codigo == 0
    assert (registro["semente"], registro["teto_por_classe"]) == (SEMENTE, TETO)
    assert registro["saida"]["linhas"] == 510


def test_main_duas_execucoes_dao_os_mesmos_arquivos(tmp_path, capsys):
    caso_simples(tmp_path)
    _, saida, manifesto = executar(tmp_path, "--teto", "20")
    primeira = (saida.read_bytes(), manifesto.read_bytes())
    saida.unlink()
    manifesto.unlink()
    executar(tmp_path, "--teto", "20")
    assert (saida.read_bytes(), manifesto.read_bytes()) == primeira


def test_main_com_erro_nao_toca_na_saida_anterior(tmp_path, capsys):
    arquivos = caso_simples(tmp_path)
    codigo, saida, manifesto = executar(tmp_path, "--teto", "20")
    antes = (saida.read_bytes(), manifesto.read_bytes())
    with open(arquivos[1], "a") as arquivo:
        arquivo.write(linha(1, "ROTULO_NOVO") + "\n")
    codigo, _, _ = executar(tmp_path, "--teto", "20")
    assert codigo == 1
    assert "erro:" in capsys.readouterr().err
    assert (saida.read_bytes(), manifesto.read_bytes()) == antes
    assert sorted(p.name for p in saida.parent.iterdir()) == ["amostra.csv.gz", "manifesto.json"]


def test_main_sem_arquivos_de_entrada(tmp_path, capsys):
    codigo, saida, _ = executar(tmp_path, pasta=tmp_path / "ausente")
    assert codigo == 1
    assert "nenhum arquivo CSV" in capsys.readouterr().err
    assert not saida.exists()


def test_main_recusa_saida_que_nao_seja_csv_gz(tmp_path, capsys):
    caso_simples(tmp_path)
    codigo = main([
        "--entrada", str(tmp_path / "MERGED_CSV"), "--saida", str(tmp_path / "amostra.csv"),
        "--manifesto", str(tmp_path / "m.json"),
    ])
    assert codigo == 1
    assert ".csv.gz" in capsys.readouterr().err
    assert not (tmp_path / "amostra.csv").exists()


@pytest.mark.parametrize("teto", ["0", "-5", "muitos"])
def test_main_recusa_teto_invalido(tmp_path, capsys, teto):
    caso_simples(tmp_path)
    codigo, saida, _ = executar(tmp_path, "--teto", teto)
    assert codigo == 2
    assert not saida.exists()


def test_main_avisa_e_registra_arquivo_com_final_incompleto(tmp_path, capsys):
    arquivos = caso_simples(tmp_path)
    cortar_no_fim(arquivos[1], "20.0,6,64.0,960")
    codigo, _, manifesto = executar(tmp_path, "--teto", "20")
    assert codigo == 0
    assert "aviso: Merged02.csv termina no meio de uma linha" in capsys.readouterr().err
    registro = json.loads(manifesto.read_text(encoding="utf-8"))
    assert registro["entrada"]["arquivos_com_final_incompleto"] == ["Merged02.csv"]
    assert registro["entrada"]["linhas"] == 510 and registro["saida"]["linhas"] == 30


def test_main_avisa_das_classes_sem_linha(tmp_path, capsys):
    caso_simples(tmp_path)
    executar(tmp_path, "--teto", "20")
    assert "31 das 34 classes não têm nenhuma linha" in capsys.readouterr().err


@pytest.mark.skipif(not (MERGED / "Merged63.csv").exists(), reason="dataset ausente")
def test_merged63_real():
    amostra = amostrar([MERGED / "Merged63.csv"], teto=1000)
    assert amostra.arquivos[0]["linhas"] == 428_161
    assert amostra.populacao["DictionaryBruteForce"] == 116
    assert amostra.populacao["Recon-PortScan"] == 726
    assert all(amostra.populacao[rotulo] > 0 for rotulo in ROTULOS)
    assert all(amostra.selecionadas[rotulo] == min(1000, amostra.populacao[rotulo]) for rotulo in ROTULOS)
    assert amostra.arquivos[0]["final_incompleto"] is False
    if MANIFESTO.exists():
        registrado = json.loads(MANIFESTO.read_text(encoding="utf-8"))["entrada"]["arquivos"][-1]
        assert registrado == amostra.arquivos[0]


@pytest.mark.skipif(not (MERGED / "Merged52.csv").exists(), reason="dataset ausente")
def test_merged52_real_termina_no_meio_de_uma_linha():
    # Na cópia local do dataset, 9 dos 63 arquivos estão cortados no fim. Este é o menor deles.
    amostra = amostrar([MERGED / "Merged52.csv"], teto=100)
    assert amostra.arquivos[0]["final_incompleto"] is True
    assert amostra.arquivos[0]["linhas"] == sum(amostra.populacao.values()) > 60_000
