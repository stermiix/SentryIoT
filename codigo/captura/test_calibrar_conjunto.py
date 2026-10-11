import csv
import hashlib
import json
import math
import struct
from pathlib import Path

import numpy as np
import pytest

from codigo.captura.calibrar import fatiar
from codigo.captura.calibrar_conjunto import (
    MANIFESTO,
    RELATORIO,
    TABELA_PCAPS,
    TABELA_ROTULOS,
    VARIANTES,
    amostra_sem_par,
    cabecalho_pcap,
    contar_comuns,
    extrair_pcap,
    hashes,
    janela_da_classe,
    ks,
    ler_merged,
    main,
    presentes,
    quantizar,
    vizinhos,
)
from codigo.captura.extrator import COLUNAS, extrair, ler_pcap
from codigo.captura.test_extrator import QUADRO_IPV6, pcap, quadro_tcp, quadro_udp

I = {coluna: j for j, coluna in enumerate(COLUNAS)}
# Nome de argumento de cada coluna: "Tot sum" vira Tot_sum, "Protocol Type" vira Protocol_Type.
_ARGUMENTO = {coluna.replace(" ", "_"): coluna for coluna in COLUNAS}


def linha(**valores):
    """Uma linha com as 39 colunas: 1.0 em todas, menos as dadas."""
    base = np.ones(len(COLUNAS))
    for argumento, valor in valores.items():
        base[I[_ARGUMENTO[argumento]]] = valor
    return base


def chave(*linhas, variante="todas"):
    return hashes(quantizar(np.array(linhas)), VARIANTES[variante])


# --- chave de correspondência -----------------------------------------------------------------


def test_chave_tolera_o_arredondamento_do_texto_e_separa_valores_diferentes():
    a, b, c = chave(linha(Rate=1234.5678), linha(Rate=1234.5678 * (1 + 1e-12)), linha(Rate=1234.5678 * (1 + 1e-8)))
    assert a == b and a != c
    # O formato do Java do MERGED_CSV e o repr do Python dão o mesmo valor.
    assert chave(linha(IAT=float("3.861904144287109E-5")))[0] == chave(linha(IAT=3.861904144287109e-05))[0]


def test_chave_de_infinito_nan_e_zero_negativo():
    assert chave(linha(Rate=math.inf))[0] == chave(linha(Rate=math.inf))[0] != chave(linha(Rate=1e308))[0]
    assert chave(linha(Std=math.nan))[0] == chave(linha(Std=-math.nan))[0] != chave(linha(Std=0.0))[0]
    assert chave(linha(IAT=-0.0))[0] == chave(linha(IAT=0.0))[0]


def test_chave_depende_da_coluna_de_cada_valor():
    assert chave(linha(Rate=2.0, IAT=3.0))[0] != chave(linha(Rate=3.0, IAT=2.0))[0]


def test_variantes_da_chave_ignoram_as_colunas_de_tempo_ou_de_tamanho():
    a, b = linha(Rate=10.0, IAT=0.5), linha(Rate=99.0, IAT=0.7)
    assert chave(a)[0] != chave(b)[0]
    assert chave(a, variante="sem_tempo")[0] == chave(b, variante="sem_tempo")[0]
    c, d = linha(Min=60.0, Max=1514.0), linha(Min=42.0, Max=1500.0)
    assert chave(c, variante="sem_tamanho")[0] == chave(d, variante="sem_tamanho")[0]
    assert chave(c, variante="sem_tempo")[0] != chave(d, variante="sem_tempo")[0]


def test_correspondencia_por_multiconjunto():
    nossos = np.array([7, 7, 2, 3, 7], dtype=np.uint64)
    deles = np.sort(np.array([7, 2, 2, 5, 7], dtype=np.uint64))
    comuns, mascara = contar_comuns(nossos, deles)
    # Duas linhas 7 deles servem a duas das três nossas, na ordem em que aparecem; o 2 casa uma vez.
    assert comuns == 3
    assert mascara.tolist() == [True, True, True, False, False]
    assert contar_comuns(np.empty(0, dtype=np.uint64), deles)[0] == 0
    assert presentes(nossos, deles).tolist() == [True, True, True, False, True]
    assert presentes(nossos, np.empty(0, dtype=np.uint64)).tolist() == [False] * 5


def test_janela_da_classe_e_ks():
    assert janela_da_classe("DDoS-ICMP_Flood") == janela_da_classe("Mirai-udpplain") == 100
    assert janela_da_classe("DoS-SYN_Flood") == 100
    assert janela_da_classe("BenignTraffic") == janela_da_classe("Recon-PortScan") == 10
    assert ks(np.array([1.0, 2.0, 3.0]), np.array([1.0, 2.0, 3.0, math.inf])) == 0.0
    assert ks(np.array([1.0, 2.0]), np.array([3.0, 4.0])) == 1.0


# --- MERGED_CSV -------------------------------------------------------------------------------


def campos_merged(valores, rotulo):
    """Uma linha do MERGED_CSV como os autores a escrevem: números no formato do Java."""
    texto = []
    for coluna, valor in zip(COLUNAS, map(float, valores)):
        if math.isnan(valor):
            texto.append("")
        elif math.isinf(valor):
            texto.append("inf")
        elif coluna in ("Protocol Type", "Number", "Tot sum", "Min", "Max", "ack_count", "syn_count"):
            texto.append(str(int(valor)))
        elif "e" in repr(valor):
            mantissa, expoente = repr(valor).split("e")
            texto.append(f"{mantissa}E{int(expoente)}")
        else:
            texto.append(repr(valor))
    return [*texto, rotulo]


def gravar_merged(caminho, linhas, cortar_a_ultima=False):
    with open(caminho, "w", newline="") as arquivo:
        escritor = csv.writer(arquivo, lineterminator="\n")
        escritor.writerow([*COLUNAS, "Label"])
        for valores, rotulo in linhas:
            escritor.writerow(campos_merged(valores, rotulo))
    if cortar_a_ultima:
        dados = Path(caminho).read_bytes()
        Path(caminho).write_bytes(dados[:-15])


def test_ler_merged_entende_o_formato_dos_autores_e_descarta_a_linha_cortada(tmp_path):
    primeira = linha(Rate=math.inf, IAT=3.861904144287109e-05, Std=math.nan, Variance=math.nan, Number=100.0)
    segunda = linha(Rate=25893.962217557724, Number=10.0)
    caminho = tmp_path / "Merged01.csv"
    gravar_merged(caminho, [(primeira, "DDOS-ICMP_FLOOD"), (segunda, "BENIGN"), (segunda, "Recon-PingSweep")],
                  cortar_a_ultima=True)
    assert "E-5" in caminho.read_text()
    valores, rotulos, truncado, sha256, tamanho = ler_merged(caminho)
    assert truncado and len(valores) == 2
    assert rotulos.tolist() == ["DDoS-ICMP_Flood", "BenignTraffic"]
    assert np.array_equal(valores, np.array([primeira, segunda]), equal_nan=True)
    assert sha256 == hashlib.sha256(caminho.read_bytes()).hexdigest() and tamanho == caminho.stat().st_size


# --- extração ---------------------------------------------------------------------------------


def registro(segundos, micros, quadro, original=None):
    return struct.pack("<IIII", segundos, micros, len(quadro), original or len(quadro)) + quadro


def pcap_misto(caminho, quantos=300):
    """Pcap com TCP, UDP, IPv6, um quadro grande e registros gravados menores que o original."""
    partes = [pcap([])]
    for i in range(quantos):
        quadro = (quadro_tcp(flags=0x10), quadro_udp(), QUADRO_IPV6, quadro_tcp(dados=bytes(2000)))[i % 4]
        original = 1454 if i % 50 == 0 else None
        partes.append(registro(1_700_000_000 + i // 7, (i * 137_001) % 1_000_000, quadro, original))
    caminho.write_bytes(b"".join(partes))
    return caminho


def como_os_autores(caminho, janela, limite):
    linhas, pedacos = [], []
    for indice, pedaco in enumerate(fatiar(ler_pcap(caminho), limite)):
        bloco = [[l[c] for c in COLUNAS] for l in extrair(pedaco, janela)]
        linhas += bloco
        pedacos += [indice] * len(bloco)
    return np.array(linhas, dtype=np.float64), np.array(pedacos)


@pytest.mark.parametrize("janela,limite", [(10, 5_000), (10, 10_000_000), (100, 20_000), (7, 3_333)])
def test_extracao_fatiada_e_continua_iguais_as_do_extrator(tmp_path, janela, limite):
    caminho = pcap_misto(tmp_path / "Recon-PingSweep.pcap")
    fatiada, pedacos, continua, reg = extrair_pcap(caminho, janela, limite)
    esperada, pedacos_esperados = como_os_autores(caminho, janela, limite)
    assert np.array_equal(fatiada, esperada, equal_nan=True)
    assert pedacos.tolist() == pedacos_esperados.tolist()
    continua_esperada = np.array([[l[c] for c in COLUNAS] for l in extrair(ler_pcap(caminho), janela)])
    assert np.array_equal(continua, continua_esperada, equal_nan=True)
    assert reg["pedacos"] == len(list(fatiar(ler_pcap(caminho), limite)))
    if limite < caminho.stat().st_size:
        assert reg["pedacos"] > 1


def test_registro_da_extracao_descreve_a_captura(tmp_path):
    caminho = pcap_misto(tmp_path / "Recon-PingSweep.pcap")
    _, _, _, reg = extrair_pcap(caminho, 10)
    assert reg["pacotes"] == 300 and reg["quadros_mantidos"] == 225
    assert reg["tipos_ethernet"] == {str(0x0800): 225, str(0x86DD): 75}
    assert reg["quadros_menores_que_60"] == 3 * 75  # TCP sem dados e IPv6 com 54 bytes, UDP com 50
    assert reg["quadros_maiores_que_1514"] == 75
    assert reg["registros_menores_que_o_original"] == 6
    assert reg["sha256"] == hashlib.sha256(caminho.read_bytes()).hexdigest()
    assert (reg["formato_do_instante"], reg["limite_de_captura"], reg["enlace"]) == ("microssegundos", 262144, 1)
    assert reg["avisos"] == []
    caminho.write_bytes(caminho.read_bytes()[:-5])
    (aviso,) = extrair_pcap(caminho, 10)[3]["avisos"]
    assert aviso.startswith("pacote 300 incompleto")
    nano = tmp_path / "nano.pcap"
    nano.write_bytes(b"\x4d\x3c\xb2\xa1" + caminho.read_bytes()[4:24])
    assert cabecalho_pcap(nano)["formato_do_instante"] == "nanossegundos"


def test_amostra_das_linhas_sem_par_e_fixa_e_na_ordem():
    matriz = np.arange(100 * len(COLUNAS), dtype=np.float64).reshape(100, -1)
    mascara = np.arange(100) % 3 == 0
    a, b = amostra_sem_par(matriz, mascara, 10), amostra_sem_par(matriz, mascara, 10)
    assert np.array_equal(a, b) and len(a) == 10
    assert np.all(np.diff(a[:, 0]) > 0) and not np.isin(a[:, 0] // len(COLUNAS) % 3, [0]).any()
    assert len(amostra_sem_par(matriz, mascara, 1000)) == 66


# --- controle do vizinho ----------------------------------------------------------------------


def test_vizinho_mais_proximo_aponta_as_colunas_que_diferem(tmp_path):
    base = linha(Number=10.0, Tot_sum=600.0, Min=60.0, Max=60.0, Rate=100.0, IAT=0.01)
    so_tempo = base.copy()
    so_tempo[[I["Rate"], I["IAT"]]] = (250.0, 0.004)
    outra = base.copy()
    outra[[I["Rate"], I["Time_To_Live"], I["Header_Length"]]] = (7.0, 128.0, 32.0)
    pasta = tmp_path / "MERGED_CSV"
    pasta.mkdir()
    gravar_merged(pasta / "Merged01.csv", [(base, "XSS"), (outra, "XSS"), (base, "SqlInjection")])
    sem_candidato = linha(Number=3.0, Tot_sum=9999.0, Protocol_Type=99.0)
    resultado = vizinhos(pasta, {"XSS.pcap": ("XSS", np.array([so_tempo, sem_candidato]))})["XSS.pcap"]
    assert resultado["examinadas"] == 2
    assert (resultado["so_tempo"], resultado["sem_candidato"], resultado["tempo_e_outras"]) == (1, 1, 0)
    assert resultado["colunas"] == {"Rate": 1, "IAT": 1}


# --- ponta a ponta ----------------------------------------------------------------------------


def montar_dataset(pasta):
    """Dois pcaps e um MERGED_CSV feito das linhas deles, com perdas, sobras e um arquivo truncado.

    O Recon perde 3 linhas no MERGED_CSV e tem uma linha que aparece 3 vezes lá e 1 vez no pcap;
    o flood ganha 40 linhas de outra captura do rótulo.
    """
    pasta.mkdir()
    recon = pcap_misto(pasta / "Recon-PingSweep.pcap", 400)
    flood = pasta / "DDoS-ICMP_Flood.pcap"
    flood.write_bytes(pcap([(1_700_000_000 + i // 50, (i * 7919) % 1_000_000, quadro_udp(dados=bytes(i % 30)))
                            for i in range(1_000)]))
    linhas_recon, _ = como_os_autores(recon, 10, 10_000_000)
    linhas_flood, _ = como_os_autores(flood, 100, 10_000_000)
    outras = linhas_flood.copy()
    outras[:, I["Rate"]] += 1.5
    (pasta / "MERGED_CSV").mkdir()
    todas = [(l, "RECON-PINGSWEEP") for l in [*linhas_recon[3:], linhas_recon[5], linhas_recon[5]]]
    todas += [(l, "DDOS-ICMP_FLOOD") for l in linhas_flood]
    todas += [(l, "DDoS-ICMP_Flood") for l in np.concatenate([outras] * 4)]
    meio = len(todas) // 2
    gravar_merged(pasta / "MERGED_CSV" / "Merged01.csv", todas[:meio])
    # A última linha do segundo arquivo fica cortada no meio, como nos arquivos truncados na fonte.
    gravar_merged(pasta / "MERGED_CSV" / "Merged02.csv", [*todas[meio:], (linhas_recon[0], "XSS")],
                  cortar_a_ultima=True)
    return len(linhas_recon), len(linhas_flood)


def ler_tabela(caminho):
    with open(caminho, newline="") as arquivo:
        return {registro[next(iter(registro))]: registro for registro in csv.DictReader(arquivo)}


def test_calibracao_de_conjunto_ponta_a_ponta(tmp_path, capsys):
    n_recon, n_flood = montar_dataset(tmp_path / "ds")
    argumentos = ["--dataset", str(tmp_path / "ds"), "--processos", "1", "--saida", str(tmp_path / "saida"),
                  "--trabalho", str(tmp_path / "trabalho"), "--vizinhos", "5"]
    assert main(argumentos) == 0
    pcaps = ler_tabela(tmp_path / "saida" / TABELA_PCAPS)
    recon, flood = pcaps["Recon-PingSweep.pcap"], pcaps["DDoS-ICMP_Flood.pcap"]
    assert (int(recon["linhas"]), int(recon["com_par"]), int(recon["sem_par"])) == (n_recon, n_recon - 3, 3)
    assert (int(flood["linhas"]), int(flood["com_par"])) == (n_flood, n_flood)
    assert (recon["janela"], flood["janela"]) == ("10", "100")
    assert recon["formato_do_instante"] == "microssegundos" and int(recon["registros_menores_que_o_original"]) == 8
    assert int(recon["vizinho_examinadas"]) == 3
    rotulos = ler_tabela(tmp_path / "saida" / TABELA_ROTULOS)
    # A linha repetida no MERGED_CSV é coberta uma vez só, pela única cópia dela no pcap.
    assert int(rotulos["Recon-PingSweep"]["linhas_merged"]) == n_recon - 3 + 2
    assert int(rotulos["Recon-PingSweep"]["linhas_merged_cobertas"]) == n_recon - 3
    assert int(rotulos["DDoS-ICMP_Flood"]["linhas_merged"]) == 5 * n_flood
    assert float(rotulos["DDoS-ICMP_Flood"]["fracao_coberta"]) == pytest.approx(0.2, abs=1e-6)
    manifesto = json.loads((tmp_path / "saida" / MANIFESTO).read_text(encoding="utf-8"))
    arquivos = manifesto["merged_csv"]["arquivos"]
    assert [a["truncado"] for a in arquivos] == [False, True]
    assert all(len(a["sha256"]) == 64 for a in arquivos) and all(len(p["sha256"]) == 64 for p in manifesto["pcaps"])
    texto = (tmp_path / "saida" / RELATORIO).read_text(encoding="utf-8")
    for secao in ("## Resumo", "## Resultado por pcap", "## Cobertura por rótulo", "## Como ler os números",
                  "## Leitura contínua contra leitura fatiada", "## Linhas sem par", "## A captura de cada pcap",
                  "## Como refazer"):
        assert secao in texto
    assert "`Merged02.csv`" in texto and "2 pcaps em microssegundos" in texto
    # Na segunda execução, o índice e as extrações são reaproveitados, e os números não mudam.
    capsys.readouterr()
    assert main(argumentos) == 0
    assert "0 pcaps a extrair, 2 reaproveitados; índice reaproveitado" in capsys.readouterr().err
    de_novo = json.loads((tmp_path / "saida" / MANIFESTO).read_text(encoding="utf-8"))
    assert [p["com_par"] for p in de_novo["pcaps"]] == [p["com_par"] for p in manifesto["pcaps"]]
    assert de_novo["rotulos"] == manifesto["rotulos"]


def test_main_sem_merged_csv_ou_com_opcao_invalida(tmp_path, capsys):
    (tmp_path / "ds").mkdir()
    pcap_misto(tmp_path / "ds" / "XSS.pcap", 20)
    base = ["--dataset", str(tmp_path / "ds"), "--saida", str(tmp_path / "s"), "--trabalho", str(tmp_path / "t")]
    assert main(base) == 2
    assert "Merged" in capsys.readouterr().err
    assert main([*base, "--processos", "0"]) == 2


# --- com o dataset ----------------------------------------------------------------------------

DATASET = Path(__file__).resolve().parents[2] / "CICIoT2023"
# Rótulos pequenos em que os nossos pcaps cobrem todas as linhas do MERGED_CSV.
PEQUENOS = ("Uploading_Attack", "Recon-PingSweep", "XSS", "SqlInjection", "Backdoor_Malware", "CommandInjection",
            "BrowserHijacking")


@pytest.mark.skipif(not (DATASET / "MERGED_CSV" / "Merged01.csv").exists()
                    or not all((DATASET / f"{nome}.pcap").exists() for nome in PEQUENOS),
                    reason="dataset ausente: são necessários o MERGED_CSV e os pcaps pequenos")
def test_linhas_dos_rotulos_pequenos_num_arquivo_do_merged_csv_vem_dos_nossos_pcaps():
    valores, rotulos, *_ = ler_merged(DATASET / "MERGED_CSV" / "Merged01.csv")
    for nome in PEQUENOS:
        fatiada, _, _, reg = extrair_pcap(DATASET / f"{nome}.pcap", 10)
        deles = valores[rotulos == nome]
        assert len(deles) > 0, nome
        # Toda linha do rótulo neste arquivo é uma janela do nosso pcap, extraída como os autores extraíram.
        comuns, _ = contar_comuns(hashes(quantizar(deles)), np.sort(hashes(quantizar(fatiada))))
        assert comuns == len(deles), nome
        assert reg["formato_do_instante"] == "microssegundos"


@pytest.mark.skipif(not DATASET.is_dir() or not list(DATASET.glob("*.pcap")), reason="dataset ausente")
def test_pcaps_do_dataset_estao_em_microssegundos():
    # O instante em nanossegundos seria truncado para microssegundos; nos pcaps do dataset não há nada a truncar.
    formatos = {cabecalho_pcap(caminho)["formato_do_instante"] for caminho in DATASET.glob("*.pcap")}
    assert formatos == {"microssegundos"}
