import json
import math
import re
from collections import Counter
from pathlib import Path

import pytest

from codigo.classificador.mapeamento import (
    BINARIO_DO_ROTULO,
    CATEGORIA_DO_ROTULO,
    CATEGORIAS,
    ROTULOS,
    binario,
    categoria,
    normalizar,
)

DATASET = Path(__file__).resolve().parents[2] / "CICIoT2023"
NOTEBOOK = DATASET / "example.ipynb"
MERGED01 = DATASET / "MERGED_CSV" / "Merged01.csv"


def test_sao_34_rotulos_distintos():
    assert len(ROTULOS) == 34
    assert len(set(ROTULOS)) == 34


def test_rotulos_continuam_distintos_sem_diferenciar_maiusculas():
    assert len({rotulo.casefold() for rotulo in ROTULOS}) == 34


@pytest.mark.parametrize("no_merged,canonico", [
    ("DDOS-ICMP_FLOOD", "DDoS-ICMP_Flood"),
    ("DDOS-RSTFINFLOOD", "DDoS-RSTFINFlood"),
    ("DDOS-PSHACK_FLOOD", "DDoS-PSHACK_Flood"),
    ("DDOS-SYNONYMOUSIP_FLOOD", "DDoS-SynonymousIP_Flood"),
    ("DOS-HTTP_FLOOD", "DoS-HTTP_Flood"),
    ("MIRAI-GREETH_FLOOD", "Mirai-greeth_flood"),
    ("MIRAI-UDPPLAIN", "Mirai-udpplain"),
    ("MITM-ARPSPOOFING", "MITM-ArpSpoofing"),
    ("DICTIONARYBRUTEFORCE", "DictionaryBruteForce"),
    ("SQLINJECTION", "SqlInjection"),
    ("XSS", "XSS"),
])
def test_rotulo_em_maiusculas_como_no_merged_csv(no_merged, canonico):
    assert normalizar(no_merged) == canonico


def test_rotulo_em_minusculas():
    assert normalizar("ddos-icmp_flood") == "DDoS-ICMP_Flood"
    assert normalizar("recon-portscan") == "Recon-PortScan"


@pytest.mark.parametrize("rotulo", ROTULOS)
def test_qualquer_grafia_de_um_rotulo_leva_ao_canonico(rotulo):
    assert normalizar(rotulo) == rotulo
    assert normalizar(rotulo.upper()) == rotulo
    assert normalizar(rotulo.lower()) == rotulo


@pytest.mark.parametrize("grafia", ["BENIGN", "BenignTraffic", "BENIGNTRAFFIC", "Benign_Final", "benign"])
def test_trafego_benigno_tem_tres_nomes_no_dataset(grafia):
    # MERGED_CSV: BENIGN. Dicionário dos autores: BenignTraffic. Pasta dos CSVs por ataque: Benign_Final.
    assert normalizar(grafia) == "BenignTraffic"


def test_espacos_e_fim_de_linha_em_volta_sao_ignorados():
    assert normalizar("  DDOS-ICMP_FLOOD\r\n") == "DDoS-ICMP_Flood"


@pytest.mark.parametrize("rotulo", [
    "", " ", "DDoS", "DDOS-ICMP", "DDOS-ICMP_FLOOD2", "DDOS ICMP FLOOD", "BENIGNO", "Exfiltration",
    None, math.nan, 7, b"XSS",
])
def test_rotulo_desconhecido_da_erro(rotulo):
    with pytest.raises(ValueError, match="rótulo desconhecido"):
        normalizar(rotulo)


def test_erro_mostra_o_rotulo_recebido():
    with pytest.raises(ValueError, match="'DDOS-NOVO_ATAQUE'"):
        normalizar("DDOS-NOVO_ATAQUE")


def test_as_34_classes_tem_categoria():
    assert set(CATEGORIA_DO_ROTULO) == set(ROTULOS)
    assert set(CATEGORIA_DO_ROTULO.values()) == set(CATEGORIAS)


def test_sao_8_categorias_com_as_quantidades_do_artigo():
    assert CATEGORIAS == ("DDoS", "DoS", "Mirai", "Recon", "Spoofing", "Web", "BruteForce", "Benign")
    assert Counter(CATEGORIA_DO_ROTULO.values()) == {
        "DDoS": 12, "DoS": 4, "Mirai": 3, "Recon": 5, "Spoofing": 2, "Web": 6, "BruteForce": 1, "Benign": 1,
    }


@pytest.mark.parametrize("rotulo,esperada", [
    ("DDOS-ICMP_FLOOD", "DDoS"),
    ("DDoS-SlowLoris", "DDoS"),
    ("DOS-UDP_FLOOD", "DoS"),
    ("MIRAI-GREIP_FLOOD", "Mirai"),
    ("VULNERABILITYSCAN", "Recon"),
    ("RECON-PINGSWEEP", "Recon"),
    ("DNS_SPOOFING", "Spoofing"),
    ("MITM-ARPSPOOFING", "Spoofing"),
    ("BACKDOOR_MALWARE", "Web"),
    ("UPLOADING_ATTACK", "Web"),
    ("DICTIONARYBRUTEFORCE", "BruteForce"),
    ("BENIGN", "Benign"),
])
def test_categoria_aceita_a_grafia_do_merged_csv(rotulo, esperada):
    assert categoria(rotulo) == esperada


def test_categoria_de_rotulo_desconhecido_da_erro():
    with pytest.raises(ValueError, match="rótulo desconhecido"):
        categoria("DDOS")


def test_agrupamento_binario():
    assert set(BINARIO_DO_ROTULO) == set(ROTULOS)
    benignos = [rotulo for rotulo, grupo in BINARIO_DO_ROTULO.items() if grupo == "Benign"]
    assert benignos == ["BenignTraffic"]
    assert set(BINARIO_DO_ROTULO.values()) == {"Attack", "Benign"}
    assert binario("BENIGN") == "Benign"
    assert binario("ddos-icmp_flood") == "Attack"
    with pytest.raises(ValueError, match="rótulo desconhecido"):
        binario("")


def test_binario_e_categoria_concordam():
    for rotulo in ROTULOS:
        assert (BINARIO_DO_ROTULO[rotulo] == "Benign") == (CATEGORIA_DO_ROTULO[rotulo] == "Benign")


def _dicionario_do_notebook(nome):
    celulas = json.loads(NOTEBOOK.read_text(encoding="utf-8"))["cells"]
    fonte = "\n".join("".join(celula["source"]) for celula in celulas)
    return dict(re.findall(rf"{nome}\['([^']+)'\]\s*=\s*'([^']+)'", fonte))


@pytest.mark.skipif(not NOTEBOOK.exists(), reason="dataset ausente")
def test_agrupamento_igual_ao_do_notebook_dos_autores():
    assert CATEGORIA_DO_ROTULO == _dicionario_do_notebook("dict_7classes")
    assert BINARIO_DO_ROTULO == _dicionario_do_notebook("dict_2classes")


@pytest.mark.skipif(not MERGED01.exists(), reason="dataset ausente")
def test_rotulos_do_merged_csv_sao_os_34_conhecidos():
    vistos = set()
    with open(MERGED01, encoding="utf-8") as arquivo:
        next(arquivo)
        for _, linha in zip(range(300_000), arquivo):
            vistos.add(linha.rsplit(",", 1)[1].strip())
    assert {normalizar(rotulo) for rotulo in vistos} == set(ROTULOS)
    assert "BENIGN" in vistos and "BenignTraffic" not in vistos
