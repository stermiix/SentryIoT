import math
from pathlib import Path

import pytest

from codigo.captura.calibrar import (
    calibrar_pcap,
    colunas_divergentes,
    encaixar,
    fatiar,
    ler_oficial,
    main,
    montar_relatorio,
    valores_iguais,
)
from codigo.captura.extrator import COLUNAS, extrair, gravar_csv, ler_pcap
from codigo.captura.test_extrator import pcap, quadro_tcp, quadro_udp


def linha(valor):
    return {coluna: float(valor) for coluna in COLUNAS}


def test_fatiar_abre_pedaco_novo_depois_de_passar_do_limite():
    quadros = [(float(i), b"\x00" * 1000) for i in range(7)]
    assert [len(p) for p in fatiar(quadros, limite=3000)] == [3, 3, 1]
    assert list(fatiar([])) == []


@pytest.mark.parametrize("a,b,esperado", [
    (1.0, 1.0, True),
    (1.0, 1.0 + 1e-12, True),
    (1.0, 1.001, False),
    (0.0, 0.0, True),
    (math.nan, math.nan, True),
    (math.nan, 1.0, False),
    (math.inf, math.inf, True),
    (math.inf, 1e300, False),
])
def test_valores_iguais(a, b, esperado):
    assert valores_iguais(a, b) is esperado


def test_ler_oficial_converte_vazio_e_infinito(tmp_path):
    caminho = tmp_path / "oficial.csv"
    valores = ["inf" if c == "Rate" else "" if c in ("Std", "Variance") else "2" for c in COLUNAS]
    caminho.write_text(",".join(COLUNAS) + "\n" + ",".join(valores) + "\n")
    (lida,) = ler_oficial(caminho)
    assert lida["Rate"] == math.inf and math.isnan(lida["Std"]) and lida["Number"] == 2.0


def test_ler_oficial_exige_as_39_colunas(tmp_path):
    caminho = tmp_path / "oficial.csv"
    caminho.write_text("Rate,Number\n1,2\n")
    with pytest.raises(ValueError, match="colunas"):
        ler_oficial(caminho)


def test_colunas_divergentes():
    assert colunas_divergentes(linha(1), linha(1)) == []
    outra = linha(1) | {"Rate": 9.0, "IAT": 7.0}
    assert colunas_divergentes(linha(1), outra) == ["Rate", "IAT"]


def test_encaixar_segue_a_ordem_do_oficial():
    a, b = [linha(0), linha(1), linha(2)], [linha(3), linha(4)]
    assert encaixar([a, b], b + a) == b + a


def test_encaixar_mesmo_com_a_primeira_linha_do_bloco_divergente():
    a, b, c = [linha(0), linha(1), linha(2)], [linha(3), linha(4)], [linha(5), linha(6)]
    oficial = c + [linha(3) | {"Rate": 99.0}, linha(4)] + a
    assert encaixar([a, b, c], oficial) == c + b + a


DATASET = Path(__file__).resolve().parents[2] / "CICIoT2023"


def montar_caso(tmp_path, adulterar=False):
    """Pcap pequeno e um CSV 'oficial' gerado em pedaços de 1000 bytes, na ordem inversa."""
    quadros = [(i, 0, quadro_udp() if i % 3 == 0 else quadro_tcp(flags=0x10)) for i in range(35)]
    caminho_pcap = tmp_path / "Caso.pcap"
    caminho_pcap.write_bytes(pcap(quadros))
    blocos = [list(extrair(p)) for p in fatiar(ler_pcap(caminho_pcap), limite=1000)]
    linhas = [l for bloco in reversed(blocos) for l in bloco]
    if adulterar:
        linhas[1] = linhas[1] | {"Rate": linhas[1]["Rate"] * 2}
    (tmp_path / "Caso").mkdir()
    caminho_csv = tmp_path / "Caso" / "Caso.pcap.csv"
    with open(caminho_csv, "w", newline="") as arquivo:
        gravar_csv(linhas, arquivo)
    return caminho_pcap, caminho_csv, len(blocos), len(linhas)


def test_calibrar_pcap_aprova_quando_tudo_bate(tmp_path):
    caminho_pcap, caminho_csv, n_blocos, n_linhas = montar_caso(tmp_path)
    r = calibrar_pcap(caminho_pcap, caminho_csv, limite=1000)
    assert n_blocos > 1
    assert (r.pedacos, r.pacotes, r.mantidos) == (n_blocos, 35, 35)
    assert r.linhas_extraidas == r.linhas_oficiais == r.linhas_iguais == n_linhas
    assert r.aprovado and r.divergencias == {}
    assert r.tipos[0x0800] == 35


def test_calibrar_pcap_aponta_a_coluna_que_diverge(tmp_path):
    caminho_pcap, caminho_csv, _, n_linhas = montar_caso(tmp_path, adulterar=True)
    r = calibrar_pcap(caminho_pcap, caminho_csv, limite=1000)
    assert not r.aprovado
    assert r.linhas_iguais == n_linhas - 1
    assert list(r.divergencias) == ["Rate"] and r.divergencias["Rate"][0] == 1
    assert r.divergencias["Rate"][1][0] == 3  # linha 3 do arquivo CSV (a 1 é o cabeçalho)


def test_relatorio_e_saida_do_main(tmp_path, capsys):
    montar_caso(tmp_path)
    saida = tmp_path / "relatorio.md"
    # Com o limite real de 10 MB o caso vira um pedaço só, e o CSV em ordem inversa deixa de bater.
    assert main(["--dataset", str(tmp_path), "--saida", str(saida)]) == 1
    texto = saida.read_text(encoding="utf-8")
    assert "Caso" in texto and "## Divergências" in texto


def test_main_sem_dataset(tmp_path, capsys):
    assert main(["--dataset", str(tmp_path / "ausente"), "--saida", str(tmp_path / "r.md")]) == 2
    assert "nenhum pcap" in capsys.readouterr().err
    (tmp_path / "Solto.pcap").write_bytes(pcap([(1, 0, quadro_tcp())]))  # pcap sem CSV oficial
    assert main(["--dataset", str(tmp_path), "--saida", str(tmp_path / "r.md")]) == 2


def test_relatorio_sem_divergencias(tmp_path):
    caminho_pcap, caminho_csv, _, _ = montar_caso(tmp_path)
    texto = montar_relatorio([calibrar_pcap(caminho_pcap, caminho_csv, limite=1000)])
    assert "Nenhuma divergência" in texto


@pytest.mark.skipif(not (DATASET / "DictionaryBruteForce.pcap").exists(), reason="dataset ausente")
def test_dictionary_brute_force_reproduz_o_oficial():
    r = calibrar_pcap(
        DATASET / "DictionaryBruteForce.pcap",
        DATASET / "DictionaryBruteForce" / "DictionaryBruteForce.pcap.csv",
    )
    assert (r.pacotes, r.mantidos, r.pedacos) == (133138, 130632, 4)
    assert r.linhas_oficiais == 13064
    assert r.aprovado, r.divergencias
