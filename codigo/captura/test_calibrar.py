import math
from pathlib import Path

import pytest

from codigo.captura.calibrar import (
    LIMITE_PEDACO,
    calibrar_pcap,
    colunas_divergentes,
    encaixar,
    fatiar,
    janela_do_oficial,
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
    assert "Caso" in texto and "| pcap | coluna |" in texto


def test_main_sem_dataset(tmp_path, capsys):
    assert main(["--dataset", str(tmp_path / "ausente"), "--saida", str(tmp_path / "r.md")]) == 2
    assert "nenhum pcap" in capsys.readouterr().err
    (tmp_path / "Solto.pcap").write_bytes(pcap([(1, 0, quadro_tcp())]))  # pcap sem CSV oficial
    assert main(["--dataset", str(tmp_path), "--saida", str(tmp_path / "r.md")]) == 2


def test_relatorio_sem_divergencias(tmp_path):
    caminho_pcap, caminho_csv, _, _ = montar_caso(tmp_path)
    texto = montar_relatorio([calibrar_pcap(caminho_pcap, caminho_csv, limite=1000)])
    assert "Nenhuma divergência" in texto
    assert "limite de captura declarado" in texto


@pytest.mark.skipif(not (DATASET / "DictionaryBruteForce.pcap").exists(), reason="dataset ausente")
def test_dictionary_brute_force_reproduz_o_oficial():
    r = calibrar_pcap(
        DATASET / "DictionaryBruteForce.pcap",
        DATASET / "DictionaryBruteForce" / "DictionaryBruteForce.pcap.csv",
    )
    assert (r.pacotes, r.mantidos, r.pedacos) == (133138, 130632, 4)
    assert r.linhas_oficiais == 13064
    assert r.aprovado, r.divergencias


def test_tolerancia_da_comparacao():
    assert valores_iguais(1.0, 1.0 + 1e-10) is True
    assert valores_iguais(1.0, 1.0 + 1e-8) is False


def test_fatiar_conta_os_cabecalhos_do_arquivo_e_de_cada_pacote():
    quadros = [(float(i), b"\x00" * 22) for i in range(7)]  # cada pacote ocupa 22 + 16 bytes
    assert [len(p) for p in fatiar(quadros, limite=99)] == [2, 2, 2, 1]
    assert [len(p) for p in fatiar(quadros, limite=100)] == [3, 3, 1]
    assert LIMITE_PEDACO == 10_000_000


def test_reprovado_quando_sobra_linha_extraida(tmp_path):
    caminho_pcap, caminho_csv, _, n_linhas = montar_caso(tmp_path)
    linhas = caminho_csv.read_text().splitlines()
    caminho_csv.write_text("\n".join(linhas[:-1]) + "\n")
    r = calibrar_pcap(caminho_pcap, caminho_csv, limite=1000)
    assert (r.linhas_extraidas, r.linhas_oficiais) == (n_linhas, n_linhas - 1)
    assert not r.aprovado


def test_encaixar_com_uma_coluna_errada_em_todas_as_linhas():
    a, b, c = [linha(0), linha(1), linha(2)], [linha(3), linha(4)], [linha(5), linha(6)]
    oficial = [registro | {"IAT": registro["IAT"] * 1000 + 1} for registro in c + b + a]
    alinhadas = encaixar([a, b, c], oficial)
    assert alinhadas == c + b + a
    erradas = {col for minha, dele in zip(alinhadas, oficial) for col in colunas_divergentes(minha, dele)}
    assert erradas == {"IAT"}


def test_calibrar_descobre_a_janela_pelo_csv_oficial(tmp_path):
    caminho_pcap = tmp_path / "Flood.pcap"
    caminho_pcap.write_bytes(pcap([(i, 0, quadro_tcp(flags=0x10)) for i in range(250)]))
    (tmp_path / "Flood").mkdir()
    caminho_csv = tmp_path / "Flood" / "Flood.pcap.csv"
    with open(caminho_csv, "w", newline="") as arquivo:
        gravar_csv(extrair(ler_pcap(caminho_pcap), janela=100), arquivo)
    r = calibrar_pcap(caminho_pcap, caminho_csv)
    assert r.janela == 100
    assert r.aprovado and r.linhas_oficiais == 3


def test_main_acha_csv_de_pcap_numerado_e_reclama_do_que_nao_tem_csv(tmp_path, capsys):
    dados = pcap([(i, 0, quadro_tcp()) for i in range(30)])
    (tmp_path / "Flood1.pcap").write_bytes(dados)
    (tmp_path / "Solto.pcap").write_bytes(dados)
    (tmp_path / "Flood").mkdir()
    with open(tmp_path / "Flood" / "Flood1.pcap.csv", "w", newline="") as arquivo:
        gravar_csv(extrair(ler_pcap(tmp_path / "Flood1.pcap")), arquivo)
    saida = tmp_path / "relatorio.md"
    assert main(["--dataset", str(tmp_path), "--saida", str(saida)]) == 1
    assert "Solto.pcap" in capsys.readouterr().err
    assert "Flood1" in saida.read_text(encoding="utf-8")


def test_relatorio_declara_escopo_tolerancia_e_diferencas(tmp_path):
    caminho_pcap, caminho_csv, _, _ = montar_caso(tmp_path)
    texto = montar_relatorio([calibrar_pcap(caminho_pcap, caminho_csv, limite=1000)])
    assert "## Escopo" in texto and "janela de 10" in texto
    assert "## Diferenças conhecidas" in texto
    assert "sem tolerância" not in texto


def test_main_trata_csv_oficial_invalido_sem_derrubar_a_execucao(tmp_path, capsys):
    dados = pcap([(i, 0, quadro_tcp()) for i in range(30)])
    for nome in ("Bom", "Ruim"):
        (tmp_path / f"{nome}.pcap").write_bytes(dados)
        (tmp_path / nome).mkdir()
    with open(tmp_path / "Bom" / "Bom.pcap.csv", "w", newline="") as arquivo:
        gravar_csv(extrair(ler_pcap(tmp_path / "Bom.pcap")), arquivo)
    (tmp_path / "Ruim" / "Ruim.pcap.csv").write_text(",".join(COLUNAS) + "\n" + ",".join(["texto"] * 39) + "\n")
    saida = tmp_path / "relatorio.md"
    assert main(["--dataset", str(tmp_path), "--saida", str(saida)]) == 2
    assert "erro: Ruim.pcap" in capsys.readouterr().err
    assert "Bom" in saida.read_text(encoding="utf-8")


@pytest.mark.parametrize("valor", [math.inf, math.nan, 0.0, -5.0, 1e18])
def test_janela_absurda_no_csv_oficial_e_recusada(valor):
    with pytest.raises(ValueError, match="Number"):
        janela_do_oficial([linha(1) | {"Number": valor}])


def test_main_nao_trata_nome_de_pcap_como_padrao_de_busca(tmp_path, capsys):
    dados = pcap([(i, 0, quadro_tcp()) for i in range(30)])
    (tmp_path / "a.pcap").write_bytes(dados)
    (tmp_path / "[ab].pcap").write_bytes(dados)
    (tmp_path / "sub").mkdir()
    with open(tmp_path / "sub" / "a.pcap.csv", "w", newline="") as arquivo:
        gravar_csv(extrair(ler_pcap(tmp_path / "a.pcap")), arquivo)
    saida = tmp_path / "relatorio.md"
    assert main(["--dataset", str(tmp_path), "--saida", str(saida)]) == 1
    assert "[ab].pcap" in capsys.readouterr().err
    texto = saida.read_text(encoding="utf-8")
    assert "`a`" in texto and "[ab]" not in texto
