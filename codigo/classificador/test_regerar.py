import gzip
import json
from pathlib import Path

import pandas as pd

from codigo.captura.extrator import COLUNAS
from codigo.captura.test_extrator import pcap
from codigo.classificador.preparar import carregar
from codigo.classificador.regerar import (
    CABECALHO,
    COLUNAS_EXTRAS,
    DESCARTADAS,
    DESTINO,
    MANIFESTO,
    PARTES,
    VERSAO_DA_REGRA,
    codigo_do_extrator,
    main,
    nome_da_pasta,
)
from codigo.classificador.test_atacantes import (
    ATACANTE,
    OUTRO,
    VITIMA,
    captura_de_teste,
    quadro,
)


def preparar_dataset(pasta):
    pasta.mkdir(parents=True, exist_ok=True)
    captura_de_teste(pasta / "Recon-PortScan.pcap")
    captura_de_teste(pasta / "DoS-HTTP_Flood1.pcap")
    (pasta / "BenignTraffic.pcap").write_bytes(pcap([(i, 0, quadro(OUTRO, VITIMA)) for i in range(7)]))
    (pasta / "BenignTraffic1.pcap").write_bytes(pcap([(i, 0, quadro(VITIMA, ATACANTE)) for i in range(3)]))
    return pasta


def executar(pasta, *extras):
    return main([
        "--dataset", str(pasta / "dataset"), "--saida", str(pasta / "resultados"), "--destino", str(pasta / "regerado"),
        "--janelas", "2,5", *extras,
    ])


def ler(caminho):
    return pd.read_csv(caminho, dtype={"arquivo": str, "Label": str})


def ler_manifesto(pasta):
    return json.loads((pasta / "resultados" / MANIFESTO).read_text(encoding="utf-8"))


def ler_sem_cabecalho(caminho):
    return pd.read_csv(caminho, header=None, names=list(CABECALHO), dtype={"arquivo": str, "Label": str})


def test_pastas_e_colunas():
    assert DESTINO == "dados/processed/regerado"
    assert nome_da_pasta(10) == "janela_10"
    # As colunas novas ficam no fim: as de antes continuam nas mesmas posições.
    assert COLUNAS_EXTRAS == (
        "Label", "arquivo", "indice", "ips_origem", "ips_destino", "atacante", "quadros_atacante", "macs_atacante",
    )
    assert CABECALHO.index("indice") == 41 and CABECALHO.index("atacante") == 44
    assert (PARTES, DESCARTADAS) == ("partes", "descartadas")


def test_main_grava_um_csv_por_rotulo_e_janela_com_a_regra_de_rotulo(tmp_path, capsys):
    preparar_dataset(tmp_path / "dataset")
    assert executar(tmp_path) == 0
    regerado = tmp_path / "regerado"
    assert sorted(p.name for p in (regerado / "janela_2").glob("*.csv.gz")) == [
        "BenignTraffic.csv.gz", "DoS-HTTP_Flood.csv.gz", "Recon-PortScan.csv.gz",
    ]
    assert sorted(p.name for p in (regerado / "janela_5").glob("*.csv.gz")) == [
        "BenignTraffic.csv.gz", "DoS-HTTP_Flood.csv.gz", "Recon-PortScan.csv.gz",
    ]
    # Pcap de ataque: só as janelas com atacante, com o índice que a janela tem no arquivo.
    recon = ler(regerado / "janela_2" / "Recon-PortScan.csv.gz")
    assert list(recon.columns) == [*COLUNAS, *COLUNAS_EXTRAS]
    assert recon["indice"].tolist() == [1, 3]
    assert recon["Label"].unique().tolist() == ["Recon-PortScan"]
    assert recon["arquivo"].unique().tolist() == ["Recon-PortScan.pcap"]
    assert recon["atacante"].tolist() == [1, 1]
    assert recon["quadros_atacante"].tolist() == [1, 1] and recon["macs_atacante"].tolist() == [1, 1]
    assert recon["Number"].tolist() == [2, 2]
    assert recon["ips_origem"].tolist() == [2, 2] and recon["ips_destino"].tolist() == [1, 1]
    de_cinco = ler(regerado / "janela_5" / "Recon-PortScan.csv.gz")
    assert de_cinco["indice"].tolist() == [0, 1] and de_cinco["Number"].tolist() == [5, 5]
    # Pcap benigno: todas as janelas, de todos os arquivos do rótulo, mesmo quando um MAC da lista aparece.
    benigno = ler(regerado / "janela_2" / "BenignTraffic.csv.gz")
    assert benigno["arquivo"].tolist() == ["BenignTraffic.pcap"] * 4 + ["BenignTraffic1.pcap"] * 2
    assert benigno["indice"].tolist() == [0, 1, 2, 3, 0, 1]
    assert benigno["atacante"].tolist() == [0, 0, 0, 0, 1, 1]
    assert benigno["quadros_atacante"].tolist() == [0, 0, 0, 0, 2, 1]
    assert benigno["Number"].tolist() == [2, 2, 2, 1, 2, 1]
    assert benigno["Label"].unique().tolist() == ["BenignTraffic"]
    # O arquivo é lido pelo preparo do treino como qualquer CSV com rótulo.
    quadro_lido, _ = carregar(regerado / "janela_2" / "Recon-PortScan.csv.gz")
    assert len(quadro_lido) == 2 and quadro_lido["Label"].iloc[0] == "Recon-PortScan"
    # O manifesto conta as janelas extraídas, mantidas e descartadas de cada pcap e janela.
    m = ler_manifesto(tmp_path)
    assert m["janelas"] == [2, 5] and m["destino"] == str(tmp_path / "regerado")
    por_arquivo = {p["arquivo"]: p for p in m["pcaps"]}
    assert por_arquivo["Recon-PortScan.pcap"]["janelas"]["2"] == {
        "extraidas": 6, "mantidas": 2, "descartadas": 4, "com_atacante": 2, "incompletas": 0,
    }
    assert por_arquivo["Recon-PortScan.pcap"]["janelas"]["5"]["mantidas"] == 2
    assert por_arquivo["BenignTraffic1.pcap"]["janelas"]["2"] == {
        "extraidas": 2, "mantidas": 2, "descartadas": 0, "com_atacante": 2, "incompletas": 1,
    }
    assert m["versao_da_regra"] == VERSAO_DA_REGRA
    assert m["extrator"] == {"sha256": codigo_do_extrator(), "opcoes": {}}
    assert len(m["extrator"]["sha256"]) == 64
    assert len(por_arquivo["Recon-PortScan.pcap"]["sha256"]) == 64
    assert por_arquivo["Recon-PortScan.pcap"]["bytes"] == (tmp_path / "dataset" / "Recon-PortScan.pcap").stat().st_size
    assert {r["rotulo"] for r in m["rotulos"]} == {"BenignTraffic", "DoS-HTTP_Flood", "Recon-PortScan"}
    benign = next(r for r in m["rotulos"] if r["rotulo"] == "BenignTraffic")
    assert benign["arquivos"] == ["BenignTraffic.pcap", "BenignTraffic1.pcap"]
    assert benign["linhas"] == {"2": 6, "5": 3}
    assert "4 pcaps" in capsys.readouterr().err


def test_main_so_extrai_de_novo_o_pcap_novo_ou_alterado_e_apaga_o_que_sumiu(tmp_path, monkeypatch):
    import codigo.classificador.regerar as modulo

    pasta = preparar_dataset(tmp_path / "dataset")
    assert executar(tmp_path) == 0
    lidos = []
    original = modulo.percorrer

    def contando(caminho, *args, **kwargs):
        lidos.append(Path(caminho).name)
        return original(caminho, *args, **kwargs)

    monkeypatch.setattr(modulo, "percorrer", contando)
    regerado = tmp_path / "regerado"
    antes = ler(regerado / "janela_2" / "BenignTraffic.csv.gz")
    assert executar(tmp_path) == 0
    assert lidos == []
    assert ler(regerado / "janela_2" / "BenignTraffic.csv.gz").equals(antes)
    # Um pcap alterado tem as linhas trocadas, um novo entra, e o que sumiu sai junto com o rótulo dele.
    (pasta / "BenignTraffic1.pcap").write_bytes(pcap([(i, 0, quadro(OUTRO, VITIMA)) for i in range(9)]))
    captura_de_teste(pasta / "DictionaryBruteForce.pcap")
    (pasta / "DoS-HTTP_Flood1.pcap").unlink()
    assert executar(tmp_path) == 0
    assert sorted(lidos) == ["BenignTraffic1.pcap", "DictionaryBruteForce.pcap"]
    benigno = ler(regerado / "janela_2" / "BenignTraffic.csv.gz")
    assert benigno["arquivo"].tolist() == ["BenignTraffic.pcap"] * 4 + ["BenignTraffic1.pcap"] * 5
    assert benigno["atacante"].sum() == 0
    assert not (regerado / "janela_2" / "DoS-HTTP_Flood.csv.gz").exists()
    assert not (regerado / "janela_2" / PARTES / "DoS-HTTP_Flood1.csv.gz").exists()
    assert (regerado / "janela_5" / "DictionaryBruteForce.csv.gz").exists()
    assert sorted(p["arquivo"] for p in ler_manifesto(tmp_path)["pcaps"]) == [
        "BenignTraffic.pcap", "BenignTraffic1.pcap", "DictionaryBruteForce.pcap", "Recon-PortScan.pcap",
    ]
    # Se a saída de um pcap sumiu, ele é extraído de novo mesmo sem ter mudado.
    lidos.clear()
    (regerado / "janela_5" / PARTES / "Recon-PortScan.csv.gz").unlink()
    assert executar(tmp_path) == 0
    assert lidos == ["Recon-PortScan.pcap"]
    assert ler(regerado / "janela_5" / "Recon-PortScan.csv.gz")["indice"].tolist() == [0, 1]
    # Outra lista de janelas invalida tudo.
    lidos.clear()
    assert main([
        "--dataset", str(pasta), "--saida", str(tmp_path / "resultados"), "--destino", str(regerado), "--janelas", "3",
    ]) == 0
    assert len(lidos) == 4
    assert (regerado / "janela_3" / "Recon-PortScan.csv.gz").exists()


def test_main_recusa_nome_desconhecido_antes_de_extrair(tmp_path, capsys):
    pasta = preparar_dataset(tmp_path / "dataset")
    (pasta / "captura.pcap").write_bytes(pcap([(1, 0, quadro(OUTRO, VITIMA))]))
    assert executar(tmp_path) == 1
    assert "captura.pcap" in capsys.readouterr().err
    assert not (tmp_path / "regerado").exists() and not (tmp_path / "resultados").exists()


def test_main_explica_pasta_sem_pcap(tmp_path, capsys):
    (tmp_path / "dataset").mkdir()
    assert executar(tmp_path) == 1
    assert "nenhum pcap" in capsys.readouterr().err


def test_as_partes_nao_tem_cabecalho_e_o_arquivo_do_rotulo_e_a_junção_delas(tmp_path):
    preparar_dataset(tmp_path / "dataset")
    assert executar(tmp_path) == 0
    pasta = tmp_path / "regerado" / "janela_2"
    with gzip.open(pasta / PARTES / "BenignTraffic1.csv.gz", "rt", encoding="utf-8") as arquivo:
        linhas = arquivo.read().splitlines()
    assert len(linhas) == 2 and not linhas[0].startswith("Header_Length")
    with gzip.open(pasta / "BenignTraffic.csv.gz", "rt", encoding="utf-8") as arquivo:
        juncao = arquivo.read().splitlines()
    assert juncao[0].startswith("Header_Length") and juncao[-2:] == linhas


def test_main_sem_csv_anterior_e_sem_manifesto_refaz_tudo(tmp_path):
    preparar_dataset(tmp_path / "dataset")
    assert executar(tmp_path) == 0
    (tmp_path / "resultados" / MANIFESTO).unlink()
    assert executar(tmp_path) == 0
    assert ler(tmp_path / "regerado" / "janela_2" / "Recon-PortScan.csv.gz")["indice"].tolist() == [1, 3]


def test_as_janelas_descartadas_ficam_a_parte_com_as_mesmas_colunas(tmp_path):
    preparar_dataset(tmp_path / "dataset")
    assert executar(tmp_path) == 0
    pasta = tmp_path / "regerado" / "janela_2"
    descartadas = ler_sem_cabecalho(pasta / DESCARTADAS / "Recon-PortScan.csv.gz")
    mantidas = ler_sem_cabecalho(pasta / PARTES / "Recon-PortScan.csv.gz")
    # As 6 janelas do arquivo: 2 mantidas e 4 descartadas, sem repetir nem perder nenhuma.
    assert descartadas["indice"].tolist() == [0, 2, 4, 5]
    assert sorted([*descartadas["indice"], *mantidas["indice"]]) == list(range(6))
    assert (descartadas["atacante"] == 0).all() and (descartadas["quadros_atacante"] == 0).all()
    assert (descartadas["macs_atacante"] == 0).all()
    assert descartadas["Label"].unique().tolist() == ["Recon-PortScan"]
    assert list(descartadas[list(COLUNAS)].columns) == list(COLUNAS)
    # As descartadas não entram no arquivo do rótulo, que continua só com as mantidas.
    assert ler(pasta / "Recon-PortScan.csv.gz")["indice"].tolist() == [1, 3]
    m = ler_manifesto(tmp_path)
    recon = next(p for p in m["pcaps"] if p["arquivo"] == "Recon-PortScan.pcap")
    assert recon["janelas"]["2"]["descartadas"] == len(descartadas) == 4
    # Num pcap benigno nada é descartado, e a parte das descartadas existe vazia.
    assert ler_sem_cabecalho(pasta / DESCARTADAS / "BenignTraffic.csv.gz").empty


def test_mudanca_no_extrator_na_regra_ou_o_pedido_de_refazer_leem_tudo_de_novo(tmp_path, monkeypatch):
    import codigo.classificador.regerar as modulo

    preparar_dataset(tmp_path / "dataset")
    assert executar(tmp_path) == 0
    lidos = []
    original = modulo.percorrer

    def contando(caminho, *args, **kwargs):
        lidos.append(Path(caminho).name)
        return original(caminho, *args, **kwargs)

    monkeypatch.setattr(modulo, "percorrer", contando)
    assert executar(tmp_path) == 0 and lidos == []
    # Uma correção no código do extrator invalida as partes gravadas com o código anterior.
    monkeypatch.setattr(modulo, "codigo_do_extrator", lambda: "f" * 64)
    assert executar(tmp_path) == 0 and len(lidos) == 4
    assert ler_manifesto(tmp_path)["extrator"]["sha256"] == "f" * 64
    lidos.clear()
    assert executar(tmp_path) == 0 and lidos == []
    # Outra versão da regra também.
    monkeypatch.setattr(modulo, "VERSAO_DA_REGRA", VERSAO_DA_REGRA + 1)
    assert executar(tmp_path) == 0 and len(lidos) == 4
    lidos.clear()
    # E --refazer lê tudo, mesmo sem mudança.
    assert executar(tmp_path, "--refazer") == 0 and len(lidos) == 4
    # Se a parte das descartadas sumiu, o pcap é lido de novo.
    lidos.clear()
    (tmp_path / "regerado" / "janela_5" / DESCARTADAS / "Recon-PortScan.csv.gz").unlink()
    assert executar(tmp_path) == 0 and lidos == ["Recon-PortScan.pcap"]


def test_varios_processos_dao_o_mesmo_resultado_da_leitura_em_sequencia(tmp_path):
    preparar_dataset(tmp_path / "dataset")
    assert executar(tmp_path) == 0
    sequencia = tmp_path / "regerado"
    paralela = tmp_path / "paralela"
    assert main([
        "--dataset", str(tmp_path / "dataset"), "--saida", str(tmp_path / "resultados_paralela"),
        "--destino", str(paralela), "--janelas", "2,5", "--processos", "2",
    ]) == 0
    for caminho in sorted(sequencia.rglob("*.csv.gz")):
        outro = paralela / caminho.relative_to(sequencia)
        with gzip.open(caminho, "rb") as a, gzip.open(outro, "rb") as b:
            assert a.read() == b.read(), caminho
    um = ler_manifesto(tmp_path)
    dois = json.loads((tmp_path / "resultados_paralela" / MANIFESTO).read_text(encoding="utf-8"))
    assert [p["janelas"] for p in um["pcaps"]] == [p["janelas"] for p in dois["pcaps"]]
    assert executar(tmp_path, "--processos", "0") == 2


def test_opcoes_do_extrator_medem_o_quadro_como_no_fio_e_ficam_no_manifesto(tmp_path, monkeypatch):
    import codigo.classificador.regerar as modulo
    from codigo.captura.test_extrator import eth, ipv4, tcp

    pasta = preparar_dataset(tmp_path / "dataset")
    # Quadros de 54 bytes, sem o preenchimento até 60, e um pcap benigno com quadros de 3.054 bytes.
    grande = eth(0x0800, ipv4(6, tcp(40000, 443, 0x10, dados=b"x" * 3000)))
    (pasta / "BenignTraffic2.pcap").write_bytes(pcap([(i, 0, grande) for i in range(4)]))
    assert executar(tmp_path) == 0
    sem_opcao = ler(tmp_path / "regerado" / "janela_2" / "Recon-PortScan.csv.gz")
    assert sem_opcao["Min"].tolist() == [54.0, 54.0]
    assert ler(tmp_path / "regerado" / "janela_2" / "BenignTraffic.csv.gz")["Max"].max() == 3054.0
    assert main([
        "--dataset", str(pasta), "--saida", str(tmp_path / "no_fio"), "--destino", str(tmp_path / "regerado_no_fio"),
        "--janelas", "2,5", "--preencher", "--limitar",
    ]) == 0
    no_fio = ler(tmp_path / "regerado_no_fio" / "janela_2" / "Recon-PortScan.csv.gz")
    assert no_fio["Min"].tolist() == [60.0, 60.0]
    assert ler(tmp_path / "regerado_no_fio" / "janela_2" / "BenignTraffic.csv.gz")["Max"].max() == 1514.0
    # A opção só muda o tamanho: as mesmas janelas são mantidas, com os mesmos índices.
    assert no_fio["indice"].tolist() == sem_opcao["indice"].tolist()
    m = json.loads((tmp_path / "no_fio" / MANIFESTO).read_text(encoding="utf-8"))
    assert m["extrator"]["opcoes"] == {"limitar": True, "preencher": True}
    # Rodar de novo sem as opções, na mesma pasta, lê todos os pcaps de novo.
    lidos = []
    original = modulo.percorrer
    monkeypatch.setattr(modulo, "percorrer", lambda caminho, *a, **k: lidos.append(caminho) or original(caminho, *a, **k))
    assert main([
        "--dataset", str(pasta), "--saida", str(tmp_path / "no_fio"), "--destino", str(tmp_path / "regerado_no_fio"),
        "--janelas", "2,5",
    ]) == 0
    assert len(lidos) == 5
