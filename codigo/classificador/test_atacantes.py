import csv
import json
import struct
import warnings
from pathlib import Path

import pytest

from codigo.captura.extrator import COLUNAS, Enderecos
from codigo.captura.test_extrator import QUADRO_IPV6, eth, ipv4, pcap, tcp
from codigo.classificador.atacantes import (
    ATACANTES,
    CSV_MACS,
    JANELAS,
    MANIFESTO,
    RELATORIO,
    TABELA,
    main,
    montar_relatorio,
    percorrer,
    rotulo_do_pcap,
    tem_atacante,
)
from codigo.classificador.mapeamento import ROTULOS

RAIZ = Path(__file__).resolve().parents[2]
DATASET = RAIZ / "CICIoT2023"

ATACANTE = "dc:a6:32:dc:27:d5"
VITIMA = "3c:18:a0:41:c3:a0"
OUTRO = "aa:bb:cc:00:00:01"


def quadro(origem, destino, ip_origem=(10, 0, 0, 1)):
    return eth(
        0x0800, ipv4(6, tcp(40000, 80, 0x02), origem=bytes(ip_origem)),
        origem=bytes.fromhex(origem.replace(":", "")), destino=bytes.fromhex(destino.replace(":", "")),
    )


def test_os_sete_raspberry_pi_atacantes_da_tabela_1_do_artigo():
    assert len(ATACANTES) == 7
    assert ATACANTE in ATACANTES
    # Na grafia do extrator: minúsculas, separadas por dois-pontos.
    assert all(mac == mac.lower() and len(mac.split(":")) == 6 for mac in ATACANTES)


@pytest.mark.parametrize("nome,rotulo", [
    ("DoS-HTTP_Flood1.pcap", "DoS-HTTP_Flood"),
    ("DDoS-HTTP_Flood-.pcap", "DDoS-HTTP_Flood"),
    ("BenignTraffic1.pcap", "BenignTraffic"),
    ("BenignTraffic.pcap", "BenignTraffic"),
    ("Mirai-greip_flood21.pcap", "Mirai-greip_flood"),
    ("Recon-PortScan.pcap", "Recon-PortScan"),
    ("DictionaryBruteForce.pcap", "DictionaryBruteForce"),
    ("DNS_Spoofing.pcap", "DNS_Spoofing"),
    ("MITM-ArpSpoofing.pcap", "MITM-ArpSpoofing"),
    ("ddos-icmp_flood-3.pcap", "DDoS-ICMP_Flood"),
])
def test_o_rotulo_vem_do_nome_do_arquivo(nome, rotulo):
    assert rotulo_do_pcap(nome) == rotulo
    assert rotulo in ROTULOS


@pytest.mark.parametrize("nome", ["captura.pcap", "DDoS.pcap", "Flood1.pcap", "DDoS-HTTP_Flood.pcapng"])
def test_nome_que_nao_casa_com_rotulo_e_recusado(nome):
    with pytest.raises(ValueError, match="não casa com nenhum rótulo"):
        rotulo_do_pcap(nome)


def test_tem_atacante_olha_a_origem_e_o_destino():
    assert tem_atacante(Enderecos(frozenset({ATACANTE}), frozenset({VITIMA}), 1, 1))
    assert tem_atacante(Enderecos(frozenset({VITIMA}), frozenset({ATACANTE, OUTRO}), 1, 2))
    assert not tem_atacante(Enderecos(frozenset({VITIMA, OUTRO}), frozenset({OUTRO}), 2, 1))
    assert not tem_atacante(Enderecos(frozenset(), frozenset(), 0, 0))


def captura_de_teste(caminho):
    """12 quadros IPv4: o atacante aparece nos quadros 2 e 7, e há um IPv6 no meio que não entra em janela."""
    registros = []
    for i in range(12):
        origem, destino = (ATACANTE, VITIMA) if i == 2 else (VITIMA, ATACANTE) if i == 7 else (OUTRO, VITIMA)
        registros.append((100 + i, 0, quadro(origem, destino, ip_origem=(10, 0, 0, 1 + i % 3))))
        if i == 4:
            registros.append((100 + i, 500, QUADRO_IPV6))
    caminho.write_bytes(pcap(registros))
    return caminho


def test_percorrer_conta_macs_e_janelas_com_e_sem_atacante(tmp_path):
    captura = captura_de_teste(tmp_path / "Recon-PortScan.pcap")
    fechadas = []
    registro = percorrer(captura, janelas=(2, 5), ao_fechar=lambda *args: fechadas.append(args))
    assert registro["pacotes"] == 13
    assert registro["bytes"] == captura.stat().st_size
    assert len(registro["sha256"]) == 64
    assert registro["avisos"] == []
    # Os MACs são contados em todos os quadros, inclusive no IPv6 que o extrator não mede.
    assert registro["macs_origem"][OUTRO] == 10 and registro["macs_origem"][ATACANTE] == 1
    assert registro["macs_destino"][VITIMA] == 11 and registro["macs_destino"][ATACANTE] == 1
    assert registro["macs_origem"]["02:00:00:00:00:01"] == 1
    assert sum(registro["macs_origem"].values()) == 13
    # Janela de 2: 6 janelas, o atacante está na 2ª (quadros 2 e 3) e na 4ª (quadros 6 e 7).
    assert registro["janelas"][2] == {"extraidas": 6, "com_atacante": 2, "sem_atacante": 4, "incompletas": 0}
    # Janela de 5: 3 janelas (a última com 2 quadros), o atacante está na 1ª e na 2ª.
    assert registro["janelas"][5] == {"extraidas": 3, "com_atacante": 2, "sem_atacante": 1, "incompletas": 1}
    assert registro["segundos"] > 0
    # A chamada a cada janela fechada: janela, índice no arquivo, linha, endereços e se há atacante.
    de_dois = [args for args in fechadas if args[0] == 2]
    assert [indice for _, indice, *_ in de_dois] == [0, 1, 2, 3, 4, 5]
    assert [com_atacante for *_, com_atacante in de_dois] == [False, True, False, True, False, False]
    _, _, linha, enderecos, _ = de_dois[1]
    assert list(linha) == list(COLUNAS) and linha["Number"] == 2
    assert enderecos.macs_origem == frozenset({ATACANTE, OUTRO}) and enderecos.ips_origem == 2
    de_cinco = [args for args in fechadas if args[0] == 5]
    assert [indice for _, indice, *_ in de_cinco] == [0, 1, 2]
    assert de_cinco[2][2]["Number"] == 2


def test_percorrer_registra_captura_interrompida_e_faz_o_hash_do_arquivo_inteiro(tmp_path):
    captura = tmp_path / "Recon-PortScan.pcap"
    inteiro = pcap([(i, 0, quadro(OUTRO, VITIMA)) for i in range(4)])
    captura.write_bytes(inteiro[:-7])
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # o aviso fica no registro, e não na saída
        registro = percorrer(captura, janelas=(2,))
    assert registro["pacotes"] == 3
    assert registro["bytes"] == len(inteiro) - 7
    assert len(registro["avisos"]) == 1 and "incompleto" in registro["avisos"][0]
    import hashlib
    assert registro["sha256"] == hashlib.sha256(inteiro[:-7]).hexdigest()


def test_percorrer_recusa_o_que_nao_e_pcap(tmp_path):
    ruim = tmp_path / "Recon-PortScan.pcap"
    ruim.write_bytes(b"isto nao e um pcap")
    with pytest.raises(ValueError, match="Recon-PortScan.pcap"):
        percorrer(ruim, janelas=(2,))


def preparar_dataset(pasta):
    pasta.mkdir(parents=True, exist_ok=True)
    captura_de_teste(pasta / "Recon-PortScan.pcap")
    captura_de_teste(pasta / "DoS-HTTP_Flood1.pcap")
    (pasta / "BenignTraffic.pcap").write_bytes(pcap([(i, 0, quadro(OUTRO, VITIMA)) for i in range(7)]))
    return pasta


def executar(pasta, *extras):
    return main(["--dataset", str(pasta / "dataset"), "--saida", str(pasta / "resultados"), *extras])


def ler_csv(caminho):
    with open(caminho, encoding="utf-8", newline="") as arquivo:
        return list(csv.DictReader(arquivo))


def test_main_mede_os_pcaps_de_ataque_e_grava_relatorio_tabela_e_manifesto(tmp_path, capsys):
    preparar_dataset(tmp_path / "dataset")
    assert executar(tmp_path, "--janelas", "2,5") == 0
    resultados = tmp_path / "resultados"
    manifesto = json.loads((resultados / MANIFESTO).read_text(encoding="utf-8"))
    assert [p["arquivo"] for p in manifesto["pcaps"]] == [
        "BenignTraffic.pcap", "DoS-HTTP_Flood1.pcap", "Recon-PortScan.pcap",
    ]
    assert manifesto["janelas"] == [2, 5]
    assert sorted(manifesto["atacantes"]) == sorted(ATACANTES)
    recon = next(p for p in manifesto["pcaps"] if p["arquivo"] == "Recon-PortScan.pcap")
    assert recon["rotulo"] == "Recon-PortScan" and recon["benigno"] is False
    assert recon["janelas"]["2"]["sem_atacante"] == 4
    assert recon["macs"][ATACANTE] == {"origem": 1, "destino": 1, "na_lista": True}
    benigno = next(p for p in manifesto["pcaps"] if p["arquivo"] == "BenignTraffic.pcap")
    assert benigno["benigno"] is True and benigno["janelas"]["2"]["sem_atacante"] == 4
    # A tabela das janelas sem atacante tem uma linha por pcap e janela.
    tabela = ler_csv(resultados / TABELA)
    assert len(tabela) == 6
    linha = next(l for l in tabela if l["arquivo"] == "Recon-PortScan.pcap" and l["janela"] == "2")
    assert (linha["janelas"], linha["com_atacante"], linha["sem_atacante"]) == ("6", "2", "4")
    assert linha["fracao_sem_atacante"] == "0.666667"
    # A tabela dos MACs traz os sete da lista e os mais frequentes de cada pcap.
    macs = ler_csv(resultados / CSV_MACS)
    assert {l["mac"] for l in macs if l["arquivo"] == "Recon-PortScan.pcap"} >= {ATACANTE, VITIMA, OUTRO}
    assert all(l["na_lista"] in ("0", "1") for l in macs)
    relatorio = (resultados / RELATORIO).read_text(encoding="utf-8")
    assert "# Janelas sem atacante" in relatorio
    assert "`Recon-PortScan.pcap`" in relatorio and "66,67%" in relatorio
    assert "DC:A6:32:DC:27:D5".lower() in relatorio
    assert "3 pcaps" in capsys.readouterr().err


def test_main_recusa_pcap_com_nome_desconhecido_sem_medir_nada(tmp_path, capsys):
    pasta = preparar_dataset(tmp_path / "dataset")
    (pasta / "captura_estranha.pcap").write_bytes(pcap([(1, 0, quadro(OUTRO, VITIMA))]))
    assert executar(tmp_path, "--janelas", "2") == 1
    assert "captura_estranha.pcap" in capsys.readouterr().err
    assert not (tmp_path / "resultados").exists()


def test_main_so_mede_de_novo_o_pcap_novo_ou_alterado(tmp_path, monkeypatch):
    import codigo.classificador.atacantes as modulo

    pasta = preparar_dataset(tmp_path / "dataset")
    assert executar(tmp_path, "--janelas", "2") == 0
    medidos = []
    original = modulo.percorrer

    def contando(caminho, *args, **kwargs):
        medidos.append(Path(caminho).name)
        return original(caminho, *args, **kwargs)

    monkeypatch.setattr(modulo, "percorrer", contando)
    # Nada mudou: nenhum pcap é lido de novo, e o relatório sai igual.
    antes = (tmp_path / "resultados" / TABELA).read_text(encoding="utf-8")
    assert executar(tmp_path, "--janelas", "2") == 0
    assert medidos == []
    assert (tmp_path / "resultados" / TABELA).read_text(encoding="utf-8") == antes
    # Um pcap novo e um alterado são medidos; o que sumiu da pasta sai do relatório.
    captura_de_teste(pasta / "DictionaryBruteForce.pcap")
    (pasta / "DoS-HTTP_Flood1.pcap").write_bytes(pcap([(i, 0, quadro(ATACANTE, VITIMA)) for i in range(4)]))
    (pasta / "BenignTraffic.pcap").unlink()
    assert executar(tmp_path, "--janelas", "2") == 0
    assert sorted(medidos) == ["DictionaryBruteForce.pcap", "DoS-HTTP_Flood1.pcap"]
    tabela = ler_csv(tmp_path / "resultados" / TABELA)
    assert sorted({l["arquivo"] for l in tabela}) == [
        "DictionaryBruteForce.pcap", "DoS-HTTP_Flood1.pcap", "Recon-PortScan.pcap",
    ]
    dos = next(l for l in tabela if l["arquivo"] == "DoS-HTTP_Flood1.pcap")
    assert (dos["janelas"], dos["sem_atacante"]) == ("2", "0")
    # Outra lista de janelas invalida o registro: tudo é medido de novo.
    medidos.clear()
    assert executar(tmp_path, "--janelas", "2,3") == 0
    assert len(medidos) == 3


def test_main_sem_pcap_na_pasta_explica_o_erro(tmp_path, capsys):
    (tmp_path / "dataset").mkdir()
    assert executar(tmp_path) == 1
    assert "nenhum pcap" in capsys.readouterr().err
    assert main(["--dataset", str(tmp_path / "nao_existe"), "--saida", str(tmp_path / "r")]) == 1


def test_janelas_padrao_sao_as_do_dataset_e_a_opcao_e_validada(tmp_path, capsys):
    assert JANELAS == (10, 100)
    preparar_dataset(tmp_path / "dataset")
    assert executar(tmp_path, "--janelas", "0") == 2
    assert executar(tmp_path, "--janelas", "dez") == 2


def test_relatorio_e_o_mesmo_a_partir_do_manifesto(tmp_path):
    preparar_dataset(tmp_path / "dataset")
    assert executar(tmp_path, "--janelas", "2,5") == 0
    manifesto = json.loads((tmp_path / "resultados" / MANIFESTO).read_text(encoding="utf-8"))
    assert montar_relatorio(manifesto) == (tmp_path / "resultados" / RELATORIO).read_text(encoding="utf-8")


PCAP_DO_PORTSCAN = DATASET / "Recon-PortScan.pcap"


@pytest.mark.skipif(not PCAP_DO_PORTSCAN.exists(), reason="dataset ausente")
def test_recon_portscan_real_tem_o_atacante_da_lista_e_janelas_sem_ele():
    registro = percorrer(PCAP_DO_PORTSCAN, janelas=(10,))
    assert registro["pacotes"] == 831_856
    assert registro["macs_origem"][ATACANTE] == 143_683
    assert registro["janelas"][10]["extraidas"] == 82_278
    # A medição preliminar registrada no ROADMAP.md (62,5% das janelas sem o atacante).
    fracao = registro["janelas"][10]["sem_atacante"] / registro["janelas"][10]["extraidas"]
    assert 0.55 < fracao < 0.70


def test_struct_do_quadro_de_teste():
    # O quadro de teste leva os MACs pedidos nos 12 primeiros bytes, como o extrator lê.
    q = quadro(ATACANTE, VITIMA)
    assert q[6:12].hex(":") == ATACANTE and q[:6].hex(":") == VITIMA
    assert struct.unpack(">H", q[12:14])[0] == 0x0800
