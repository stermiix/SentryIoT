from pathlib import Path

import pytest

from codigo.captura.extrator import COLUNAS
from codigo.classificador.amostrar import CABECALHO
from codigo.classificador.explorar import (
    RELACOES,
    contar_por_ataque,
    explorar,
    main,
    montar_relatorio,
)
from codigo.classificador.mapeamento import ROTULOS

DATASET = Path(__file__).resolve().parents[2] / "CICIoT2023"
MERGED = DATASET / "MERGED_CSV"


def _texto(valor):
    return "" if valor is None else str(valor)


def linha(rotulo, quadros=10, media=60.0, desvio=0.0, acks=0, trocas=None):
    """Linha em que as colunas derivadas seguem as relações do dataset. None vira campo vazio."""
    valores = dict.fromkeys(COLUNAS, 0.0) | {
        "Header_Length": 20.0, "Protocol Type": 6, "Time_To_Live": 64.0, "Rate": 1000.0,
        "ack_flag_number": acks / quadros, "ack_count": acks, "TCP": 1.0, "IPv": 1.0, "LLC": 1.0,
        "Tot sum": media * quadros, "Min": media, "Max": media, "AVG": media, "Std": desvio,
        "Tot size": media, "IAT": 0.001, "Number": quadros, "Variance": desvio ** 2,
    } | (trocas or {})
    return ",".join(_texto(valores[coluna]) for coluna in COLUNAS) + "," + rotulo


def escrever(caminho, linhas, cabecalho=CABECALHO):
    caminho.parent.mkdir(parents=True, exist_ok=True)
    caminho.write_text(",".join(cabecalho) + "\n" + "".join(texto + "\n" for texto in linhas))
    return caminho


LINHAS_DO_CASO = (
    [linha("DDOS-ICMP_FLOOD", quadros=100, media=60.0 + i, acks=i) for i in range(6)]
    + [linha("DDOS-ICMP_FLOOD", quadros=37)]
    + [linha("DOS-UDP_FLOOD", quadros=100, media=70.0 + i, trocas={"Protocol Type": 17}) for i in range(3)]
    + [linha("BENIGN", media=200.0 + i, desvio=3.0) for i in range(4)]
    + [linha("RECON-PORTSCAN", media=80.0), linha("RECON-PORTSCAN", quadros=9, media=81.0)]
    + [linha("XSS", media=90.0)]
)


def caso(tmp_path):
    """Dois arquivos com 17 linhas: 7 de DDoS-ICMP_Flood, 3 de DoS-UDP_Flood, 4 benignas, 2 de PortScan e 1 de XSS."""
    pasta = tmp_path / "MERGED_CSV"
    return [
        escrever(pasta / "Merged01.csv", LINHAS_DO_CASO[:9]),
        escrever(pasta / "Merged02.csv", LINHAS_DO_CASO[9:]),
    ]


def explorar_linhas(tmp_path, linhas, **opcoes):
    return explorar([escrever(tmp_path / "a.csv", linhas)], **opcoes)


def test_conta_linhas_por_classe_e_por_categoria(tmp_path):
    e = explorar(caso(tmp_path))
    assert e.linhas == 17
    assert list(e.por_rotulo) == list(ROTULOS)
    presentes = {rotulo: linhas for rotulo, linhas in e.por_rotulo.items() if linhas}
    assert presentes == {
        "DDoS-ICMP_Flood": 7, "DoS-UDP_Flood": 3, "Recon-PortScan": 2, "XSS": 1, "BenignTraffic": 4,
    }
    assert e.por_categoria == {
        "DDoS": 7, "DoS": 3, "Mirai": 0, "Recon": 2, "Spoofing": 0, "Web": 1, "BruteForce": 0, "Benign": 4,
    }


def test_registra_cada_arquivo_e_a_contagem_por_classe_dentro_dele(tmp_path):
    e = explorar(caso(tmp_path))
    assert [(a["nome"], a["linhas"], a["final_incompleto"]) for a in e.arquivos] == [
        ("Merged01.csv", 9, False), ("Merged02.csv", 8, False),
    ]
    assert e.por_arquivo[0] == {"DDoS-ICMP_Flood": 7, "DoS-UDP_Flood": 2}
    assert e.por_arquivo[1] == {"DoS-UDP_Flood": 1, "BenignTraffic": 4, "Recon-PortScan": 2, "XSS": 1}


def test_grafias_dos_rotulos_nos_arquivos(tmp_path):
    e = explorar(caso(tmp_path))
    assert e.grafias["BenignTraffic"] == ["BENIGN"]
    assert e.grafias["DDoS-ICMP_Flood"] == ["DDOS-ICMP_FLOOD"]
    assert e.grafias["XSS"] == ["XSS"]
    assert e.grafias["Mirai-udpplain"] == []
    relatorio = montar_relatorio(e)
    assert "4 das 5 classes presentes" in relatorio
    assert "`BENIGN` no lugar de `BenignTraffic`" in relatorio


def test_janela_por_classe_vem_da_coluna_number(tmp_path):
    e = explorar(caso(tmp_path))
    assert e.janela["DDoS-ICMP_Flood"] == {100: 6, 37: 1}
    assert e.janela["Recon-PortScan"] == {10: 1, 9: 1}
    assert e.janela["BenignTraffic"] == {10: 4}
    assert e.janela["Mirai-udpplain"] == {}


def test_vazios_e_infinitos_sao_contados_por_coluna_sem_quebrar(tmp_path):
    linhas = [
        linha("DDOS-PSHACK_FLOOD", quadros=1, trocas={"Rate": "inf", "Std": None, "Variance": None}),
        linha("DDOS-TCP_FLOOD", quadros=2, trocas={"Rate": "inf"}),
        linha("DDOS-TCP_FLOOD", quadros=100, trocas={"Rate": 2500.0, "IAT": "-inf"}),
        linha("BENIGN", trocas={"Rate": 0.5}),
    ]
    e = explorar_linhas(tmp_path, linhas)
    assert e.linhas == 4
    rate, std = e.colunas["Rate"], e.colunas["Std"]
    assert (rate.infinitos, rate.infinitos_com_um_quadro, rate.vazios) == (2, 1, 0)
    assert (std.vazios, std.vazios_com_um_quadro, std.infinitos) == (1, 1, 0)
    assert e.colunas["Variance"].vazios == 1
    assert e.colunas["IAT"].infinitos == 1
    assert e.colunas["AVG"].vazios == 0 and e.colunas["AVG"].infinitos == 0
    # A faixa de valores ignora vazios e infinitos.
    assert (rate.minimo, rate.maximo) == (0.5, 2500.0)
    assert (std.minimo, std.maximo) == (0.0, 0.0)


def test_faixa_de_valores_e_linhas_diferentes_de_zero(tmp_path):
    e = explorar(caso(tmp_path))
    assert (e.colunas["AVG"].minimo, e.colunas["AVG"].maximo) == (60.0, 203.0)
    assert (e.colunas["Number"].minimo, e.colunas["Number"].maximo) == (9.0, 100.0)
    assert e.colunas["AVG"].diferentes_de_zero == 17
    assert e.colunas["Std"].diferentes_de_zero == 4
    assert e.colunas["Telnet"].diferentes_de_zero == 0
    assert list(e.colunas) == list(COLUNAS)


def test_colunas_constantes(tmp_path):
    e = explorar(caso(tmp_path))
    assert "Time_To_Live" in e.constantes and "Telnet" in e.constantes
    assert "AVG" not in e.constantes and "Number" not in e.constantes


def test_coluna_com_vazio_nao_e_constante(tmp_path):
    linhas = [linha("XSS"), linha("XSS", trocas={"Time_To_Live": None})]
    assert "Time_To_Live" not in explorar_linhas(tmp_path, linhas).constantes


def test_colunas_identicas_em_todas_as_linhas(tmp_path):
    e = explorar(caso(tmp_path))
    assert ("AVG", "Tot size") in e.identicas
    assert ("IPv", "LLC") in e.identicas
    assert ("AVG", "Std") not in e.identicas


def test_uma_linha_diferente_desfaz_o_par_de_colunas_identicas(tmp_path):
    linhas = [*LINHAS_DO_CASO, linha("XSS", trocas={"LLC": 0.9})]
    e = explorar_linhas(tmp_path, linhas, linhas_por_bloco=5)
    assert ("IPv", "LLC") not in e.identicas
    assert ("AVG", "Tot size") in e.identicas


def test_colunas_vazias_na_mesma_linha_contam_como_iguais(tmp_path):
    linhas = [linha("XSS"), linha("XSS", trocas={"AVG": None, "Tot size": None})]
    assert ("AVG", "Tot size") in explorar_linhas(tmp_path, linhas).identicas


def test_relacoes_conferidas(tmp_path):
    e = explorar(caso(tmp_path))
    assert [coluna for coluna, _, _ in RELACOES] == [
        "Variance", "Tot size", "LLC", "ARP", "Tot sum", "ack_count", "syn_count", "fin_count", "rst_count",
    ]
    assert list(e.relacoes) == [coluna for coluna, _, _ in RELACOES]
    assert all(relacao.fora == 0 for relacao in e.relacoes.values())
    assert all(relacao.conferidas == 17 for relacao in e.relacoes.values())
    assert e.relacoes["Variance"].expressao == "`Std`²"
    assert e.relacoes["ack_count"].expressao == "`ack_flag_number` × `Number`"


@pytest.mark.parametrize("coluna,trocas", [
    ("Variance", {"Variance": 5.0}),
    ("Tot size", {"Tot size": 60.5}),
    ("LLC", {"LLC": 0.0}),
    ("ARP", {"ARP": 0.5}),
    ("Tot sum", {"Tot sum": 601.0}),
    ("ack_count", {"ack_count": 3}),
    ("syn_count", {"syn_flag_number": 0.1}),
])
def test_relacao_quebrada_e_contada(tmp_path, coluna, trocas):
    linhas = [*LINHAS_DO_CASO, linha("XSS", desvio=3.0, trocas=trocas)]
    e = explorar_linhas(tmp_path, linhas)
    assert e.relacoes[coluna].fora == 1
    assert e.relacoes[coluna].conferidas == 18
    assert [nome for nome, relacao in e.relacoes.items() if relacao.fora] == [coluna]


def test_relacao_mede_o_maior_desvio_relativo(tmp_path):
    e = explorar_linhas(tmp_path, [linha("XSS", desvio=3.0, trocas={"Variance": 4.5})])
    assert e.relacoes["Variance"].maior_desvio == pytest.approx(0.5)


def test_relacao_tolera_erro_de_arredondamento(tmp_path):
    linhas = [
        linha("XSS", desvio=3.0, trocas={"Variance": 9.000000000000002}),
        linha("DDOS-ICMP_FLOOD", quadros=100, trocas={"ack_flag_number": 0.07, "ack_count": 7}),
    ]
    e = explorar_linhas(tmp_path, linhas)
    assert e.relacoes["Variance"].fora == 0 and 0 < e.relacoes["Variance"].maior_desvio < 1e-12
    assert e.relacoes["ack_count"].fora == 0


def test_relacao_com_campo_vazio(tmp_path):
    linhas = [
        linha("XSS", quadros=1, trocas={"Std": None, "Variance": None}),  # vazio dos dois lados: vale
        linha("XSS", trocas={"Std": None, "Variance": 4.0}),  # vazio de um lado só: não vale
    ]
    e = explorar_linhas(tmp_path, linhas)
    assert (e.relacoes["Variance"].conferidas, e.relacoes["Variance"].fora) == (2, 1)


def test_min_media_e_max_fora_de_ordem(tmp_path):
    linhas = [*LINHAS_DO_CASO, linha("XSS", trocas={"Min": 61.0}), linha("XSS", trocas={"Max": 59.0})]
    assert explorar(caso(tmp_path)).fora_de_ordem == 0
    assert explorar_linhas(tmp_path, linhas).fora_de_ordem == 2


def test_valores_de_protocol_type(tmp_path):
    assert explorar(caso(tmp_path)).protocolos == {6: 14, 17: 3}


LINHAS_REPETIDAS = (
    [linha("DDOS-TCP_FLOOD", quadros=100, media=61.0)] * 3
    + [linha("DDOS-UDP_FLOOD", quadros=100, media=62.0), linha("DOS-UDP_FLOOD", quadros=100, media=62.0)]
    + [linha("DDOS-SYN_FLOOD", quadros=100, media=63.0), linha("DDOS-SYNONYMOUSIP_FLOOD", quadros=100, media=63.0)]
    + [linha("BENIGN", media=300.0 + i) for i in range(4)]
)


def test_linhas_repetidas_nas_39_features(tmp_path):
    d = explorar_linhas(tmp_path, LINHAS_REPETIDAS).duplicatas
    assert d.distintas == 7
    assert d.repetidas == 7
    assert d.com_outro_rotulo == 4
    assert d.com_outra_categoria == 2
    repetidas = {rotulo: n for rotulo, n in d.repetidas_por_rotulo.items() if n}
    assert repetidas == {
        "DDoS-TCP_Flood": 3, "DDoS-UDP_Flood": 1, "DoS-UDP_Flood": 1, "DDoS-SYN_Flood": 1,
        "DDoS-SynonymousIP_Flood": 1,
    }
    outro_rotulo = {rotulo: n for rotulo, n in d.com_outro_rotulo_por_rotulo.items() if n}
    assert outro_rotulo == {
        "DDoS-UDP_Flood": 1, "DoS-UDP_Flood": 1, "DDoS-SYN_Flood": 1, "DDoS-SynonymousIP_Flood": 1,
    }
    outra_categoria = {rotulo: n for rotulo, n in d.com_outra_categoria_por_rotulo.items() if n}
    assert outra_categoria == {"DDoS-UDP_Flood": 1, "DoS-UDP_Flood": 1}
    assert d.combinacoes == {
        ("DDoS-UDP_Flood", "DoS-UDP_Flood"): 2, ("DDoS-SYN_Flood", "DDoS-SynonymousIP_Flood"): 2,
    }
    assert list(d.repetidas_por_rotulo) == list(ROTULOS)


LINHAS_EM_CONFLITO = [
    # Mesma combinação, 2 linhas de DoS e 1 de DDoS: a resposta mais frequente erra a de DDoS.
    *[linha("DOS-UDP_FLOOD", quadros=100, media=62.0)] * 2,
    linha("DDOS-UDP_FLOOD", quadros=100, media=62.0),
    # Empate entre DDoS e DoS: vale a primeira categoria da lista, e a linha de DoS é o erro.
    linha("DDOS-TCP_FLOOD", quadros=100, media=63.0),
    linha("DOS-TCP_FLOOD", quadros=100, media=63.0),
    # Rótulos diferentes da mesma categoria: sem erro em 8 categorias.
    linha("DDOS-SYN_FLOOD", quadros=100, media=64.0),
    linha("DDOS-SYNONYMOUSIP_FLOOD", quadros=100, media=64.0),
    linha("BENIGN"),
    linha("BENIGN", media=70.0),
]


def test_erro_minimo_de_quem_so_ve_as_39_features(tmp_path):
    d = explorar_linhas(tmp_path, LINHAS_EM_CONFLITO, linhas_por_bloco=4).duplicatas
    assert d.erro_minimo_por_categoria == {
        "DDoS": 1, "DoS": 1, "Mirai": 0, "Recon": 0, "Spoofing": 0, "Web": 0, "BruteForce": 0, "Benign": 0,
    }
    assert d.com_outra_categoria == 5


def test_sem_conflito_o_erro_minimo_e_zero(tmp_path):
    d = explorar(caso(tmp_path)).duplicatas
    assert set(d.erro_minimo_por_categoria.values()) == {0}
    assert list(d.erro_minimo_por_categoria) == ["DDoS", "DoS", "Mirai", "Recon", "Spoofing", "Web", "BruteForce", "Benign"]


def test_relatorio_traz_o_erro_minimo_por_categoria(tmp_path):
    relatorio = montar_relatorio(explorar_linhas(tmp_path, LINHAS_EM_CONFLITO))
    assert "| DDoS | 4 | 1 | 75,00% |" in relatorio
    assert "| DoS | 3 | 1 | 66,67% |" in relatorio
    assert "| Benign | 2 | 0 | 100,00% |" in relatorio
    assert "| Total | 9 | 2 | 77,78% |" in relatorio
    resumo = relatorio.split("## Resumo\n")[1].split("## 1. ")[0]
    assert "o acerto em 8 categorias não passa de 77,78%" in resumo
    assert "não passa de" not in montar_relatorio(explorar(caso(tmp_path)))


def test_valores_negativos_sao_contados(tmp_path):
    linhas = [*LINHAS_DO_CASO, linha("XSS", trocas={"IAT": -0.017818}), linha("XSS", trocas={"IAT": "-inf"})]
    e = explorar_linhas(tmp_path, linhas)
    assert e.colunas["IAT"].negativos == 1
    assert e.colunas["AVG"].negativos == 0
    assert "Só `IAT` tem valores negativos, em 1 linha." in montar_relatorio(e)
    assert "Nenhuma coluna tem valor negativo." in montar_relatorio(explorar(caso(tmp_path)))


def test_sem_linhas_repetidas(tmp_path):
    d = explorar(caso(tmp_path)).duplicatas
    assert (d.distintas, d.repetidas, d.com_outro_rotulo, d.com_outra_categoria) == (17, 0, 0, 0)
    assert d.combinacoes == {}


def test_linhas_com_o_mesmo_campo_vazio_contam_como_repetidas(tmp_path):
    vazia = linha("DDOS-ICMP_FLOOD", quadros=1, trocas={"Rate": "inf", "Std": None, "Variance": None})
    d = explorar_linhas(tmp_path, [vazia, vazia, linha("XSS")]).duplicatas
    assert (d.distintas, d.repetidas) == (2, 2)


@pytest.mark.parametrize("coluna", COLUNAS)
def test_linhas_que_diferem_em_uma_so_coluna_nao_sao_repetidas(tmp_path, coluna):
    base = linha("XSS", desvio=3.0)
    campos = base.split(",")
    posicao = COLUNAS.index(coluna)
    campos[posicao] = str(float(campos[posicao]) + 1)
    d = explorar_linhas(tmp_path, [base, base, ",".join(campos)]).duplicatas
    # As duas linhas iguais formam uma combinação, e a que muda só nessa coluna forma outra.
    assert (d.distintas, d.repetidas, d.maior_grupo) == (2, 2, 2)


def test_repeticao_e_encontrada_entre_arquivos_e_entre_blocos(tmp_path):
    arquivos = [
        escrever(tmp_path / "Merged01.csv", LINHAS_REPETIDAS[::2]),
        escrever(tmp_path / "Merged02.csv", LINHAS_REPETIDAS[1::2]),
    ]
    d = explorar(arquivos, linhas_por_bloco=2).duplicatas
    assert (d.distintas, d.repetidas, d.com_outro_rotulo, d.com_outra_categoria) == (7, 7, 4, 2)


def test_resultado_nao_depende_do_tamanho_do_bloco(tmp_path):
    arquivo = escrever(tmp_path / "a.csv", [*LINHAS_DO_CASO, *LINHAS_REPETIDAS])
    assert explorar([arquivo], linhas_por_bloco=4) == explorar([arquivo])


def test_rotulo_desconhecido_da_erro(tmp_path):
    with pytest.raises(ValueError, match=r"a\.csv, linha 3: rótulo desconhecido: 'ATAQUE_NOVO'"):
        explorar_linhas(tmp_path, [linha("XSS"), linha("ATAQUE_NOVO")])


def test_arquivo_vazio_ou_sem_a_coluna_label_da_erro(tmp_path):
    vazio = tmp_path / "vazio.csv"
    vazio.write_bytes(b"")
    with pytest.raises(ValueError, match=r"vazio\.csv: arquivo vazio"):
        explorar([vazio])
    sem_label = escrever(tmp_path / "sem.csv", [",".join(["0"] * 39)], cabecalho=COLUNAS)
    with pytest.raises(ValueError, match=r"sem\.csv: falta a coluna Label"):
        explorar([sem_label])


def test_arquivo_so_com_cabecalho_nao_quebra(tmp_path):
    e = explorar([escrever(tmp_path / "a.csv", [])])
    assert e.linhas == 0 and e.duplicatas.distintas == 0
    assert "0 linhas" in montar_relatorio(e)


def test_valor_que_nao_e_numero_da_erro_com_o_nome_do_arquivo(tmp_path):
    with pytest.raises(ValueError, match=r"a\.csv: valor que não é número"):
        explorar_linhas(tmp_path, [linha("XSS"), linha("XSS", trocas={"Rate": "rápido"})])


def test_arquivo_cortado_no_fim_e_registrado(tmp_path):
    arquivo = escrever(tmp_path / "Merged42.csv", LINHAS_DO_CASO)
    with open(arquivo, "a") as cortado:
        cortado.write("20.0,6,64.0,960")
    e = explorar([arquivo])
    assert e.linhas == 17 and e.arquivos[0]["final_incompleto"] is True
    relatorio = montar_relatorio(e)
    assert "termina no meio de uma linha" in relatorio and "| `Merged42.csv` | 17 |" in relatorio


def test_relatorio_traz_as_contagens_com_percentuais(tmp_path):
    relatorio = montar_relatorio(explorar(caso(tmp_path)))
    assert relatorio.startswith("# Exploração do MERGED_CSV\n")
    assert "2 arquivos" in relatorio and "17 linhas" in relatorio
    assert "| DDoS | 12 | 7 | 41,18% |" in relatorio
    assert "| Benign | 1 | 4 | 23,53% |" in relatorio
    assert "DDoS e DoS somam 58,82% das linhas" in relatorio
    assert "| `DDoS-ICMP_Flood` | DDoS | 7 | 41,1765% |" in relatorio
    assert "| `XSS` | Web | 1 | 5,8824% |" in relatorio
    assert "(`DDoS-ICMP_Flood`, 7 linhas) e a menor (`XSS`, 1 linha) é de 7,0 para 1" in relatorio


def test_relatorio_abre_com_um_resumo(tmp_path):
    relatorio = montar_relatorio(explorar_linhas(tmp_path, [*LINHAS_DO_CASO, *LINHAS_REPETIDAS]))
    resumo = relatorio.split("## Resumo\n")[1].split("## 1. ")[0]
    assert "- 28 linhas em 1 arquivo, com 39 features e a coluna `Label`." in resumo
    assert "- DDoS e DoS somam 60,71% das linhas, e o tráfego benigno é 28,57%." in resumo
    assert "- A maior classe (`BenignTraffic`) tem 8,0 vezes as linhas da menor (`XSS`)." in resumo
    assert "- A janela completa é de 100 quadros em 6 classes e de 10 em 3." in resumo
    assert "- Não há valores vazios nem infinitos." in resumo
    assert "- 25,00% das linhas repetem as 39 features de outra linha, e 7,14% têm" in resumo


def test_resumo_aponta_vazios_infinitos_redundancias_e_arquivos_cortados(tmp_path):
    arquivo = escrever(tmp_path / "Merged42.csv", [
        *LINHAS_DO_CASO,
        linha("DDOS-PSHACK_FLOOD", quadros=1, trocas={"Rate": "inf", "Std": None, "Variance": None}),
    ])
    with open(arquivo, "a") as cortado:
        cortado.write("20.0,6,64.0,960")
    relatorio = montar_relatorio(explorar([arquivo]))
    resumo = relatorio.split("## Resumo\n")[1].split("## 1. ")[0]
    assert "- Há valores vazios em `Std` e `Variance` e infinitos em `Rate`." in resumo
    assert "9 das 39 colunas podem ser recalculadas a partir das outras" in resumo
    assert "- 1 arquivo termina no meio de uma linha" in resumo


def test_relatorio_formata_numeros_grandes_e_pequenos(tmp_path):
    linhas = [
        linha("XSS", trocas={"Rate": 1754940.52, "IAT": 5.6982e-07, "AVG": 4023.5, "Tot size": 4023.5}),
        linha("XSS", trocas={"Rate": 0.0416031}),
    ]
    relatorio = montar_relatorio(explorar_linhas(tmp_path, linhas))
    assert "| `Rate` | 0,0416031 | 1.754.940,5 |" in relatorio
    assert "| `IAT` | 5,7e-07 | 0,001 |" in relatorio
    assert "| `AVG` | 60 | 4.023,5 |" in relatorio


def test_relatorio_lista_as_classes_ausentes(tmp_path):
    relatorio = montar_relatorio(explorar(caso(tmp_path)))
    assert "29 das 34 classes não têm nenhuma linha" in relatorio
    assert "`Mirai-udpplain`" in relatorio


def test_relatorio_traz_a_janela_por_classe(tmp_path):
    relatorio = montar_relatorio(explorar(caso(tmp_path)))
    assert "| `DDoS-ICMP_Flood` | DDoS | 100 | 6 | 85,71% | 37 |" in relatorio
    assert "| `Recon-PortScan` | Recon | 10 | 1 | 50,00% | 9 |" in relatorio
    assert "| `BenignTraffic` | Benign | 10 | 4 | 100,00% | 10 |" in relatorio


def test_relatorio_traz_vazios_infinitos_e_redundancias(tmp_path):
    linhas = [
        *LINHAS_DO_CASO,
        linha("DDOS-PSHACK_FLOOD", quadros=1, trocas={"Rate": "inf", "Std": None, "Variance": None}),
        linha("XSS", desvio=3.0, trocas={"Variance": 5.0}),
    ]
    relatorio = montar_relatorio(explorar_linhas(tmp_path, linhas))
    assert "| `Rate` | 0 | 1 | 1 |" in relatorio
    assert "| `Std` | 1 | 0 | 1 |" in relatorio
    assert "| `Variance` | `Std`² | 19 | 1 |" in relatorio
    assert "| `Tot size` | `AVG` | 19 | 0 |" in relatorio
    assert "`Telnet`" in relatorio  # coluna constante


def test_relatorio_traz_as_linhas_repetidas(tmp_path):
    relatorio = montar_relatorio(explorar_linhas(tmp_path, LINHAS_REPETIDAS))
    assert "7 combinações distintas" in relatorio
    assert "| `DDoS-UDP_Flood` e `DoS-UDP_Flood` | 2 |" in relatorio
    assert "| `DDoS-TCP_Flood` | DDoS | 3 | 3 | 100,00% | 0 | 0 |" in relatorio
    assert "| `DoS-UDP_Flood` | DoS | 1 | 1 | 100,00% | 1 | 1 |" in relatorio


def pastas_por_ataque(tmp_path):
    raiz = tmp_path / "CICIoT2023"
    sem_rotulo = [texto.rsplit(",", 1)[0] for texto in LINHAS_DO_CASO]
    escrever(raiz / "DDoS-ICMP_Flood" / "DDoS-ICMP_Flood.pcap.csv", sem_rotulo[:5], cabecalho=COLUNAS)
    escrever(raiz / "DDoS-ICMP_Flood" / "DDoS-ICMP_Flood1.pcap.csv", sem_rotulo[5:9], cabecalho=COLUNAS)
    escrever(raiz / "Benign_Final" / "BenignTraffic.pcap.csv", sem_rotulo[:4], cabecalho=COLUNAS)
    cortado = escrever(raiz / "XSS" / "XSS.pcap.csv", sem_rotulo[:2], cabecalho=COLUNAS)
    with open(cortado, "a") as arquivo:
        arquivo.write("20.0,6,64")
    escrever(raiz / "MERGED_CSV" / "Merged01.csv", LINHAS_DO_CASO)
    escrever(raiz / "pcap2csv" / "saida.csv", sem_rotulo, cabecalho=COLUNAS)
    (raiz / "README.pdf").write_bytes(b"")
    return raiz


def test_contar_por_ataque_le_as_pastas_com_nome_de_classe(tmp_path):
    contagem = contar_por_ataque(pastas_por_ataque(tmp_path))
    assert contagem == {
        "DDoS-ICMP_Flood": {"arquivos": 2, "linhas": 9, "incompletos": []},
        "XSS": {"arquivos": 1, "linhas": 2, "incompletos": ["XSS.pcap.csv"]},
        "BenignTraffic": {"arquivos": 1, "linhas": 4, "incompletos": []},
    }


def test_contar_por_ataque_sem_pastas(tmp_path):
    assert contar_por_ataque(tmp_path) == {}
    assert contar_por_ataque(tmp_path / "ausente") == {}


def test_relatorio_compara_com_os_csvs_por_ataque(tmp_path):
    raiz = pastas_por_ataque(tmp_path)
    e = explorar([raiz / "MERGED_CSV" / "Merged01.csv"])
    relatorio = montar_relatorio(e, por_ataque=contar_por_ataque(raiz))
    assert "| `DDoS-ICMP_Flood` | 2 | 9 | 7 | 2 | 22,22% |" in relatorio
    assert "| `XSS` | 1 | 2 | 1 | 1 | 50,00% |" in relatorio
    assert "`XSS.pcap.csv`" in relatorio
    assert "Nas 2 classes cujos CSVs por ataque estão inteiros, a diferença vai de 0,00% a 22,22%" in relatorio
    assert "CSVs por ataque" not in montar_relatorio(e)


def test_main_grava_o_relatorio(tmp_path, capsys):
    raiz = pastas_por_ataque(tmp_path)
    saida = tmp_path / "resultados" / "exploracao.md"
    assert main(["--entrada", str(raiz / "MERGED_CSV"), "--saida", str(saida)]) == 0
    relatorio = saida.read_text(encoding="utf-8")
    assert "17 linhas" in relatorio and "| `XSS` | 1 | 2 | 1 | 1 | 50,00% |" in relatorio
    assert "relatório em" in capsys.readouterr().err


def test_main_com_erro_nao_grava_o_relatorio(tmp_path, capsys):
    escrever(tmp_path / "MERGED_CSV" / "Merged01.csv", [linha("ATAQUE_NOVO")])
    saida = tmp_path / "exploracao.md"
    assert main(["--entrada", str(tmp_path / "MERGED_CSV"), "--saida", str(saida)]) == 1
    assert "erro: Merged01.csv, linha 2: rótulo desconhecido" in capsys.readouterr().err
    assert not saida.exists()
    assert main(["--entrada", str(tmp_path / "ausente"), "--saida", str(saida)]) == 1
    assert "nenhum arquivo CSV" in capsys.readouterr().err


@pytest.mark.skipif(not (MERGED / "Merged52.csv").exists(), reason="dataset ausente")
def test_merged52_real():
    e = explorar([MERGED / "Merged52.csv"])
    assert e.linhas == sum(e.por_rotulo.values()) > 60_000
    assert e.arquivos[0]["final_incompleto"] is True
    assert max(e.janela["DDoS-ICMP_Flood"]) == 100 and max(e.janela["BenignTraffic"]) == 10
    assert ("AVG", "Tot size") in e.identicas and ("IPv", "LLC") in e.identicas
    assert all(relacao.fora == 0 for relacao in e.relacoes.values())
    assert e.colunas["Rate"].infinitos >= e.colunas["Std"].vazios == e.colunas["Variance"].vazios
    assert e.duplicatas.com_outra_categoria > 0
    assert "## " in montar_relatorio(e)
