"""Testes do verificador do artigo: regras conferidas sobre parágrafos montados aqui, sem o .docx real."""

import zipfile

import pytest

from artigo.verificador import (
    contar_palavras,
    extrair_citacoes,
    extrair_referencias,
    ler_paragrafos,
    ler_siglas,
    verificar,
)

SIGLAS = {"IoT": "Internet das Coisas", "MCP": "Model Context Protocol", "IP": "Internet Protocol"}
NOMES = ["CICIoT2023", "BenignTraffic"]
REFERENCIAS = [
    "KELLY, D.; GLAVIN, F. G.; BARRETT, E. Denial of Wallet: defining a looming threat. arXiv, 2021.",
    "LIU, L. et al. Error prevalence in NIDS datasets: a case study on CIC-IDS-2017. In: CNS, 2022, Austin.",
    "NETO, E. C. P. et al. CICIoT2023: a real-time dataset. Sensors, v. 23, n. 13, 5941, 2023.",
]


def artigo(corpo, resumo=None, referencias=REFERENCIAS):
    resumo = resumo if resumo is not None else " ".join(["palavra"] * 160)
    return [
        "Título",
        "Resumo", resumo, "Palavras-chave: detecção de intrusão; Internet das Coisas.",
        "Abstract", resumo, "Keywords: intrusion detection; Internet of Things.",
        "1. Introdução", *corpo,
        "6. Referências bibliográficas", *referencias,
    ]


CORPO_OK = [
    "A Internet das Coisas (IoT) usa o Model Context Protocol (MCP) e o Internet Protocol (IP).",
    "O CICIoT2023 (NETO et al., 2023) tem 105 aparelhos IoT; Liu et al. (2022) revisaram outro dataset.",
    "O Denial of Wallet (KELLY; GLAVIN; BARRETT, 2021) cobra por uso, e os IPs ficam no servidor.",
]


def erros(relatorio, trecho):
    return [erro for erro in relatorio.erros if trecho in erro]


def test_artigo_em_ordem_passa():
    relatorio = verificar(artigo(CORPO_OK), SIGLAS, NOMES, paginas=12)
    assert relatorio.erros == []


def test_paginas_acima_do_limite_sao_erro():
    assert erros(verificar(artigo(CORPO_OK), SIGLAS, NOMES, paginas=21), "Páginas: 21")


def test_sem_libreoffice_as_paginas_viram_aviso():
    relatorio = verificar(artigo(CORPO_OK), SIGLAS, NOMES, paginas=None)
    assert any("Páginas: não conferidas" in aviso for aviso in relatorio.avisos)


@pytest.mark.parametrize("palavras, erro", [(149, True), (150, False), (250, False), (251, True)])
def test_resumo_de_150_a_250_palavras(palavras, erro):
    relatorio = verificar(artigo(CORPO_OK, resumo=" ".join(["termo"] * palavras)), SIGLAS, NOMES, paginas=12)
    assert bool(erros(relatorio, "Resumo:")) is erro
    assert bool(erros(relatorio, "Abstract:")) is erro


def test_pendencia_nao_conta_como_palavra_do_resumo():
    assert contar_palavras("[PENDENTE: escrever por último, com 150 a 250 palavras]") == 0


def test_citacao_entre_parenteses_com_varios_autores_e_instituicao():
    citacoes = extrair_citacoes("(KELLY; GLAVIN; BARRETT, 2021) e (CANADIAN INSTITUTE FOR CYBERSECURITY, 2023)")
    assert [(c[1], c[2]) for c in citacoes] == [(["KELLY"], "2021"), (["CANADIAN"], "2023")]


def test_parenteses_sem_sobrenome_em_maiusculas_nao_e_citacao():
    assert extrair_citacoes("o recall caiu (de 89,7% em 2023)") == []


def test_citacao_em_linha_com_artigo_antes_do_nome():
    citacoes = extrair_citacoes("A Darktrace (2024) e Kelly, Glavin e Barrett (2021) descrevem")
    assert ("DARKTRACE" in citacoes[0][1], citacoes[1][1][0]) == (True, "KELLY")


def test_ano_da_referencia_nao_vem_do_titulo():
    assert [(chave, ano) for _, chave, ano in extrair_referencias(REFERENCIAS)] == [
        ("KELLY", "2021"), ("LIU", "2022"), ("NETO", "2023")
    ]


def test_citacao_sem_referencia_e_referencia_nao_citada_sao_erro():
    corpo = CORPO_OK[:1] + ["Segundo Doménech et al. (2025), a janela varia (NETO et al., 2023)."]
    relatorio = verificar(artigo(corpo), SIGLAS, NOMES, paginas=12)
    assert erros(relatorio, "Citação sem referência: Doménech et al. (2025)")
    assert erros(relatorio, "Referência não citada no texto: KELLY")
    assert erros(relatorio, "Referência não citada no texto: LIU")


def test_referencias_fora_de_ordem_sao_aviso():
    relatorio = verificar(artigo(CORPO_OK, referencias=REFERENCIAS[::-1]), SIGLAS, NOMES, paginas=12)
    assert "Referências fora da ordem alfabética." in relatorio.avisos


def test_sigla_sem_significado_no_primeiro_uso_e_erro():
    corpo = ["O MCP liga os agentes.", "Bem depois, o Model Context Protocol aparece por extenso."] + CORPO_OK[1:]
    corpo[1] = " ".join(["texto"] * 60) + " " + corpo[1]
    assert erros(verificar(artigo(corpo), SIGLAS, NOMES, paginas=12), "Primeiro uso de MCP")


def test_sigla_fora_da_lista_e_erro_e_nome_da_lista_nao():
    corpo = CORPO_OK + ["O BenignTraffic do CICIoT2023 passa por HTTP."]
    relatorio = verificar(artigo(corpo), SIGLAS, NOMES, paginas=12)
    assert erros(relatorio, "Sigla fora de artigo/siglas.md: HTTP")
    assert not erros(relatorio, "BenignTraffic") and not erros(relatorio, "CICIoT2023")


def test_sigla_no_titulo_nao_conta_como_primeiro_uso():
    paragrafos = artigo(["O MCP liga os agentes ao Model Context Protocol."] + CORPO_OK)
    paragrafos[0] = "SentryIoT: agentes via MCP"
    assert not erros(verificar(paragrafos, SIGLAS, NOMES, paginas=12), "Primeiro uso de MCP")


def test_sigla_dentro_de_pendencia_nao_e_cobrada():
    corpo = CORPO_OK + ["[PENDENTE: explicar o NIDS e o HTTP.]"]
    assert not erros(verificar(artigo(corpo), SIGLAS, NOMES, paginas=12), "Sigla fora")


def test_sigla_da_lista_sem_uso_e_aviso():
    siglas = {**SIGLAS, "VLAN": "Virtual Local Area Network"}
    relatorio = verificar(artigo(CORPO_OK), siglas, NOMES, paginas=12)
    assert "Sigla da lista que o texto não usa: VLAN." in relatorio.avisos


def test_pendencia_e_aviso_e_com_final_vira_erro():
    corpo = CORPO_OK + ["[CONFERIR ano]"]
    assert not erros(verificar(artigo(corpo), SIGLAS, NOMES, paginas=12), "Pendência")
    assert erros(verificar(artigo(corpo), SIGLAS, NOMES, paginas=12, final=True), "Pendência no texto: [CONFERIR ano]")


def test_le_paragrafos_e_tabelas_do_docx(tmp_path):
    w = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    documento = (
        f'<w:document {w}><w:body>'
        '<w:p><w:r><w:t>Resumo</w:t></w:r></w:p><w:p/>'
        '<w:p><w:r><w:t xml:space="preserve">Texto </w:t></w:r><w:r><w:tab/><w:t>em dois runs</w:t></w:r></w:p>'
        '<w:tbl><w:tr><w:tc><w:p><w:r><w:t>célula</w:t></w:r></w:p></w:tc></w:tr></w:tbl>'
        '</w:body></w:document>'
    )
    caminho = tmp_path / "artigo.docx"
    with zipfile.ZipFile(caminho, "w") as docx:
        docx.writestr("word/document.xml", documento)
    assert ler_paragrafos(caminho) == ["Resumo", "Texto  em dois runs", "célula"]


def test_lista_de_siglas_versionada_em_ordem_e_sem_repeticao():
    siglas, nomes = ler_siglas()
    assert list(siglas) == sorted(siglas, key=str.upper)
    assert len(siglas) >= 30 and all(siglas.values())
    assert "CICIoT2023" in nomes and not set(siglas) & set(nomes)
