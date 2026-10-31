"""Testes do verificador do artigo: regras conferidas sobre trechos LaTeX montados aqui, sem depender do texto real."""

import pytest

from artigo.verificador import (
    LATEX,
    RESUMO,
    Artigo,
    contar_palavras,
    ler_artigo,
    ler_siglas,
    texto_do_latex,
    verificar,
)

SIGLAS = {"IoT": "Internet das Coisas", "MCP": "Model Context Protocol", "IP": "Internet Protocol"}
NOMES = ["CICIoT2023", "BenignTraffic", "MB"]
BIB = """%% CONFERIR marca o que falta conferir.
@article{neto2023,
  author = {Neto, E. C. P. and others},
  year   = {2023},
}
@misc{kelly2021,
  author = {Kelly, D.},
  year   = {2021},
}
@misc{ferrag2024,
  note   = {CONFERIR o DOI},
}
"""


def resumo(palavras=160, rotulo="Palavras-chave", termos="detecção de intrusão; Internet das Coisas.", texto=None):
    corpo = texto if texto is not None else " ".join(["palavra"] * palavras)
    return f"% Resumo: de 150 a 250 palavras.\n\\textit{{{corpo}}}\n\n\\vspace{{\\onelineskip}}\n\n\\noindent\n\\textbf{{{rotulo}}}: {termos}\n"


CORPO_OK = r"""\section{Introdução}
\label{sec:introducao}
A Internet das Coisas (IoT) usa o Model Context Protocol (MCP) e o Internet Protocol (IP). O CICIoT2023
\cite{neto2023} tem 105 aparelhos IoT; segundo \citeonline{kelly2021}, os IPs ficam no servidor.
"""


def artigo(corpo=CORPO_OK, resumo_=None, abstract=None, principal="", bib=BIB):
    return Artigo(
        {
            RESUMO: resumo_ if resumo_ is not None else resumo(),
            "abstract": abstract if abstract is not None else resumo(rotulo="Keywords", termos="intrusion detection; IoT."),
            "1-introducao": corpo,
        },
        principal,
        bib,
    )


def erros(relatorio, trecho):
    return [erro for erro in relatorio.erros if trecho in erro]


def avisos(relatorio, trecho):
    return [aviso for aviso in relatorio.avisos if trecho in aviso]


def test_artigo_em_ordem_passa():
    relatorio = verificar(artigo(), SIGLAS, NOMES)
    assert relatorio.erros == [] and relatorio.avisos == []


def test_texto_do_latex_fica_so_com_o_texto_corrido():
    fonte = (
        "O \\textbf{DDoS+DoS} tem 99,1\\% % comentário que some\n"
        "(seção~\\ref{sec:x}, \\cite[p.~3]{neto2023}) \\pendente{falta isto}.\n"
        "\\begin{tabular}[b]{@{}r@{}}\\textbf{Janelas}\\\\\\textbf{de teste}\\end{tabular} & 214.373 \\\\ \\hline\n"
        "pcap DNS\\_Spoofing -- fim"
    )
    assert texto_do_latex(fonte) == "O DDoS+DoS tem 99,1% (seção , ) . Janelas de teste 214.373 pcap DNS_Spoofing – fim"


def test_titulo_de_secao_sai_so_quando_pedido():
    assert texto_do_latex("\\subsection{Servidor MCP}\nTexto.") == "Servidor MCP Texto."
    assert texto_do_latex("\\subsection{Servidor MCP}\nTexto.", sem_titulos=True) == "Texto."


def test_palavras_contadas_como_no_word_com_numeros_e_sem_pontuacao_solta():
    assert contar_palavras("As 39 features, 99,10% e DDoS+DoS – fim .") == 7


@pytest.mark.parametrize("palavras, erro", [(149, True), (150, False), (250, False), (251, True)])
def test_resumo_e_abstract_de_150_a_250_palavras(palavras, erro):
    relatorio = verificar(
        artigo(resumo_=resumo(palavras), abstract=resumo(palavras, "Keywords", "a; b.")), SIGLAS, NOMES
    )
    assert bool(erros(relatorio, "Resumo:")) is erro
    assert bool(erros(relatorio, "Abstract:")) is erro


def test_numero_conta_como_palavra_do_resumo():
    texto = " ".join(["palavra"] * 200 + ["39"] * 60)
    assert erros(verificar(artigo(resumo_=resumo(texto=texto)), SIGLAS, NOMES), "Resumo: 260 palavras")


def test_pendencia_nao_conta_como_palavra_do_resumo():
    fonte = "\\textit{\\pendente{escrever por último, com 150 a 250 palavras}}\n\\textbf{Palavras-chave}: a; b."
    assert erros(verificar(artigo(resumo_=fonte), SIGLAS, NOMES), "Resumo: 0 palavras")


def test_sem_palavras_chave_e_erro_e_termos_sem_ponto_e_virgula_e_aviso():
    sem_linha = verificar(artigo(resumo_=" ".join(["palavra"] * 160)), SIGLAS, NOMES)
    assert erros(sem_linha, "Resumo: falta a linha de Palavras-chave")
    com_virgulas = verificar(artigo(resumo_=resumo(termos="detecção, IoT, MCP.")), SIGLAS, NOMES)
    assert avisos(com_virgulas, "Palavras-chave: separe os termos")


def test_chave_citada_sem_entrada_no_bib_e_erro():
    corpo = CORPO_OK + "Outro trabalho \\cite{neto2023,domenech2025} e \\citeonline[p.~2]{liu2022}.\n"
    relatorio = verificar(artigo(corpo), SIGLAS, NOMES)
    assert erros(relatorio, "Citação sem entrada no referencias.bib: domenech2025")
    assert erros(relatorio, "Citação sem entrada no referencias.bib: liu2022")
    assert not erros(relatorio, "neto2023")


@pytest.mark.parametrize("trecho", ["(NETO et al., 2023)", "(KELLY; GLAVIN; BARRETT, 2021, p. 4)", "Darktrace (2024)", "Neto et al. (2023)"])
def test_citacao_escrita_a_mao_e_aviso(trecho):
    relatorio = verificar(artigo(CORPO_OK + f"Como mostra {trecho}, o tráfego varia.\n"), SIGLAS, NOMES)
    assert avisos(relatorio, f"Citação escrita à mão em 1-introducao.tex, fora da lista de referências: {trecho}")
    assert not erros(relatorio, "Sigla fora")


def test_parenteses_com_ano_sem_autor_nao_e_citacao():
    relatorio = verificar(artigo(CORPO_OK + "O recall caiu (de 89,7% em 2023) no CICIoT2023 (2023).\n"), SIGLAS, NOMES)
    assert not avisos(relatorio, "Citação escrita à mão")


def test_sigla_sem_significado_no_primeiro_uso_e_erro():
    corpo = "O MCP liga os agentes. " + " ".join(["texto"] * 60) + " O Model Context Protocol aparece depois.\n" + CORPO_OK
    assert erros(verificar(artigo(corpo), SIGLAS, NOMES), "Primeiro uso de MCP no corpo")


def test_sigla_definida_so_no_resumo_e_cobrada_de_novo_no_corpo():
    fonte = resumo(texto="o Model Context Protocol (MCP) " + " ".join(["palavra"] * 160))
    corpo = "O MCP liga os agentes. " + " ".join(["texto"] * 60) + "\n" + CORPO_OK
    relatorio = verificar(artigo(corpo, resumo_=fonte), SIGLAS, NOMES)
    assert erros(relatorio, "Primeiro uso de MCP no corpo") and not erros(relatorio, "Primeiro uso de MCP no Resumo")


def test_sigla_no_titulo_de_secao_nao_conta_como_primeiro_uso():
    corpo = "\\section{O servidor MCP}\n" + " ".join(["texto"] * 60) + "\n" + CORPO_OK
    assert not erros(verificar(artigo(corpo), SIGLAS, NOMES), "Primeiro uso de MCP")


def test_sigla_fora_da_lista_e_erro_e_nome_da_lista_nao():
    corpo = CORPO_OK + "O BenignTraffic2 do CICIoT2023 tem 5 MB e passa por HTTP.\n"
    relatorio = verificar(artigo(corpo), SIGLAS, NOMES)
    assert erros(relatorio, "Sigla fora de artigo/siglas.md: HTTP")
    assert not erros(relatorio, "BenignTraffic") and not erros(relatorio, "CICIoT2023") and not erros(relatorio, ": MB")


def test_nome_da_lista_nao_esconde_sigla_que_o_contem():
    relatorio = verificar(artigo(CORPO_OK + "O SMB fica de fora.\n"), SIGLAS, NOMES)
    assert erros(relatorio, "Sigla fora de artigo/siglas.md: SMB")


def test_nome_que_e_o_significado_de_uma_sigla_vale_como_significado():
    siglas = {**SIGLAS, "JSONL": "JSON Lines"}
    corpo = CORPO_OK + "O log é gravado em JSONL (JSON Lines).\n"
    relatorio = verificar(artigo(corpo), siglas, NOMES + ["JSON Lines"])
    assert not erros(relatorio, "JSONL") and not erros(relatorio, "JSON.")


def test_sigla_dentro_de_pendencia_nao_e_cobrada():
    corpo = CORPO_OK + "\\pendente{explicar o NIDS e o HTTP}\n"
    assert not erros(verificar(artigo(corpo), SIGLAS, NOMES), "Sigla fora")


def test_sigla_da_lista_sem_uso_e_aviso():
    siglas = {**SIGLAS, "VLAN": "Virtual Local Area Network"}
    assert "Sigla da lista que o texto não usa: VLAN." in verificar(artigo(), siglas, NOMES).avisos


def test_pendencia_e_aviso_e_com_final_vira_erro():
    corpo = CORPO_OK + "Texto \\pendente{CONFERIR o ano} e \\textit{\\pendente{a implementar}}.\n"
    principal = "\\DeclareRobustCommand{\\pendente}[1]{\\textcolor{red}{#1}}\n\\pendente{referências do TCC I}\n"
    normal = verificar(artigo(corpo, principal=principal), SIGLAS, NOMES)
    assert not erros(normal, "Pendência")
    assert avisos(normal, "Pendência em 1-introducao.tex: CONFERIR o ano")
    assert avisos(normal, "Pendência em 1-introducao.tex: a implementar")
    assert avisos(normal, "Pendência em artigo.tex: referências do TCC I")
    assert len(avisos(normal, "Pendência")) == 3
    assert len(erros(verificar(artigo(corpo, principal=principal), SIGLAS, NOMES, final=True), "Pendência")) == 3


def test_conferir_no_bib_so_conta_na_referencia_citada():
    assert not avisos(verificar(artigo(), SIGLAS, NOMES), "CONFERIR")
    relatorio = verificar(artigo(CORPO_OK + "E \\cite{ferrag2024}.\n"), SIGLAS, NOMES, final=True)
    assert erros(relatorio, "Referência citada com CONFERIR no referencias.bib: ferrag2024")


def test_le_as_secoes_na_ordem_dos_input(tmp_path):
    (tmp_path / "secoes").mkdir()
    (tmp_path / "artigo.tex").write_text(
        "% \\input{secoes/comentada}\n\\input{secoes/resumo}\n\\input{secoes/2-b}\n\\input{secoes/1-a.tex}\n",
        encoding="utf-8",
    )
    for nome in ("resumo", "2-b", "1-a"):
        (tmp_path / "secoes" / f"{nome}.tex").write_text(f"texto de {nome}", encoding="utf-8")
    lido = ler_artigo(tmp_path)
    assert list(lido.secoes) == ["resumo", "2-b", "1-a"] and lido.corpo == ["texto de 2-b", "texto de 1-a"]
    assert lido.bib == ""


@pytest.mark.skipif(not (LATEX / "artigo.tex").exists(), reason="sem artigo/latex nesta cópia")
def test_le_o_artigo_do_repositorio():
    lido = ler_artigo()
    assert RESUMO in lido.secoes and "abstract" in lido.secoes and len(lido.corpo) >= 5 and "@" in lido.bib
    verificar(lido, *ler_siglas())


def test_lista_de_siglas_versionada_em_ordem_e_sem_repeticao():
    siglas, nomes = ler_siglas()
    assert list(siglas) == sorted(siglas, key=str.upper)
    assert len(siglas) >= 30 and all(siglas.values())
    assert "CICIoT2023" in nomes and not set(siglas) & set(nomes)
