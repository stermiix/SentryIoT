import pytest

from codigo.classificador.mapeamento import CATEGORIAS
from codigo.mcp import base
from codigo.mcp.acoes import BASE
from codigo.mcp.base import (
    LIMITE_DE_MITIGACOES,
    LIMITE_DE_TRECHOS,
    PASTA_PADRAO,
    carregar,
    mitigacoes,
    pesquisar,
)
from codigo.mcp.tipos import Mitigacoes, Solucoes, Trecho, contrato

DOCUMENTO = """# Flood de teste

Categorias: DDoS, DoS

Introdução do documento, que não entra em nenhuma seção.

## Bloquear a origem

Ação do catálogo: bloquear_ip

Bloquear o endereço de origem interrompe o ataque
quando ele vem de uma origem só.

Segundo parágrafo da mesma seção.

## Ativar SYN cookies

O dispositivo responde ao SYN sem reservar memória.
"""
REFERENCIA = """# Material de referência

## Separar a rede em segmentos

Dispositivos em um segmento próprio ficam menos expostos.
"""


@pytest.fixture
def pasta(tmp_path):
    (tmp_path / "flood.md").write_text(DOCUMENTO, encoding="utf-8")
    (tmp_path / "referencia.md").write_text(REFERENCIA, encoding="utf-8")
    (tmp_path / "README.md").write_text("# Aviso\n\n## Seção do aviso\n\nNão é documento da base.\n", encoding="utf-8")
    (tmp_path / "anotacoes.txt").write_text("## Não é markdown\n\nFica de fora.\n", encoding="utf-8")
    return tmp_path


# --- leitura dos documentos ------------------------------------------------------------------


def test_cada_secao_de_um_documento_vira_um_trecho_com_a_origem(pasta):
    secoes = carregar(pasta)
    assert [(s.origem, s.titulo, s.acao, s.categorias) for s in secoes] == [
        ("flood.md", "Bloquear a origem", "bloquear_ip", ("DDoS", "DoS")),
        ("flood.md", "Ativar SYN cookies", None, ("DDoS", "DoS")),
        ("referencia.md", "Separar a rede em segmentos", None, ()),
    ]
    assert secoes[0].texto == (
        "Bloquear o endereço de origem interrompe o ataque quando ele vem de uma origem só.\n\n"
        "Segundo parágrafo da mesma seção."
    )
    assert secoes[0].documento == "Flood de teste"


def test_readme_e_arquivos_que_nao_sao_markdown_ficam_de_fora(pasta):
    assert {secao.origem for secao in carregar(pasta)} == {"flood.md", "referencia.md"}


@pytest.mark.parametrize("conteudo,trecho_do_erro", [
    ("# Título\n\nCategorias: DDoS, Exfiltracao\n\n## Seção\n\nTexto.\n", "Exfiltracao"),
    ("# Título\n\n## Seção\n\nAção do catálogo: desligar_tudo\n\nTexto.\n", "desligar_tudo"),
    ("# Título\n\n## Seção sem texto\n\n## Outra\n\nTexto.\n", "Seção sem texto"),
    ("# Título\n\nSó a introdução, sem nenhuma seção.\n", "nenhuma seção"),
    ("## Seção antes do título\n\nTexto.\n", "título"),
])
def test_documento_fora_do_formato_da_erro_com_o_nome_do_arquivo(tmp_path, conteudo, trecho_do_erro):
    (tmp_path / "ruim.md").write_text(conteudo, encoding="utf-8")
    with pytest.raises(ValueError, match=rf"ruim\.md.*{trecho_do_erro}"):
        carregar(tmp_path)


@pytest.mark.parametrize("conteudo,trecho_do_erro", [
    ("# Título\n\n## Seção\n\n" + "Texto comprido. " * 130 + "\n", "Seção"),
    ("# Título\n\n## Seção\n\nTexto com sequência de terminal \x1b[2J no meio.\n", "Seção"),
    ("# Título\n\n## " + "Título comprido " * 14 + "\n\nTexto.\n", "Título comprido"),
], ids=["texto de mais de 2.000 caracteres", "caractere de controle", "título de mais de 200 caracteres"])
def test_secao_fora_dos_limites_de_texto_do_contrato_da_erro_na_leitura(tmp_path, conteudo, trecho_do_erro):
    # O erro aparece quando a base é lida, na partida, e não na primeira consulta de um agente.
    (tmp_path / "ruim.md").write_text(conteudo, encoding="utf-8")
    with pytest.raises(ValueError, match=rf"ruim\.md.*{trecho_do_erro}") as captura:
        carregar(tmp_path)
    assert len(str(captura.value)) < 400


def test_pasta_que_nao_existe_da_erro(tmp_path):
    with pytest.raises(ValueError, match="pasta da base"):
        carregar(tmp_path / "nao_existe")


# --- tabela do levantamento ------------------------------------------------------------------

LEVANTAMENTO = """# Flood de teste - Ataque de volume

Categorias: DDoS

- **Definição:** introdução em lista, que não entra em nenhuma medida.

## Mitigações recomendadas

| Mitigações Recomendadas | Ação do catálogo | Fonte |
| --- | --- | --- |
| Filtrar as origens confirmadas do ataque. | `bloquear_ip` | [MITRE ATT&CK — T1498](https://attack.mitre.org/techniques/T1498/) |
| Habilitar SYN cookies no serviço atacado. | nenhuma | [MITRE ATT&CK — T1499](https://attack.mitre.org/techniques/T1499/); [IETF — RFC 4987](https://www.rfc-editor.org/info/rfc4987/) |
"""


def test_cada_linha_da_tabela_vira_uma_medida_com_a_fonte_no_texto(tmp_path):
    (tmp_path / "ddos.md").write_text(LEVANTAMENTO, encoding="utf-8")
    secoes = carregar(tmp_path)
    assert [(s.origem, s.titulo, s.acao, s.categorias) for s in secoes] == [
        ("ddos.md", "Filtrar as origens confirmadas do ataque.", "bloquear_ip", ("DDoS",)),
        ("ddos.md", "Habilitar SYN cookies no serviço atacado.", None, ("DDoS",)),
    ]
    # O link em markdown vira nome e endereço, que o modelo lê sem a sintaxe.
    assert secoes[0].texto == "Fonte: MITRE ATT&CK — T1498 (https://attack.mitre.org/techniques/T1498/)"
    assert secoes[1].texto == (
        "Fonte: MITRE ATT&CK — T1499 (https://attack.mitre.org/techniques/T1499/); "
        "IETF — RFC 4987 (https://www.rfc-editor.org/info/rfc4987/)"
    )
    assert mitigacoes(secoes, "DDoS") == [secoes[0].trecho()]
    assert pesquisar(secoes, "syn cookies")[0].titulo == "Habilitar SYN cookies no serviço atacado."


def test_as_colunas_sao_achadas_pelo_nome_e_nao_pela_posicao(tmp_path):
    invertida = LEVANTAMENTO.replace("| Ação do catálogo | Fonte |", "| Fonte | Ação do catálogo |").replace(
        "| `bloquear_ip` | [MITRE ATT&CK — T1498](https://attack.mitre.org/techniques/T1498/) |",
        "| [MITRE ATT&CK — T1498](https://attack.mitre.org/techniques/T1498/) | `bloquear_ip` |",
    ).replace(
        "| nenhuma | [MITRE ATT&CK — T1499](https://attack.mitre.org/techniques/T1499/); "
        "[IETF — RFC 4987](https://www.rfc-editor.org/info/rfc4987/) |",
        "| [MITRE ATT&CK — T1499](https://attack.mitre.org/techniques/T1499/) | nenhuma |",
    )
    (tmp_path / "ddos.md").write_text(invertida, encoding="utf-8")
    assert [(s.acao, s.texto[:26]) for s in carregar(tmp_path)] == [
        ("bloquear_ip", "Fonte: MITRE ATT&CK — T149"), (None, "Fonte: MITRE ATT&CK — T149"),
    ]


@pytest.mark.parametrize("troca,trecho_do_erro", [
    (("| Ação do catálogo | Fonte |", "| Ação | Fonte |"), "precisa das colunas"),
    (("| Ação do catálogo | Fonte |", "| Ação do catálogo | Origem |"), "precisa das colunas"),
    (("`bloquear_ip`", "`desligar_tudo`"), "desligar_tudo"),
    (("| nenhuma |", "| nenhuma | a mais |"), "colunas do cabeçalho"),
    (("[MITRE ATT&CK — T1498](https://attack.mitre.org/techniques/T1498/)", ""), "sem a fonte"),
    (("## Mitigações recomendadas\n", "## Mitigações recomendadas\n\nTexto solto ao lado da tabela.\n"), "tabela e texto"),
], ids=["sem a coluna da ação", "sem a coluna da fonte", "ação fora do catálogo", "linha com coluna a mais",
        "medida sem fonte", "seção com tabela e texto"])
def test_tabela_fora_do_formato_da_erro_com_o_nome_do_arquivo(tmp_path, troca, trecho_do_erro):
    antes, depois = troca
    assert antes in LEVANTAMENTO
    (tmp_path / "ruim.md").write_text(LEVANTAMENTO.replace(antes, depois, 1), encoding="utf-8")
    with pytest.raises(ValueError, match=rf"ruim\.md.*{trecho_do_erro}"):
        carregar(tmp_path)



# --- mitigações por categoria ----------------------------------------------------------------


def test_mitigacoes_sao_as_secoes_da_categoria_que_o_catalogo_cobre(pasta):
    secoes = carregar(pasta)
    esperado = [
        Trecho(
            origem="flood.md", titulo="Bloquear a origem", acao="bloquear_ip",
            texto=secoes[0].texto,
        )
    ]
    assert mitigacoes(secoes, "DDoS") == esperado
    assert mitigacoes(secoes, "DoS") == esperado
    assert mitigacoes(secoes, "Recon") == []


def test_mitigacoes_tem_teto_de_trechos_por_resposta(tmp_path):
    # Numa base grande, a resposta viraria milhões de caracteres para o modelo.
    secoes = "".join(
        f"## Medida {n}\n\nAção do catálogo: limitar_taxa\n\nLimitar a taxa, variante {n}.\n\n" for n in range(1, 31)
    )
    (tmp_path / "muitas.md").write_text("# Muitas medidas\n\nCategorias: DDoS\n\n" + secoes, encoding="utf-8")
    recomendadas = mitigacoes(carregar(tmp_path), "DDoS")
    assert LIMITE_DE_MITIGACOES == 10
    # Na ordem dos documentos.
    assert [trecho.titulo for trecho in recomendadas] == [f"Medida {n}" for n in range(1, 11)]
    # O teto está também no contrato.
    definicoes = contrato()["$defs"]
    assert definicoes["Mitigacoes"]["properties"]["mitigacoes"]["maxItems"] == LIMITE_DE_MITIGACOES
    assert definicoes["Solucoes"]["properties"]["trechos"]["maxItems"] == LIMITE_DE_TRECHOS
    with pytest.raises(ValueError):
        Mitigacoes(categoria="DDoS", mitigacoes=recomendadas * 2, acoes=[])
    with pytest.raises(ValueError):
        Solucoes(consulta="x", fonte="base_local", trechos=recomendadas[:4])


# --- pesquisa --------------------------------------------------------------------------------


def test_cada_secao_e_quebrada_em_palavras_uma_vez_so_na_leitura(pasta, monkeypatch):
    secoes = carregar(pasta)
    quebras = []
    original = base._raizes
    monkeypatch.setattr(base, "_raizes", lambda texto: quebras.append(texto) or original(texto))
    for consulta in ("syn cookies", "bloquear a origem", "segmento de rede"):
        pesquisar(secoes, consulta)
    # Só a consulta é quebrada em palavras a cada pesquisa; as seções já vêm prontas da leitura.
    assert quebras == ["syn cookies", "bloquear a origem", "segmento de rede"]


def test_pesquisa_devolve_trechos_com_a_origem_de_cada_um(pasta):
    trechos = pesquisar(carregar(pasta), "syn cookies")
    assert trechos == [
        Trecho(
            origem="flood.md", titulo="Ativar SYN cookies", acao=None,
            texto="O dispositivo responde ao SYN sem reservar memória.",
        )
    ]


def test_pesquisa_alcanca_o_que_esta_fora_do_catalogo_e_o_material_de_referencia(pasta):
    assert [t.titulo for t in pesquisar(carregar(pasta), "segmento de rede")] == ["Separar a rede em segmentos"]


@pytest.mark.parametrize("consulta", [
    "SYN COOKIES", "syn-cookies", "  cookies   syn ", "Cookie de SYN", "memória", "memoria", "MEMÓRIAS",
])
def test_pesquisa_ignora_caixa_acento_pontuacao_e_plural(pasta, consulta):
    assert pesquisar(carregar(pasta), consulta)[0].titulo == "Ativar SYN cookies"


def test_pesquisa_ordena_do_trecho_mais_proximo_para_o_mais_distante(pasta):
    titulos = [trecho.titulo for trecho in pesquisar(carregar(pasta), "bloquear origem do ataque")]
    assert titulos[0] == "Bloquear a origem"


def test_palavra_do_titulo_do_documento_tambem_conta(pasta):
    assert {t.origem for t in pesquisar(carregar(pasta), "flood")} == {"flood.md"}


@pytest.mark.parametrize("consulta", ["", "   ", "de para com", "criptografia quântica", "?!"])
def test_pesquisa_sem_resultado_devolve_lista_vazia(pasta, consulta):
    assert pesquisar(carregar(pasta), consulta) == []


def test_pesquisa_devolve_no_maximo_o_limite_de_trechos(tmp_path):
    secoes = "".join(f"## Medida {n}\n\nLimitar a taxa de pacotes, variante {n}.\n\n" for n in range(1, 8))
    (tmp_path / "muitas.md").write_text("# Muitas medidas\n\n" + secoes, encoding="utf-8")
    trechos = pesquisar(carregar(tmp_path), "limitar taxa")
    assert LIMITE_DE_TRECHOS == 3
    # No empate, vale a ordem do documento.
    assert [trecho.titulo for trecho in trechos] == ["Medida 1", "Medida 2", "Medida 3"]
    assert len(pesquisar(carregar(tmp_path), "limitar taxa", limite=5)) == 5


# --- o levantamento da equipe, que é a base do servidor -------------------------------------


def test_a_base_padrao_e_o_levantamento_de_mitigacoes_da_equipe():
    assert PASTA_PADRAO.parts[-2:] == ("agente", "recomendacoes")
    assert {secao.origem for secao in carregar()} == {
        "bruteforce.md", "ddos.md", "dos.md", "mirai.md", "recon.md", "spoofing.md", "web.md",
    }


def test_levantamento_e_valido_e_so_usa_categorias_e_acoes_conhecidas():
    for secao in carregar():
        assert (PASTA_PADRAO / secao.origem).is_file()
        assert len(secao.categorias) == 1 and secao.categorias[0] in CATEGORIAS
        assert secao.acao is None or secao.acao in BASE
        assert secao.titulo and secao.texto


def test_toda_medida_do_levantamento_cita_a_fonte_com_o_endereco():
    for secao in carregar():
        assert secao.texto.startswith("Fonte: "), secao.titulo
        assert "https://" in secao.texto, secao.titulo


def test_cada_documento_do_levantamento_e_de_uma_categoria_so():
    # DDoS e DoS ficam em arquivos separados porque a categoria do incidente já vem separada.
    categoria_do_arquivo = {secao.origem: secao.categorias for secao in carregar()}
    assert categoria_do_arquivo["ddos.md"] == ("DDoS",)
    assert categoria_do_arquivo["dos.md"] == ("DoS",)


def test_levantamento_nao_recomenda_acao_para_trafego_benigno():
    assert mitigacoes(carregar(), "Benign") == []


@pytest.mark.parametrize("consulta,origem,palavra_do_titulo", [
    ("syn flood", "ddos.md", "SYN cookies"),
    ("autenticação multifator", "bruteforce.md", "MFA"),
    ("segmentar redes iot", "recon.md", "Segmentar"),
    ("dnssec", "spoofing.md", "DNSSEC"),
    ("sql injection", "web.md", "SQL Injection"),
])
def test_pesquisa_no_levantamento_acha_medidas_fora_do_catalogo(consulta, origem, palavra_do_titulo):
    primeiro = pesquisar(carregar(), consulta)[0]
    assert primeiro.origem == origem
    assert palavra_do_titulo in primeiro.titulo
    assert primeiro.acao is None


def test_medida_de_fechar_portas_do_levantamento_e_a_acao_fechar_porta():
    primeiro = pesquisar(carregar(), "fechar portas sem uso")[0]
    assert (primeiro.origem, primeiro.acao) == ("recon.md", "fechar_porta")
    assert "fechar_porta" in {trecho.acao for trecho in mitigacoes(carregar(), "Mirai")}


def test_toda_categoria_de_ataque_tem_medida_ligada_ao_catalogo():
    """Sem isso, um incidente da categoria chega ao agente de decisão sem nenhuma mitigação."""
    from codigo.mcp.base import carregar, mitigacoes
    from codigo.mcp.tipos import CATEGORIAS

    secoes = carregar()
    sem_medida = [categoria for categoria in CATEGORIAS if categoria != "Benign" and not mitigacoes(secoes, categoria)]

    assert sem_medida == []
