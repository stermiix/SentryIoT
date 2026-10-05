import pytest

from codigo.classificador.mapeamento import CATEGORIAS
from codigo.mcp.acoes import BASE
from codigo.mcp.base import (
    LIMITE_DE_TRECHOS,
    PASTA_PADRAO,
    carregar,
    mitigacoes,
    pesquisar,
)
from codigo.mcp.tipos import Trecho

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


# --- pesquisa --------------------------------------------------------------------------------


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


# --- a base provisória que acompanha o stub --------------------------------------------------


def test_base_provisoria_tem_o_aviso_de_conteudo_provisorio():
    aviso = (PASTA_PADRAO / "README.md").read_text(encoding="utf-8")
    assert PASTA_PADRAO.name == "base_provisoria"
    assert "conteúdo provisório do stub" in aviso
    assert "levantamento de mitigações" in aviso


def test_base_provisoria_e_valida_e_so_usa_categorias_e_acoes_conhecidas():
    secoes = carregar()
    assert len({secao.origem for secao in secoes}) >= 3
    for secao in secoes:
        assert (PASTA_PADRAO / secao.origem).is_file()
        assert set(secao.categorias) <= set(CATEGORIAS)
        assert secao.acao is None or secao.acao in BASE
        assert secao.titulo and secao.texto


def test_base_provisoria_nao_cita_fonte_norma_nem_link():
    for arquivo in PASTA_PADRAO.glob("*.md"):
        texto = arquivo.read_text(encoding="utf-8")
        for proibido in ("http", "www.", "ISO", "NIST", "RFC", "OWASP", "et al"):
            assert proibido not in texto, f"{arquivo.name} cita {proibido}"


@pytest.mark.parametrize("categoria", ["DDoS", "DoS", "BruteForce", "Recon"])
def test_base_provisoria_cobre_as_categorias_dos_cenarios_do_stub(categoria):
    recomendadas = mitigacoes(carregar(), categoria)
    assert recomendadas
    assert all(trecho.acao in BASE for trecho in recomendadas)


def test_base_provisoria_nao_recomenda_acao_para_trafego_benigno():
    assert mitigacoes(carregar(), "Benign") == []


@pytest.mark.parametrize("consulta,origem,palavra_do_titulo", [
    ("syn flood", "flood.md", "SYN cookies"),
    ("bloqueio de conta após tentativas", "forca_bruta.md", "conta"),
    ("fechar portas sem uso", "varredura.md", "portas"),
    ("falso positivo", "alerta_duvidoso.md", "falso positivo"),
])
def test_pesquisa_na_base_provisoria_acha_medidas_fora_do_catalogo(consulta, origem, palavra_do_titulo):
    primeiro = pesquisar(carregar(), consulta)[0]
    assert primeiro.origem == origem
    assert palavra_do_titulo in primeiro.titulo
    assert primeiro.acao is None
