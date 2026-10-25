"""O gabarito da qualidade da recomendação só aceita o que o levantamento da equipe recomenda."""
import tomllib
from pathlib import Path

from codigo.mcp.acoes import BASE
from codigo.mcp.base import carregar
from codigo.mcp.tipos import CATEGORIAS

GABARITO = Path(__file__).resolve().parents[2] / "experimentos" / "gabarito_da_recomendacao.toml"
PAPEIS = {"origem", "destino"}


def ler():
    return tomllib.loads(GABARITO.read_text(encoding="utf-8"))


def test_gabarito_cobre_toda_categoria_de_ataque_e_nenhuma_outra():
    assert set(ler()) == set(CATEGORIAS) - {"Benign"}


def test_gabarito_usa_so_acoes_do_catalogo_e_papeis_conhecidos():
    for categoria, acoes in ler().items():
        assert acoes, categoria
        for acao, papeis in acoes.items():
            assert acao in BASE, (categoria, acao)
            assert papeis and set(papeis) <= PAPEIS, (categoria, acao)
            assert len(papeis) == len(set(papeis)), (categoria, acao)


def test_toda_acao_aceitavel_vem_de_uma_medida_do_levantamento_da_categoria():
    ligadas = {}
    for secao in carregar():
        if secao.acao is not None:
            for categoria in secao.categorias:
                ligadas.setdefault(categoria, set()).add(secao.acao)
    for categoria, acoes in ler().items():
        assert set(acoes) <= ligadas.get(categoria, set()), categoria


def test_toda_acao_que_o_levantamento_liga_a_categoria_esta_no_gabarito():
    # Sem isso, o agente que seguir a base à risca seria contado como erro.
    gabarito = ler()
    for secao in carregar():
        if secao.acao is not None:
            for categoria in secao.categorias:
                assert secao.acao in gabarito[categoria], (categoria, secao.titulo)
