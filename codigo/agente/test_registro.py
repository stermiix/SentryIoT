"""Testes do registro das chamadas ao modelo no log de eventos."""

import pytest

from codigo.agente.laco import ChamadaAoModelo
from codigo.agente.registro import chamadas_no_log
from codigo.mcp.eventos import GravadorDoAgente, Registro, ler
from codigo.mcp.stub import Stub


@pytest.fixture
def log(tmp_path):
    """Um log com os quatro incidentes de exemplo abertos."""
    caminho = tmp_path / "eventos.jsonl"
    Stub(Registro(caminho), agente="todos").abrir_incidentes()
    return caminho


def chamada(**mudancas):
    dados = {
        "volta": 1, "modelo": "qwen3.8-27c", "tokens_entrada": 812, "tokens_saida": 164, "duracao_ms": 2300.0,
        "tools_pedidas": ("obter_incidente",),
    }
    return ChamadaAoModelo(**{**dados, **mudancas})


def test_cada_chamada_vira_um_evento_llm_chamada_do_incidente(log):
    gravar = chamadas_no_log(GravadorDoAgente("triagem", log), "inc-0001")

    gravar(chamada())
    gravar(chamada(volta=2, tokens_entrada=900, tokens_saida=30, duracao_ms=1100.5))

    eventos = [evento for evento in ler(log) if evento.tipo == "llm_chamada"]
    assert [evento.incidente for evento in eventos] == ["inc-0001", "inc-0001"]
    assert [(e.dados.agente, e.dados.modelo, e.dados.tokens_entrada, e.dados.tokens_saida, e.dados.duracao_ms) for e in eventos] == [
        ("triagem", "qwen3.8-27c", 812, 164, 2300.0),
        ("triagem", "qwen3.8-27c", 900, 30, 1100.5),
    ]


@pytest.mark.parametrize("entrada,saida", [(None, None), (10, None), (None, 5)])
def test_tokens_desconhecidos_nao_sao_registrados_como_zero(log, entrada, saida):
    gravar = chamadas_no_log(GravadorDoAgente("decisao", log), "inc-0001")

    dados = chamada(tokens_entrada=entrada, tokens_saida=saida)
    with pytest.raises(ValueError, match="usage completo"):
        gravar(dados)

    assert [e for e in ler(log) if e.tipo == "llm_chamada"] == []


def test_uso_zero_informado_pelo_provedor_e_valido(log):
    gravar = chamadas_no_log(GravadorDoAgente("triagem", log), "inc-0001")
    gravar(chamada(tokens_entrada=0, tokens_saida=0))
    evento = next(e for e in ler(log) if e.tipo == "llm_chamada")
    assert (evento.dados.tokens_entrada, evento.dados.tokens_saida) == (0, 0)


def test_incidente_que_nao_existe_no_log_nao_grava(log):
    gravar = chamadas_no_log(GravadorDoAgente("triagem", log), "inc-0099")

    dados = chamada()
    with pytest.raises(ValueError, match="não existe no log"):
        gravar(dados)

    assert [e for e in ler(log) if e.tipo == "llm_chamada"] == []
