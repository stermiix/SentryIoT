"""Testes do registro das chamadas ao modelo e da conclusão dos agentes no log de eventos."""

import pytest

from codigo.agente import laco
from codigo.agente.laco import RESPOSTA_FINAL, ChamadaAoModelo, ResultadoDoLaco
from codigo.agente.registro import (
    chamadas_no_log,
    conclusao_no_log,
    veredito_da_triagem,
)
from codigo.mcp.eventos import GravadorDoAgente, Registro, ler
from codigo.mcp.stub import Stub
from codigo.mcp.tipos import MOTIVOS_DE_PARADA


@pytest.fixture
def log(tmp_path):
    """Um log com os quatro incidentes de exemplo abertos."""
    caminho = tmp_path / "eventos.jsonl"
    Stub(Registro(caminho), agente="todos").abrir_incidentes()
    return caminho


def chamada(**mudancas):
    dados = {
        "volta": 1, "modelo": "qwen3.8-27c", "tokens_entrada": 812, "tokens_saida": 164, "duracao_ms": 2300.0,
        "tools_pedidas": ("obter_incidente",), "motivo_termino": "tool_calls",
    }
    return ChamadaAoModelo(**{**dados, **mudancas})


def resultado(motivo=RESPOSTA_FINAL, resposta="Rótulo da triagem: coerente", chamadas=None):
    chamadas = (chamada(), chamada(volta=2, tokens_entrada=900, tokens_saida=30)) if chamadas is None else chamadas
    return ResultadoDoLaco(motivo, resposta, (), tuple(chamadas))


def test_cada_chamada_vira_um_evento_llm_chamada_do_incidente(log):
    gravar = chamadas_no_log(GravadorDoAgente("triagem", log), "inc-0001", onde="local")

    gravar(chamada())
    gravar(chamada(volta=2, tokens_entrada=900, tokens_saida=30, duracao_ms=1100.5, motivo_termino="stop"))

    eventos = [evento for evento in ler(log) if evento.tipo == "llm_chamada"]
    assert [evento.incidente for evento in eventos] == ["inc-0001", "inc-0001"]
    assert [(e.dados.agente, e.dados.modelo, e.dados.tokens_entrada, e.dados.tokens_saida, e.dados.duracao_ms) for e in eventos] == [
        ("triagem", "qwen3.8-27c", 812, 164, 2300.0),
        ("triagem", "qwen3.8-27c", 900, 30, 1100.5),
    ]
    assert [(e.dados.motivo_termino, e.dados.onde) for e in eventos] == [("tool_calls", "local"), ("stop", "local")]


@pytest.mark.parametrize("termino", [None, "", 7, ["stop"]])
def test_finish_reason_que_nao_e_texto_fica_nulo(log, termino):
    gravar = chamadas_no_log(GravadorDoAgente("decisao", log), "inc-0001", onde="nuvem")
    gravar(chamada(motivo_termino=termino))
    evento = next(e for e in ler(log) if e.tipo == "llm_chamada")
    assert (evento.dados.motivo_termino, evento.dados.onde) == (None, "nuvem")


@pytest.mark.parametrize("onde", [None, "gateway", ""])
def test_onde_precisa_ser_local_ou_nuvem(log, onde):
    with pytest.raises(ValueError, match="local ou nuvem"):
        chamadas_no_log(GravadorDoAgente("triagem", log), "inc-0001", onde=onde)


@pytest.mark.parametrize("entrada,saida", [(None, None), (10, None), (None, 5)])
def test_tokens_desconhecidos_nao_sao_registrados_como_zero(log, entrada, saida):
    gravar = chamadas_no_log(GravadorDoAgente("decisao", log), "inc-0001", onde="nuvem")

    dados = chamada(tokens_entrada=entrada, tokens_saida=saida)
    with pytest.raises(ValueError, match="usage completo"):
        gravar(dados)

    assert [e for e in ler(log) if e.tipo == "llm_chamada"] == []


def test_uso_zero_informado_pelo_provedor_e_valido(log):
    gravar = chamadas_no_log(GravadorDoAgente("triagem", log), "inc-0001", onde="local")
    gravar(chamada(tokens_entrada=0, tokens_saida=0))
    evento = next(e for e in ler(log) if e.tipo == "llm_chamada")
    assert (evento.dados.tokens_entrada, evento.dados.tokens_saida) == (0, 0)


def test_incidente_que_nao_existe_no_log_nao_grava(log):
    gravar = chamadas_no_log(GravadorDoAgente("triagem", log), "inc-0099", onde="local")

    dados = chamada()
    with pytest.raises(ValueError, match="não existe no log"):
        gravar(dados)

    assert [e for e in ler(log) if e.tipo == "llm_chamada"] == []


# --- a conclusão de cada agente --------------------------------------------------------------


def test_os_motivos_de_parada_do_laco_sao_os_do_contrato():
    nomes = (
        "RESPOSTA_FINAL", "LIMITE_DE_VOLTAS", "CHAMADA_REPETIDA", "LIMITE_DE_TOOLS", "LIMITE_DO_HISTORICO",
        "RESPOSTA_INCOMPLETA", "RESPOSTA_VAZIA", "RECUSA_DO_PROVEDOR", "LIMITE_DE_SAIDA",
    )
    assert [getattr(laco, nome) for nome in nomes] == list(MOTIVOS_DE_PARADA)


def test_a_triagem_conclui_com_motivo_voltas_tokens_e_veredito(log):
    conclusao_no_log(GravadorDoAgente("triagem", log), "inc-0001", resultado())

    evento = next(e for e in ler(log) if e.tipo == "agente_concluido")
    assert evento.incidente == "inc-0001"
    assert evento.dados.model_dump() == {
        "agente": "triagem", "motivo": "resposta_final", "voltas": 2, "tokens_entrada": 1712, "tokens_saida": 194,
        "veredito": "coerente",
    }


def test_laco_que_parou_num_limite_tambem_conclui_e_sem_veredito(log):
    parado = resultado(motivo="recusa_do_provedor", resposta=None)
    conclusao_no_log(GravadorDoAgente("triagem", log), "inc-0001", parado)
    evento = next(e for e in ler(log) if e.tipo == "agente_concluido")
    assert (evento.dados.motivo, evento.dados.veredito) == ("recusa_do_provedor", None)


def test_so_a_triagem_tem_veredito(log):
    conclusao_no_log(GravadorDoAgente("decisao", log), "inc-0001", resultado(resposta="Rótulo da triagem: duvidoso"))
    evento = next(e for e in ler(log) if e.tipo == "agente_concluido")
    assert (evento.dados.agente, evento.dados.veredito) == ("decisao", None)


def test_conclusao_sem_usage_completo_nao_grava(log):
    sem_uso = resultado(chamadas=(chamada(), chamada(tokens_saida=None)))
    with pytest.raises(ValueError, match="usage completo"):
        conclusao_no_log(GravadorDoAgente("triagem", log), "inc-0001", sem_uso)
    assert [e for e in ler(log) if e.tipo == "agente_concluido"] == []


@pytest.mark.parametrize(
    "resposta,veredito",
    [
        ("Incidente: inc-0001\nRótulo da triagem: coerente\nPor quê: confiança alta.", "coerente"),
        ("**Rótulo da triagem:** Duvidoso", "duvidoso"),
        ("**Rótulo da triagem**: ruído (poucas janelas)", "ruido"),
        ("rotulo da triagem: ruido", "ruido"),
        # O modelo que só copiou o molde da skill não deu veredito.
        ("Rótulo da triagem: coerente | duvidoso | ruído", None),
        ("O incidente parece coerente.", None),
        ("", None),
        (None, None),
    ],
)
def test_veredito_lido_da_linha_do_rotulo(resposta, veredito):
    assert veredito_da_triagem(resposta) == veredito
