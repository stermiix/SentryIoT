"""Testes da rodada com tools do provedor, sem rede: a função que abre a conexão é trocada."""

import dataclasses
import json

import pytest

from codigo.api.provedor import ErroDoProvedor, PedidoDeTool, Provedor
from codigo.api.test_provedor import CONFIG, abrir_com

TOOLS = [{"type": "function", "function": {"name": "obter_incidente", "description": "x", "parameters": {}}}]
MENSAGENS = [{"role": "system", "content": "Triagem."}, {"role": "user", "content": "Abriu o inc-0001."}]


def chamada(identificador, nome, argumentos):
    return {"id": identificador, "type": "function", "function": {"name": nome, "arguments": argumentos}}


def test_conversar_manda_mensagens_e_tools_e_le_o_pedido_de_tool():
    capturado = {}
    corpo = {
        "model": "m-1",
        "choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [chamada("c1", "obter_incidente", '{"id": "inc-0001"}')]}}],
        "usage": {"prompt_tokens": 40, "completion_tokens": 8},
    }
    provedor = Provedor(CONFIG, abrir=abrir_com(corpo, capturado))

    resposta = provedor.conversar("m-1", MENSAGENS, TOOLS)

    assert capturado["url"] == "https://gateway.exemplo/v1/chat/completions"
    assert capturado["corpo"] == {"model": "m-1", "stream": False, "messages": MENSAGENS, "tools": TOOLS}
    assert resposta.pedidos == (PedidoDeTool(id="c1", nome="obter_incidente", argumentos='{"id": "inc-0001"}'),)
    assert resposta.conteudo == ""
    assert (resposta.tokens_entrada, resposta.tokens_saida) == (40, 8)
    assert resposta.mensagem == {
        "role": "assistant",
        "content": "",
        "tool_calls": [chamada("c1", "obter_incidente", '{"id": "inc-0001"}')],
    }


def test_conversar_sem_tools_nao_manda_o_campo_e_a_resposta_final_nao_tem_pedidos():
    capturado = {}
    corpo = {"choices": [{"message": {"content": "Veredito: coerente."}}]}
    provedor = Provedor(CONFIG, abrir=abrir_com(corpo, capturado))

    resposta = provedor.conversar("m-1", MENSAGENS)

    assert "tools" not in capturado["corpo"]
    assert resposta.pedidos == ()
    assert resposta.conteudo == "Veredito: coerente."
    assert resposta.mensagem == {"role": "assistant", "content": "Veredito: coerente."}


def test_conversar_manda_os_parametros_de_geracao_da_configuracao():
    capturado = {}
    config = dataclasses.replace(CONFIG, temperatura=0.0, semente=7)
    provedor = Provedor(config, abrir=abrir_com({"choices": [{"message": {"content": "ok"}}]}, capturado))

    provedor.conversar("m-1", MENSAGENS)

    assert capturado["corpo"]["temperature"] == 0.0
    assert capturado["corpo"]["seed"] == 7


def test_o_raciocinio_que_o_servidor_devolve_nao_entra_no_historico():
    corpo = {"choices": [{"message": {"content": "ok", "reasoning": "pensando...", "reasoning_content": "mais"}}]}
    provedor = Provedor(CONFIG, abrir=abrir_com(corpo, {}))

    assert provedor.conversar("m-1", MENSAGENS).mensagem == {"role": "assistant", "content": "ok"}


def test_argumentos_que_chegam_como_objeto_viram_texto_json():
    corpo = {"choices": [{"message": {"tool_calls": [chamada("c1", "obter_incidente", {"id": "inc-0001"})]}}]}
    provedor = Provedor(CONFIG, abrir=abrir_com(corpo, {}))

    pedido = provedor.conversar("m-1", MENSAGENS, TOOLS).pedidos[0]

    assert json.loads(pedido.argumentos) == {"id": "inc-0001"}


def test_tool_call_sem_identificador_e_recusada_sem_inventar_id():
    corpo = {"choices": [{"message": {"tool_calls": [{"type": "function", "function": {"name": "consultar_estado", "arguments": "{}"}}]}}]}
    provedor = Provedor(CONFIG, abrir=abrir_com(corpo, {}))

    with pytest.raises(ErroDoProvedor, match="id único"):
        provedor.conversar("m-1", MENSAGENS, TOOLS)


def test_varias_chamadas_na_mesma_resposta_mantem_a_ordem():
    chamadas = [chamada("a", "obter_incidente", "{}"), chamada("b", "obter_resumo", "{}")]
    provedor = Provedor(CONFIG, abrir=abrir_com({"choices": [{"message": {"tool_calls": chamadas}}]}, {}))

    assert [p.id for p in provedor.conversar("m-1", MENSAGENS, TOOLS).pedidos] == ["a", "b"]


@pytest.mark.parametrize(
    "mensagem",
    [
        {"tool_calls": "obter_incidente"},
        {"tool_calls": [{"function": {"arguments": "{}"}}]},
        {"tool_calls": ["obter_incidente"]},
        {"tool_calls": {}},
        {"tool_calls": False},
        {"tool_calls": [{"id": "c1", "type": "retrieval", "function": {"name": "obter_incidente", "arguments": "{}"}}]},
        {"tool_calls": [chamada("c1", "obter_incidente", "{}"), chamada("c1", "obter_incidente", "{}")]},
    ],
)
def test_tool_call_mal_formada_vira_erro_do_provedor(mensagem):
    provedor = Provedor(CONFIG, abrir=abrir_com({"choices": [{"message": mensagem}]}, {}))

    with pytest.raises(ErroDoProvedor):
        provedor.conversar("m-1", MENSAGENS, TOOLS)


def test_resposta_sem_message_vira_erro_do_provedor():
    provedor = Provedor(CONFIG, abrir=abrir_com({"choices": []}, {}))

    with pytest.raises(ErroDoProvedor, match="choices"):
        provedor.conversar("m-1", MENSAGENS)


def test_message_que_nao_e_objeto_vira_erro_do_provedor():
    provedor = Provedor(CONFIG, abrir=abrir_com({"choices": [{"message": "oi"}]}, {}))

    with pytest.raises(ErroDoProvedor, match="não é um objeto"):
        provedor.conversar("m-1", MENSAGENS)


def test_finish_reason_e_preservado_para_o_laco_reconhecer_truncamento():
    corpo = {"choices": [{"message": {"content": "Parcial"}, "finish_reason": "length"}]}
    provedor = Provedor(CONFIG, abrir=abrir_com(corpo, {}))
    assert provedor.conversar("m-1", MENSAGENS).motivo_termino == "length"


def test_tool_call_sem_o_campo_type_e_aceita():
    corpo = {"choices": [{"message": {"tool_calls": [{"id": "c1", "function": {"name": "obter_incidente", "arguments": "{}"}}]}}]}
    provedor = Provedor(CONFIG, abrir=abrir_com(corpo, {}))

    resposta = provedor.conversar("m-1", MENSAGENS, TOOLS)

    assert resposta.pedidos == (PedidoDeTool(id="c1", nome="obter_incidente", argumentos="{}"),)
    assert resposta.mensagem["tool_calls"][0]["type"] == "function"


@pytest.mark.parametrize("argumentos", [None, 7, ["x"]])
def test_argumentos_ausentes_ou_de_outro_tipo_viram_texto_vazio_para_o_laco_recusar(argumentos):
    corpo = {"choices": [{"message": {"tool_calls": [chamada("c1", "obter_incidente", argumentos)]}}]}
    provedor = Provedor(CONFIG, abrir=abrir_com(corpo, {}))

    assert provedor.conversar("m-1", MENSAGENS, TOOLS).pedidos[0].argumentos == ""


@pytest.mark.parametrize("uso", [[], "invalido", 7, True])
def test_usage_fora_do_formato_nao_quebra_o_chat_nem_inventa_tokens(uso):
    corpo = {"choices": [{"message": {"content": "Ok."}}], "usage": uso}
    provedor = Provedor(CONFIG, abrir=abrir_com(corpo, {}))
    assert provedor.conversar("m-1", MENSAGENS).tokens_entrada is None
    assert provedor.chat("m-1", "", []).tokens_saida is None


@pytest.mark.parametrize("valor", [-1, 1.5, float("nan"), float("inf"), True, "12"])
def test_contagem_de_tokens_invalida_nao_e_medida_valida(valor):
    corpo = {"choices": [{"message": {"content": "Ok."}}], "usage": {"prompt_tokens": valor, "completion_tokens": 0}}
    provedor = Provedor(CONFIG, abrir=abrir_com(corpo, {}))
    resultado = provedor.conversar("m-1", MENSAGENS)
    assert resultado.tokens_entrada is None
    assert resultado.tokens_saida == 0
