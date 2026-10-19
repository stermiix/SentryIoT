"""Testes dos pedidos aos modelos, sem provedor."""

from codigo.agente.pedidos import (
    SKILL_DA_TRIAGEM,
    pedido_da_triagem,
    prompt_da_skill,
    tools_da_linha,
)


def test_tools_da_triagem_sao_so_as_da_linha_dela():
    nomes = [tool["function"]["name"] for tool in tools_da_linha("triagem")]

    assert nomes == ["obter_incidente", "obter_janelas"]
    assert tools_da_linha("triagem")[0]["function"]["parameters"]["properties"]["id"]["type"] == "string"


def test_pedido_da_triagem_traz_a_skill_a_abertura_as_tools_e_os_parametros():
    pedido = pedido_da_triagem("inc-0007", "modelo-local", {"temperature": 0, "chat_template_kwargs": {"enable_thinking": False}})

    sistema, usuario = pedido["messages"]
    assert pedido["model"] == "modelo-local"
    assert sistema["role"] == "system" and sistema["content"].startswith(prompt_da_skill(SKILL_DA_TRIAGEM))
    assert "inc-0007" in usuario["content"]
    assert [tool["function"]["name"] for tool in pedido["tools"]] == ["obter_incidente", "obter_janelas"]
    assert pedido["temperature"] == 0
    assert pedido["chat_template_kwargs"] == {"enable_thinking": False}
    assert pedido["stream"] is False
