"""Testes dos pedidos aos modelos, sem provedor."""

import re

import pytest

from codigo.agente.pedidos import (
    PASTA_DE_SKILLS,
    SKILL_DA_TRIAGEM,
    pedido_da_triagem,
    prompt_da_skill,
    tools_da_linha,
)

SKILLS_DO_REPOSITORIO = sorted(pasta.name for pasta in PASTA_DE_SKILLS.iterdir() if (pasta / "SKILL.md").is_file())


@pytest.mark.parametrize("nome", SKILLS_DO_REPOSITORIO)
def test_o_cabecalho_de_cada_skill_tem_o_nome_da_pasta_e_uma_descricao_em_yaml_valido(nome):
    texto = (PASTA_DE_SKILLS / nome / "SKILL.md").read_text(encoding="utf-8")

    cabecalho = re.match(r"---\n(.*?)\n---\n", texto, re.DOTALL)
    assert cabecalho, f"{nome}: sem cabeçalho YAML"
    campos = dict(linha.split(": ", 1) for linha in cabecalho.group(1).splitlines())
    assert campos["name"] == nome
    descricao = campos["description"]
    # Texto simples em YAML não pode ter ": " nem " #" no meio; com isso, é preciso pôr a descrição entre aspas.
    if not descricao.startswith(('"', "'")):
        assert ": " not in descricao and " #" not in descricao


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
