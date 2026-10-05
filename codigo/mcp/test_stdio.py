"""Um cliente MCP de verdade conversa com o stub por stdio.

Cada teste sobe o stub em outro processo, com `python -m codigo.mcp.stub`, e fala com ele pelo
cliente do SDK oficial, como um agente faria. Não usa rede.
"""
import asyncio
import sys
from pathlib import Path

from mcp import Client, StdioServerParameters

from codigo.mcp import aprovar
from codigo.mcp.eventos import ler
from codigo.mcp.test_acoes import ACAO_NOVA
from codigo.mcp.tipos import TOOLS, Execucao, Incidente, Proposta, tools_do_agente

RAIZ = Path(__file__).resolve().parents[2]


def conversar(log, roteiro, *opcoes):
    """Sobe o stub, roda `roteiro(cliente)` e devolve o que ele devolver."""
    parametros = StdioServerParameters(
        command=sys.executable, args=["-m", "codigo.mcp.stub", "--log", str(log), *opcoes], cwd=RAIZ
    )

    async def sessao():
        async with Client(parametros) as cliente:
            return await roteiro(cliente)

    return asyncio.run(asyncio.wait_for(sessao(), timeout=60))


def test_cliente_lista_as_nove_tools(tmp_path):
    async def roteiro(cliente):
        return (await cliente.list_tools()).tools

    tools = conversar(tmp_path / "eventos.jsonl", roteiro)
    assert [tool.name for tool in tools] == [tool.nome for tool in TOOLS]
    assert len(tools) == 9
    assert [tool.description for tool in tools] == [tool.descricao for tool in TOOLS]
    por_nome = {tool.name: tool for tool in tools}
    assert list(por_nome["propor_acao"].input_schema["properties"]) == [
        "id", "acao", "alvo", "parametros", "justificativa",
    ]
    assert por_nome["obter_janelas"].input_schema["required"] == ["id", "limite"]
    assert all(tool.output_schema["type"] == "object" for tool in tools)


def test_cliente_de_um_agente_so_lista_as_tools_da_linha_dele(tmp_path):
    async def roteiro(cliente):
        return tuple(tool.name for tool in (await cliente.list_tools()).tools)

    assert conversar(tmp_path / "eventos.jsonl", roteiro, "--agente", "triagem") == tools_do_agente("triagem")
    assert conversar(tmp_path / "eventos.jsonl", roteiro, "--agente", "execucao") == tools_do_agente("execucao")


def test_cliente_chama_tool_e_recebe_dados_validos_pelo_contrato(tmp_path):
    log = tmp_path / "eventos.jsonl"

    async def roteiro(cliente):
        return await cliente.call_tool("obter_incidente", {"id": "inc-0001"})

    resposta = conversar(log, roteiro)
    assert not resposta.is_error
    incidente = Incidente.model_validate(resposta.structured_content)
    assert (incidente.id, incidente.categoria, incidente.janelas) == ("inc-0001", "DDoS", 10_734)
    assert [evento.tipo for evento in ler(log)] == ["janelas_classificadas", "incidente_aberto"] * 4 + ["tool_chamada"]


def test_recusa_chega_ao_cliente_como_erro_de_tool_e_o_servidor_continua_no_ar(tmp_path):
    log = tmp_path / "eventos.jsonl"

    async def roteiro(cliente):
        recusada = await cliente.call_tool("obter_incidente", {"id": "inc-0099"})
        fora_do_esquema = await cliente.call_tool("obter_janelas", {"id": "inc-0001"})
        depois = await cliente.call_tool("obter_incidente", {"id": "inc-0002"})
        return recusada, fora_do_esquema, depois

    recusada, fora_do_esquema, depois = conversar(log, roteiro)
    assert recusada.is_error
    assert "Não existe incidente com o identificador 'inc-0099'" in recusada.content[0].text
    # Argumento fora do esquema é barrado pelo SDK antes de chegar ao stub: é erro, sem evento.
    assert fora_do_esquema.is_error
    assert not depois.is_error
    assert depois.structured_content["id"] == "inc-0002"
    assert [evento.tipo for evento in ler(log)][8:] == ["recusa", "tool_chamada"]


def test_incidente_inteiro_por_stdio_com_aprovacao_pelo_comando_de_terminal(tmp_path, capsys):
    log = tmp_path / "eventos.jsonl"

    async def roteiro(cliente):
        async def chamar(nome, **argumentos):
            return await cliente.call_tool(nome, argumentos)

        proposta = await chamar(
            "propor_acao", id="inc-0001", acao="ativar_syn_cookies", alvo="192.168.137.20",
            parametros=ACAO_NOVA, justificativa="Flood de SYN vindo de muitas origens.",
        )
        antes_de_aprovar = await chamar("executar_acao", id_proposta="prop-0001")
        # A pessoa aprova por fora, com o comando de terminal, enquanto o servidor segue no ar.
        aprovado = aprovar.main(["prop-0001", "--log", str(log)])
        execucao = await chamar("executar_acao", id_proposta="prop-0001")
        efeito = await chamar("verificar_efeito", id_execucao="exec-0001")
        ativo = await chamar("consultar_estado")
        desfeita = await chamar("desfazer_acao", id_execucao="exec-0001")
        restaurado = await chamar("consultar_estado")
        return proposta, antes_de_aprovar, aprovado, execucao, efeito, ativo, desfeita, restaurado

    proposta, antes_de_aprovar, aprovado, execucao, efeito, ativo, desfeita, restaurado = conversar(log, roteiro)
    capsys.readouterr()
    assert Proposta.model_validate(proposta.structured_content).estado == "aguardando_aprovacao"
    assert antes_de_aprovar.is_error and "aprovação humana" in antes_de_aprovar.content[0].text
    assert aprovado == 0
    assert Execucao.model_validate(execucao.structured_content).estado == "aplicada"
    assert efeito.structured_content["resultado"] == "persiste"
    assert [medida["id"] for medida in ativo.structured_content["outras_medidas"]] == ["exec-0001"]
    assert desfeita.structured_content["estado"] == "desfeita"
    assert restaurado.structured_content["outras_medidas"] == []
    assert [evento.tipo for evento in ler(log)][8:] == [
        "tool_chamada", "acao_proposta",
        "recusa",
        "acao_aprovada",
        "tool_chamada", "acao_executada",
        "tool_chamada", "efeito_verificado", "incidente_atualizado",
        "tool_chamada",
        "tool_chamada", "acao_desfeita",
        "tool_chamada",
    ]
