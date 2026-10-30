"""Testes do cliente MCP dos agentes: o stub sobe em outro processo e é falado por stdio, sem rede."""

import asyncio
import concurrent.futures
import json
import threading
from types import SimpleNamespace

import anyio
import pytest
from mcp import MCPError
from mcp.types import CONNECTION_CLOSED

from codigo.agente import cliente_mcp
from codigo.agente.cliente_mcp import ClienteMCP, ErroDoServidor
from codigo.agente.laco import RESPOSTA_FINAL, rodar
from codigo.agente.test_laco import ProvedorFalso, pedido, resposta
from codigo.mcp.eventos import ler
from codigo.mcp.tipos import tools_do_agente


@pytest.fixture(scope="module")
def triagem(tmp_path_factory):
    """Um servidor da triagem para os testes que só leem, aberto uma vez só."""
    log = tmp_path_factory.mktemp("cliente") / "eventos.jsonl"
    with ClienteMCP("triagem", log) as cliente:
        yield cliente


def test_cliente_so_enxerga_as_tools_da_linha_do_agente(triagem):
    nomes = [tool["function"]["name"] for tool in triagem.tools]

    assert tuple(nomes) == tools_do_agente("triagem")
    assert "executar_acao" not in nomes


def test_tools_saem_no_formato_da_api_com_o_esquema_do_servidor(triagem):
    tool = next(t for t in triagem.tools if t["function"]["name"] == "obter_janelas")

    assert tool["type"] == "function"
    assert tool["function"]["description"]
    assert tool["function"]["parameters"]["required"] == ["id", "limite"]


def test_chamar_devolve_o_resultado_em_json_compacto(triagem):
    resultado = triagem.chamar("obter_incidente", {"id": "inc-0001"})

    assert not resultado.erro
    dados = json.loads(resultado.texto)
    assert (dados["id"], dados["categoria"]) == ("inc-0001", "DDoS")
    assert resultado.texto == json.dumps(dados, ensure_ascii=False, separators=(",", ":"))


def test_recusa_da_tool_volta_como_erro_e_o_servidor_continua_no_ar(triagem):
    recusada = triagem.chamar("obter_incidente", {"id": "inc-0099"})
    depois = triagem.chamar("obter_incidente", {"id": "inc-0002"})

    assert recusada.erro
    assert "inc-0099" in recusada.texto
    assert not depois.erro
    assert json.loads(depois.texto)["id"] == "inc-0002"


def test_argumento_fora_do_esquema_volta_como_erro_da_tool(triagem):
    resultado = triagem.chamar("obter_janelas", {"id": "inc-0001"})

    assert resultado.erro
    assert resultado.texto


def test_o_cliente_serve_de_executar_no_laco_contra_o_servidor_de_verdade(triagem):
    provedor = ProvedorFalso(
        resposta(pedidos=[pedido("obter_incidente", '{"id": "inc-0001"}')]),
        resposta("Veredito: coerente."),
    )

    resultado = rodar(provedor, "m-1", [{"role": "user", "content": "Abriu o inc-0001."}], triagem.tools, triagem)

    assert resultado.motivo == RESPOSTA_FINAL
    assert resultado.resposta == "Veredito: coerente."
    lido_pelo_modelo = provedor.rodadas[1]["mensagens"][-1]
    assert lido_pelo_modelo["role"] == "tool"
    assert json.loads(lido_pelo_modelo["content"])["id"] == "inc-0001"


def test_a_fatia_de_20_janelas_que_a_skill_pede_chega_inteira_ao_modelo(triagem):
    # Regressão: com o limite antigo de 6 mil caracteres, esta chamada fazia a triagem parar.
    provedor = ProvedorFalso(
        resposta(pedidos=[pedido("obter_janelas", '{"id": "inc-0001", "limite": 20}')]),
        resposta("Veredito: coerente."),
    )

    resultado = rodar(provedor, "m-1", [{"role": "user", "content": "Abriu o inc-0001."}], triagem.tools, triagem)

    assert resultado.motivo == RESPOSTA_FINAL
    fatia = json.loads(provedor.rodadas[1]["mensagens"][-1]["content"])
    assert len(fatia["janelas"]) == 20


def test_argumento_com_surrogate_solto_vira_erro_e_a_sessao_continua(triagem):
    # Regressão: o SDK falhava ao serializar "\ud800" e derrubava a sessão com o stub de verdade.
    recusada = triagem.chamar("obter_incidente", {"id": "\ud800"})
    depois = triagem.chamar("obter_incidente", {"id": "inc-0001"})

    assert recusada.erro
    assert "UTF-8" in recusada.texto
    assert json.loads(depois.texto)["id"] == "inc-0001"


def test_a_chamada_fica_no_log_com_o_nome_do_agente(tmp_path):
    log = tmp_path / "eventos.jsonl"
    with ClienteMCP("decisao", log) as cliente:
        cliente.chamar("obter_resumo", {"id": "inc-0001"})

    chamadas = [evento for evento in ler(log) if evento.tipo == "tool_chamada"]
    assert [(c.dados.agente, c.dados.nome) for c in chamadas] == [("decisao", "obter_resumo")]


def test_depois_de_fechar_o_cliente_nao_chama_mais(tmp_path):
    with ClienteMCP("execucao", tmp_path / "eventos.jsonl") as cliente:
        assert tuple(t["function"]["name"] for t in cliente.tools) == tools_do_agente("execucao")

    with pytest.raises(ErroDoServidor):
        cliente.chamar("consultar_estado", {})
    cliente.fechar()


@pytest.mark.parametrize("agente", ["todos", "orquestrador", ""])
def test_so_os_tres_papeis_abrem_cliente(agente, tmp_path):
    with pytest.raises(ValueError, match="agente desconhecido"):
        ClienteMCP(agente, tmp_path / "eventos.jsonl")


def test_servidor_que_nao_abre_vira_erro_do_servidor(tmp_path):
    with pytest.raises(ErroDoServidor, match="não abriu"), ClienteMCP(
        "triagem", tmp_path / "eventos.jsonl", cenarios=tmp_path / "nao_existe.jsonl", prazo_da_abertura_s=30
    ):
        pass


class ServidorControlado:
    """Conexão falsa bloqueável: permite testar cancelamento sem esperar os 60 s padrão."""

    def __init__(self, *, bloquear_abertura=False, bloquear_lista=False, bloquear_chamada=False, falhas=(), erro_ao_sair=None):
        self.bloquear_abertura = bloquear_abertura
        self.bloquear_lista = bloquear_lista
        self.bloquear_chamada = bloquear_chamada
        # Exceções levantadas pelas primeiras chamadas, uma por chamada.
        self.falhas = list(falhas)
        # Como o SDK, que ao sair por cancelamento levanta o erro que derrubou o transporte.
        self.erro_ao_sair = erro_ao_sair
        self.abertura_iniciada = threading.Event()
        self.chamada_iniciada = threading.Event()
        self.encerrado = threading.Event()

    async def __aenter__(self):
        self.abertura_iniciada.set()
        if self.bloquear_abertura:
            try:
                await asyncio.Event().wait()
            finally:
                self.encerrado.set()
        return self

    async def __aexit__(self, tipo, *_):
        self.encerrado.set()
        if self.erro_ao_sair is not None and tipo is asyncio.CancelledError:
            raise self.erro_ao_sair

    async def list_tools(self):
        if self.bloquear_lista:
            await asyncio.Event().wait()
        tool = SimpleNamespace(name="obter_incidente", description="x", input_schema={})
        return SimpleNamespace(tools=[tool])

    async def call_tool(self, nome, argumentos):
        self.chamada_iniciada.set()
        if self.falhas:
            raise self.falhas.pop(0)
        if self.bloquear_chamada:
            await asyncio.Event().wait()
        return SimpleNamespace(content=[], structured_content={"id": argumentos["id"]}, is_error=False)


@pytest.mark.parametrize("bloqueio", ["bloquear_abertura", "bloquear_lista"])
def test_timeout_na_abertura_nao_deixa_thread_ou_sessao_aberta(monkeypatch, tmp_path, bloqueio):
    servidor = ServidorControlado(**{bloqueio: True})
    monkeypatch.setattr(cliente_mcp, "Client", lambda *_: servidor)
    cliente = ClienteMCP("triagem", tmp_path / "log.jsonl", prazo_da_abertura_s=0.5, prazo_do_fechamento_s=5)

    with pytest.raises(ErroDoServidor, match="não abriu"):
        cliente.__enter__()

    assert servidor.abertura_iniciada.is_set()
    assert servidor.encerrado.is_set()
    assert not cliente._fio.is_alive()
    assert not cliente._pendentes


def test_timeout_de_tool_fecha_sessao_e_nao_repete_acao(monkeypatch, tmp_path):
    servidor = ServidorControlado(bloquear_chamada=True)
    monkeypatch.setattr(cliente_mcp, "Client", lambda *_: servidor)
    with ClienteMCP("triagem", tmp_path / "log.jsonl", prazo_s=0.05) as cliente:
        with pytest.raises(ErroDoServidor, match="prazo"):
            cliente.chamar("obter_incidente", {"id": "inc-0001"})
        with pytest.raises(ErroDoServidor, match="não está no ar"):
            cliente.chamar("obter_incidente", {"id": "inc-0001"})
    assert servidor.encerrado.is_set()
    assert not cliente._fio.is_alive()
    assert not cliente._pendentes


def test_fechar_interrompe_uma_chamada_em_andamento(monkeypatch, tmp_path):
    servidor = ServidorControlado(bloquear_chamada=True)
    monkeypatch.setattr(cliente_mcp, "Client", lambda *_: servidor)
    with ClienteMCP("triagem", tmp_path / "log.jsonl") as cliente, concurrent.futures.ThreadPoolExecutor() as pool:
        chamada = pool.submit(cliente.chamar, "obter_incidente", {"id": "inc-0001"})
        assert servidor.chamada_iniciada.wait(5)
        cliente.fechar()
        with pytest.raises(ErroDoServidor):
            chamada.result(timeout=5)
    assert servidor.encerrado.is_set()
    assert not cliente._fio.is_alive()


def test_falha_de_uma_tool_traz_a_causa_e_a_sessao_continua(monkeypatch, tmp_path):
    servidor = ServidorControlado(falhas=[RuntimeError("resposta inválida do servidor")])
    monkeypatch.setattr(cliente_mcp, "Client", lambda *_: servidor)
    with ClienteMCP("triagem", tmp_path / "log.jsonl") as cliente:
        with pytest.raises(ErroDoServidor, match="falha na tool obter_incidente: RuntimeError: resposta inválida"):
            cliente.chamar("obter_incidente", {"id": "inc-0001"})
        assert json.loads(cliente.chamar("obter_incidente", {"id": "inc-0002"}).texto)["id"] == "inc-0002"


@pytest.mark.parametrize(
    "queda",
    # A segunda é o que o SDK levanta quando o processo do servidor morre no meio da chamada.
    [anyio.BrokenResourceError(), MCPError(code=CONNECTION_CLOSED, message="Connection closed")],
    ids=["canal", "processo"],
)
def test_conexao_que_cai_encerra_a_sessao(monkeypatch, tmp_path, queda):
    servidor = ServidorControlado(falhas=[queda])
    monkeypatch.setattr(cliente_mcp, "Client", lambda *_: servidor)
    with ClienteMCP("triagem", tmp_path / "log.jsonl") as cliente:
        with pytest.raises(ErroDoServidor, match="conexão com o servidor MCP caiu"):
            cliente.chamar("obter_incidente", {"id": "inc-0001"})
        cliente._fio.join(5)
        with pytest.raises(ErroDoServidor, match="não está no ar"):
            cliente.chamar("obter_incidente", {"id": "inc-0001"})
    assert not cliente._fio.is_alive()


def test_chamada_pendente_recebe_a_causa_quando_o_transporte_cai(monkeypatch, tmp_path):
    servidor = ServidorControlado(
        falhas=[asyncio.CancelledError()],
        erro_ao_sair=ExceptionGroup("erros", [UnicodeEncodeError("utf-8", "\ud800", 0, 1, "surrogates not allowed")]),
    )
    monkeypatch.setattr(cliente_mcp, "Client", lambda *_: servidor)
    with ClienteMCP("triagem", tmp_path / "log.jsonl") as cliente, pytest.raises(
        ErroDoServidor, match="encerrou: UnicodeEncodeError"
    ):
        cliente.chamar("obter_incidente", {"id": "inc-0001"})


def test_mesma_instancia_nao_abre_duas_sessoes(monkeypatch, tmp_path):
    servidor = ServidorControlado()
    monkeypatch.setattr(cliente_mcp, "Client", lambda *_: servidor)
    with ClienteMCP("triagem", tmp_path / "log.jsonl") as cliente, pytest.raises(ErroDoServidor, match="uso único"):
        cliente.__enter__()
    with pytest.raises(ErroDoServidor, match="uso único"):
        cliente.__enter__()


def test_chamadas_concorrentes_recebem_sua_propria_resposta(monkeypatch, tmp_path):
    servidor = ServidorControlado()
    monkeypatch.setattr(cliente_mcp, "Client", lambda *_: servidor)
    with ClienteMCP("triagem", tmp_path / "log.jsonl") as cliente, concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        chamadas = [pool.submit(cliente.chamar, "obter_incidente", {"id": str(i)}) for i in range(10)]
        assert [json.loads(f.result(timeout=5).texto)["id"] for f in chamadas] == [str(i) for i in range(10)]


def test_tool_de_outro_papel_nao_e_enviada_ao_servidor(triagem):
    resultado = triagem.chamar("executar_acao", {"id_proposta": "prop-0001"})
    assert resultado.erro
    assert "não disponibilizada" in resultado.texto


def test_caminhos_relativos_sao_resolvidos_no_diretorio_de_quem_chamou(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    cliente = ClienteMCP("triagem", "log.jsonl", cenarios="cenarios.json")
    assert str(tmp_path / "log.jsonl") in cliente._parametros.args
    assert str(tmp_path / "cenarios.json") in cliente._parametros.args


@pytest.mark.parametrize("campo", ["prazo_s", "prazo_da_abertura_s", "prazo_do_fechamento_s"])
@pytest.mark.parametrize("valor", [0, -1, True, float("nan"), float("inf")])
def test_prazos_invalidos_nao_iniciam_processo(tmp_path, campo, valor):
    with pytest.raises(ValueError, match=campo):
        ClienteMCP("triagem", tmp_path / "log.jsonl", **{campo: valor})
