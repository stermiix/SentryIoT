"""Testes do laço ReAct, sem rede e sem servidor: o provedor e a execução das tools são falsos."""

import dataclasses

import pytest

from codigo.agente.laco import (
    CHAMADA_REPETIDA,
    LIMITE_DE_TOOLS,
    LIMITE_DE_VOLTAS,
    LIMITE_DO_HISTORICO,
    RESPOSTA_FINAL,
    RESPOSTA_INCOMPLETA,
    RESPOSTA_VAZIA,
    ResultadoDeTool,
    rodar,
)
from codigo.api.provedor import PedidoDeTool, RespostaDaConversa

ABERTURA = [
    {"role": "system", "content": "Você é o agente de triagem."},
    {"role": "user", "content": "Abriu o incidente inc-0001."},
]
TOOLS = [
    {"type": "function", "function": {"name": nome, "description": "x", "parameters": {}}}
    for nome in ("obter_incidente", "obter_resumo", "obter_janelas", "consultar_estado")
]


def resposta(texto="", pedidos=(), entrada=10, saida=5, modelo="m-1"):
    mensagem = {"role": "assistant", "content": texto}
    if pedidos:
        mensagem["tool_calls"] = [
            {"id": p.id, "type": "function", "function": {"name": p.nome, "arguments": p.argumentos}} for p in pedidos
        ]
    return RespostaDaConversa(mensagem, texto, tuple(pedidos), modelo, entrada, saida)


def pedido(nome="obter_incidente", argumentos='{"id": "inc-0001"}', identificador="c1"):
    return PedidoDeTool(id=identificador, nome=nome, argumentos=argumentos)


class ProvedorFalso:
    """Devolve as respostas na ordem e guarda o que recebeu em cada rodada."""

    def __init__(self, *respostas):
        self.respostas = list(respostas)
        self.rodadas = []

    def conversar(self, modelo, mensagens, tools=None):
        self.rodadas.append({"modelo": modelo, "mensagens": list(mensagens), "tools": tools})
        return self.respostas.pop(0)


class Executor:
    def __init__(self, resultado=None):
        self.resultado = resultado or ResultadoDeTool('{"id": "inc-0001"}')
        self.chamadas = []

    def __call__(self, nome, argumentos):
        self.chamadas.append((nome, argumentos))
        return self.resultado


def test_resposta_sem_pedir_tool_e_a_final():
    provedor = ProvedorFalso(resposta("Veredito: coerente.", entrada=120, saida=30))
    executor = Executor()

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert resultado.motivo == RESPOSTA_FINAL
    assert resultado.terminou_bem
    assert resultado.resposta == "Veredito: coerente."
    assert executor.chamadas == []
    assert len(resultado.chamadas_ao_modelo) == 1
    assert (resultado.tokens_entrada, resultado.tokens_saida) == (120, 30)
    assert provedor.rodadas[0]["modelo"] == "m-1"
    assert provedor.rodadas[0]["tools"] == TOOLS


def test_tool_pedida_e_executada_e_o_resultado_volta_ao_modelo():
    provedor = ProvedorFalso(resposta(pedidos=[pedido()]), resposta("Pronto."))
    executor = Executor(ResultadoDeTool("incidente lido"))

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert executor.chamadas == [("obter_incidente", {"id": "inc-0001"})]
    assert resultado.resposta == "Pronto."
    segunda_rodada = provedor.rodadas[1]["mensagens"]
    assert segunda_rodada[:2] == ABERTURA
    assert segunda_rodada[2]["role"] == "assistant"
    assert segunda_rodada[2]["tool_calls"][0]["id"] == "c1"
    assert segunda_rodada[3] == {"role": "tool", "tool_call_id": "c1", "content": "incidente lido"}
    assert resultado.mensagens[-1]["content"] == "Pronto."
    assert resultado.chamadas_ao_modelo[0].tools_pedidas == ("obter_incidente",)
    assert resultado.chamadas_ao_modelo[1].tools_pedidas == ()


def test_varias_tools_na_mesma_resposta_sao_executadas_em_ordem_cada_uma_com_a_sua_mensagem():
    pedidos = [pedido("obter_incidente", identificador="a"), pedido("obter_resumo", '{"id": "inc-0001"}', "b")]
    provedor = ProvedorFalso(resposta(pedidos=pedidos), resposta("Pronto."))
    executor = Executor()

    rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert [nome for nome, _ in executor.chamadas] == ["obter_incidente", "obter_resumo"]
    mensagens = provedor.rodadas[1]["mensagens"]
    assert [(m["role"], m.get("tool_call_id")) for m in mensagens[3:]] == [("tool", "a"), ("tool", "b")]


def test_argumento_que_nao_e_json_nao_chega_a_tool_e_o_modelo_recebe_o_erro():
    provedor = ProvedorFalso(resposta(pedidos=[pedido(argumentos="{id: inc-0001")]), resposta("Corrigi."))
    executor = Executor()

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert executor.chamadas == []
    erro = provedor.rodadas[1]["mensagens"][3]["content"]
    assert erro.startswith("Erro da tool:")
    assert "objeto JSON" in erro
    assert resultado.terminou_bem


def test_argumento_que_nao_e_objeto_tambem_e_erro():
    provedor = ProvedorFalso(resposta(pedidos=[pedido(argumentos='["inc-0001"]')]), resposta("Ok."))
    executor = Executor()

    rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert executor.chamadas == []


def test_argumentos_vazios_nao_disparam_tool_sem_argumentos():
    provedor = ProvedorFalso(resposta(pedidos=[pedido("consultar_estado", argumentos="")]), resposta("Ok."))
    executor = Executor()

    rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert executor.chamadas == []


def test_objeto_vazio_explicito_pode_chamar_tool_sem_argumentos():
    provedor = ProvedorFalso(resposta(pedidos=[pedido("consultar_estado", argumentos="{}")]), resposta("Ok."))
    executor = Executor()

    rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert executor.chamadas == [("consultar_estado", {})]


def test_erro_da_tool_vai_ao_modelo_com_o_aviso():
    provedor = ProvedorFalso(resposta(pedidos=[pedido()]), resposta("Entendi."))
    executor = Executor(ResultadoDeTool("Não existe incidente com o identificador 'inc-0099'.", erro=True))

    rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    conteudo = provedor.rodadas[1]["mensagens"][3]["content"]
    assert conteudo == "Erro da tool: Não existe incidente com o identificador 'inc-0099'."


def test_resultado_grande_nao_vai_ao_modelo_e_o_laco_continua():
    provedor = ProvedorFalso(resposta(pedidos=[pedido()]), resposta("Pedi menos dados."))
    executor = Executor(ResultadoDeTool("x" * 50))

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, executor, maximo_do_resultado=10)

    assert resultado.motivo == RESPOSTA_FINAL
    aviso = provedor.rodadas[1]["mensagens"][3]["content"]
    assert "foi executada" in aviso
    assert "50 caracteres" in aviso
    assert "xxxxx" not in aviso


def test_fatia_de_20_janelas_do_tamanho_medido_passa_com_os_limites_padrao():
    # obter_janelas(id, 20) mediu até 15 mil caracteres no stub e cerca de 22,5 mil no pior caso do
    # reprodutor; a skill da triagem pede 20 janelas.
    fatia = "j" * 22_500
    provedor = ProvedorFalso(resposta(pedidos=[pedido("obter_janelas", '{"id": "inc-0001", "limite": 20}')]), resposta("Ok."))

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, Executor(ResultadoDeTool(fatia)))

    assert resultado.motivo == RESPOSTA_FINAL
    assert provedor.rodadas[1]["mensagens"][3]["content"] == fatia


def test_limite_de_voltas_para_o_laco_sem_resposta():
    argumentos = ['{"id": "inc-0001"}', '{"id": "inc-0002"}', '{"id": "inc-0003"}']
    provedor = ProvedorFalso(*[resposta(pedidos=[pedido(argumentos=a)]) for a in argumentos])

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, Executor(), maximo_de_voltas=3)

    assert resultado.motivo == LIMITE_DE_VOLTAS
    assert not resultado.terminou_bem
    assert resultado.resposta is None
    assert len(resultado.chamadas_ao_modelo) == 3


def test_tools_pedidas_na_ultima_volta_nao_sao_executadas():
    # O modelo não leria o resultado: um executar_acao aqui ficaria sem o verificar_efeito.
    voltas = 4
    provedor = ProvedorFalso(
        *[resposta(pedidos=[pedido(argumentos=f'{{"id": "inc-000{i}"}}', identificador=f"c{i}")]) for i in range(voltas)]
    )
    executor = Executor()

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, executor, maximo_de_voltas=voltas)

    assert resultado.motivo == LIMITE_DE_VOLTAS
    assert len(executor.chamadas) == voltas - 1
    assert resultado.mensagens[-1]["tool_call_id"] == f"c{voltas - 1}"
    assert "não executada" in resultado.mensagens[-1]["content"]


def test_argumento_com_surrogate_solto_nao_chega_a_tool():
    # "\ud800" é JSON válido, mas não vira UTF-8 e derrubava a sessão MCP no envio.
    provedor = ProvedorFalso(resposta(pedidos=[pedido(argumentos='{"id": "\\ud800"}')]), resposta("Corrigi."))
    executor = Executor()

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert executor.chamadas == []
    assert "UTF-8" in provedor.rodadas[1]["mensagens"][3]["content"]
    assert resultado.terminou_bem


def test_mesma_chamada_pela_terceira_vez_para_sem_executar():
    provedor = ProvedorFalso(*[resposta(pedidos=[pedido()]) for _ in range(5)])
    executor = Executor()

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert resultado.motivo == CHAMADA_REPETIDA
    assert resultado.resposta is None
    assert len(executor.chamadas) == 2
    assert len(resultado.chamadas_ao_modelo) == 3
    assert resultado.mensagens[-1]["role"] == "tool"
    assert "não executada" in resultado.mensagens[-1]["content"]


def test_a_repeticao_vale_para_o_mesmo_objeto_escrito_com_as_chaves_em_outra_ordem():
    pedidos = [pedido("obter_janelas", '{"id": "inc-0001", "limite": 5}'), pedido("obter_janelas", '{"limite": 5, "id": "inc-0001"}')]
    provedor = ProvedorFalso(*[resposta(pedidos=[p]) for p in pedidos], resposta(pedidos=[pedidos[0]]))
    executor = Executor()

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert resultado.motivo == CHAMADA_REPETIDA
    assert len(executor.chamadas) == 2


def test_argumentos_diferentes_nao_contam_como_repeticao():
    argumentos = [f'{{"id": "inc-000{numero}"}}' for numero in range(1, 5)]
    provedor = ProvedorFalso(*[resposta(pedidos=[pedido(argumentos=a)]) for a in argumentos], resposta("Fim."))

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, Executor(), maximo_de_voltas=8)

    assert resultado.terminou_bem


def test_ao_chamar_recebe_cada_chamada_com_a_duracao_medida():
    instantes = iter([10.0, 10.25, 20.0, 20.5])
    recebidas = []
    provedor = ProvedorFalso(resposta(pedidos=[pedido()], entrada=100, saida=10), resposta("Ok.", entrada=150, saida=20))

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, Executor(), ao_chamar=recebidas.append, relogio=lambda: next(instantes))

    assert [(c.volta, c.tokens_entrada, c.tokens_saida, c.duracao_ms) for c in recebidas] == [
        (1, 100, 10, 250.0),
        (2, 150, 20, 500.0),
    ]
    assert tuple(recebidas) == resultado.chamadas_ao_modelo
    assert (resultado.tokens_entrada, resultado.tokens_saida) == (250, 30)


def test_tokens_que_o_provedor_nao_informa_continuam_desconhecidos():
    provedor = ProvedorFalso(resposta("Ok.", entrada=None, saida=None))

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, Executor())

    assert (resultado.tokens_entrada, resultado.tokens_saida) == (None, None)
    assert resultado.chamadas_ao_modelo[0].tokens_entrada is None


def test_o_historico_do_chamador_nao_e_alterado():
    entrada = list(ABERTURA)
    provedor = ProvedorFalso(resposta(pedidos=[pedido()]), resposta("Ok."))

    rodar(provedor, "m-1", entrada, TOOLS, Executor())

    assert entrada == ABERTURA


def test_o_resultado_e_o_historico_completo_em_ordem():
    provedor = ProvedorFalso(resposta(pedidos=[pedido()]), resposta("Ok."))

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, Executor())

    assert [m["role"] for m in resultado.mensagens] == ["system", "user", "assistant", "tool", "assistant"]


@pytest.mark.parametrize("texto", ["", "   "])
def test_resposta_vazia_nao_e_sucesso(texto):
    resultado = rodar(ProvedorFalso(resposta(texto)), "m-1", ABERTURA, TOOLS, Executor())
    assert resultado.motivo == RESPOSTA_VAZIA
    assert not resultado.terminou_bem


@pytest.mark.parametrize("motivo", ["length", "content_filter"])
def test_resposta_interrompida_pelo_provedor_nao_dispara_tools(motivo):
    executor = Executor()
    incompleta = dataclasses.replace(resposta("Parcial", pedidos=[pedido()]), motivo_termino=motivo)

    resultado = rodar(ProvedorFalso(incompleta), "m-1", ABERTURA, TOOLS, executor)

    assert resultado.motivo == RESPOSTA_INCOMPLETA
    assert executor.chamadas == []
    assert len(resultado.chamadas_ao_modelo) == 1


def test_tool_nao_anunciada_nunca_chega_ao_executor():
    executor = Executor()
    provedor = ProvedorFalso(resposta(pedidos=[pedido("executar_acao", "{}")]), resposta("Entendi."))

    rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert executor.chamadas == []
    assert "não disponibilizada" in provedor.rodadas[1]["mensagens"][-1]["content"]


@pytest.mark.parametrize("argumentos", ['{"x":NaN}', '{"x":Infinity}', '{"x":1e999}', '{"id":1,"id":2}'])
def test_json_ambiguo_ou_nao_finito_nao_executa(argumentos):
    executor = Executor()
    provedor = ProvedorFalso(resposta(pedidos=[pedido(argumentos=argumentos)]), resposta("Ok."))

    rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert executor.chamadas == []


def test_lote_excessivo_nao_executa_nenhuma_tool():
    executor = Executor()
    provedor = ProvedorFalso(resposta(pedidos=[pedido(identificador=str(i)) for i in range(3)]))

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, executor, maximo_de_tools_por_volta=2)

    assert resultado.motivo == LIMITE_DE_TOOLS
    assert executor.chamadas == []


def test_historico_inicial_grande_nao_chama_o_modelo():
    provedor = ProvedorFalso()

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, Executor(), maximo_do_historico=10)

    assert resultado.motivo == LIMITE_DO_HISTORICO
    assert provedor.rodadas == []


def test_historico_grande_depois_da_tool_impede_a_chamada_seguinte():
    provedor = ProvedorFalso(resposta(pedidos=[pedido()]))

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, Executor(ResultadoDeTool("x" * 2000)), maximo_do_historico=1500)

    assert resultado.motivo == LIMITE_DO_HISTORICO
    assert len(provedor.rodadas) == 1


@pytest.mark.parametrize("campo", ["maximo_de_voltas", "maximo_de_repeticoes", "maximo_do_resultado", "maximo_de_tools_por_volta", "maximo_do_historico"])
@pytest.mark.parametrize("valor", [0, -1, True, 1.5])
def test_limites_invalidos_falham_antes_de_chamar_o_provedor(campo, valor):
    provedor = ProvedorFalso()
    executor = Executor()
    with pytest.raises(ValueError, match=campo):
        rodar(provedor, "m-1", ABERTURA, TOOLS, executor, **{campo: valor})
    assert provedor.rodadas == []


def test_repeticao_no_fim_do_lote_nao_dispara_a_tool_no_comeco():
    repetido = pedido()
    provedor = ProvedorFalso(
        resposta(pedidos=[repetido]),
        resposta(pedidos=[repetido]),
        resposta(pedidos=[pedido("consultar_estado", "{}", "novo"), repetido]),
    )
    executor = Executor()

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert resultado.motivo == CHAMADA_REPETIDA
    assert [nome for nome, _ in executor.chamadas] == ["obter_incidente", "obter_incidente"]
    assert [m["tool_call_id"] for m in resultado.mensagens[-2:]] == ["novo", "c1"]


def test_uso_parcial_nao_produz_soma_enganosa():
    provedor = ProvedorFalso(resposta(pedidos=[pedido()], entrada=None, saida=10), resposta("Ok.", entrada=50, saida=20))
    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, Executor())
    assert resultado.tokens_entrada is None
    assert resultado.tokens_saida == 30
