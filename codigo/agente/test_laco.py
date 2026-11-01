"""Testes do laço ReAct, sem rede e sem servidor: o provedor e a execução das tools são falsos."""

import dataclasses

import pytest

from codigo.agente.laco import (
    AVISO_DE_CHAMADA_REPETIDA,
    AVISO_SEM_TOOLS,
    CHAMADA_REPETIDA,
    COMECO_DO_TEXTO_CORTADO,
    LIMITE_DE_SAIDA,
    LIMITE_DE_TOOLS,
    LIMITE_DE_VOLTAS,
    LIMITE_DO_HISTORICO,
    RECUSA_DO_PROVEDOR,
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
    for nome in ("obter_incidente", "obter_resumo", "obter_janelas", "consultar_estado", "apontar_atacante", "propor_acao")
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


def test_chamada_repetida_nao_roda_de_novo_e_o_modelo_recebe_o_aviso_sem_o_resultado():
    provedor = ProvedorFalso(resposta(pedidos=[pedido()]), resposta(pedidos=[pedido(identificador="c2")]), resposta("Pronto."))
    executor = Executor(ResultadoDeTool("incidente lido"))

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert resultado.motivo == RESPOSTA_FINAL
    assert executor.chamadas == [("obter_incidente", {"id": "inc-0001"})]
    aviso = provedor.rodadas[2]["mensagens"][-1]
    assert aviso == {"role": "tool", "tool_call_id": "c2", "content": AVISO_DE_CHAMADA_REPETIDA}
    assert "incidente lido" not in aviso["content"]
    assert [m["content"] for m in resultado.mensagens if m["role"] == "tool"].count("incidente lido") == 1


def test_a_triagem_que_refaz_a_sequencia_inteira_executa_cada_tool_uma_vez():
    # Teste de 31/10: obter_incidente, obter_janelas e apontar_atacante, e depois as três de novo, iguais.
    sequencia = [
        pedido("obter_incidente", '{"id": "inc-0001"}', "a"),
        pedido("obter_janelas", '{"id": "inc-0001", "limite": 20}', "b"),
        pedido("apontar_atacante", '{"id": "inc-0001", "endereco": "10.0.0.3", "justificativa": "Mais quadros."}', "c"),
    ]
    provedor = ProvedorFalso(*[resposta(pedidos=[p]) for p in sequencia * 2], resposta("Rótulo da triagem: coerente"))
    executor = Executor()

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert resultado.motivo == RESPOSTA_FINAL
    assert [nome for nome, _ in executor.chamadas] == ["obter_incidente", "obter_janelas", "apontar_atacante"]
    respostas_das_tools = [m["content"] for m in resultado.mensagens if m["role"] == "tool"]
    assert respostas_das_tools[-3:] == [AVISO_DE_CHAMADA_REPETIDA] * 3


def test_a_mesma_chamada_duas_vezes_no_mesmo_lote_roda_so_a_primeira():
    proposta = '{"id": "inc-0001", "acao": "bloquear_ip", "alvo": "origem-1"}'
    lote = [pedido("propor_acao", proposta, "p1"), pedido("propor_acao", proposta, "p2")]
    provedor = ProvedorFalso(resposta(pedidos=lote), resposta("Proposta feita."))
    executor = Executor(ResultadoDeTool('{"proposta": "prop-0001"}'))

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert resultado.terminou_bem
    assert len(executor.chamadas) == 1
    assert [(m["tool_call_id"], m["content"]) for m in provedor.rodadas[1]["mensagens"][3:]] == [
        ("p1", '{"proposta": "prop-0001"}'),
        ("p2", AVISO_DE_CHAMADA_REPETIDA),
    ]


def test_quem_insiste_depois_de_dois_avisos_para_o_laco_sem_executar():
    provedor = ProvedorFalso(*[resposta(pedidos=[pedido()]) for _ in range(5)])
    executor = Executor()

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert resultado.motivo == CHAMADA_REPETIDA
    assert resultado.resposta is None
    assert len(executor.chamadas) == 1
    assert len(resultado.chamadas_ao_modelo) == 4
    assert [m["content"] for m in resultado.mensagens if m["role"] == "tool"].count(AVISO_DE_CHAMADA_REPETIDA) == 2
    assert resultado.mensagens[-1]["role"] == "tool"
    assert "não executada" in resultado.mensagens[-1]["content"]


def test_a_repeticao_vale_para_o_mesmo_objeto_escrito_com_as_chaves_em_outra_ordem():
    pedidos = [pedido("obter_janelas", '{"id": "inc-0001", "limite": 5}'), pedido("obter_janelas", '{"limite": 5, "id": "inc-0001"}')]
    provedor = ProvedorFalso(*[resposta(pedidos=[p]) for p in pedidos], resposta("Pronto."))
    executor = Executor()

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert resultado.terminou_bem
    assert len(executor.chamadas) == 1
    assert provedor.rodadas[2]["mensagens"][-1]["content"] == AVISO_DE_CHAMADA_REPETIDA


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


@pytest.mark.parametrize(
    "motivo,esperado",
    # O artigo conta à parte quantas vezes o provedor recusou e quantas a resposta foi cortada.
    [("content_filter", RECUSA_DO_PROVEDOR), ("length", LIMITE_DE_SAIDA), ("error", RESPOSTA_INCOMPLETA), (["x"], RESPOSTA_INCOMPLETA)],
)
def test_resposta_interrompida_pelo_provedor_nao_dispara_tools(motivo, esperado):
    executor = Executor()
    incompleta = dataclasses.replace(resposta("Parcial", pedidos=[pedido()]), motivo_termino=motivo)

    resultado = rodar(ProvedorFalso(incompleta), "m-1", ABERTURA, TOOLS, executor)

    assert resultado.motivo == esperado
    assert executor.chamadas == []
    assert len(resultado.chamadas_ao_modelo) == 1
    assert resultado.chamadas_ao_modelo[0].motivo_termino == motivo


def test_resposta_cortada_no_limite_de_saida_guarda_o_comeco_do_texto():
    degenerado = "varredura de portas, " * 100
    cortada = dataclasses.replace(resposta(degenerado), motivo_termino="length")

    resultado = rodar(ProvedorFalso(cortada), "m-1", ABERTURA, TOOLS, Executor())

    assert resultado.motivo == LIMITE_DE_SAIDA
    assert resultado.comeco_do_texto_cortado == degenerado[:COMECO_DO_TEXTO_CORTADO]


def test_sem_texto_o_comeco_cortado_vem_das_tools_pedidas_pela_metade():
    cortada = dataclasses.replace(
        resposta(pedidos=[pedido("propor_acao", '{"id": "inc-0001", "justificativa": "varredura, varredura')]),
        motivo_termino="length",
    )
    executor = Executor()

    resultado = rodar(ProvedorFalso(cortada), "m-1", ABERTURA, TOOLS, executor)

    assert executor.chamadas == []
    assert resultado.comeco_do_texto_cortado == 'propor_acao({"id": "inc-0001", "justificativa": "varredura, varredura)'


def test_so_o_limite_de_saida_guarda_o_texto():
    recusa = dataclasses.replace(resposta("Não posso."), motivo_termino="content_filter")
    assert rodar(ProvedorFalso(recusa), "m-1", ABERTURA, TOOLS, Executor()).comeco_do_texto_cortado is None
    assert rodar(ProvedorFalso(resposta("Pronto.")), "m-1", ABERTURA, TOOLS, Executor()).comeco_do_texto_cortado is None


def test_cada_chamada_guarda_o_finish_reason_do_provedor():
    provedor = ProvedorFalso(
        dataclasses.replace(resposta(pedidos=[pedido()]), motivo_termino="tool_calls"),
        dataclasses.replace(resposta("Pronto."), motivo_termino="stop"),
    )
    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, Executor())
    assert [chamada.motivo_termino for chamada in resultado.chamadas_ao_modelo] == ["tool_calls", "stop"]


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
        *[resposta(pedidos=[repetido]) for _ in range(3)],
        resposta(pedidos=[pedido("consultar_estado", "{}", "novo"), repetido]),
    )
    executor = Executor()

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert resultado.motivo == CHAMADA_REPETIDA
    assert [nome for nome, _ in executor.chamadas] == ["obter_incidente"]
    assert [m["tool_call_id"] for m in resultado.mensagens[-2:]] == ["novo", "c1"]


def test_uso_parcial_nao_produz_soma_enganosa():
    provedor = ProvedorFalso(resposta(pedidos=[pedido()], entrada=None, saida=10), resposta("Ok.", entrada=50, saida=20))
    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, Executor())
    assert resultado.tokens_entrada is None
    assert resultado.tokens_saida == 30


def test_depois_de_dois_avisos_o_modelo_so_pode_dar_a_resposta_final():
    uma, outra = pedido("consultar_estado", "{}", "c1"), pedido("obter_incidente", '{"id": "inc-0001"}', "c2")
    provedor = ProvedorFalso(
        resposta(pedidos=[uma]), resposta(pedidos=[outra]), resposta(pedidos=[uma]), resposta(pedidos=[outra]),
        resposta("Recomendação final."),
    )

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, Executor())

    assert (resultado.motivo, resultado.resposta) == (RESPOSTA_FINAL, "Recomendação final.")
    assert [bool(rodada["tools"]) for rodada in provedor.rodadas] == [True, True, True, True, False]


def test_a_volta_sem_tools_diz_ao_modelo_que_elas_acabaram():
    uma, outra = pedido("consultar_estado", "{}", "c1"), pedido("obter_incidente", '{"id": "inc-0001"}', "c2")
    provedor = ProvedorFalso(
        resposta(pedidos=[uma]), resposta(pedidos=[outra]), resposta(pedidos=[uma]), resposta(pedidos=[outra]),
        resposta("Recomendação final."),
    )

    rodar(provedor, "m-1", ABERTURA, TOOLS, Executor())

    assert provedor.rodadas[-1]["mensagens"][-1] == {"role": "user", "content": AVISO_SEM_TOOLS}


def test_chamada_escrita_em_texto_nao_e_resposta_final():
    em_texto = "<tool_call>\n<function=obter_janelas>\n<parameter=id>\ninc-0001\n</parameter>\n</function>\n</tool_call>"
    provedor = ProvedorFalso(resposta(em_texto), resposta("Veredito: coerente."))
    executor = Executor()

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, executor)

    assert (resultado.motivo, resultado.resposta) == (RESPOSTA_FINAL, "Veredito: coerente.")
    assert executor.chamadas == []
    assert [bool(rodada["tools"]) for rodada in provedor.rodadas] == [True, False]
    assert provedor.rodadas[-1]["mensagens"][-1] == {"role": "user", "content": AVISO_SEM_TOOLS}


def test_quem_so_escreve_chamada_em_texto_termina_sem_resposta():
    provedor = ProvedorFalso(resposta("<tool_call>x</tool_call>"), resposta("<tool_call>y</tool_call>"))

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, Executor(), maximo_de_voltas=2)

    assert (resultado.motivo, resultado.resposta) == (LIMITE_DE_VOLTAS, None)


def test_depois_de_uma_tool_que_encerra_o_modelo_so_pode_dar_a_resposta_final():
    provedor = ProvedorFalso(resposta(pedidos=[pedido("propor_acao")]), resposta("Recomendação final."))

    resultado = rodar(provedor, "m-1", ABERTURA, TOOLS, Executor(), tools_que_encerram={"propor_acao"})

    assert (resultado.motivo, resultado.resposta) == (RESPOSTA_FINAL, "Recomendação final.")
    assert [bool(rodada["tools"]) for rodada in provedor.rodadas] == [True, False]


def test_tool_que_encerra_e_foi_recusada_deixa_as_tools():
    provedor = ProvedorFalso(resposta(pedidos=[pedido("propor_acao")]), resposta("Nenhuma ação foi proposta."))
    recusada = Executor(ResultadoDeTool("incidente_duvidoso", erro=True))

    rodar(provedor, "m-1", ABERTURA, TOOLS, recusada, tools_que_encerram={"propor_acao"})

    assert [bool(rodada["tools"]) for rodada in provedor.rodadas] == [True, True]
