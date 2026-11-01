"""O laço ReAct dos agentes: o modelo responde com chamadas de tool ou com a resposta final.

Um único laço serve aos três papéis (triagem, decisão e execução). O que muda de um papel para o
outro é a skill, que vai no prompt de sistema, e as tools da linha do agente, que o servidor MCP
já filtra. O laço não conhece HTTP nem o servidor MCP: recebe um provedor com `conversar` (ver
`codigo/api/provedor.py`) e uma função `executar(nome, argumentos)` que leva a chamada ao servidor.

Cada volta chama o modelo uma vez. Se ele pede tools, o laço as executa, devolve os resultados e
chama de novo; se responde sem pedir tool, a resposta é a final. Há limites de voltas, chamadas
por volta, histórico, resultado de tool e repetição. Os limites em caracteres são uma trava contra
custo descontrolado: não medem tokens nem configuram a janela de contexto do servidor do modelo, que
responde com erro se o pedido passar dela.

Uma chamada igual a outra já feita no laço (mesma tool, mesmos argumentos) não roda de novo: o
modelo recebe um aviso de que o resultado já está no histórico. Vale também para uma leitura depois
de uma ação, que poderia trazer outro resultado, como `consultar_estado` antes e depois de
`executar_acao`; nenhuma skill pede a mesma leitura duas vezes.

Numa volta sem tools, o modelo só pode dar a resposta final, e uma mensagem diz isso a ele. É assim
depois dos avisos de chamada repetida e depois de uma tool que encerra o trabalho do agente, como
`propor_acao`. Uma resposta que escreve a chamada de tool como texto não é a final: ela não vai para
o log como análise, e a volta seguinte é sem tools.

Cada chamada ao modelo gera uma `ChamadaAoModelo`, entregue a `ao_chamar` na hora. É o que vira o
evento `llm_chamada` do log (ver `registro.py`).
"""

import json
import time
from collections import Counter
from copy import deepcopy
from dataclasses import dataclass

MAXIMO_DE_VOLTAS = 8
# A mesma tool com os mesmos argumentos roda uma vez só em cada laço. Cada repetição recebe o aviso
# de chamada repetida, e na terceira, quando o modelo já ignorou dois avisos, o laço para. No teste
# de 31/10, a triagem refez a sequência inteira de tools em 39 das 98 rodadas, e a trava antiga, que
# parava na terceira vez sem aviso, encerrou um incidente antes do veredito.
MAXIMO_DE_REPETICOES = 3
# Depois de tantos avisos no laço, somando as tools, a volta seguinte vai sem tools: o modelo só pode
# dar a resposta final. Alternando entre duas tools repetidas, ele gastaria as voltas sem nunca parar
# na trava de cima, e a proposta já registrada ficaria sem recomendação.
AVISOS_ANTES_DE_TIRAR_AS_TOOLS = 2
# Sem a lista de tools, o modelo local às vezes escreve a chamada no texto da resposta, e isso virava
# a análise da triagem: 6 das 98 rodadas da validação de 31/10.
CHAMADA_EM_TEXTO = "<tool_call>"
# Medido contra o stub em 26/10/2026: `obter_janelas(id, 20)`, que a skill da triagem pede, devolve
# de 6,9 mil a 15 mil caracteres nos quatro incidentes de exemplo, e até cerca de 22,5 mil com as 39
# features em 6 casas decimais, como as do reprodutor. As demais tools ficam abaixo de 4 mil. Um
# resultado maior não vai ao modelo, nem cortado: ele recebe um aviso para pedir menos.
MAXIMO_DO_RESULTADO = 30000
MAXIMO_DE_TOOLS_POR_VOLTA = 8
# O prompt de sistema tem cerca de 5 mil caracteres e as tools de uma linha, até 3,4 mil. Cabem
# folgadas três fatias de 20 janelas no pior caso.
MAXIMO_DO_HISTORICO = 100000

RESPOSTA_FINAL = "resposta_final"
LIMITE_DE_VOLTAS = "limite_de_voltas"
CHAMADA_REPETIDA = "chamada_repetida"
LIMITE_DE_TOOLS = "limite_de_tools"
LIMITE_DO_HISTORICO = "limite_do_historico"
RESPOSTA_INCOMPLETA = "resposta_incompleta"
RESPOSTA_VAZIA = "resposta_vazia"
# O provedor recusou responder (finish_reason content_filter): contado à parte no artigo.
RECUSA_DO_PROVEDOR = "recusa_do_provedor"
# A resposta foi cortada no máximo de tokens de saída (finish_reason length).
LIMITE_DE_SAIDA = "limite_de_saida"
_TERMINO_INTERROMPIDO = {"content_filter": RECUSA_DO_PROVEDOR, "length": LIMITE_DE_SAIDA}
# Quanto do texto cortado no limite de saída fica no resultado, para diagnosticar a degeneração.
COMECO_DO_TEXTO_CORTADO = 300

AVISO_DE_CHAMADA_REPETIDA = (
    "Chamada repetida, não executada: esta tool já foi chamada nesta conversa com estes mesmos argumentos, "
    "e o resultado está acima, na resposta à primeira chamada. Não repita a chamada; use aquele resultado "
    "para seguir com o próximo passo ou dar a resposta final."
)
AVISO_SEM_TOOLS = (
    "Não há mais tools nesta conversa, e chamada de tool escrita em texto não é executada. "
    "Escreva agora a resposta final, no formato pedido, com o que já está acima."
)


@dataclass(frozen=True)
class ResultadoDeTool:
    """O que a execução de uma tool devolve ao laço: o texto que o modelo vai ler e se foi um erro."""

    texto: str
    erro: bool = False


@dataclass(frozen=True)
class ChamadaAoModelo:
    volta: int
    modelo: str
    tokens_entrada: int | None
    tokens_saida: int | None
    duracao_ms: float
    tools_pedidas: tuple[str, ...]
    # O finish_reason como o provedor o devolveu (stop, tool_calls, length, content_filter...).
    motivo_termino: str | None = None


@dataclass(frozen=True)
class ResultadoDoLaco:
    """Como o laço terminou. Só `RESPOSTA_FINAL` traz uma resposta; nos outros motivos, é `None`.

    `mensagens` é o histórico inteiro, com o que o chamador mandou na frente. Chamadas não
    executadas recebem uma resposta de erro no histórico, sem disparar ações ao encerrar o laço.
    Com `LIMITE_DE_SAIDA`, `comeco_do_texto_cortado` guarda o começo do que o modelo escreveu antes
    do corte, que não vai para o log; nos outros motivos, é `None`.
    """

    motivo: str
    resposta: str | None
    mensagens: tuple[dict, ...]
    chamadas_ao_modelo: tuple[ChamadaAoModelo, ...]
    comeco_do_texto_cortado: str | None = None

    @property
    def terminou_bem(self):
        return self.motivo == RESPOSTA_FINAL

    @property
    def tokens_entrada(self):
        return _somar_tokens(self.chamadas_ao_modelo, "tokens_entrada")

    @property
    def tokens_saida(self):
        return _somar_tokens(self.chamadas_ao_modelo, "tokens_saida")


def rodar(
    provedor,
    modelo,
    mensagens,
    tools,
    executar,
    *,
    maximo_de_voltas=MAXIMO_DE_VOLTAS,
    maximo_de_repeticoes=MAXIMO_DE_REPETICOES,
    maximo_do_resultado=MAXIMO_DO_RESULTADO,
    maximo_de_tools_por_volta=MAXIMO_DE_TOOLS_POR_VOLTA,
    maximo_do_historico=MAXIMO_DO_HISTORICO,
    tools_que_encerram=frozenset(),
    ao_chamar=None,
    relogio=time.perf_counter,
):
    """Roda o laço até a resposta final ou até um dos limites.

    `mensagens` é o começo da conversa, no formato da API (o prompt de sistema e a abertura do
    incidente). `tools` está no formato de `tools` da API. `executar(nome, argumentos)` recebe os
    argumentos já lidos como dicionário e devolve um `ResultadoDeTool`. Falha de transporte ou do
    provedor passa para quem chamou: o laço só trata o que o modelo pode corrigir, como argumento
    que não é JSON ou tool que recusou o pedido. Depois que uma das `tools_que_encerram` roda sem
    erro, a volta seguinte vai sem tools.
    """
    _validar_limites(
        maximo_de_voltas=maximo_de_voltas, maximo_de_repeticoes=maximo_de_repeticoes,
        maximo_do_resultado=maximo_do_resultado, maximo_de_tools_por_volta=maximo_de_tools_por_volta,
        maximo_do_historico=maximo_do_historico,
    )
    historico = deepcopy(list(mensagens))
    tools = deepcopy(list(tools))
    permitidas = {tool["function"]["name"] for tool in tools}
    chamadas = []
    # Quantas vezes cada chamada (tool e argumentos) já foi pedida neste laço.
    pedidas = Counter()
    avisos = 0
    sem_tools = False

    def terminar(motivo, resposta=None, cortado=None):
        return ResultadoDoLaco(motivo, resposta, tuple(historico), tuple(chamadas), cortado)

    def cabe_no_historico():
        return len(json.dumps({"messages": historico, "tools": tools}, ensure_ascii=False)) <= maximo_do_historico

    def interromper(motivo, pedidos, cortado=None):
        for pedido in pedidos:
            historico.append(_mensagem_da_tool(pedido, f"Erro da tool: não executada; laço encerrado por {motivo}."))
        return terminar(motivo, cortado=cortado)

    def tirar_as_tools():
        nonlocal sem_tools
        sem_tools = True
        historico.append({"role": "user", "content": AVISO_SEM_TOOLS})

    for volta in range(1, maximo_de_voltas + 1):
        if not cabe_no_historico():
            return terminar(LIMITE_DO_HISTORICO)
        inicio = relogio()
        resposta = provedor.conversar(modelo, historico, [] if sem_tools else tools)
        chamada = ChamadaAoModelo(
            volta=volta,
            modelo=resposta.modelo,
            tokens_entrada=resposta.tokens_entrada,
            tokens_saida=resposta.tokens_saida,
            duracao_ms=(relogio() - inicio) * 1000,
            tools_pedidas=tuple(pedido.nome for pedido in resposta.pedidos),
            motivo_termino=resposta.motivo_termino,
        )
        chamadas.append(chamada)
        if ao_chamar is not None:
            ao_chamar(chamada)
        historico.append(deepcopy(resposta.mensagem))
        motivo = _termino_da_resposta(resposta, cabe_no_historico(), maximo_de_tools_por_volta)
        if motivo == RESPOSTA_FINAL:
            if CHAMADA_EM_TEXTO not in resposta.conteudo:
                return terminar(RESPOSTA_FINAL, resposta.conteudo)
            tirar_as_tools()
            continue
        if motivo is not None:
            cortado = _comeco_do_texto(resposta) if motivo == LIMITE_DE_SAIDA else None
            return interromper(motivo, resposta.pedidos, cortado)
        if volta == maximo_de_voltas:
            # O modelo não teria outra volta para ler o resultado: uma ação aplicada aqui ficaria
            # sem a verificação do efeito.
            return interromper(LIMITE_DE_VOLTAS, resposta.pedidos)
        argumentos = [_argumentos(pedido.argumentos) for pedido in resposta.pedidos]
        # Confere o lote inteiro antes de executar: a repetição no fim não dispara as ações do começo.
        repetidas = _repetidas(resposta.pedidos, argumentos, pedidas, maximo_de_repeticoes)
        if repetidas is None:
            return interromper(CHAMADA_REPETIDA, resposta.pedidos)
        concluidas = _executar_pedidos(
            historico, resposta.pedidos, argumentos, repetidas, permitidas, executar, maximo_do_resultado
        )
        avisos += sum(repetidas)
        if not sem_tools and (avisos >= AVISOS_ANTES_DE_TIRAR_AS_TOOLS or concluidas & set(tools_que_encerram)):
            tirar_as_tools()
    return terminar(LIMITE_DE_VOLTAS)


def _validar_limites(**limites):
    for nome, valor in limites.items():
        if isinstance(valor, bool) or not isinstance(valor, int) or valor < 1:
            raise ValueError(f"{nome} precisa ser um inteiro positivo")


def _termino_da_resposta(resposta, cabe_no_historico, maximo_de_tools):
    termino = resposta.motivo_termino
    if termino not in (None, "stop", "tool_calls"):
        # O finish_reason vem do JSON do provedor e pode nem ser texto.
        return _TERMINO_INTERROMPIDO.get(termino, RESPOSTA_INCOMPLETA) if isinstance(termino, str) else RESPOSTA_INCOMPLETA
    if resposta.pedidos:
        if not cabe_no_historico:
            return LIMITE_DO_HISTORICO
        if len(resposta.pedidos) > maximo_de_tools:
            return LIMITE_DE_TOOLS
        return None
    if resposta.motivo_termino == "tool_calls":
        return RESPOSTA_INCOMPLETA
    return RESPOSTA_FINAL if resposta.conteudo.strip() else RESPOSTA_VAZIA


def _repetidas(pedidos, argumentos, pedidas, maximo):
    """Diz, pedido a pedido, se a chamada já foi feita no laço, inclusive antes no mesmo lote.

    Devolve `None` quando uma chamada chega à repetição de número `maximo`: o modelo insistiu depois
    dos avisos, e o laço para.
    """
    repetidas = []
    for pedido, dados in zip(pedidos, argumentos, strict=True):
        chave = json.dumps(dados, sort_keys=True, ensure_ascii=False) if dados is not None else pedido.argumentos
        igual = (pedido.nome, chave)
        if pedidas[igual] >= maximo:
            return None
        repetidas.append(pedidas[igual] > 0)
        pedidas[igual] += 1
    return repetidas


def _executar_pedidos(historico, pedidos, argumentos, repetidas, permitidas, executar, maximo):
    """Executa o lote e devolve os nomes das tools que rodaram sem erro."""
    concluidas = set()
    for pedido, dados, repetida in zip(pedidos, argumentos, repetidas, strict=True):
        if repetida:
            # Sem executar de novo: uma ação (apontar, propor) não chega duas vezes ao servidor, e o
            # resultado, que já está no histórico, não é mandado outra vez.
            texto = AVISO_DE_CHAMADA_REPETIDA
        elif pedido.nome not in permitidas:
            texto = "Erro da tool: ferramenta não disponibilizada a este agente."
        elif dados is None:
            texto = "Erro da tool: os argumentos precisam ser um objeto JSON válido em UTF-8, sem chaves repetidas."
        else:
            resultado = executar(pedido.nome, dados)
            if not resultado.erro:
                concluidas.add(pedido.nome)
            if len(resultado.texto) > maximo:
                # Nada de JSON cortado, que poderia esconder parte do estado. O aviso diz que a
                # chamada já aconteceu, para o modelo não repetir uma ação achando que ela falhou.
                texto = (
                    f"Erro da tool: a chamada foi executada, mas o resultado tem {len(resultado.texto)} caracteres "
                    f"e passa do limite de {maximo}. Não repita a mesma chamada; peça menos dados."
                )
            else:
                texto = f"Erro da tool: {resultado.texto}" if resultado.erro else resultado.texto
        historico.append(_mensagem_da_tool(pedido, texto))
    return concluidas


def _comeco_do_texto(resposta):
    """O começo do que o modelo escreveu antes do corte: o texto ou, sem ele, as tools que pediu."""
    texto = resposta.conteudo.strip() or " ".join(f"{pedido.nome}({pedido.argumentos})" for pedido in resposta.pedidos)
    return texto[:COMECO_DO_TEXTO_CORTADO]


def _somar_tokens(chamadas, atributo):
    valores = [getattr(chamada, atributo) for chamada in chamadas]
    return None if any(valor is None for valor in valores) else sum(valores)


def _mensagem_da_tool(pedido, texto):
    return {"role": "tool", "tool_call_id": pedido.id, "content": texto}


def _sem_chaves_repetidas(pares):
    objeto = {}
    for chave, valor in pares:
        if chave in objeto:
            raise ValueError("chave repetida nos argumentos")
        objeto[chave] = valor
    return objeto


def _constante_invalida(_):
    raise ValueError("NaN e Infinity não são valores JSON")


def _argumentos(texto):
    try:
        argumentos = json.loads(texto, object_pairs_hook=_sem_chaves_repetidas, parse_constant=_constante_invalida)
        # Também recusa um expoente que o parser converte em infinito (por exemplo 1e999) e um
        # surrogate solto ("\ud800"), que não vira UTF-8 e derrubaria a sessão MCP no envio.
        json.dumps(argumentos, allow_nan=False, ensure_ascii=False).encode("utf-8")
    except (ValueError, RecursionError):
        return None
    return argumentos if isinstance(argumentos, dict) else None
