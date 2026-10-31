"""Servidor MCP de mentira (stub) do SentryIoT.

Responde às onze tools do contrato com os incidentes de `cenarios.py`, sem classificador
treinado e sem rede. Serve para a frente dos agentes trabalhar em paralelo: quem escreve as
skills chama as tools, percorre um incidente do começo ao fim e obtém o log de eventos que a
interface web vai ler.

O servidor não guarda estado na memória. A cada chamada ele lê o log, decide e grava o que
aconteceu. Por isso o comando de aprovação, que é outro processo, vale na chamada seguinte, e
cada agente pode ter o seu próprio processo sobre o mesmo log.

A linha de decisão não recebe endereço nenhum (arquitetura híbrida, decisão de 2026-10-10): ela
lê o resumo com rótulos neutros, escreve o alvo com o rótulo, e toda resposta a ela passa por um
filtro que troca o endereço que sobrar em texto livre por um marcador. Se o filtro não consegue
entregar a resposta dentro do contrato, ela não é entregue.

Uso, a partir da raiz do repositório (transporte stdio). O agente é obrigatório:
    python -m codigo.mcp.stub --agente triagem
    python -m codigo.mcp.stub --agente decisao --log outro/caminho.jsonl
    python -m codigo.mcp.stub --agente todos       todas as tools de uma vez, só para desenvolvimento
"""
import argparse
import inspect
import json
import math
import sys
from typing import Annotated

from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, TextContent
from pydantic import TypeAdapter, ValidationError

from codigo.mcp import acoes
from codigo.mcp.acoes import PedidoRecusado, carregar_politica, reconstruir, resumir
from codigo.mcp.base import carregar, mitigacoes, pesquisar
from codigo.mcp.cenarios import CENARIOS, efeito, evoluir, janelas, ler_cenarios
from codigo.mcp.eventos import CAMINHO_PADRAO, LogInvalido, Registro, novo
from codigo.mcp.tipos import (
    AGENTES,
    LIMITE_DE_JANELAS,
    TEXTO_CURTO,
    TEXTO_LONGO,
    TODOS,
    TOOLS,
    ChamadaDeTool,
    Consulta,
    Efeito,
    FatiaDeJanelas,
    Mitigacoes,
    Proposta,
    Recusa,
    Solucoes,
    mascarar_enderecos,
    tools_do_agente,
)

INSTRUCOES = (
    "Servidor de mentira (stub) do SentryIoT. Responde com incidentes de exemplo, de números ilustrativos, "
    "e aplica as ações só em um ambiente simulado. Os incidentes são inc-0001 (flood), inc-0002 (força "
    "bruta), inc-0003 (varredura de portas) e inc-0004. Ação de risco alto e ação nova, fora do catálogo, "
    "só são executadas depois que uma pessoa aprova. Na linha de decisão, os endereços do incidente são "
    "rótulos neutros, como origem-1 e destino-1."
)
# A linha que não recebe endereço nenhum: a do agente que pode estar num modelo de nuvem.
LINHA_SEM_ENDERECOS = "decisao"
_LOG_INVALIDO = (
    "O log de eventos do servidor está inconsistente, e nenhuma tool é atendida até que ele seja corrigido. "
    "O detalhe está na saída de erro do servidor."
)
_TOOLS = {tool.nome: tool for tool in TOOLS}
_CONSULTA = TypeAdapter(Consulta)
# Até onde uma lista, um objeto ou uma estrutura aninhada de um argumento vai para o log.
_MAIS_ITENS = 20
_MAIS_NIVEIS = 4
# Teto, em bytes de JSON, dos argumentos de uma chamada no log. O corte item a item não basta: 20
# objetos de 20 listas de 20 textos de 2.000 caracteres cabem nele e somam 16 MB.
MAIOR_REGISTRO_DE_ARGUMENTOS = 8 * 1024


def _milhar(numero):
    return f"{numero:,}".replace(",", ".")


def _para_o_log(valor, nivel=0):
    """O argumento como é gravado no log: igual ao recebido quando cabe no contrato, cortado quando não.

    O que um agente manda vai para o log em `tool_chamada` e em `recusa`. Sem este corte, um
    texto de megabytes recusado ficaria inteiro no arquivo, e um valor que o leitor do log não
    aceita (um inteiro de milhares de dígitos, um número não finito) deixaria o log ilegível.
    """
    if valor is None or isinstance(valor, bool):
        return valor
    if isinstance(valor, int):
        # O Python não converte em texto um inteiro de mais de 4.300 dígitos: conta-se em bits.
        return valor if valor.bit_length() <= 64 else f"[inteiro de {_milhar(valor.bit_length())} bits]"
    if isinstance(valor, float):
        return valor if math.isfinite(valor) else f"[{valor}]"
    if isinstance(valor, str):
        # Par substituto solto não é texto válido e não pode ser gravado em UTF-8.
        texto = valor.encode("utf-8", "backslashreplace").decode("utf-8")
        if len(texto) <= TEXTO_LONGO:
            return texto
        return f"{texto[:TEXTO_CURTO]} [cortado: {_milhar(len(texto))} caracteres]"
    if isinstance(valor, dict | list | tuple):
        if nivel >= _MAIS_NIVEIS:
            return "[estrutura cortada]"
        if isinstance(valor, dict):
            resumo = {
                str(_para_o_log(chave if isinstance(chave, str) else repr(chave)))[:TEXTO_CURTO]:
                _para_o_log(item, nivel + 1)
                for chave, item in list(valor.items())[:_MAIS_ITENS]
            }
            if len(valor) > _MAIS_ITENS:
                resumo["[cortado]"] = f"{_milhar(len(valor))} chaves"
            return resumo
        resumo = [_para_o_log(item, nivel + 1) for item in valor[:_MAIS_ITENS]]
        if len(valor) > _MAIS_ITENS:
            resumo.append(f"[cortado: {_milhar(len(valor))} itens]")
        return resumo
    return f"[valor do tipo {type(valor).__name__}]"


def _bytes(valor):
    return len(json.dumps(valor, ensure_ascii=False).encode("utf-8"))


def _argumentos_para_o_log(argumentos):
    """Os argumentos como vão para o log: cortados item a item e, depois, com teto no total.

    Os argumentos entram na ordem em que vieram enquanto cabem no teto. O que não cabe vira a marca
    `[cortado: N bytes]`, com o tamanho do que ficou de fora. Os nomes dos argumentos ficam todos, e
    são no máximo 20, de até 200 caracteres.
    """
    resumo = _para_o_log(argumentos)
    if _bytes(resumo) <= MAIOR_REGISTRO_DE_ARGUMENTOS:
        return resumo
    # Cada argumento ocupa, no pior caso, o tamanho da marca. O que sobra do teto vai para os que
    # cabem inteiros, na ordem em que vieram.
    marca = "[cortado: 000.000.000 bytes]"
    livre = MAIOR_REGISTRO_DE_ARGUMENTOS - sum(_bytes({nome: marca}) for nome in resumo)
    cabem = {}
    for nome, valor in resumo.items():
        a_mais = _bytes({nome: valor}) - _bytes({nome: marca})
        if a_mais <= livre:
            cabem[nome] = valor
            livre -= max(a_mais, 0)
        else:
            cabem[nome] = f"[cortado: {_milhar(_bytes(valor))} bytes]"
    return cabem


_OBSERVACOES = {
    "cessou": "O tráfego do incidente cessou depois da ação.",
    "diminuiu": "O tráfego do incidente diminuiu depois da ação, mas não cessou.",
    "persiste": "O tráfego do incidente continua no mesmo nível depois da ação.",
}
# O que vai para o log como resultado resumido de cada tool.
_RESUMOS = {
    "obter_incidente": lambda r: {
        "estado": r.estado, "categoria": r.categoria, "confianca": r.confianca, "janelas": r.janelas,
    },
    "obter_resumo": lambda r: {
        "estado": r.estado, "categoria": r.categoria, "confianca": r.confianca, "janelas": r.janelas,
        "ja_resolvido": r.ja_resolvido,
    },
    "obter_janelas": lambda r: {"janelas": len(r.janelas), "total": r.total},
    "apontar_atacante": lambda r: {"endereco": r.endereco},
    "consultar_mitigacoes": lambda r: {"mitigacoes": len(r.mitigacoes), "acoes": len(r.acoes)},
    "pesquisar_solucoes": lambda r: {"trechos": [f"{trecho.origem}: {trecho.titulo}" for trecho in r.trechos]},
    "propor_acao": lambda r: {
        "proposta": r.id, "risco": r.risco,
        "motivos_de_risco_alto": [motivo.codigo for motivo in r.motivos_de_risco_alto],
        "exige_aprovacao": r.exige_aprovacao,
    },
    "verificar_efeito": lambda r: {"resultado": r.resultado},
    "executar_acao": lambda r: {"execucao": r.id, "estado": r.estado},
    "desfazer_acao": lambda r: {"execucao": r.id, "estado": r.estado},
    "consultar_estado": lambda r: {grupo: len(medidas) for grupo, medidas in r},
}


class Stub:
    """As tools do contrato, respondidas com os cenários e registradas no log de eventos.

    O agente é obrigatório. Com `triagem`, `decisao` ou `execucao`, o stub atende só as tools
    da linha desse agente e registra o nome dele em cada chamada. Com `agente="todos"`, atende
    todas e deixa o agente nulo no log: é o que `--agente todos` pede na linha de comando, e
    serve só para desenvolvimento.
    """

    def __init__(self, registro=None, *, agente, cenarios=CENARIOS, politica=None, secoes=None):
        self.registro = registro if registro is not None else Registro()
        # As tools que este processo atende e anuncia ao cliente.
        self.permitidas = tools_do_agente(agente)
        # Com todas as tools, não se sabe qual dos três agentes chamou: o log fica sem o nome.
        self.agente = None if agente == TODOS else agente
        self._cenarios = {cenario.incidente.id: cenario for cenario in cenarios}
        self._politica = politica if politica is not None else carregar_politica()
        self._secoes = secoes if secoes is not None else carregar()
        # Incidente da última chamada. As tools sem identificador (consultar_mitigacoes,
        # pesquisar_solucoes e consultar_estado) são registradas nele, para que a interface
        # consiga mostrar o rastro completo de um incidente.
        self._em_foco = None

    def abrir_incidentes(self):
        """Grava no log a abertura dos incidentes dos cenários, se ainda não estiverem lá.

        No sistema de verdade esses eventos vêm do classificador e da política de acionamento.
        """
        def decidir(eventos):
            abertos = reconstruir(eventos).incidentes
            rascunhos = []
            for identificador, cenario in self._cenarios.items():
                if identificador not in abertos:
                    rascunhos.append(novo("janelas_classificadas", cenario.lote))
                    rascunhos.append(novo("incidente_aberto", cenario.incidente, identificador))
                elif not _mesmo_incidente(abertos[identificador], cenario.incidente):
                    # Um log de outra execução com o mesmo identificador: servir este cenário daria
                    # janelas e efeitos de outro incidente.
                    raise ValueError(
                        f"o log já tem um {identificador} diferente do cenário {cenario.nome}: use outro log, "
                        "ou passe os cenários da execução que gravou este log com --cenarios"
                    )
            return None, rascunhos

        self.registro.atualizar(decidir)

    def chamar(self, nome, **argumentos):
        """Atende a chamada de uma tool e devolve o resultado, no tipo de saída do contrato.

        Toda chamada fica no log: `tool_chamada`, seguida dos eventos que a tool produziu, ou
        `recusa`, quando o pedido é recusado. A recusa levanta PedidoRecusado, com o motivo e
        a mensagem.
        """
        if nome not in _TOOLS:
            raise ValueError(f"tool desconhecida: {nome}")
        inicio = self.registro.relogio()
        # Para o log vai o resumo dos argumentos: igual a eles, a não ser quando são grandes demais.
        para_o_log = _argumentos_para_o_log(argumentos)

        def decidir(eventos):
            estado = reconstruir(eventos)
            incidente = self._incidente_da_chamada(estado, argumentos)
            try:
                resultado, rascunhos = self._atender(nome, estado, argumentos, inicio)
            except PedidoRecusado as recusa:
                if self.agente == LINHA_SEM_ENDERECOS:
                    # Rede de proteção: o filtro roda sobre a mensagem inteira, antes do corte.
                    recusa = PedidoRecusado(recusa.motivo, mascarar_enderecos(recusa.inteira))
                dados = Recusa(
                    agente=self.agente, tool=nome, argumentos=para_o_log, motivo=recusa.motivo,
                    mensagem=recusa.mensagem,
                )
                return recusa, [novo("recusa", dados, incidente)]
            duracao = (self.registro.relogio() - inicio).total_seconds() * 1000
            chamada = ChamadaDeTool(
                agente=self.agente, nome=nome, argumentos=para_o_log, resultado=_RESUMOS[nome](resultado),
                duracao_ms=round(duracao, 3),
            )
            if self.agente == LINHA_SEM_ENDERECOS:
                # Dentro da gravação: se a resposta não pode ser entregue sem endereço, nada é gravado.
                resultado = _sem_enderecos(resultado)
            return resultado, [novo("tool_chamada", chamada, incidente), *rascunhos]

        resultado, _ = self.registro.atualizar(decidir)
        if isinstance(resultado, PedidoRecusado):
            raise resultado
        return resultado

    def _atender(self, nome, estado, argumentos, inicio):
        if nome not in self.permitidas:
            raise PedidoRecusado(
                "tool_fora_da_linha",
                f"A tool {nome} não faz parte da linha do agente de {self.agente}, que só enxerga: "
                f"{', '.join(self.permitidas)}.",
            )
        try:
            entrada = _TOOLS[nome].entrada.model_validate(argumentos)
        except ValidationError as erro:
            # O nome de um argumento a mais vem de quem chamou: entra na mensagem escapado e cortado.
            declarados = _TOOLS[nome].entrada.model_fields
            campos = sorted({str(defeito["loc"][0]) if defeito["loc"] else nome for defeito in erro.errors()})
            mostrados = [campo if campo in declarados else resumir(campo, 30) for campo in campos[:_MAIS_ITENS]]
            raise PedidoRecusado(
                "argumentos_invalidos",
                f"Argumentos fora do contrato de {nome}. Confira: {', '.join(mostrados)}.",
            ) from None
        return getattr(self, f"_{nome}")(estado, inicio, **dict(entrada))

    def _incidente_da_chamada(self, estado, argumentos):
        """Incidente a que a chamada se refere: o do argumento ou, se não houver, o da chamada anterior."""
        def texto(nome):
            # Argumento que não é texto não identifica nada. Ele é recusado mais adiante, na validação.
            valor = argumentos.get(nome)
            return valor if isinstance(valor, str) else None

        identificador = texto("id")
        if identificador not in estado.incidentes:
            de_onde = estado.propostas.get(texto("id_proposta")) or estado.execucoes.get(texto("id_execucao"))
            identificador = de_onde.incidente if de_onde is not None else self._em_foco
        self._em_foco = identificador
        return identificador

    def _incidente(self, estado, identificador):
        if identificador not in estado.incidentes or identificador not in self._cenarios:
            raise PedidoRecusado(
                "identificador_desconhecido", f"Não existe incidente com o identificador {resumir(identificador)}."
            )
        return estado.incidentes[identificador]

    # --- as tools, uma função para cada: recebem o estado e devolvem o resultado e os eventos ---

    def _obter_incidente(self, estado, _inicio, id):
        return self._incidente(estado, id), []

    def _obter_janelas(self, estado, _inicio, id, limite):
        incidente = self._incidente(estado, id)
        fatia = janelas(self._cenarios[id], incidente, min(limite, LIMITE_DE_JANELAS))
        return FatiaDeJanelas(incidente=id, total=incidente.janelas, janelas=fatia), []

    def _apontar_atacante(self, estado, _inicio, id, endereco, justificativa):
        self._incidente(estado, id)
        return acoes.apontar_atacante(estado, id, endereco, justificativa)

    def _obter_resumo(self, estado, _inicio, id):
        self._incidente(estado, id)
        return acoes.resumo_do_incidente(estado, self._politica, id), []

    def _consultar_mitigacoes(self, estado, _inicio, categoria):
        return Mitigacoes(
            categoria=categoria,
            mitigacoes=mitigacoes(self._secoes, categoria),
            acoes=acoes.catalogo(estado, self._politica, com_rotulos=self.agente == LINHA_SEM_ENDERECOS),
        ), []

    def _pesquisar_solucoes(self, _estado, _inicio, consulta):
        try:
            consulta = _CONSULTA.validate_python(consulta)
        except ValidationError:
            raise PedidoRecusado(
                "argumentos_invalidos",
                f"A consulta precisa ser um texto de até {_milhar(TEXTO_LONGO)} caracteres, sem caractere de controle "
                "nem caractere que não aparece na tela.",
            ) from None
        return Solucoes(consulta=consulta, fonte="base_local", trechos=pesquisar(self._secoes, consulta)), []

    def _propor_acao(self, estado, _inicio, id, acao, alvo, parametros, justificativa):
        self._incidente(estado, id)
        return acoes.propor(
            estado, self._politica, id, acao, alvo, parametros, justificativa,
            so_rotulos=self.agente == LINHA_SEM_ENDERECOS,
        )

    def _executar_acao(self, estado, inicio, id_proposta):
        return acoes.executar(estado, self._politica, id_proposta, inicio)

    def _desfazer_acao(self, estado, inicio, id_execucao):
        return acoes.desfazer(estado, id_execucao, inicio)

    def _consultar_estado(self, estado, _inicio):
        return acoes.ambiente(estado), []

    def _verificar_efeito(self, estado, _inicio, id_execucao):
        execucao = estado.execucoes.get(id_execucao)
        if execucao is None:
            raise PedidoRecusado(
                "identificador_desconhecido", f"Não existe execução com o identificador {resumir(id_execucao)}."
            )
        if execucao.estado == "desfeita":
            raise PedidoRecusado(
                "acao_nao_aplicada", f"A execução {execucao.id} foi desfeita: não há efeito a verificar."
            )
        incidente = self._incidente(estado, execucao.incidente)
        cenario = self._cenarios[incidente.id]
        # O efeito vem do roteiro do cenário: depende de quantas ações já foram aplicadas no
        # incidente até esta, e não de qual ação foi.
        do_incidente = [e.id for e in estado.execucoes.values() if e.incidente == incidente.id]
        resultado = efeito(cenario, do_incidente.index(execucao.id) + 1)
        verificado = Efeito(
            execucao=execucao.id, incidente=incidente.id, resultado=resultado, observacao=_OBSERVACOES[resultado]
        )
        rascunhos = [novo("efeito_verificado", verificado, incidente.id)]
        # Na primeira verificação de uma execução, o incidente anda: é encerrado ou continua, maior.
        # No sistema de verdade quem grava isso é a política de acionamento.
        if execucao.id not in estado.efeitos and incidente.estado == "aberto":
            tipo = "incidente_encerrado" if resultado == "cessou" else "incidente_atualizado"
            rascunhos.append(novo(tipo, evoluir(cenario, incidente, resultado, execucao.aplicada_em), incidente.id))
        return verificado, rascunhos


def _mesmo_incidente(no_log, do_cenario):
    """Se o incidente do log é o do cenário: mesmo começo e mesma categoria do modelo."""
    return no_log.inicio == do_cenario.inicio and no_log.categoria_do_modelo == do_cenario.categoria_do_modelo


def _limpar(valor):
    if isinstance(valor, str):
        return mascarar_enderecos(valor)
    if isinstance(valor, list):
        return [_limpar(item) for item in valor]
    if isinstance(valor, dict):
        return {_limpar(chave): _limpar(item) for chave, item in valor.items()}
    return valor


def _sem_enderecos(resultado):
    """A resposta como vai para a linha de decisão: sem endereço nenhum.

    A proposta volta com o alvo escrito com o rótulo, como o agente o escreveu. Depois, todo texto
    da resposta passa pelo filtro que troca IPv4, IPv6 e MAC por um marcador: é a rede de proteção
    para o endereço que sobrou em texto livre, como num documento da base ou numa ação promovida.
    A falha é fechada: se a resposta filtrada não cabe no contrato, ela não é entregue.
    """
    if isinstance(resultado, Proposta) and resultado.alvo_com_rotulo is not None:
        resultado = resultado.model_copy(update={"alvo": resultado.alvo_com_rotulo})
    try:
        return type(resultado).model_validate(_limpar(resultado.model_dump(mode="json")))
    except ValidationError:
        raise ValueError(
            f"a resposta do tipo {type(resultado).__name__} não pôde ser entregue à linha de decisão sem endereço: "
            "com o marcador no lugar, ela sai do contrato"
        ) from None


def _funcao_da_tool(stub, tool):
    """A função que o SDK registra como tool.

    A assinatura é montada a partir do tipo de entrada do contrato, e o retorno é o tipo de
    saída. Assim o esquema que o servidor anuncia aos clientes é o do contrato, sem uma segunda
    lista de argumentos para manter igual.
    """
    def funcao(**argumentos):
        try:
            return stub.chamar(tool.nome, **argumentos)
        except PedidoRecusado as recusa:
            # Erro de tool: o cliente recebe a mensagem como ela foi escrita, e o servidor segue no ar.
            return CallToolResult(content=[TextContent(type="text", text=recusa.mensagem)], is_error=True)
        except LogInvalido as erro:
            # O agente fica sabendo que o servidor não pode atender. O arquivo, a linha e o trecho
            # do log ficam na saída de erro, para quem opera o servidor.
            print(f"erro: {erro}", file=sys.stderr)
            return CallToolResult(content=[TextContent(type="text", text=_LOG_INVALIDO)], is_error=True)

    funcao.__name__ = tool.nome
    funcao.__signature__ = inspect.Signature(
        [
            inspect.Parameter(nome, inspect.Parameter.KEYWORD_ONLY, annotation=Annotated[campo.annotation, campo])
            for nome, campo in tool.entrada.model_fields.items()
        ],
        return_annotation=tool.saida,
    )
    return funcao


def criar_servidor(stub):
    """Monta o servidor MCP com as tools que o stub atende."""
    servidor = MCPServer("sentryiot-stub", instructions=INSTRUCOES, log_level="WARNING")
    for tool in TOOLS:
        if tool.nome in stub.permitidas:
            servidor.add_tool(_funcao_da_tool(stub, tool), name=tool.nome, description=tool.descricao)
    return servidor


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.mcp.stub",
        description="Servidor MCP de mentira do SentryIoT, com transporte stdio.",
    )
    analisador.add_argument(
        "--log", default=str(CAMINHO_PADRAO), help=f"arquivo do log de eventos (padrão: {CAMINHO_PADRAO})"
    )
    analisador.add_argument(
        "--agente", required=True, choices=(*AGENTES, TODOS),
        help=(
            "obrigatório. Com triagem, decisao ou execucao, expõe só as tools da linha desse agente e registra o "
            f"nome dele no log. Com {TODOS}, expõe todas as tools em um processo só, o que serve apenas para "
            "desenvolvimento: um mesmo cliente consegue propor e executar"
        ),
    )
    analisador.add_argument(
        "--cenarios",
        help=(
            "arquivo de cenários gravado pelo reprodutor de tráfego (codigo.reprodutor), ao lado do log. Com ele, o "
            "servidor atende os incidentes do pcap, com as janelas reais, no lugar dos quatro cenários de exemplo"
        ),
    )
    try:
        argumentos = analisador.parse_args(argv)
    except SystemExit as encerramento:
        return encerramento.code
    try:
        cenarios = ler_cenarios(argumentos.cenarios) if argumentos.cenarios else CENARIOS
        stub = Stub(Registro(argumentos.log), agente=argumentos.agente, cenarios=cenarios)
        stub.abrir_incidentes()
    except (OSError, ValueError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    # A saída padrão é o canal do protocolo: qualquer aviso vai para a saída de erro.
    print(f"stub do SentryIoT no ar (stdio); log de eventos em {argumentos.log}", file=sys.stderr)
    criar_servidor(stub).run("stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
