"""Servidor MCP de mentira (stub) do SentryIoT.

Responde às nove tools do contrato com os incidentes de `cenarios.py`, sem classificador
treinado e sem rede. Serve para a frente dos agentes trabalhar em paralelo: quem escreve as
skills chama as tools, percorre um incidente do começo ao fim e obtém o log de eventos que a
interface web vai ler.

O servidor não guarda estado na memória. A cada chamada ele lê o log, decide e grava o que
aconteceu. Por isso o comando de aprovação, que é outro processo, vale na chamada seguinte, e
cada agente pode ter o seu próprio processo sobre o mesmo log.

Uso, a partir da raiz do repositório (transporte stdio):
    python -m codigo.mcp.stub
    python -m codigo.mcp.stub --agente triagem
    python -m codigo.mcp.stub --log outro/caminho.jsonl
"""
import argparse
import inspect
import sys
from typing import Annotated

from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, TextContent
from pydantic import ValidationError

from codigo.mcp import acoes
from codigo.mcp.acoes import PedidoRecusado, carregar_politica, reconstruir
from codigo.mcp.base import carregar, mitigacoes, pesquisar
from codigo.mcp.cenarios import CENARIOS, efeito, evoluir, janelas
from codigo.mcp.eventos import CAMINHO_PADRAO, Registro, novo
from codigo.mcp.tipos import (
    AGENTES,
    LIMITE_DE_JANELAS,
    TOOLS,
    ChamadaDeTool,
    Efeito,
    FatiaDeJanelas,
    Mitigacoes,
    Recusa,
    Solucoes,
    tools_do_agente,
)

INSTRUCOES = (
    "Servidor de mentira (stub) do SentryIoT. Responde com incidentes de exemplo, de números ilustrativos, "
    "e aplica as ações só em um ambiente simulado. Os incidentes são inc-0001 (flood), inc-0002 (força "
    "bruta), inc-0003 (varredura de portas) e inc-0004. Ação de risco alto e ação nova, fora do catálogo, "
    "só são executadas depois que uma pessoa aprova."
)
_TOOLS = {tool.nome: tool for tool in TOOLS}
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
    "obter_janelas": lambda r: {"janelas": len(r.janelas), "total": r.total},
    "consultar_mitigacoes": lambda r: {"mitigacoes": len(r.mitigacoes), "acoes": len(r.acoes)},
    "pesquisar_solucoes": lambda r: {"trechos": [f"{trecho.origem}: {trecho.titulo}" for trecho in r.trechos]},
    "propor_acao": lambda r: {"proposta": r.id, "risco": r.risco, "exige_aprovacao": r.exige_aprovacao},
    "verificar_efeito": lambda r: {"resultado": r.resultado},
    "executar_acao": lambda r: {"execucao": r.id, "estado": r.estado},
    "desfazer_acao": lambda r: {"execucao": r.id, "estado": r.estado},
    "consultar_estado": lambda r: {grupo: len(medidas) for grupo, medidas in r},
}


class Stub:
    """As nove tools, respondidas com os cenários e registradas no log de eventos.

    Com `agente`, o stub atende só as tools da linha desse agente e registra o nome dele em
    cada chamada. Sem agente, atende todas.
    """

    def __init__(self, registro=None, agente=None, cenarios=CENARIOS, politica=None, secoes=None):
        self.registro = registro if registro is not None else Registro()
        self.agente = agente
        self._permitidas = tools_do_agente(agente)
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

        def decidir(eventos):
            estado = reconstruir(eventos)
            incidente = self._incidente_da_chamada(estado, argumentos)
            try:
                resultado, rascunhos = self._atender(nome, estado, argumentos, inicio)
            except PedidoRecusado as recusa:
                dados = Recusa(
                    agente=self.agente, tool=nome, argumentos=argumentos, motivo=recusa.motivo,
                    mensagem=recusa.mensagem,
                )
                return recusa, [novo("recusa", dados, incidente)]
            duracao = (self.registro.relogio() - inicio).total_seconds() * 1000
            chamada = ChamadaDeTool(
                agente=self.agente, nome=nome, argumentos=argumentos, resultado=_RESUMOS[nome](resultado),
                duracao_ms=round(duracao, 3),
            )
            return resultado, [novo("tool_chamada", chamada, incidente), *rascunhos]

        resultado, _ = self.registro.atualizar(decidir)
        if isinstance(resultado, PedidoRecusado):
            raise resultado
        return resultado

    def _atender(self, nome, estado, argumentos, inicio):
        if nome not in self._permitidas:
            raise PedidoRecusado(
                "tool_fora_da_linha",
                f"A tool {nome} não faz parte da linha do agente de {self.agente}, que só enxerga: "
                f"{', '.join(self._permitidas)}.",
            )
        try:
            entrada = _TOOLS[nome].entrada.model_validate(argumentos)
        except ValidationError as erro:
            campos = sorted({".".join(str(parte) for parte in defeito["loc"]) for defeito in erro.errors()})
            raise PedidoRecusado(
                "argumentos_invalidos",
                f"Argumentos fora do contrato de {nome}. Confira: {', '.join(campos)}.",
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
                "identificador_desconhecido", f"Não existe incidente com o identificador {identificador!r}."
            )
        return estado.incidentes[identificador]

    # --- as tools, uma função para cada: recebem o estado e devolvem o resultado e os eventos ---

    def _obter_incidente(self, estado, _inicio, id):
        return self._incidente(estado, id), []

    def _obter_janelas(self, estado, _inicio, id, limite):
        incidente = self._incidente(estado, id)
        fatia = janelas(self._cenarios[id], incidente, min(limite, LIMITE_DE_JANELAS))
        return FatiaDeJanelas(incidente=id, total=incidente.janelas, janelas=fatia), []

    def _consultar_mitigacoes(self, estado, _inicio, categoria):
        return Mitigacoes(
            categoria=categoria,
            mitigacoes=mitigacoes(self._secoes, categoria),
            acoes=acoes.catalogo(estado, self._politica),
        ), []

    def _pesquisar_solucoes(self, _estado, _inicio, consulta):
        return Solucoes(consulta=consulta, fonte="base_local", trechos=pesquisar(self._secoes, consulta)), []

    def _propor_acao(self, estado, _inicio, id, acao, alvo, parametros, justificativa):
        self._incidente(estado, id)
        return acoes.propor(estado, self._politica, id, acao, alvo, parametros, justificativa)

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
                "identificador_desconhecido", f"Não existe execução com o identificador {id_execucao!r}."
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
        if tool.nome in tools_do_agente(stub.agente):
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
        "--agente", choices=AGENTES, help="expõe só as tools da linha desse agente e registra o nome dele no log"
    )
    try:
        argumentos = analisador.parse_args(argv)
    except SystemExit as encerramento:
        return encerramento.code
    try:
        stub = Stub(Registro(argumentos.log), agente=argumentos.agente)
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
