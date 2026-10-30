"""O cliente MCP dos agentes: um processo do servidor por papel, falado pelo stdio.

Cada agente conversa com o servidor pela linha dele: o stub é aberto com `--agente <papel>`, que
expõe só as tools desse papel e registra o nome dele no log (ver `codigo/mcp/stub.py`). Por isso um
`ClienteMCP` é de um papel só, e a triagem, a decisão e a execução têm um cada.

O SDK do MCP é assíncrono, e o laço dos agentes (`laco.py`) e o provedor são síncronos. A ponte é
um fio próprio por cliente, que roda o servidor e atende os pedidos de uma fila: assim a sessão
inteira, da abertura ao fechamento, acontece numa tarefa só, como o SDK exige, e quem chama vê
métodos comuns. Um `ClienteMCP` aceito como `executar` no laço:

    with ClienteMCP("triagem", log) as cliente:
        resultado = rodar(provedor, modelo, abertura, cliente.tools, cliente)
"""

import asyncio
import concurrent.futures
import json
import math
import sys
import threading
from pathlib import Path

import anyio
from mcp import Client, MCPError, StdioServerParameters
from mcp.types import CONNECTION_CLOSED

from codigo.agente.laco import ResultadoDeTool
from codigo.mcp.tipos import AGENTES, tools_do_agente

RAIZ = Path(__file__).resolve().parents[2]
PRAZO_DA_ABERTURA_S = 60
PRAZO_DA_CHAMADA_S = 60
# Folga para o prazo de dentro do fio estourar primeiro e trazer a mensagem dele.
FOLGA_DO_PRAZO_S = 5


class ErroDoServidor(Exception):
    """O servidor MCP não abriu, caiu ou não respondeu no prazo. Recusa de uma tool não é isso."""


class ClienteMCP:
    def __init__(
        self,
        agente,
        log,
        cenarios=None,
        *,
        prazo_s=PRAZO_DA_CHAMADA_S,
        prazo_da_abertura_s=PRAZO_DA_ABERTURA_S,
        prazo_do_fechamento_s=15,
    ):
        if agente not in AGENTES:
            raise ValueError(f"agente desconhecido: {agente!r}. Diga {', '.join(AGENTES)}")
        for nome, prazo in (("prazo_s", prazo_s), ("prazo_da_abertura_s", prazo_da_abertura_s), ("prazo_do_fechamento_s", prazo_do_fechamento_s)):
            if isinstance(prazo, bool) or not isinstance(prazo, int | float) or not math.isfinite(prazo) or prazo <= 0:
                raise ValueError(f"{nome} precisa ser positivo e finito")
        argumentos = ["-m", "codigo.mcp.stub", "--log", str(Path(log).resolve()), "--agente", agente]
        if cenarios is not None:
            argumentos += ["--cenarios", str(Path(cenarios).resolve())]
        self.agente = agente
        self._parametros = StdioServerParameters(command=sys.executable, args=argumentos, cwd=RAIZ)
        self._prazo_s = prazo_s
        self._prazo_da_abertura_s = prazo_da_abertura_s
        self._prazo_do_fechamento_s = prazo_do_fechamento_s
        self._pronto = threading.Event()
        self._trava = threading.Lock()
        self._chamadas = threading.Lock()
        self._pendentes = set()
        self._fio = None
        self._laco = None
        self._fila = None
        self._tarefa = None
        self._tools = ()
        self._erro = None
        self._fechado = False

    def __enter__(self):
        with self._trava:
            if self._fio is not None or self._fechado:
                raise ErroDoServidor("ClienteMCP é de uso único; crie outro para abrir uma nova sessão")
            self._fio = threading.Thread(target=self._rodar, name=f"cliente-mcp-{self.agente}", daemon=True)
            self._fio.start()
        if not self._pronto.wait(self._prazo_da_abertura_s):
            self.fechar()
            raise ErroDoServidor(f"o servidor MCP do agente de {self.agente} não abriu em {self._prazo_da_abertura_s:g} s")
        if self._erro is not None:
            self.fechar()
            raise ErroDoServidor(f"o servidor MCP do agente de {self.agente} não abriu: {self._erro}") from self._erro
        if not self._fio.is_alive():
            self.fechar()
            raise ErroDoServidor("o servidor MCP encerrou durante a abertura")
        return self

    def __exit__(self, *_):
        self.fechar()

    @property
    def tools(self):
        """As tools da linha do agente, como o servidor as anuncia, no formato de `tools` da API."""
        return [
            {
                "type": "function",
                "function": {"name": tool.name, "description": tool.description or "", "parameters": tool.input_schema},
            }
            for tool in self._tools
        ]

    def __call__(self, nome, argumentos):
        return self.chamar(nome, argumentos)

    def chamar(self, nome, argumentos):
        """Chama uma tool e devolve o que o modelo vai ler. A recusa da tool vem como `erro=True`.

        Só falha com `ErroDoServidor`: quando o servidor não está mais lá, passa do prazo ou a chamada
        falha no SDK. Nesse último caso, se a conexão segue de pé, a sessão continua servindo.
        """
        # Uma chamada por vez: a espera de um segundo chamador não consome o prazo da primeira.
        with self._chamadas:
            return self._chamar(nome, argumentos)

    def _chamar(self, nome, argumentos):
        futuro = concurrent.futures.Future()
        with self._trava:
            if self._fechado or not self._pronto.is_set() or self._fio is None or not self._fio.is_alive():
                raise ErroDoServidor(f"o servidor MCP do agente de {self.agente} não está no ar")
            if nome not in {tool.name for tool in self._tools}:
                return ResultadoDeTool("ferramenta não disponibilizada a este agente", erro=True)
            if not _cabe_no_envio(argumentos):
                # O SDK falha ao serializar a mensagem e derruba a sessão inteira: nem chega ao servidor.
                return ResultadoDeTool("os argumentos precisam ser um objeto JSON válido em UTF-8", erro=True)
            self._pendentes.add(futuro)
        try:
            try:
                self._laco.call_soon_threadsafe(self._fila.put_nowait, (nome, argumentos, futuro))
            except RuntimeError as erro:
                raise ErroDoServidor(f"o servidor MCP do agente de {self.agente} já foi encerrado") from erro
            try:
                resposta = futuro.result(timeout=self._prazo_s + FOLGA_DO_PRAZO_S)
            except TimeoutError as erro:
                # A operação pode ter sido aplicada antes do timeout: não repetir automaticamente.
                # A sessão é encerrada, e o próximo passo deve conferir o log, não tentar de novo.
                self.fechar()
                raise ErroDoServidor(f"a tool {nome} passou do prazo de {self._prazo_s:g} s") from erro
            except ErroDoServidor:
                raise
            except Exception as erro:
                raise ErroDoServidor(f"falha ao chamar a tool {nome}: {erro}") from erro
        finally:
            futuro.cancel()
            with self._trava:
                self._pendentes.discard(futuro)
        return resultado_da_tool(resposta)

    def fechar(self):
        """Encerra o servidor. Pode ser chamado mais de uma vez."""
        with self._trava:
            self._fechado = True
        if self._laco is not None:
            try:
                self._laco.call_soon_threadsafe(self._cancelar)
            except RuntimeError:
                pass  # O laço de eventos já terminou.
        if self._fio is not None and self._fio.is_alive():
            self._fio.join(timeout=self._prazo_do_fechamento_s)
            if self._fio.is_alive():
                raise ErroDoServidor("o servidor MCP não encerrou no prazo; a sessão não pode ser reutilizada")

    def _cancelar(self):
        if self._tarefa is not None and not self._tarefa.done():
            self._tarefa.cancel()

    def _rodar(self):
        try:
            asyncio.run(self._servir())
        except asyncio.CancelledError:
            if not self._fechado:
                self._erro = ErroDoServidor("a sessão MCP foi cancelada inesperadamente")
        except Exception as erro:  # noqa: BLE001 - fronteira da thread; repassa a falha ao chamador síncrono
            if self._erro is None:
                self._erro = erro
        finally:
            with self._trava:
                self._fechado = True
                pendentes = list(self._pendentes)
                self._pendentes.clear()
            for futuro in pendentes:
                self._concluir(futuro, erro=_com_causa(f"o servidor MCP do agente de {self.agente} encerrou", self._erro))
            self._pronto.set()

    async def _servir(self):
        self._laco = asyncio.get_running_loop()
        self._tarefa = asyncio.current_task()
        self._fila = asyncio.Queue()
        if self._fechado:
            return
        # timeout na mesma tarefa: mover __aenter__ para wait_for quebraria os cancel scopes do SDK.
        async with asyncio.timeout(self._prazo_da_abertura_s) as abertura, Client(self._parametros) as cliente:
            self._tools = tuple((await cliente.list_tools()).tools)
            if any(tool.name not in tools_do_agente(self.agente) for tool in self._tools):
                raise ErroDoServidor("o servidor anunciou tool fora do papel do agente")
            abertura.reschedule(None)
            self._pronto.set()
            while True:
                nome, argumentos, futuro = await self._fila.get()
                if futuro.done():
                    continue
                try:
                    resposta = await asyncio.wait_for(cliente.call_tool(nome, argumentos), self._prazo_s)
                except TimeoutError:
                    self._concluir(futuro, erro=TimeoutError())
                    return
                except Exception as erro:
                    # A falha de uma chamada não encerra a sessão, a não ser que a conexão tenha caído.
                    if _conexao_caiu(erro):
                        # O servidor morreu ou o canal fechou: não há sessão para continuar servindo.
                        self._concluir(futuro, erro=_com_causa(f"a conexão com o servidor MCP caiu na tool {nome}", erro))
                        raise
                    self._concluir(futuro, erro=_com_causa(f"falha na tool {nome}", erro))
                else:
                    self._concluir(futuro, resultado=resposta)

    @staticmethod
    def _concluir(futuro, *, resultado=None, erro=None):
        try:
            if erro is not None:
                futuro.set_exception(erro)
            else:
                futuro.set_result(resultado)
        except concurrent.futures.InvalidStateError:
            pass  # O chamador já cancelou o futuro depois de um timeout.


def _cabe_no_envio(argumentos):
    try:
        json.dumps(argumentos, allow_nan=False, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        return False
    return isinstance(argumentos, dict)


def _conexao_caiu(erro):
    # Quando o processo do servidor morre, o SDK acorda a chamada com MCPError(CONNECTION_CLOSED).
    if isinstance(erro, anyio.ClosedResourceError | anyio.BrokenResourceError):
        return True
    return isinstance(erro, MCPError) and erro.code == CONNECTION_CLOSED


def _com_causa(mensagem, causa):
    """Um `ErroDoServidor` que diz por que falhou, com os erros de dentro de um grupo do AnyIO."""
    erro = ErroDoServidor(f"{mensagem}: {_descrever(causa)}" if causa is not None else mensagem)
    erro.__cause__ = causa
    return erro


def _descrever(erro):
    if isinstance(erro, BaseExceptionGroup):
        return "; ".join(_descrever(dentro) for dentro in erro.exceptions)
    return f"{type(erro).__name__}: {erro}"


def resultado_da_tool(resposta):
    """A resposta de `call_tool` do SDK como o laço a entende."""
    texto = " ".join(bloco.text for bloco in resposta.content if getattr(bloco, "text", None))
    if resposta.is_error:
        return ResultadoDeTool(texto or "a tool recusou o pedido", erro=True)
    if resposta.structured_content is not None:
        return ResultadoDeTool(json.dumps(resposta.structured_content, ensure_ascii=False, separators=(",", ":")))
    return ResultadoDeTool(texto)
