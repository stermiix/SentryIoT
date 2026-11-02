"""Cliente do provedor de LLM, pela API compatível com OpenAI, só com a biblioteca padrão.

O orquestrador dos agentes vai reaproveitar este módulo: ele não sabe nada de HTTP do servidor
da interface, só monta a chamada a `chat/completions`, lê a resposta e traduz as falhas.
"""

import json
import math
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

TAMANHO_DA_MENSAGEM_DE_ERRO = 500
PAPEIS = {"usuario": "user", "assistente": "assistant"}
# Uma falha passageira (conexão caída ou recusada, prazo estourado, gateway sem o modelo atrás dele)
# é tentada de novo depois de cada uma destas esperas, em segundos; a última falha sobe como erro. No
# teste de 31/10, um "Connection reset by peer" perdeu uma rodada inteira dos agentes.
ESPERAS_ENTRE_TENTATIVAS_S = (3, 6)
CODIGOS_PASSAGEIROS = frozenset({502, 503, 504})


@dataclass(frozen=True)
class RespostaDoProvedor:
    conteudo: str
    modelo: str
    tokens_entrada: int | None
    tokens_saida: int | None


@dataclass(frozen=True)
class PedidoDeTool:
    """Uma chamada de tool que o modelo pediu. `argumentos` é o texto JSON, como o modelo o escreveu."""

    id: str
    nome: str
    argumentos: str


@dataclass(frozen=True)
class RespostaDaConversa:
    """Uma rodada com tools. `mensagem` é a do assistente, no formato da API, pronta para voltar ao histórico."""

    mensagem: dict
    conteudo: str
    pedidos: tuple[PedidoDeTool, ...]
    modelo: str
    tokens_entrada: int | None
    tokens_saida: int | None
    motivo_termino: str | None = None


class ErroDoProvedor(Exception):
    """O provedor recusou ou não respondeu. `codigo` é o status HTTP dele, ou nulo sem resposta.

    `passageiro` diz se a falha costuma passar sozinha, como uma conexão que caiu. A falha passageira
    que chega a quem chamou já esgotou as novas tentativas.
    """

    def __init__(self, mensagem, codigo=None, passageiro=False):
        super().__init__(mensagem)
        self.mensagem = mensagem
        self.codigo = codigo
        self.passageiro = passageiro


class Provedor:
    def __init__(self, config, abrir=urllib.request.urlopen, esperar=time.sleep, esperas_s=None):
        self.config = config
        self._abrir = abrir
        self._esperar = esperar
        # Lido aqui, e não na assinatura, para o teste que sobe o comando inteiro poder zerar as esperas.
        self._esperas_s = ESPERAS_ENTRE_TENTATIVAS_S if esperas_s is None else tuple(esperas_s)
        self._contexto = ssl.create_default_context(cafile=config.ca) if config.ca else None

    def chat(self, modelo, sistema, mensagens):
        """Uma rodada de `chat/completions`, sem streaming.

        `mensagens` vem no formato da interface (`papel` em português); o prompt de sistema, se
        houver, vai na frente como mensagem de sistema.
        """
        conversa = [{"role": "system", "content": sistema}] if sistema else []
        conversa += [{"role": PAPEIS[m["papel"]], "content": m["conteudo"]} for m in mensagens]
        corpo = {"model": modelo, "messages": conversa, "stream": False, **self.config.parametros()}
        resposta = self._pedir("/chat/completions", corpo)
        mensagem = _primeira_mensagem(resposta)
        uso = _uso(resposta)
        return RespostaDoProvedor(
            conteudo=mensagem.get("content") or "",
            modelo=resposta.get("model") or modelo,
            tokens_entrada=_inteiro(uso.get("prompt_tokens")),
            tokens_saida=_inteiro(uso.get("completion_tokens")),
        )

    def conversar(self, modelo, mensagens, tools=None):
        """Uma rodada de `chat/completions` com as mensagens no formato da API e tools opcionais.

        É o que o laço dos agentes usa. `mensagens` já vem com `role` em inglês e, depois de uma
        chamada de tool, com as mensagens `tool`; `tools` está no formato de `tools` da API. A resposta
        traz o que o modelo pediu para chamar, e `mensagem` para pôr no histórico: só `role`,
        `content` e `tool_calls`, sem o raciocínio que alguns servidores devolvem junto.
        """
        corpo = {"model": modelo, "messages": list(mensagens), "stream": False, **self.config.parametros()}
        if tools:
            corpo["tools"] = list(tools)
        resposta = self._pedir("/chat/completions", corpo)
        mensagem = _primeira_mensagem(resposta)
        conteudo = mensagem.get("content")
        conteudo = conteudo if isinstance(conteudo, str) else ""
        pedidos = _pedidos(mensagem)
        historico = {"role": "assistant", "content": conteudo}
        if pedidos:
            historico["tool_calls"] = [
                {"id": p.id, "type": "function", "function": {"name": p.nome, "arguments": p.argumentos}}
                for p in pedidos
            ]
        uso = _uso(resposta)
        return RespostaDaConversa(
            mensagem=historico,
            conteudo=conteudo,
            pedidos=pedidos,
            modelo=resposta.get("model") or modelo,
            tokens_entrada=_inteiro(uso.get("prompt_tokens")),
            tokens_saida=_inteiro(uso.get("completion_tokens")),
            motivo_termino=resposta["choices"][0].get("finish_reason"),
        )

    def _pedir(self, caminho, corpo):
        dados = json.dumps(corpo).encode("utf-8")
        cabecalhos = {"Content-Type": "application/json", "Authorization": f"Bearer {self.config.chave}"}
        pedido = urllib.request.Request(self.config.url_base + caminho, data=dados, headers=cabecalhos)
        # Só a falha passageira volta a ser tentada. Recusa do provedor (4xx), resposta que não é JSON
        # e content_filter, que chega numa resposta normal, não mudariam com outra tentativa.
        for espera in (*self._esperas_s, None):
            try:
                bruto = self._enviar(pedido)
                break
            except ErroDoProvedor as erro:
                if not erro.passageiro or espera is None:
                    raise
            self._esperar(espera)
        try:
            return json.loads(bruto.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as erro:
            raise ErroDoProvedor("o provedor respondeu algo que não é JSON") from erro

    def _enviar(self, pedido):
        try:
            with self._abrir(pedido, timeout=self.config.prazo_s, context=self._contexto) as resposta:
                return resposta.read()
        except urllib.error.HTTPError as erro:
            detalhe = erro.read().decode("utf-8", "replace")[:TAMANHO_DA_MENSAGEM_DE_ERRO]
            passageiro = erro.code in CODIGOS_PASSAGEIROS
            raise ErroDoProvedor(detalhe or erro.reason, codigo=erro.code, passageiro=passageiro) from erro
        except OSError as erro:
            # Na abertura da conexão, o estouro do prazo chega embrulhado num URLError.
            motivo = getattr(erro, "reason", erro)
            if isinstance(erro, TimeoutError) or isinstance(motivo, TimeoutError):
                mensagem = f"prazo de {self.config.prazo_s:g} s estourado esperando o provedor"
                raise ErroDoProvedor(mensagem, passageiro=True) from erro
            # Conexão recusada, caída ou fechada no meio da resposta; nome que não resolve, não.
            passageiro = isinstance(motivo, ConnectionError)
            raise ErroDoProvedor(f"falha ao falar com o provedor: {motivo}", passageiro=passageiro) from erro


def _inteiro(valor):
    if isinstance(valor, bool) or not isinstance(valor, int | float):
        return None
    if isinstance(valor, float) and (not math.isfinite(valor) or not valor.is_integer()):
        return None
    return int(valor) if valor >= 0 else None


def _uso(resposta):
    uso = resposta.get("usage")
    return uso if isinstance(uso, dict) else {}


def _primeira_mensagem(resposta):
    try:
        mensagem = resposta["choices"][0]["message"]
    except (KeyError, IndexError, TypeError) as erro:
        raise ErroDoProvedor("resposta do provedor sem o campo choices[0].message") from erro
    if not isinstance(mensagem, dict):
        raise ErroDoProvedor("resposta do provedor com choices[0].message que não é um objeto")
    return mensagem


def _pedidos(mensagem):
    """As chamadas de tool da mensagem do assistente, com os argumentos ainda em texto."""
    itens = mensagem.get("tool_calls")
    if itens is None:
        return ()
    if not isinstance(itens, list):
        raise ErroDoProvedor("resposta do provedor com tool_calls que não é uma lista")
    pedidos = []
    identificadores = set()
    for posicao, item in enumerate(itens, start=1):
        pedido = _pedido_de_tool(item, posicao)
        if pedido.id in identificadores:
            raise ErroDoProvedor(f"resposta do provedor com tool_call {posicao} sem id único")
        identificadores.add(pedido.id)
        pedidos.append(pedido)
    return tuple(pedidos)


def _pedido_de_tool(item, posicao):
    funcao = item.get("function") if isinstance(item, dict) else None
    nome = funcao.get("name") if isinstance(funcao, dict) else None
    if not isinstance(nome, str) or not nome.strip():
        raise ErroDoProvedor(f"resposta do provedor com tool_call {posicao} sem o nome da tool")
    # Alguns servidores compatíveis omitem o `type`; um tipo diferente de function é recusado.
    if item.get("type", "function") != "function":
        raise ErroDoProvedor(f"resposta do provedor com tool_call {posicao} que não é function")
    argumentos = funcao.get("arguments")
    if isinstance(argumentos, dict):
        # Alguns servidores mandam o objeto em vez do texto JSON.
        argumentos = json.dumps(argumentos, ensure_ascii=False)
    elif not isinstance(argumentos, str):
        # Sem argumentos válidos, a tool não é executada: o laço devolve o erro ao modelo, que corrige.
        argumentos = ""
    identificador = item.get("id")
    if not isinstance(identificador, str) or not identificador.strip():
        raise ErroDoProvedor(f"resposta do provedor com tool_call {posicao} sem id único")
    return PedidoDeTool(id=identificador, nome=nome, argumentos=argumentos)
