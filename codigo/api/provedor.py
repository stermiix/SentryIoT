"""Cliente do provedor de LLM, pela API compatível com OpenAI, só com a biblioteca padrão.

O orquestrador dos agentes vai reaproveitar este módulo: ele não sabe nada de HTTP do servidor
da interface, só monta a chamada a `chat/completions`, lê a resposta e traduz as falhas.
"""

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass

TAMANHO_DA_MENSAGEM_DE_ERRO = 500
PAPEIS = {"usuario": "user", "assistente": "assistant"}


@dataclass(frozen=True)
class RespostaDoProvedor:
    conteudo: str
    modelo: str
    tokens_entrada: int | None
    tokens_saida: int | None


class ErroDoProvedor(Exception):
    """O provedor recusou ou não respondeu. `codigo` é o status HTTP dele, ou nulo sem resposta."""

    def __init__(self, mensagem, codigo=None):
        super().__init__(mensagem)
        self.mensagem = mensagem
        self.codigo = codigo


class Provedor:
    def __init__(self, config, abrir=urllib.request.urlopen):
        self.config = config
        self._abrir = abrir
        self._contexto = ssl.create_default_context(cafile=config.ca) if config.ca else None

    def chat(self, modelo, sistema, mensagens):
        """Uma rodada de `chat/completions`, sem streaming.

        `mensagens` vem no formato da interface (`papel` em português); o prompt de sistema, se
        houver, vai na frente como mensagem de sistema.
        """
        conversa = [{"role": "system", "content": sistema}] if sistema else []
        conversa += [{"role": PAPEIS[m["papel"]], "content": m["conteudo"]} for m in mensagens]
        corpo = {"model": modelo, "messages": conversa, "stream": False}
        resposta = self._pedir("/chat/completions", corpo)
        try:
            mensagem = resposta["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as erro:
            raise ErroDoProvedor("resposta do provedor sem o campo choices[0].message") from erro
        uso = resposta.get("usage") or {}
        return RespostaDoProvedor(
            conteudo=mensagem.get("content") or "",
            modelo=resposta.get("model") or modelo,
            tokens_entrada=_inteiro(uso.get("prompt_tokens")),
            tokens_saida=_inteiro(uso.get("completion_tokens")),
        )

    def _pedir(self, caminho, corpo):
        dados = json.dumps(corpo).encode("utf-8")
        cabecalhos = {"Content-Type": "application/json", "Authorization": f"Bearer {self.config.chave}"}
        pedido = urllib.request.Request(self.config.url_base + caminho, data=dados, headers=cabecalhos)
        try:
            with self._abrir(pedido, timeout=self.config.prazo_s, context=self._contexto) as resposta:
                bruto = resposta.read()
        except urllib.error.HTTPError as erro:
            detalhe = erro.read().decode("utf-8", "replace")[:TAMANHO_DA_MENSAGEM_DE_ERRO]
            raise ErroDoProvedor(detalhe or erro.reason, codigo=erro.code) from erro
        except (urllib.error.URLError, OSError) as erro:
            # Na abertura da conexão, o estouro do prazo chega embrulhado num URLError.
            motivo = getattr(erro, "reason", erro)
            if isinstance(erro, TimeoutError) or isinstance(motivo, TimeoutError):
                raise ErroDoProvedor(f"prazo de {self.config.prazo_s:g} s estourado esperando o provedor") from erro
            raise ErroDoProvedor(f"falha ao falar com o provedor: {motivo}") from erro
        try:
            return json.loads(bruto.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as erro:
            raise ErroDoProvedor("o provedor respondeu algo que não é JSON") from erro


def _inteiro(valor):
    return int(valor) if isinstance(valor, int | float) and not isinstance(valor, bool) else None
