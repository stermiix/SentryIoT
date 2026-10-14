"""O servidor fino da interface: as rotas sob `/api`, em Starlette.

`criar_app` recebe a configuração e a função que fala com o provedor, para os testes trocarem o
provedor por um de mentira. A chamada ao provedor roda fora do laço de eventos, porque uma
resposta lenta não pode travar as outras rotas.
"""

import logging
import time

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from codigo.api.provedor import PAPEIS, ErroDoProvedor

log = logging.getLogger(__name__)


class PedidoInvalido(Exception):
    def __init__(self, mensagem):
        super().__init__(mensagem)
        self.mensagem = mensagem


def _campo_de_texto(corpo, campo, obrigatorio=True):
    valor = corpo.get(campo, "" if not obrigatorio else None)
    if valor is None:
        raise PedidoInvalido(f"falta o campo {campo}")
    if not isinstance(valor, str):
        raise PedidoInvalido(f"o campo {campo} precisa ser texto")
    return valor


def _ler_pedido_de_chat(corpo):
    """Confere a forma do corpo de `/api/chat`. Os limites de tamanho ficam para outra etapa."""
    if not isinstance(corpo, dict):
        raise PedidoInvalido("o corpo precisa ser um objeto JSON")
    modelo = _campo_de_texto(corpo, "modelo", obrigatorio=False)
    sistema = _campo_de_texto(corpo, "sistema", obrigatorio=False)
    mensagens = corpo.get("mensagens")
    if not isinstance(mensagens, list):
        raise PedidoInvalido("o campo mensagens precisa ser uma lista")
    lidas = []
    for mensagem in mensagens:
        if not isinstance(mensagem, dict):
            raise PedidoInvalido("cada item de mensagens precisa ser um objeto com papel e conteudo")
        papel = _campo_de_texto(mensagem, "papel")
        if papel not in PAPEIS:
            raise PedidoInvalido("o campo papel precisa ser usuario ou assistente")
        lidas.append({"papel": papel, "conteudo": _campo_de_texto(mensagem, "conteudo")})
    return modelo, sistema, lidas


def criar_app(config, chamar_provedor):
    async def chat(request: Request):
        faltando = config.faltando()
        if faltando:
            return JSONResponse(
                {"erro": "o backend está sem configuração do provedor: faltam " + ", ".join(faltando), "faltando": faltando},
                status_code=503,
            )
        try:
            corpo = await request.json()
        except ValueError:
            return JSONResponse({"erro": "o corpo precisa ser JSON"}, status_code=400)
        try:
            modelo, sistema, mensagens = _ler_pedido_de_chat(corpo)
        except PedidoInvalido as erro:
            return JSONResponse({"erro": erro.mensagem}, status_code=400)
        modelo = modelo or config.modelo
        if modelo not in config.modelos():
            return JSONResponse({"erro": "o campo modelo precisa ser um dos permitidos: " + ", ".join(config.modelos())}, status_code=400)
        inicio = time.perf_counter()
        try:
            resposta = await run_in_threadpool(chamar_provedor, modelo, sistema, mensagens)
        except ErroDoProvedor as erro:
            return JSONResponse({"erro": erro.mensagem, "codigo": erro.codigo}, status_code=502)
        except Exception:  # o detalhe vai para o log do servidor, não para a resposta
            log.exception("falha inesperada ao chamar o provedor")
            return JSONResponse({"erro": "falha inesperada no backend ao chamar o provedor"}, status_code=500)
        return JSONResponse(
            {
                "conteudo": resposta.conteudo,
                "modelo": resposta.modelo,
                "tokens_entrada": resposta.tokens_entrada,
                "tokens_saida": resposta.tokens_saida,
                "tempo_ms": int((time.perf_counter() - inicio) * 1000),
            }
        )

    async def modelos(request: Request):
        return JSONResponse({"modelos": list(config.modelos()), "padrao": config.modelo})

    return Starlette(routes=[Route("/api/chat", chat, methods=["POST"]), Route("/api/modelos", modelos, methods=["GET"])])
