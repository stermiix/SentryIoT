"""O servidor fino da interface: as rotas sob `/api`, em Starlette.

`criar_app` recebe a configuração e a função que fala com o provedor, para os testes trocarem o
provedor por um de mentira. A chamada ao provedor roda fora do laço de eventos, porque uma
resposta lenta não pode travar as outras rotas.
"""

import logging
import os
import tempfile
import time

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route

from codigo.api.prompts import ler_prompts
from codigo.api.provedor import PAPEIS, ErroDoProvedor
from codigo.api.simulacao import nome_do_pcap

log = logging.getLogger(__name__)
RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PASTA_DE_SKILLS = os.path.join(RAIZ, "codigo", "agente", "skills")
PASTA_CONSTRUIDA = os.path.join(RAIZ, "frontend", "dist")
# Limites conferidos antes de qualquer chamada ao provedor: protegem o custo e o próprio servidor.
LIMITE_DO_SISTEMA = 20_000  # caracteres do prompt de sistema
LIMITE_DA_MENSAGEM = 8_000  # caracteres de cada mensagem
LIMITE_DE_MENSAGENS = 40  # mensagens no histórico
LIMITE_DA_SOMA = 80_000  # caracteres de sistema e mensagens somados
# Maior pcap aceito pela simulação. O extrator lê cerca de 160 mil quadros por segundo: um pcap
# deste tamanho leva perto de um minuto.
LIMITE_DO_PCAP = 600 * 1024 * 1024


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
    """Confere a forma e os limites do corpo de `/api/chat`, antes de qualquer chamada ao provedor."""
    if not isinstance(corpo, dict):
        raise PedidoInvalido("o corpo precisa ser um objeto JSON")
    modelo = _campo_de_texto(corpo, "modelo", obrigatorio=False)
    sistema = _campo_de_texto(corpo, "sistema", obrigatorio=False)
    if len(sistema) > LIMITE_DO_SISTEMA:
        raise PedidoInvalido(f"o campo sistema passa de {LIMITE_DO_SISTEMA} caracteres")
    mensagens = corpo.get("mensagens")
    if not isinstance(mensagens, list):
        raise PedidoInvalido("o campo mensagens precisa ser uma lista")
    if not mensagens:
        raise PedidoInvalido("o campo mensagens precisa ter ao menos uma mensagem")
    if len(mensagens) > LIMITE_DE_MENSAGENS:
        raise PedidoInvalido(f"o campo mensagens passa de {LIMITE_DE_MENSAGENS} mensagens")
    lidas = []
    for mensagem in mensagens:
        if not isinstance(mensagem, dict):
            raise PedidoInvalido("cada item de mensagens precisa ser um objeto com papel e conteudo")
        papel = _campo_de_texto(mensagem, "papel")
        if papel not in PAPEIS:
            raise PedidoInvalido("o campo papel precisa ser usuario ou assistente")
        conteudo = _campo_de_texto(mensagem, "conteudo")
        if len(conteudo) > LIMITE_DA_MENSAGEM:
            raise PedidoInvalido(f"o campo conteudo passa de {LIMITE_DA_MENSAGEM} caracteres")
        lidas.append({"papel": papel, "conteudo": conteudo})
    if lidas[-1]["papel"] != "usuario":
        raise PedidoInvalido("a última mensagem precisa ser da pessoa (papel usuario)")
    if len(sistema) + sum(len(m["conteudo"]) for m in lidas) > LIMITE_DA_SOMA:
        raise PedidoInvalido(f"a soma dos textos (sistema e mensagens) passa de {LIMITE_DA_SOMA} caracteres")
    return modelo, sistema, lidas


def criar_app(
    config, chamar_provedor, pasta_de_skills=PASTA_DE_SKILLS, pasta_construida=PASTA_CONSTRUIDA, simulador=None,
    limite_do_pcap=LIMITE_DO_PCAP,
):
    """O app ASGI. Com `pasta_construida` existente, serve a interface construída fora de `/api`.

    `simulador` atende `/api/simulacao` (ver `codigo/api/simulacao.py`); sem ele, a rota responde 503.
    """
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

    async def prompts(request: Request):
        return JSONResponse({"prompts": await run_in_threadpool(ler_prompts, pasta_de_skills)})

    async def simulacao(request: Request):
        if simulador is None or not simulador.disponivel():
            return JSONResponse(
                {"erro": "a simulação está desligada: falta o modelo do sistema em modelos/rf_regerado_janela_100.joblib"},
                status_code=503,
            )
        declarado = request.headers.get("content-length", "")
        if declarado.isdigit() and int(declarado) > limite_do_pcap:
            return JSONResponse({"erro": f"o pcap passa do limite de {limite_do_pcap // (1024 * 1024)} MB"}, status_code=413)
        if not simulador.trava.acquire(blocking=False):
            return JSONResponse({"erro": "já há uma simulação em andamento; espere ela terminar"}, status_code=409)
        caminho = None
        try:
            with tempfile.NamedTemporaryFile(prefix="simulacao-", suffix=".pcap", delete=False) as arquivo:
                caminho = arquivo.name
                recebidos = 0
                async for pedaco in request.stream():
                    recebidos += len(pedaco)
                    if recebidos > limite_do_pcap:
                        return JSONResponse(
                            {"erro": f"o pcap passa do limite de {limite_do_pcap // (1024 * 1024)} MB"}, status_code=413,
                        )
                    arquivo.write(pedaco)
            if not recebidos:
                return JSONResponse({"erro": "o corpo veio vazio: envie o pcap"}, status_code=400)
            nome = nome_do_pcap(request.query_params.get("nome"))
            try:
                resultado = await run_in_threadpool(simulador.simular, caminho, nome)
            except ValueError as erro:  # pcapng, arquivo que não é pcap, enlace que não é Ethernet
                return JSONResponse({"erro": str(erro)}, status_code=400)
            except Exception:  # o detalhe vai para o log do servidor, não para a resposta
                log.exception("falha inesperada na simulação")
                return JSONResponse({"erro": "falha inesperada no backend ao processar o pcap"}, status_code=500)
            return JSONResponse(resultado)
        finally:
            if caminho is not None and os.path.exists(caminho):
                os.remove(caminho)
            simulador.trava.release()

    async def api_desconhecida(request: Request):
        return JSONResponse({"erro": "rota desconhecida"}, status_code=404)

    rotas = [
        Route("/api/chat", chat, methods=["POST"]),
        Route("/api/modelos", modelos, methods=["GET"]),
        Route("/api/prompts", prompts, methods=["GET"]),
        Route("/api/simulacao", simulacao, methods=["POST"]),
        Route("/api", api_desconhecida, methods=["GET", "POST", "PUT", "PATCH", "DELETE"]),
        Route("/api/{resto:path}", api_desconhecida, methods=["GET", "POST", "PUT", "PATCH", "DELETE"]),
    ]

    raiz = os.path.realpath(pasta_construida)
    if os.path.isdir(raiz):
        index = os.path.join(raiz, "index.html")

        async def arquivo(request: Request):
            # Só o que está dentro da pasta construída é servido; qualquer outro caminho recebe o
            # index.html, e a interface decide pela âncora o que mostrar.
            alvo = os.path.realpath(os.path.join(raiz, request.path_params.get("caminho", "")))
            if alvo.startswith(raiz + os.sep) and os.path.isfile(alvo):
                return FileResponse(alvo)
            return FileResponse(index, media_type="text/html")

        rotas.append(Route("/{caminho:path}", arquivo, methods=["GET"]))

    return Starlette(routes=rotas)
