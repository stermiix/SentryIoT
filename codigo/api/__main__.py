"""Sobe o servidor fino da interface.

Uso, a partir da raiz do repositório, com o `.env` preenchido:

    python -m codigo.api
    python -m codigo.api --host 100.64.0.5 --port 8000     # no servidor, no endereço do Tailscale
    python -m codigo.api --env /outro/caminho/.env

O padrão escuta só na própria máquina (127.0.0.1:8000) e lê o `.env` da raiz do repositório.
"""

import argparse
import os
import sys

import uvicorn

from codigo.api.configuracao import Configuracao, carregar_env
from codigo.api.provedor import Provedor
from codigo.api.servidor import PASTA_CONSTRUIDA, RAIZ, criar_app


def main(argv=None):
    analisador = argparse.ArgumentParser(prog="python -m codigo.api", description="Servidor fino da interface do SentryIoT.")
    analisador.add_argument("--host", default="127.0.0.1", help="endereço em que escutar (padrão: só a própria máquina)")
    analisador.add_argument("--port", type=int, default=8000, help="porta (padrão: 8000)")
    analisador.add_argument("--env", default=os.path.join(RAIZ, ".env"), help="arquivo .env (padrão: o da raiz do repositório)")
    argumentos = analisador.parse_args(argv)

    carregar_env(argumentos.env)
    config = Configuracao.do_ambiente(os.environ)
    faltando = config.faltando()
    if faltando:
        print(f"aviso: faltam no ambiente {', '.join(faltando)}; /api/chat vai responder 503 até preenchê-las", file=sys.stderr)
    app = criar_app(config, Provedor(config).chat)
    if not os.path.isdir(PASTA_CONSTRUIDA):
        print("sem frontend/dist: só a API responde (no desenvolvimento, a interface vem do Vite)", file=sys.stderr)
    print(f"servidor da interface em http://{argumentos.host}:{argumentos.port}", file=sys.stderr)
    uvicorn.run(app, host=argumentos.host, port=argumentos.port, log_level="warning")


if __name__ == "__main__":
    main()
