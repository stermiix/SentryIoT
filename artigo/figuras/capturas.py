"""Capturas das telas da interface em modo replay, sobre o log de exemplo do MCP.

Copia `codigo/mcp/exemplos/incidente_flood.jsonl` para `frontend/public/dados/` (ignorada pelo
git), sobe o servidor de desenvolvimento do frontend com `VITE_LOG_DE_EVENTOS` apontando para
ele e fotografa cada tela com o Chrome sem janela, a 1440 px de largura e resolução 2x. O replay
abre no último evento do log, e por isso a tela mostra o estado final sem nenhum clique. Precisa do
Node.js (com `npm ci` feito em `frontend/`, que o script faz se faltar) e do Chrome ou Chromium;
outro executável vai na variável `CHROME`.

    python -m artigo.figuras.capturas
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from artigo.figuras.estilo import PASTA, RAIZ

FRONTEND = RAIZ / "frontend"
LOG = RAIZ / "codigo" / "mcp" / "exemplos" / "incidente_flood.jsonl"
PORTA = 5180
LARGURA = 1440
ESCALA = 2
# Nome do arquivo, âncora da tela e altura da janela em pixels.
TELAS = (
    ("interface_fila", "#/visao-geral", 1220),
    ("interface_detalhe", "#/incidentes/inc-0001", 900),
)
CANDIDATOS = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome",
    "chromium",
    "chromium-browser",
)


def chrome():
    for candidato in (os.environ.get("CHROME"), *CANDIDATOS):
        if candidato and (Path(candidato).exists() or shutil.which(candidato)):
            return candidato
    sys.exit("O Chrome não foi encontrado: instale o Chrome ou o Chromium, ou aponte a variável CHROME para ele.")


def esperar(url, segundos=60):
    limite = time.monotonic() + segundos
    while time.monotonic() < limite:
        try:
            with urllib.request.urlopen(url, timeout=2):
                return
        except OSError:
            time.sleep(0.5)
    sys.exit(f"O servidor do frontend não respondeu em {url}.")


def fotografar(navegador, url, destino, altura, perfil):
    comando = [
        navegador, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
        f"--user-data-dir={perfil}", f"--window-size={LARGURA},{altura}",
        f"--force-device-scale-factor={ESCALA}", "--virtual-time-budget=8000", f"--screenshot={destino}", url,
    ]
    subprocess.run(comando, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    if shutil.which("npx") is None:
        sys.exit("O npx não foi encontrado: instale o Node.js para subir o frontend.")
    navegador = chrome()
    if not (FRONTEND / "node_modules").exists():
        subprocess.run(["npm", "ci"], check=True, cwd=FRONTEND)
    dados = FRONTEND / "public" / "dados"
    dados.mkdir(parents=True, exist_ok=True)
    shutil.copy(LOG, dados / LOG.name)
    ambiente = {**os.environ, "VITE_LOG_DE_EVENTOS": f"/dados/{LOG.name}"}
    servidor = subprocess.Popen(
        ["npx", "vite", "--port", str(PORTA), "--strictPort"], cwd=FRONTEND, env=ambiente,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        base = f"http://localhost:{PORTA}/"
        esperar(base)
        with tempfile.TemporaryDirectory() as perfil:
            for nome, ancora, altura in TELAS:
                destino = PASTA / f"{nome}.png"
                fotografar(navegador, base + ancora, destino, altura, perfil)
                print(destino.relative_to(RAIZ))
    finally:
        servidor.terminate()
        servidor.wait(timeout=10)


if __name__ == "__main__":
    main()
