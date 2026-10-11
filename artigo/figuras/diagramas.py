"""Exporta os diagramas Mermaid de artigo/figuras/ em PNG (300 dpi) e PDF.

Usa o mermaid-cli pelo npx, com a versão fixada abaixo, e por isso precisa do Node.js. Na
primeira execução o npx baixa o mermaid-cli e o navegador que ele usa para desenhar.

    python -m artigo.figuras.diagramas                 # todos os .mmd da pasta
    python -m artigo.figuras.diagramas arquitetura     # só um
"""

import shutil
import subprocess
import sys

from PIL import Image

from artigo.figuras.estilo import DPI, PASTA, RAIZ

MERMAID_CLI = "@mermaid-js/mermaid-cli@11.17.0"
# O mermaid-cli desenha a 96 pixels por polegada; esta escala leva o PNG a 300.
ESCALA = DPI / 96


def mmdc(entrada, saida, *opcoes):
    comando = ["npx", "--yes", "-p", MERMAID_CLI, "mmdc", "-i", str(entrada), "-o", str(saida),
               "-b", "white", *opcoes]
    subprocess.run(comando, check=True, cwd=RAIZ, stdout=subprocess.DEVNULL)


def exportar(nome):
    fonte = PASTA / f"{nome}.mmd"
    png, pdf = PASTA / f"{nome}.png", PASTA / f"{nome}.pdf"
    mmdc(fonte, png, "-s", f"{ESCALA:g}")
    # Grava a resolução no PNG, para o editor de texto abrir a figura no tamanho certo.
    with Image.open(png) as imagem:
        imagem.load()
    imagem.save(png, dpi=(DPI, DPI))
    mmdc(fonte, pdf, "--pdfFit")
    for caminho in (png, pdf):
        print(caminho.relative_to(RAIZ))


def main(nomes=None):
    if shutil.which("npx") is None:
        sys.exit("O npx não foi encontrado: instale o Node.js para exportar os diagramas.")
    nomes = nomes or sorted(caminho.stem for caminho in PASTA.glob("*.mmd"))
    for nome in nomes:
        exportar(nome)


if __name__ == "__main__":
    main(sys.argv[1:])
