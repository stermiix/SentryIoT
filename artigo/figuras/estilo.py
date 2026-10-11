"""Estilo comum dos gráficos do artigo.

Fonte serifada (Times New Roman, ou DejaVu Serif onde ela não existir), largura de 16 cm, tons
de cinza e hachuras para a figura ser lida em preto e branco, e saída em PNG de 300 dpi e em PDF,
lado a lado com o script que gerou a figura.
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt

RAIZ = Path(__file__).resolve().parents[2]
RESULTADOS = RAIZ / "experimentos" / "resultados"
PASTA = Path(__file__).resolve().parent

LARGURA_CM = 16
CM = 1 / 2.54
DPI = 300

# Do mais claro ao mais escuro, com hachura, para as séries continuarem distintas em preto e branco.
CINZAS = ("white", "0.55", "0.2")
HACHURAS = ("///", "", "")


def configurar():
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "Nimbus Roman", "DejaVu Serif"],
        "mathtext.fontset": "dejavuserif",
        "font.size": 9,
        "axes.titlesize": 9,
        "axes.labelsize": 9,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "legend.fontsize": 8,
        "axes.edgecolor": "black",
        "axes.linewidth": 0.6,
        "hatch.linewidth": 0.5,
        "pdf.fonttype": 42,
        "svg.fonttype": "none",
    })


def figura(altura_cm, **kwargs):
    configurar()
    return plt.subplots(figsize=(LARGURA_CM * CM, altura_cm * CM), **kwargs)


def porcento(fracao, casas=1):
    """Fração em percentual com vírgula decimal, como no texto do artigo."""
    return f"{100 * fracao:.{casas}f}".replace(".", ",") + "%"


def salvar(fig, nome):
    """Grava `nome.png` (300 dpi) e `nome.pdf` em artigo/figuras/ e devolve os dois caminhos."""
    caminhos = (PASTA / f"{nome}.png", PASTA / f"{nome}.pdf")
    fig.savefig(caminhos[0], dpi=DPI, bbox_inches="tight", metadata={"Software": None})
    # Sem data de criação, o PDF sai igual a cada execução com os mesmos dados.
    fig.savefig(caminhos[1], bbox_inches="tight", metadata={"CreationDate": None, "Creator": None})
    plt.close(fig)
    for caminho in caminhos:
        print(caminho.relative_to(RAIZ))
    return caminhos
