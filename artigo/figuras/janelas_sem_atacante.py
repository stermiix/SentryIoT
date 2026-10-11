"""Figura das janelas sem atacante: quanto do que o dataset rotula como ataque não tem o atacante.

Lê `experimentos/resultados/janelas_sem_atacante.csv` e mostra, para cada rótulo de ataque, a
fração das janelas sem nenhum quadro de um dos sete atacantes, na janela com que o dataset agrega
a classe. Um painel para as classes de janela de 10 (Recon, Spoofing, Web e BruteForce) e outro
para os floods de janela de 100 (DDoS, DoS e Mirai). O tráfego benigno fica de fora. Um rótulo com
mais de um pcap soma as janelas de todos.

    python -m artigo.figuras.janelas_sem_atacante
"""

import pandas as pd

from artigo.figuras.estilo import CINZAS, HACHURAS, RESULTADOS, figura, porcento, salvar
from codigo.classificador.experimento import JANELA_DE_100
from codigo.classificador.mapeamento import CATEGORIA_DO_ROTULO

ARQUIVO = RESULTADOS / "janelas_sem_atacante.csv"


def janela_do_dataset(rotulo):
    return 100 if CATEGORIA_DO_ROTULO[rotulo] in JANELA_DE_100 else 10


def carregar():
    tabela = pd.read_csv(ARQUIVO)
    ataques = tabela[tabela["benigno"] == 0]
    ataques = ataques[ataques["janela"] == ataques["rotulo"].map(janela_do_dataset)]
    por_rotulo = ataques.groupby(["rotulo", "janela"], as_index=False)[["janelas", "sem_atacante"]].sum()
    por_rotulo["fracao"] = por_rotulo["sem_atacante"] / por_rotulo["janelas"]
    return por_rotulo


def desenhar(por_rotulo):
    grupos = [
        (10, "(a) Classes que o dataset agrega em janelas de 10 quadros (Recon, Spoofing, Web e BruteForce)"),
        (100, "(b) Floods, que o dataset agrega em janelas de 100 quadros (DDoS, DoS e Mirai)"),
    ]
    tamanhos = [int((por_rotulo["janela"] == janela).sum()) for janela, _ in grupos]
    fig, eixos = figura(17, nrows=len(grupos), sharex=True, gridspec_kw={"height_ratios": tamanhos})
    for (janela, titulo), eixo, cinza, hachura in zip(grupos, eixos, CINZAS[1:], HACHURAS[1:]):
        parte = por_rotulo[por_rotulo["janela"] == janela].sort_values("fracao")
        barras = eixo.barh(
            parte["rotulo"], 100 * parte["fracao"], height=0.7, color=cinza, hatch=hachura,
            edgecolor="black", linewidth=0.5,
        )
        for barra, fracao in zip(barras, parte["fracao"]):
            texto = porcento(fracao, 2 if fracao < 0.01 else 1)
            eixo.annotate(
                texto, (barra.get_width(), barra.get_y() + barra.get_height() / 2),
                xytext=(2, 0), textcoords="offset points", ha="left", va="center", fontsize=6.5,
            )
        eixo.set_title(titulo, loc="left")
        eixo.set_ylim(-0.6, len(parte) - 0.4)
        eixo.tick_params(axis="y", length=0, labelsize=7)
        eixo.spines[["top", "right"]].set_visible(False)
    eixos[-1].set_xlim(0, 100)
    eixos[-1].set_xlabel("Janelas rotuladas como ataque sem nenhum quadro do atacante (%)")
    fig.tight_layout()
    return fig


def main():
    return salvar(desenhar(carregar()), "janelas_sem_atacante")


if __name__ == "__main__":
    main()
