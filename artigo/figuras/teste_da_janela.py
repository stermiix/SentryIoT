"""Figura do teste da janela: o modelo treinado no CSV oficial depende do tamanho da janela.

Lê `experimentos/resultados/teste_da_janela.csv` e mostra, para cada uma das cinco capturas, a
fração das janelas que o modelo põe na categoria esperada com janela de 10 e de 100 quadros. Um
painel por conjunto de features (39, e 33 sem as seis colunas que dependem da janela), os dois com
a priori da amostra. A janela com que o dataset agrega a classe de cada captura vem marcada no
rótulo do eixo.

    python -m artigo.figuras.teste_da_janela
"""

import numpy as np
import pandas as pd

from artigo.figuras.estilo import CINZAS, HACHURAS, RESULTADOS, figura, porcento, salvar

ARQUIVO = RESULTADOS / "teste_da_janela.csv"
PRIORI = "amostra"


def carregar():
    tabela = pd.read_csv(ARQUIVO)
    acertos = tabela[(tabela["e_a_esperada"] == 1) & (tabela["priori"] == PRIORI)]
    return acertos.loc[:, ["captura", "rotulo", "janela", "janela_oficial", "features", "fracao"]]


def desenhar(acertos):
    capturas = list(dict.fromkeys(acertos["captura"]))
    janelas = sorted(acertos["janela"].unique())
    conjuntos = sorted(acertos["features"].unique(), reverse=True)
    oficial = acertos.drop_duplicates("captura").set_index("captura")
    rotulos = [
        f"{oficial.at[c, 'rotulo']}\n(no dataset: {oficial.at[c, 'janela_oficial']})" for c in capturas
    ]

    fig, eixos = figura(11, nrows=len(conjuntos), sharex=True)
    largura = 0.8 / len(janelas)
    posicoes = np.arange(len(capturas))
    for letra, (eixo, features) in zip("abcdefgh", zip(eixos, conjuntos)):
        parte = acertos[acertos["features"] == features]
        for i, janela in enumerate(janelas):
            fracoes = parte[parte["janela"] == janela].set_index("captura").loc[capturas, "fracao"]
            x = posicoes + (i - (len(janelas) - 1) / 2) * largura
            barras = eixo.bar(
                x, 100 * fracoes.to_numpy(), largura, color=CINZAS[i], hatch=HACHURAS[i],
                edgecolor="black", linewidth=0.6, label=f"Janela de {janela} quadros",
            )
            for barra, fracao in zip(barras, fracoes):
                # Abaixo de 1%, duas casas, para um valor pequeno não aparecer como zero.
                texto = porcento(fracao, 2 if 0 < fracao < 0.01 else 1)
                eixo.annotate(
                    texto, (barra.get_x() + barra.get_width() / 2, barra.get_height()),
                    xytext=(0, 1.5), textcoords="offset points", ha="center", va="bottom", fontsize=6.5,
                )
        sem = "" if features == max(conjuntos) else ", sem as seis colunas que dependem da janela"
        eixo.set_title(f"({letra}) Modelo com {features} features{sem}", loc="left")
        eixo.set_ylim(0, 115)
        eixo.set_yticks(range(0, 101, 25))
        eixo.set_ylabel("Janelas na categoria\nesperada (%)")
        eixo.spines[["top", "right"]].set_visible(False)
    eixos[-1].set_xticks(posicoes, rotulos)
    alcas, nomes = eixos[0].get_legend_handles_labels()
    fig.legend(alcas, nomes, loc="upper center", ncols=len(janelas), frameon=False)
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    return fig


def main():
    return salvar(desenhar(carregar()), "teste_da_janela")


if __name__ == "__main__":
    main()
