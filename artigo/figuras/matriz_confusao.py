"""Figura da matriz de confusão do modelo do sistema (dados regerados, janela de 100 quadros).

ATENÇÃO: o modelo final ainda não está fechado. Faltam definir a proporção das classes no treino e
rodar mais sementes (ver "Decisões em aberto" no ROADMAP.md). Quando o treino for refeito com
`python -m codigo.classificador.treinar_regerado`, que regrava
`experimentos/resultados/matrizes_confusao/regerado_janela_100.csv`, basta rodar este script de
novo. Ele não guarda nenhum número: lê tudo do CSV.

Cada linha da matriz é uma categoria real, e cada célula traz a fração das janelas de teste daquela
categoria que o modelo pôs em cada categoria prevista, com a contagem embaixo. A diagonal é o recall.

    python -m artigo.figuras.matriz_confusao
"""

import numpy as np
import pandas as pd

from artigo.figuras.estilo import RESULTADOS, figura, porcento, salvar

ARQUIVO = RESULTADOS / "matrizes_confusao" / "regerado_janela_100.csv"
# Acima desta fração a célula é escura, e o texto dela sai em branco.
CELULA_ESCURA = 0.55


def carregar():
    return pd.read_csv(ARQUIVO, index_col="classe_real")


def desenhar(matriz):
    fracoes = matriz.div(matriz.sum(axis=1), axis=0)
    fig, eixo = figura(12)
    imagem = eixo.imshow(fracoes.to_numpy(), cmap="Greys", vmin=0, vmax=1)
    for i, real in enumerate(matriz.index):
        for j, prevista in enumerate(matriz.columns):
            fracao = fracoes.at[real, prevista]
            contagem = f"{int(matriz.at[real, prevista]):,}".replace(",", ".")
            eixo.text(
                j, i, f"{porcento(fracao)}\n({contagem})", ha="center", va="center", fontsize=6.5,
                color="white" if fracao > CELULA_ESCURA else "black",
            )
    eixo.set_xticks(np.arange(len(matriz.columns)), matriz.columns, rotation=30, ha="right")
    eixo.set_yticks(np.arange(len(matriz.index)), matriz.index)
    eixo.set_xlabel("Categoria prevista")
    eixo.set_ylabel("Categoria real")
    eixo.tick_params(length=0)
    barra = fig.colorbar(imagem, ax=eixo, fraction=0.04, pad=0.02)
    barra.set_label("Fração das janelas da categoria real")
    barra.set_ticks(np.linspace(0, 1, 5), labels=[porcento(v, 0) for v in np.linspace(0, 1, 5)])
    fig.tight_layout()
    return fig


def main():
    return salvar(desenhar(carregar()), "matriz_confusao")


if __name__ == "__main__":
    main()
