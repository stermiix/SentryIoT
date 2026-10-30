"""Regera as figuras que o artigo em LaTeX inclui: os três gráficos e os dois diagramas.

    python -m artigo.figuras                        # tudo
    python -m artigo.figuras graficos diagramas     # só as partes pedidas

Os gráficos precisam do `requirements-figuras.txt`; os diagramas, do Node.js (ver `diagramas.py`).
O gráfico de análise `pcap_fora_do_treino.py` fica de fora, porque não está no artigo.
"""

import sys

from artigo.figuras import (
    diagramas,
    janelas_sem_atacante,
    matriz_confusao,
    teste_da_janela,
)

GRAFICOS = (matriz_confusao, teste_da_janela, janelas_sem_atacante)
DIAGRAMAS = ("arquitetura", "fluxo_incidente")


def graficos():
    for grafico in GRAFICOS:
        grafico.main()


PARTES = {
    "graficos": graficos,
    "diagramas": lambda: diagramas.main(list(DIAGRAMAS)),
}


def main(pedidas=None):
    pedidas = pedidas or list(PARTES)
    desconhecidas = [parte for parte in pedidas if parte not in PARTES]
    if desconhecidas:
        sys.exit(f"Parte desconhecida: {', '.join(desconhecidas)}. Use {', '.join(PARTES)}.")
    for parte in pedidas:
        PARTES[parte]()


if __name__ == "__main__":
    main(sys.argv[1:])
