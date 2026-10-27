"""Regera todas as figuras do artigo: os gráficos, os diagramas e as capturas da interface.

    python -m artigo.figuras                        # tudo
    python -m artigo.figuras graficos diagramas     # só as partes pedidas

Os gráficos precisam do `requirements-figuras.txt`; os diagramas e as capturas, do Node.js; as
capturas, também do Chrome (ver `capturas.py`).
"""

import sys

from artigo.figuras import (
    capturas,
    diagramas,
    janelas_sem_atacante,
    matriz_confusao,
    pcap_fora_do_treino,
    teste_da_janela,
)

GRAFICOS = (matriz_confusao, teste_da_janela, janelas_sem_atacante, pcap_fora_do_treino)
PARTES = {
    "graficos": lambda: [grafico.main() for grafico in GRAFICOS],
    "diagramas": diagramas.main,
    "capturas": capturas.main,
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
