"""Gráfico de análise, fora do artigo: o recall de cada pcap com o começo dele no treino e com ele
inteiro fora do treino.

Lê `experimentos/resultados/rodadas_normalizadas_pcap_fora.csv`, nas linhas do modelo do sistema
(a configuração 5 de `rodadas_normalizadas.md`, com o fundo da parte de treino como benigno). Para
cada pcap retirado nas rodadas, compara o recall no trecho de teste entre o corte por tempo (o começo
do pcap no treino) e o pcap inteiro fora do treino, com a categoria mais provável, que é o ponto
de operação do modelo do sistema, na média das sementes 42, 1 e 2. Ao lado do nome de cada pcap
vai o número de janelas de teste da semente 42. Um painel por categoria, na ordem da Tabela 1 do
artigo; o título de cada painel traz o recall da categoria com o pcap fora, somando as janelas dos
pcaps, que é a última coluna da Tabela 1.

A figura não entra no artigo nem no `python -m artigo.figuras`, e o PNG e o PDF não são
versionados: o script grava os dois em `artigo/figuras/` só quando é chamado.

    python -m artigo.figuras.pcap_fora_do_treino
"""

import pandas as pd

from artigo.figuras.estilo import CINZAS, HACHURAS, RESULTADOS, figura, porcento, salvar

ARQUIVO = RESULTADOS / "rodadas_normalizadas_pcap_fora.csv"
# Linhas do modelo do sistema no CSV das rodadas.
CONFIGURACAO = 5
CATEGORIAS = ("DDoS+DoS", "Mirai", "Recon", "Spoofing", "Web", "BruteForce")
# Valor da coluna `treino` no CSV e rótulo da série no gráfico.
SERIES = (
    ("divisão publicada", "Começo do pcap no treino (corte por tempo)"),
    ("pcap fora", "Pcap inteiro fora do treino"),
)


def milhar(numero):
    return f"{numero:,}".replace(",", ".")


def carregar():
    tabela = pd.read_csv(ARQUIVO)
    tabela = tabela[(tabela["configuracao"] == CONFIGURACAO) & (tabela["trecho"] == "teste")].copy()
    tabela["acertos"] = [linha[linha["categoria"]] for _, linha in tabela.iterrows()]
    tabela["recall"] = tabela["acertos"] / tabela["janelas"]
    por_pcap = tabela.groupby(["categoria", "arquivo", "treino"])["recall"].mean().unstack("treino")
    janelas = tabela[(tabela["semente"] == 42) & (tabela["treino"] == "pcap fora")]
    por_pcap["janelas"] = janelas.set_index(["categoria", "arquivo"])["janelas"]
    por_semente = tabela.groupby(["categoria", "treino", "semente"])[["acertos", "janelas"]].sum()
    por_categoria = (por_semente["acertos"] / por_semente["janelas"]).groupby(["categoria", "treino"]).mean()
    return por_pcap.reset_index(), por_categoria.unstack("treino")


def desenhar(por_pcap, por_categoria):
    tamanhos = [int((por_pcap["categoria"] == categoria).sum()) for categoria in CATEGORIAS]
    fig, eixos = figura(20, nrows=len(CATEGORIAS), sharex=True, gridspec_kw={"height_ratios": tamanhos})
    altura = 0.38
    for letra, categoria, eixo in zip("abcdef", CATEGORIAS, eixos):
        parte = por_pcap[por_pcap["categoria"] == categoria].sort_values("pcap fora")
        posicoes = range(len(parte))
        series = zip((altura / 2, -altura / 2), SERIES, CINZAS[::2], HACHURAS[::2])
        for deslocamento, (serie, rotulo), cinza, hachura in series:
            barras = eixo.barh(
                [p + deslocamento for p in posicoes], 100 * parte[serie], height=altura, color=cinza,
                hatch=hachura, edgecolor="black", linewidth=0.5, label=rotulo,
            )
            if serie == "pcap fora":
                for barra, recall in zip(barras, parte[serie]):
                    eixo.annotate(
                        porcento(recall), (barra.get_width(), barra.get_y() + barra.get_height() / 2),
                        xytext=(2, 0), textcoords="offset points", ha="left", va="center", fontsize=6.5,
                    )
        rotulos = [
            f"{arquivo.removesuffix('.pcap')} ({milhar(janelas)})"
            for arquivo, janelas in zip(parte["arquivo"], parte["janelas"])
        ]
        eixo.set_yticks(list(posicoes), rotulos)
        fora = por_categoria.loc[categoria, "pcap fora"]
        eixo.set_title(
            f"({letra}) {categoria}: {porcento(fora)} com o pcap fora do treino, somando as janelas", loc="left",
        )
        eixo.set_ylim(-0.6, len(parte) - 0.4)
        eixo.tick_params(axis="y", length=0, labelsize=7)
        eixo.spines[["top", "right"]].set_visible(False)
    eixos[-1].set_xlim(0, 100)
    eixos[-1].set_xlabel("Recall no trecho de teste do pcap (%); entre parênteses, as janelas de teste")
    fig.legend(*eixos[0].get_legend_handles_labels(), loc="upper center", ncol=2, frameon=False)
    fig.tight_layout(rect=(0, 0, 1, 0.97))
    return fig


def main():
    return salvar(desenhar(*carregar()), "pcap_fora_do_treino")


if __name__ == "__main__":
    main()
