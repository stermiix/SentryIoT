"""Limiar de confiança da triagem: quantos alarmes falsos ele pega e quantos ataques ele marca.

A skill de triagem (`codigo/agente/skills/triagem-do-alerta/SKILL.md`) dá o veredito "duvidoso" ao
incidente cuja confiança do classificador fica abaixo de `LIMIAR_DA_TRIAGEM` (decisão de
25/10/2026). Este módulo mede esse limiar nos incidentes da avaliação dos 38 pcaps
(`codigo/reprodutor/avaliar.py`), sem rodar o reprodutor de novo: lê os resultados gravados.

Um incidente é verdadeiro quando o pcap não é benigno, quando alguma janela dele tem quadro de um
atacante do dataset e quando a categoria do incidente é a do pcap, com DDoS e DoS como uma família só
(`mesma_familia`). Os outros são falsos: os de pcap benigno, os sem quadro de atacante e os de
categoria trocada. O acerto da regra que separa DDoS de DoS está em `reproducao_dos_pcaps.md`.

A tabela separa os incidentes que ficam inteiros fora do trecho de teste do modelo dos que têm
janela no teste. O limiar é escolhido só com os primeiros; os do teste servem de conferência.

Uso, a partir da raiz do repositório (os resultados em dados/processed/reproducao/):
    python -m codigo.reprodutor.limiar
"""

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from codigo.classificador.mapeamento import mesma_familia
from codigo.reprodutor import avaliar

LIMIAR_DA_TRIAGEM = 0.6
LIMIARES = (0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80)
# Acima disso o falso é chamado de confiança alta no relatório: nenhum limiar razoável o pega.
CONFIANCA_ALTA = 0.8
RELATORIO = Path("experimentos") / "resultados" / "limiar_da_triagem.md"


@dataclass(frozen=True)
class Incidente:
    pcap: str
    categoria: str
    confianca: float
    janelas: int
    verdadeiro: bool
    no_teste: bool


def ler(pasta=avaliar.PASTA_DOS_RESULTADOS):
    """Os incidentes de todos os resultados da pasta, em ordem de nome do pcap."""
    arquivos = sorted(Path(pasta).glob("*.json"))
    if not arquivos:
        raise ValueError(f"nenhum resultado da avaliação em {pasta}; rode antes python -m codigo.reprodutor.avaliar")
    incidentes = []
    for arquivo in arquivos:
        resultado = json.loads(arquivo.read_text(encoding="utf-8"))
        for incidente in resultado["incidentes"]:
            verdadeiro = (
                not resultado["benigno"]
                and incidente["janelas_com_atacante"] > 0
                and mesma_familia(incidente["categoria"], resultado["categoria"])
            )
            incidentes.append(Incidente(
                resultado["arquivo"], incidente["categoria"], incidente["confianca"], incidente["janelas"],
                verdadeiro, incidente["janelas_no_teste"] > 0,
            ))
    return incidentes


def contar(incidentes, limiar):
    """Falsos pegos e verdadeiros marcados pelo limiar: (falsos abaixo, falsos, verdadeiros abaixo, verdadeiros)."""
    falsos = [i for i in incidentes if not i.verdadeiro]
    verdadeiros = [i for i in incidentes if i.verdadeiro]
    return (
        sum(i.confianca < limiar for i in falsos), len(falsos),
        sum(i.confianca < limiar for i in verdadeiros), len(verdadeiros),
    )


def escolher(incidentes, limiares=LIMIARES):
    """O menor limiar que pega o máximo de falsos sem marcar nenhum verdadeiro, só fora do teste.

    No empate vale o menor, porque marcar um ataque verdadeiro como duvidoso custa mais do que
    deixar passar um alarme falso. Sem limiar que deixe todos os verdadeiros passarem, ou sem falso
    fora do teste para pegar, devolve None.
    """
    fora = [i for i in incidentes if not i.no_teste]
    candidatos = [(contar(fora, limiar)[0], limiar) for limiar in limiares if contar(fora, limiar)[2] == 0]
    if not candidatos or all(i.verdadeiro for i in fora):
        return None
    maximo = max(pegos for pegos, _ in candidatos)
    return min(limiar for pegos, limiar in candidatos if pegos == maximo)


def _celulas(incidentes, limiar, janelas=None):
    """As duas células de um recorte: falsos pegos e verdadeiros marcados, com a condição de janelas se houver."""
    if janelas is not None:
        abaixo = [i for i in incidentes if i.janelas < janelas]
        falsos_abaixo, _, verdadeiros_abaixo, _ = contar(abaixo, limiar)
        _, falsos, _, verdadeiros = contar(incidentes, limiar)
    else:
        falsos_abaixo, falsos, verdadeiros_abaixo, verdadeiros = contar(incidentes, limiar)
    return f"{falsos_abaixo} de {falsos} | {verdadeiros_abaixo} de {verdadeiros}"


def _decimal(valor):
    return f"{valor:.2f}".replace(".", ",")


def relatorio(incidentes, pcaps_benignos=None):
    """O relatório em markdown. `pcaps_benignos` separa, entre os falsos, os de tráfego benigno."""
    fora = [i for i in incidentes if not i.no_teste]
    no_teste = [i for i in incidentes if i.no_teste]
    falsos = [i for i in incidentes if not i.verdadeiro]
    de_benigno = [i for i in falsos if pcaps_benignos is not None and i.pcap in pcaps_benignos]
    altos = [i for i in falsos if i.confianca >= CONFIANCA_ALTA]
    marcados = sorted(
        (i for i in incidentes if i.verdadeiro and i.confianca < LIMIAR_DA_TRIAGEM), key=lambda i: i.confianca
    )
    linhas = [
        "# Limiar de confiança da triagem",
        "",
        ("Gerado por `python -m codigo.reprodutor.limiar`, a partir dos resultados da avaliação dos 38 "
        "pcaps (`python -m codigo.reprodutor.avaliar`, relatório em `reproducao_dos_pcaps.md`)."),
        "",
        ("A regra testada é a da skill de triagem: o incidente com confiança do classificador abaixo do "
        "limiar recebe o veredito \"duvidoso\". Um incidente é verdadeiro quando o pcap não é benigno, "
        "quando alguma janela dele tem quadro de um atacante do dataset e quando a categoria do incidente "
        "é a do pcap, com DDoS e DoS como uma família só. Os outros são falsos."),
        "",
        (f"São {len(incidentes)} incidentes: {sum(i.verdadeiro for i in incidentes)} verdadeiros e "
        f"{len(falsos)} falsos. {len(fora)} ficam inteiros fora do trecho de teste do modelo, e "
        f"{len(no_teste)} têm janela no teste."),
    ]
    if pcaps_benignos is not None:
        linhas += [
            "",
            (f"Dos {len(falsos)} falsos, {len(de_benigno)} {'é alarme' if len(de_benigno) == 1 else 'são alarmes'} "
            "em pcap benigno e "
            f"{len(falsos) - len(de_benigno)} são incidentes de um pcap de ataque com a categoria errada. "
            "Para a triagem, os dois pedem o veredito duvidoso: no segundo caso o ataque existe, mas a "
            "categoria que guia a resposta está errada."),
        ]
    linhas += [
        "",
        ("Cada par de colunas diz quantos incidentes ficam abaixo do limiar: falsos pegos e verdadeiros "
        "marcados."),
        "",
        ("| Limiar | Falsos, todos | Verdadeiros, todos | Falsos, fora do teste | Verdadeiros, fora do teste "
        "| Falsos, no teste | Verdadeiros, no teste |"),
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for limiar in LIMIARES:
        marca = " (escolhido)" if limiar == LIMIAR_DA_TRIAGEM else ""
        linhas.append(
            f"| {_decimal(limiar)}{marca} | {_celulas(incidentes, limiar)} | {_celulas(fora, limiar)} "
            f"| {_celulas(no_teste, limiar)} |"
        )
    escolhido = escolher(incidentes)
    if escolhido == LIMIAR_DA_TRIAGEM:
        situacao = f"Com estes resultados, a regra escolhe {_decimal(escolhido)}, o limiar da skill."
    elif all(i.verdadeiro for i in fora):
        situacao = (
            f"Atenção: fora do teste não sobra incidente falso, e a regra não tem o que escolher. O "
            f"{_decimal(LIMIAR_DA_TRIAGEM)} vem da decisão de 25/10/2026, quando as trocas entre DDoS e DoS contavam "
            "como falsas, e foi mantido sem ajuste: aqui, a conferência é só a coluna do teste."
        )
    else:
        situacao = (
            f"Atenção: com estes resultados, a regra escolhe "
            f"{'nenhum limiar' if escolhido is None else _decimal(escolhido)}, e não o "
            f"{_decimal(LIMIAR_DA_TRIAGEM)} da skill."
        )
    linhas += [
        "",
        "## A escolha",
        "",
        ("O limiar é escolhido só com os incidentes fora do teste: é o menor dos limiares que pegam ali o "
        "máximo de falsos sem marcar nenhum verdadeiro. O empate é resolvido para baixo porque marcar um "
        "ataque verdadeiro como duvidoso custa mais do que deixar passar um falso, que ainda passa "
        "pelo agente de decisão e pela aprovação humana das ações de risco alto. A coluna do teste é a "
        f"conferência. {situacao}"),
        "",
        ("Exigir também poucas janelas troca falsos pegos por verdadeiros poupados. Com todos os "
        "incidentes:"),
        "",
        "| Limiar | Condição de janelas | Falsos pegos | Verdadeiros marcados |",
        "| --- | --- | --- | --- |",
    ]
    for limiar in (LIMIAR_DA_TRIAGEM, 0.65):
        for janelas in (None, 10, 5):
            condicao = "nenhuma" if janelas is None else f"menos de {janelas}"
            linhas.append(f"| {_decimal(limiar)} | {condicao} | {_celulas(incidentes, limiar, janelas)} |")
    linhas += [
        "",
        ("A skill fica sem a condição de janelas: ela poupa poucos verdadeiros e deixa passar boa parte dos "
        "falsos que o limiar pegaria."),
        "",
        f"Verdadeiros abaixo de {_decimal(LIMIAR_DA_TRIAGEM)}, que a triagem passa a marcar como duvidosos:",
        "",
        "| Pcap | Categoria | Confiança | Janelas |",
        "| --- | --- | --- | --- |",
    ]
    linhas += [f"| `{i.pcap}` | {i.categoria} | {_decimal(i.confianca)} | {i.janelas} |" for i in marcados]
    altos_de_ataque = [i for i in altos if i not in de_benigno]
    linhas += [
        "",
        "## O que o limiar não pega",
        "",
        (f"{len(altos)} dos {len(falsos)} falsos {'tem' if len(altos) == 1 else 'têm'} confiança de "
        f"{_decimal(CONFIANCA_ALTA)} ou mais, e nenhum limiar de confiança separa esses casos dos verdadeiros sem "
        "marcar boa parte dos ataques."),
    ]
    if pcaps_benignos is not None and altos_de_ataque:
        linhas[-1] += (
            f" Desses, {len(altos_de_ataque)} são de pcap de ataque com a categoria errada, com mediana de "
            f"{_mediana([i.janelas for i in altos_de_ataque])} janelas."
        )
    linhas.append("")
    return "\n".join(linhas)


def _mediana(valores):
    if not valores:
        return 0
    ordenados = sorted(valores)
    meio = len(ordenados) // 2
    return ordenados[meio] if len(ordenados) % 2 else round((ordenados[meio - 1] + ordenados[meio]) / 2)


def benignos(pasta=avaliar.PASTA_DOS_RESULTADOS):
    """Os nomes dos pcaps benignos entre os resultados da pasta."""
    nomes = set()
    for arquivo in Path(pasta).glob("*.json"):
        resultado = json.loads(arquivo.read_text(encoding="utf-8"))
        if resultado["benigno"]:
            nomes.add(resultado["arquivo"])
    return nomes


def main(argv=None):
    analisador = argparse.ArgumentParser(prog="python -m codigo.reprodutor.limiar", description=__doc__)
    analisador.add_argument("--resultados", type=Path, default=avaliar.PASTA_DOS_RESULTADOS)
    analisador.add_argument("--relatorio", type=Path, default=RELATORIO)
    args = analisador.parse_args(argv)
    try:
        incidentes = ler(args.resultados)
    except ValueError as erro:
        print(erro, file=sys.stderr)
        return 1
    args.relatorio.write_text(relatorio(incidentes, benignos(args.resultados)), encoding="utf-8")
    print(f"relatório: {args.relatorio}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
