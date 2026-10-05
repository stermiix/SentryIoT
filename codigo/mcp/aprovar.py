"""Comando de terminal com que a pessoa aprova ou rejeita uma proposta de ação.

A aprovação e a rejeição não são tools: nenhum agente consegue aprovar a própria proposta.
Elas entram por este comando, que é o canal da pessoa neste trabalho. Mais adiante serão os
botões da interface web, pelo mesmo caminho: um evento gravado no log.

O comando também promove ao catálogo uma ação nova que já foi aprovada e aplicada. É outra
decisão que cabe só à pessoa.

Uso, a partir da raiz do repositório:
    python -m codigo.mcp.aprovar                        lista o que aguarda aprovação
    python -m codigo.mcp.aprovar prop-0002              aprova
    python -m codigo.mcp.aprovar prop-0002 --rejeitar --motivo "o dispositivo não pode parar"
    python -m codigo.mcp.aprovar prop-0002 --promover   leva a ação nova para o catálogo
"""
import argparse
import sys
from pathlib import Path

from codigo.mcp.acoes import PedidoRecusado, decidir, promover, reconstruir
from codigo.mcp.eventos import CAMINHO_PADRAO, Registro

_COMANDO = "python -m codigo.mcp.aprovar"


def descrever(proposta):
    """Texto com tudo o que a pessoa precisa ver antes de decidir: o que será feito, onde e por quê."""
    origem = "nova, fora do catálogo" if proposta.nova else "do catálogo"
    linhas = [
        f"{proposta.id}  incidente {proposta.incidente}  risco {proposta.risco}",
        f"  ação: {proposta.acao} ({origem})",
        f"  alvo: {proposta.alvo}",
        f"  justificativa: {proposta.justificativa}",
    ]
    parametros = dict(proposta.parametros)
    # Os campos de uma ação nova saem em ordem fixa, com os passos numerados.
    if parametros.get("descricao"):
        linhas.append(f"  descrição: {parametros.pop('descricao')}")
    passos = parametros.pop("passos", None)
    if passos:
        linhas.append("  passos:")
        linhas.extend(f"    {numero}. {passo}" for numero, passo in enumerate(passos, start=1))
    for campo, rotulo in (("efeito_esperado", "efeito esperado"), ("como_desfazer", "como desfazer"), ("fonte", "fonte")):
        valor = parametros.pop(campo, None)
        if valor:
            linhas.append(f"  {rotulo}: {valor}")
    linhas.extend(f"  {nome}: {valor}" for nome, valor in parametros.items())
    return "\n".join(linhas)


def _listar(registro):
    pendentes = [
        proposta for proposta in reconstruir(registro.ler()).propostas.values()
        if proposta.estado == "aguardando_aprovacao"
    ]
    if not pendentes:
        print("Nenhuma proposta aguarda aprovação.")
        return
    print(f"{len(pendentes)} proposta aguarda aprovação:" if len(pendentes) == 1
          else f"{len(pendentes)} propostas aguardam aprovação:")
    for proposta in pendentes:
        print()
        print(descrever(proposta))
        print(f"  para aprovar:  {_COMANDO} {proposta.id}")
        print(f"  para rejeitar: {_COMANDO} {proposta.id} --rejeitar")


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog=_COMANDO,
        description="Aprova ou rejeita uma proposta de ação. Sem proposta, lista as que aguardam aprovação.",
    )
    analisador.add_argument("proposta", nargs="?", help="identificador da proposta, como prop-0002")
    escolha = analisador.add_mutually_exclusive_group()
    escolha.add_argument("--rejeitar", action="store_true", help="rejeita a proposta, em vez de aprovar")
    escolha.add_argument(
        "--promover", action="store_true", help="promove ao catálogo a ação nova já aprovada e aplicada"
    )
    analisador.add_argument("--motivo", help="motivo da decisão, que fica registrado no log")
    analisador.add_argument(
        "--log", default=str(CAMINHO_PADRAO), help=f"arquivo do log de eventos (padrão: {CAMINHO_PADRAO})"
    )
    try:
        argumentos = analisador.parse_args(argv)
        if argumentos.proposta is None and (argumentos.rejeitar or argumentos.promover or argumentos.motivo):
            analisador.error("diga a proposta, como prop-0002")
    except SystemExit as encerramento:
        return encerramento.code
    try:
        # Sem esta conferência, um caminho errado criaria um log vazio em vez de avisar.
        if not Path(argumentos.log).is_file():
            raise ValueError(f"log de eventos não encontrado: {argumentos.log}")
        registro = Registro(argumentos.log)
        if argumentos.proposta is None:
            _listar(registro)
        elif argumentos.promover:
            acao, _ = registro.atualizar(lambda eventos: promover(reconstruir(eventos), argumentos.proposta))
            print(f"{acao.nome} promovida ao catálogo de ações.")
        else:
            proposta, _ = registro.atualizar(
                lambda eventos: decidir(
                    reconstruir(eventos), argumentos.proposta, not argumentos.rejeitar, motivo=argumentos.motivo
                )
            )
            print(descrever(proposta))
            if argumentos.rejeitar:
                print(f"{proposta.id} rejeitada. A ação não será aplicada.")
            else:
                print(f"{proposta.id} aprovada. O agente de execução já pode aplicar a ação.")
    except (PedidoRecusado, OSError, ValueError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
