"""Comando de terminal com que a pessoa aprova ou rejeita uma proposta de ação.

A aprovação e a rejeição não são tools: nenhum agente consegue aprovar a própria proposta.
Elas entram por este comando, que é o canal da pessoa neste trabalho. Mais adiante serão os
botões da interface web, pelo mesmo caminho: um evento gravado no log.

O comando também promove ao catálogo uma ação nova que já foi aprovada e aplicada. É outra
decisão que cabe só à pessoa.

Antes de aprovar ou de promover, o comando mostra a proposta inteira, com os motivos do risco
alto e todos os parâmetros, e pede confirmação. Tudo o que vem do log é escrito na tela com os caracteres não imprimíveis
escapados: o log é entrada, e uma sequência de terminal gravada nele não pode trocar o que a
pessoa lê.

Uso, a partir da raiz do repositório:
    python -m codigo.mcp.aprovar                        lista o que aguarda aprovação
    python -m codigo.mcp.aprovar prop-0002              mostra a proposta e pede confirmação para aprovar
    python -m codigo.mcp.aprovar prop-0002 --sim        aprova sem perguntar (uso não interativo)
    python -m codigo.mcp.aprovar prop-0002 --rejeitar --motivo "o dispositivo não pode parar"
    python -m codigo.mcp.aprovar prop-0002 --promover   leva a ação nova para o catálogo, com confirmação
"""
import argparse
import json
import shlex
import sys
from pathlib import Path

from codigo.mcp.acoes import BASE, PedidoRecusado, decidir, promover, reconstruir
from codigo.mcp.eventos import CAMINHO_PADRAO, Registro
from codigo.mcp.tipos import visivel

_COMANDO = "python -m codigo.mcp.aprovar"
_CONFIRMAM = ("s", "sim")


class _SemConfirmacao(Exception):
    """A pessoa não confirmou, ou não havia como perguntar."""


def descrever(proposta):
    """Texto com tudo o que a pessoa precisa ver antes de decidir: o que será feito, onde e por quê.

    Nenhum campo fica de fora, e todo valor passa por `visivel`.
    """
    if proposta.nova:
        origem = "nova, fora do catálogo"
    else:
        origem = "do catálogo" if proposta.acao in BASE else "promovida ao catálogo"
    linhas = [f"{visivel(proposta.id)}  incidente {visivel(proposta.incidente)}  risco {visivel(proposta.risco)}"]
    # Por que a proposta depende da pessoa: logo abaixo do risco, antes do que será feito.
    if proposta.motivos_de_risco_alto:
        linhas.append("  motivos do risco alto:")
        linhas.extend(
            f"    - {visivel(motivo.codigo)}: {visivel(motivo.descricao)}" for motivo in proposta.motivos_de_risco_alto
        )
    linhas += [
        f"  ação: {visivel(proposta.acao)} ({origem})",
        f"  alvo: {visivel(proposta.alvo)}",
        f"  justificativa: {visivel(proposta.justificativa)}",
    ]
    parametros = dict(proposta.parametros)
    # Os campos de uma ação nova saem em ordem fixa, com os passos numerados.
    if parametros.get("descricao"):
        linhas.append(f"  descrição: {_valor(parametros.pop('descricao'))}")
    passos = parametros.pop("passos", None)
    if isinstance(passos, list) and passos:
        linhas.append("  passos:")
        linhas.extend(f"    {numero}. {_valor(passo)}" for numero, passo in enumerate(passos, start=1))
    elif passos:
        parametros["passos"] = passos
    for campo, rotulo in (("efeito_esperado", "efeito esperado"), ("como_desfazer", "como desfazer"), ("fonte", "fonte")):
        valor = parametros.pop(campo, None)
        if valor:
            linhas.append(f"  {rotulo}: {_valor(valor)}")
    # O prazo de uma medida muda o risco dela: aparece sempre, com a unidade, inclusive quando falta.
    definicao = BASE.get(proposta.acao)
    if definicao is not None and definicao.duracao is not None:
        duracao = parametros.pop("duracao", None)
        prazo = "sem prazo, até a medida ser desfeita" if duracao is None else f"{_valor(duracao)} minutos"
        linhas.append(f"  duracao: {prazo}")
    # O que sobrar aparece como está gravado. Nenhum parâmetro fica fora da tela.
    linhas.extend(f"  {visivel(nome)}: {_valor(valor)}" for nome, valor in parametros.items())
    return "\n".join(linhas)


def _valor(valor):
    """Um valor de parâmetro como aparece na tela: texto escapado, ou JSON escapado quando não é texto."""
    if isinstance(valor, str):
        return visivel(valor)
    try:
        return visivel(json.dumps(valor, ensure_ascii=False))
    except (TypeError, ValueError):
        return visivel(repr(valor))


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
        # O identificador vem do log: vai entre aspas se tiver algo que o terminal interprete.
        identificador = shlex.quote(visivel(proposta.id))
        print()
        print(descrever(proposta))
        print(f"  para aprovar:  {_COMANDO} {identificador}")
        print(f"  para rejeitar: {_COMANDO} {identificador} --rejeitar")


def _confirmar(pergunta):
    """Pede a confirmação da pessoa. Sem terminal interativo, não há a quem perguntar."""
    if not sys.stdin.isatty():
        raise _SemConfirmacao(
            "a confirmação pede um terminal interativo. Para decidir sem a pergunta, acrescente --sim"
        )
    try:
        resposta = input(pergunta)
    except EOFError:
        resposta = ""
    if resposta.strip().casefold() not in _CONFIRMAM:
        raise _SemConfirmacao("a confirmação não foi dada")


def _decidir_com_confirmacao(registro, id_proposta, sem_perguntar, pergunta, funcao):
    """Mostra a proposta, pede a confirmação e só então grava o que `funcao(estado)` pedir.

    A proposta é lida duas vezes: para mostrar e, depois da resposta, com o arquivo travado, para
    gravar. Se entre uma e outra ela não for mais a mesma, nada é gravado: a pessoa confirmou o
    que viu.
    """
    estado = reconstruir(registro.ler())
    # O pedido que não cabe (proposta que não existe, que já foi decidida) é recusado antes da pergunta.
    funcao(estado)
    mostrada = estado.propostas[id_proposta]
    print(descrever(mostrada))
    if not sem_perguntar:
        _confirmar(pergunta(mostrada))

    def gravar(eventos):
        estado = reconstruir(eventos)
        if estado.propostas.get(id_proposta) != mostrada:
            raise _SemConfirmacao(f"a proposta {visivel(id_proposta)} mudou depois de ser mostrada. Confira de novo")
        return funcao(estado)

    return registro.atualizar(gravar)[0]


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog=_COMANDO,
        description=(
            "Aprova ou rejeita uma proposta de ação. Sem proposta, lista as que aguardam aprovação. Antes de "
            "aprovar ou de promover, mostra a proposta inteira e pede confirmação."
        ),
    )
    analisador.add_argument("proposta", nargs="?", help="identificador da proposta, como prop-0002")
    escolha = analisador.add_mutually_exclusive_group()
    escolha.add_argument("--rejeitar", action="store_true", help="rejeita a proposta, em vez de aprovar")
    escolha.add_argument(
        "--promover", action="store_true", help="promove ao catálogo a ação nova já aprovada e aplicada"
    )
    analisador.add_argument("--motivo", help="motivo da decisão, que fica registrado no log")
    analisador.add_argument(
        "--sim", action="store_true",
        help=(
            "aprova ou promove sem pedir a confirmação. É para uso não interativo, em que ninguém lê a proposta "
            "antes de a decisão ser gravada"
        ),
    )
    analisador.add_argument(
        "--log", default=str(CAMINHO_PADRAO), help=f"arquivo do log de eventos (padrão: {CAMINHO_PADRAO})"
    )
    try:
        argumentos = analisador.parse_args(argv)
        sem_proposta = argumentos.rejeitar or argumentos.promover or argumentos.motivo or argumentos.sim
        if argumentos.proposta is None and sem_proposta:
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
            acao = _decidir_com_confirmacao(
                registro, argumentos.proposta, argumentos.sim,
                lambda proposta: (
                    f"Promover {visivel(proposta.acao)} ao catálogo de ações, com os passos acima? "
                    "Digite sim para confirmar: "
                ),
                lambda estado: promover(estado, argumentos.proposta),
            )
            print(f"{visivel(acao.nome)} promovida ao catálogo de ações.")
        elif argumentos.rejeitar:
            # Rejeitar não libera nada: é gravado sem pergunta, depois de mostrar o que foi rejeitado.
            proposta, _ = registro.atualizar(
                lambda eventos: decidir(reconstruir(eventos), argumentos.proposta, False, motivo=argumentos.motivo)
            )
            print(descrever(proposta))
            print(f"{visivel(proposta.id)} rejeitada. A ação não será aplicada.")
        else:
            proposta = _decidir_com_confirmacao(
                registro, argumentos.proposta, argumentos.sim,
                lambda proposta: (
                    f"Aprovar {visivel(proposta.id)}? Com a aprovação, o agente de execução pode aplicar a ação "
                    "acima. Digite sim para confirmar: "
                ),
                lambda estado: decidir(estado, argumentos.proposta, True, motivo=argumentos.motivo),
            )
            print(f"{visivel(proposta.id)} aprovada. O agente de execução já pode aplicar a ação.")
    except _SemConfirmacao as motivo:
        print(f"erro: {motivo}. Nada foi gravado.", file=sys.stderr)
        return 1
    except (PedidoRecusado, OSError, ValueError) as erro:
        print(f"erro: {visivel(erro)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
