"""Roda o orquestrador num incidente já aberto no log.

Uso, a partir da raiz do repositório, com o `.env` preenchido:

    python -m codigo.agente --incidente inc-0001 --log dados/eventos/x.jsonl --configuracao hibrida
    python -m codigo.agente --incidente inc-0001 --log x.jsonl --cenarios y.jsonl --configuracao local

O log é o do reprodutor (ou do stub), e `--cenarios` é o mesmo arquivo que o servidor MCP lê em modo de
reprodução. O `.env` traz o modelo local (`LLM_*`) e o da nuvem (`LLM_NUVEM_*`); a configuração `local` só
precisa do primeiro, a `nuvem` só do segundo, e a `hibrida` dos dois.

Se uma proposta de risco alto aguardar aprovação, o comando espera que uma pessoa decida, em outro
terminal, com `python -m codigo.mcp.aprovar --log <o mesmo log> prop-0002`. Se a pessoa rejeitar todas as
propostas com um motivo (`--motivo`), a decisão volta com ele, para propor outra ou dizer que não há; no
fim, a triagem escreve o sumário do incidente no log. `--sem-nova-rodada` e `--sem-sumario` desligam os dois.

A saída é um resumo do que cada agente fez: nunca traz a chave, o texto dos modelos nem endereços.
"""

import argparse
import os
import sys

from codigo.agente.agentes import (
    CONFIGURACOES,
    ESPERA_DA_APROVACAO_S,
    MAXIMO_DE_RODADAS,
    Perfil,
    orquestrar,
)
from codigo.agente.cliente_mcp import ErroDoServidor
from codigo.api.configuracao import (
    PREFIXO_DA_NUVEM,
    PREFIXO_LOCAL,
    Configuracao,
    carregar_env,
)
from codigo.api.provedor import ErroDoProvedor, Provedor
from codigo.mcp.cenarios import CENARIOS, ler_cenarios
from codigo.mcp.eventos import Registro
from codigo.mcp.stub import Stub

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PREFIXOS = {"local": PREFIXO_LOCAL, "nuvem": PREFIXO_DA_NUVEM}


def perfis_da_configuracao(configuracao, ambiente):
    """Os modelos que a configuração usa, lidos do ambiente. Devolve `(perfis, faltando)`."""
    perfis, faltando = {}, []
    for lugar in sorted(set(CONFIGURACOES[configuracao].values())):
        config = Configuracao.do_ambiente(ambiente, PREFIXOS[lugar])
        if config.faltando():
            faltando += config.faltando()
        else:
            perfis[lugar] = Perfil(Provedor(config), config.modelo)
    return perfis, faltando


def resumo(resultado):
    """O resumo de um incidente, sem endereço e sem chave.

    O único texto de modelo é o começo de uma resposta cortada no limite de saída, num aviso.
    """
    linhas = [f"incidente {resultado.incidente}, configuração {resultado.configuracao}: {resultado.desfecho}"]
    for execucao in resultado.execucoes:
        r = execucao.resultado
        tokens = f"{r.tokens_entrada}+{r.tokens_saida} tokens" if r.tokens_entrada is not None else "tokens não informados"
        linhas.append(
            f"  rodada {execucao.rodada}  {execucao.agente:<8} ({execucao.onde})  {r.motivo}, "
            f"{len(r.chamadas_ao_modelo)} chamadas, {tokens}"
        )
    linhas += [f"  aviso: {aviso}" for aviso in resultado.avisos]
    return "\n".join(linhas)


def main(argv=None):
    analisador = argparse.ArgumentParser(prog="python -m codigo.agente", description="Orquestrador dos agentes do SentryIoT.")
    analisador.add_argument("--incidente", required=True, help="o incidente aberto no log, como inc-0001")
    analisador.add_argument("--log", required=True, help="o log de eventos do incidente")
    analisador.add_argument("--cenarios", help="os cenários do servidor MCP em modo de reprodução")
    analisador.add_argument("--configuracao", choices=list(CONFIGURACOES), default="hibrida")
    analisador.add_argument("--rodadas", type=int, default=MAXIMO_DE_RODADAS, help="máximo de rodadas da decisão")
    analisador.add_argument(
        "--espera-aprovacao", type=float, default=ESPERA_DA_APROVACAO_S, help="segundos esperando uma pessoa aprovar"
    )
    analisador.add_argument("--env", default=os.path.join(RAIZ, ".env"), help="arquivo .env (padrão: o da raiz)")
    analisador.add_argument(
        "--sem-nova-rodada", action="store_true", help="não devolve a vez à decisão depois de uma rejeição com motivo"
    )
    analisador.add_argument("--sem-sumario", action="store_true", help="não pede à triagem o sumário do incidente")
    argumentos = analisador.parse_args(argv)

    carregar_env(argumentos.env)
    try:
        perfis, faltando = perfis_da_configuracao(argumentos.configuracao, os.environ)
    except ValueError as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 2
    if faltando:
        print(f"faltam no .env: {', '.join(faltando)}", file=sys.stderr)
        return 2

    def esperando(pendentes):
        ids = ", ".join(proposta.id for proposta in pendentes)
        print(f"aguardando uma pessoa: python -m codigo.mcp.aprovar --log {argumentos.log} {ids}", file=sys.stderr)

    try:
        # Como o servidor MCP faz ao subir: um log novo recebe a abertura dos incidentes dos cenários
        # (os de exemplo, sem `--cenarios`). Num log que já os tem, não muda nada.
        cenarios = ler_cenarios(argumentos.cenarios) if argumentos.cenarios else CENARIOS
        Stub(Registro(argumentos.log), agente="todos", cenarios=cenarios).abrir_incidentes()
        resultado = orquestrar(
            argumentos.incidente, log=argumentos.log, cenarios=argumentos.cenarios, perfis=perfis,
            configuracao=argumentos.configuracao, maximo_de_rodadas=argumentos.rodadas,
            espera_da_aprovacao_s=argumentos.espera_aprovacao, ao_esperar=esperando,
            rodada_apos_rejeicao=not argumentos.sem_nova_rodada, sumario=not argumentos.sem_sumario,
        )
    except (ErroDoProvedor, ErroDoServidor, OSError, ValueError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    print(resumo(resultado))
    return 0


if __name__ == "__main__":
    sys.exit(main())
