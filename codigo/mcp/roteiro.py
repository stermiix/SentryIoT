"""Execução roteirizada do stub: um incidente de flood, do começo ao fim.

Gera o log de exemplo versionado em `exemplos/incidente_flood.jsonl`, que é o primeiro insumo
do modo replay da interface web. O roteiro passa por todos os tipos de evento do contrato: a
primeira ação não resolve, o agente de decisão pesquisa outra saída, o executor é recusado ao
tentar aplicar antes da hora, a pessoa rejeita uma proposta e aprova outra, o incidente cessa,
a primeira ação é desfeita e a ação nova vai para o catálogo.

Não há agente nem modelo de linguagem aqui. As chamadas de tool são feitas de verdade no stub,
uma por uma, na ordem do roteiro. As chamadas ao modelo e as recomendações são eventos escritos
à mão, com tokens e durações ilustrativos. O relógio também é de mentira, para que o arquivo
saia igual a cada execução.

Uso, a partir da raiz do repositório:
    python -m codigo.mcp.roteiro
    python -m codigo.mcp.roteiro --saida outro/caminho.jsonl
"""
import argparse
import sys
from datetime import timedelta
from pathlib import Path

from codigo.mcp.acoes import PedidoRecusado, decidir, promover, reconstruir
from codigo.mcp.cenarios import CENARIOS
from codigo.mcp.eventos import Registro, novo
from codigo.mcp.stub import Stub
from codigo.mcp.tipos import ChamadaDeLLM, Recomendacao

SAIDA_PADRAO = Path(__file__).with_name("exemplos") / "incidente_flood.jsonl"
MODELO = "modelo-de-exemplo"
_FLOOD = next(cenario for cenario in CENARIOS if cenario.nome == "flood")
_INCIDENTE = _FLOOD.incidente.id


class RelogioDoRoteiro:
    """Relógio de mentira: avança um passo fixo a cada leitura e o que o roteiro mandar esperar."""

    def __init__(self, inicio, passo=timedelta(milliseconds=4)):
        self.instante = inicio
        self.passo = passo

    def __call__(self):
        self.instante += self.passo
        return self.instante

    def esperar(self, segundos):
        self.instante += timedelta(seconds=segundos)


def executar(saida=SAIDA_PADRAO):
    """Roda o roteiro e grava o log em `saida`, substituindo o arquivo que houver."""
    saida = Path(saida)
    saida.unlink(missing_ok=True)
    # O lote sai do classificador quando o incidente é aberto, no fim do primeiro período.
    relogio = RelogioDoRoteiro(_FLOOD.incidente.fim)
    registro = Registro(saida, relogio)
    # Um stub por agente, sobre o mesmo log: cada um só atende as tools da sua linha.
    triagem, decisao, execucao = (Stub(registro, agente=agente, cenarios=[_FLOOD]) for agente in ("triagem", "decisao", "execucao"))

    def modelo(agente, tokens_entrada, tokens_saida, segundos):
        relogio.esperar(segundos)
        chamada = ChamadaDeLLM(
            agente=agente, modelo=MODELO, tokens_entrada=tokens_entrada, tokens_saida=tokens_saida,
            duracao_ms=segundos * 1000,
        )
        registro.gravar(novo("llm_chamada", chamada, _INCIDENTE))

    def recomendar(texto, *propostas):
        registro.gravar(novo("recomendacao_emitida", Recomendacao(agente="decisao", texto=texto, propostas=propostas), _INCIDENTE))

    def pessoa(funcao, *argumentos, espera, **opcoes):
        relogio.esperar(espera)
        registro.atualizar(lambda eventos: funcao(reconstruir(eventos), *argumentos, **opcoes))

    triagem.abrir_incidentes()

    # Triagem: lê o resumo, pede uma fatia pequena das janelas e conclui.
    modelo("triagem", 1240, 96, 2.1)
    triagem.chamar("obter_incidente", id=_INCIDENTE)
    triagem.chamar("obter_janelas", id=_INCIDENTE, limite=5)
    modelo("triagem", 3980, 212, 3.4)

    # Decisão: consulta as mitigações da categoria e propõe a de risco baixo.
    modelo("decisao", 1510, 88, 2.4)
    incidente = decisao.chamar("obter_incidente", id=_INCIDENTE)
    decisao.chamar("consultar_mitigacoes", categoria=incidente.categoria)
    modelo("decisao", 2890, 240, 4.0)
    bloqueio = decisao.chamar(
        "propor_acao", id=_INCIDENTE, acao="bloquear_ip", alvo=incidente.origens[0].endereco,
        parametros={"duracao": 10},
        justificativa="É a origem com mais quadros no incidente, e o bloqueio por 10 minutos é de risco baixo.",
    )
    recomendar(
        "Flood de pacotes SYN contra 192.168.137.20, vindo de 37 origens. Recomendo bloquear por 10 minutos a "
        "origem com mais quadros, 203.0.113.7, e conferir o efeito. Como o ataque é distribuído, o bloqueio "
        "de uma origem pode não bastar.",
        bloqueio.id,
    )

    # Execução: a proposta é de risco baixo, então é aplicada sem aprovação. Não resolve.
    modelo("execucao", 980, 64, 1.6)
    primeira = execucao.chamar("executar_acao", id_proposta=bloqueio.id)
    relogio.esperar(30)
    execucao.chamar("verificar_efeito", id_execucao=primeira.id)
    modelo("execucao", 1320, 71, 1.8)

    # Decisão, de novo, sabendo o que já foi tentado: pesquisa outra saída e propõe duas.
    modelo("decisao", 2140, 102, 2.7)
    decisao.chamar("pesquisar_solucoes", consulta="flood de SYN com muitas origens")
    modelo("decisao", 3620, 418, 6.2)
    isolamento = decisao.chamar(
        "propor_acao", id=_INCIDENTE, acao="isolar_dispositivo", alvo="192.168.137.20", parametros={},
        justificativa="Isolar o dispositivo atacado interrompe o efeito do flood, ao custo de tirá-lo de serviço.",
    )
    syn_cookies = decisao.chamar(
        "propor_acao", id=_INCIDENTE, acao="ativar_syn_cookies", alvo="192.168.137.20",
        parametros={
            "descricao": "Ativa SYN cookies no dispositivo atacado.",
            "passos": [
                "Ativar SYN cookies na pilha TCP de 192.168.137.20.",
                "Conferir se o dispositivo volta a aceitar conexões legítimas.",
            ],
            "efeito_esperado": "A fila de conexões pendentes deixa de esgotar, mesmo com o flood em curso.",
            "como_desfazer": "Desativar SYN cookies na pilha TCP de 192.168.137.20.",
            "fonte": "Base local: flood.md, seção sobre SYN cookies.",
        },
        justificativa=(
            "O bloqueio de uma origem não resolveu, porque o ataque vem de 37 origens. SYN cookies não "
            "dependem de conhecer as origens e mantêm o dispositivo em serviço."
        ),
    )
    recomendar(
        "O bloqueio de 203.0.113.7 não resolveu: o flood continua pelas outras origens. Há duas saídas, as "
        "duas de risco alto e dependentes de aprovação. Recomendo ativar SYN cookies em 192.168.137.20, uma "
        "ação nova encontrada na base local, que mantém o dispositivo em serviço. A alternativa é isolar o "
        "dispositivo, o que interrompe o efeito do ataque e também o serviço.",
        isolamento.id, syn_cookies.id,
    )

    # O executor tenta aplicar a ação nova antes da aprovação e é recusado.
    modelo("execucao", 1050, 58, 1.5)
    try:
        execucao.chamar("executar_acao", id_proposta=syn_cookies.id)
    except PedidoRecusado:
        pass

    # A pessoa decide pelo canal dela: rejeita o isolamento e aprova a ação nova.
    pessoa(decidir, isolamento.id, False, espera=40, motivo="O dispositivo não pode sair de serviço.")
    pessoa(decidir, syn_cookies.id, True, espera=12)

    # Execução: aplica a ação aprovada, confere que o incidente cessou e desfaz o bloqueio inútil.
    modelo("execucao", 1090, 60, 1.5)
    segunda = execucao.chamar("executar_acao", id_proposta=syn_cookies.id)
    relogio.esperar(30)
    execucao.chamar("verificar_efeito", id_execucao=segunda.id)
    execucao.chamar("consultar_estado")
    execucao.chamar("desfazer_acao", id_execucao=primeira.id)
    modelo("execucao", 1480, 93, 2.0)

    # Com a ação nova aplicada e o incidente encerrado, a pessoa a promove ao catálogo.
    pessoa(promover, syn_cookies.id, espera=90)
    return saida


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.mcp.roteiro",
        description="Gera o log de eventos de exemplo: um incidente de flood, do começo ao fim, no stub.",
    )
    analisador.add_argument("--saida", default=str(SAIDA_PADRAO), help=f"arquivo a gravar (padrão: {SAIDA_PADRAO})")
    try:
        argumentos = analisador.parse_args(argv)
    except SystemExit as encerramento:
        return encerramento.code
    try:
        saida = executar(argumentos.saida)
    except (OSError, ValueError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    print(f"log de exemplo gravado em {saida}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
