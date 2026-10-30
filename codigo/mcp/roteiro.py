"""Execução roteirizada do stub: um incidente de flood, do começo ao fim.

Gera o log de exemplo versionado em `exemplos/incidente_flood.jsonl`, que é o primeiro insumo
do modo replay da interface web. O roteiro passa por todos os tipos de evento do contrato: a
primeira ação não resolve, o agente de decisão pesquisa outra saída, o executor é recusado ao
tentar aplicar antes da hora, a pessoa rejeita uma proposta e aprova outra, o incidente cessa,
a primeira ação é desfeita e a ação nova vai para o catálogo. Depois, um segundo incidente, de
força bruta, que a pessoa resolve antes dos agentes e marca como já resolvido: o agente de
decisão só explica.

O agente de decisão segue a arquitetura híbrida: lê o resumo do incidente, que não traz endereço,
e escreve o alvo das propostas com os rótulos neutros (`origem-1`, `destino-1`), que o servidor
troca pelo endereço. A pessoa e o agente de execução veem o endereço.

Não há agente nem modelo de linguagem aqui. As chamadas de tool são feitas de verdade no stub,
uma por uma, na ordem do roteiro. As chamadas ao modelo, as conclusões de cada agente e as
recomendações são eventos escritos à mão, com tokens e durações ilustrativos, e gravados como o
código dos agentes vai gravar: pelo `GravadorDoAgente`. O exemplo não diz onde cada modelo roda
nem o finish_reason de cada chamada: esses campos ficam nulos. O relógio também é de mentira, para
que o arquivo saia igual a cada execução.

Uso, a partir da raiz do repositório:
    python -m codigo.mcp.roteiro --sobrescrever                 gera de novo o exemplo versionado
    python -m codigo.mcp.roteiro --saida outro/caminho.jsonl

O roteiro não grava por cima de um arquivo que já existe, a não ser com `--sobrescrever`.
"""
import argparse
import sys
from datetime import timedelta
from pathlib import Path

from codigo.mcp.acoes import (
    PedidoRecusado,
    decidir,
    marcar_resolvido,
    promover,
    reconstruir,
)
from codigo.mcp.cenarios import CENARIOS
from codigo.mcp.eventos import GravadorDoAgente, Registro, novo
from codigo.mcp.stub import Stub
from codigo.mcp.tipos import AGENTES, ChamadaDeLLM, ConclusaoDoAgente, Recomendacao

SAIDA_PADRAO = Path(__file__).with_name("exemplos") / "incidente_flood.jsonl"
MODELO = "modelo-de-exemplo"
# O usuário do sistema que decide no exemplo. É fixo, para que o arquivo saia igual em qualquer máquina.
PESSOA = "operador"
_FLOOD = next(cenario for cenario in CENARIOS if cenario.nome == "flood")
_FORCA_BRUTA = next(cenario for cenario in CENARIOS if cenario.nome == "forca_bruta")
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

    def ate(self, instante):
        """Avança até o instante dado, se ele ainda não passou."""
        self.instante = max(self.instante, instante)


def executar(saida=SAIDA_PADRAO, sobrescrever=False):
    """Roda o roteiro e grava o log em `saida`.

    Se o arquivo já existe, só é substituído com `sobrescrever`: o caminho vem da linha de
    comando, e o arquivo que está lá pode não ser um log de exemplo.
    """
    saida = Path(saida)
    if saida.exists():
        if not sobrescrever:
            raise FileExistsError(f"{saida} já existe. Para gravar por cima dele, use --sobrescrever")
        saida.unlink()
    # O lote sai do classificador quando o incidente é aberto, no fim do primeiro período.
    relogio = RelogioDoRoteiro(_FLOOD.incidente.fim)
    registro = Registro(saida, relogio)
    cenarios = [_FLOOD, _FORCA_BRUTA]
    # Um stub por agente, sobre o mesmo log: cada um só atende as tools da sua linha.
    triagem, decisao, execucao = (Stub(registro, agente=agente, cenarios=cenarios) for agente in AGENTES)
    # O que cada agente grava por conta própria passa pelo gravador restrito dele.
    gravadores = {agente: GravadorDoAgente(agente, saida, relogio) for agente in AGENTES}
    # As chamadas ao modelo da execução em curso de cada agente, que o agente_concluido resume.
    em_curso = {agente: [] for agente in AGENTES}

    def classificador(cenario):
        # No sistema de verdade, o lote e a abertura vêm do classificador e da política de acionamento.
        Stub(registro, agente="triagem", cenarios=[cenario]).abrir_incidentes()

    def modelo(agente, tokens_entrada, tokens_saida, segundos, incidente=_INCIDENTE):
        relogio.esperar(segundos)
        chamada = ChamadaDeLLM(
            agente=agente, modelo=MODELO, tokens_entrada=tokens_entrada, tokens_saida=tokens_saida,
            duracao_ms=segundos * 1000,
        )
        em_curso[agente].append(chamada)
        gravadores[agente].gravar(novo("llm_chamada", chamada, incidente))

    def concluir(agente, veredito=None, incidente=_INCIDENTE):
        # O laço do agente terminou com a resposta final: o log guarda o resumo da execução dele.
        chamadas, em_curso[agente] = em_curso[agente], []
        conclusao = ConclusaoDoAgente(
            agente=agente, motivo="resposta_final", voltas=len(chamadas),
            tokens_entrada=sum(chamada.tokens_entrada for chamada in chamadas),
            tokens_saida=sum(chamada.tokens_saida for chamada in chamadas),
            veredito=veredito,
        )
        gravadores[agente].gravar(novo("agente_concluido", conclusao, incidente))

    def recomendar(texto, *propostas, incidente=_INCIDENTE):
        recomendacao = Recomendacao(agente="decisao", texto=texto, propostas=propostas)
        gravadores["decisao"].gravar(novo("recomendacao_emitida", recomendacao, incidente))

    def pessoa(funcao, *argumentos, espera, **opcoes):
        relogio.esperar(espera)
        registro.atualizar(lambda eventos: funcao(reconstruir(eventos), *argumentos, **opcoes))

    classificador(_FLOOD)

    # Triagem: lê o resumo, pede uma fatia pequena das janelas e conclui.
    modelo("triagem", 1240, 96, 2.1)
    triagem.chamar("obter_incidente", id=_INCIDENTE)
    triagem.chamar("obter_janelas", id=_INCIDENTE, limite=5)
    modelo("triagem", 3980, 212, 3.4)
    concluir("triagem", veredito="coerente")

    # Decisão: lê o resumo, sem endereço, consulta as mitigações da categoria e propõe a de risco baixo.
    # O alvo vai com o rótulo neutro, e o servidor o troca pelo endereço.
    modelo("decisao", 1510, 88, 2.4)
    resumo = decisao.chamar("obter_resumo", id=_INCIDENTE)
    decisao.chamar("consultar_mitigacoes", categoria=resumo.categoria)
    modelo("decisao", 2890, 240, 4.0)
    bloqueio = decisao.chamar(
        "propor_acao", id=_INCIDENTE, acao="bloquear_ip", alvo=resumo.origens[0].rotulo,
        parametros={"duracao": 10},
        justificativa="É a origem com mais quadros no incidente, e o bloqueio por 10 minutos é de risco baixo.",
    )
    recomendar(
        "Flood de pacotes SYN contra destino-1, vindo de 37 origens. Recomendo bloquear por 10 minutos a "
        "origem com mais quadros, origem-1, e conferir o efeito. Como o ataque é distribuído, o bloqueio "
        "de uma origem pode não bastar.",
        bloqueio.id,
    )
    concluir("decisao")

    # Execução: a proposta é de risco baixo, então é aplicada sem aprovação. Não resolve.
    modelo("execucao", 980, 64, 1.6)
    primeira = execucao.chamar("executar_acao", id_proposta=bloqueio.id)
    relogio.esperar(30)
    execucao.chamar("verificar_efeito", id_execucao=primeira.id)
    modelo("execucao", 1320, 71, 1.8)
    concluir("execucao")

    # Decisão, de novo: o resumo traz o último efeito verificado. Pesquisa outra saída e propõe duas.
    modelo("decisao", 2140, 102, 2.7)
    decisao.chamar("obter_resumo", id=_INCIDENTE)
    decisao.chamar("pesquisar_solucoes", consulta="flood de SYN com muitas origens")
    modelo("decisao", 3620, 418, 6.2)
    atacado = resumo.destinos[0].rotulo
    isolamento = decisao.chamar(
        "propor_acao", id=_INCIDENTE, acao="isolar_dispositivo", alvo=atacado, parametros={},
        justificativa="Isolar o dispositivo atacado interrompe o efeito do flood, ao custo de tirá-lo de serviço.",
    )
    syn_cookies = decisao.chamar(
        "propor_acao", id=_INCIDENTE, acao="ativar_syn_cookies", alvo=atacado,
        parametros={
            "descricao": "Ativa SYN cookies no dispositivo atacado.",
            "passos": [
                "Ativar SYN cookies na pilha TCP do dispositivo atacado.",
                "Conferir se o dispositivo volta a aceitar conexões legítimas.",
            ],
            "efeito_esperado": "A fila de conexões pendentes deixa de esgotar, mesmo com o flood em curso.",
            "como_desfazer": "Desativar SYN cookies na pilha TCP do dispositivo atacado.",
            "fonte": "Base local: ddos.md, medida sobre SYN cookies (MITRE ATT&CK T1499).",
        },
        justificativa=(
            "O bloqueio de uma origem não resolveu, porque o ataque vem de 37 origens. SYN cookies não "
            "dependem de conhecer as origens e mantêm o dispositivo em serviço."
        ),
    )
    recomendar(
        "O bloqueio de origem-1 não resolveu: o flood continua pelas outras origens. Há duas saídas, as "
        "duas de risco alto e dependentes de aprovação. Recomendo ativar SYN cookies em destino-1, uma "
        "ação nova encontrada na base local, que mantém o dispositivo em serviço. A alternativa é isolar o "
        "dispositivo, o que interrompe o efeito do ataque e também o serviço.",
        isolamento.id, syn_cookies.id,
    )
    concluir("decisao")

    # O executor tenta aplicar a ação nova antes da aprovação e é recusado.
    modelo("execucao", 1050, 58, 1.5)
    try:
        execucao.chamar("executar_acao", id_proposta=syn_cookies.id)
    except PedidoRecusado:
        pass
    concluir("execucao")

    # A pessoa decide pelo canal dela: rejeita o isolamento e aprova a ação nova.
    pessoa(decidir, isolamento.id, False, espera=40, motivo="O dispositivo não pode sair de serviço.", usuario=PESSOA)
    pessoa(decidir, syn_cookies.id, True, espera=12, usuario=PESSOA)

    # Execução: aplica a ação aprovada, confere que o incidente cessou e desfaz o bloqueio inútil.
    modelo("execucao", 1090, 60, 1.5)
    segunda = execucao.chamar("executar_acao", id_proposta=syn_cookies.id)
    relogio.esperar(30)
    execucao.chamar("verificar_efeito", id_execucao=segunda.id)
    execucao.chamar("consultar_estado")
    execucao.chamar("desfazer_acao", id_execucao=primeira.id)
    modelo("execucao", 1480, 93, 2.0)
    concluir("execucao")

    # Com a ação nova aplicada e o incidente encerrado, a pessoa a promove ao catálogo.
    pessoa(promover, syn_cookies.id, espera=90)

    # Segundo incidente: força bruta no SSH. Avisada na abertura, a pessoa bloqueia a origem no roteador
    # antes dos agentes e marca o incidente pelo terminal. Com a marca, nada é proposto nem aplicado.
    forca_bruta = _FORCA_BRUTA.incidente.id
    relogio.ate(_FORCA_BRUTA.incidente.fim)
    classificador(_FORCA_BRUTA)
    pessoa(
        marcar_resolvido, forca_bruta, espera=25, usuario=PESSOA,
        motivo="Bloqueei a origem no roteador antes de os agentes responderem.",
    )
    modelo("triagem", 1180, 88, 2.0, incidente=forca_bruta)
    triagem.chamar("obter_incidente", id=forca_bruta)
    concluir("triagem", veredito="coerente", incidente=forca_bruta)
    modelo("decisao", 1290, 154, 3.2, incidente=forca_bruta)
    # O resumo traz a marca de já resolvido: o agente de decisão só explica.
    decisao.chamar("obter_resumo", id=forca_bruta)
    recomendar(
        "Incidente marcado como já resolvido pela pessoa que opera a rede. Era um ataque de dicionário contra o "
        "SSH de um dispositivo, vindo de uma origem só: 18 janelas com SSH em quase todos os quadros e taxa de "
        "11,8 quadros por segundo. A medida indicada seria bloquear a origem por até 15 minutos, que é o que a "
        "pessoa já fez. Nenhuma ação foi proposta nem aplicada.",
        incidente=forca_bruta,
    )
    concluir("decisao", incidente=forca_bruta)
    return saida


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.mcp.roteiro",
        description="Gera o log de eventos de exemplo: um incidente de flood, do começo ao fim, no stub.",
    )
    analisador.add_argument("--saida", default=str(SAIDA_PADRAO), help=f"arquivo a gravar (padrão: {SAIDA_PADRAO})")
    analisador.add_argument(
        "--sobrescrever", action="store_true", help="grava por cima do arquivo de saída, se ele já existir"
    )
    try:
        argumentos = analisador.parse_args(argv)
    except SystemExit as encerramento:
        return encerramento.code
    try:
        saida = executar(argumentos.saida, sobrescrever=argumentos.sobrescrever)
    except (OSError, ValueError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    print(f"log de exemplo gravado em {saida}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
