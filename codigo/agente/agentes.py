"""O orquestrador dos agentes: o código que encadeia triagem, decisão e execução num incidente.

Não é um quarto agente (decisão de 25/10/2026): é Python que decide só a ordem, que é quase sempre a
mesma. A cada incidente aberto no log:

1. a triagem lê o incidente e dá o veredito;
2. o veredito passa por `mascarar_enderecos` e segue para o agente de decisão, que lê o resumo (sem
   endereços), propõe a ação e escreve a recomendação;
3. se a proposta é de risco alto, o orquestrador espera a `acao_aprovada` no log. Quem aprova é uma pessoa,
   pelo comando `python -m codigo.mcp.aprovar`, ou um `aprovador` entregue por quem chama (os
   experimentos usam um aprovador automático);
4. o agente de execução aplica a proposta liberada e verifica o efeito;
5. se o efeito não cessou, a decisão volta, até `maximo_de_rodadas`.

Cada agente roda no modelo que a configuração diz (`CONFIGURACOES`): tudo local, tudo na nuvem ou
híbrida, com a decisão na nuvem. Cada chamada ao modelo e o fim de cada agente vão para o log
(`registro.py`), com o lugar onde o modelo rodou.

O que o orquestrador não faz: não grava proposta, aprovação nem execução. Isso é do servidor MCP e do
comando de aprovação.
"""

import time
from dataclasses import dataclass

from codigo.agente.cliente_mcp import ClienteMCP
from codigo.agente.laco import rodar
from codigo.agente.pedidos import (
    ABERTURA_DA_TRIAGEM,
    COMPLEMENTO_DO_SISTEMA,
    prompt_da_skill,
)
from codigo.agente.registro import chamadas_no_log, conclusao_no_log
from codigo.mcp.acoes import decidir, reconstruir
from codigo.mcp.eventos import GravadorDoAgente, Registro, ler, novo
from codigo.mcp.tipos import TEXTO_LONGO, mascarar_enderecos

LOCAL = "local"
NUVEM = "nuvem"
# Onde roda o modelo de cada agente, em cada configuração dos experimentos.
CONFIGURACOES = {
    "local": {"triagem": LOCAL, "decisao": LOCAL, "execucao": LOCAL},
    "nuvem": {"triagem": NUVEM, "decisao": NUVEM, "execucao": NUVEM},
    "hibrida": {"triagem": LOCAL, "decisao": NUVEM, "execucao": LOCAL},
}
# As skills que formam o prompt de sistema de cada agente. A skill de coordenação do agente de decisão
# (aceitar ou descartar o veredito da triagem) ainda está por escrever: quando existir, entra aqui.
SKILLS = {
    "triagem": ("triagem-do-alerta",),
    "decisao": ("analise-por-categoria", "recomendacao-de-mitigacao"),
    "execucao": ("execucao-da-acao",),
}
MAXIMO_DE_RODADAS = 3
ESPERA_DA_APROVACAO_S = 600
INTERVALO_DA_APROVACAO_S = 2
# O veredito é texto de um modelo local. Antes de ir à nuvem, passa pelo filtro de endereços; um texto
# longo demais é cortado antes, e o filtro trata o fim como possível começo de um endereço.
MAXIMO_DO_VEREDITO = 4000

ABERTURA_DA_DECISAO = (
    "O incidente {incidente} foi aberto e passou pela triagem. Este é o veredito dela, sem endereços:\n\n"
    "{veredito}\n\n"
    "Leia o resumo do incidente, decida se aceita o veredito, proponha a ação e devolva a recomendação."
)
ABERTURA_DA_DECISAO_DE_NOVO = (
    "O incidente {incidente} continua aberto: a ação anterior foi aplicada e o efeito verificado foi "
    "\"{efeito}\". Este é o veredito da triagem, sem endereços:\n\n"
    "{veredito}\n\n"
    "Leia o resumo de novo, que traz o último efeito, proponha outra ação e devolva a recomendação."
)
ABERTURA_DA_EXECUCAO = (
    "A proposta {proposta} do incidente {incidente} está liberada. Aplique a ação, verifique o efeito "
    "e devolva o resultado."
)

# Como terminou o incidente no orquestrador.
RESOLVIDO = "resolvido"
SEM_RESOLUCAO = "sem_resolucao"
INCIDENTE_ENCERRADO = "incidente_encerrado"
AGENTE_PAROU = "agente_parou"
SEM_PROPOSTA = "sem_proposta"
SEM_APROVACAO = "sem_aprovacao"
TODAS_REJEITADAS = "todas_rejeitadas"
EFEITO_NAO_VERIFICADO = "efeito_nao_verificado"


@dataclass(frozen=True)
class Perfil:
    """Um modelo ao alcance do orquestrador: o provedor que o chama e o nome dele."""

    provedor: object
    modelo: str


@dataclass(frozen=True)
class ExecucaoDoAgente:
    agente: str
    rodada: int
    onde: str
    resultado: object  # ResultadoDoLaco

    @property
    def motivo(self):
        return self.resultado.motivo


@dataclass(frozen=True)
class ResultadoDoIncidente:
    incidente: str
    configuracao: str
    desfecho: str
    execucoes: tuple[ExecucaoDoAgente, ...]
    avisos: tuple[str, ...]


def orquestrar(
    incidente,
    *,
    log,
    perfis,
    configuracao="hibrida",
    cenarios=None,
    aprovador=None,
    maximo_de_rodadas=MAXIMO_DE_RODADAS,
    espera_da_aprovacao_s=ESPERA_DA_APROVACAO_S,
    esperar=time.sleep,
    relogio=time.monotonic,
    abrir_cliente=ClienteMCP,
    ao_esperar=None,
    **limites_do_laco,
):
    """Trata um incidente aberto no log, da triagem ao efeito verificado.

    `perfis` é um dicionário `{"local": Perfil, "nuvem": Perfil}` com os modelos que a configuração usa.
    `aprovador(estado, pendentes)` recebe as propostas que aguardam aprovação e grava as decisões no log
    (ver `decidir_no_log`); sem ele, o orquestrador espera até `espera_da_aprovacao_s` que uma pessoa decida.
    `ao_esperar(pendentes)` é chamado uma vez quando há proposta esperando uma pessoa.
    """
    if configuracao not in CONFIGURACOES:
        raise ValueError(f"configuração desconhecida: {configuracao!r}. Diga {', '.join(CONFIGURACOES)}")
    onde = CONFIGURACOES[configuracao]
    faltam = sorted(set(onde.values()) - set(perfis))
    if faltam:
        raise ValueError(f"a configuração {configuracao} precisa do modelo {' e do modelo '.join(faltam)}")
    if isinstance(maximo_de_rodadas, bool) or not isinstance(maximo_de_rodadas, int) or maximo_de_rodadas < 1:
        raise ValueError("maximo_de_rodadas precisa ser um inteiro positivo")

    execucoes = []
    avisos = []

    def terminar(desfecho):
        return ResultadoDoIncidente(incidente, configuracao, desfecho, tuple(execucoes), tuple(avisos))

    def agente(papel, rodada, abertura, depois=None):
        resultado = rodar_agente(
            papel, incidente, abertura, perfil=perfis[onde[papel]], onde=onde[papel], log=log,
            cenarios=cenarios, abrir_cliente=abrir_cliente, depois=depois, **limites_do_laco,
        )
        execucoes.append(ExecucaoDoAgente(papel, rodada, onde[papel], resultado))
        return resultado

    estado = reconstruir(ler(log))
    if incidente not in estado.incidentes:
        raise ValueError(f"o incidente {incidente} não existe no log {log}")
    if estado.incidentes[incidente].estado == "encerrado":
        return terminar(INCIDENTE_ENCERRADO)

    triagem = agente("triagem", 1, ABERTURA_DA_TRIAGEM.format(id=incidente))
    if not triagem.terminou_bem:
        return terminar(AGENTE_PAROU)
    veredito = para_a_decisao(triagem.resposta)

    efeito = None
    for rodada in range(1, maximo_de_rodadas + 1):
        antes = _ids_do_incidente(estado, incidente)
        abertura = (
            ABERTURA_DA_DECISAO.format(incidente=incidente, veredito=veredito)
            if efeito is None
            else ABERTURA_DA_DECISAO_DE_NOVO.format(incidente=incidente, veredito=veredito, efeito=efeito)
        )

        def registrar(resultado, antes=antes):
            aviso = _registrar_recomendacao(log, incidente, resultado.resposta, antes)
            if aviso:
                avisos.append(aviso)

        decisao = agente("decisao", rodada, abertura, depois=registrar)
        if not decisao.terminou_bem:
            return terminar(AGENTE_PAROU)

        estado = reconstruir(ler(log))
        novas = _propostas_novas(estado, incidente, antes)
        if not novas:
            return terminar(SEM_PROPOSTA)

        estado, decidido = _aguardar_decisoes(
            log, novas, aprovador, espera_da_aprovacao_s, esperar, relogio, ao_esperar
        )
        if not decidido:
            return terminar(SEM_APROVACAO)
        liberadas = [id_ for id_ in novas if estado.propostas[id_].estado == "liberada"]
        if not liberadas:
            return terminar(TODAS_REJEITADAS)

        execucoes_antes = set(estado.execucoes)
        for proposta in liberadas:
            execucao = agente(
                "execucao", rodada, ABERTURA_DA_EXECUCAO.format(proposta=proposta, incidente=incidente)
            )
            if not execucao.terminou_bem:
                return terminar(AGENTE_PAROU)

        estado = reconstruir(ler(log))
        novas_execucoes = set(estado.execucoes) - execucoes_antes
        verificado = estado.ultimos_efeitos.get(incidente)
        if verificado is None or verificado.execucao not in novas_execucoes:
            return terminar(EFEITO_NAO_VERIFICADO)
        if verificado.resultado == "cessou":
            return terminar(RESOLVIDO)
        efeito = verificado.resultado
    return terminar(SEM_RESOLUCAO)


def rodar_agente(papel, incidente, abertura, *, perfil, onde, log, cenarios=None, abrir_cliente=ClienteMCP,
                 depois=None, **limites_do_laco):
    """Roda o laço de um agente num servidor MCP só da linha dele e grava no log o que ele fez.

    `depois(resultado)`, se houver, roda quando o laço acaba e antes do `agente_concluido`: é onde o
    orquestrador grava a recomendação, para que ela venha antes da conclusão, como no log de exemplo.
    """
    gravador = GravadorDoAgente(papel, log)
    sistema = "\n\n".join([*(prompt_da_skill(skill) for skill in SKILLS[papel]), COMPLEMENTO_DO_SISTEMA])
    mensagens = [{"role": "system", "content": sistema}, {"role": "user", "content": abertura}]
    with abrir_cliente(papel, log, cenarios) as cliente:
        resultado = rodar(
            perfil.provedor, perfil.modelo, mensagens, cliente.tools, cliente,
            ao_chamar=chamadas_no_log(gravador, incidente, onde), **limites_do_laco,
        )
    if depois is not None:
        depois(resultado)
    conclusao_no_log(gravador, incidente, resultado)
    return resultado


def para_a_decisao(resposta):
    """O veredito da triagem como o agente de decisão o recebe: sem nenhum endereço.

    Obrigatório em toda configuração, e não só na híbrida: o agente de decisão pode estar na nuvem, e o
    texto da triagem é de um modelo que viu os endereços do incidente.
    """
    texto = (resposta or "").strip()
    cortado = len(texto) > MAXIMO_DO_VEREDITO
    return mascarar_enderecos(texto[:MAXIMO_DO_VEREDITO], cortado_no_fim=cortado)


def decidir_no_log(log, id_proposta, aprovar, *, usuario, motivo=None, canal="terminal"):
    """Grava a aprovação ou a rejeição de uma proposta, como o comando de aprovação grava.

    É o que um aprovador automático usa. A decisão fica no log como a de uma pessoa, com o `usuario` que
    o chamador disser.
    """
    registro = Registro(log)
    return registro.atualizar(
        lambda eventos: decidir(reconstruir(eventos), id_proposta, aprovar, canal=canal, motivo=motivo, usuario=usuario)
    )[0]


def _ids_do_incidente(estado, incidente):
    return {id_ for id_, proposta in estado.propostas.items() if proposta.incidente == incidente}


def _propostas_novas(estado, incidente, antes):
    return [id_ for id_, proposta in estado.propostas.items() if proposta.incidente == incidente and id_ not in antes]


def _aguardar_decisoes(log, novas, aprovador, espera_s, esperar, relogio, ao_esperar):
    """Espera a decisão de cada proposta nova que aguarda aprovação. Devolve o estado e se todas foram decididas."""

    def pendentes_de(estado):
        return [estado.propostas[id_] for id_ in novas if estado.propostas[id_].estado == "aguardando_aprovacao"]

    estado = reconstruir(ler(log))
    pendentes = pendentes_de(estado)
    if pendentes and aprovador is not None:
        aprovador(estado, pendentes)
        estado = reconstruir(ler(log))
        pendentes = pendentes_de(estado)
    if pendentes and ao_esperar is not None:
        ao_esperar(pendentes)
    limite = relogio() + espera_s
    while pendentes:
        if relogio() >= limite:
            return estado, False
        esperar(INTERVALO_DA_APROVACAO_S)
        estado = reconstruir(ler(log))
        pendentes = pendentes_de(estado)
    return estado, True


def _registrar_recomendacao(log, incidente, texto, antes):
    """Grava a resposta final do agente de decisão como a recomendação. Devolve um aviso, ou None se gravou."""
    texto = (texto or "").strip()
    if not texto:
        return None
    if len(texto) > TEXTO_LONGO:
        texto = texto[: TEXTO_LONGO - 1].rstrip() + "…"
    estado = reconstruir(ler(log))
    propostas = _propostas_novas(estado, incidente, antes)
    try:
        GravadorDoAgente("decisao", log).gravar(
            novo("recomendacao_emitida", {"agente": "decisao", "texto": texto, "propostas": propostas}, incidente)
        )
    except ValueError as erro:
        return f"a recomendação do agente de decisão não foi gravada: {erro}"
    return None
