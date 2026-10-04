"""Catálogo de ações, política de risco e ambiente simulado do SentryIoT.

O catálogo de base tem quatro ações. Ele é o ponto de partida do agente de decisão, não um
limite: o agente pode propor uma ação nova, fora do catálogo, desde que diga os passos e como
desfazer. A autonomia é graduada pelo risco. Ação de risco baixo é aplicada sem aprovação;
ação de risco alto e toda ação nova só são aplicadas depois que uma pessoa aprova. Os limites
ficam em `politica.toml`.

Nada aqui toca a rede: aplicar uma ação é registrar um evento no log. O estado das propostas,
das aprovações e das medidas ativas é sempre reconstruído a partir dos eventos (`reconstruir`),
e as funções deste módulo não gravam nada. Elas recebem o estado e devolvem o resultado e os
rascunhos dos eventos, que quem chamou grava com `eventos.Registro`.
"""
import ipaddress
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from codigo.mcp.eventos import novo
from codigo.mcp.tipos import (
    AcaoDoCatalogo,
    Ambiente,
    Decisao,
    Execucao,
    ParametroDeAcao,
    ParametrosDeAcaoNova,
    Promocao,
    Proposta,
)

POLITICA_PADRAO = Path(__file__).with_name("politica.toml")
RISCOS = ("baixo", "alto")
_NOME_DE_ACAO = re.compile(r"[a-z][a-z0-9_]{0,59}")
_USUARIO = re.compile(r"[A-Za-z0-9._-]{1,64}")
_MAIOR_ALVO = 200
_REGRA_DE_RISCO_ALTO = "Risco alto: só com aprovação humana."


class PedidoRecusado(Exception):
    """Um pedido que o sistema recusa, com o motivo (um dos códigos do contrato) e a mensagem."""

    def __init__(self, motivo, mensagem):
        super().__init__(mensagem)
        self.motivo = motivo
        self.mensagem = mensagem


@dataclass(frozen=True)
class _AcaoDeBase:
    descricao: str
    alvo: str
    # "ip" ou "credencial": o formato que o alvo precisa ter.
    tipo_de_alvo: str
    # "obrigatoria", "opcional" ou None, quando a ação não aceita prazo.
    duracao: str | None
    # Lista do ambiente simulado em que a medida ativa aparece.
    grupo: str
    como_desfazer: str


BASE = {
    "limitar_taxa": _AcaoDeBase(
        descricao="Limita, por um prazo, a taxa de pacotes aceitos de um endereço ou para ele.",
        alvo="Endereço IP do dispositivo atacado ou da origem, como 192.168.137.20",
        tipo_de_alvo="ip",
        duracao="obrigatoria",
        grupo="limites",
        como_desfazer="Retirar o limite com desfazer_acao.",
    ),
    "bloquear_ip": _AcaoDeBase(
        descricao="Bloqueia o tráfego vindo de um endereço de origem.",
        alvo="Endereço IP de origem, como 203.0.113.7",
        tipo_de_alvo="ip",
        duracao="opcional",
        grupo="bloqueios",
        como_desfazer="Retirar o bloqueio com desfazer_acao.",
    ),
    "isolar_dispositivo": _AcaoDeBase(
        descricao="Isola um dispositivo do restante da rede.",
        alvo="Endereço IP do dispositivo, como 192.168.137.20",
        tipo_de_alvo="ip",
        duracao=None,
        grupo="isolamentos",
        como_desfazer="Devolver o dispositivo à rede com desfazer_acao.",
    ),
    "revogar_credencial": _AcaoDeBase(
        descricao="Revoga a credencial de uma conta em um dispositivo.",
        alvo="Conta e dispositivo, no formato usuario@endereco, como admin@192.168.137.31",
        tipo_de_alvo="credencial",
        duracao=None,
        grupo="credenciais_revogadas",
        como_desfazer="Restabelecer a credencial com desfazer_acao.",
    ),
}
_PRAZO = "prazo_maximo_de_risco_baixo"


# --- política de risco -----------------------------------------------------------------------


def carregar_politica(caminho=POLITICA_PADRAO):
    """Lê o arquivo de política e devolve, para cada ação de base, o risco e o prazo máximo.

    Arquivo com ação a mais, ação a menos ou valor fora do esperado levanta ValueError: uma
    política lida pela metade liberaria ou travaria ações sem ninguém perceber.
    """
    try:
        with open(caminho, "rb") as arquivo:
            lido = tomllib.load(arquivo)
    except tomllib.TOMLDecodeError as erro:
        raise ValueError(f"arquivo de política ilegível ({caminho}): {erro}") from None

    def invalida(detalhe):
        return ValueError(f"política inválida em {caminho}: {detalhe}")

    faltando = [nome for nome in BASE if nome not in lido]
    sobrando = [nome for nome in lido if nome not in BASE]
    if faltando:
        raise invalida(f"falta a ação {', '.join(faltando)}")
    if sobrando:
        raise invalida(f"ação fora do catálogo de base: {', '.join(sobrando)}")
    politica = {}
    for nome, definicao in BASE.items():
        regra = lido[nome]
        desconhecidas = [chave for chave in regra if chave not in ("risco", _PRAZO)]
        if desconhecidas:
            raise invalida(f"chave desconhecida em {nome}: {', '.join(desconhecidas)}")
        if regra.get("risco") not in RISCOS:
            raise invalida(f"o risco de {nome} precisa ser baixo ou alto, e veio {regra.get('risco')!r}")
        prazo = regra.get(_PRAZO)
        if prazo is not None:
            if definicao.duracao is None:
                raise invalida(f"{nome} não aceita prazo, então não pode ter {_PRAZO}")
            if type(prazo) is not int or prazo < 1:
                raise invalida(f"{_PRAZO} de {nome} precisa ser um número inteiro de minutos, a partir de 1")
        politica[nome] = {"risco": regra["risco"], _PRAZO: prazo}
    return politica


def _risco(politica, acao, parametros):
    """Risco de uma ação de base com os parâmetros dados. Fora da base, o risco é sempre alto."""
    if acao not in BASE:
        return "alto"
    regra = politica[acao]
    if regra["risco"] == "alto":
        return "alto"
    prazo = regra[_PRAZO]
    if prazo is None:
        return "baixo"
    duracao = parametros.get("duracao")
    return "baixo" if duracao is not None and duracao <= prazo else "alto"


def _regra(politica, acao):
    regra = politica[acao]
    if regra["risco"] == "alto":
        return _REGRA_DE_RISCO_ALTO
    if regra[_PRAZO] is None:
        return "Risco baixo: o agente de execução aplica sem aprovação."
    return (
        f"Risco baixo com duracao de até {regra[_PRAZO]} minutos: o agente de execução aplica sem "
        "aprovação. Sem duracao ou com duracao maior, risco alto: só com aprovação humana."
    )


# --- estado reconstruído do log --------------------------------------------------------------


@dataclass
class Estado:
    """O que o log diz até agora: a última versão de cada coisa, por identificador."""

    incidentes: dict = field(default_factory=dict)
    propostas: dict = field(default_factory=dict)
    execucoes: dict = field(default_factory=dict)
    # Último efeito verificado de cada execução.
    efeitos: dict = field(default_factory=dict)
    # Ações novas promovidas ao catálogo, pelo nome.
    promovidas: dict = field(default_factory=dict)


def reconstruir(eventos):
    """Percorre os eventos na ordem do log e devolve o estado em que eles deixam o sistema."""
    estado = Estado()

    def mudar_proposta(identificador, novo_estado):
        proposta = estado.propostas[identificador]
        estado.propostas[identificador] = proposta.model_copy(update={"estado": novo_estado})

    for evento in eventos:
        dados = evento.dados
        match evento.tipo:
            case "incidente_aberto" | "incidente_atualizado" | "incidente_encerrado":
                estado.incidentes[dados.id] = dados
            case "acao_proposta":
                estado.propostas[dados.id] = dados
            case "acao_aprovada":
                mudar_proposta(dados.proposta, "liberada")
            case "acao_rejeitada":
                mudar_proposta(dados.proposta, "rejeitada")
            case "acao_executada":
                estado.execucoes[dados.id] = dados
                mudar_proposta(dados.proposta, "executada")
            case "acao_desfeita":
                estado.execucoes[dados.id] = dados
                mudar_proposta(dados.proposta, "desfeita")
            case "efeito_verificado":
                estado.efeitos[dados.execucao] = dados
            case "catalogo_ampliado":
                estado.promovidas[dados.acao.nome] = dados.acao
    return estado


def catalogo(estado, politica):
    """As ações que o agente pode propor: as quatro de base e as promovidas, nessa ordem."""
    de_base = [
        AcaoDoCatalogo(
            nome=nome,
            descricao=definicao.descricao,
            alvo=definicao.alvo,
            parametros=_parametros_de_base(definicao),
            regra=_regra(politica, nome),
            origem="base",
            passos=[],
            efeito_esperado=None,
            como_desfazer=definicao.como_desfazer,
            fonte=None,
        )
        for nome, definicao in BASE.items()
    ]
    return [*de_base, *estado.promovidas.values()]


def _parametros_de_base(definicao):
    if definicao.duracao is None:
        return []
    return [
        ParametroDeAcao(
            nome="duracao",
            descricao="Prazo da medida, em minutos (número inteiro, a partir de 1)",
            obrigatorio=definicao.duracao == "obrigatoria",
        )
    ]


def ambiente(estado):
    """As medidas ativas no ambiente simulado. Ação desfeita não aparece."""
    grupos = {nome: [] for nome in Ambiente.model_fields}
    for execucao in estado.execucoes.values():
        if execucao.estado == "aplicada":
            grupo = BASE[execucao.acao].grupo if execucao.acao in BASE else "outras_medidas"
            grupos[grupo].append(execucao)
    return Ambiente(**grupos)


# --- propor ----------------------------------------------------------------------------------


def propor(estado, politica, incidente, acao, alvo, parametros, justificativa):
    """Registra a proposta de uma ação do catálogo ou de uma ação nova.

    Devolve a proposta, com o nível de risco e se ela exige aprovação, e o rascunho do evento
    `acao_proposta`. Não aplica nada: proposta de risco baixo já nasce liberada para o agente
    de execução, e a de risco alto fica aguardando a decisão de uma pessoa.
    """
    if incidente not in estado.incidentes:
        raise PedidoRecusado("identificador_desconhecido", f"Não existe incidente com o identificador {incidente!r}.")
    if not isinstance(justificativa, str) or not justificativa.strip():
        raise PedidoRecusado("argumentos_invalidos", "A proposta precisa de uma justificativa.")
    if not isinstance(parametros, dict):
        raise PedidoRecusado("argumentos_invalidos", "O campo parametros precisa ser um objeto.")

    if acao in BASE:
        alvo = _alvo_de_base(acao, alvo)
        parametros = _parametros_validos(acao, parametros)
    elif acao in estado.promovidas:
        alvo = _alvo_livre(acao, alvo)
        # Os passos e a forma de desfazer vêm do catálogo: a pessoa aprova o que foi promovido,
        # e não uma variação com o mesmo nome.
        promovida = estado.promovidas[acao]
        parametros = parametros | {
            "descricao": promovida.descricao,
            "passos": promovida.passos,
            "efeito_esperado": promovida.efeito_esperado,
            "como_desfazer": promovida.como_desfazer,
            "fonte": promovida.fonte,
        }
    else:
        if not isinstance(acao, str) or not _NOME_DE_ACAO.fullmatch(acao):
            raise PedidoRecusado(
                "argumentos_invalidos",
                f"O nome de uma ação nova usa só letras minúsculas sem acento, números e sublinhado, começa por "
                f"letra e tem até 60 caracteres, como ativar_syn_cookies. Veio {acao!r}.",
            )
        alvo = _alvo_livre(acao, alvo)
        parametros = _parametros_de_acao_nova(acao, parametros)

    risco = _risco(politica, acao, parametros)
    proposta = Proposta(
        id=f"prop-{len(estado.propostas) + 1:04d}",
        incidente=incidente,
        acao=acao,
        alvo=alvo,
        parametros=parametros,
        justificativa=justificativa,
        nova=acao not in BASE and acao not in estado.promovidas,
        risco=risco,
        exige_aprovacao=risco == "alto",
        estado="aguardando_aprovacao" if risco == "alto" else "liberada",
    )
    return proposta, [novo("acao_proposta", proposta, incidente)]


def _endereco(texto):
    """Endereço IP na forma canônica, ou None se o texto não é um endereço."""
    try:
        return str(ipaddress.ip_address(texto.strip()))
    except (AttributeError, ValueError):
        return None


def _alvo_de_base(acao, alvo):
    definicao = BASE[acao]
    if definicao.tipo_de_alvo == "ip":
        endereco = _endereco(alvo)
        if endereco is None:
            raise PedidoRecusado(
                "alvo_malformado",
                f"O alvo de {acao} precisa ser um endereço IP, como 203.0.113.7. Veio {alvo!r}.",
            )
        return endereco
    usuario, arroba, dispositivo = alvo.strip().rpartition("@") if isinstance(alvo, str) else ("", "", "")
    endereco = _endereco(dispositivo)
    if not arroba or not _USUARIO.fullmatch(usuario) or endereco is None:
        raise PedidoRecusado(
            "alvo_malformado",
            f"O alvo de {acao} precisa ter o formato usuario@endereco, como admin@192.168.137.31. Veio {alvo!r}.",
        )
    return f"{usuario}@{endereco}"


def _alvo_livre(acao, alvo):
    """Alvo de ação fora da base: um texto curto, de uma linha só."""
    limpo = alvo.strip() if isinstance(alvo, str) else ""
    if not limpo or len(limpo) > _MAIOR_ALVO or not limpo.isprintable():
        raise PedidoRecusado(
            "alvo_malformado",
            f"O alvo de {acao} precisa ser um texto de uma linha, com até {_MAIOR_ALVO} caracteres, que diga "
            "sobre o que a ação age, como o endereço do dispositivo.",
        )
    return limpo


def _parametros_validos(acao, parametros):
    definicao = BASE[acao]
    aceitos = () if definicao.duracao is None else ("duracao",)
    desconhecidos = [nome for nome in parametros if nome not in aceitos]
    if desconhecidos:
        raise PedidoRecusado(
            "argumentos_invalidos",
            f"{acao} não aceita o parâmetro {', '.join(desconhecidos)}. "
            + (f"Aceita: {', '.join(aceitos)}." if aceitos else "Essa ação não tem parâmetros."),
        )
    duracao = parametros.get("duracao")
    if duracao is None:
        if definicao.duracao == "obrigatoria":
            raise PedidoRecusado("argumentos_invalidos", f"{acao} exige o parâmetro duracao, em minutos.")
        return {}
    if type(duracao) is not int or duracao < 1:
        raise PedidoRecusado(
            "argumentos_invalidos",
            f"O parâmetro duracao de {acao} é o prazo em minutos: um número inteiro, a partir de 1. Veio {duracao!r}.",
        )
    return {"duracao": duracao}


def _parametros_de_acao_nova(acao, parametros):
    try:
        return ParametrosDeAcaoNova.model_validate(parametros).model_dump(mode="json")
    except ValidationError as erro:
        campos = sorted({str(defeito["loc"][0]) if defeito["loc"] else "parametros" for defeito in erro.errors()})
        raise PedidoRecusado(
            "acao_nova_incompleta",
            f"{acao} não está no catálogo, e uma ação nova precisa trazer em parametros: descricao, passos "
            f"(lista com ao menos um passo), efeito_esperado e como_desfazer, e pode trazer fonte. "
            f"Falta ou está inválido: {', '.join(campos)}.",
        ) from None


# --- decidir, executar, desfazer e promover --------------------------------------------------


def _proposta(estado, identificador):
    if identificador not in estado.propostas:
        raise PedidoRecusado(
            "identificador_desconhecido", f"Não existe proposta com o identificador {identificador!r}."
        )
    return estado.propostas[identificador]


def _execucao_da_proposta(estado, proposta):
    return next(execucao for execucao in estado.execucoes.values() if execucao.proposta == proposta.id)


def decidir(estado, id_proposta, aprovar, canal="terminal", motivo=None):
    """Aprova ou rejeita uma proposta que aguarda aprovação.

    Não é tool: nenhum agente chega aqui. A decisão entra por um canal só da pessoa, que neste
    trabalho é o comando `python -m codigo.mcp.aprovar`.
    """
    proposta = _proposta(estado, id_proposta)
    if proposta.estado != "aguardando_aprovacao":
        situacao = {
            "rejeitada": "já foi rejeitada",
            "executada": "já foi aprovada e aplicada",
            "desfeita": "já foi aplicada e desfeita",
            "liberada": "já foi aprovada" if proposta.exige_aprovacao else "é de risco baixo e não exige aprovação",
        }[proposta.estado]
        raise PedidoRecusado("argumentos_invalidos", f"A proposta {proposta.id} {situacao}.")
    decisao = Decisao(proposta=proposta.id, canal=canal, motivo=motivo or None)
    decidida = proposta.model_copy(update={"estado": "liberada" if aprovar else "rejeitada"})
    return decidida, [novo("acao_aprovada" if aprovar else "acao_rejeitada", decisao, proposta.incidente)]


def executar(estado, id_proposta, instante):
    """Aplica no ambiente simulado a ação de uma proposta liberada."""
    proposta = _proposta(estado, id_proposta)
    if proposta.estado == "aguardando_aprovacao":
        raise PedidoRecusado(
            "proposta_nao_liberada",
            f"A proposta {proposta.id} é de risco alto e aguarda aprovação humana. Ela só pode ser executada "
            "depois que uma pessoa aprovar.",
        )
    if proposta.estado == "rejeitada":
        raise PedidoRecusado(
            "proposta_nao_liberada", f"A proposta {proposta.id} foi rejeitada e não pode ser executada."
        )
    if proposta.estado != "liberada":
        execucao = _execucao_da_proposta(estado, proposta)
        raise PedidoRecusado(
            "proposta_ja_executada",
            f"A proposta {proposta.id} já foi executada ({execucao.id}). Para aplicar a ação outra vez, "
            "registre uma nova proposta.",
        )
    execucao = Execucao(
        id=f"exec-{len(estado.execucoes) + 1:04d}",
        proposta=proposta.id,
        incidente=proposta.incidente,
        acao=proposta.acao,
        alvo=proposta.alvo,
        parametros=proposta.parametros,
        estado="aplicada",
        aplicada_em=instante,
        desfeita_em=None,
    )
    return execucao, [novo("acao_executada", execucao, proposta.incidente)]


def desfazer(estado, id_execucao, instante):
    """Reverte uma ação aplicada no ambiente simulado."""
    if id_execucao not in estado.execucoes:
        if id_execucao in estado.propostas:
            proposta = estado.propostas[id_execucao]
            if proposta.estado in ("executada", "desfeita"):
                execucao = _execucao_da_proposta(estado, proposta)
                detalhe = f"O que se desfaz é a execução: use o identificador {execucao.id}."
            else:
                detalhe = "Ela não foi aplicada: não há o que desfazer."
            raise PedidoRecusado("acao_nao_aplicada", f"{id_execucao} é uma proposta. {detalhe}")
        raise PedidoRecusado(
            "identificador_desconhecido", f"Não existe execução com o identificador {id_execucao!r}."
        )
    execucao = estado.execucoes[id_execucao]
    if execucao.estado == "desfeita":
        raise PedidoRecusado("acao_nao_aplicada", f"A execução {execucao.id} já foi desfeita.")
    desfeita = execucao.model_copy(update={"estado": "desfeita", "desfeita_em": instante})
    return desfeita, [novo("acao_desfeita", desfeita, execucao.incidente)]


def promover(estado, id_proposta):
    """Promove ao catálogo uma ação nova que foi aprovada e está aplicada.

    Como a aprovação, é uma decisão da pessoa e não uma tool. A ação promovida passa a aparecer
    no catálogo com os passos e a forma de desfazer, e continua de risco alto.
    """
    proposta = _proposta(estado, id_proposta)
    if proposta.acao in estado.promovidas:
        raise PedidoRecusado("argumentos_invalidos", f"A ação {proposta.acao} já foi promovida ao catálogo.")
    if not proposta.nova:
        raise PedidoRecusado("argumentos_invalidos", f"A ação {proposta.acao} já faz parte do catálogo de base.")
    if proposta.estado != "executada":
        raise PedidoRecusado(
            "acao_nao_aplicada",
            f"A proposta {proposta.id} só pode ser promovida depois de aprovada e aplicada, e enquanto a ação "
            "não for desfeita.",
        )
    detalhes = ParametrosDeAcaoNova.model_validate(proposta.parametros)
    acao = AcaoDoCatalogo(
        nome=proposta.acao,
        descricao=detalhes.descricao,
        alvo=f"O mesmo tipo de alvo da proposta que deu origem à ação, como {proposta.alvo}",
        parametros=[],
        regra=_REGRA_DE_RISCO_ALTO,
        origem="promovida",
        passos=detalhes.passos,
        efeito_esperado=detalhes.efeito_esperado,
        como_desfazer=detalhes.como_desfazer,
        fonte=detalhes.fonte,
    )
    return acao, [novo("catalogo_ampliado", Promocao(proposta=proposta.id, acao=acao), proposta.incidente)]
