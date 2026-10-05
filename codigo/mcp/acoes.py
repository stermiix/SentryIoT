"""Catálogo de ações, política de risco e ambiente simulado do SentryIoT.

O catálogo de base tem quatro ações. Ele é o ponto de partida do agente de decisão, não um
limite: o agente pode propor uma ação nova, fora do catálogo, desde que diga os passos e como
desfazer. A autonomia é graduada pelo risco. Ação de risco baixo é aplicada sem aprovação;
ação de risco alto e toda ação nova só são aplicadas depois que uma pessoa aprova.

O risco não sai só do nome da ação e da duração. Uma ação é de risco baixo quando o alvo faz
parte do incidente aberto, no papel que a política aceita para a ação, não é endereço
protegido, a duração cabe no prazo e o incidente ainda não atingiu o limite de medidas de risco
baixo ativas. O papel depende da ação: limitar a taxa vale para origem e para destino, e
bloquear só para origem, porque o destino é o dispositivo atacado e bloqueá-lo tira a vítima do
ar. Os números e os papéis ficam em `politica.toml`. O piso fica aqui, no código:
isolar_dispositivo, revogar_credencial e toda ação nova são sempre de risco alto.

A proposta de risco alto diz por quê: traz a lista dos motivos, cada um com um código estável e
uma frase (`tipos.MOTIVOS_DE_RISCO_ALTO`). A lista sai da mesma conta que decide o risco, e por
isso é vazia quando o risco é baixo, e só então.

Quem chama as tools é um modelo de linguagem, que pode ser enganado por conteúdo vindo da rede.
Por isso tudo o que chega é tratado como entrada: textos têm uma linha e tamanho máximo, o alvo
de uma ação de base é um endereço IP sem zona, e a mensagem de recusa nunca devolve a entrada
inteira. O log também é entrada: `reconstruir` confere cada transição, e `executar` não confia
no campo `estado` lido.

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

from pydantic import TypeAdapter, ValidationError

from codigo.mcp.eventos import LogInvalido, novo
from codigo.mcp.tipos import (
    MAIOR_NOME_DE_ACAO,
    MAXIMO_DE_PASSOS,
    MOTIVOS_DE_RISCO_ALTO,
    TEXTO_CURTO,
    TEXTO_LONGO,
    AcaoDoCatalogo,
    Ambiente,
    Decisao,
    Execucao,
    MotivoDeRiscoAlto,
    NomeDeAcao,
    ParametroDeAcao,
    ParametrosDeAcaoNova,
    Promocao,
    Proposta,
    TextoLongo,
    endereco_canonico,
    visivel,
)

POLITICA_PADRAO = Path(__file__).with_name("politica.toml")
RISCOS = ("baixo", "alto")
# Maior prazo aceito em uma proposta: um ano, em minutos. Medida para mais tempo que isso é medida
# sem prazo, e número sem teto no log é número que o leitor do log pode não conseguir ler.
MAIOR_DURACAO = 525_600
_NOME_DE_ACAO = TypeAdapter(NomeDeAcao)
_TEXTO_LONGO = TypeAdapter(TextoLongo)
# Nome de conta: sem espaço e sem nada que um interpretador de comandos trate de modo especial. Não
# começa por hífen, para nunca ser lido como opção de um comando.
_USUARIO = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}")
_MAIOR_ALVO = TEXTO_CURTO
# Quanto de um valor recebido aparece em uma mensagem de recusa.
_MAIOR_TRECHO = 60
_MAIS_NOMES = 5
_REGRA_DE_RISCO_ALTO = "Risco alto: só com aprovação humana."


def _milhar(numero):
    return f"{numero:,}".replace(",", ".")


_UMA_LINHA = f"um texto de uma linha, com até {_milhar(TEXTO_LONGO)} caracteres, sem caractere de controle"


def resumir(valor, maximo=_MAIOR_TRECHO):
    """Como um valor recebido aparece em uma mensagem: escapado e cortado.

    A mensagem de recusa volta para o agente e vai para o log. Ela nunca devolve a entrada
    inteira nem repete sequência de terminal ou quebra de linha que veio nela.
    """
    if isinstance(valor, str):
        if len(valor) <= maximo:
            return repr(valor)
        return f"{valor[:maximo]!r} (cortado: {_milhar(len(valor))} caracteres)"
    if valor is None or isinstance(valor, bool | float):
        return repr(valor)
    if isinstance(valor, int):
        # Inteiro muito grande não é convertido em texto: o Python limita essa conversão.
        return repr(valor) if valor.bit_length() <= 64 else f"um inteiro de {valor.bit_length()} bits"
    return f"um valor do tipo {type(valor).__name__}"


def _resumir_nomes(nomes):
    """Lista de nomes vindos de fora (chaves de parametros) para uma mensagem, com no máximo cinco."""
    nomes = list(nomes)
    mostrados = ", ".join(resumir(nome, 30) for nome in nomes[:_MAIS_NOMES])
    return mostrados if len(nomes) <= _MAIS_NOMES else f"{mostrados} e mais {len(nomes) - _MAIS_NOMES}"


class PedidoRecusado(Exception):
    """Um pedido que o sistema recusa, com o motivo (um dos códigos do contrato) e a mensagem.

    A mensagem é sempre de uma linha, imprimível e dentro do tamanho de um texto longo do contrato,
    mesmo que quem a montou tenha deixado passar um trecho da entrada.
    """

    def __init__(self, motivo, mensagem):
        mensagem = visivel(mensagem)[:TEXTO_LONGO]
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
# Piso do código: nenhum arquivo de política baixa o risco destas ações. Ação nova, fora da base,
# também é sempre de risco alto, mesmo depois de promovida ao catálogo.
_SEMPRE_DE_RISCO_ALTO = ("isolar_dispositivo", "revogar_credencial")
# Nomes das seções e das chaves de `politica.toml`.
_PRAZO = "prazo_maximo_de_risco_baixo"
_ALVOS = "alvos_de_risco_baixo"
# Em que papel o alvo precisa estar no incidente para a ação contar como de risco baixo. A origem
# vale sempre. O destino é o dispositivo atacado, e só vale para a ação que a política disser.
_SO_ORIGENS = "origens"
_ORIGENS_E_DESTINOS = "origens_e_destinos"
ALVOS_DE_RISCO_BAIXO = (_SO_ORIGENS, _ORIGENS_E_DESTINOS)
_LIMITES = "limites"
_MEDIDAS = "medidas_de_risco_baixo_por_incidente"
_PENDENTES = "propostas_aguardando_aprovacao_por_incidente"
_REDE = "rede"
_PROTEGIDOS = "enderecos_protegidos"
_REDES_LOCAIS = "redes_locais"


# --- política de risco -----------------------------------------------------------------------


@dataclass(frozen=True)
class Politica:
    """A política de risco, como sai de `politica.toml`."""

    # Para cada ação de base, o risco, o prazo máximo, em minutos, para ela contar como risco baixo
    # e os alvos em que o risco baixo vale: só as origens do incidente, ou as origens e os destinos.
    acoes: dict
    # Máximo de medidas de risco baixo ativas ao mesmo tempo em um incidente.
    medidas_de_risco_baixo_por_incidente: int
    # Máximo de propostas de um incidente aguardando aprovação ao mesmo tempo. A seguinte é recusada.
    propostas_aguardando_aprovacao_por_incidente: int
    # Endereços em que qualquer ação é de risco alto, na forma canônica.
    enderecos_protegidos: frozenset
    # Redes locais: o endereço de rede e o de broadcast de cada uma não são aceitos como alvo.
    redes_locais: tuple


def carregar_politica(caminho=POLITICA_PADRAO):
    """Lê o arquivo de política e devolve a política de risco.

    Arquivo com seção a mais, seção a menos ou valor fora do esperado levanta ValueError: uma
    política lida pela metade liberaria ou travaria ações sem ninguém perceber. O arquivo também
    não baixa o piso do código: as ações de `_SEMPRE_DE_RISCO_ALTO` só aceitam risco alto.
    """
    try:
        with open(caminho, "rb") as arquivo:
            lido = tomllib.load(arquivo)
    except tomllib.TOMLDecodeError as erro:
        raise ValueError(f"arquivo de política ilegível ({caminho}): {erro}") from None

    def invalida(detalhe):
        return ValueError(f"política inválida em {caminho}: {detalhe}")

    def secao(nome, chaves):
        """A seção do arquivo, conferida: é uma tabela e só tem as chaves esperadas."""
        valores = lido[nome]
        if not isinstance(valores, dict):
            raise invalida(f"{nome} precisa ser uma seção, como [{nome}]")
        desconhecidas = [chave for chave in valores if chave not in chaves]
        if desconhecidas:
            raise invalida(f"chave desconhecida em {nome}: {', '.join(desconhecidas)}")
        return valores

    def lista_de_textos(valores, chave):
        lista = valores.get(chave)
        if not isinstance(lista, list) or not all(isinstance(item, str) for item in lista):
            raise invalida(f"{chave} precisa ser uma lista de textos, que pode ser vazia")
        return lista

    faltando = [nome for nome in (*BASE, _LIMITES, _REDE) if nome not in lido]
    sobrando = [nome for nome in lido if nome not in (*BASE, _LIMITES, _REDE)]
    if faltando:
        raise invalida(
            "falta a " + ", ".join(f"{'ação' if nome in BASE else 'seção'} {nome}" for nome in faltando)
        )
    if sobrando:
        raise invalida(f"seção desconhecida ou ação fora do catálogo de base: {', '.join(sobrando)}")

    regras = {}
    for nome, definicao in BASE.items():
        regra = secao(nome, ("risco", _PRAZO, _ALVOS))
        if regra.get("risco") not in RISCOS:
            raise invalida(f"o risco de {nome} precisa ser baixo ou alto, e veio {regra.get('risco')!r}")
        if nome in _SEMPRE_DE_RISCO_ALTO and regra["risco"] != "alto":
            raise invalida(f"{nome} é sempre de risco alto: esse piso está no código, e a política não o baixa")
        prazo = regra.get(_PRAZO)
        if prazo is not None:
            if definicao.duracao is None:
                raise invalida(f"{nome} não aceita prazo, então não pode ter {_PRAZO}")
            if type(prazo) is not int or not 1 <= prazo <= MAIOR_DURACAO:
                raise invalida(
                    f"{_PRAZO} de {nome} precisa ser um número inteiro de minutos, de 1 a {MAIOR_DURACAO}"
                )
        elif regra["risco"] == "baixo":
            # Sem prazo máximo, a medida de risco baixo não teria teto de duração.
            raise invalida(f"{nome} é de risco baixo e precisa de {_PRAZO}, em minutos")
        alvos = regra.get(_ALVOS)
        if alvos is not None:
            if nome in _SEMPRE_DE_RISCO_ALTO:
                raise invalida(f"{nome} é sempre de risco alto, então não pode ter {_ALVOS}")
            if alvos not in ALVOS_DE_RISCO_BAIXO:
                raise invalida(
                    f"{_ALVOS} de {nome} precisa ser {' ou '.join(map(repr, ALVOS_DE_RISCO_BAIXO))}, e veio {alvos!r}"
                )
        elif regra["risco"] == "baixo":
            # Sem a regra escrita, bloquear o dispositivo atacado poderia passar por medida de risco baixo.
            raise invalida(
                f"{nome} é de risco baixo e precisa de {_ALVOS}: {' ou '.join(map(repr, ALVOS_DE_RISCO_BAIXO))}"
            )
        regras[nome] = {"risco": regra["risco"], _PRAZO: prazo, _ALVOS: alvos}

    limites = secao(_LIMITES, (_MEDIDAS, _PENDENTES))
    medidas = limites.get(_MEDIDAS)
    if type(medidas) is not int or medidas < 0:
        raise invalida(f"{_MEDIDAS} precisa ser um número inteiro, a partir de 0")
    pendentes = limites.get(_PENDENTES)
    # Com zero, nenhuma proposta de risco alto chegaria à pessoa.
    if type(pendentes) is not int or pendentes < 1:
        raise invalida(f"{_PENDENTES} precisa ser um número inteiro, a partir de 1")

    rede = secao(_REDE, (_PROTEGIDOS, _REDES_LOCAIS))
    protegidos, redes = [], []
    for texto in lista_de_textos(rede, _PROTEGIDOS):
        try:
            protegidos.append(endereco_canonico(texto.strip()))
        except ValueError:
            raise invalida(f"{_PROTEGIDOS} traz {texto!r}, que não é um endereço IP") from None
    for texto in lista_de_textos(rede, _REDES_LOCAIS):
        try:
            redes.append(ipaddress.ip_network(texto.strip()))
        except ValueError:
            raise invalida(
                f"{_REDES_LOCAIS} traz {texto!r}, que não é uma rede no formato endereço/prefixo, como 192.168.137.0/24"
            ) from None
    return Politica(
        acoes=regras,
        medidas_de_risco_baixo_por_incidente=medidas,
        propostas_aguardando_aprovacao_por_incidente=pendentes,
        enderecos_protegidos=frozenset(protegidos),
        redes_locais=tuple(redes),
    )


def _motivos_de_risco_alto(estado, politica, incidente, acao, alvo, parametros):
    """Os códigos dos motivos pelos quais aplicar agora a ação no incidente é de risco alto.

    Sem motivo, o risco é baixo. O nome da ação e a duração não bastam para isso: bloquear por 10
    minutos o gateway, o dispositivo atacado ou um endereço que não tem relação com o incidente
    não é uma medida de risco baixo. Saem todos os motivos que valem, na ordem da tabela do
    contrato, para a pessoa que decide ver o quadro inteiro.
    """
    if acao not in BASE:
        # Ação nova ou promovida: é sempre de risco alto, e o alvo é texto livre, sem o que conferir.
        return ["acao_sempre_de_risco_alto" if acao in estado.promovidas else "acao_nova"]
    regra = politica.acoes[acao]
    # O alvo de revogar_credencial é usuario@endereco: o que se compara com o incidente é o endereço.
    endereco = alvo.rpartition("@")[2]
    origens, destinos = _enderecos_do_incidente(estado, incidente)
    valem = set()
    # O piso do código, que nenhuma política baixa, e a ação que a política marca como de risco alto.
    if acao in _SEMPRE_DE_RISCO_ALTO or regra["risco"] != "baixo":
        valem.add("acao_sempre_de_risco_alto")
    else:
        # As três condições seguintes só existem na ação que pode ser de risco baixo.
        duracao = parametros.get("duracao")
        if regra[_PRAZO] is None or type(duracao) is not int or duracao > regra[_PRAZO]:
            valem.add("prazo_acima_do_limite")
        # O endereço que é destino do incidente é o dispositivo atacado, mesmo que também apareça entre
        # as origens (as respostas dele ao ataque saem dele). Só a ação que aceita destino o trata como
        # alvo de risco baixo.
        if endereco in destinos and regra[_ALVOS] != _ORIGENS_E_DESTINOS:
            valem.add("alvo_e_destino_do_incidente")
        if _medidas_de_risco_baixo(estado, incidente) >= politica.medidas_de_risco_baixo_por_incidente:
            valem.add("orcamento_de_risco_baixo_esgotado")
    # O que se diz do alvo vale para toda ação de base, inclusive a que já é sempre de risco alto: quem
    # aprova o isolamento de um dispositivo precisa saber que ele é o gateway, ou que é alheio ao incidente.
    if endereco not in origens and endereco not in destinos:
        valem.add("alvo_fora_do_incidente")
    if endereco in politica.enderecos_protegidos:
        valem.add("alvo_protegido")
    return [codigo for codigo in MOTIVOS_DE_RISCO_ALTO if codigo in valem]


def _enderecos_do_incidente(estado, incidente):
    """As origens e os destinos do incidente, na última versão dele. Incidente encerrado não tem alvo."""
    ocorrido = estado.incidentes.get(incidente)
    if ocorrido is None or ocorrido.estado != "aberto":
        return frozenset(), frozenset()
    return (
        frozenset(item.endereco for item in ocorrido.origens),
        frozenset(item.endereco for item in ocorrido.destinos),
    )


def _medidas_de_risco_baixo(estado, incidente):
    """Quantas medidas aplicadas sem aprovação humana estão ativas no incidente."""
    return sum(
        1 for execucao in estado.execucoes.values()
        if execucao.incidente == incidente and execucao.estado == "aplicada"
        and execucao.proposta not in estado.aprovadas
    )


def _regra(politica, acao):
    regra = politica.acoes[acao]
    if acao in _SEMPRE_DE_RISCO_ALTO or regra["risco"] == "alto":
        return _REGRA_DE_RISCO_ALTO
    sem_prazo = "sem duracao, " if BASE[acao].duracao == "opcional" else ""
    if regra[_ALVOS] == _ORIGENS_E_DESTINOS:
        papel, destino = "origem ou destino", ""
    else:
        papel, destino = "origem", "alvo que é destino do incidente, isto é, o dispositivo atacado, "
    return (
        f"Risco baixo quando o alvo é {papel} do incidente, a duracao é de até {regra[_PRAZO]} "
        f"minutos e o incidente tem menos de {politica.medidas_de_risco_baixo_por_incidente} medidas de risco "
        f"baixo ativas: o agente de execução aplica sem aprovação. Fora disso ({sem_prazo}duracao maior, alvo "
        f"que não consta do incidente, {destino}endereço protegido pela política ou limite de medidas atingido), "
        "risco alto: só com aprovação humana."
    )


def _motivo_de_endereco_recusado(politica, endereco):
    """Por que o endereço não pode ser alvo de ação nenhuma, ou None se ele pode.

    São os endereços que não designam um dispositivo da rede: agir sobre eles atinge a própria
    máquina ou todos os dispositivos de uma vez.
    """
    ip = ipaddress.ip_address(endereco)
    if ip.is_loopback:
        return "é um endereço de loopback, que designa a própria máquina"
    if ip.is_unspecified:
        return "é o endereço não especificado"
    if ip.is_multicast:
        return "é um endereço de multicast"
    if ip.is_link_local:
        return "é um endereço de link-local"
    if endereco == "255.255.255.255":
        return "é o endereço de broadcast"
    for rede in politica.redes_locais:
        # Só rede IPv4 com mais de dois endereços tem endereço de rede e de broadcast.
        if rede.version == 4 and rede.prefixlen < 31 and ip in (rede.network_address, rede.broadcast_address):
            return f"é o endereço de rede ou de broadcast de {rede}"
    return None


def _conferir_alvo_permitido(politica, acao, alvo):
    """Recusa o alvo de uma ação de base quando o endereço dele é um dos endereços especiais."""
    endereco = alvo.rpartition("@")[2]
    motivo = _motivo_de_endereco_recusado(politica, endereco)
    if motivo is not None:
        raise PedidoRecusado(
            "alvo_nao_permitido",
            f"O alvo de {acao} não pode ser {endereco}: {motivo}. O alvo é o endereço de um dispositivo.",
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
    # Identificadores das propostas que têm o evento de aprovação de uma pessoa.
    aprovadas: set = field(default_factory=set)


class _Violacao(Exception):
    """Um evento que não cabe no ponto do log em que aparece."""


def _exigir(condicao, detalhe):
    if not condicao:
        raise _Violacao(detalhe)


def _citado(colecao, identificador, o_que):
    """O item que o evento cita. Citar o que não existe é violação, e não KeyError."""
    _exigir(identificador in colecao, f"{o_que} {identificador} não existe no log até este ponto")
    return colecao[identificador]


def reconstruir(eventos):
    """Percorre os eventos na ordem do log e devolve o estado em que eles deixam o sistema.

    O log é entrada, e não memória confiável: cada evento precisa caber no ponto em que aparece.
    Identificador de proposta e de execução é único; aprovação e rejeição só valem para proposta
    que aguarda aprovação; execução só vale para proposta liberada ou aprovada, e precisa ser a
    execução daquela proposta; nenhum evento cita proposta ou execução que não existe. A proposta
    precisa nascer no estado que o risco dela pede, e o incidente não reabre depois de encerrado.

    Qualquer violação levanta `LogInvalido`, com o arquivo e a linha quando os eventos vieram de
    um arquivo. O que esta conferência não alcança está no README: quem consegue escrever uma
    linha bem formada no arquivo consegue aprovar.
    """
    estado = Estado()
    for indice, evento in enumerate(eventos):
        try:
            _aplicar(estado, evento)
        except _Violacao as violacao:
            onde = eventos.onde(indice) if hasattr(eventos, "onde") else f"evento {indice + 1} ({evento.id})"
            raise LogInvalido(visivel(f"{onde}: {evento.tipo} fora de lugar: {violacao}")) from None
    return estado


def _aplicar(estado, evento):
    """Confere se o evento cabe no estado e, se couber, aplica o que ele diz."""
    dados = evento.dados

    def mudar_proposta(identificador, novo_estado):
        proposta = estado.propostas[identificador]
        estado.propostas[identificador] = proposta.model_copy(update={"estado": novo_estado})

    match evento.tipo:
        case "incidente_aberto":
            _exigir(dados.id not in estado.incidentes, f"o incidente {dados.id} já foi aberto")
            _exigir(dados.estado == "aberto", f"o incidente {dados.id} é aberto com o estado {dados.estado}")
            estado.incidentes[dados.id] = dados
        case "incidente_atualizado" | "incidente_encerrado":
            _exigir(dados.id in estado.incidentes, f"o incidente {dados.id} não foi aberto")
            _exigir(estado.incidentes[dados.id].estado == "aberto", f"o incidente {dados.id} já está encerrado")
            esperado = "encerrado" if evento.tipo == "incidente_encerrado" else "aberto"
            _exigir(dados.estado == esperado, f"o incidente {dados.id} vem com o estado {dados.estado}")
            estado.incidentes[dados.id] = dados
        case "acao_proposta":
            _conferir_proposta_nova(estado, dados)
            estado.propostas[dados.id] = dados
        case "acao_aprovada" | "acao_rejeitada":
            proposta = _citado(estado.propostas, dados.proposta, "a proposta")
            _exigir(
                proposta.estado == "aguardando_aprovacao",
                f"a proposta {proposta.id} não aguarda aprovação: está {proposta.estado}",
            )
            if evento.tipo == "acao_aprovada":
                estado.aprovadas.add(proposta.id)
            mudar_proposta(proposta.id, "liberada" if evento.tipo == "acao_aprovada" else "rejeitada")
        case "acao_executada":
            proposta = _citado(estado.propostas, dados.proposta, "a proposta")
            _exigir(dados.id not in estado.execucoes, f"a execução {dados.id} já existe")
            _exigir(
                proposta.estado == "liberada",
                f"a proposta {proposta.id} não está liberada nem aprovada: está {proposta.estado}",
            )
            _exigir(
                (dados.incidente, dados.acao, dados.alvo, dados.parametros, dados.estado)
                == (proposta.incidente, proposta.acao, proposta.alvo, proposta.parametros, "aplicada"),
                f"a execução {dados.id} não é a aplicação do que a proposta {proposta.id} descreve",
            )
            estado.execucoes[dados.id] = dados
            mudar_proposta(proposta.id, "executada")
        case "acao_desfeita":
            aplicada = _citado(estado.execucoes, dados.id, "a execução")
            _exigir(aplicada.estado == "aplicada", f"a execução {dados.id} já foi desfeita")
            _exigir(
                dados == aplicada.model_copy(update={"estado": "desfeita", "desfeita_em": dados.desfeita_em})
                and dados.desfeita_em is not None,
                f"a execução {dados.id} desfeita não é a mesma que foi aplicada",
            )
            estado.execucoes[dados.id] = dados
            mudar_proposta(dados.proposta, "desfeita")
        case "efeito_verificado":
            _citado(estado.execucoes, dados.execucao, "a execução")
            estado.efeitos[dados.execucao] = dados
        case "recomendacao_emitida":
            for citada in dados.propostas:
                _citado(estado.propostas, citada, "a proposta")
        case "catalogo_ampliado":
            proposta = _citado(estado.propostas, dados.proposta, "a proposta")
            nome = dados.acao.nome
            _exigir(nome not in BASE and nome not in estado.promovidas, f"a ação {nome} já está no catálogo")
            _exigir(
                proposta.nova and proposta.estado == "executada" and nome == proposta.acao
                and dados.acao.origem == "promovida",
                f"a proposta {proposta.id} não é de uma ação nova aplicada, com o nome {nome}",
            )
            estado.promovidas[nome] = dados.acao


def _conferir_proposta_nova(estado, proposta):
    """Uma proposta só entra no estado como `propor` a teria criado.

    O campo `estado` gravado não é aceito como veio: uma linha escrita por fora com a proposta já
    liberada, ou com o risco de uma ação de risco alto trocado para baixo, é violação.
    """
    _exigir(proposta.id not in estado.propostas, f"a proposta {proposta.id} já existe")
    _exigir(
        proposta.incidente in estado.incidentes,
        f"a proposta {proposta.id} cita o incidente {proposta.incidente}, que não existe no log até este ponto",
    )
    de_risco_alto = proposta.risco == "alto"
    _exigir(
        proposta.exige_aprovacao == de_risco_alto,
        f"a proposta {proposta.id} tem risco {proposta.risco} e exige_aprovacao {proposta.exige_aprovacao}",
    )
    inicial = "aguardando_aprovacao" if de_risco_alto else "liberada"
    _exigir(
        proposta.estado == inicial,
        f"a proposta {proposta.id}, de risco {proposta.risco}, nasce como {inicial}, e não como {proposta.estado}",
    )
    _exigir(
        de_risco_alto or (proposta.acao in BASE and proposta.acao not in _SEMPRE_DE_RISCO_ALTO),
        f"{proposta.acao} é sempre de risco alto, e a proposta {proposta.id} vem como de risco baixo",
    )
    _exigir(
        proposta.nova == (proposta.acao not in BASE and proposta.acao not in estado.promovidas),
        f"a proposta {proposta.id} vem com nova = {proposta.nova}, o que não confere com o catálogo",
    )
    # Os motivos são texto do sistema na tela de aprovação: existem se e só se o risco é alto, não se
    # repetem e trazem a frase do contrato, e não outra.
    codigos = [motivo.codigo for motivo in proposta.motivos_de_risco_alto]
    _exigir(
        bool(codigos) == de_risco_alto,
        f"a proposta {proposta.id} é de risco {proposta.risco} e "
        + ("traz motivo de risco alto" if codigos else "não traz nenhum motivo de risco alto"),
    )
    _exigir(len(set(codigos)) == len(codigos), f"a proposta {proposta.id} repete um motivo de risco alto")
    _exigir(
        all(motivo.descricao == MOTIVOS_DE_RISCO_ALTO[motivo.codigo] for motivo in proposta.motivos_de_risco_alto),
        f"a proposta {proposta.id} traz um motivo de risco alto com uma frase que não é a do contrato",
    )


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
            descricao=f"Prazo da medida, em minutos (número inteiro, de 1 a {_milhar(MAIOR_DURACAO)})",
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

    Devolve a proposta, com o nível de risco, os motivos quando o risco é alto e se ela exige
    aprovação, e o rascunho do evento `acao_proposta`. Não aplica nada: proposta de risco baixo
    já nasce liberada para o agente de execução, e a de risco alto fica aguardando a decisão de
    uma pessoa.

    Alvo que não consta do incidente, endereço protegido e limite de medidas atingido não são
    motivo de recusa: a proposta é registrada como de risco alto, e quem decide é a pessoa.

    A fila da pessoa tem teto. A proposta de risco alto é recusada quando o incidente já tem o
    máximo de propostas aguardando aprovação que a política aceita.
    """
    if not isinstance(incidente, str) or incidente not in estado.incidentes:
        raise PedidoRecusado(
            "identificador_desconhecido", f"Não existe incidente com o identificador {resumir(incidente)}."
        )
    if estado.incidentes[incidente].estado != "aberto":
        raise PedidoRecusado(
            "incidente_encerrado", f"O incidente {incidente} está encerrado e não recebe novas propostas."
        )
    justificativa = _justificativa(justificativa)
    if not isinstance(parametros, dict):
        raise PedidoRecusado("argumentos_invalidos", "O campo parametros precisa ser um objeto.")
    if not isinstance(acao, str):
        raise PedidoRecusado("argumentos_invalidos", f"O nome da ação precisa ser um texto. Veio {resumir(acao)}.")

    if acao in BASE:
        alvo = _alvo_de_base(acao, alvo)
        _conferir_alvo_permitido(politica, acao, alvo)
        parametros = _parametros_validos(acao, parametros)
    elif acao in estado.promovidas:
        # Os passos e a forma de desfazer são os do catálogo: a pessoa aprova o que foi promovido,
        # e não uma variação com o mesmo nome. Por isso a proposta não aceita parâmetro nenhum.
        if parametros:
            raise PedidoRecusado(
                "argumentos_invalidos",
                f"{acao} foi promovida ao catálogo e é proposta sem parâmetros: os passos e a forma de "
                f"desfazer são os do catálogo. Veio: {_resumir_nomes(parametros)}.",
            )
        alvo = _alvo_livre(acao, alvo)
        promovida = estado.promovidas[acao]
        parametros = {
            "descricao": promovida.descricao,
            "passos": promovida.passos,
            "efeito_esperado": promovida.efeito_esperado,
            "como_desfazer": promovida.como_desfazer,
            "fonte": promovida.fonte,
        }
    else:
        try:
            _NOME_DE_ACAO.validate_python(acao)
        except ValidationError:
            raise PedidoRecusado(
                "argumentos_invalidos",
                f"O nome de uma ação nova usa só letras minúsculas sem acento, números e sublinhado, começa por "
                f"letra e tem até {MAIOR_NOME_DE_ACAO} caracteres, como ativar_syn_cookies. Veio {resumir(acao)}.",
            ) from None
        alvo = _alvo_livre(acao, alvo)
        parametros = _parametros_de_acao_nova(acao, parametros)

    motivos = _motivos_de_risco_alto(estado, politica, incidente, acao, alvo, parametros)
    if motivos:
        _conferir_fila_de_aprovacao(estado, politica, incidente)
    proposta = Proposta(
        id=f"prop-{len(estado.propostas) + 1:04d}",
        incidente=incidente,
        acao=acao,
        alvo=alvo,
        parametros=parametros,
        justificativa=justificativa,
        nova=acao not in BASE and acao not in estado.promovidas,
        risco="alto" if motivos else "baixo",
        motivos_de_risco_alto=[
            MotivoDeRiscoAlto(codigo=codigo, descricao=MOTIVOS_DE_RISCO_ALTO[codigo]) for codigo in motivos
        ],
        exige_aprovacao=bool(motivos),
        estado="aguardando_aprovacao" if motivos else "liberada",
    )
    return proposta, [novo("acao_proposta", proposta, incidente)]


def _conferir_fila_de_aprovacao(estado, politica, incidente):
    """Recusa a proposta de risco alto quando a fila de aprovação do incidente está no teto.

    Sem o teto, um agente enganado por conteúdo vindo da rede poderia registrar propostas sem
    parar: a pessoa teria de ler todas, e o log cresceria sem limite. A conferência vem depois das
    outras: o pedido malformado continua recusado pelo próprio defeito.
    """
    pendentes = sum(
        1 for proposta in estado.propostas.values()
        if proposta.incidente == incidente and proposta.estado == "aguardando_aprovacao"
    )
    if pendentes >= politica.propostas_aguardando_aprovacao_por_incidente:
        quantas = "1 proposta" if pendentes == 1 else f"{pendentes} propostas"
        raise PedidoRecusado(
            "limite_de_propostas_pendentes",
            f"O incidente {incidente} já tem {quantas} aguardando aprovação, que é o máximo aceito pela "
            "política, e esta proposta não foi registrada. Uma nova proposta de risco alto só entra depois que "
            "uma pessoa aprovar ou rejeitar alguma das pendentes.",
        )


def _justificativa(justificativa):
    try:
        return _TEXTO_LONGO.validate_python(justificativa)
    except ValidationError:
        raise PedidoRecusado(
            "argumentos_invalidos", f"A proposta precisa de uma justificativa: {_UMA_LINHA}."
        ) from None


def _endereco(texto):
    """Endereço IP na forma canônica, ou None se o texto não é um endereço que o sistema aceita.

    Não aceita zona de IPv6 (`fe80::1%eth0`): o que vem depois de `%` é texto livre, e o alvo de
    uma ação acaba como argumento de um comando no servidor de verdade.
    """
    if not isinstance(texto, str) or len(texto) > _MAIOR_ALVO:
        return None
    try:
        return endereco_canonico(texto.strip())
    except ValueError:
        return None


def _alvo_de_base(acao, alvo):
    definicao = BASE[acao]
    if definicao.tipo_de_alvo == "ip":
        endereco = _endereco(alvo)
        if endereco is None:
            raise PedidoRecusado(
                "alvo_malformado",
                f"O alvo de {acao} precisa ser um endereço IP, sem zona, como 203.0.113.7. Veio {resumir(alvo)}.",
            )
        return endereco
    cabe = isinstance(alvo, str) and len(alvo) <= _MAIOR_ALVO
    usuario, arroba, dispositivo = alvo.strip().rpartition("@") if cabe else ("", "", "")
    endereco = _endereco(dispositivo)
    if not arroba or not _USUARIO.fullmatch(usuario) or endereco is None:
        raise PedidoRecusado(
            "alvo_malformado",
            f"O alvo de {acao} precisa ter o formato usuario@endereco, como admin@192.168.137.31. O usuário usa "
            f"letras sem acento, números, ponto, hífen e sublinhado, e não começa por ponto nem por hífen. "
            f"Veio {resumir(alvo)}.",
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
            f"{acao} não aceita o parâmetro {_resumir_nomes(desconhecidos)}. "
            + (f"Aceita: {', '.join(aceitos)}." if aceitos else "Essa ação não tem parâmetros."),
        )
    duracao = parametros.get("duracao")
    if duracao is None:
        if definicao.duracao == "obrigatoria":
            raise PedidoRecusado("argumentos_invalidos", f"{acao} exige o parâmetro duracao, em minutos.")
        return {}
    if type(duracao) is not int or not 1 <= duracao <= MAIOR_DURACAO:
        raise PedidoRecusado(
            "argumentos_invalidos",
            f"O parâmetro duracao de {acao} é o prazo em minutos: um número inteiro, de 1 a "
            f"{_milhar(MAIOR_DURACAO)} (um ano). Veio {resumir(duracao)}.",
        )
    return {"duracao": duracao}


def _parametros_de_acao_nova(acao, parametros):
    try:
        return ParametrosDeAcaoNova.model_validate(parametros).model_dump(mode="json")
    except ValidationError as erro:
        # O nome de um campo a mais vem do agente: entra na mensagem escapado e cortado.
        defeitos = {defeito["loc"][0] if defeito["loc"] else "parametros" for defeito in erro.errors()}
        conhecidos = sorted(campo for campo in defeitos if campo in ParametrosDeAcaoNova.model_fields)
        a_mais = sorted(str(campo) for campo in defeitos if campo not in ParametrosDeAcaoNova.model_fields)
        campos = ", ".join(filter(None, [", ".join(conhecidos), _resumir_nomes(a_mais) if a_mais else ""]))
        raise PedidoRecusado(
            "acao_nova_incompleta",
            f"{acao} não está no catálogo, e uma ação nova precisa trazer em parametros: descricao, passos "
            f"(lista de 1 a {MAXIMO_DE_PASSOS} passos), efeito_esperado e como_desfazer, e pode trazer fonte. "
            f"Cada um é {_UMA_LINHA}; a fonte tem até {TEXTO_CURTO}. Falta ou está inválido: {campos}.",
        ) from None


# --- decidir, executar, desfazer e promover --------------------------------------------------


def _proposta(estado, identificador):
    if not isinstance(identificador, str) or identificador not in estado.propostas:
        raise PedidoRecusado(
            "identificador_desconhecido", f"Não existe proposta com o identificador {resumir(identificador)}."
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
    try:
        decisao = Decisao(proposta=proposta.id, canal=canal, motivo=motivo or None)
    except ValidationError:
        raise PedidoRecusado("argumentos_invalidos", f"O motivo da decisão precisa ser {_UMA_LINHA}.") from None
    decidida = proposta.model_copy(update={"estado": "liberada" if aprovar else "rejeitada"})
    return decidida, [novo("acao_aprovada" if aprovar else "acao_rejeitada", decisao, proposta.incidente)]


def executar(estado, politica, id_proposta, instante):
    """Aplica no ambiente simulado a ação de uma proposta liberada.

    O campo `estado` da proposta, que veio do log, não basta para liberar. Proposta que exige
    aprovação só executa se o log tiver o evento de aprovação dela. Proposta registrada como de
    risco baixo tem o risco calculado de novo, com a política e o estado de agora: se o prazo
    da política diminuiu, se o alvo virou endereço protegido, se o incidente encerrou ou se o
    limite de medidas foi atingido, ela não executa sem passar por uma pessoa.
    """
    proposta = _proposta(estado, id_proposta)
    if proposta.estado == "rejeitada":
        raise PedidoRecusado(
            "proposta_nao_liberada", f"A proposta {proposta.id} foi rejeitada e não pode ser executada."
        )
    if proposta.estado in ("executada", "desfeita"):
        execucao = _execucao_da_proposta(estado, proposta)
        raise PedidoRecusado(
            "proposta_ja_executada",
            f"A proposta {proposta.id} já foi executada ({execucao.id}). Para aplicar a ação outra vez, "
            "registre uma nova proposta.",
        )
    if proposta.id not in estado.aprovadas:
        if proposta.exige_aprovacao or proposta.estado != "liberada":
            raise PedidoRecusado(
                "proposta_nao_liberada",
                f"A proposta {proposta.id} é de risco alto e aguarda aprovação humana. Ela só pode ser executada "
                "depois que uma pessoa aprovar.",
            )
        if _risco_de_agora(estado, politica, proposta) == "alto":
            raise PedidoRecusado(
                "proposta_nao_liberada",
                f"A proposta {proposta.id} foi registrada como de risco baixo, mas pelas regras de agora ela é de "
                "risco alto: mudou a política, o incidente encerrou ou o limite de medidas de risco baixo do "
                "incidente foi atingido. Registre uma nova proposta, que passará pela aprovação humana.",
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


def _risco_de_agora(estado, politica, proposta):
    """O risco da proposta calculado de novo, como se ela fosse feita agora. Na dúvida, alto."""
    if proposta.acao not in BASE:
        return "alto"
    try:
        # O alvo e os parâmetros são lidos de novo, como entrada: têm de sair iguais ao que está gravado.
        alvo = _alvo_de_base(proposta.acao, proposta.alvo)
        _conferir_alvo_permitido(politica, proposta.acao, alvo)
        parametros = _parametros_validos(proposta.acao, proposta.parametros)
    except PedidoRecusado:
        return "alto"
    if (alvo, parametros) != (proposta.alvo, proposta.parametros):
        return "alto"
    motivos = _motivos_de_risco_alto(estado, politica, proposta.incidente, proposta.acao, alvo, parametros)
    return "alto" if motivos else "baixo"


def desfazer(estado, id_execucao, instante):
    """Reverte uma ação aplicada no ambiente simulado."""
    if not isinstance(id_execucao, str) or id_execucao not in estado.execucoes:
        if isinstance(id_execucao, str) and id_execucao in estado.propostas:
            proposta = estado.propostas[id_execucao]
            if proposta.estado in ("executada", "desfeita"):
                execucao = _execucao_da_proposta(estado, proposta)
                detalhe = f"O que se desfaz é a execução: use o identificador {execucao.id}."
            else:
                detalhe = "Ela não foi aplicada: não há o que desfazer."
            raise PedidoRecusado("acao_nao_aplicada", f"{id_execucao} é uma proposta. {detalhe}")
        raise PedidoRecusado(
            "identificador_desconhecido", f"Não existe execução com o identificador {resumir(id_execucao)}."
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
