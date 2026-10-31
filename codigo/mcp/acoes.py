"""Catálogo de ações, política de risco e ambiente simulado do SentryIoT.

O catálogo de base tem cinco ações. Ele é o ponto de partida do agente de decisão, não um
limite: o agente pode propor uma ação nova, fora do catálogo, desde que diga os passos e como
desfazer. A autonomia é graduada pelo risco. Ação de risco baixo é aplicada sem aprovação;
ação de risco alto e toda ação nova só são aplicadas depois que uma pessoa aprova.

O risco não sai só do nome da ação e da duração. Uma ação é de risco baixo quando o alvo faz
parte do incidente aberto, no papel que a política aceita para a ação, não é endereço protegido
nem crítico, a duração cabe no prazo e nem o incidente nem o sistema todo atingiram o limite de
medidas de risco baixo ativas. O papel depende da ação: limitar a taxa vale para origem e para
destino, e bloquear só para origem fora da rede local, porque o destino é o dispositivo atacado,
bloqueá-lo tira a vítima do ar, e a origem de um flood é forjável. Os números e os papéis ficam
em `politica.toml`. O piso fica aqui, no código: isolar_dispositivo, revogar_credencial,
fechar_porta e toda ação nova são sempre de risco alto.

O agente de decisão não conhece endereço (arquitetura híbrida). Cada endereço do incidente ganha
um rótulo neutro (`origem-1`, `destino-1`), o resumo que ele lê é montado aqui, sem endereço, e
`propor` troca o rótulo do alvo pelo endereço antes de calcular o risco.

A proposta de risco alto diz por quê: traz a lista dos motivos, cada um com um código estável e
uma frase (`tipos.MOTIVOS_DE_RISCO_ALTO`). A lista sai da mesma conta que decide o risco, e por
isso é vazia quando o risco é baixo, e só então.

Quem chama as tools é um modelo de linguagem, que pode ser enganado por conteúdo vindo da rede.
Por isso tudo o que chega é tratado como entrada: textos têm uma linha, tamanho máximo e só
caracteres visíveis, o alvo de uma ação de base é um endereço IP sem zona ou o rótulo dele, e a
mensagem de recusa nunca devolve a entrada inteira. O log também é entrada: `reconstruir` confere cada transição, e `executar` não confia
no campo `estado` lido.

Nada aqui toca a rede: aplicar uma ação é registrar um evento no log. O estado das propostas,
das aprovações e das medidas ativas é sempre reconstruído a partir dos eventos (`reconstruir`),
e as funções deste módulo não gravam nada. Elas recebem o estado e devolvem o resultado e os
rascunhos dos eventos, que quem chamou grava com `eventos.Registro`.
"""
import getpass
import ipaddress
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

try:
    import pwd
except ImportError:  # No Windows não existe pwd: o nome vem de getpass.
    pwd = None

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
    AtacanteApontado,
    AtacanteRotulado,
    Decisao,
    EnderecoRotulado,
    Execucao,
    MarcaDeResolvido,
    MotivoDeRiscoAlto,
    NomeDeAcao,
    ParametroDeAcao,
    ParametrosDeAcaoNova,
    PortaRotulada,
    Promocao,
    Proposta,
    ResumoDoIncidente,
    TextoLongo,
    endereco_canonico,
    invisivel,
    mascarar_enderecos,
    tem_endereco,
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
# Folga do primeiro corte de um valor grande, antes do filtro de endereços: maior que o maior
# endereço escrito por extenso (45 caracteres).
_FOLGA_DO_CORTE = 64
_MAIS_NOMES = 5
_REGRA_DE_RISCO_ALTO = "Risco alto: só com aprovação humana."


def _milhar(numero):
    return f"{numero:,}".replace(",", ".")


_UMA_LINHA = (
    f"um texto de uma linha, com até {_milhar(TEXTO_LONGO)} caracteres, sem caractere de controle nem caractere "
    "que não aparece na tela"
)


def resumir(valor, maximo=_MAIOR_TRECHO):
    """Como um valor recebido aparece em uma mensagem: sem endereço, escapado e cortado.

    A mensagem de recusa volta para o agente e vai para o log. Ela nunca devolve a entrada
    inteira nem repete sequência de terminal ou quebra de linha que veio nela. O filtro de
    endereços vem antes do corte final: nenhum pedaço de endereço sobra dele.

    O valor chega sem teto e a mensagem é montada com o log travado. Por isso o valor grande é
    cortado primeiro com folga, maior que qualquer endereço, e só a janela passa pelo filtro, que
    troca também o pedaço de endereço que o corte deixar no fim dela. O tamanho contado é o do valor
    recebido, que é o texto do próprio agente: o endereço resolvido de um rótulo não passa por aqui.
    """
    if isinstance(valor, str):
        if len(valor) > maximo + _FOLGA_DO_CORTE:
            janela = mascarar_enderecos(valor[:maximo + _FOLGA_DO_CORTE], cortado_no_fim=True)
            return f"{janela[:maximo]!r} (cortado: {_milhar(len(valor))} caracteres)"
        valor = mascarar_enderecos(valor)
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
        # Guardada antes do corte, para que um filtro aplicado depois (o da linha de decisão) venha
        # antes do corte, e não sobre um pedaço.
        self.inteira = mensagem
        mensagem = visivel(mensagem)[:TEXTO_LONGO]
        super().__init__(mensagem)
        self.motivo = motivo
        self.mensagem = mensagem


@dataclass(frozen=True)
class _AcaoDeBase:
    descricao: str
    alvo: str
    # Como o alvo é escrito na linha de decisão, que só conhece os rótulos neutros do incidente.
    alvo_com_rotulo: str
    # "ip", "credencial" ou "porta": o formato que o alvo precisa ter.
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
        alvo_com_rotulo="Rótulo de uma origem ou de um destino do incidente, como origem-1 ou destino-1",
        tipo_de_alvo="ip",
        duracao="obrigatoria",
        grupo="limites",
        como_desfazer="Retirar o limite com desfazer_acao.",
    ),
    "bloquear_ip": _AcaoDeBase(
        descricao="Bloqueia o tráfego vindo de um endereço de origem.",
        alvo="Endereço IP de origem, como 203.0.113.7",
        alvo_com_rotulo="Rótulo de uma origem do incidente, como origem-1",
        tipo_de_alvo="ip",
        duracao="opcional",
        grupo="bloqueios",
        como_desfazer="Retirar o bloqueio com desfazer_acao.",
    ),
    "isolar_dispositivo": _AcaoDeBase(
        descricao="Isola um dispositivo do restante da rede.",
        alvo="Endereço IP do dispositivo, como 192.168.137.20",
        alvo_com_rotulo="Rótulo do dispositivo no incidente, como destino-1",
        tipo_de_alvo="ip",
        duracao=None,
        grupo="isolamentos",
        como_desfazer="Devolver o dispositivo à rede com desfazer_acao.",
    ),
    "revogar_credencial": _AcaoDeBase(
        descricao="Revoga a credencial de uma conta em um dispositivo.",
        alvo="Conta e dispositivo, no formato usuario@endereco, como admin@192.168.137.31",
        alvo_com_rotulo="Conta e dispositivo, no formato usuario@rotulo, como admin@destino-1",
        tipo_de_alvo="credencial",
        duracao=None,
        grupo="credenciais_revogadas",
        como_desfazer="Restabelecer a credencial com desfazer_acao.",
    ),
    "fechar_porta": _AcaoDeBase(
        descricao="Fecha no firewall do gateway o acesso a uma porta de um dispositivo.",
        alvo="Porta, protocolo e dispositivo, no formato porta/protocolo@endereco, como 23/tcp@192.168.137.31",
        alvo_com_rotulo="Porta, protocolo e dispositivo, no formato porta/protocolo@rotulo, como 23/tcp@destino-1",
        tipo_de_alvo="porta",
        duracao=None,
        grupo="portas_fechadas",
        como_desfazer="Reabrir a porta com desfazer_acao.",
    ),
}
# Piso do código: nenhum arquivo de política baixa o risco destas ações. Fechar uma porta corta um
# serviço do dispositivo, e a porta é inferida do incidente. Ação nova, fora da base, também é
# sempre de risco alto, mesmo depois de promovida ao catálogo.
_SEMPRE_DE_RISCO_ALTO = ("isolar_dispositivo", "revogar_credencial", "fechar_porta")
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
_MEDIDAS_NO_TOTAL = "medidas_de_risco_baixo_no_total"
_PENDENTES = "propostas_aguardando_aprovacao_por_incidente"
_LIBERADAS = "propostas_liberadas_por_incidente"
_REDE = "rede"
_PROTEGIDOS = "enderecos_protegidos"
_CRITICOS = "enderecos_criticos"
_REDES_LOCAIS = "redes_locais"
# Prefixos IPv6 que levam um IPv4 dentro deles: NAT64 (64:ff9b::/96), SIIT (::ffff:0:0:0/96) e o
# IPv4 compatível (::/96), todos com o IPv4 nos últimos 32 bits. O NAT64 de uso local, o 6to4, o
# ISATAP e o Teredo são tratados à parte, em `_ipv4_embutidos`.
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIIT = ipaddress.ip_network("::ffff:0:0:0/96")
_COMPATIVEL = ipaddress.ip_network("::/96")
# NAT64 de uso local (RFC 8215). A rede escolhe o tamanho do prefixo dentro do /48, e o IPv4 fica numa
# posição diferente em cada tamanho (RFC 6052), pulando o octeto 8: os quatro tamanhos são conferidos.
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
_POSICOES_NO_NAT64_LOCAL = ((6, 7, 9, 10), (7, 9, 10, 11), (9, 10, 11, 12), (12, 13, 14, 15))
# ISATAP: o identificador de interface é 0:5efe ou 200:5efe, seguido do IPv4.
_ISATAP = (bytes.fromhex("00005efe"), bytes.fromhex("02005efe"))
# ULA: a faixa de endereços IPv6 de uso local, que conta sempre como rede local.
_ULA = ipaddress.ip_network("fc00::/7")
# Alvo escrito com o rótulo neutro de um endereço do incidente: o rótulo só, usuario@rótulo ou
# porta/protocolo@rótulo.
_ALVO_COM_ROTULO = re.compile(r"(?:[A-Za-z0-9_][A-Za-z0-9._-]{0,63}@|[1-9][0-9]{0,4}/(?:tcp|udp)@)?(?:origem|destino)-[1-9][0-9]{0,5}")
# Porta e protocolo do alvo de fechar_porta: sem zero à esquerda, e o protocolo em minúsculas.
_PORTA = re.compile(r"([1-9][0-9]{0,4})/(tcp|udp)")
_MAIOR_PORTA = 65_535
# O que parece um rótulo sem ser escrito como ele: outra caixa, zero à esquerda, espaço no lugar do
# hífen, ou o rótulo no meio de um texto. Na linha de decisão, o alvo assim é recusado.
_PARECE_ROTULO = re.compile(r"(?i)(?:origem|destino)[\s_-]*[0-9]")
# O alvo da ação promovida: genérico, sem o endereço da proposta que deu origem a ela.
_ALVO_DA_PROMOVIDA = (
    "Texto de uma linha que diga sobre o que a ação age. Um endereço do incidente vai com o rótulo neutro, "
    "como destino-1."
)


# --- política de risco -----------------------------------------------------------------------


@dataclass(frozen=True)
class Politica:
    """A política de risco, como sai de `politica.toml`."""

    # Para cada ação de base, o risco, o prazo máximo, em minutos, para ela contar como risco baixo
    # e os alvos em que o risco baixo vale: só as origens do incidente, ou as origens e os destinos.
    acoes: dict
    # Máximo de medidas de risco baixo ativas ao mesmo tempo em um incidente.
    medidas_de_risco_baixo_por_incidente: int
    # Máximo de medidas de risco baixo ativas ao mesmo tempo, somando todos os incidentes.
    medidas_de_risco_baixo_no_total: int
    # Máximo de propostas de um incidente aguardando aprovação ao mesmo tempo. A seguinte é recusada.
    propostas_aguardando_aprovacao_por_incidente: int
    # Máximo de propostas de um incidente liberadas e ainda não executadas. A seguinte de risco baixo é
    # recusada.
    propostas_liberadas_por_incidente: int
    # Endereços em que qualquer ação é de risco alto, na forma canônica: o gateway e a captura.
    enderecos_protegidos: frozenset
    # Endereços dos serviços de que o sistema depende, tratados como protegidos.
    enderecos_criticos: frozenset
    # Redes locais: o endereço de rede e o de broadcast de cada uma não são aceitos como alvo, e
    # bloquear um endereço delas é de risco alto.
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

    limites = secao(_LIMITES, (_MEDIDAS, _MEDIDAS_NO_TOTAL, _PENDENTES, _LIBERADAS))
    medidas = limites.get(_MEDIDAS)
    if type(medidas) is not int or medidas < 0:
        raise invalida(f"{_MEDIDAS} precisa ser um número inteiro, a partir de 0")
    no_total = limites.get(_MEDIDAS_NO_TOTAL)
    if type(no_total) is not int or no_total < 0:
        raise invalida(f"{_MEDIDAS_NO_TOTAL} precisa ser um número inteiro, a partir de 0")
    pendentes = limites.get(_PENDENTES)
    # Com zero, nenhuma proposta de risco alto chegaria à pessoa.
    if type(pendentes) is not int or pendentes < 1:
        raise invalida(f"{_PENDENTES} precisa ser um número inteiro, a partir de 1")
    liberadas = limites.get(_LIBERADAS)
    # Com zero, nenhuma proposta de risco baixo seria registrada.
    if type(liberadas) is not int or liberadas < 1:
        raise invalida(f"{_LIBERADAS} precisa ser um número inteiro, a partir de 1")

    rede = secao(_REDE, (_PROTEGIDOS, _CRITICOS, _REDES_LOCAIS))

    def enderecos(chave):
        lidos = []
        for texto in lista_de_textos(rede, chave):
            try:
                lidos.append(endereco_canonico(texto.strip()))
            except ValueError:
                raise invalida(f"{chave} traz {texto!r}, que não é um endereço IP") from None
        return frozenset(lidos)

    protegidos = enderecos(_PROTEGIDOS)
    criticos = enderecos(_CRITICOS)
    redes = []
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
        medidas_de_risco_baixo_no_total=no_total,
        propostas_aguardando_aprovacao_por_incidente=pendentes,
        propostas_liberadas_por_incidente=liberadas,
        enderecos_protegidos=protegidos,
        enderecos_criticos=criticos,
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
    # O alvo de revogar_credencial e o de fechar_porta trazem o endereço depois da arroba: é ele que
    # se compara com o incidente.
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
        # Na ação que só é de risco baixo sobre quem ataca, um endereço da rede local não conta como
        # atacante: num flood UDP ou ICMP a origem é forjável, e bloquear um dispositivo interno
        # equivale a isolá-lo.
        if regra[_ALVOS] == _SO_ORIGENS and _na_rede_local(politica, endereco):
            valem.add("alvo_na_rede_local")
        if _medidas_de_risco_baixo(estado, incidente) >= politica.medidas_de_risco_baixo_por_incidente:
            valem.add("orcamento_de_risco_baixo_esgotado")
        # Cada incidente aberto com origens forjadas teria o seu limite: há também o do sistema todo.
        if _medidas_de_risco_baixo(estado) >= politica.medidas_de_risco_baixo_no_total:
            valem.add("orcamento_global_de_risco_baixo_esgotado")
    # O que se diz do alvo vale para toda ação de base, inclusive a que já é sempre de risco alto: quem
    # aprova o isolamento de um dispositivo precisa saber que ele é o gateway, ou que é alheio ao incidente.
    if endereco not in origens and endereco not in destinos:
        valem.add("alvo_fora_do_incidente")
    if _protegido(politica, endereco):
        valem.add("alvo_protegido")
    return [codigo for codigo in MOTIVOS_DE_RISCO_ALTO if codigo in valem]


def _ipv4_embutidos(endereco):
    """Os IPv4 que um endereço IPv6 leva dentro dele, ou nenhum.

    São as formas em que um IPv6 chega ao mesmo dispositivo que um IPv4: o IPv4 compatível
    (`::a.b.c.d`), o SIIT (`::ffff:0:a.b.c.d`), o NAT64 (`64:ff9b::a.b.c.d`), o NAT64 de uso local
    (`64:ff9b:1::/48`, em qualquer das posições que o tamanho do prefixo permite), o 6to4
    (`2002:AABB:CCDD::`), o ISATAP (`...:5efe:a.b.c.d`) e o Teredo (o servidor e o cliente). O IPv4
    escrito como IPv6 (`::ffff:a.b.c.d`) já vira o IPv4 na leitura. Na dúvida sobre a posição,
    valem todas: o endereço conta como protegido ou local se qualquer uma delas for.
    """
    ip = ipaddress.ip_address(endereco)
    if ip.version != 6:
        return ()
    octetos = ip.packed
    embutidos = []
    if ip.sixtofour is not None:
        embutidos.append(ip.sixtofour)
    if ip.teredo is not None:
        embutidos.extend(ip.teredo)
    # O compatível exclui :: e ::1, que são o endereço não especificado e o loopback do IPv6.
    if ip in _NAT64 or ip in _SIIT or (ip in _COMPATIVEL and int(ip) > 1) or octetos[8:12] in _ISATAP:
        embutidos.append(ipaddress.IPv4Address(octetos[12:16]))
    if ip in _NAT64_LOCAL:
        embutidos.extend(
            ipaddress.IPv4Address(bytes(octetos[posicao] for posicao in posicoes)) for posicoes in _POSICOES_NO_NAT64_LOCAL
        )
    return tuple(dict.fromkeys(str(embutido) for embutido in embutidos))


def _formas(endereco):
    """O endereço e, quando ele é um IPv6 que leva um IPv4, também esse IPv4."""
    return (endereco, *_ipv4_embutidos(endereco))


def _protegido(politica, endereco):
    """O endereço é protegido ou crítico, escrito direto ou dentro de um IPv6."""
    return any(forma in politica.enderecos_protegidos | politica.enderecos_criticos for forma in _formas(endereco))


def _na_rede_local(politica, endereco):
    """O endereço está numa das redes locais, escrito direto ou dentro de um IPv6, ou é um IPv6 de ULA."""
    if ipaddress.ip_address(endereco) in _ULA:
        return True
    return any(
        ipaddress.ip_address(forma) in rede for forma in _formas(endereco) for rede in politica.redes_locais
        if ipaddress.ip_address(forma).version == rede.version
    )


def _enderecos_do_incidente(estado, incidente):
    """As origens e os destinos do incidente, na última versão dele. Incidente encerrado não tem alvo."""
    ocorrido = estado.incidentes.get(incidente)
    if ocorrido is None or ocorrido.estado != "aberto":
        return frozenset(), frozenset()
    # O candidato a atacante é origem do incidente: a triagem pode apontá-lo mesmo fora das origens com mais quadros.
    return (
        _suspeitos(ocorrido),
        frozenset(item.endereco for item in ocorrido.destinos),
    )


def _medidas_de_risco_baixo(estado, incidente=None):
    """Quantas medidas aplicadas sem aprovação humana estão ativas no incidente, ou em todos."""
    return sum(
        1 for execucao in estado.execucoes.values()
        if incidente in (None, execucao.incidente) and execucao.estado == "aplicada"
        and execucao.proposta not in estado.aprovadas
    )


def _regra(politica, acao):
    regra = politica.acoes[acao]
    if acao in _SEMPRE_DE_RISCO_ALTO or regra["risco"] == "alto":
        return _REGRA_DE_RISCO_ALTO
    sem_prazo = "sem duracao, " if BASE[acao].duracao == "opcional" else ""
    if regra[_ALVOS] == _ORIGENS_E_DESTINOS:
        papel, destino = "origem ou destino do incidente", ""
    else:
        papel = "origem do incidente fora da rede local"
        destino = "alvo que é destino do incidente, isto é, o dispositivo atacado, endereço da rede local, "
    return (
        f"Risco baixo quando o alvo é {papel}, a duracao é de até {regra[_PRAZO]} minutos, o incidente "
        f"tem menos de {politica.medidas_de_risco_baixo_por_incidente} medidas de risco baixo ativas e o sistema, "
        f"somando os incidentes, menos de {politica.medidas_de_risco_baixo_no_total}: o agente de execução aplica "
        f"sem aprovação. Fora disso ({sem_prazo}duracao maior, alvo que não consta do incidente, {destino}"
        "endereço protegido pela política ou limite de medidas atingido), risco alto: só com aprovação humana."
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


def _conferir_alvo_permitido(politica, acao, alvo, com_rotulo=None):
    """Recusa o alvo de uma ação de base quando o endereço dele é um dos endereços especiais.

    Com `com_rotulo`, o alvo como o agente o escreveu, a mensagem cita o rótulo, e não o endereço
    em que o servidor o trocou.
    """
    endereco = alvo.rpartition("@")[2]
    motivo = _motivo_de_endereco_recusado(politica, endereco)
    if motivo is not None:
        if com_rotulo is not None:
            raise PedidoRecusado(
                "alvo_nao_permitido",
                f"O alvo de {acao} não pode ser {com_rotulo}: o endereço desse rótulo {motivo}. O alvo é o "
                "endereço de um dispositivo.",
            )
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
    # Incidentes que a pessoa marcou como já resolvidos, com a marca.
    resolvidos: dict = field(default_factory=dict)
    # Rótulos neutros dos endereços de cada incidente: rótulo -> endereço, na ordem em que apareceram.
    rotulos: dict = field(default_factory=dict)
    # Último efeito verificado em cada incidente, na ordem do log.
    ultimos_efeitos: dict = field(default_factory=dict)
    # O atacante que a triagem apontou em cada incidente: vale o último apontado.
    atacantes: dict = field(default_factory=dict)


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
            _rotular(estado, dados)
        case "incidente_atualizado" | "incidente_encerrado":
            _exigir(dados.id in estado.incidentes, f"o incidente {dados.id} não foi aberto")
            _exigir(estado.incidentes[dados.id].estado == "aberto", f"o incidente {dados.id} já está encerrado")
            esperado = "encerrado" if evento.tipo == "incidente_encerrado" else "aberto"
            _exigir(dados.estado == esperado, f"o incidente {dados.id} vem com o estado {dados.estado}")
            estado.incidentes[dados.id] = dados
            _rotular(estado, dados)
        case "incidente_marcado_resolvido":
            marcado = _citado(estado.incidentes, dados.incidente, "o incidente")
            _exigir(dados.incidente not in estado.resolvidos, f"o incidente {dados.incidente} já foi marcado como resolvido")
            # A mesma regra de marcar_resolvido: só o incidente aberto recebe a marca.
            _exigir(marcado.estado == "aberto", f"o incidente {dados.incidente} já está encerrado e não recebe a marca")
            estado.resolvidos[dados.incidente] = dados
        case "acao_proposta":
            _conferir_proposta_nova(estado, dados)
            estado.propostas[dados.id] = dados
        case "acao_aprovada" | "acao_rejeitada":
            proposta = _citado(estado.propostas, dados.proposta, "a proposta")
            _no_incidente_da_proposta(evento, proposta)
            _exigir(
                proposta.estado == "aguardando_aprovacao",
                f"a proposta {proposta.id} não aguarda aprovação: está {proposta.estado}",
            )
            if evento.tipo == "acao_aprovada":
                _exigir(
                    proposta.incidente not in estado.resolvidos,
                    f"o incidente {proposta.incidente} foi marcado como já resolvido, e a proposta {proposta.id} não "
                    "pode mais ser aprovada",
                )
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
                proposta.incidente not in estado.resolvidos,
                f"o incidente {proposta.incidente} foi marcado como já resolvido, e nenhuma ação é aplicada nele",
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
            execucao = _citado(estado.execucoes, dados.execucao, "a execução")
            _exigir(
                dados.incidente == execucao.incidente,
                f"o efeito diz que é do incidente {dados.incidente}, e a execução {execucao.id} é do incidente "
                f"{execucao.incidente}",
            )
            estado.efeitos[dados.execucao] = dados
            estado.ultimos_efeitos[dados.incidente] = dados
        case "atacante_apontado":
            _exigir(evento.incidente is not None, "o atacante apontado não diz de que incidente é")
            ocorrido = _citado(estado.incidentes, evento.incidente, "o incidente")
            _exigir(
                dados.endereco in _suspeitos(ocorrido),
                f"o endereço apontado como atacante não está entre os candidatos nem as origens do incidente {ocorrido.id}",
            )
            estado.atacantes[ocorrido.id] = dados
            _rotular_origem(estado, ocorrido.id, dados.endereco)
        case "analise_emitida" | "sumario_emitido":
            _exigir(evento.incidente is not None, f"o evento {evento.tipo} não diz de que incidente é")
        case "recomendacao_emitida":
            for citada in dados.propostas:
                proposta = _citado(estado.propostas, citada, "a proposta")
                _exigir(
                    proposta.incidente == evento.incidente,
                    f"a recomendação está no incidente {evento.incidente} e cita a proposta {proposta.id}, que é do "
                    f"incidente {proposta.incidente}",
                )
        case "catalogo_ampliado":
            proposta = _citado(estado.propostas, dados.proposta, "a proposta")
            _no_incidente_da_proposta(evento, proposta)
            nome = dados.acao.nome
            _exigir(nome not in BASE and nome not in estado.promovidas, f"a ação {nome} já está no catálogo")
            _exigir(
                proposta.nova and proposta.estado == "executada" and nome == proposta.acao
                and dados.acao.origem == "promovida",
                f"a proposta {proposta.id} não é de uma ação nova aplicada, com o nome {nome}",
            )
            # O que entra no catálogo é o que a pessoa aprovou, e não uma variação com o mesmo nome. O
            # filtro de endereços de agora vale para os dois lados: uma promoção gravada por uma versão
            # do filtro que deixou passar um endereço continua válida.
            try:
                aprovada = _acao_promovida(proposta)
            except ValidationError:
                aprovada = None
            _exigir(
                aprovada is not None and _sem_enderecos_nos_textos(dados.acao) == aprovada,
                f"a ação promovida pela proposta {proposta.id} não é a que foi aprovada e aplicada",
            )
            estado.promovidas[nome] = dados.acao
    # O evento que diz ser de um incidente está no rastro de um incidente que existe: é por esse campo
    # que a interface monta o rastro e o custo de cada incidente.
    _exigir(
        evento.incidente is None or evento.incidente in estado.incidentes,
        f"o incidente {evento.incidente} não existe no log até este ponto",
    )


def _rotular(estado, incidente):
    """Dá um rótulo neutro a cada endereço novo do incidente, na ordem em que ele aparece.

    O rótulo de um endereço não muda quando o incidente é atualizado e a lista é reordenada: o
    agente de decisão que propôs sobre origem-2 continua falando do mesmo dispositivo. O papel
    (origem ou destino) faz parte do rótulo, e o endereço que aparece nos dois ganha um de cada.
    """
    rotulos = estado.rotulos.setdefault(incidente.id, {})
    # Os candidatos a atacante são origens também, e vêm depois das origens: o rótulo das origens fica
    # igual ao de um log gravado antes dos candidatos.
    for papel, lista in (
        ("origem", [*incidente.origens, *incidente.candidatos]),
        ("destino", incidente.destinos),
    ):
        do_papel = [endereco for rotulo, endereco in rotulos.items() if rotulo.startswith(f"{papel}-")]
        for item in lista:
            if item.endereco not in do_papel:
                do_papel.append(item.endereco)
                rotulos[f"{papel}-{len(do_papel)}"] = item.endereco


def _rotular_origem(estado, incidente, endereco):
    """Dá o rótulo de origem ao endereço, se ele ainda não tiver um (o atacante apontado de uma versão antiga)."""
    rotulos = estado.rotulos.setdefault(incidente, {})
    origens = [valor for rotulo, valor in rotulos.items() if rotulo.startswith("origem-")]
    if endereco not in origens:
        rotulos[f"origem-{len(origens) + 1}"] = endereco


def _suspeitos(incidente):
    """Os endereços que podem ser apontados como atacante: os candidatos e as origens do incidente."""
    return frozenset(item.endereco for item in [*incidente.candidatos, *incidente.origens])


def _resolver_rotulo(estado, incidente, alvo):
    """O alvo com o rótulo trocado pelo endereço que ele representa no incidente."""
    usuario, arroba, rotulo = alvo.rpartition("@")
    rotulos = estado.rotulos.get(incidente, {})
    if rotulo not in rotulos:
        raise PedidoRecusado(
            "alvo_malformado",
            f"O rótulo {resumir(rotulo, 30)} não existe no incidente {incidente}. Os rótulos dele são: "
            f"{', '.join(rotulos) or 'nenhum'}.",
        )
    return f"{usuario}{arroba}{rotulos[rotulo]}"


def _no_incidente_da_proposta(evento, proposta):
    """A decisão e a promoção ficam no rastro do incidente da proposta, e não no de outro."""
    _exigir(
        evento.incidente == proposta.incidente,
        f"o evento diz que é do incidente {evento.incidente}, e a proposta {proposta.id} é do incidente "
        f"{proposta.incidente}",
    )


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
    _exigir(
        proposta.incidente not in estado.resolvidos,
        f"o incidente {proposta.incidente} foi marcado como já resolvido e não recebe proposta",
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
    if proposta.alvo_com_rotulo is not None:
        # O rótulo gravado é o que o servidor resolveu: com ele, o incidente dá o mesmo alvo.
        try:
            resolvido = _resolver_rotulo(estado, proposta.incidente, proposta.alvo_com_rotulo)
        except PedidoRecusado:
            resolvido = None
        _exigir(
            _ALVO_COM_ROTULO.fullmatch(proposta.alvo_com_rotulo) is not None and resolvido == proposta.alvo,
            f"a proposta {proposta.id} traz um rótulo que não dá o alvo dela no incidente {proposta.incidente}",
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


def catalogo(estado, politica, com_rotulos=False):
    """As ações que o agente pode propor: as cinco de base e as promovidas, nessa ordem.

    Com `com_rotulos`, o alvo de cada ação de base é descrito com os rótulos neutros, como a
    linha de decisão o escreve.
    """
    de_base = [
        AcaoDoCatalogo(
            nome=nome,
            descricao=definicao.descricao,
            alvo=definicao.alvo_com_rotulo if com_rotulos else definicao.alvo,
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


def resumo_do_incidente(estado, politica, identificador):
    """O incidente como o agente de decisão o vê: montado aqui, sem endereço nenhum.

    O agente de decisão pode estar num modelo de nuvem (arquitetura híbrida, decisão de
    2026-10-10). Em vez dos endereços, o resumo traz os rótulos neutros, com a contagem de
    quadros e se o endereço é protegido pela política, e as portas atacadas com o rótulo do
    destino. Traz também o último efeito verificado e a
    marca de já resolvido, para o agente saber o que já foi tentado e quando só deve explicar.
    """
    incidente = estado.incidentes[identificador]
    rotulo_de = {(rotulo.partition("-")[0], endereco): rotulo for rotulo, endereco in estado.rotulos[identificador].items()}

    def rotulados(lista, papel):
        return [
            EnderecoRotulado(
                rotulo=rotulo_de[(papel, item.endereco)], quadros=item.quadros, protegido=_protegido(politica, item.endereco),
            )
            for item in lista
        ]

    return ResumoDoIncidente(
        id=incidente.id,
        estado=incidente.estado,
        ja_resolvido=identificador in estado.resolvidos,
        categoria=incidente.categoria,
        categoria_do_modelo=incidente.categoria_do_modelo,
        confianca=incidente.confianca,
        duracao_s=max(0.0, (incidente.fim - incidente.inicio).total_seconds()),
        janelas=incidente.janelas,
        origens_distintas=incidente.origens_distintas,
        distribuido=incidente.distribuido,
        origens=rotulados(incidente.origens, "origem"),
        destinos=rotulados(incidente.destinos, "destino"),
        features_principais=incidente.features_principais,
        # O contrato garante que a porta é de um destino listado, e todo destino listado tem rótulo.
        portas=[
            PortaRotulada(
                destino=rotulo_de[("destino", item.destino)], porta=item.porta, protocolo=item.protocolo,
                quadros=item.quadros,
            )
            for item in incidente.portas
        ],
        ultimo_efeito=estado.ultimos_efeitos.get(identificador),
        atacante_apontado=_atacante_rotulado(estado, identificador),
    )


def _atacante_rotulado(estado, identificador):
    """O atacante apontado pela triagem, pelo rótulo, com a justificativa sem endereço nenhum."""
    apontado = estado.atacantes.get(identificador)
    if apontado is None:
        return None
    rotulos = estado.rotulos[identificador]
    rotulo = next(r for r, endereco in rotulos.items() if r.startswith("origem-") and endereco == apontado.endereco)
    justificativa = com_rotulos(apontado.justificativa, rotulos)
    if len(justificativa) > TEXTO_LONGO:
        justificativa = justificativa[: TEXTO_LONGO - 1].rstrip() + "…"
    return AtacanteRotulado(rotulo=rotulo, justificativa=justificativa)


def com_rotulos(texto, rotulos):
    """O texto com cada endereço do incidente trocado pelo rótulo dele e qualquer outro pelo marcador.

    Um endereço que é origem e destino fica com o rótulo de origem. O que sobrar com cara de endereço
    passa por `mascarar_enderecos`, como o veredito da triagem.
    """
    por_endereco = {}
    for rotulo, endereco in rotulos.items():
        if rotulo.startswith("origem-") or endereco not in por_endereco:
            por_endereco[endereco] = rotulo
    # O endereço mais longo primeiro: 10.0.0.12 não pode virar origem-1 seguido de 2. O ponto final da
    # frase pode vir colado ao endereço; o ponto seguido de dígito, não.
    for endereco in sorted(por_endereco, key=len, reverse=True):
        padrao = rf"(?<![0-9A-Fa-f.:]){re.escape(endereco)}(?![0-9A-Fa-f:]|\.[0-9A-Fa-f])"
        texto = re.sub(padrao, por_endereco[endereco], texto)
    return mascarar_enderecos(texto)


def apontar_atacante(estado, identificador, endereco, justificativa):
    """Registra o atacante que a triagem apontou. Devolve o apontamento e o rascunho do evento.

    Só vale um dos candidatos ou das origens do incidente aberto: a triagem escolhe entre o que o
    classificador e a política de acionamento viram, e não traz endereço de fora.
    """
    incidente = estado.incidentes[identificador]
    if incidente.estado != "aberto":
        raise PedidoRecusado("incidente_encerrado", f"O incidente {identificador} está encerrado.")
    canonico = _endereco(endereco)
    if canonico is None or canonico not in _suspeitos(incidente):
        raise PedidoRecusado(
            "alvo_nao_permitido",
            f"O atacante apontado precisa ser um dos candidatos ou das origens do incidente {identificador}, "
            "escrito como o incidente o traz.",
        )
    try:
        apontado = AtacanteApontado(endereco=canonico, justificativa=_TEXTO_LONGO.validate_python(justificativa))
    except ValidationError:
        raise PedidoRecusado(
            "argumentos_invalidos", f"O apontamento precisa de uma justificativa: {_UMA_LINHA}."
        ) from None
    return apontado, [novo("atacante_apontado", apontado, identificador)]


def ambiente(estado):
    """As medidas ativas no ambiente simulado. Ação desfeita não aparece."""
    grupos = {nome: [] for nome in Ambiente.model_fields}
    for execucao in estado.execucoes.values():
        if execucao.estado == "aplicada":
            grupo = BASE[execucao.acao].grupo if execucao.acao in BASE else "outras_medidas"
            grupos[grupo].append(execucao)
    return Ambiente(**grupos)


# --- propor ----------------------------------------------------------------------------------


def propor(estado, politica, incidente, acao, alvo, parametros, justificativa, so_rotulos=False):
    """Registra a proposta de uma ação do catálogo ou de uma ação nova.

    Devolve a proposta, com o nível de risco, os motivos quando o risco é alto e se ela exige
    aprovação, e o rascunho do evento `acao_proposta`. Não aplica nada: proposta de risco baixo
    já nasce liberada para o agente de execução, e a de risco alto fica aguardando a decisão de
    uma pessoa.

    O alvo pode vir com o rótulo neutro de um endereço do incidente (`origem-1`, `destino-1`,
    `admin@destino-1`). O rótulo é trocado aqui pelo endereço, o risco é calculado sobre o
    endereço, e a proposta guarda os dois. Com `so_rotulos`, que é o caso da linha de decisão, o
    alvo de uma ação de base só pode vir com o rótulo, e nenhum alvo pode trazer endereço: o
    agente de decisão não conhece endereço, e o que vier com um foi copiado de texto de fora.

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
    if incidente in estado.resolvidos:
        raise PedidoRecusado(
            "incidente_ja_resolvido",
            f"O incidente {incidente} foi marcado como já resolvido pela pessoa que opera a rede e não recebe "
            "propostas. Explique o incidente, sem propor ação.",
        )
    justificativa = _justificativa(justificativa)
    if not isinstance(parametros, dict):
        raise PedidoRecusado("argumentos_invalidos", "O campo parametros precisa ser um objeto.")
    if not isinstance(acao, str):
        raise PedidoRecusado("argumentos_invalidos", f"O nome da ação precisa ser um texto. Veio {resumir(acao)}.")

    # O tamanho e o tipo do alvo vêm antes de qualquer expressão regular: um alvo de megabytes não
    # chega a ser lido, e a trava do log não fica presa por ele.
    if not isinstance(alvo, str) or len(alvo) > _MAIOR_ALVO:
        raise PedidoRecusado(
            "alvo_malformado",
            f"O alvo de {_nome_na_mensagem(acao)} é um texto de até {_MAIOR_ALVO} caracteres. Veio {resumir(alvo)}.",
        )
    alvo_com_rotulo = None
    if _ALVO_COM_ROTULO.fullmatch(alvo.strip()):
        alvo_com_rotulo = alvo.strip()
        alvo = _resolver_rotulo(estado, incidente, alvo_com_rotulo)
    elif so_rotulos and (acao in BASE or tem_endereco(alvo) or _PARECE_ROTULO.search(alvo)):
        # O nome só entra na mensagem quando é de uma ação de base: o de uma ação nova vem do agente.
        de_qual = f" de {acao}" if acao in BASE else ""
        raise PedidoRecusado(
            "alvo_malformado",
            f"Na linha de decisão, o alvo{de_qual} é o rótulo neutro de um endereço do incidente, sozinho e escrito "
            "como vem em obter_resumo, como origem-1, destino-1, admin@destino-1 ou 23/tcp@destino-1, e não um "
            "endereço. Uma ação "
            "nova também pode descrever o alvo em texto, sem endereço e sem rótulo.",
        )

    if acao in BASE:
        alvo = _alvo_de_base(acao, alvo, alvo_com_rotulo)
        _conferir_alvo_permitido(politica, acao, alvo, alvo_com_rotulo)
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
    else:
        _conferir_propostas_liberadas(estado, politica, incidente)
    proposta = Proposta(
        id=f"prop-{len(estado.propostas) + 1:04d}",
        incidente=incidente,
        acao=acao,
        alvo=alvo,
        alvo_com_rotulo=alvo_com_rotulo,
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


def _nome_na_mensagem(acao):
    """O nome da ação como entra numa mensagem: inteiro se é um nome válido, e cortado se não é."""
    try:
        return _NOME_DE_ACAO.validate_python(acao)
    except ValidationError:
        return resumir(acao, 30)


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


def _conferir_propostas_liberadas(estado, politica, incidente):
    """Recusa a proposta de risco baixo quando o incidente já tem o máximo de propostas liberadas.

    A proposta de risco baixo nasce liberada e assim fica até o agente de execução aplicá-la. Sem
    o teto, um agente enganado em laço registraria propostas sem fim, e o log cresceria com elas.
    Contam também as aprovadas e ainda não executadas.
    """
    liberadas = sum(
        1 for proposta in estado.propostas.values() if proposta.incidente == incidente and proposta.estado == "liberada"
    )
    if liberadas >= politica.propostas_liberadas_por_incidente:
        quantas = "1 proposta liberada" if liberadas == 1 else f"{liberadas} propostas liberadas"
        raise PedidoRecusado(
            "limite_de_propostas_liberadas",
            f"O incidente {incidente} já tem {quantas} que ainda não foram executadas, que é o máximo aceito pela "
            "política, e esta proposta não foi registrada. Uma nova proposta de risco baixo só entra depois que o "
            "agente de execução aplicar alguma das liberadas.",
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


def _alvo_de_base(acao, alvo, com_rotulo=None):
    """O alvo de uma ação de base na forma canônica, ou a recusa.

    Com `com_rotulo`, o alvo veio escrito com o rótulo neutro, e `alvo` já é o endereço em que o
    servidor o trocou. A recusa então repete o que o agente escreveu, com o rótulo, e nunca o
    endereço: nem inteiro, nem um pedaço dele.
    """
    definicao = BASE[acao]
    if com_rotulo is not None:
        usuario, arroba, _ = com_rotulo.rpartition("@")
        if definicao.tipo_de_alvo == "ip" and arroba:
            raise PedidoRecusado(
                "alvo_malformado",
                f"O alvo de {acao} é o rótulo de um endereço do incidente, como origem-1, sem nada antes dele: o "
                f"formato usuario@rótulo é só de revogar_credencial, e porta/protocolo@rótulo, só de fechar_porta. "
                f"Veio {resumir(com_rotulo)}.",
            )
        if definicao.tipo_de_alvo == "credencial" and (not arroba or not _USUARIO.fullmatch(usuario)):
            raise PedidoRecusado(
                "alvo_malformado",
                f"O alvo de {acao} precisa ter o formato usuario@rótulo, como admin@destino-1. O usuário usa letras "
                f"sem acento, números, ponto, hífen e sublinhado, e não começa por ponto nem por hífen. Veio "
                f"{resumir(com_rotulo)}.",
            )
        if definicao.tipo_de_alvo == "porta" and (not arroba or _porta(usuario) is None):
            raise PedidoRecusado(
                "alvo_malformado",
                f"O alvo de {acao} precisa ter o formato porta/protocolo@rótulo, como 23/tcp@destino-1. {_DA_PORTA} "
                f"Veio {resumir(com_rotulo)}.",
            )
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
    if definicao.tipo_de_alvo == "porta":
        porta = _porta(usuario)
        if not arroba or porta is None or endereco is None:
            raise PedidoRecusado(
                "alvo_malformado",
                f"O alvo de {acao} precisa ter o formato porta/protocolo@endereco, como 23/tcp@192.168.137.31. "
                f"{_DA_PORTA} Veio {resumir(alvo)}.",
            )
        return f"{porta}@{endereco}"
    if not arroba or not _USUARIO.fullmatch(usuario) or endereco is None:
        raise PedidoRecusado(
            "alvo_malformado",
            f"O alvo de {acao} precisa ter o formato usuario@endereco, como admin@192.168.137.31. O usuário usa "
            f"letras sem acento, números, ponto, hífen e sublinhado, e não começa por ponto nem por hífen. "
            f"Veio {resumir(alvo)}.",
        )
    return f"{usuario}@{endereco}"


_DA_PORTA = "A porta vai de 1 a 65535, sem zero à esquerda, e o protocolo é tcp ou udp, em minúsculas."


def _porta(texto):
    """A porta e o protocolo como vêm no alvo de fechar_porta, ou None se o texto não tem esse formato."""
    achado = _PORTA.fullmatch(texto)
    if achado is None or int(achado[1]) > _MAIOR_PORTA:
        return None
    return texto


def _alvo_livre(acao, alvo):
    """Alvo de ação fora da base: um texto curto, de uma linha só."""
    limpo = alvo.strip() if isinstance(alvo, str) else ""
    if not limpo or len(limpo) > _MAIOR_ALVO or not limpo.isprintable() or any(map(invisivel, limpo)):
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


def usuario_do_sistema():
    """O nome do usuário do sistema operacional dono do processo, para registrar quem decidiu.

    Vem da conta do processo, e não das variáveis de ambiente, onde houver como. O nome é escapado
    e cortado para caber no contrato.
    """
    try:
        nome = pwd.getpwuid(os.getuid()).pw_name if pwd is not None else getpass.getuser()
    except (KeyError, OSError):
        nome = ""
    return visivel(nome).strip()[:TEXTO_CURTO] or "desconhecido"


def decidir(estado, id_proposta, aprovar, canal="terminal", motivo=None, usuario=None):
    """Aprova ou rejeita uma proposta que aguarda aprovação.

    Não é tool: nenhum agente chega aqui. A decisão entra por um canal só da pessoa, que neste
    trabalho é o comando `python -m codigo.mcp.aprovar`. Fica registrado quem decidiu: o usuário
    dado ou, sem ele, o usuário do sistema que roda o processo.
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
    if aprovar and proposta.incidente in estado.resolvidos:
        # A execução seria recusada: aprovar diria à pessoa que a ação vai ser aplicada, e não vai.
        raise PedidoRecusado(
            "incidente_ja_resolvido",
            f"A proposta {proposta.id} é do incidente {proposta.incidente}, que foi marcado como já resolvido, e "
            "nenhuma ação é aplicada nele. A proposta só pode ser rejeitada.",
        )
    try:
        decisao = Decisao(
            proposta=proposta.id, canal=canal, usuario=usuario or usuario_do_sistema(), motivo=motivo or None
        )
    except ValidationError:
        raise PedidoRecusado("argumentos_invalidos", f"O motivo da decisão precisa ser {_UMA_LINHA}.") from None
    decidida = proposta.model_copy(update={"estado": "liberada" if aprovar else "rejeitada"})
    return decidida, [novo("acao_aprovada" if aprovar else "acao_rejeitada", decisao, proposta.incidente)]


def marcar_resolvido(estado, incidente, canal="terminal", usuario=None, motivo=None):
    """Registra que a pessoa que opera a rede já resolveu o incidente por conta própria.

    Como a aprovação, não é tool: entra pelo canal da pessoa (o comando `aprovar --resolvido` ou,
    mais adiante, o botão "Já resolvido" da interface). Daí em diante, `propor` e `executar`
    recusam qualquer proposta do incidente, inclusive a já aprovada. A garantia fica no servidor, e
    não no prompt do agente.
    """
    if not isinstance(incidente, str) or incidente not in estado.incidentes:
        raise PedidoRecusado(
            "identificador_desconhecido", f"Não existe incidente com o identificador {resumir(incidente)}."
        )
    if incidente in estado.resolvidos:
        raise PedidoRecusado("argumentos_invalidos", f"O incidente {incidente} já foi marcado como resolvido.")
    if estado.incidentes[incidente].estado != "aberto":
        raise PedidoRecusado(
            "incidente_encerrado", f"O incidente {incidente} já está encerrado: não há o que marcar."
        )
    try:
        marca = MarcaDeResolvido(
            incidente=incidente, canal=canal, usuario=usuario or usuario_do_sistema(), motivo=motivo or None
        )
    except ValidationError:
        raise PedidoRecusado("argumentos_invalidos", f"O motivo precisa ser {_UMA_LINHA}.") from None
    return marca, [novo("incidente_marcado_resolvido", marca, incidente)]


def executar(estado, politica, id_proposta, instante):
    """Aplica no ambiente simulado a ação de uma proposta liberada.

    Proposta de incidente marcado como já resolvido não executa, nem a aprovada. O campo
    `estado` da proposta, que veio do log, não basta para liberar. Proposta que exige
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
    if proposta.incidente in estado.resolvidos:
        raise PedidoRecusado(
            "incidente_ja_resolvido",
            f"A proposta {proposta.id} é do incidente {proposta.incidente}, que foi marcado como já resolvido pela "
            "pessoa que opera a rede. Nenhuma ação é aplicada nele, nem a que já foi aprovada.",
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
    acao = _acao_promovida(proposta)
    return acao, [novo("catalogo_ampliado", Promocao(proposta=proposta.id, acao=acao), proposta.incidente)]


def _sem_enderecos_nos_textos(acao):
    """A ação do catálogo com o filtro de endereços aplicado aos textos que a promoção filtra."""
    def mascarado(texto, maximo=TEXTO_LONGO):
        return None if texto is None else mascarar_enderecos(texto)[:maximo]

    return acao.model_copy(update={
        "descricao": mascarado(acao.descricao),
        "passos": [mascarado(passo) for passo in acao.passos],
        "efeito_esperado": mascarado(acao.efeito_esperado),
        "como_desfazer": mascarado(acao.como_desfazer),
        "fonte": mascarado(acao.fonte, TEXTO_CURTO),
    })


def _acao_promovida(proposta):
    """A ação do catálogo que sai de uma proposta de ação nova: os passos aprovados, sempre de risco alto.

    A ação promovida volta a todas as sessões do agente de decisão, em qualquer categoria. Por isso
    ela vai sem endereço: o alvo é genérico, e o endereço que estiver nos textos aprovados vira o
    marcador neutro.
    """
    detalhes = ParametrosDeAcaoNova.model_validate(proposta.parametros)
    return _sem_enderecos_nos_textos(AcaoDoCatalogo(
        nome=proposta.acao,
        descricao=detalhes.descricao,
        alvo=_ALVO_DA_PROMOVIDA,
        parametros=[],
        regra=_REGRA_DE_RISCO_ALTO,
        origem="promovida",
        passos=detalhes.passos,
        efeito_esperado=detalhes.efeito_esperado,
        como_desfazer=detalhes.como_desfazer,
        fonte=detalhes.fonte,
    ))
