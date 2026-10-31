"""Tipos do contrato MCP do SentryIoT.

Este módulo é a fonte única do contrato entre o lado do classificador e o lado dos agentes: o
que cada tool recebe e devolve e o formato de cada linha do log de eventos. O servidor de
mentira (`stub.py`), o servidor de verdade e a interface web partem daqui.

O `contrato.json` é a mesma informação em JSON Schema, para quem não lê Python. Ele é gerado
deste módulo e versionado, e um teste falha se os dois divergirem.

Uso, a partir da raiz do repositório, para gerar o `contrato.json` de novo:
    python -m codigo.mcp.tipos
"""
import ipaddress
import json
import re
import sys
import unicodedata
from functools import reduce
from operator import or_
from pathlib import Path
from typing import Annotated, Any, Literal, NamedTuple

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    StringConstraints,
    WithJsonSchema,
    create_model,
    model_validator,
)
from pydantic.json_schema import GenerateJsonSchema, models_json_schema
from typing_extensions import TypedDict

from codigo.captura.extrator import COLUNAS
from codigo.classificador.mapeamento import CATEGORIAS

VERSAO = "0.7.0"
# Máximo de janelas que o agente recebe por chamada. Um flood tem milhares de janelas, e mandar
# todas para a LLM custaria tokens demais.
LIMITE_DE_JANELAS = 20
# Candidatos a atacante que o incidente traz, para a triagem escolher, e destinos citados de cada um.
MAXIMO_DE_CANDIDATOS = 5
DESTINOS_DO_CANDIDATO = 3
PORTAS_DO_CANDIDATO = 3
# Máximo de trechos da base por resposta: em consultar_mitigacoes e em pesquisar_solucoes. Numa base
# grande, a resposta sem teto viraria milhões de caracteres para o modelo.
LIMITE_DE_MITIGACOES = 10
LIMITE_DE_TRECHOS = 3
ARQUIVO_DO_CONTRATO = Path(__file__).with_name("contrato.json")
AGENTES = ("triagem", "decisao", "execucao")
# O nome que expõe todas as tools em um processo só. Serve só para desenvolvimento e precisa ser dito.
TODOS = "todos"
# Tamanhos máximos. O que um agente escreve chega a uma pessoa, na tela de aprovação, e ao log:
# nenhum texto entra sem limite.
TEXTO_CURTO = 200
TEXTO_LONGO = 2_000
MAXIMO_DE_PASSOS = 20
MAIOR_NOME_DE_ACAO = 60
MAXIMO_DE_PROPOSTAS_POR_RECOMENDACAO = 20
# Caracteres que nenhum texto do contrato aceita: os de controle (C0, DEL e C1, que inclui U+0085),
# os separadores de linha e de parágrafo do Unicode (U+2028 e U+2029) e os que invertem a direção
# do texto (U+202A a U+202E e U+2066 a U+2069). Com eles, o que a pessoa lê no terminal pode não
# ser o que está gravado: uma sequência de escape apaga e reescreve a tela.
_ALEM_DO_ASCII = r"\x7f-\x9f\u2028-\u202e\u2066-\u2069"
_UMA_LINHA = rf"^[^\x00-\x1f{_ALEM_DO_ASCII}]*$"
# Texto em parágrafos: aceita a quebra de linha (U+000A) e mais nenhum caractere de controle.
_PARAGRAFOS = rf"^[^\x00-\x09\x0b-\x1f{_ALEM_DO_ASCII}]*$"
_NOME_DE_ACAO = rf"^[a-z][a-z0-9_]{{0,{MAIOR_NOME_DE_ACAO - 1}}}$"
# Além disso, o texto é uma lista do que é permitido: letras, marcas, números, pontuação, símbolos e
# espaços. Fica de fora o que a tela não mostra e o modelo lê: os caracteres de formatação (Cf), como
# as etiquetas U+E0000 a U+E007F e os de largura zero, que escondem uma instrução num texto que parece
# inofensivo; os de uso privado (Co); os sem atribuição (Cn); os substitutos soltos (Cs); e os
# preenchimentos que o Unicode classifica como letra ou símbolo, mas que aparecem em branco.
_GRUPOS_PERMITIDOS = frozenset("LMNPS")
_PREENCHIMENTOS = frozenset("\u115f\u1160\u2800\u3164\uffa0")

# As 7 categorias que o modelo do sistema responde. Ele não separa DDoS de DoS: as features descrevem
# os pacotes, e não quantas máquinas atacam (decisão de 2026-10-04). A separação sai da quantidade de
# origens do incidente, fora do modelo, e só existe em `Incidente.categoria`. Os nomes são os de
# `ALVOS["7"]`, em `codigo/classificador/preparar.py`, e um teste confere que continuam iguais.
DDOS_E_DOS = "DDoS+DoS"
CATEGORIAS_DO_MODELO = (DDOS_E_DOS, *(nome for nome in CATEGORIAS if nome not in ("DDoS", "DoS")))

Categoria = Literal[CATEGORIAS]
CategoriaDoModelo = Literal[CATEGORIAS_DO_MODELO]
Agente = Literal[AGENTES]
Risco = Literal["baixo", "alto"]
ResultadoDoEfeito = Literal["cessou", "diminuiu", "persiste"]
# Por que uma proposta é de risco alto. O código é curto e estável, para quem programa sobre o
# contrato, e a frase é a que a pessoa lê antes de aprovar. A ordem é a da lista na proposta.
MOTIVOS_DE_RISCO_ALTO = {
    "acao_sempre_de_risco_alto": "A ação é sempre de risco alto, qualquer que seja o alvo ou o prazo.",
    "acao_nova": "A ação é nova, fora do catálogo.",
    "prazo_acima_do_limite": "A medida não tem prazo, ou o prazo pedido passa do máximo aceito para risco baixo.",
    "alvo_fora_do_incidente": "O alvo não está entre as origens nem entre os destinos do incidente.",
    "alvo_e_destino_do_incidente": (
        "O alvo é destino do incidente, isto é, o dispositivo atacado, e esta ação só é de risco baixo sobre "
        "uma origem."
    ),
    "alvo_na_rede_local": (
        "O alvo é um endereço da rede local, e bloqueá-lo equivale a isolar um dispositivo interno."
    ),
    "alvo_protegido": "O alvo é um endereço protegido pela política.",
    # Desde a versão 0.7.0: depois de uma rejeição, nenhuma ação no mesmo alvo sai sem a pessoa.
    "alvo_rejeitado": "A pessoa já rejeitou uma ação neste alvo neste incidente.",
    "orcamento_de_risco_baixo_esgotado": "O incidente já tem o máximo de medidas de risco baixo ativas.",
    "orcamento_global_de_risco_baixo_esgotado": (
        "O sistema já tem o máximo de medidas de risco baixo ativas, somando todos os incidentes."
    ),
}
CodigoDeRiscoAlto = Literal[tuple(MOTIVOS_DE_RISCO_ALTO)]
# Onde o modelo de uma chamada rodou: no gateway local ou num provedor de nuvem.
LUGARES_DO_MODELO = ("local", "nuvem")
LugarDoModelo = Literal[LUGARES_DO_MODELO]
# Por que o laço de um agente parou (`codigo/agente/laco.py`). Só resposta_final traz a resposta do
# modelo; recusa_do_provedor é o content_filter, e limite_de_saida, o length.
MOTIVOS_DE_PARADA = (
    "resposta_final",
    "limite_de_voltas",
    "chamada_repetida",
    "limite_de_tools",
    "limite_do_historico",
    "resposta_incompleta",
    "resposta_vazia",
    "recusa_do_provedor",
    "limite_de_saida",
)
MotivoDeParada = Literal[MOTIVOS_DE_PARADA]
# Os rótulos da skill da triagem, sem acento no código (ruído vira ruido), como os nomes dos agentes.
VEREDITOS_DA_TRIAGEM = ("coerente", "duvidoso", "ruido")
VereditoDaTriagem = Literal[VEREDITOS_DA_TRIAGEM]
MotivoDeRecusa = Literal[
    "identificador_desconhecido",
    "argumentos_invalidos",
    "alvo_malformado",
    "alvo_nao_permitido",
    "incidente_encerrado",
    "incidente_ja_resolvido",
    "limite_de_propostas_pendentes",
    "limite_de_propostas_liberadas",
    # Desde a versão 0.7.0: a proposta igual a uma que a pessoa já rejeitou no incidente.
    "proposta_repetida",
    "acao_nova_incompleta",
    "proposta_nao_liberada",
    "proposta_ja_executada",
    "acao_nao_aplicada",
    "tool_fora_da_linha",
]


def invisivel(letra):
    """Verdadeiro para o caractere que não aparece na tela e que nenhum texto do contrato aceita.

    A quebra de linha fica de fora: quem diz onde ela é aceita é a expressão regular de cada tipo
    de texto.
    """
    if letra in _PREENCHIMENTOS:
        return True
    if letra == "\n":
        return False
    categoria = unicodedata.category(letra)
    # Letra, marca, número, pontuação e símbolo; dos separadores, só o espaço (Zs).
    return categoria[0] not in _GRUPOS_PERMITIDOS and categoria != "Zs"


def _so_visiveis(texto):
    if any(invisivel(letra) for letra in texto):
        raise ValueError("o texto traz caractere que não aparece na tela (formatação, uso privado ou preenchimento)")
    return texto


def _texto(maximo, padrao=_UMA_LINHA, minimo=1):
    return Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=minimo, max_length=maximo, pattern=padrao),
        AfterValidator(_so_visiveis),
    ]


def visivel(texto):
    """O texto com tudo o que não é imprimível trocado pela sequência de escape correspondente.

    É como o conteúdo do log aparece em um terminal ou em uma mensagem: o log é entrada, e uma
    sequência de controle gravada nele não pode chegar crua à tela de quem decide.
    """
    return "".join(
        letra if letra.isprintable() and letra not in _PREENCHIMENTOS
        else letra.encode("unicode_escape").decode("ascii")
        for letra in str(texto)
    )


def endereco_canonico(texto):
    """Endereço IP na forma canônica. Levanta ValueError se o texto não é um endereço.

    Zona de IPv6 (`fe80::1%eth0`) é recusada: o que vem depois de `%` é texto livre. Endereço IPv4
    escrito como IPv6 (`::ffff:192.168.137.1`) vira o IPv4, para que as regras que comparam
    endereços enxerguem o mesmo dispositivo.
    """
    if "%" in texto:
        raise ValueError("endereço IP com zona não é aceito")
    endereco = ipaddress.ip_address(texto)
    if endereco.version == 6 and endereco.ipv4_mapped is not None:
        endereco = endereco.ipv4_mapped
    return str(endereco)


# --- endereços em texto livre, para a linha de decisão ----------------------------------------

# O agente de decisão pode estar num modelo de nuvem e não recebe endereço nenhum (arquitetura
# híbrida, decisão de 2026-10-10). Os endereços do incidente chegam a ele como rótulos neutros, e o
# que sobrar em texto livre (um documento da base, uma ação promovida) é trocado por este marcador.
# A busca é larga de propósito: na dúvida, o trecho vira o marcador.
MARCADOR_DE_ENDERECO = "[endereço]"
# Rótulo neutro de um endereço do incidente, na ordem em que o endereço apareceu nele.
ROTULO = r"^(?:origem|destino)-[1-9][0-9]{0,5}$"
# As buscas abaixo não retrocedem: cada uma lê o texto uma vez, e o custo é linear no tamanho dele.
# O filtro roda com o log travado, e um texto montado de propósito não pode segurar a trava. Nenhuma
# olha o que vem antes ou depois do endereço: colado a uma letra, depois de `src:` ou com sufixo,
# ele vira o marcador do mesmo jeito. Elas correm sobre uma cópia normalizada do texto (`_normalizado`),
# para pegar também os dígitos e a pontuação de largura total, e o marcador entra no texto original.
#
# IPv6: cada trecho máximo só de dígitos hexadecimais, dois-pontos e pontos é conferido no código.
_TRECHO_HEXADECIMAL = re.compile(r"[0-9A-Fa-f:.]+")
# Dois dígitos hexadecimais separados por um ou dois dois-pontos: o que um IPv6 tem e uma pontuação não.
_GRUPOS_SEPARADOS = re.compile(r"[0-9A-Fa-f]:{1,2}[0-9A-Fa-f]")
# O maior IPv6 escrito por extenso, com um IPv4 no fim, tem 45 caracteres.
_MAIOR_IPV6 = 45
# MAC: seis grupos de um ou dois dígitos hexadecimais, com dois-pontos ou hífen (o `arp` do macOS
# escreve sem o zero à esquerda), e o formato com pontos, de três grupos de quatro.
_MAC_NO_TEXTO = re.compile(r"[0-9A-Fa-f]{1,2}(?:[:-][0-9A-Fa-f]{1,2}){5}|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}")
# IPv4 em quatro grupos de um a quatro dígitos, inclusive com zero à esquerda, octal ou fora da faixa,
# e o IPv4 "desarmado", como se escreve em texto de segurança: 203.0.113[.]7 ou 203(.)0(.)113(.)7.
_IPV4_NO_TEXTO = re.compile(r"[0-9]{1,4}(?:(?:\.|\[\.\]|\(\.\))[0-9]{1,4}){3}")
# O fim de um texto cortado que pode ser o começo de um endereço: o filtro não o reconheceria.
_FIM_CORTADO = re.compile(r"[0-9A-Fa-f:.\[\]()%-]+$")
# Caracteres que a normalização NFKC pode transformar num caractere de endereço.
_DE_ENDERECO = frozenset("0123456789abcdefABCDEF:.[]()%-")


def _normalizado(texto):
    """O texto com cada caractere que, pela NFKC, é um caractere de endereço trocado por ele.

    A troca é de um caractere por um, e o texto normalizado tem o mesmo tamanho do original: o que
    se acha nele está na mesma posição no original. Os demais caracteres ficam como estão.
    """
    if texto.isascii():
        return texto
    tabela = {}
    for letra in set(texto):
        if not letra.isascii():
            normal = unicodedata.normalize("NFKC", letra)
            if len(normal) == 1 and normal in _DE_ENDERECO:
                tabela[ord(letra)] = normal
    return texto.translate(tabela)


def _e_ipv6(trecho):
    """O trecho hexadecimal é um IPv6, ou quase.

    Com `::` e ao menos um dígito (inclusive `fe80::` e `::1`), ou com seis ou mais dois-pontos entre
    dígitos hexadecimais, nenhum horário nem razão é. Os demais são conferidos com `ipaddress`.
    """
    if trecho.count(":") < 2:
        return False
    if "::" in trecho:
        return any(letra not in ":." for letra in trecho)
    if _GRUPOS_SEPARADOS.search(trecho) is None:
        return False
    if trecho.count(":") >= 6:
        return True
    candidato = trecho.strip(".")
    if len(candidato) > _MAIOR_IPV6:
        return False
    try:
        ipaddress.IPv6Address(candidato)
    except ValueError:
        return False
    return True


def mascarar_enderecos(texto, cortado_no_fim=False):
    """O texto com todo endereço IPv4, IPv6 ou MAC trocado por `MARCADOR_DE_ENDERECO`.

    Os trechos de endereço achados pelas três buscas se juntam quando se sobrepõem: o IPv4 dentro
    de um IPv6 sai com ele. Com `cortado_no_fim`, o texto é um pedaço de outro maior, e o que o fim
    dele tiver de caractere de endereço também vira o marcador: pode ser o começo de um endereço
    cortado, que nenhuma busca reconheceria.
    """
    normal = _normalizado(texto)
    trechos = [achado.span() for achado in _TRECHO_HEXADECIMAL.finditer(normal) if _e_ipv6(achado.group())]
    for busca in (_IPV4_NO_TEXTO, _MAC_NO_TEXTO):
        trechos.extend(achado.span() for achado in busca.finditer(normal))
    if cortado_no_fim:
        # Só letras hexadecimais no fim não dizem nada de um endereço; um dígito ou um separador, sim.
        fim = _FIM_CORTADO.search(normal)
        if fim is not None and any(letra in "0123456789:.-" for letra in fim.group()):
            trechos.append(fim.span())
    if not trechos:
        return texto
    partes, posicao = [], 0
    for inicio, fim in sorted(trechos):
        if fim <= posicao:
            continue
        if inicio < posicao:
            # Sobreposto ao anterior: o marcador já cobre o começo deste.
            partes[-1] = MARCADOR_DE_ENDERECO
        else:
            partes.append(texto[posicao:inicio])
            partes.append(MARCADOR_DE_ENDERECO)
        posicao = fim
    partes.append(texto[posicao:])
    return "".join(partes)


def tem_endereco(texto):
    """Verdadeiro se o texto traz algo que o filtro da linha de decisão trocaria pelo marcador."""
    return isinstance(texto, str) and mascarar_enderecos(texto) != texto


# Texto curto, de uma linha: identificadores, alvos, nomes e títulos.
Texto = _texto(TEXTO_CURTO)
# Texto longo, de uma linha: justificativa, descrição, cada passo, efeito esperado e como desfazer.
TextoLongo = _texto(TEXTO_LONGO)
# Texto em parágrafos: a recomendação do agente de decisão e os trechos da base de conhecimento.
Paragrafos = _texto(TEXTO_LONGO, _PARAGRAFOS)
Consulta = _texto(TEXTO_LONGO, _PARAGRAFOS, minimo=0)
NomeDeAcao = Annotated[str, StringConstraints(max_length=MAIOR_NOME_DE_ACAO, pattern=_NOME_DE_ACAO)]
NomeDeFeature = Literal[COLUNAS]
# O maior endereço escrito por extenso é um IPv6 com um IPv4 no fim, de 45 caracteres.
EnderecoIP = Annotated[
    str,
    StringConstraints(strip_whitespace=True, max_length=45),
    AfterValidator(endereco_canonico),
    WithJsonSchema({"type": "string", "anyOf": [{"format": "ipv4"}, {"format": "ipv6"}]}),
]
Proporcao = Annotated[float, Field(ge=0, le=1)]
Contagem = Annotated[int, Field(ge=0)]
Rotulo = Annotated[str, StringConstraints(pattern=ROTULO)]
# A porta 0 não designa serviço nenhum, e o firewall não fecha uma porta que não existe.
Porta = Annotated[int, Field(ge=1, le=65_535)]
PROTOCOLOS_DE_TRANSPORTE = ("tcp", "udp")
Transporte = Literal[PROTOCOLOS_DE_TRANSPORTE]


class Modelo(BaseModel):
    """Base dos tipos do contrato. Campo desconhecido e número não finito são erros."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


# --- Incidente e janelas ---------------------------------------------------------------------


class EnderecoContado(Modelo):
    endereco: EnderecoIP = Field(description="Endereço IP, sem zona")
    quadros: Contagem = Field(description="Quadros desse endereço no incidente")


class PortaContada(Modelo):
    destino: EnderecoIP = Field(description="Destino do incidente que recebe os quadros nessa porta")
    porta: Porta = Field(description="Porta de destino do TCP ou do UDP")
    protocolo: Transporte
    quadros: Contagem = Field(description="Quadros enviados a essa porta do destino no incidente")


class FeaturePrincipal(Modelo):
    nome: NomeDeFeature = Field(description="Nome da feature: uma das 39 colunas do extrator")
    valor: float = Field(description="Valor típico da feature nas janelas do incidente")
    referencia_benigno: float = Field(description="Valor típico da mesma feature no tráfego benigno")


class PortaDoCandidato(Modelo):
    porta: Porta = Field(description="Porta de destino do TCP ou do UDP")
    protocolo: Transporte
    quadros: Contagem = Field(description="Quadros que o candidato mandou a essa porta, em qualquer destino")


class CandidatoAAtacante(Modelo):
    """Uma origem que pode ser o atacante, com as medidas para a triagem decidir.

    Quem escolhe entre os candidatos é o agente de triagem (decisão de 2026-10-31), com
    `apontar_atacante`. A regra fixa do reprodutor, que dá as `origens`, acerta o atacante em pouco
    mais da metade dos incidentes da avaliação.
    """

    endereco: EnderecoIP = Field(description="Endereço IP, sem zona")
    janelas: Contagem = Field(description="Janelas do incidente em que o endereço aparece como origem")
    no_trafego_normal: Proporcao = Field(
        description="Parcela das janelas benignas, fora de incidente, em que o endereço aparece como origem"
    )
    quadros_enviados: Contagem = Field(description="Quadros que o endereço mandou no incidente")
    quadros_recebidos: Contagem = Field(description="Quadros que o endereço recebeu no incidente")
    conexoes_abertas: Contagem = Field(description="Conexões TCP que o endereço abriu no incidente (SYN sem ACK)")
    conexoes_recebidas: Contagem = Field(description="Conexões TCP que outros abriram com o endereço no incidente")
    destinos: list[EnderecoContado] = Field(
        max_length=DESTINOS_DO_CANDIDATO, description="Destinos a que o endereço mais mandou quadros, do maior para o menor"
    )
    portas: list[PortaDoCandidato] = Field(
        default_factory=list,
        max_length=PORTAS_DO_CANDIDATO,
        description="Portas de destino a que o endereço mais mandou quadros, da maior para a menor",
    )


class Incidente(Modelo):
    """Resumo de um ataque: as janelas do mesmo ataque, reunidas pela política de acionamento."""

    id: Texto = Field(description="Identificador do incidente, como inc-0001")
    estado: Literal["aberto", "encerrado"]
    categoria: Categoria = Field(
        description="Categoria depois da regra que separa DoS de DDoS pela quantidade de origens"
    )
    categoria_do_modelo: CategoriaDoModelo = Field(
        description="Categoria que o Random Forest atribuiu, entre as 7 do modelo, com DDoS e DoS juntos"
    )
    confianca: Proporcao = Field(description="Confiança do classificador, de 0 a 1")
    inicio: AwareDatetime
    fim: AwareDatetime
    janelas: int = Field(ge=1, description="Quantidade de janelas reunidas no incidente")
    origens_distintas: Contagem
    distribuido: bool = Field(description="Verdadeiro quando o tráfego vem de várias origens")
    origens: list[EnderecoContado] = Field(description="Origens com mais quadros, da maior para a menor")
    destinos: list[EnderecoContado] = Field(description="Destinos com mais quadros, do maior para o menor")
    features_principais: list[FeaturePrincipal] = Field(
        description="Features que mais pesaram, com o valor de referência do tráfego benigno"
    )
    # Com valor padrão, para que um log gravado antes das portas continue legível.
    portas: list[PortaContada] = Field(
        default_factory=list,
        description=(
            "Portas de destino que mais receberam quadros nos destinos listados, da maior para a menor. Vem "
            "vazia sem TCP nem UDP, como num ARP spoofing ou num flood ICMP"
        ),
    )
    # Os dois abaixo entraram na versão 0.6.0, com valor padrão para o log anterior continuar legível.
    janelas_por_categoria: dict[CategoriaDoModelo, Contagem] = Field(
        default_factory=dict,
        description=(
            "O que o classificador disse de cada janela do incidente, contando as benignas que ficaram entre as "
            "de ataque. Cobre todas as janelas, e não só as que obter_janelas devolve"
        ),
    )
    candidatos: list[CandidatoAAtacante] = Field(
        default_factory=list,
        max_length=MAXIMO_DE_CANDIDATOS,
        description=(
            "Até cinco origens, entre as da regra fixa, as que mais se destacam do tráfego normal e as que mais mandam "
            "do que recebem, da que mais se destaca para a que menos, com as medidas de cada uma, para a "
            "triagem apontar o atacante. Vem vazia quando nenhuma origem serve, como num flood com origem forjada"
        ),
    )

    @model_validator(mode="after")
    def _portas_sao_de_destinos_listados(self):
        listados = {item.endereco for item in self.destinos}
        fora = sorted({porta.destino for porta in self.portas} - listados)
        if fora:
            raise ValueError(f"as portas citam destinos que o incidente não lista: {', '.join(fora)}")
        return self

    @model_validator(mode="after")
    def _categoria_cabe_no_que_o_modelo_disse(self):
        # A regra das origens só separa DDoS de DoS. As outras categorias são as do modelo.
        possiveis = ("DDoS", "DoS") if self.categoria_do_modelo == DDOS_E_DOS else (self.categoria_do_modelo,)
        if self.categoria not in possiveis:
            raise ValueError(
                f"a categoria {self.categoria} não sai do que o modelo disse ({self.categoria_do_modelo})"
            )
        return self


class AtacanteApontado(Modelo):
    """O atacante que a triagem apontou entre os candidatos e as origens do incidente."""

    endereco: EnderecoIP = Field(description="Endereço do atacante, um dos candidatos ou das origens do incidente")
    justificativa: TextoLongo = Field(description="Por que este é o atacante, com as medidas que pesaram")


class AtacanteRotulado(Modelo):
    rotulo: Rotulo = Field(description="Rótulo neutro do atacante apontado, como origem-3")
    justificativa: TextoLongo = Field(
        description="A justificativa da triagem, com cada endereço do incidente trocado pelo rótulo dele"
    )


class EnderecoRotulado(Modelo):
    rotulo: Rotulo = Field(description="Rótulo neutro do endereço no incidente, como origem-1 ou destino-1")
    quadros: Contagem = Field(description="Quadros desse endereço no incidente")
    protegido: bool = Field(description="Verdadeiro quando o endereço é protegido pela política, como o gateway")


class PortaRotulada(Modelo):
    destino: Rotulo = Field(description="Rótulo neutro do destino que recebe os quadros nessa porta, como destino-1")
    porta: Porta = Field(description="Porta de destino do TCP ou do UDP")
    protocolo: Transporte
    quadros: Contagem = Field(description="Quadros enviados a essa porta do destino no incidente")


# As 39 features, com os nomes das colunas do extrator. O valor é nulo quando o extrator não
# produz um número finito: Rate de uma janela em que todos os quadros têm o mesmo instante, e
# Std e Variance de uma janela com um só quadro.
Features = TypedDict("Features", {coluna: float | None for coluna in COLUNAS})
Features.__pydantic_config__ = ConfigDict(extra="forbid", allow_inf_nan=False)


class Janela(Modelo):
    """Uma janela de quadros consecutivos, como sai do extrator e do classificador."""

    indice: Contagem = Field(description="Posição da janela dentro do incidente, a partir de 0")
    instante: AwareDatetime
    categoria_do_modelo: CategoriaDoModelo
    confianca: Proporcao
    origem: EnderecoIP = Field(description="Endereço de origem mais frequente na janela")
    destino: EnderecoIP = Field(description="Endereço de destino mais frequente na janela")
    features: Features


class FatiaDeJanelas(Modelo):
    incidente: Texto
    total: Contagem = Field(description="Quantidade de janelas do incidente")
    janelas: list[Janela] = Field(
        max_length=LIMITE_DE_JANELAS, description="Janelas espaçadas ao longo do incidente"
    )


# --- Mitigações e pesquisa -------------------------------------------------------------------


class ParametroDeAcao(Modelo):
    nome: Texto
    descricao: TextoLongo
    obrigatorio: bool


class AcaoDoCatalogo(Modelo):
    """Uma ação que o agente pode propor: da base ou promovida depois de aprovada e aplicada."""

    nome: NomeDeAcao
    descricao: TextoLongo
    alvo: TextoLongo = Field(description="O que o campo alvo da proposta deve trazer")
    parametros: list[ParametroDeAcao]
    regra: TextoLongo = Field(description="Nível de risco da ação e quando ela exige aprovação humana")
    origem: Literal["base", "promovida"]
    passos: list[TextoLongo] = Field(
        max_length=MAXIMO_DE_PASSOS, description="Passos aplicados. Vazio nas ações da base"
    )
    efeito_esperado: TextoLongo | None
    como_desfazer: TextoLongo
    fonte: Texto | None


class Trecho(Modelo):
    """Uma seção de um documento da base local de conhecimento."""

    origem: Texto = Field(description="Arquivo da base local de onde o trecho saiu")
    titulo: Texto
    texto: Paragrafos
    acao: NomeDeAcao | None = Field(description="Ação do catálogo que aplica a medida, quando existe")


class Mitigacoes(Modelo):
    categoria: Categoria
    mitigacoes: list[Trecho] = Field(
        max_length=LIMITE_DE_MITIGACOES,
        description=f"Medidas recomendadas que o catálogo de ações cobre, até {LIMITE_DE_MITIGACOES}",
    )
    acoes: list[AcaoDoCatalogo] = Field(description="Catálogo de ações disponíveis")


class Solucoes(Modelo):
    consulta: Consulta
    fonte: Literal["base_local"] = Field(description="A busca na internet fica desligada neste trabalho")
    trechos: list[Trecho] = Field(
        max_length=LIMITE_DE_TRECHOS,
        description=f"Até {LIMITE_DE_TRECHOS} trechos mais próximos da consulta, do melhor para o pior",
    )


# --- Ações -----------------------------------------------------------------------------------


class ParametrosDeAcaoNova(Modelo):
    """O que `parametros` precisa trazer quando a ação proposta não está no catálogo.

    Cada texto tem uma linha só. É o que a pessoa lê, inteiro, antes de aprovar.
    """

    descricao: TextoLongo
    passos: list[TextoLongo] = Field(
        min_length=1, max_length=MAXIMO_DE_PASSOS, description="Passos que seriam aplicados, em ordem"
    )
    efeito_esperado: TextoLongo
    como_desfazer: TextoLongo
    fonte: Texto | None = Field(None, description="De onde a solução veio, quando houver")


class MotivoDeRiscoAlto(Modelo):
    """Um motivo pelo qual a proposta é de risco alto."""

    codigo: CodigoDeRiscoAlto = Field(description="Código do motivo, curto e estável")
    descricao: TextoLongo = Field(description="O motivo em uma frase, para a pessoa que decide")


class Proposta(Modelo):
    id: Texto = Field(description="Identificador da proposta, como prop-0001")
    incidente: Texto
    acao: NomeDeAcao
    alvo: Texto = Field(description="Sobre o que a ação age. Na resposta à linha de decisão, com o rótulo neutro")
    alvo_com_rotulo: Texto | None = Field(
        description=(
            "O alvo escrito com o rótulo neutro, como origem-1 ou admin@destino-1, quando veio assim: o servidor o "
            "trocou pelo endereço em alvo. Nulo quando o alvo veio sem rótulo"
        )
    )
    parametros: dict[str, Any]
    justificativa: TextoLongo
    nova: bool = Field(description="Verdadeiro quando a ação não está no catálogo")
    risco: Risco
    motivos_de_risco_alto: list[MotivoDeRiscoAlto] = Field(
        max_length=len(MOTIVOS_DE_RISCO_ALTO),
        description="Por que a proposta é de risco alto: todos os motivos que valem. Vazio quando o risco é baixo",
    )
    exige_aprovacao: bool
    estado: Literal["aguardando_aprovacao", "liberada", "rejeitada", "executada", "desfeita"]


class Execucao(Modelo):
    """Uma ação aplicada no ambiente simulado."""

    id: Texto = Field(description="Identificador da execução, como exec-0001")
    proposta: Texto
    incidente: Texto
    acao: NomeDeAcao
    alvo: Texto
    parametros: dict[str, Any]
    estado: Literal["aplicada", "desfeita"]
    aplicada_em: AwareDatetime
    desfeita_em: AwareDatetime | None


class Efeito(Modelo):
    execucao: Texto
    incidente: Texto
    resultado: ResultadoDoEfeito
    observacao: TextoLongo


class ResumoDoIncidente(Modelo):
    """O incidente como o agente de decisão o vê: montado pelo servidor, sem endereço nenhum.

    O agente de decisão pode estar num modelo de nuvem (arquitetura híbrida, decisão de
    2026-10-10). Os endereços chegam a ele como rótulos neutros, na ordem em que apareceram no
    incidente, e o rótulo de um endereço não muda quando o incidente é atualizado. `propor_acao`
    aceita o rótulo como alvo, e o servidor o troca pelo endereço.
    """

    id: Texto = Field(description="Identificador do incidente, como inc-0001")
    estado: Literal["aberto", "encerrado"]
    ja_resolvido: bool = Field(
        description="Verdadeiro quando a pessoa que opera a rede marcou o incidente como já resolvido: nada é proposto"
    )
    categoria: Categoria = Field(
        description="Categoria depois da regra que separa DoS de DDoS pela quantidade de origens"
    )
    categoria_do_modelo: CategoriaDoModelo = Field(description="Categoria que o Random Forest atribuiu")
    confianca: Proporcao = Field(description="Confiança do classificador, de 0 a 1")
    duracao_s: float = Field(ge=0, description="Duração do incidente até agora, em segundos")
    janelas: int = Field(ge=1, description="Quantidade de janelas reunidas no incidente")
    origens_distintas: Contagem
    distribuido: bool = Field(description="Verdadeiro quando o tráfego vem de várias origens")
    origens: list[EnderecoRotulado] = Field(description="Origens com mais quadros, da maior para a menor")
    destinos: list[EnderecoRotulado] = Field(description="Destinos com mais quadros, do maior para o menor")
    features_principais: list[FeaturePrincipal] = Field(
        description="Features que mais pesaram, com o valor de referência do tráfego benigno"
    )
    portas: list[PortaRotulada] = Field(
        description=(
            "Portas de destino que mais receberam quadros, com o rótulo do destino, da maior para a menor. Porta "
            "não é endereço: vem como está. É daqui que sai o alvo de fechar_porta, como 23/tcp@destino-1"
        )
    )
    ultimo_efeito: Efeito | None = Field(
        description="O último efeito verificado no incidente, depois de uma ação aplicada, ou nulo"
    )
    atacante_apontado: AtacanteRotulado | None = Field(
        default=None,
        description=(
            "O atacante que a triagem apontou, pelo rótulo, ou nulo quando ela não apontou. É o alvo das ações "
            "sobre a origem do ataque, mesmo quando não é a origem com mais quadros"
        ),
    )


class Ambiente(Modelo):
    """Medidas ativas no ambiente simulado. Ação desfeita não aparece."""

    bloqueios: list[Execucao]
    limites: list[Execucao]
    isolamentos: list[Execucao]
    credenciais_revogadas: list[Execucao]
    portas_fechadas: list[Execucao]
    outras_medidas: list[Execucao] = Field(description="Ações novas ou promovidas ao catálogo")


# --- Argumentos das tools --------------------------------------------------------------------


class EntradaObterIncidente(Modelo):
    id: str = Field(description="Identificador do incidente, como inc-0001")


class EntradaObterResumo(Modelo):
    id: str = Field(description="Identificador do incidente, como inc-0001")


class EntradaApontarAtacante(Modelo):
    """O limite de texto vale aqui, mas quem o confere é o servidor, para que a recusa fique no log."""

    id: str = Field(description="Identificador do incidente, como inc-0001")
    endereco: str = Field(description="Endereço do atacante: um dos candidatos ou das origens do incidente")
    justificativa: str = Field(
        description=f"Por que este é o atacante, citando as medidas. Texto de uma linha, com até {TEXTO_LONGO} caracteres"
    )


class EntradaObterJanelas(Modelo):
    id: str = Field(description="Identificador do incidente, como inc-0001")
    limite: int = Field(
        ge=1, description=f"Quantas janelas devolver. Acima de {LIMITE_DE_JANELAS}, vêm {LIMITE_DE_JANELAS}"
    )


class EntradaConsultarMitigacoes(Modelo):
    categoria: Categoria = Field(description="Categoria do incidente (campo categoria)")


class EntradaPesquisarSolucoes(Modelo):
    consulta: str = Field(
        description=f"Palavras que descrevem o problema ou a medida procurada, em até {TEXTO_LONGO} caracteres"
    )


class EntradaProporAcao(Modelo):
    """Os limites de texto valem aqui, mas quem os confere é o servidor, para que a recusa fique no log."""

    id: str = Field(description="Identificador do incidente, como inc-0001")
    acao: str = Field(
        description=(
            "Nome de uma ação do catálogo ou nome de uma ação nova: letras minúsculas sem acento, números e "
            f"sublinhado, até {MAIOR_NOME_DE_ACAO} caracteres"
        )
    )
    alvo: str = Field(
        description=(
            f"Sobre o que a ação age, em até {TEXTO_CURTO} caracteres. O formato depende da ação. Um endereço do "
            "incidente é escrito com o rótulo neutro do resumo, como origem-1, destino-1, admin@destino-1 ou "
            "23/tcp@destino-1; o agente de decisão não escreve endereço"
        )
    )
    parametros: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Parâmetros da ação. Ação nova, fora do catálogo, traz aqui descricao, passos (até "
            f"{MAXIMO_DE_PASSOS}), efeito_esperado, como_desfazer e, quando houver, fonte. Ação promovida ao "
            "catálogo não aceita parâmetros"
        ),
    )
    justificativa: str = Field(
        description=(
            f"Por que a ação é indicada para este incidente. Texto de uma linha, com até {TEXTO_LONGO} caracteres"
        )
    )


class EntradaVerificarEfeito(Modelo):
    id_execucao: str = Field(description="Identificador da execução, como exec-0001")


class EntradaExecutarAcao(Modelo):
    id_proposta: str = Field(description="Identificador da proposta, como prop-0001")


class EntradaDesfazerAcao(Modelo):
    id_execucao: str = Field(description="Identificador da execução, como exec-0001")


class EntradaConsultarEstado(Modelo):
    pass


class Tool(NamedTuple):
    nome: str
    agentes: tuple[str, ...]
    descricao: str
    entrada: type[Modelo]
    saida: type[Modelo]


TOOLS = (
    Tool(
        "obter_incidente", ("triagem",),
        "Devolve o incidente: categoria, confiança do classificador, período, quantidade de janelas, "
        "o que o classificador disse de cada janela, origens, destinos, portas, as features que mais pesaram "
        "e os candidatos a atacante, com as medidas de cada um.",
        EntradaObterIncidente, Incidente,
    ),
    Tool(
        "apontar_atacante", ("triagem",),
        "Registra qual dos candidatos (ou das origens) do incidente é o atacante, com a justificativa. O agente "
        "de decisão recebe o rótulo dele no resumo, como alvo das ações sobre a origem. Chamada de novo, vale a "
        "última. Não aponte quando as medidas não mostram o atacante, como num flood com origem forjada.",
        EntradaApontarAtacante, AtacanteApontado,
    ),
    Tool(
        "obter_janelas", ("triagem",),
        f"Devolve até `limite` janelas do incidente, espaçadas ao longo dele, com as 39 features de cada "
        f"uma. O limite máximo é {LIMITE_DE_JANELAS}. Use quando o resumo não bastar.",
        EntradaObterJanelas, FatiaDeJanelas,
    ),
    Tool(
        "obter_resumo", ("decisao",),
        "Devolve o resumo do incidente montado pelo servidor, sem endereço nenhum: categorias, confiança, "
        "contagens, features com a referência do tráfego benigno, estado, último efeito verificado, a marca de "
        "já resolvido e os rótulos neutros das origens e dos destinos (origem-1, destino-1), que são o que "
        "propor_acao aceita como alvo.",
        EntradaObterResumo, ResumoDoIncidente,
    ),
    Tool(
        "consultar_mitigacoes", ("decisao",),
        "Devolve as mitigações recomendadas para a categoria e o catálogo de ações disponíveis, com a "
        "regra de risco de cada ação.",
        EntradaConsultarMitigacoes, Mitigacoes,
    ),
    Tool(
        "pesquisar_solucoes", ("decisao",),
        "Busca outras soluções na base local de conhecimento, além do catálogo. Use quando as mitigações "
        "recomendadas não resolverem. Cada trecho vem com o arquivo de origem.",
        EntradaPesquisarSolucoes, Solucoes,
    ),
    Tool(
        "propor_acao", ("decisao",),
        "Registra a proposta de uma ação do catálogo ou de uma ação nova e devolve o nível de risco e se "
        "ela exige aprovação humana. O alvo usa o rótulo neutro do resumo, como origem-1: o servidor o troca "
        "pelo endereço e calcula o risco sobre ele. Ação nova é sempre de risco alto e precisa trazer em "
        "`parametros` a descrição, os passos, o efeito esperado e como desfazer. Incidente marcado como já "
        "resolvido não recebe proposta. Proposta igual a uma que a pessoa já rejeitou no incidente é recusada, "
        "e qualquer outra sobre o mesmo alvo exige aprovação humana.",
        EntradaProporAcao, Proposta,
    ),
    Tool(
        "verificar_efeito", ("execucao",),
        "Diz se o incidente cessou, diminuiu ou persiste depois de uma ação aplicada.",
        EntradaVerificarEfeito, Efeito,
    ),
    Tool(
        "executar_acao", ("execucao",),
        "Aplica no ambiente simulado a ação de uma proposta liberada: de risco baixo ou já aprovada por "
        "uma pessoa. Proposta que aguarda aprovação ou foi rejeitada é recusada.",
        EntradaExecutarAcao, Execucao,
    ),
    Tool(
        "desfazer_acao", ("execucao",),
        "Reverte uma ação aplicada no ambiente simulado.",
        EntradaDesfazerAcao, Execucao,
    ),
    Tool(
        "consultar_estado", ("execucao",),
        "Devolve os bloqueios, limites, isolamentos e demais medidas ativas no ambiente simulado.",
        EntradaConsultarEstado, Ambiente,
    ),
)


def tools_do_agente(agente):
    """Nomes das tools que o agente enxerga. Com `TODOS`, todas: é preciso pedir, não é o padrão."""
    if agente == TODOS:
        return tuple(tool.nome for tool in TOOLS)
    if agente not in AGENTES:
        raise ValueError(f"agente desconhecido: {agente!r}. Diga {', '.join(AGENTES)} ou {TODOS}")
    return tuple(tool.nome for tool in TOOLS if agente in tool.agentes)


# --- Log de eventos --------------------------------------------------------------------------


class LoteDeJanelas(Modelo):
    janelas: Contagem = Field(description="Janelas do lote que saiu do classificador")
    por_categoria: dict[CategoriaDoModelo, Contagem] = Field(
        description="Janelas do lote em cada uma das 7 categorias do modelo"
    )


class ChamadaDeLLM(Modelo):
    agente: Agente
    modelo: Texto
    tokens_entrada: Contagem
    tokens_saida: Contagem
    duracao_ms: float = Field(ge=0)
    # Com valor padrão, para que um log gravado antes da versão 0.5.0 continue legível.
    motivo_termino: Texto | None = Field(
        default=None,
        description="O finish_reason que o provedor devolveu, como stop, tool_calls, length ou content_filter",
    )
    onde: LugarDoModelo | None = Field(
        default=None, description="Onde o modelo rodou: local, no gateway, ou nuvem"
    )


class ConclusaoDoAgente(Modelo):
    """Como terminou o laço de um agente num incidente: a base das tabelas de custo e de desfecho."""

    agente: Agente
    motivo: MotivoDeParada = Field(description="Por que o laço parou; só resposta_final traz a resposta do modelo")
    voltas: Contagem = Field(description="Chamadas ao modelo que o laço fez")
    tokens_entrada: Contagem = Field(description="Soma dos tokens de entrada das chamadas")
    tokens_saida: Contagem = Field(description="Soma dos tokens de saída das chamadas")
    veredito: VereditoDaTriagem | None = Field(
        description="Rótulo da triagem, lido da resposta dela; nulo nos outros agentes e quando a resposta não o traz"
    )

    @model_validator(mode="after")
    def _veredito_so_da_triagem(self):
        if self.veredito is not None and self.agente != "triagem":
            raise ValueError(f"só a triagem dá veredito, e veio um do agente de {self.agente}")
        return self


class ChamadaDeTool(Modelo):
    agente: Agente | None = Field(description="Agente que chamou, quando o servidor sabe quem é")
    nome: Texto = Field(description="Nome da tool")
    argumentos: dict[str, Any]
    resultado: dict[str, Any] = Field(description="Resumo do que a tool devolveu")
    duracao_ms: float = Field(ge=0)


class AnaliseDaTriagem(Modelo):
    """A resposta final da triagem, gravada pelo orquestrador: é o que o relatório mostra dela."""

    agente: Literal["triagem"]
    texto: Paragrafos
    veredito: VereditoDaTriagem | None = Field(description="Rótulo da triagem, lido do texto; nulo quando não vem")


class Sumario(Modelo):
    """O sumário do incidente, escrito pelo agente de triagem a partir do log quando o orquestrador termina."""

    agente: Literal["triagem"]
    texto: Paragrafos


class Recomendacao(Modelo):
    agente: Agente
    texto: Paragrafos
    propostas: list[Texto] = Field(
        max_length=MAXIMO_DE_PROPOSTAS_POR_RECOMENDACAO, description="Propostas de ação ligadas à recomendação"
    )


class Decisao(Modelo):
    """Aprovação ou rejeição de uma proposta. Só uma pessoa decide, nunca um agente."""

    proposta: Texto
    canal: Literal["terminal", "interface"]
    usuario: Texto = Field(description="Usuário do sistema que registrou a decisão")
    motivo: TextoLongo | None


class MarcaDeResolvido(Modelo):
    """A pessoa que opera a rede diz que já resolveu o incidente por conta própria.

    É o botão "Já resolvido" da interface, ou o comando de terminal (decisão de 2026-10-10). Com a
    marca, o servidor não registra nem executa proposta do incidente, nem a já aprovada: os agentes
    só explicam o que aconteceu.
    """

    incidente: Texto
    canal: Literal["terminal", "interface"]
    usuario: Texto = Field(description="Usuário do sistema que marcou o incidente")
    motivo: TextoLongo | None = Field(description="O que a pessoa fez, quando ela disser")


class Promocao(Modelo):
    proposta: Texto
    acao: AcaoDoCatalogo


class Recusa(Modelo):
    agente: Agente | None
    tool: Texto
    argumentos: dict[str, Any]
    motivo: MotivoDeRecusa
    mensagem: TextoLongo


# Tipos de evento e o que cada um traz em `dados`, na ordem da tabela da especificação.
EVENTOS = (
    ("EventoDeJanelas", ("janelas_classificadas",), LoteDeJanelas),
    ("EventoDeIncidente", ("incidente_aberto", "incidente_atualizado", "incidente_encerrado"), Incidente),
    ("EventoDeMarca", ("incidente_marcado_resolvido",), MarcaDeResolvido),
    ("EventoDeLLM", ("llm_chamada",), ChamadaDeLLM),
    ("EventoDeTool", ("tool_chamada",), ChamadaDeTool),
    ("EventoDeConclusao", ("agente_concluido",), ConclusaoDoAgente),
    ("EventoDeAtacante", ("atacante_apontado",), AtacanteApontado),
    ("EventoDeAnalise", ("analise_emitida",), AnaliseDaTriagem),
    ("EventoDeRecomendacao", ("recomendacao_emitida",), Recomendacao),
    ("EventoDeSumario", ("sumario_emitido",), Sumario),
    ("EventoDeProposta", ("acao_proposta",), Proposta),
    ("EventoDeDecisao", ("acao_aprovada", "acao_rejeitada"), Decisao),
    ("EventoDeExecucao", ("acao_executada", "acao_desfeita"), Execucao),
    ("EventoDeEfeito", ("efeito_verificado",), Efeito),
    ("EventoDeCatalogo", ("catalogo_ampliado",), Promocao),
    ("EventoDeRecusa", ("recusa",), Recusa),
)
TIPOS_DE_EVENTO = tuple(tipo for _, tipos, _ in EVENTOS for tipo in tipos)


def _modelo_de_evento(nome, tipos, dados):
    """Uma linha do log: os campos comuns, mais `dados` no formato do tipo do evento."""
    return create_model(
        nome,
        __base__=Modelo,
        id=(Texto, Field(description="Identificador do evento, sequencial dentro do arquivo")),
        instante=(AwareDatetime, ...),
        tipo=(Literal[tipos], ...),
        incidente=(Texto | None, Field(description="Incidente a que o evento se refere, quando houver")),
        dados=(dados, ...),
    )


# A união dos modelos de evento: o campo `tipo` diz qual deles vale para a linha.
_QualquerEvento = reduce(or_, (_modelo_de_evento(*evento) for evento in EVENTOS))


class Evento(RootModel[Annotated[_QualquerEvento, Field(discriminator="tipo")]]):
    """Uma linha do log de eventos."""


def validar_evento(dados):
    """Confere um evento contra o contrato e devolve o modelo do tipo dele."""
    return Evento.model_validate(dados).root


# --- contrato.json ---------------------------------------------------------------------------


class _SemTituloDeCampo(GenerateJsonSchema):
    """Gera o esquema sem repetir o nome de cada campo em `title`."""

    def field_title_should_be_set(self, schema):
        return False


def contrato():
    """O contrato em JSON Schema: as onze tools, o evento do log e as definições dos tipos.

    Traz também a tabela dos motivos de risco alto, com a frase de cada código.
    """
    modelos = dict.fromkeys(
        [*(tool.entrada for tool in TOOLS), *(tool.saida for tool in TOOLS), ParametrosDeAcaoNova, Evento]
    )
    _, esquema = models_json_schema(
        [(modelo, "validation") for modelo in modelos],
        ref_template="#/$defs/{model}",
        schema_generator=_SemTituloDeCampo,
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "titulo": "Contrato MCP do SentryIoT",
        "versao": VERSAO,
        "limite_de_janelas": LIMITE_DE_JANELAS,
        "motivos_de_risco_alto": MOTIVOS_DE_RISCO_ALTO,
        "tools": {
            tool.nome: {
                "descricao": tool.descricao,
                "agentes": list(tool.agentes),
                "entrada": {"$ref": f"#/$defs/{tool.entrada.__name__}"},
                "saida": {"$ref": f"#/$defs/{tool.saida.__name__}"},
            }
            for tool in TOOLS
        },
        "evento": {"$ref": "#/$defs/Evento"},
        "$defs": esquema["$defs"],
    }


def texto_do_contrato():
    return json.dumps(contrato(), indent=2, ensure_ascii=False) + "\n"


def main():
    ARQUIVO_DO_CONTRATO.write_text(texto_do_contrato(), encoding="utf-8")
    print(f"contrato gravado em {ARQUIVO_DO_CONTRATO}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
