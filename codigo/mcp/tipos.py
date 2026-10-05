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
import sys
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
)
from pydantic.json_schema import GenerateJsonSchema, models_json_schema
from typing_extensions import TypedDict

from codigo.captura.extrator import COLUNAS
from codigo.classificador.mapeamento import CATEGORIAS

VERSAO = "0.1.0"
# Máximo de janelas que o agente recebe por chamada. Um flood tem milhares de janelas, e mandar
# todas para a LLM custaria tokens demais.
LIMITE_DE_JANELAS = 20
ARQUIVO_DO_CONTRATO = Path(__file__).with_name("contrato.json")
AGENTES = ("triagem", "decisao", "execucao")
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

Categoria = Literal[CATEGORIAS]
Agente = Literal[AGENTES]
Risco = Literal["baixo", "alto"]
ResultadoDoEfeito = Literal["cessou", "diminuiu", "persiste"]
MotivoDeRecusa = Literal[
    "identificador_desconhecido",
    "argumentos_invalidos",
    "alvo_malformado",
    "alvo_nao_permitido",
    "incidente_encerrado",
    "acao_nova_incompleta",
    "proposta_nao_liberada",
    "proposta_ja_executada",
    "acao_nao_aplicada",
    "tool_fora_da_linha",
]


def _texto(maximo, padrao=_UMA_LINHA, minimo=1):
    return Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=minimo, max_length=maximo, pattern=padrao)
    ]


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


class Modelo(BaseModel):
    """Base dos tipos do contrato. Campo desconhecido e número não finito são erros."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


# --- Incidente e janelas ---------------------------------------------------------------------


class EnderecoContado(Modelo):
    endereco: EnderecoIP = Field(description="Endereço IP, sem zona")
    quadros: Contagem = Field(description="Quadros desse endereço no incidente")


class FeaturePrincipal(Modelo):
    nome: NomeDeFeature = Field(description="Nome da feature: uma das 39 colunas do extrator")
    valor: float = Field(description="Valor típico da feature nas janelas do incidente")
    referencia_benigno: float = Field(description="Valor típico da mesma feature no tráfego benigno")


class Incidente(Modelo):
    """Resumo de um ataque: as janelas do mesmo ataque, reunidas pela política de acionamento."""

    id: Texto = Field(description="Identificador do incidente, como inc-0001")
    estado: Literal["aberto", "encerrado"]
    categoria: Categoria = Field(
        description="Categoria depois da regra que separa DoS de DDoS pela quantidade de origens"
    )
    categoria_do_modelo: Categoria = Field(description="Categoria que o Random Forest atribuiu")
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


# As 39 features, com os nomes das colunas do extrator. O valor é nulo quando o extrator não
# produz um número finito: Rate de uma janela em que todos os quadros têm o mesmo instante, e
# Std e Variance de uma janela com um só quadro.
Features = TypedDict("Features", {coluna: float | None for coluna in COLUNAS})
Features.__pydantic_config__ = ConfigDict(extra="forbid", allow_inf_nan=False)


class Janela(Modelo):
    """Uma janela de quadros consecutivos, como sai do extrator e do classificador."""

    indice: Contagem = Field(description="Posição da janela dentro do incidente, a partir de 0")
    instante: AwareDatetime
    categoria_do_modelo: Categoria
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
    mitigacoes: list[Trecho] = Field(description="Medidas recomendadas que o catálogo de ações cobre")
    acoes: list[AcaoDoCatalogo] = Field(description="Catálogo de ações disponíveis")


class Solucoes(Modelo):
    consulta: Consulta
    fonte: Literal["base_local"] = Field(description="A busca na internet fica desligada neste trabalho")
    trechos: list[Trecho] = Field(description="Trechos mais próximos da consulta, do melhor para o pior")


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


class Proposta(Modelo):
    id: Texto = Field(description="Identificador da proposta, como prop-0001")
    incidente: Texto
    acao: NomeDeAcao
    alvo: Texto
    parametros: dict[str, Any]
    justificativa: TextoLongo
    nova: bool = Field(description="Verdadeiro quando a ação não está no catálogo")
    risco: Risco
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


class Ambiente(Modelo):
    """Medidas ativas no ambiente simulado. Ação desfeita não aparece."""

    bloqueios: list[Execucao]
    limites: list[Execucao]
    isolamentos: list[Execucao]
    credenciais_revogadas: list[Execucao]
    outras_medidas: list[Execucao] = Field(description="Ações novas ou promovidas ao catálogo")


# --- Argumentos das tools --------------------------------------------------------------------


class EntradaObterIncidente(Modelo):
    id: str = Field(description="Identificador do incidente, como inc-0001")


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
        description=f"Sobre o que a ação age, em até {TEXTO_CURTO} caracteres. O formato depende da ação"
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
        "obter_incidente", ("triagem", "decisao"),
        "Devolve o resumo do incidente: categoria, confiança do classificador, período, quantidade de "
        "janelas, origens, destinos e as features que mais pesaram.",
        EntradaObterIncidente, Incidente,
    ),
    Tool(
        "obter_janelas", ("triagem",),
        f"Devolve até `limite` janelas do incidente, espaçadas ao longo dele, com as 39 features de cada "
        f"uma. O limite máximo é {LIMITE_DE_JANELAS}. Use quando o resumo não bastar.",
        EntradaObterJanelas, FatiaDeJanelas,
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
        "ela exige aprovação humana. Ação nova é sempre de risco alto e precisa trazer em `parametros` "
        "a descrição, os passos, o efeito esperado e como desfazer.",
        EntradaProporAcao, Proposta,
    ),
    Tool(
        "verificar_efeito", ("decisao", "execucao"),
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
    """Nomes das tools que o agente enxerga. Sem agente, todas."""
    if agente is None:
        return tuple(tool.nome for tool in TOOLS)
    if agente not in AGENTES:
        raise ValueError(f"agente desconhecido: {agente!r}")
    return tuple(tool.nome for tool in TOOLS if agente in tool.agentes)


# --- Log de eventos --------------------------------------------------------------------------


class LoteDeJanelas(Modelo):
    janelas: Contagem = Field(description="Janelas do lote que saiu do classificador")
    por_categoria: dict[Categoria, Contagem]


class ChamadaDeLLM(Modelo):
    agente: Agente
    modelo: Texto
    tokens_entrada: Contagem
    tokens_saida: Contagem
    duracao_ms: float = Field(ge=0)


class ChamadaDeTool(Modelo):
    agente: Agente | None = Field(description="Agente que chamou, quando o servidor sabe quem é")
    nome: Texto = Field(description="Nome da tool")
    argumentos: dict[str, Any]
    resultado: dict[str, Any] = Field(description="Resumo do que a tool devolveu")
    duracao_ms: float = Field(ge=0)


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
    motivo: TextoLongo | None


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
    ("EventoDeLLM", ("llm_chamada",), ChamadaDeLLM),
    ("EventoDeTool", ("tool_chamada",), ChamadaDeTool),
    ("EventoDeRecomendacao", ("recomendacao_emitida",), Recomendacao),
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
    """O contrato em JSON Schema: as nove tools, o evento do log e as definições dos tipos."""
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
