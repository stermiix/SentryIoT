"""Base local de conhecimento e a busca usada por `pesquisar_solucoes`.

A base é o levantamento de mitigações da equipe, em `codigo/agente/recomendacoes/`: um documento
em markdown por categoria de ataque, com as medidas numa tabela e a fonte de cada uma. Cada
medida vira um trecho. Dela saem duas respostas:

- `consultar_mitigacoes` devolve as medidas da categoria que têm uma ação do catálogo, até 10.
- `pesquisar_solucoes` procura em todas as medidas, inclusive nas que o catálogo não cobre. É
  por aí que o agente de decisão encontra uma saída quando a base de ações não resolve.

A busca é por palavras, sem modelo de linguagem e sem rede: neste trabalho nenhum dado sai da
máquina, e a busca na internet fica desligada.

Formato de um documento do levantamento:

    # Título do documento

    Categorias: DDoS

    ## Mitigações recomendadas

    | Mitigação | Ação do catálogo | Fonte |
    | --- | --- | --- |
    | Texto da medida. | `bloquear_ip` | [Nome da fonte](https://...) |

Cada linha da tabela é uma medida: o texto vira o título do trecho, e a fonte, o texto dele. A
ação do catálogo é `nenhuma` quando nenhuma das quatro ações aplica a medida, e a fonte é
obrigatória. As colunas são achadas pelo nome, na linha de cabeçalho.

A base também aceita a medida escrita em texto corrido, numa seção própria:

    ## Título da medida

    Ação do catálogo: bloquear_ip

    Texto da medida, em um ou mais parágrafos.

As linhas `Categorias:` e `Ação do catálogo:` são opcionais, e uma seção traz texto ou tabela,
não os dois. Documento sem categoria é material de referência e só aparece na pesquisa. O
`README.md` da pasta não faz parte da base.
"""
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from codigo.classificador.mapeamento import CATEGORIAS
from codigo.mcp.acoes import BASE
from codigo.mcp.tipos import (
    LIMITE_DE_MITIGACOES,
    LIMITE_DE_TRECHOS,
    TEXTO_CURTO,
    TEXTO_LONGO,
    Trecho,
)

PASTA_PADRAO = Path(__file__).parents[1] / "agente" / "recomendacoes"
_CATEGORIAS = "Categorias:"
_ACAO = "Ação do catálogo:"
# Nomes das colunas da tabela, já em minúsculas. A primeira coluna é sempre a da medida.
_COLUNA_DA_ACAO = "ação do catálogo"
_COLUNA_DA_FONTE = "fonte"
_SEM_ACAO = "nenhuma"
_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
# Palavras que não ajudam a distinguir um trecho do outro, já sem acento.
_VAZIAS = frozenset((
    "a", "ao", "aos", "as", "com", "como", "da", "das", "de", "do", "dos", "e", "em", "na", "nas", "no", "nos",
    "o", "os", "ou", "para", "por", "que", "se", "sem", "um", "uma",
))
# Tamanho da raiz comparada: aproxima "bloquear" de "bloqueio" e o singular do plural.
_RAIZ = 5


@dataclass(frozen=True)
class Secao:
    """Uma medida descrita em um documento da base.

    As palavras do título, do texto e do título do documento são separadas uma vez, na leitura: a
    cada pesquisa, só a consulta é quebrada em palavras.
    """

    origem: str
    documento: str
    titulo: str
    texto: str
    categorias: tuple
    acao: str | None
    palavras_do_titulo: frozenset = field(default=frozenset(), compare=False, repr=False)
    palavras_do_texto: Counter = field(default_factory=Counter, compare=False, repr=False, hash=False)
    palavras_do_documento: frozenset = field(default=frozenset(), compare=False, repr=False)

    def trecho(self):
        return Trecho(origem=self.origem, titulo=self.titulo, texto=self.texto, acao=self.acao)


def carregar(pasta=PASTA_PADRAO):
    """Lê os documentos da pasta, em ordem de nome, e devolve as seções de todos eles."""
    pasta = Path(pasta)
    if not pasta.is_dir():
        raise ValueError(f"pasta da base de conhecimento não encontrada: {pasta}")
    secoes = []
    for arquivo in sorted(pasta.glob("*.md")):
        if arquivo.name.casefold() != "readme.md":
            secoes.extend(_ler_documento(arquivo))
    return tuple(secoes)


def _ler_documento(arquivo):
    def invalido(detalhe):
        return ValueError(f"documento da base fora do formato ({arquivo.name}): {detalhe}")

    def acao_do_catalogo(nome):
        if nome not in BASE:
            raise invalido(f"a ação {nome} não está no catálogo de base")
        return nome

    documento = None
    categorias = ()
    # Cada seção em montagem: título, ação, os parágrafos, cada um como lista de linhas, e a
    # tabela, com as colunas do cabeçalho e as linhas de medida.
    secoes = []
    for linha in arquivo.read_text(encoding="utf-8").splitlines():
        linha = linha.strip()
        if linha.startswith("## "):
            if documento is None:
                raise invalido("a seção veio antes do título do documento")
            secoes.append({"titulo": linha[3:].strip(), "acao": None, "paragrafos": [[]], "colunas": None, "linhas": []})
        elif linha.startswith("# "):
            documento = linha[2:].strip()
        elif linha.startswith(_CATEGORIAS) and not secoes:
            categorias = tuple(nome.strip() for nome in linha[len(_CATEGORIAS):].split(",") if nome.strip())
            desconhecidas = [nome for nome in categorias if nome not in CATEGORIAS]
            if desconhecidas:
                raise invalido(f"categoria desconhecida: {', '.join(desconhecidas)}")
        elif linha.startswith(_ACAO) and secoes:
            secoes[-1]["acao"] = acao_do_catalogo(linha[len(_ACAO):].strip())
        elif linha.startswith("|") and secoes:
            celulas = [celula.strip() for celula in linha.strip("|").split("|")]
            secao = secoes[-1]
            if secao["colunas"] is None:
                secao["colunas"] = [celula.casefold() for celula in celulas]
                if _COLUNA_DA_ACAO not in secao["colunas"] or _COLUNA_DA_FONTE not in secao["colunas"]:
                    raise invalido(f"a tabela da seção {secao['titulo']!r} precisa das colunas 'Ação do catálogo' e 'Fonte'")
            elif len(celulas) != len(secao["colunas"]):
                raise invalido(f"a linha {celulas[0][:60]!r} não tem as {len(secao['colunas'])} colunas do cabeçalho")
            elif not all(celula and set(celula) <= set("-: ") for celula in celulas):
                # A linha de traços que separa o cabeçalho das medidas não é medida.
                secao["linhas"].append(celulas)
        elif secoes:
            # Linha em branco fecha o parágrafo. O que vem antes da primeira seção é introdução.
            if linha:
                secoes[-1]["paragrafos"][-1].append(linha)
            elif secoes[-1]["paragrafos"][-1]:
                secoes[-1]["paragrafos"].append([])
    if documento is None:
        raise invalido("falta o título do documento, em uma linha que começa com '# '")
    if not secoes:
        raise invalido("nenhuma seção encontrada; cada medida começa com '## '")

    def montar(titulo, texto, acao):
        lida = Secao(
            arquivo.name, documento, titulo, texto, categorias, acao,
            palavras_do_titulo=frozenset(_raizes(titulo)), palavras_do_texto=Counter(_raizes(texto)),
            palavras_do_documento=frozenset(_raizes(documento)),
        )
        # Cada medida vira um trecho do contrato. Conferir aqui faz o erro aparecer na partida, e
        # não na primeira consulta de um agente.
        try:
            lida.trecho()
        except ValidationError:
            raise invalido(
                f"a medida {titulo[:60]!r} não cabe no contrato: o título tem até {TEXTO_CURTO} "
                f"caracteres, o texto tem até {TEXTO_LONGO}, e nenhum dos dois aceita caractere de controle nem "
                "caractere que não aparece na tela"
            ) from None
        return lida

    resultado = []
    for secao in secoes:
        texto = "\n\n".join(" ".join(linhas) for linhas in secao["paragrafos"] if linhas)
        if secao["colunas"] is not None:
            if texto or secao["acao"] is not None:
                raise invalido(f"a seção {secao['titulo']!r} traz tabela e texto; cada seção traz um ou outro")
            coluna_da_acao = secao["colunas"].index(_COLUNA_DA_ACAO)
            coluna_da_fonte = secao["colunas"].index(_COLUNA_DA_FONTE)
            for celulas in secao["linhas"]:
                medida, fonte = celulas[0], _LINK.sub(r"\1 (\2)", celulas[coluna_da_fonte])
                if not medida or not fonte:
                    raise invalido(f"a linha {medida[:60]!r} está sem a medida ou sem a fonte")
                nome = celulas[coluna_da_acao].strip("`").strip()
                acao = None if nome.casefold() == _SEM_ACAO else acao_do_catalogo(nome)
                resultado.append(montar(medida, f"Fonte: {fonte}", acao))
            continue
        if not secao["titulo"] or not texto:
            raise invalido(f"a seção {secao['titulo']!r} está sem título ou sem texto")
        resultado.append(montar(secao["titulo"], texto, secao["acao"]))
    return resultado


def mitigacoes(secoes, categoria, limite=LIMITE_DE_MITIGACOES):
    """As medidas recomendadas para a categoria que o catálogo de ações cobre, até `limite`, na ordem da base."""
    recomendadas = [secao for secao in secoes if categoria in secao.categorias and secao.acao is not None]
    return [secao.trecho() for secao in recomendadas[:limite]]


def _raizes(texto):
    """As palavras do texto sem acento, em minúsculas, sem as vazias e cortadas na raiz."""
    sem_acento = unicodedata.normalize("NFKD", texto.casefold()).encode("ascii", "ignore").decode()
    return [palavra[:_RAIZ] for palavra in re.findall(r"[a-z0-9]+", sem_acento) if palavra not in _VAZIAS]


def _pontos(secao, termos):
    """Quanto a seção se aproxima da consulta. Palavra no título pesa mais que no texto."""
    return sum(
        3 * (termo in secao.palavras_do_titulo) + min(secao.palavras_do_texto[termo], 3)
        + (termo in secao.palavras_do_documento)
        for termo in termos
    )


def pesquisar(secoes, consulta, limite=LIMITE_DE_TRECHOS):
    """Os trechos mais próximos da consulta, do melhor para o pior, cada um com a origem.

    Trecho que não tem nenhuma palavra da consulta fica de fora. No empate vale a ordem dos
    documentos, então a mesma consulta devolve sempre a mesma resposta.
    """
    termos = set(_raizes(consulta))
    pontuadas = [(_pontos(secao, termos), secao) for secao in secoes]
    melhores = sorted((par for par in pontuadas if par[0] > 0), key=lambda par: -par[0])
    return [secao.trecho() for _, secao in melhores[:limite]]
