"""Verificador do artigo em LaTeX: o que o CI do artigo e o próprio LaTeX não conferem.

O workflow "Artigo" compila o PDF, confere o limite de 20 páginas e mostra as palavras por
arquivo; o abntex2cite monta as citações e a lista de referências a partir do `referencias.bib`,
em ordem e só com o que o texto cita. Este verificador lê os `.tex` de `artigo/latex/`, na ordem
dos `\\input` do `artigo.tex`, e confere o resto:

- Resumo e Abstract: de 150 a 250 palavras cada, contadas como o Word conta (número também é
  palavra), seguidos das palavras-chave e das keywords, separadas por ponto e vírgula;
- siglas: toda sigla do texto está em `artigo/siglas.md`, o primeiro uso no Resumo e o primeiro
  uso no corpo trazem o significado ao lado, e a lista não tem sigla que o texto não usa. O
  Abstract, em inglês, fica de fora, e título de seção não conta como primeiro uso;
- citações: toda chave de `\\cite` e `\\citeonline` existe no `referencias.bib`, e a citação
  escrita à mão, como "(NETO et al., 2023)", é aviso, porque não entra na lista de referências;
- pendências: cada `\\pendente{...}` e cada CONFERIR de uma referência citada é aviso e, com
  `--final`, erro.

    python -m artigo.verificador                  # artigo/latex
    python -m artigo.verificador --final          # pendência vira erro
    python -m artigo.verificador outra/pasta      # outra cópia do artigo
"""

import argparse
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

PASTA = Path(__file__).resolve().parent
LATEX = PASTA / "latex"
SIGLAS = PASTA / "siglas.md"

PALAVRAS_DO_RESUMO = (150, 250)
# Distância, em caracteres, em que o significado precisa aparecer em volta do primeiro uso da sigla.
VIZINHANCA = 200
# Os arquivos do Resumo e do Abstract, pelo nome do \input; os demais são o corpo, na ordem do artigo.
RESUMO, ABSTRACT = "resumo", "abstract"

COMANDO = re.compile(r"\\([A-Za-z]+)\*?")
# Comandos que somem com os argumentos: não imprimem texto corrido do artigo. Os de citação (\cite,
# \citeonline, \apud e variantes) também somem.
SEM_TEXTO = {
    "pendente", "ref", "pageref", "eqref", "autoref", "label", "includegraphics", "input", "include", "vspace",
    "hspace", "setlength", "url", "begin", "end", "graphicspath", "bibliography",
}
TITULOS = {"section", "subsection", "subsubsection", "paragraph"}
CHAVES_CITADAS = re.compile(r"\\(?:[Cc]ite[a-z]*|[Aa]pud[a-z]*)\*?(?:\[[^\]]*\])*((?:\{[^{}]*\})+)")
ENTRADA_DO_BIB = re.compile(r"@(\w+)\s*\{\s*([^,\s]+)\s*,")
ANO = r"(?:1[5-9]|20)\d{2}[a-z]?"
# Citação digitada no texto em vez de \cite: "(NETO et al., 2023)", "(KELLY; GLAVIN; BARRETT, 2021)",
# "Neto et al. (2023)" ou "Darktrace (2024)".
CITACAO_A_MAO = re.compile(
    rf"\([^()]*?\b[A-ZÀ-Ý]{{2,}}\b[^()]*?,\s*{ANO}\b[^()]*\)"
    rf"|\b[A-ZÀ-Ý][a-zà-ÿ'-]+(?:\s+et\s+al\.)?\s+\({ANO}(?:,\s*p\.[^()]*)?\)"
)
# Palavra com pelo menos duas maiúsculas: IoT, MCP, DDoS, CoAP.
CANDIDATA = re.compile(r"\b(?=[A-Za-z0-9]*[A-Z][A-Za-z0-9]*[A-Z])[A-Za-z][A-Za-z0-9]*\b")


@dataclass
class Relatorio:
    erros: list = field(default_factory=list)
    avisos: list = field(default_factory=list)

    def texto(self):
        linhas = []
        for titulo, itens in (("Erros", self.erros), ("Avisos", self.avisos)):
            linhas.append(f"{titulo} ({len(itens)}):")
            linhas.extend(f"  - {item}" for item in itens)
            linhas.append("")
        linhas.append("Resultado: " + ("reprovado" if self.erros else "aprovado"))
        return "\n".join(linhas)


@dataclass
class Artigo:
    """As fontes LaTeX do artigo: cada `\\input`, pelo nome, na ordem do `artigo.tex`."""

    secoes: dict
    principal: str = ""
    bib: str = ""

    @property
    def corpo(self):
        return [fonte for nome, fonte in self.secoes.items() if nome not in (RESUMO, ABSTRACT)]


def normalizar(texto):
    """Sem acento e em maiúsculas, para comparar nomes e significados."""
    sem_acento = unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode()
    return re.sub(r"\s+", " ", sem_acento).strip().upper()


def sem_comentarios(fonte):
    return re.sub(r"(?<!\\)%.*", "", fonte)


def _fim_do_grupo(fonte, inicio):
    """Posição depois do `}` ou `]` que fecha o grupo aberto em `fonte[inicio]`, ou None."""
    abre = fonte[inicio]
    fecha = "}" if abre == "{" else "]"
    nivel, i = 0, inicio
    while i < len(fonte):
        if fonte[i] == "\\":
            i += 2
            continue
        if fonte[i] == abre:
            nivel += 1
        elif fonte[i] == fecha:
            nivel -= 1
            if nivel == 0:
                return i + 1
        i += 1
    return None


def _fim_dos_argumentos(fonte, inicio):
    """Posição depois dos argumentos `[...]` e `{...}` colados ao comando que termina em `inicio`."""
    while inicio < len(fonte) and fonte[inicio] in "[{":
        fim = _fim_do_grupo(fonte, inicio)
        if fim is None:
            break
        inicio = fim
    return inicio


def argumentos_de(fonte, comando):
    """O primeiro argumento de cada uso de `\\comando{...}` na fonte."""
    achados = []
    for achado in re.finditer(rf"\\{comando}(?![A-Za-z])", fonte):
        if achado.end() < len(fonte) and fonte[achado.end()] == "{":
            fim = _fim_do_grupo(fonte, achado.end())
            if fim is not None:
                achados.append(fonte[achado.end() + 1 : fim - 1])
    return achados


def texto_do_latex(fonte, sem_titulos=False):
    """O texto corrido de um trecho LaTeX: sem comentários, pendências, citações, rótulos e comandos.

    Os comandos de formatação (`\\textbf{...}`, `\\caption{...}`) ficam só com o texto; os de
    `SEM_TEXTO` somem com os argumentos. Com `sem_titulos`, os títulos de seção também somem.
    """
    fonte = sem_comentarios(fonte).replace("\\\\", " ")
    removidos = SEM_TEXTO | TITULOS if sem_titulos else SEM_TEXTO
    partes, i = [], 0
    while achado := COMANDO.search(fonte, i):
        partes.append(fonte[i : achado.start()])
        nome = achado.group(1)
        some = nome in removidos or nome.lower().startswith(("cite", "apud"))
        i = _fim_dos_argumentos(fonte, achado.end()) if some else achado.end()
    partes.append(fonte[i:])
    texto = "".join(partes)
    texto = re.sub(r"(?<!\\)\$", "", texto)
    texto = re.sub(r"(?<!\\)[&~]", " ", texto)
    texto = re.sub(r"\\[,;:! ]", " ", texto).replace("\\-", "")
    texto = re.sub(r"\\([%_&#$])", r"\1", texto)
    texto = re.sub(r"[{}]", "", texto).replace("---", "—").replace("--", "–")
    return re.sub(r"\s+", " ", texto).strip()


def contar_palavras(texto):
    """Palavras como o Word conta: o que fica entre espaços, número inclusive, sem pontuação solta."""
    return sum(1 for termo in texto.split() if re.search(r"\w", termo))


def ler_siglas(caminho=SIGLAS):
    """A tabela de siglas e os nomes que não são siglas, de `artigo/siglas.md`."""
    siglas, nomes, secao = {}, [], None
    for linha in Path(caminho).read_text(encoding="utf-8").splitlines():
        if linha.startswith("## "):
            secao = linha[3:].strip().lower()
        elif secao == "siglas" and linha.startswith("|") and not linha.startswith("|---"):
            sigla, significado = (celula.strip() for celula in linha.strip("|").split("|")[:2])
            if sigla != "Sigla":
                siglas[sigla] = significado
        elif secao and secao.startswith("nomes") and linha.startswith("- ") and ":" in linha:
            nomes.extend(nome.strip().rstrip(".") for nome in linha.split(":", 1)[1].split(","))
    return siglas, [nome for nome in nomes if nome]


def ler_artigo(pasta=LATEX):
    """As fontes do artigo em `pasta`: os `\\input` do `artigo.tex`, na ordem, e o `referencias.bib`."""
    pasta = Path(pasta)
    principal = (pasta / "artigo.tex").read_text(encoding="utf-8")
    secoes = {}
    for nome in re.findall(r"\\input\{([^}]+)\}", sem_comentarios(principal)):
        caminho = pasta / (nome if nome.endswith(".tex") else nome + ".tex")
        secoes[caminho.stem] = caminho.read_text(encoding="utf-8")
    bib = pasta / "referencias.bib"
    return Artigo(secoes, principal, bib.read_text(encoding="utf-8") if bib.exists() else "")


def _conferir_resumo(nome, fonte, rotulo, relatorio):
    if fonte is None:
        relatorio.erros.append(f"{nome}: arquivo não encontrado nos \\input do artigo.tex.")
        return
    texto = texto_do_latex(fonte)
    partes = re.split(rf"\b{re.escape(rotulo)}\s*:", texto, maxsplit=1, flags=re.IGNORECASE)
    minimo, maximo = PALAVRAS_DO_RESUMO
    palavras = contar_palavras(partes[0])
    if not minimo <= palavras <= maximo:
        relatorio.erros.append(f"{nome}: {palavras} palavras; o template pede de {minimo} a {maximo}.")
    if len(partes) == 1:
        relatorio.erros.append(f"{nome}: falta a linha de {rotulo}.")
    elif len([termo for termo in partes[1].rstrip(" .").split(";") if termo.strip()]) < 2:
        relatorio.avisos.append(f"{rotulo}: separe os termos por ponto e vírgula.")


def _chaves_citadas(fontes):
    chaves = []
    for fonte in fontes:
        for grupos in CHAVES_CITADAS.findall(sem_comentarios(fonte)):
            chaves.extend(chave for chave in re.findall(r"[^{},\s]+", grupos) if chave not in chaves)
    return chaves


def _entradas_do_bib(bib):
    """{chave: texto da entrada} do `referencias.bib`."""
    entradas = {}
    for trecho in re.split(r"(?m)^\s*(?=@)", bib):
        achado = ENTRADA_DO_BIB.match(trecho)
        if achado and achado.group(1).lower() not in ("comment", "string", "preamble"):
            entradas[achado.group(2)] = trecho
    return entradas


def _conferir_citacoes(artigo, relatorio):
    entradas = _entradas_do_bib(artigo.bib)
    for chave in _chaves_citadas([artigo.principal, *artigo.secoes.values()]):
        if chave not in entradas:
            relatorio.erros.append(f"Citação sem entrada no referencias.bib: {chave}.")
    for nome, fonte in artigo.secoes.items():
        for achado in CITACAO_A_MAO.finditer(texto_do_latex(fonte)):
            relatorio.avisos.append(
                f"Citação escrita à mão em {nome}.tex, fora da lista de referências: {achado.group(0)}."
            )


def _mascarar(texto, padrao):
    """Troca cada trecho por espaços do mesmo tamanho: as posições continuam as do texto."""
    return re.sub(padrao, lambda achado: " " * len(achado.group(0)), texto)


def _conferir_siglas(artigo, siglas, nomes, relatorio):
    resumo = artigo.secoes.get(RESUMO, "")
    blocos = [("no Resumo", texto_do_latex(resumo, sem_titulos=True))]
    blocos.append(("no corpo", texto_do_latex("\n".join(artigo.corpo), sem_titulos=True)))
    desconhecidas, usadas = set(), set()
    for onde, texto in blocos:
        # Os nomes saem só da busca de siglas, sem pedaço de palavra (MB não esconde o SMB), mas com o número
        # de arquivo colado (BenignTraffic2). O significado é procurado no texto sem máscara: "JSON Lines" é
        # nome, mas é o significado de JSONL.
        busca = _mascarar(texto, CITACAO_A_MAO)
        for nome in sorted(nomes, key=len, reverse=True):
            busca = _mascarar(busca, rf"(?<!\w){re.escape(nome)}(?![A-Za-z_])")
        primeiro_uso = {}
        for achado in CANDIDATA.finditer(busca):
            palavra = achado.group(0)
            plural = palavra.endswith("s") and palavra[:-1] in siglas
            sigla = palavra if palavra in siglas else palavra[:-1] if plural else None
            if sigla is None:
                if palavra not in desconhecidas:
                    desconhecidas.add(palavra)
                    relatorio.erros.append(f"Sigla fora de artigo/siglas.md: {palavra}.")
                continue
            primeiro_uso.setdefault(sigla, achado.start())
        for sigla, inicio in primeiro_uso.items():
            janela = normalizar(texto[max(0, inicio - VIZINHANCA) : inicio + len(sigla) + VIZINHANCA])
            if normalizar(siglas[sigla]) not in janela:
                relatorio.erros.append(f"Primeiro uso de {sigla} {onde} sem o significado ao lado ({siglas[sigla]}).")
        usadas.update(primeiro_uso)
    juntos = " ".join(texto for _, texto in blocos)
    for sigla in siglas:
        if sigla not in usadas and not re.search(rf"(?<![A-Za-z0-9]){re.escape(sigla)}s?(?![A-Za-z0-9])", juntos):
            relatorio.avisos.append(f"Sigla da lista que o texto não usa: {sigla}.")


def _conferir_pendencias(artigo, final, relatorio):
    destino = relatorio.erros if final else relatorio.avisos
    fontes = [("artigo", artigo.principal), *artigo.secoes.items()]
    for nome, fonte in fontes:
        for pendencia in argumentos_de(sem_comentarios(fonte), "pendente"):
            trecho = re.sub(r"\s+", " ", pendencia).strip()
            destino.append(f"Pendência em {nome}.tex: " + (trecho if len(trecho) <= 90 else trecho[:89] + "…"))
    entradas = _entradas_do_bib(artigo.bib)
    for chave in _chaves_citadas([artigo.principal, *artigo.secoes.values()]):
        if "CONFERIR" in entradas.get(chave, ""):
            destino.append(f"Referência citada com CONFERIR no referencias.bib: {chave}.")


def verificar(artigo, siglas, nomes, final=False):
    relatorio = Relatorio()
    _conferir_resumo("Resumo", artigo.secoes.get(RESUMO), "Palavras-chave", relatorio)
    _conferir_resumo("Abstract", artigo.secoes.get(ABSTRACT), "Keywords", relatorio)
    _conferir_citacoes(artigo, relatorio)
    _conferir_siglas(artigo, siglas, nomes, relatorio)
    _conferir_pendencias(artigo, final, relatorio)
    return relatorio


def main(argv=None):
    parser = argparse.ArgumentParser(description="Confere o artigo em LaTeX no que o CI do artigo não confere.")
    parser.add_argument(
        "pasta", nargs="?", default=LATEX, type=Path, help="pasta do artigo.tex (padrão: artigo/latex)"
    )
    parser.add_argument("--final", action="store_true", help="pendência vira erro")
    args = parser.parse_args(argv)
    siglas, nomes = ler_siglas()
    relatorio = verificar(ler_artigo(args.pasta), siglas, nomes, final=args.final)
    print(f"Artigo: {args.pasta}")
    print("Páginas e palavras por arquivo: no workflow Artigo do CI.\n")
    print(relatorio.texto())
    return 1 if relatorio.erros else 0


if __name__ == "__main__":
    sys.exit(main())
