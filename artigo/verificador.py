"""Verificador do artigo contra as regras do template do Oriente (FCI, TCC 2026).

Confere no .docx o que o template pede e o que dá para conferir sem ler o texto:

- páginas: no máximo 20, com as referências, contadas no PDF que o LibreOffice gera;
- Resumo e Abstract: de 150 a 250 palavras cada, seguidos de palavras-chave e keywords;
- citações: toda citação, em linha, como "Neto et al. (2023)", ou entre parênteses, como
  "(NETO et al., 2023)", tem referência, toda referência é citada, e a lista está em ordem
  alfabética, como pede a ABNT (NBR 6023);
- siglas: toda sigla do texto está em `artigo/siglas.md`, o primeiro uso traz o significado ao lado,
  e a lista não tem sigla que o texto não usa;
- pendências: os trechos marcados no texto, como [PENDENTE] e [CONFERIR], são avisos e, com
  `--final`, erros.

    python -m artigo.verificador                       # o .docx do repositório
    python -m artigo.verificador outro.docx --final    # pendência vira erro
    python -m artigo.verificador --sem-paginas         # sem o LibreOffice
"""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

PASTA = Path(__file__).resolve().parent
ARTIGO = PASTA / "Artigo_TCC2_SentryIoT.docx"
SIGLAS = PASTA / "siglas.md"

MAX_PAGINAS = 20
PALAVRAS_DO_RESUMO = (150, 250)
# Distância, em caracteres, em que o significado precisa aparecer em volta do primeiro uso da sigla.
VIZINHANCA = 200

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
PENDENCIA = re.compile(
    r"\[(?:PENDENTE|CONFERIR|FIGURA|a implementar|a escrever|Se houver tempo)[^\]]*\]", re.IGNORECASE
)
PALAVRA = re.compile(r"[^\W\d_]+(?:[-'][^\W\d_]+)*")
ANO = r"\d{4}[a-z]?"
ENTRE_PARENTESES = re.compile(rf"\(([^()]*?\b{ANO})\)")
FIM_DE_OBRA = re.compile(rf",\s*({ANO})\s*$")
NOME = r"[A-ZÀ-Ý][\wÀ-ÿ'-]*"
EM_LINHA = re.compile(
    rf"\b(?P<autores>{NOME}(?:\s+{NOME})?(?:,\s+{NOME})*(?:\s+e\s+{NOME})?(?:\s+et\s+al\.)?)\s+\((?P<ano>{ANO})\)"
)
# Palavras que abrem a frase antes do nome do autor, como em "Segundo Neto et al. (2023)".
ABERTURAS = {"A", "O", "AS", "OS", "SEGUNDO", "CONFORME", "PARA", "COMO", "EM", "NA", "NO", "DE", "E"}
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


def normalizar(texto):
    """Sem acento e em maiúsculas, para comparar nomes e significados."""
    sem_acento = unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode()
    return re.sub(r"\s+", " ", sem_acento).strip().upper()


def ler_paragrafos(caminho):
    """Texto de cada parágrafo do corpo, na ordem do documento, incluindo os das tabelas."""
    with zipfile.ZipFile(caminho) as docx:
        raiz = ET.fromstring(docx.read("word/document.xml"))
    paragrafos = []
    for p in raiz.iter(W + "p"):
        partes = [no.text or "" if no.tag == W + "t" else " " for no in p.iter() if no.tag in (W + "t", W + "tab")]
        texto = "".join(partes).strip()
        if texto:
            paragrafos.append(texto)
    return paragrafos


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


def _indice(paragrafos, padrao, inicio=0):
    for i in range(inicio, len(paragrafos)):
        if re.match(padrao, paragrafos[i], re.IGNORECASE):
            return i
    return None


def _secoes(paragrafos):
    resumo = _indice(paragrafos, r"Resumo$")
    abstract = _indice(paragrafos, r"Abstract$")
    chave = _indice(paragrafos, r"Palavras-chave", resumo or 0)
    keywords = _indice(paragrafos, r"Keywords", abstract or 0)
    referencias = _indice(paragrafos, r"(\d+\.\s*)?Refer[eê]ncias")
    return resumo, chave, abstract, keywords, referencias


def contar_palavras(texto):
    return len(PALAVRA.findall(PENDENCIA.sub(" ", texto)))


def _conferir_resumos(paragrafos, relatorio):
    resumo, chave, abstract, keywords, _ = _secoes(paragrafos)
    minimo, maximo = PALAVRAS_DO_RESUMO
    for nome, inicio, fim, rotulo in (("Resumo", resumo, chave, "Palavras-chave"), ("Abstract", abstract, keywords, "Keywords")):
        if inicio is None:
            relatorio.erros.append(f"{nome}: seção não encontrada.")
            continue
        if fim is None:
            relatorio.erros.append(f"{nome}: falta a linha de {rotulo}.")
            fim = inicio + 1
        palavras = contar_palavras(" ".join(paragrafos[inicio + 1 : fim]))
        if not minimo <= palavras <= maximo:
            relatorio.erros.append(f"{nome}: {palavras} palavras; o template pede de {minimo} a {maximo}.")
        if fim < len(paragrafos) and paragrafos[fim].lower().startswith(rotulo.lower()):
            termos = [t for t in paragrafos[fim].split(":", 1)[-1].rstrip(".").split(";") if t.strip()]
            if len(termos) < 2:
                relatorio.avisos.append(f"{rotulo}: separe os termos por ponto e vírgula.")


def _primeira_palavra(nome):
    palavras = normalizar(nome.replace("et al.", "")).split()
    return palavras[0] if palavras else ""


def extrair_citacoes(texto):
    """Pares (texto da citação, nomes candidatos, ano) das citações entre parênteses e em linha."""
    citacoes = []
    for trecho in ENTRE_PARENTESES.findall(texto):
        autores = []
        for parte in trecho.split(";"):
            fim = FIM_DE_OBRA.search(parte)
            nome = parte[: fim.start()] if fim else parte
            autores.append(nome.strip())
            if fim:
                primeiro = autores[0].replace("et al.", "").strip()
                if primeiro and primeiro == primeiro.upper() and re.search(r"[A-Z]{2}", primeiro):
                    citacoes.append((f"({'; '.join(autores)}, {fim.group(1)})", [_primeira_palavra(primeiro)], fim.group(1)))
                autores = []
    for achado in EM_LINHA.finditer(texto):
        autores = achado.group("autores")
        primeira = autores.split()[0]
        if normalizar(primeira) in ABERTURAS and len(autores.split()) > 1:
            autores = autores[len(primeira):].strip()
        candidatos = [normalizar(n) for n in re.findall(NOME, autores.replace("et al.", ""))]
        citacoes.append((f"{autores} ({achado.group('ano')})", candidatos, achado.group("ano")))
    return citacoes


def extrair_referencias(paragrafos):
    """(texto, primeira palavra do primeiro autor, ano) de cada referência."""
    referencias = []
    for texto in paragrafos:
        if PENDENCIA.fullmatch(texto.strip()):
            continue
        corte = min((i for i in (texto.find(","), texto.find(".")) if i > 0), default=len(texto))
        # O ano vem solto, depois de espaço, vírgula ou parêntese; o 2017 de "CIC-IDS-2017" é do título.
        ano = re.search(r"(?<=[\s,(])(?:19|20)\d{2}[a-z]?(?=[.,;:\s)])", texto[corte:])
        referencias.append((texto, _primeira_palavra(texto[:corte]), ano.group(0) if ano else None))
    return referencias


def _conferir_citacoes(paragrafos, relatorio):
    _, _, _, keywords, referencias = _secoes(paragrafos)
    if referencias is None:
        relatorio.erros.append("Referências: seção não encontrada.")
        return
    corpo = PENDENCIA.sub(" ", "\n".join(paragrafos[(keywords or 0) + 1 : referencias]))
    lista = extrair_referencias(paragrafos[referencias + 1 :])
    chaves = {(chave, ano) for _, chave, ano in lista}
    citadas = set()
    for texto, candidatos, ano in extrair_citacoes(corpo):
        achadas = [(c, ano) for c in candidatos if (c, ano) in chaves]
        if achadas:
            citadas.update(achadas)
        else:
            relatorio.erros.append(f"Citação sem referência: {texto}.")
    for texto, chave, ano in lista:
        if (chave, ano) not in citadas:
            relatorio.erros.append(f"Referência não citada no texto: {texto[:90]}…")
    ordem = [normalizar(texto) for texto, _, _ in lista]
    if ordem != sorted(ordem):
        relatorio.avisos.append("Referências fora da ordem alfabética.")


def _conferir_siglas(paragrafos, siglas, nomes, relatorio):
    _, _, abstract, keywords, referencias = _secoes(paragrafos)
    # O título (primeiro parágrafo) não define sigla: o primeiro uso conta a partir dos autores.
    trechos = paragrafos[1:abstract] + paragrafos[(keywords or 0) + 1 : referencias]
    texto = PENDENCIA.sub(" ", "\n".join(trechos))
    texto = ENTRE_PARENTESES.sub(lambda m: " " if re.search(r"[A-Z]{2}", m.group(1)) else m.group(0), texto)
    for nome in sorted(nomes, key=len, reverse=True):
        texto = texto.replace(nome, " ")
    usadas = {}
    for achado in CANDIDATA.finditer(texto):
        palavra = achado.group(0)
        sigla = palavra if palavra in siglas else palavra[:-1] if palavra.endswith("s") and palavra[:-1] in siglas else None
        if sigla is None:
            if palavra not in usadas:
                relatorio.erros.append(f"Sigla fora de artigo/siglas.md: {palavra}.")
                usadas[palavra] = achado.start()
            continue
        usadas.setdefault(sigla, achado.start())
    normal = normalizar(texto)
    for sigla, inicio in usadas.items():
        if sigla not in siglas:
            continue
        janela = normalizar(texto[max(0, inicio - VIZINHANCA) : inicio + len(sigla) + VIZINHANCA])
        if normalizar(siglas[sigla]) not in janela:
            relatorio.erros.append(f"Primeiro uso de {sigla} sem o significado ao lado ({siglas[sigla]}).")
    for sigla in siglas:
        if sigla not in usadas and not re.search(rf"\b{re.escape(normalizar(sigla))}S?\b", normal):
            relatorio.avisos.append(f"Sigla da lista que o texto não usa: {sigla}.")


def _conferir_pendencias(paragrafos, final, relatorio):
    destino = relatorio.erros if final else relatorio.avisos
    for paragrafo in paragrafos:
        for achado in PENDENCIA.finditer(paragrafo):
            trecho = achado.group(0)
            destino.append("Pendência no texto: " + (trecho if len(trecho) <= 90 else trecho[:89] + "…]"))


def verificar(paragrafos, siglas, nomes, paginas=None, final=False):
    relatorio = Relatorio()
    if paginas is None:
        relatorio.avisos.append("Páginas: não conferidas (sem o LibreOffice).")
    elif paginas > MAX_PAGINAS:
        relatorio.erros.append(f"Páginas: {paginas}; o template permite no máximo {MAX_PAGINAS}, com as referências.")
    _conferir_resumos(paragrafos, relatorio)
    _conferir_citacoes(paragrafos, relatorio)
    _conferir_siglas(paragrafos, siglas, nomes, relatorio)
    _conferir_pendencias(paragrafos, final, relatorio)
    return relatorio


def libreoffice():
    for candidato in ("soffice", "libreoffice", "/Applications/LibreOffice.app/Contents/MacOS/soffice"):
        if shutil.which(candidato) or Path(candidato).exists():
            return candidato
    return None


def contar_paginas(caminho):
    """Páginas do PDF que o LibreOffice gera do .docx, ou None sem o LibreOffice."""
    executavel = libreoffice()
    if executavel is None:
        return None
    with tempfile.TemporaryDirectory() as pasta:
        subprocess.run(
            [executavel, "--headless", "--convert-to", "pdf", "--outdir", pasta, str(caminho)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        pdf = Path(pasta) / (Path(caminho).stem + ".pdf")
        return len(re.findall(rb"/Type\s*/Page[^s]", pdf.read_bytes()))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Confere o artigo contra as regras do template.")
    parser.add_argument("docx", nargs="?", default=ARTIGO, type=Path)
    parser.add_argument("--final", action="store_true", help="pendência marcada no texto vira erro")
    parser.add_argument("--sem-paginas", action="store_true", help="não conta as páginas pelo LibreOffice")
    args = parser.parse_args(argv)
    siglas, nomes = ler_siglas()
    paginas = None if args.sem_paginas else contar_paginas(args.docx)
    relatorio = verificar(ler_paragrafos(args.docx), siglas, nomes, paginas=paginas, final=args.final)
    print(f"Artigo: {args.docx}")
    print(f"Páginas: {paginas if paginas is not None else 'não conferidas'}\n")
    print(relatorio.texto())
    return 1 if relatorio.erros else 0


if __name__ == "__main__":
    sys.exit(main())
