"""Amostragem do MERGED_CSV do CICIoT2023 para o treino do classificador.

O conjunto tem cerca de 45 milhões de linhas e não cabe na memória. Este módulo percorre os
arquivos em fluxo, uma linha por vez, e guarda no máximo `teto` linhas de cada classe: as
classes raras ficam inteiras e as grandes são reduzidas por sorteio uniforme, com amostragem
por reservatório (Vitter, 1985). A memória usada cresce com a amostra, não com o conjunto.

As 39 features saem como texto, exatamente como estão no arquivo de origem. Nenhuma coluna é
removida, convertida ou limpa: isso fica para o passo de preparação. A saída acrescenta a
coluna `Categoria` e traz o rótulo na grafia canônica.

Junto com a amostra é gravado um manifesto com a semente, o teto, a contagem por classe e o
hash da amostra. Com a mesma entrada, a mesma semente e o mesmo teto, a amostra é a mesma.

Uso, a partir da raiz do repositório:
    python -m codigo.classificador.amostrar
    python -m codigo.classificador.amostrar --teto 20000 --semente 7
"""
import argparse
import gzip
import hashlib
import json
import os
import platform
import random
import sys
from dataclasses import dataclass
from pathlib import Path

from codigo.captura.extrator import COLUNAS
from codigo.classificador.mapeamento import (
    CATEGORIA_DO_ROTULO,
    CATEGORIAS,
    ROTULOS,
    normalizar,
)

SEMENTE = 42
TETO = 50_000
CABECALHO = (*COLUNAS, "Label")
COLUNAS_DA_SAIDA = (*CABECALHO, "Categoria")
_LINHAS_POR_BLOCO = 10_000
METODO = (
    "Amostragem por reservatório (algoritmo R), com um reservatório por classe. Os arquivos são "
    "lidos em ordem de nome e as linhas na ordem do arquivo. O gerador de cada classe é "
    "random.Random('<semente>:<rótulo canônico>'), e a amostra sai na ordem original das linhas."
)


class _Reservatorio:
    """Amostra uniforme de até `teto` linhas de uma classe, mantida enquanto as linhas passam."""

    __slots__ = ("linhas", "rotulo", "sortear", "vistas")

    def __init__(self, rotulo, semente):
        self.rotulo = rotulo
        self.vistas = 0
        self.linhas = []
        # Um gerador por classe: o sorteio de uma classe não muda com a presença das outras.
        self.sortear = random.Random(f"{semente}:{rotulo}").randrange


@dataclass
class Amostra:
    """O que a amostragem produziu."""

    linhas: list  # (features como texto, rótulo canônico), na ordem em que estão nos arquivos
    populacao: dict  # rótulo -> linhas no conjunto completo
    selecionadas: dict  # rótulo -> linhas na amostra
    arquivos: list  # o registro de cada arquivo lido, como o Leitor o entrega
    teto: int
    semente: int


def listar_arquivos(pasta):
    """Arquivos CSV da pasta, em ordem de nome. A ordem faz parte do resultado do sorteio."""
    arquivos = sorted(Path(pasta).glob("*.csv"))
    if not arquivos:
        raise ValueError(f"nenhum arquivo CSV em {pasta}/")
    return arquivos


def conferir_cabecalho(nome, colunas):
    """Recusa arquivo cujas colunas não sejam as 39 features seguidas de Label."""
    colunas = tuple(colunas)
    if "Label" not in colunas:
        raise ValueError(f"{nome}: falta a coluna Label")
    if colunas != CABECALHO:
        faltam = [c for c in CABECALHO if c not in colunas]
        sobram = [c for c in colunas if c not in CABECALHO]
        detalhe = "; ".join(
            f"{verbo} {', '.join(nomes)}" for verbo, nomes in (("faltam", faltam), ("sobram", sobram)) if nomes
        )
        raise ValueError(
            f"{nome}: colunas diferentes das 39 features seguidas de Label ({detalhe or 'ordem trocada'})"
        )


class Leitor:
    """Lê um arquivo do MERGED_CSV em fluxo e entrega (features como texto, rótulo canônico).

    Confere o cabeçalho e cada linha. Linha em branco é ignorada. Linha com a quantidade errada
    de campos ou com rótulo desconhecido levanta ValueError, com o nome do arquivo e o número
    da linha. A exceção é a última linha de um arquivo que não termina em quebra de linha: o
    arquivo foi cortado no meio dela, então ela fica de fora e o registro marca
    `final_incompleto`.

    Terminada a leitura, `registro` traz nome, linhas, bytes, sha256 e final_incompleto, e
    `grafias` diz como cada rótulo estava escrito no arquivo.
    """

    def __init__(self, caminho):
        self.caminho = Path(caminho)
        self.registro = None
        self.grafias = {}  # o rótulo como está no arquivo -> rótulo canônico

    def __iter__(self):
        nome = self.caminho.name
        resumo = hashlib.sha256()
        rotulos = {}  # o rótulo como está no arquivo, em bytes -> rótulo canônico
        separadores = len(CABECALHO) - 1
        linhas, incompleto = 0, False
        with open(self.caminho, "rb") as arquivo:
            primeira = arquivo.readline()
            resumo.update(primeira)
            if not primeira.strip():
                raise ValueError(f"{nome}: arquivo vazio, sem a linha de cabeçalho")
            conferir_cabecalho(nome, primeira.decode("utf-8-sig", "replace").strip().split(","))
            for numero, linha in enumerate(arquivo, start=2):
                resumo.update(linha)
                corte = linha.rfind(b",")
                rotulo = rotulos.get(linha[corte + 1:]) if linha.count(b",") == separadores else None
                if rotulo is None:
                    # Caminho raro: linha em branco, grafia que ainda não apareceu ou linha com defeito.
                    if not linha.strip():
                        continue
                    try:
                        rotulo = rotulos[linha[corte + 1:]] = self._rotulo_novo(linha, corte)
                    except ValueError as erro:
                        if linha.endswith(b"\n"):
                            raise ValueError(f"{nome}, linha {numero}: {erro}") from None
                        # Só a última linha do arquivo pode vir sem a quebra no fim.
                        incompleto = True
                        continue
                linhas += 1
                yield linha[:corte], rotulo
        self.registro = {
            "nome": nome,
            "linhas": linhas,
            "bytes": self.caminho.stat().st_size,
            "sha256": resumo.hexdigest(),
            "final_incompleto": incompleto,
        }

    def _rotulo_novo(self, linha, corte):
        campos = linha.count(b",") + 1
        if campos != len(CABECALHO):
            raise ValueError(f"{campos} campos, e o esperado são {len(CABECALHO)}")
        grafia = linha[corte + 1:].decode("utf-8", "replace").strip()
        self.grafias[grafia] = normalizar(grafia)
        return self.grafias[grafia]


def amostrar(arquivos, teto=TETO, semente=SEMENTE, ao_terminar_arquivo=None):
    """Percorre os arquivos e devolve a Amostra, com no máximo `teto` linhas por classe."""
    if teto < 1:
        raise ValueError("o teto por classe precisa ser de ao menos 1 linha")
    reservatorios = {rotulo: _Reservatorio(rotulo, semente) for rotulo in ROTULOS}
    registros = []
    posicao = 0
    for caminho in arquivos:
        leitor = Leitor(caminho)
        for features, rotulo in leitor:
            posicao += 1
            reservatorio = reservatorios[rotulo]
            reservatorio.vistas += 1
            if reservatorio.vistas <= teto:
                reservatorio.linhas.append((posicao, features))
            else:
                # Algoritmo R: a linha de número n entra com probabilidade teto/n, no lugar de
                # uma das guardadas. Ao fim, toda linha da classe teve a mesma chance.
                sorteada = reservatorio.sortear(reservatorio.vistas)
                if sorteada < teto:
                    reservatorio.linhas[sorteada] = (posicao, features)
        registros.append(leitor.registro)
        if ao_terminar_arquivo is not None:
            ao_terminar_arquivo(leitor.registro)
    escolhidas = sorted(
        (posicao, features, reservatorio.rotulo)
        for reservatorio in reservatorios.values()
        for posicao, features in reservatorio.linhas
    )
    return Amostra(
        linhas=[(features, rotulo) for _, features, rotulo in escolhidas],
        populacao={rotulo: reservatorios[rotulo].vistas for rotulo in ROTULOS},
        selecionadas={rotulo: len(reservatorios[rotulo].linhas) for rotulo in ROTULOS},
        arquivos=registros,
        teto=teto,
        semente=semente,
    )


def _blocos(amostra):
    """O CSV da amostra em blocos de bytes: o cabeçalho e depois as linhas."""
    finais = {rotulo: f",{rotulo},{CATEGORIA_DO_ROTULO[rotulo]}\n".encode() for rotulo in ROTULOS}
    yield (",".join(COLUNAS_DA_SAIDA) + "\n").encode()
    for inicio in range(0, len(amostra.linhas), _LINHAS_POR_BLOCO):
        trecho = amostra.linhas[inicio:inicio + _LINHAS_POR_BLOCO]
        yield b"".join(features + finais[rotulo] for features, rotulo in trecho)


def gravar(amostra, destino):
    """Grava a amostra em CSV comprimido e devolve o SHA-256 do CSV, antes da compressão.

    O hash é o do conteúdo, e não o do arquivo .gz, porque os bytes comprimidos mudam com a
    versão da zlib. A gravação é feita num arquivo provisório, trocado de nome no fim: uma
    execução interrompida não deixa uma amostra pela metade no lugar da anterior.
    """
    destino = Path(destino)
    destino.parent.mkdir(parents=True, exist_ok=True)
    provisorio = destino.with_name(destino.name + ".parcial")
    resumo = hashlib.sha256()
    try:
        # Sem nome e sem data no cabeçalho do gzip, o arquivo sai igual a cada execução.
        with open(provisorio, "wb") as bruto, gzip.GzipFile(filename="", mode="wb", fileobj=bruto, mtime=0) as saida:
            for bloco in _blocos(amostra):
                resumo.update(bloco)
                saida.write(bloco)
        os.replace(provisorio, destino)
    finally:
        provisorio.unlink(missing_ok=True)
    return resumo.hexdigest()


def montar_manifesto(amostra, entrada, saida, sha256):
    """Registro da amostragem: o que é preciso para refazer a amostra e para citá-la."""
    classes = [
        {
            "rotulo": rotulo,
            "categoria": CATEGORIA_DO_ROTULO[rotulo],
            "populacao": amostra.populacao[rotulo],
            "amostra": amostra.selecionadas[rotulo],
        }
        for rotulo in ROTULOS
    ]
    categorias = {
        nome: {
            "populacao": sum(c["populacao"] for c in classes if c["categoria"] == nome),
            "amostra": sum(c["amostra"] for c in classes if c["categoria"] == nome),
        }
        for nome in CATEGORIAS
    }
    return {
        "descricao": "Amostra do MERGED_CSV do CICIoT2023, com teto de linhas por classe",
        "gerado_por": "python -m codigo.classificador.amostrar",
        "metodo": METODO,
        "semente": amostra.semente,
        "teto_por_classe": amostra.teto,
        "versoes": {"python": platform.python_version()},
        "entrada": {
            "pasta": Path(entrada).as_posix(),
            "linhas": sum(a["linhas"] for a in amostra.arquivos),
            "bytes": sum(a["bytes"] for a in amostra.arquivos),
            "arquivos_com_final_incompleto": [a["nome"] for a in amostra.arquivos if a["final_incompleto"]],
            "arquivos": amostra.arquivos,
        },
        "saida": {
            "arquivo": Path(saida).as_posix(),
            "linhas": len(amostra.linhas),
            "colunas": list(COLUNAS_DA_SAIDA),
            "sha256_do_csv_descomprimido": sha256,
        },
        "categorias": categorias,
        "classes": classes,
    }


def _milhar(numero):
    return f"{numero:,}".replace(",", ".")


def _teto(texto):
    try:
        valor = int(texto)
    except ValueError:
        raise argparse.ArgumentTypeError("o teto precisa ser um número inteiro") from None
    if valor < 1:
        raise argparse.ArgumentTypeError("o teto precisa ser de ao menos 1 linha")
    return valor


def relatar_arquivo(registro):
    """Mostra o andamento da leitura e avisa quando o arquivo está cortado no fim."""
    print(f"{registro['nome']}: {_milhar(registro['linhas'])} linhas", file=sys.stderr)
    if registro["final_incompleto"]:
        print(
            f"aviso: {registro['nome']} termina no meio de uma linha; a linha incompleta ficou de fora",
            file=sys.stderr,
        )


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.classificador.amostrar",
        description="Amostra o MERGED_CSV do CICIoT2023 com um teto de linhas por classe.",
    )
    analisador.add_argument("--entrada", default="CICIoT2023/MERGED_CSV", help="pasta com os arquivos CSV")
    analisador.add_argument(
        "--saida", default="dados/processed/amostra.csv.gz", help="arquivo da amostra, terminado em .csv.gz"
    )
    analisador.add_argument("--manifesto", default="experimentos/resultados/manifesto_amostra.json")
    analisador.add_argument(
        "--teto", type=_teto, default=TETO, help=f"máximo de linhas por classe (padrão: {TETO})"
    )
    analisador.add_argument("--semente", type=int, default=SEMENTE, help=f"semente do sorteio (padrão: {SEMENTE})")
    try:
        argumentos = analisador.parse_args(argv)
    except SystemExit as encerramento:
        return encerramento.code
    try:
        # Só .csv.gz é ignorado pelo git em qualquer pasta: outro nome poderia acabar versionado.
        if not argumentos.saida.endswith(".csv.gz"):
            raise ValueError("o nome do arquivo de saída precisa terminar em .csv.gz")
        arquivos = listar_arquivos(argumentos.entrada)
        amostra = amostrar(arquivos, argumentos.teto, argumentos.semente, ao_terminar_arquivo=relatar_arquivo)
        sha256 = gravar(amostra, argumentos.saida)
        manifesto = montar_manifesto(amostra, argumentos.entrada, argumentos.saida, sha256)
        destino = Path(argumentos.manifesto)
        destino.parent.mkdir(parents=True, exist_ok=True)
        destino.write_text(json.dumps(manifesto, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (OSError, ValueError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrompido: nenhuma amostra foi gravada", file=sys.stderr)
        return 130
    ausentes = [rotulo for rotulo in ROTULOS if amostra.populacao[rotulo] == 0]
    if ausentes:
        print(
            f"aviso: {len(ausentes)} das {len(ROTULOS)} classes não têm nenhuma linha na entrada: "
            f"{', '.join(ausentes)}",
            file=sys.stderr,
        )
    print(
        f"{_milhar(len(amostra.linhas))} linhas gravadas em {argumentos.saida}, de "
        f"{_milhar(manifesto['entrada']['linhas'])} lidas em {len(arquivos)} arquivos",
        file=sys.stderr,
    )
    print(f"sha256 do CSV descomprimido: {sha256}", file=sys.stderr)
    print(f"manifesto em {destino}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
