"""Regeração dos dados de treino a partir dos pcaps do CICIoT2023.

O `MERGED_CSV` oficial agrega as classes de DDoS, DoS e Mirai em janelas de 100 quadros e as
demais em janelas de 10, e o modelo treinado nele aprende o tamanho da janela em vez do
comportamento do tráfego (`experimentos/resultados/teste_da_janela.md`). Além disso, o rótulo
oficial é dado ao arquivo inteiro, e boa parte das janelas de um pcap de ataque não tem nenhum
quadro do atacante (`janelas_sem_atacante.md`). Este módulo gera os dados de treino de novo, a
partir dos pcaps, com o nosso extrator (decisão de 10/10/2026 no `ROADMAP.md`):

- uma janela só para todas as classes, extraída com 10 e com 100 quadros, para o treino
  escolher pelas métricas;
- o rótulo decidido janela a janela: num pcap benigno, toda janela é `BenignTraffic`; num pcap
  de ataque, a janela recebe o rótulo do arquivo se tem um quadro com MAC de um Raspberry Pi
  atacante na origem ou no destino, e é descartada se não tem. A janela descartada não vira
  benigna, porque o tráfego de fundo de uma captura de ataque pode estar contaminado.

Saída, fora do git: `dados/processed/regerado/janela_<W>/<rotulo>.csv.gz`, com as 39 features,
`Label`, o arquivo de origem, o índice da janela no arquivo, a quantidade de IPs de origem e de
destino distintos e se havia atacante. O arquivo de cada rótulo é a junção das partes de cada
pcap (`partes/<pcap>.csv.gz`), e por isso um pcap novo entra sem refazer os outros. O manifesto,
versionado em `experimentos/resultados/manifesto_regeracao.json`, guarda por pcap o tamanho, a
data de modificação, o SHA-256 e as janelas extraídas, mantidas e descartadas, por janela. Numa
execução seguinte, só os pcaps novos, alterados ou sem saída são lidos de novo; os que sumiram
da pasta saem da saída e do manifesto.

Uso, a partir da raiz do repositório:
    python -m codigo.classificador.regerar
    python -m codigo.classificador.regerar --dataset /caminho/CICIoT2023 --janelas 10,100
"""
import argparse
import csv
import datetime
import gzip
import json
import os
import platform
import shutil
import sys
from pathlib import Path

import dpkt

from codigo.captura.extrator import COLUNAS, _texto
from codigo.classificador.atacantes import (
    ATACANTES,
    JANELAS,
    _decimal,
    _identidade,
    _janelas_da_opcao,
    _milhar,
    e_benigno,
    listar_pcaps,
    percorrer,
)
from codigo.classificador.mapeamento import CATEGORIA_DO_ROTULO

MANIFESTO = "manifesto_regeracao.json"
DESTINO = "dados/processed/regerado"
PARTES = "partes"
COLUNAS_EXTRAS = ("Label", "arquivo", "indice", "ips_origem", "ips_destino", "atacante")
CABECALHO = (*COLUNAS, *COLUNAS_EXTRAS)
# Nível de compressão do gzip: o padrão (9) é lento, e a diferença de tamanho é pequena.
COMPRESSAO = 6


def nome_da_pasta(janela):
    return f"janela_{janela}"


def _parte(destino, janela, arquivo):
    return Path(destino) / nome_da_pasta(janela) / PARTES / f"{Path(arquivo).stem}.csv.gz"


def _do_rotulo(destino, janela, rotulo):
    return Path(destino) / nome_da_pasta(janela) / f"{rotulo}.csv.gz"


class _Partes:
    """As partes de um pcap, uma por janela, gravadas sem cabeçalho e em arquivo provisório."""

    def __init__(self, destino, janelas, arquivo):
        self.caminhos = {janela: _parte(destino, janela, arquivo) for janela in janelas}
        self._arquivos, self._escritores, self.linhas = {}, {}, dict.fromkeys(janelas, 0)

    def __enter__(self):
        for janela, caminho in self.caminhos.items():
            caminho.parent.mkdir(parents=True, exist_ok=True)
            arquivo = gzip.open(caminho.with_name(caminho.name + ".parcial"), "wt", encoding="utf-8", newline="",
                                compresslevel=COMPRESSAO)
            self._arquivos[janela] = arquivo
            self._escritores[janela] = csv.writer(arquivo, lineterminator="\n")
        return self

    def gravar(self, janela, campos):
        self._escritores[janela].writerow(campos)
        self.linhas[janela] += 1

    def __exit__(self, tipo, *_):
        for janela, arquivo in self._arquivos.items():
            arquivo.close()
            provisorio = self.caminhos[janela].with_name(self.caminhos[janela].name + ".parcial")
            if tipo is None:
                os.replace(provisorio, self.caminhos[janela])
            else:
                provisorio.unlink(missing_ok=True)


def regerar_pcap(caminho, rotulo, janelas, destino, atacantes=ATACANTES):
    """Extrai um pcap com cada janela, aplica a regra de rótulo e grava as partes dele.

    Devolve o registro do pcap para o manifesto.
    """
    benigno = e_benigno(rotulo)

    def ao_fechar(janela, indice, linha, enderecos, com_atacante):
        if benigno or com_atacante:
            partes.gravar(janela, [
                *(_texto(linha[coluna]) for coluna in COLUNAS),
                rotulo, caminho.name, indice, enderecos.ips_origem, enderecos.ips_destino, int(com_atacante),
            ])

    with _Partes(destino, janelas, caminho.name) as partes:
        registro = percorrer(caminho, janelas, ao_fechar=ao_fechar, atacantes=atacantes)
    return {
        "arquivo": caminho.name,
        "rotulo": rotulo,
        "categoria": CATEGORIA_DO_ROTULO[rotulo],
        "benigno": benigno,
        **_identidade(caminho),
        "sha256": registro["sha256"],
        "pacotes": registro["pacotes"],
        "segundos": registro["segundos"],
        "avisos": registro["avisos"],
        "janelas": {
            str(janela): {
                "extraidas": contagem["extraidas"],
                "mantidas": partes.linhas[janela],
                "descartadas": contagem["extraidas"] - partes.linhas[janela],
                "com_atacante": contagem["com_atacante"],
                "incompletas": contagem["incompletas"],
            }
            for janela, contagem in registro["janelas"].items()
        },
    }


def _ler_manifesto(caminho, janelas, destino):
    """Os registros do manifesto anterior, por arquivo, se ele vale para esta execução."""
    try:
        anterior = json.loads(Path(caminho).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if (
        anterior.get("janelas") != list(janelas)
        or sorted(anterior.get("atacantes", [])) != sorted(ATACANTES)
        or anterior.get("destino") != str(destino)
    ):
        return {}
    return {registro["arquivo"]: registro for registro in anterior.get("pcaps", [])}


def _vale(anterior, caminho, janelas, destino):
    """Se o registro anterior de um pcap ainda vale: mesmo tamanho e data, e todas as partes no lugar."""
    if anterior is None:
        return False
    if {chave: anterior.get(chave) for chave in ("bytes", "modificado_ns")} != _identidade(caminho):
        return False
    return all(_parte(destino, janela, caminho.name).exists() for janela in janelas)


def _juntar(destino, janela, rotulo, arquivos):
    """O arquivo do rótulo: o cabeçalho e as partes dos seus pcaps, em ordem de nome, byte a byte.

    Membros gzip concatenados formam um gzip válido, então a junção não descomprime nada.
    """
    caminho = _do_rotulo(destino, janela, rotulo)
    provisorio = caminho.with_name(caminho.name + ".parcial")
    with open(provisorio, "wb") as saida:
        saida.write(gzip.compress((",".join(CABECALHO) + "\n").encode("utf-8"), compresslevel=COMPRESSAO))
        for arquivo in arquivos:
            with open(_parte(destino, janela, arquivo), "rb") as parte:
                shutil.copyfileobj(parte, saida)
    os.replace(provisorio, caminho)


def _limpar(destino, janelas, registros):
    """Apaga as partes e os arquivos de rótulo que não correspondem a nenhum pcap da pasta."""
    partes = {Path(registro["arquivo"]).stem for registro in registros}
    rotulos = {registro["rotulo"] for registro in registros}
    for janela in janelas:
        pasta = Path(destino) / nome_da_pasta(janela)
        for caminho in pasta.glob(f"{PARTES}/*.csv.gz"):
            if caminho.name[:-len(".csv.gz")] not in partes:
                caminho.unlink()
        for caminho in pasta.glob("*.csv.gz"):
            if caminho.name[:-len(".csv.gz")] not in rotulos:
                caminho.unlink()
    for caminho in Path(destino).glob("janela_*/**/*.parcial"):
        caminho.unlink()


def rodar(dataset, janelas=JANELAS, destino=DESTINO, anteriores=None, ao_terminar=None):
    """Regera os pcaps da pasta que precisam, junta os arquivos por rótulo e devolve os registros.

    Devolve os registros dos pcaps, em ordem de nome, os registros por rótulo e quantos pcaps
    foram lidos nesta execução.
    """
    anteriores = anteriores or {}
    registros, lidos = [], 0
    for caminho, rotulo in listar_pcaps(dataset):
        anterior = anteriores.get(caminho.name)
        if _vale(anterior, caminho, janelas, destino):
            registros.append(anterior)
            continue
        registro = regerar_pcap(caminho, rotulo, janelas, destino)
        registros.append(registro)
        lidos += 1
        if ao_terminar is not None:
            ao_terminar(registro)
    registros.sort(key=lambda registro: registro["arquivo"])
    _limpar(destino, janelas, registros)
    rotulos = []
    for rotulo in sorted({registro["rotulo"] for registro in registros}):
        arquivos = [registro["arquivo"] for registro in registros if registro["rotulo"] == rotulo]
        for janela in janelas:
            _juntar(destino, janela, rotulo, arquivos)
        rotulos.append({
            "rotulo": rotulo,
            "categoria": CATEGORIA_DO_ROTULO[rotulo],
            "arquivos": arquivos,
            "linhas": {
                str(janela): sum(r["janelas"][str(janela)]["mantidas"] for r in registros if r["rotulo"] == rotulo)
                for janela in janelas
            },
        })
    return registros, rotulos, lidos


def montar_manifesto(registros, rotulos, dataset, janelas, destino):
    return {
        "descricao": (
            "Dados de treino regerados dos pcaps do CICIoT2023 com o extrator do projeto, em janela única, com o "
            "rótulo de ataque só nas janelas em que aparece um Raspberry Pi atacante"
        ),
        "gerado_por": "python -m codigo.classificador.regerar",
        "gerado_em": datetime.datetime.now(tz=datetime.UTC).astimezone().strftime("%Y-%m-%d"),
        "versoes": {"python": platform.python_version(), "dpkt": dpkt.__version__},
        "dataset": Path(dataset).as_posix(),
        "destino": str(destino),
        "janelas": list(janelas),
        "atacantes": sorted(ATACANTES),
        "regra": (
            "pcap benigno: toda janela é BenignTraffic; pcap de ataque: a janela recebe o rótulo do arquivo se tem "
            "quadro com MAC de atacante na origem ou no destino, senão é descartada"
        ),
        "colunas": list(CABECALHO),
        "rotulos": rotulos,
        "pcaps": registros,
    }


def gravar(manifesto, pasta):
    pasta = Path(pasta)
    pasta.mkdir(parents=True, exist_ok=True)
    (pasta / MANIFESTO).write_text(json.dumps(manifesto, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _relatar(registro):
    janelas = ", ".join(
        f"janela {janela}: {_milhar(c['mantidas'])} de {_milhar(c['extraidas'])} janelas mantidas"
        for janela, c in registro["janelas"].items()
    )
    print(
        f"{registro['arquivo']}: {_milhar(registro['pacotes'])} pacotes em {_decimal(registro['segundos'])} s; {janelas}",
        file=sys.stderr,
    )


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.classificador.regerar",
        description="Regera os dados de treino a partir dos pcaps do CICIoT2023, com janela única e rótulo pelo atacante.",
        allow_abbrev=False,
    )
    analisador.add_argument("--dataset", default="CICIoT2023", help="pasta com os pcaps (padrão: CICIoT2023)")
    analisador.add_argument("--destino", default=DESTINO, help=f"pasta dos CSVs regerados (padrão: {DESTINO})")
    analisador.add_argument("--saida", default="experimentos/resultados", help="pasta do manifesto")
    analisador.add_argument(
        "--janelas", type=_janelas_da_opcao, default=JANELAS,
        help="tamanhos de janela, separados por vírgula (padrão: 10,100)",
    )
    try:
        argumentos = analisador.parse_args(argv)
    except SystemExit as encerramento:
        return encerramento.code
    saida = Path(argumentos.saida)
    try:
        anteriores = _ler_manifesto(saida / MANIFESTO, argumentos.janelas, argumentos.destino)
        registros, rotulos, lidos = rodar(
            argumentos.dataset, argumentos.janelas, argumentos.destino, anteriores, ao_terminar=_relatar,
        )
        gravar(montar_manifesto(registros, rotulos, argumentos.dataset, argumentos.janelas, argumentos.destino), saida)
    except (OSError, ValueError, KeyError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrompido: o manifesto não foi gravado, e o pcap interrompido será extraído de novo", file=sys.stderr)
        return 130
    print(
        f"{len(registros)} pcaps, {lidos} lidos nesta execução; dados em {argumentos.destino}/ e manifesto em {saida}/",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
