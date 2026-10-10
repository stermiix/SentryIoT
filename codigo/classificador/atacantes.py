"""Os Raspberry Pi atacantes do CICIoT2023 e a medida das janelas sem atacante.

O dataset dá o rótulo de cada pcap ao arquivo inteiro, e cada janela reúne quadros seguidos de
todos os dispositivos da rede. Numa captura de ataque, parte das janelas não tem nenhum quadro
do dispositivo que ataca, e mesmo assim leva o rótulo do ataque. Este módulo mede isso.

Os atacantes são os sete Raspberry Pi da Tabela 1 do artigo do dataset (Neto et al., 2023),
identificados pelo endereço MAC. A contagem de quadros por MAC de cada pcap, gravada no
relatório, é o que confirma a lista nos arquivos.

O que o comando faz, para cada pcap da pasta do dataset:

1. Lê o rótulo do nome do arquivo (`DoS-HTTP_Flood1.pcap` é `DoS-HTTP_Flood`) e recusa o nome
   que não casa com nenhum dos 34 rótulos.
2. Lê o arquivo uma vez, contando os quadros por MAC de origem e de destino e extraindo as
   janelas com os dois tamanhos do dataset, 10 e 100 quadros. Uma janela tem atacante quando
   algum quadro dela tem um MAC da lista na origem ou no destino.
3. Grava o relatório `janelas_sem_atacante.md`, as tabelas em CSV e o manifesto de que elas saem.

O manifesto guarda o tamanho e a data de modificação de cada pcap: numa execução seguinte, só os
pcaps novos ou alterados são lidos de novo, e os que sumiram da pasta saem do relatório.

Uso, a partir da raiz do repositório:
    python -m codigo.classificador.atacantes
    python -m codigo.classificador.atacantes --dataset /caminho/CICIoT2023 --janelas 10,100
"""
import argparse
import datetime
import hashlib
import json
import platform
import re
import sys
import time
import warnings
from collections import Counter
from pathlib import Path

import dpkt

from codigo.captura.extrator import Extrator, ler_pcap, medir_quadro
from codigo.classificador.experimento import (
    _campo,
    _decimal,
    _enumerar,
    _gravar_csv,
    _milhar,
    _pct,
    _tabela,
)
from codigo.classificador.mapeamento import CATEGORIA_DO_ROTULO, normalizar

MANIFESTO = "manifesto_janelas_sem_atacante.json"
RELATORIO = "janelas_sem_atacante.md"
TABELA = "janelas_sem_atacante.csv"
CSV_MACS = "janelas_sem_atacante_macs.csv"

# Os sete Raspberry Pi atacantes, da Tabela 1 de Neto et al. (2023), na grafia do extrator.
ATACANTES = frozenset(
    mac.lower() for mac in (
        "E4:5F:01:55:90:C4", "DC:A6:32:DC:27:D5", "DC:A6:32:C9:E4:D5", "DC:A6:32:C9:E5:EF",
        "DC:A6:32:C9:E4:AB", "DC:A6:32:C9:E4:90", "DC:A6:32:C9:E5:A4",
    )
)
# Os dois tamanhos de janela do dataset.
JANELAS = (10, 100)
# Quantos MACs fora da lista cada pcap registra no manifesto, dos mais frequentes.
MACS_FORA_DA_LISTA = 10
# Participação a partir da qual um MAC é citado no relatório como presente no pcap.
PARTICIPACAO_CITADA = 0.01


def rotulo_do_pcap(nome):
    """O rótulo canônico de um pcap do dataset, lido do nome do arquivo.

    O nome é o rótulo, às vezes com um sufixo numérico e um hífen: `DoS-HTTP_Flood1`,
    `DDoS-HTTP_Flood-`, `BenignTraffic1`, `Mirai-greip_flood21`. O que não casa com nenhum dos
    34 rótulos é recusado, e não adivinhado.
    """
    nome = Path(nome).name
    if not nome.endswith(".pcap"):
        raise ValueError(f"{nome}: o nome não casa com nenhum rótulo do CICIoT2023 (só .pcap é aceito)")
    base = re.sub(r"\d+$", "", nome[:-len(".pcap")]).rstrip("-_")
    try:
        return normalizar(base)
    except ValueError:
        raise ValueError(
            f"{nome}: o nome não casa com nenhum rótulo do CICIoT2023 "
            "(o rótulo vem do nome do arquivo, sem o sufixo numérico)"
        ) from None


def e_benigno(rotulo):
    return CATEGORIA_DO_ROTULO[rotulo] == "Benign"


def tem_atacante(enderecos, atacantes=ATACANTES):
    """Se algum quadro da janela tem um MAC da lista na origem ou no destino."""
    return not atacantes.isdisjoint(enderecos.macs_origem) or not atacantes.isdisjoint(enderecos.macs_destino)


class _LeituraComHash:
    """Um fluxo de leitura que calcula o SHA-256 e conta os bytes do que passa por ele."""

    def __init__(self, arquivo):
        self._arquivo = arquivo
        self.sha256 = hashlib.sha256()
        self.bytes = 0

    def read(self, n):
        dados = self._arquivo.read(n)
        self.sha256.update(dados)
        self.bytes += len(dados)
        return dados

    def esgotar(self):
        """Lê o que sobrou, para que o hash seja do arquivo inteiro mesmo se a leitura parou antes."""
        while self.read(1 << 20):
            pass


def percorrer(pcap, janelas=JANELAS, ao_fechar=None, atacantes=ATACANTES):
    """Lê um pcap inteiro uma vez, com um tamanho de janela ou vários.

    Conta os quadros por MAC de origem e de destino, em todos os quadros do arquivo, e, para
    cada janela, quantas janelas têm e não têm atacante. A leitura é contínua, como na operação:
    cada quadro é medido uma vez e entregue a todos os extratores.

    `ao_fechar(janela, indice, linha, enderecos, com_atacante)` é chamado a cada janela fechada,
    com o índice dela no arquivo para aquele tamanho de janela, as 39 colunas e os endereços.

    Devolve o registro: pacotes lidos, bytes e SHA-256 do arquivo, segundos, os avisos do leitor,
    as contagens por MAC e as contagens de janelas por tamanho.
    """
    pcap = Path(pcap)
    extratores = {janela: Extrator(janela, enderecos=True) for janela in janelas}
    indices = dict.fromkeys(janelas, 0)
    contagem = {
        janela: {"extraidas": 0, "com_atacante": 0, "sem_atacante": 0, "incompletas": 0} for janela in janelas
    }
    macs_origem, macs_destino = Counter(), Counter()
    pacotes = 0

    def fechar(janela, saida):
        linha, enderecos = saida
        com_atacante = tem_atacante(enderecos, atacantes)
        conta = contagem[janela]
        conta["extraidas"] += 1
        conta["com_atacante" if com_atacante else "sem_atacante"] += 1
        conta["incompletas"] += linha["Number"] < janela
        if ao_fechar is not None:
            ao_fechar(janela, indices[janela], linha, enderecos, com_atacante)
        indices[janela] += 1

    inicio = time.perf_counter()
    with warnings.catch_warnings(record=True) as avisos:
        warnings.simplefilter("always")
        try:
            with open(pcap, "rb") as arquivo:
                leitura = _LeituraComHash(arquivo)
                ts_anterior = None
                for ts, quadro in ler_pcap(leitura):
                    pacotes += 1
                    macs_destino[quadro[:6].hex(":")] += 1
                    macs_origem[quadro[6:12].hex(":")] += 1
                    medida = medir_quadro(ts, quadro, ts_anterior)
                    if medida is None:
                        continue
                    ts_anterior = ts
                    for janela, extrator in extratores.items():
                        saida = extrator.acumular(medida)
                        if saida is not None:
                            fechar(janela, saida)
                for janela, extrator in extratores.items():
                    saida = extrator.finalizar()
                    if saida is not None:
                        fechar(janela, saida)
                leitura.esgotar()
        except ValueError as erro:
            raise ValueError(f"{pcap.name}: {erro}") from None
    return {
        "pacotes": pacotes,
        "bytes": leitura.bytes,
        "sha256": leitura.sha256.hexdigest(),
        "segundos": time.perf_counter() - inicio,
        "avisos": [str(aviso.message) for aviso in avisos],
        "macs_origem": macs_origem,
        "macs_destino": macs_destino,
        "janelas": contagem,
    }


# --- o comando: um registro por pcap, reaproveitado entre execuções ---------------------------


def listar_pcaps(dataset):
    """Os pcaps da pasta do dataset, do menor para o maior, cada um com o seu rótulo.

    Um nome que não casa com nenhum rótulo interrompe tudo antes de qualquer leitura.
    """
    dataset = Path(dataset)
    if not dataset.is_dir():
        raise ValueError(f"a pasta do dataset não existe: {dataset}")
    pcaps = sorted(dataset.glob("*.pcap"), key=lambda caminho: (caminho.stat().st_size, caminho.name))
    if not pcaps:
        raise ValueError(f"nenhum pcap em {dataset}")
    return [(caminho, rotulo_do_pcap(caminho.name)) for caminho in pcaps]


def _identidade(caminho):
    estado = caminho.stat()
    return {"bytes": estado.st_size, "modificado_ns": estado.st_mtime_ns}


def _resumo_dos_macs(registro, atacantes):
    """As contagens por MAC que vão para o manifesto: toda a lista e os mais frequentes fora dela."""
    total = Counter()
    for mac, quantos in registro["macs_origem"].items():
        total[mac] += quantos
    for mac, quantos in registro["macs_destino"].items():
        total[mac] += quantos
    fora = [mac for mac, _ in total.most_common() if mac not in atacantes][:MACS_FORA_DA_LISTA]
    return {
        mac: {
            "origem": registro["macs_origem"].get(mac, 0),
            "destino": registro["macs_destino"].get(mac, 0),
            "na_lista": mac in atacantes,
        }
        for mac in [*sorted(atacantes), *fora]
    }


def medir_pcap(caminho, rotulo, janelas, atacantes=ATACANTES):
    """O registro de um pcap no manifesto."""
    registro = percorrer(caminho, janelas, atacantes=atacantes)
    return {
        "arquivo": caminho.name,
        "rotulo": rotulo,
        "categoria": CATEGORIA_DO_ROTULO[rotulo],
        "benigno": e_benigno(rotulo),
        **_identidade(caminho),
        "sha256": registro["sha256"],
        "pacotes": registro["pacotes"],
        "segundos": registro["segundos"],
        "avisos": registro["avisos"],
        "macs": _resumo_dos_macs(registro, atacantes),
        "janelas": {str(janela): contagem for janela, contagem in registro["janelas"].items()},
    }


def _ler_manifesto(caminho, janelas):
    """Os registros do manifesto anterior, por arquivo, se ele existe e usou as mesmas janelas."""
    try:
        anterior = json.loads(Path(caminho).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if anterior.get("janelas") != list(janelas) or sorted(anterior.get("atacantes", [])) != sorted(ATACANTES):
        return {}
    return {registro["arquivo"]: registro for registro in anterior.get("pcaps", [])}


def rodar(dataset, janelas=JANELAS, anteriores=None, ao_terminar=None):
    """Mede os pcaps da pasta, reaproveitando os registros anteriores que ainda valem.

    Devolve os registros, em ordem de nome, e quantos pcaps foram lidos nesta execução.
    """
    anteriores = anteriores or {}
    registros, medidos = [], 0
    for caminho, rotulo in listar_pcaps(dataset):
        anterior = anteriores.get(caminho.name)
        if anterior is not None and {chave: anterior.get(chave) for chave in ("bytes", "modificado_ns")} == _identidade(caminho):
            registros.append(anterior)
            continue
        registro = medir_pcap(caminho, rotulo, janelas)
        registros.append(registro)
        medidos += 1
        if ao_terminar is not None:
            ao_terminar(registro)
    return sorted(registros, key=lambda registro: registro["arquivo"]), medidos


def montar_manifesto(registros, dataset, janelas):
    return {
        "descricao": (
            "Quadros por MAC e janelas sem nenhum quadro de um Raspberry Pi atacante, por pcap do CICIoT2023 "
            "e por tamanho de janela"
        ),
        "gerado_por": "python -m codigo.classificador.atacantes",
        "gerado_em": datetime.datetime.now(tz=datetime.UTC).astimezone().strftime("%Y-%m-%d"),
        "versoes": {"python": platform.python_version(), "dpkt": dpkt.__version__},
        "dataset": Path(dataset).as_posix(),
        "janelas": list(janelas),
        "atacantes": sorted(ATACANTES),
        "pcaps": registros,
    }


def gravar(manifesto, pasta):
    """Grava o manifesto e o que sai dele: o relatório e as duas tabelas."""
    pasta = Path(pasta)
    pasta.mkdir(parents=True, exist_ok=True)
    (pasta / MANIFESTO).write_text(json.dumps(manifesto, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (pasta / RELATORIO).write_text(montar_relatorio(manifesto), encoding="utf-8")
    _gravar_csv(
        pasta / TABELA,
        ["arquivo", "rotulo", "benigno", "janela", "janelas", "com_atacante", "sem_atacante", "fracao_sem_atacante",
         "incompletas"],
        [
            [
                p["arquivo"], p["rotulo"], int(p["benigno"]), janela, c["extraidas"], c["com_atacante"],
                c["sem_atacante"], _campo(c["sem_atacante"] / c["extraidas"] if c["extraidas"] else None),
                c["incompletas"],
            ]
            for p in manifesto["pcaps"] for janela, c in p["janelas"].items()
        ],
    )
    _gravar_csv(
        pasta / CSV_MACS,
        ["arquivo", "rotulo", "mac", "na_lista", "origem", "destino", "fracao_origem", "fracao_destino"],
        [
            [
                p["arquivo"], p["rotulo"], mac, int(m["na_lista"]), m["origem"], m["destino"],
                _campo(m["origem"] / p["pacotes"] if p["pacotes"] else None),
                _campo(m["destino"] / p["pacotes"] if p["pacotes"] else None),
            ]
            for p in manifesto["pcaps"] for mac, m in p["macs"].items()
        ],
    )


# --- relatório -------------------------------------------------------------------------------


def _data(m):
    return datetime.date.fromisoformat(m["gerado_em"]).strftime("%d/%m/%Y")


def _participacao(p, mac):
    """A fração dos quadros do pcap em que o MAC é origem ou destino."""
    medida = p["macs"].get(mac, {"origem": 0, "destino": 0})
    return (medida["origem"] + medida["destino"]) / p["pacotes"] if p["pacotes"] else 0.0


def _citados(p, na_lista):
    """Os MACs do pcap com participação citável, com a fração, dos maiores para os menores."""
    macs = [mac for mac, medida in p["macs"].items() if medida["na_lista"] == na_lista]
    pares = sorted(((mac, _participacao(p, mac)) for mac in macs), key=lambda par: -par[1])
    return [(mac, fracao) for mac, fracao in pares if fracao >= PARTICIPACAO_CITADA]


def _lista_de_macs(pares):
    return ", ".join(f"`{mac}` ({_pct(fracao, 1)})" for mac, fracao in pares) or "nenhum"


def _cabecalho(m):
    return [
        "# Janelas sem atacante",
        "",
        (
            f"Gerado por `{m['gerado_por']}` em {_data(m)}, com Python {m['versoes']['python']} e dpkt "
            f"{m['versoes']['dpkt']}."
        ),
        "",
        "O CICIoT2023 (Neto et al., 2023) dá o rótulo de cada pcap ao arquivo inteiro, e cada janela reúne",
        "quadros seguidos de todos os dispositivos da rede. Numa captura de ataque, parte das janelas não tem",
        "nenhum quadro do dispositivo que ataca, e mesmo assim leva o rótulo do ataque. Este relatório mede",
        "isso em cada pcap da pasta do dataset, com janela de " + _enumerar(m["janelas"]) + " quadros.",
        "",
        "Os atacantes são os sete Raspberry Pi da Tabela 1 do artigo do dataset, identificados pelo MAC:",
        _enumerar(f"`{mac}`" for mac in m["atacantes"]) + ".",
        "Uma janela tem atacante quando algum quadro dela tem um desses MACs na origem ou no destino.",
    ]


def _confirmacao(m):
    ataques = [p for p in m["pcaps"] if not p["benigno"]]
    benignos = [p for p in m["pcaps"] if p["benigno"]]
    linhas = [
        [
            f"`{p['arquivo']}`", p["rotulo"], _milhar(p["pacotes"]),
            _pct(sum(me["origem"] for me in p["macs"].values() if me["na_lista"]) / p["pacotes"], 1),
            _pct(sum(me["destino"] for me in p["macs"].values() if me["na_lista"]) / p["pacotes"], 1),
            _lista_de_macs(_citados(p, True)),
            _lista_de_macs(_citados(p, False)[:3]),
        ]
        for p in ataques
    ]
    secao = [
        "## Os atacantes em cada pcap",
        "",
        "A contagem de quadros por MAC confirma a lista nos arquivos. Para cada pcap de ataque: a fração dos",
        "quadros com um MAC da lista na origem e no destino, os MACs da lista com ao menos 1% dos quadros",
        "(origem e destino somados) e os três MACs mais frequentes fora da lista. Um pcap em que o MAC",
        "dominante não está na lista indicaria um atacante que ela não cobre.",
        "",
        *_tabela(
            ["Arquivo", "Rótulo", "Quadros", "Origem na lista", "Destino na lista", "Atacantes com mais de 1%",
             "Mais frequentes fora da lista"],
            linhas,
        ),
    ]
    if benignos:
        secao += ["", "Nos pcaps benignos, os MACs da lista também aparecem:", ""]
        secao += [
            f"- `{p['arquivo']}`: {_milhar(p['pacotes'])} quadros; "
            + "; ".join(
                f"`{mac}` em {_milhar(me['origem'])} como origem e {_milhar(me['destino'])} como destino "
                f"({_pct(_participacao(p, mac), 2)})"
                for mac, me in p["macs"].items() if me["na_lista"] and me["origem"] + me["destino"] > 0
            )
            for p in benignos
        ]
        secao += [
            "",
            "A regra de rótulo da regeração não usa a lista nos pcaps benignos: toda janela de um pcap benigno é",
            "benigna. A presença desses MACs ali mostra que o dispositivo que ataca também gera tráfego comum, e",
            "que o MAC sozinho não separa ataque de tráfego normal fora da captura de ataque.",
        ]
    return secao


def _janelas(m):
    janelas = [str(janela) for janela in m["janelas"]]
    cabecalho = ["Arquivo", "Rótulo"]
    for janela in janelas:
        cabecalho += [f"Janelas de {janela}", f"Sem atacante ({janela})", f"Fração ({janela})"]
    linhas = []
    for p in m["pcaps"]:
        if p["benigno"]:
            continue
        linha = [f"`{p['arquivo']}`", p["rotulo"]]
        for janela in janelas:
            c = p["janelas"][janela]
            linha += [
                _milhar(c["extraidas"]), _milhar(c["sem_atacante"]),
                _pct(c["sem_atacante"] / c["extraidas"] if c["extraidas"] else None),
            ]
        linhas.append(linha)
    return [
        "## Janelas sem atacante, por pcap e por janela",
        "",
        "A quantidade de janelas de cada pcap de ataque, quantas não têm nenhum quadro de um MAC da lista e a",
        "fração que isso representa. São essas as janelas que a regeração descarta.",
        "",
        *_tabela(cabecalho, linhas),
    ]


def _como_foram_obtidos(m):
    linhas = [
        "## Como os números foram obtidos",
        "",
        f"- Comando: `{m['gerado_por']}`, a partir da raiz do repositório, com os pcaps em `{m['dataset']}`.",
        "- Cada pcap é lido inteiro uma vez, em leitura contínua, sem o fatiamento em pedaços de 10 MB com que os",
        "  autores geraram os CSVs oficiais. Os MACs são contados em todos os quadros do arquivo; as janelas são",
        "  as do extrator (`codigo/captura/extrator.py`), só com quadros IPv4 e ARP, e a última janela de cada",
        "  tamanho pode ficar incompleta.",
        f"- A tabela `{TABELA}` tem uma linha por pcap e janela, e `{CSV_MACS}` traz, por pcap, as",
        f"  contagens dos sete MACs da lista e dos {MACS_FORA_DA_LISTA} mais frequentes fora dela. O manifesto",
        f"  `{MANIFESTO}` guarda tudo, com o tamanho, a data de modificação e o SHA-256 de cada pcap: numa",
        "  execução seguinte, só os pcaps novos ou alterados são lidos de novo.",
        "- Pcaps, com o tamanho, os pacotes e o tempo de leitura de cada um:",
    ]
    linhas += [
        f"  - `{p['arquivo']}`: {_milhar(p['bytes'])} bytes, {_milhar(p['pacotes'])} pacotes, "
        f"{_decimal(p['segundos'])} s, SHA-256 `{p['sha256']}`"
        + (f"; aviso: {'; '.join(p['avisos'])}" if p["avisos"] else "")
        for p in m["pcaps"]
    ]
    return linhas


def montar_relatorio(m):
    secoes = [_cabecalho(m), _confirmacao(m), _janelas(m), _como_foram_obtidos(m)]
    return "\n".join("\n".join(secao) + "\n" for secao in secoes).rstrip("\n") + "\n"


# --- comando ---------------------------------------------------------------------------------


def _janelas_da_opcao(texto):
    try:
        janelas = tuple(int(parte) for parte in texto.split(","))
    except ValueError:
        raise argparse.ArgumentTypeError("as janelas precisam ser números inteiros separados por vírgula") from None
    if not janelas or any(janela < 1 for janela in janelas) or len(set(janelas)) != len(janelas):
        raise argparse.ArgumentTypeError("as janelas precisam ser de ao menos 1 quadro, sem repetição")
    return janelas


def _relatar(registro):
    print(
        f"{registro['arquivo']}: {_milhar(registro['pacotes'])} pacotes em {_decimal(registro['segundos'])} s",
        file=sys.stderr,
    )


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.classificador.atacantes",
        description="Conta os quadros por MAC e as janelas sem atacante em cada pcap do CICIoT2023.",
        allow_abbrev=False,
    )
    analisador.add_argument("--dataset", default="CICIoT2023", help="pasta com os pcaps (padrão: CICIoT2023)")
    analisador.add_argument("--saida", default="experimentos/resultados", help="pasta dos resultados")
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
        anteriores = _ler_manifesto(saida / MANIFESTO, argumentos.janelas)
        registros, medidos = rodar(argumentos.dataset, argumentos.janelas, anteriores, ao_terminar=_relatar)
        gravar(montar_manifesto(registros, argumentos.dataset, argumentos.janelas), saida)
    except (OSError, ValueError, KeyError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrompido: nenhum resultado foi gravado", file=sys.stderr)
        return 130
    print(f"{len(registros)} pcaps, {medidos} lidos nesta execução; resultados em {saida}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
