"""Calibração de conjunto do extrator: os pcaps do CICIoT2023 contra o `MERGED_CSV` inteiro.

O `calibrar.py` compara cada pcap com o CSV oficial dele, linha a linha. Esses CSVs por ataque
não estão mais na cópia do dataset, e o `calibracao.md` cobre só os 5 pcaps conferidos assim. O
que existe é o `MERGED_CSV`, que junta as linhas de todas as capturas dos autores, embaralhadas e
sem o nome do arquivo de origem, e que vem de mais capturas do que os pcaps disponíveis. Por isso
a conferência aqui é de conjunto: as linhas de cada pcap, extraídas como os autores extraíram,
são procuradas entre as linhas do mesmo rótulo no `MERGED_CSV`.

O que o comando faz:

1. Índice do `MERGED_CSV`. Lê os 63 arquivos um a um, nunca o conjunto inteiro, descarta a linha
   final incompleta dos arquivos truncados e guarda, por rótulo, os hashes de 64 bits das linhas
   (`chave` abaixo), ordenados. Também guarda o SHA-256 de cada arquivo.
2. Extração. Cada pcap é lido como os autores leram: fatiado em pedaços de 10 MB como o
   `tcpdump -C 10` (`calibrar.fatiar`), cada pedaço com um extrator novo, na janela da classe (100
   em DDoS, DoS e Mirai, 10 nas demais). Na mesma leitura sai a extração contínua, a da operação e
   da regeração dos dados de treino, e o retrato da captura: formato do instante, limite de
   captura, quadros fora do filtro por tipo e tamanhos de quadro fora do que passa no fio.
3. Correspondência. (a) A fração das linhas de cada pcap que têm par no rótulo dele, por
   multiconjunto: cada linha do `MERGED_CSV` serve de par a uma linha nossa só. (b) A fração das
   linhas de cada rótulo no `MERGED_CSV` cobertas pelos pcaps daquele rótulo. Para as linhas sem
   par, se casariam ignorando as colunas de tempo ou as de tamanho; os pedaços de 10 MB com menos
   da metade das linhas com par; e o rótulo em que as linhas do pcap mais aparecem fora do próprio.
4. Controle do vizinho mais próximo. Uma amostra das linhas sem par de cada pcap é comparada,
   coluna a coluna, com a linha mais parecida do mesmo rótulo no `MERGED_CSV`. Se o vizinho difere
   em `Rate` e `IAT` e em geral em outras colunas, a linha sem par é outra janela, que falta no
   `MERGED_CSV`, e não uma janela calculada de outro jeito.
5. Leitura contínua contra fatiada: quantas linhas da leitura contínua têm par no `MERGED_CSV` e
   quanto as distribuições das 39 colunas se afastam (estatística de Kolmogorov-Smirnov).

A chave de uma linha arredonda cada um dos 39 valores a 30 bits de mantissa (erro relativo de até
cerca de 4,7e-10, perto de 9 algarismos), deixa o infinito como está e põe todo NaN num padrão só,
e mistura os 39 valores num hash de 64 bits. O `MERGED_CSV` escreve os números no formato do Java
(`3.861904144287109E-5`), o infinito como texto, o NaN como campo vazio e os inteiros sem ponto, e
por isso a chave é sobre o valor numérico, e não sobre o texto.

Os dados intermediários ficam em `--trabalho`, fora do git, e são reaproveitados numa execução
seguinte enquanto os arquivos e o código do extrator não mudarem. A saída, em `--saida`, é o
relatório `calibracao_conjunto.md`, as tabelas por pcap e por rótulo e o manifesto, com o
SHA-256 de cada pcap e de cada arquivo do `MERGED_CSV`.

Uso, a partir da raiz do repositório:
    python -m codigo.captura.calibrar_conjunto
    python -m codigo.captura.calibrar_conjunto --dataset CICIoT2023 --processos 3 --saida experimentos/resultados
"""
import argparse
import array
import csv
import datetime
import hashlib
import inspect
import io
import json
import platform
import struct
import sys
import time
import warnings
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import dpkt
import numpy as np
import pandas as pd

from codigo.captura import calibrar, extrator
from codigo.captura.calibrar import LIMITE_PEDACO, _milhar, fatiar
from codigo.captura.extrator import (
    COLUNAS,
    QUADRO_MAXIMO,
    QUADRO_MINIMO,
    CapturaIncompleta,
    Extrator,
    ler_pcap,
    medir_quadro,
    nome_do_tipo,
    tipo_ethernet,
)
from codigo.classificador import mapeamento
from codigo.classificador.atacantes import rotulo_do_pcap
from codigo.classificador.mapeamento import CATEGORIA_DO_ROTULO, normalizar

RELATORIO = "calibracao_conjunto.md"
TABELA_PCAPS = "calibracao_conjunto_pcaps.csv"
TABELA_ROTULOS = "calibracao_conjunto_rotulos.csv"
MANIFESTO = "manifesto_calibracao_conjunto.json"
TRABALHO = "dados/processed/calibracao_conjunto"
# Entram no resumo do código que invalida o que está guardado em --trabalho (versao_da_extracao e
# versao_do_indice), junto com o texto das funções que geram cada dado.
VERSAO_EXTRACAO = 1
VERSAO_INDICE = 1

# --- chave de correspondência -----------------------------------------------------------------

BITS_MANTIDOS = 30
_DESCARTE = 52 - BITS_MANTIDOS
_MEIO = np.uint64(1 << (_DESCARTE - 1))
_MASCARA = np.uint64(~((1 << _DESCARTE) - 1) & 0xFFFFFFFFFFFFFFFF)
_NAN = np.uint64(0x7FF8000000000000)
TEMPO = ("Rate", "IAT")
TAMANHO = ("Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "Variance")
# Subconjuntos de colunas da chave: todas, e sem as de tempo ou as de tamanho, para o diagnóstico.
VARIANTES = {
    "todas": tuple(range(len(COLUNAS))),
    "sem_tempo": tuple(i for i, c in enumerate(COLUNAS) if c not in TEMPO),
    "sem_tamanho": tuple(i for i, c in enumerate(COLUNAS) if c not in TAMANHO),
}
# Uma constante por coluna, para que trocar dois valores de coluna mude o hash.
_CONSTANTES = np.random.default_rng(20261011).integers(1, 2**63, size=len(COLUNAS), dtype=np.uint64) | np.uint64(1)
_PRIMO = np.uint64(0x9E3779B97F4A7C15)


def quantizar(valores):
    """Arredonda os valores, um array (n, 39), a BITS_MANTIDOS bits de mantissa. Devolve uint64.

    Soma meia unidade no último bit mantido e zera os seguintes. O infinito fica como está, todo
    NaN vira o mesmo padrão e -0.0 vira 0.0.
    """
    v = np.asarray(valores, dtype=np.float64) + 0.0
    bits = v.view(np.uint64).copy()
    finitos = np.isfinite(v)
    bits[finitos] = (bits[finitos] + _MEIO) & _MASCARA
    bits[np.isnan(v)] = _NAN
    return bits


def _misturar(x):
    x = x ^ (x >> np.uint64(30))
    x = x * np.uint64(0xBF58476D1CE4E5B9)
    x = x ^ (x >> np.uint64(27))
    x = x * np.uint64(0x94D049BB133111EB)
    return x ^ (x >> np.uint64(31))


def hashes(quantizados, colunas=VARIANTES["todas"]):
    """Hash de 64 bits de cada linha quantizada, sobre as colunas dadas (índices em COLUNAS)."""
    with np.errstate(over="ignore"):
        h = np.full(quantizados.shape[0], np.uint64(0x243F6A8885A308D3), dtype=np.uint64)
        for j in colunas:
            h = _misturar(h ^ (quantizados[:, j] * _PRIMO + _CONSTANTES[j]))
        return h


def contar_comuns(nossos, deles_ordenado):
    """Correspondência por multiconjunto entre os nossos hashes e os deles, já ordenados.

    Cada hash deles serve de par a um nosso só. Devolve (quantos têm par, máscara), em que a
    máscara marca, na ordem dos nossos, os que ficaram com par.
    """
    ordem = np.argsort(nossos, kind="stable")
    ns = nossos[ordem]
    unicos, inicio, contagem = np.unique(ns, return_index=True, return_counts=True)
    disponiveis = np.searchsorted(deles_ordenado, unicos, "right") - np.searchsorted(deles_ordenado, unicos, "left")
    usados = np.minimum(contagem, disponiveis)
    posicao = np.arange(ns.size) - np.repeat(inicio, contagem)
    mascara = np.empty(ns.size, dtype=bool)
    mascara[ordem] = posicao < np.repeat(usados, contagem)
    return int(usados.sum()), mascara


def presentes(h, ordenado):
    """Quais hashes aparecem ao menos uma vez no array ordenado."""
    if not len(ordenado):
        return np.zeros(len(h), dtype=bool)
    posicao = np.minimum(np.searchsorted(ordenado, h), len(ordenado) - 1)
    return ordenado[posicao] == h


# --- índice do MERGED_CSV ---------------------------------------------------------------------


def ler_merged(caminho):
    """Lê um arquivo do MERGED_CSV. Devolve (valores (n, 39), rótulos canônicos, truncado, sha256, bytes).

    A linha final sem quebra de linha, dos arquivos truncados na fonte oficial, fica de fora.
    """
    dados = Path(caminho).read_bytes()
    sha256, tamanho = hashlib.sha256(dados).hexdigest(), len(dados)
    truncado = not dados.endswith(b"\n")
    if truncado:
        dados = dados[: dados.rfind(b"\n") + 1]
    tabela = pd.read_csv(
        io.BytesIO(dados), usecols=[*COLUNAS, "Label"], dtype={"Label": str}, float_precision="round_trip",
    )
    del dados
    valores = np.empty((len(tabela), len(COLUNAS)), dtype=np.float64)
    for j, coluna in enumerate(COLUNAS):
        serie = tabela[coluna]
        if not pd.api.types.is_numeric_dtype(serie):
            serie = pd.to_numeric(serie, errors="raise")  # "inf" escrito como texto
        valores[:, j] = serie.to_numpy(dtype=np.float64, na_value=np.nan)
    canonicos = {rotulo: normalizar(rotulo) for rotulo in tabela["Label"].unique()}
    rotulos = tabela["Label"].map(canonicos).to_numpy(dtype=str)
    return valores, rotulos, truncado, sha256, tamanho


def _arquivos_merged(pasta):
    arquivos = sorted(Path(pasta).glob("Merged*.csv"))
    if not arquivos:
        raise ValueError(f"nenhum arquivo Merged*.csv em {pasta}")
    return arquivos


def _identidade(caminho):
    estado = Path(caminho).stat()
    return {"bytes": estado.st_size, "modificado_ns": estado.st_mtime_ns}


def construir_indice(pasta_merged, destino):
    """Grava em `destino` os hashes ordenados de cada rótulo e variante e o resumo `indice.json`.

    Mantém na memória só os hashes, 8 bytes por linha e variante, e um arquivo do MERGED_CSV por vez.
    """
    destino = Path(destino)
    destino.mkdir(parents=True, exist_ok=True)
    partes = {variante: defaultdict(list) for variante in VARIANTES}
    por_rotulo = Counter()
    arquivos = []
    inicio = time.perf_counter()
    for caminho in _arquivos_merged(pasta_merged):
        valores, rotulos, truncado, sha256, _ = ler_merged(caminho)
        quantizados = quantizar(valores)
        por_variante = {variante: hashes(quantizados, colunas) for variante, colunas in VARIANTES.items()}
        for rotulo in np.unique(rotulos):
            linhas = rotulos == rotulo
            por_rotulo[rotulo] += int(linhas.sum())
            for variante, h in por_variante.items():
                partes[variante][rotulo].append(h[linhas])
        arquivos.append({
            "arquivo": caminho.name, **_identidade(caminho), "sha256": sha256, "linhas": len(valores),
            "truncado": truncado,
        })
        print(f"índice: {caminho.name}, {_milhar(len(valores))} linhas", file=sys.stderr, flush=True)
    for variante, rotulos in partes.items():
        for rotulo, pedacos in rotulos.items():
            np.save(destino / f"{rotulo}__{variante}.npy", np.sort(np.concatenate(pedacos)))
        rotulos.clear()
    resumo = {
        "versao_do_codigo": versao_do_indice(), "bits_mantidos": BITS_MANTIDOS,
        "pasta": Path(pasta_merged).as_posix(),
        "arquivos": arquivos, "linhas": sum(por_rotulo.values()), "por_rotulo": dict(sorted(por_rotulo.items())),
        "segundos": round(time.perf_counter() - inicio, 1),
    }
    (destino / "indice.json").write_text(json.dumps(resumo, indent=1, ensure_ascii=False), encoding="utf-8")
    return resumo


def indice_valido(pasta_merged, destino):
    """O resumo do índice guardado, se ele ainda vale para os arquivos da pasta; senão None."""
    try:
        resumo = json.loads((Path(destino) / "indice.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    atuais = [{"arquivo": c.name, **_identidade(c)} for c in _arquivos_merged(pasta_merged)]
    guardados = [{chave: a[chave] for chave in ("arquivo", "bytes", "modificado_ns")} for a in resumo["arquivos"]]
    if resumo.get("versao_do_codigo") != versao_do_indice() or atuais != guardados:
        return None
    return resumo


def carregar_indice(destino, rotulo, variante="todas"):
    caminho = Path(destino) / f"{rotulo}__{variante}.npy"
    return np.load(caminho) if caminho.exists() else np.empty(0, dtype=np.uint64)


# --- extração ---------------------------------------------------------------------------------


def janela_da_classe(rotulo):
    """A janela com que os autores agregaram o rótulo: 100 em DDoS, DoS e Mirai, 10 nas demais."""
    return 100 if CATEGORIA_DO_ROTULO[rotulo] in ("DDoS", "DoS", "Mirai") else 10


_FORMATOS = {
    b"\xd4\xc3\xb2\xa1": ("<", "microssegundos"), b"\xa1\xb2\xc3\xd4": (">", "microssegundos"),
    b"\x4d\x3c\xb2\xa1": ("<", "nanossegundos"), b"\xa1\xb2\x3c\x4d": (">", "nanossegundos"),
}


def cabecalho_pcap(caminho):
    """Formato do instante, limite de captura e tipo de enlace declarados no cabeçalho do pcap."""
    with open(caminho, "rb") as arquivo:
        cabecalho = arquivo.read(24)
    if cabecalho[:4] not in _FORMATOS or len(cabecalho) < 24:
        raise ValueError(f"{Path(caminho).name}: não é um pcap clássico")
    ordem, formato = _FORMATOS[cabecalho[:4]]
    limite, enlace = struct.unpack(ordem + "II", cabecalho[16:24])
    return {"formato_do_instante": formato, "limite_de_captura": limite, "enlace": enlace}


class _LeituraComHash:
    """Fluxo de leitura que calcula o SHA-256 do que passa por ele."""

    def __init__(self, arquivo):
        self._arquivo = arquivo
        self.sha256 = hashlib.sha256()

    def read(self, n):
        dados = self._arquivo.read(n)
        self.sha256.update(dados)
        return dados

    def esgotar(self):
        while self.read(1 << 20):
            pass


def _guardar(destino, linha):
    destino.extend(float(linha[coluna]) for coluna in COLUNAS)


def _matriz(valores):
    return np.frombuffer(valores, dtype=np.float64).reshape(-1, len(COLUNAS)).copy()


def extrair_pcap(caminho, janela, limite=LIMITE_PEDACO):
    """Extrai o pcap das duas formas, numa leitura só.

    Fatiada, como os autores: pedaços de `limite` bytes, cada um com um extrator novo, e por isso o
    primeiro quadro mantido de cada pedaço fica com IAT 0, como em `extrair(pedaco)`. Contínua,
    como a operação. Cada quadro é medido uma vez e entregue aos dois extratores.

    Devolve (fatiada, pedaço de cada linha fatiada, contínua, registro), as matrizes com as 39
    colunas na ordem de COLUNAS.
    """
    fatiada, pedacos_das_linhas, continua = array.array("d"), array.array("i"), array.array("d")
    continuo = Extrator(janela)
    tipos, contagem = Counter(), Counter()
    pacotes = pedacos = curtos = longos = 0
    ts_anterior = None
    inicio = time.perf_counter()
    with open(caminho, "rb") as arquivo, warnings.catch_warnings(record=True) as avisos:
        warnings.simplefilter("always", CapturaIncompleta)
        leitura = _LeituraComHash(arquivo)
        for indice, pedaco in enumerate(fatiar(ler_pcap(leitura, contagem), limite)):
            pedacos += 1
            fatia = Extrator(janela)
            primeiro_do_pedaco = True
            for ts, quadro in pedaco:
                pacotes += 1
                tipos[tipo_ethernet(quadro)] += 1
                curtos += len(quadro) < QUADRO_MINIMO
                longos += len(quadro) > QUADRO_MAXIMO
                medida = medir_quadro(ts, quadro, ts_anterior)
                if medida is None:
                    continue
                ts_anterior = ts
                linha = continuo.acumular(medida)
                if linha is not None:
                    _guardar(continua, linha)
                if primeiro_do_pedaco:
                    medida = {**medida, "IAT": 0.0}
                    primeiro_do_pedaco = False
                linha = fatia.acumular(medida)
                if linha is not None:
                    _guardar(fatiada, linha)
                    pedacos_das_linhas.append(indice)
            linha = fatia.finalizar()
            if linha is not None:
                _guardar(fatiada, linha)
                pedacos_das_linhas.append(indice)
        linha = continuo.finalizar()
        if linha is not None:
            _guardar(continua, linha)
        leitura.esgotar()
    fatiada, continua = _matriz(fatiada), _matriz(continua)
    registro = {
        "arquivo": Path(caminho).name, "janela": janela, **_identidade(caminho),
        "sha256": leitura.sha256.hexdigest(), **cabecalho_pcap(caminho),
        "pacotes": pacotes, "pedacos": pedacos,
        "quadros_mantidos": int(fatiada[:, COLUNAS.index("Number")].sum()) if len(fatiada) else 0,
        "tipos_ethernet": {str(tipo): quantos for tipo, quantos in sorted(tipos.items())},
        "registros_menores_que_o_original": contagem["menor_que_o_original"],
        "quadros_menores_que_60": curtos, "quadros_maiores_que_1514": longos,
        "avisos": [str(aviso.message) for aviso in avisos if issubclass(aviso.category, CapturaIncompleta)],
        "segundos": round(time.perf_counter() - inicio, 1),
    }
    return fatiada, np.frombuffer(pedacos_das_linhas, dtype=np.int32).copy(), continua, registro


def _resumo_do_codigo(*partes):
    """SHA-256 de textos, arquivos de código e do código-fonte de funções e classes."""
    sha = hashlib.sha256()
    for parte in partes:
        if isinstance(parte, Path):
            sha.update(parte.read_bytes())
        elif isinstance(parte, str):
            sha.update(parte.encode())
        else:
            sha.update(inspect.getsource(parte).encode())
    return sha.hexdigest()


def versao_da_extracao():
    """Resumo do código que decide os números extraídos de um pcap: o extrator, o fatiamento, a
    janela da classe e o rótulo do pcap. Muda quando algum deles muda, e a extração é refeita."""
    return _resumo_do_codigo(
        str(VERSAO_EXTRACAO), Path(extrator.__file__), Path(calibrar.__file__), Path(mapeamento.__file__),
        extrair_pcap, _guardar, _matriz, _LeituraComHash, cabecalho_pcap, janela_da_classe, processar_pcap,
        rotulo_do_pcap,
    )


def versao_do_indice():
    """Resumo do código que decide os hashes do índice: a leitura do MERGED_CSV, a normalização dos
    rótulos e a chave. Muda quando algum deles muda, e o índice é refeito."""
    return _resumo_do_codigo(
        str(VERSAO_INDICE), str(BITS_MANTIDOS), repr(VARIANTES), _CONSTANTES.tobytes().hex(),
        Path(mapeamento.__file__), ler_merged, quantizar, _misturar, hashes, construir_indice,
    )


def _arquivos_da_extracao(trabalho, caminho):
    pasta = Path(trabalho) / "extracao"
    return {
        nome: pasta / f"{Path(caminho).stem}.{nome}" for nome in ("fatiada.npy", "pedaco.npy", "continua.npy", "json")
    }


def extracao_valida(trabalho, caminho, janela, versao):
    """O registro da extração guardada do pcap, se ela ainda vale; senão None."""
    arquivos = _arquivos_da_extracao(trabalho, caminho)
    try:
        registro = json.loads(arquivos["json"].read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    atual = {"janela": janela, "versao_do_codigo": versao, **_identidade(caminho)}
    if any(registro.get(chave) != valor for chave, valor in atual.items()):
        return None
    if not all(arquivo.exists() for arquivo in arquivos.values()):
        return None
    return registro


def processar_pcap(caminho, rotulo, trabalho, versao):
    """Extrai um pcap e guarda as matrizes e o registro em `trabalho`. Roda num processo à parte."""
    janela = janela_da_classe(rotulo)
    fatiada, pedacos, continua, registro = extrair_pcap(caminho, janela)
    registro |= {"rotulo": rotulo, "versao_do_codigo": versao}
    arquivos = _arquivos_da_extracao(trabalho, caminho)
    arquivos["json"].parent.mkdir(parents=True, exist_ok=True)
    np.save(arquivos["fatiada.npy"], fatiada)
    np.save(arquivos["pedaco.npy"], pedacos)
    np.save(arquivos["continua.npy"], continua)
    arquivos["json"].write_text(json.dumps(registro, indent=1, ensure_ascii=False), encoding="utf-8")
    return registro


def carregar_extracao(trabalho, caminho):
    arquivos = _arquivos_da_extracao(trabalho, caminho)
    return np.load(arquivos["fatiada.npy"]), np.load(arquivos["pedaco.npy"]), np.load(arquivos["continua.npy"])


# --- correspondência --------------------------------------------------------------------------


def ks(a, b):
    """Estatística de Kolmogorov-Smirnov entre dois conjuntos de valores, só com os finitos."""
    a, b = np.sort(a[np.isfinite(a)]), np.sort(b[np.isfinite(b)])
    if not len(a) or not len(b):
        return 0.0
    pontos = np.concatenate([a, b])
    acumulada_a = np.searchsorted(a, pontos, "right") / len(a)
    acumulada_b = np.searchsorted(b, pontos, "right") / len(b)
    return float(np.max(np.abs(acumulada_a - acumulada_b)))


def casar_pcap(fatiada, pedacos, continua, rotulo, janela, indice, pasta_indice):
    """Mede o pcap contra o índice. `indice` traz, por rótulo, os hashes ordenados de todas as colunas.

    Devolve as medidas do pcap e a máscara das linhas fatiadas que têm par.
    """
    quantizados = quantizar(fatiada)
    h = hashes(quantizados)
    deles = indice.get(rotulo, np.empty(0, dtype=np.uint64))
    com_par, mascara = contar_comuns(h, deles)
    sem = ~mascara
    casam = {}
    for variante in ("sem_tempo", "sem_tamanho"):
        if sem.any():
            ordenado = carregar_indice(pasta_indice, rotulo, variante)
            casam[variante] = int(presentes(hashes(quantizados[sem], VARIANTES[variante]), ordenado).sum())
        else:
            casam[variante] = 0
    melhor, melhor_fracao = "", 0.0
    for outro, ordenado in indice.items():
        if outro != rotulo and len(h):
            fracao = float(presentes(h, ordenado).mean())
            if fracao > melhor_fracao:
                melhor, melhor_fracao = outro, fracao
    ruins = 0
    for pedaco in np.unique(pedacos):
        ruins += bool(mascara[pedacos == pedaco].mean() < 0.5)
    incompletas = fatiada[:, COLUNAS.index("Number")] < janela
    hc = hashes(quantizar(continua))
    continua_com_par, _ = contar_comuns(hc, deles)
    continua_igual, _ = contar_comuns(hc, np.sort(h))
    distancias = [(ks(fatiada[:, j], continua[:, j]), coluna) for j, coluna in enumerate(COLUNAS)]
    maior_ks, coluna_ks = max(distancias, key=lambda par: (par[0], -COLUNAS.index(par[1])))
    n = len(fatiada)
    medidas = {
        "linhas": n, "com_par": com_par, "fracao_com_par": com_par / n if n else None, "sem_par": int(sem.sum()),
        "sem_par_incompletas": int((sem & incompletas).sum()), "linhas_incompletas": int(incompletas.sum()),
        "sem_par_casam_sem_tempo": casam["sem_tempo"], "sem_par_casam_sem_tamanho": casam["sem_tamanho"],
        "outro_rotulo": melhor, "fracao_no_outro_rotulo": melhor_fracao,
        "pedacos_com_menos_da_metade": ruins,
        "continua": {
            "linhas": len(continua), "incompletas": int((continua[:, COLUNAS.index("Number")] < janela).sum()),
            "com_par": continua_com_par, "fracao_com_par": continua_com_par / len(continua) if len(continua) else None,
            "iguais_a_fatiada": continua_igual,
            "fracao_igual_a_fatiada": continua_igual / len(continua) if len(continua) else None,
            "maior_ks": maior_ks, "coluna_do_maior_ks": coluna_ks,
        },
    }
    return medidas, mascara


def cobertura(hashes_por_rotulo, indice, linhas_por_rotulo):
    """(b): por rótulo, quantas linhas do MERGED_CSV os nossos pcaps daquele rótulo cobrem."""
    resultado = []
    for rotulo, total in sorted(linhas_por_rotulo.items()):
        partes = hashes_por_rotulo.get(rotulo, [])
        nossos = np.concatenate(partes) if partes else np.empty(0, dtype=np.uint64)
        cobertas, _ = contar_comuns(nossos, indice[rotulo]) if len(nossos) else (0, None)
        resultado.append({
            "rotulo": rotulo, "pcaps": len(partes), "linhas_merged": total, "linhas_nossas": len(nossos),
            "linhas_merged_cobertas": cobertas, "fracao_coberta": cobertas / total if total else None,
        })
    return resultado


# --- controle do vizinho mais próximo ---------------------------------------------------------

_I = {coluna: j for j, coluna in enumerate(COLUNAS)}
# Duas chaves grossas para achar candidatos: tamanhos e Number, ou protocolo, contagens e Number.
CHAVES_GROSSAS = {
    "tamanhos": tuple(_I[c] for c in ("Number", "Tot sum", "Min", "Max")),
    "protocolo": tuple(_I[c] for c in ("Number", "Protocol Type", "ack_count", "syn_count", "fin_count", "rst_count")),
}
CANDIDATOS_POR_CHAVE = 64
# Desfechos da comparação com o vizinho mais próximo.
DESFECHOS = ("so_tempo", "tempo_e_outras", "outras_sem_tempo", "sem_candidato", "igual")


def colunas_diferentes(linha, candidatos):
    """Máscara (k, 39) das colunas em que cada candidato difere da linha, com a tolerância do calibrador."""
    iguais = np.isclose(candidatos, linha[None, :], rtol=calibrar.TOLERANCIA, atol=calibrar.TOLERANCIA_ABSOLUTA,
                        equal_nan=True)
    return ~iguais


def vizinhos(pasta_merged, amostras):
    """Compara cada linha sem par com a linha mais parecida do mesmo rótulo no MERGED_CSV.

    `amostras` é {arquivo: (rótulo, matriz das linhas sem par)}. Percorre o MERGED_CSV uma vez,
    guardando até CANDIDATOS_POR_CHAVE linhas por chave grossa. Devolve, por arquivo, a contagem
    das linhas por desfecho e das colunas que diferem no vizinho mais próximo.
    """
    procura = defaultdict(lambda: defaultdict(set))  # rótulo -> chave -> hashes procurados
    for rotulo, linhas in amostras.values():
        if len(linhas):
            quantizadas = quantizar(linhas)
            for nome, colunas in CHAVES_GROSSAS.items():
                procura[rotulo][nome].update(int(x) for x in hashes(quantizadas, colunas))
    candidatos = defaultdict(list)
    alvos = {
        rotulo: {nome: np.array(sorted(chaves), dtype=np.uint64) for nome, chaves in por_chave.items()}
        for rotulo, por_chave in procura.items()
    }
    if alvos:
        for caminho in _arquivos_merged(pasta_merged):
            valores, rotulos, *_ = ler_merged(caminho)
            for rotulo, por_chave in alvos.items():
                do_rotulo = valores[rotulos == rotulo]
                quantizadas = quantizar(do_rotulo)
                for nome, colunas in CHAVES_GROSSAS.items():
                    alvo = por_chave[nome]
                    h = hashes(quantizadas, colunas)
                    for j in np.flatnonzero(np.isin(h, alvo)):
                        lista = candidatos[rotulo, nome, int(h[j])]
                        if len(lista) < CANDIDATOS_POR_CHAVE:
                            lista.append(do_rotulo[j].copy())
            print(f"vizinhos: {caminho.name}", file=sys.stderr, flush=True)
    resultado = {}
    tempo = np.array([c in TEMPO for c in COLUNAS])
    for arquivo, (rotulo, linhas) in amostras.items():
        desfechos, colunas = Counter(), Counter()
        quantizadas = quantizar(linhas) if len(linhas) else None
        for i, linha in enumerate(linhas):
            achados = [
                candidatos.get((rotulo, nome, int(hashes(quantizadas[i : i + 1], cols)[0])), [])
                for nome, cols in CHAVES_GROSSAS.items()
            ]
            achados = [c for lista in achados for c in lista]
            if not achados:
                desfechos["sem_candidato"] += 1
                continue
            diferentes = colunas_diferentes(linha, np.array(achados))
            melhor = diferentes[np.argmin(diferentes.sum(axis=1))]
            colunas.update(c for c, d in zip(COLUNAS, melhor) if d)
            if not melhor.any():
                desfechos["igual"] += 1
            elif not (melhor & ~tempo).any():
                desfechos["so_tempo"] += 1
            elif (melhor & tempo).any():
                desfechos["tempo_e_outras"] += 1
            else:
                desfechos["outras_sem_tempo"] += 1
        resultado[arquivo] = {
            "examinadas": len(linhas),
            **{chave: desfechos[chave] for chave in DESFECHOS},
            "colunas": dict(colunas.most_common()),
        }
    return resultado


def amostra_sem_par(fatiada, mascara, quantas, semente=0):
    """Até `quantas` linhas sem par, sorteadas com semente fixa e na ordem do arquivo."""
    sem = np.flatnonzero(~mascara)
    if sem.size > quantas:
        sem = np.sort(np.random.default_rng(semente).choice(sem, quantas, replace=False))
    return fatiada[sem]


# --- execução ---------------------------------------------------------------------------------


def listar_pcaps(dataset):
    pcaps = sorted(Path(dataset).glob("*.pcap"))
    if not pcaps:
        raise ValueError(f"nenhum pcap em {dataset}")
    return [(caminho, rotulo_do_pcap(caminho.name)) for caminho in pcaps]


def rodar(dataset, pasta_merged, trabalho, processos=3, vizinhos_por_pcap=200):
    """Faz a calibração e devolve o manifesto."""
    inicio = time.perf_counter()
    trabalho = Path(trabalho)
    pcaps = listar_pcaps(dataset)
    _arquivos_merged(pasta_merged)  # sem o MERGED_CSV, nada é extraído
    versao = versao_da_extracao()
    destino_indice = trabalho / "indice"
    resumo_indice = indice_valido(pasta_merged, destino_indice)
    registros = {}
    pendentes = []
    for caminho, rotulo in pcaps:
        guardado = extracao_valida(trabalho, caminho, janela_da_classe(rotulo), versao)
        if guardado is None:
            pendentes.append((caminho, rotulo))
        else:
            registros[caminho.name] = guardado
    # Os maiores primeiro, para equilibrar os processos; o índice entra como mais uma tarefa.
    pendentes.sort(key=lambda par: -par[0].stat().st_size)
    print(
        f"{len(pendentes)} pcaps a extrair, {len(pcaps) - len(pendentes)} reaproveitados; índice "
        f"{'reaproveitado' if resumo_indice else 'a construir'}; {processos} processos",
        file=sys.stderr, flush=True,
    )
    with ProcessPoolExecutor(max_workers=processos) as executor:
        tarefa_indice = None if resumo_indice else executor.submit(construir_indice, pasta_merged, destino_indice)
        tarefas = {
            executor.submit(processar_pcap, caminho, rotulo, trabalho, versao): caminho for caminho, rotulo in pendentes
        }
        for tarefa, caminho in tarefas.items():
            registro = tarefa.result()
            registros[caminho.name] = registro
            print(f"extraído: {caminho.name}, {registro['segundos']} s", file=sys.stderr, flush=True)
        if tarefa_indice is not None:
            resumo_indice = tarefa_indice.result()
    indice = {rotulo: carregar_indice(destino_indice, rotulo) for rotulo in resumo_indice["por_rotulo"]}
    hashes_por_rotulo = defaultdict(list)
    amostras = {}
    resultados = []
    for caminho, rotulo in pcaps:
        registro = registros[caminho.name]
        fatiada, pedacos, continua = carregar_extracao(trabalho, caminho)
        medidas, mascara = casar_pcap(fatiada, pedacos, continua, rotulo, registro["janela"], indice, destino_indice)
        hashes_por_rotulo[rotulo].append(hashes(quantizar(fatiada)))
        amostras[caminho.name] = (rotulo, amostra_sem_par(fatiada, mascara, vizinhos_por_pcap))
        resultados.append({**{k: v for k, v in registro.items() if k != "versao_do_codigo"}, **medidas})
        print(f"casado: {caminho.name}, {_pct(medidas['fracao_com_par'])} com par", file=sys.stderr, flush=True)
    rotulos = cobertura(hashes_por_rotulo, indice, resumo_indice["por_rotulo"])
    del indice, hashes_por_rotulo
    por_vizinho = vizinhos(pasta_merged, amostras) if vizinhos_por_pcap else {}
    for resultado in resultados:
        resultado["vizinho"] = por_vizinho.get(resultado["arquivo"])
    segundos = time.perf_counter() - inicio
    return montar_manifesto(resultados, rotulos, resumo_indice, dataset, vizinhos_por_pcap, segundos)


def montar_manifesto(pcaps, rotulos, resumo_indice, dataset, vizinhos_por_pcap, segundos):
    return {
        "descricao": (
            "Calibração de conjunto do extrator: as linhas de cada pcap do CICIoT2023, extraídas como os autores "
            "extraíram, procuradas entre as linhas do mesmo rótulo no MERGED_CSV"
        ),
        "gerado_por": "python -m codigo.captura.calibrar_conjunto",
        "gerado_em": datetime.datetime.now(tz=datetime.UTC).astimezone().strftime("%Y-%m-%d"),
        "versoes": {
            "python": platform.python_version(), "dpkt": dpkt.__version__, "numpy": np.__version__,
            "pandas": pd.__version__,
        },
        "dataset": Path(dataset).as_posix(),
        "limite_do_pedaco": LIMITE_PEDACO,
        "chave": {
            "bits_mantidos": BITS_MANTIDOS,
            "variantes": {
                nome: [COLUNAS[j] for j in colunas] for nome, colunas in VARIANTES.items() if nome != "todas"
            },
        },
        "vizinhos_por_pcap": vizinhos_por_pcap,
        "merged_csv": {k: v for k, v in resumo_indice.items() if k not in ("versao_do_codigo", "segundos")},
        "pcaps": pcaps,
        "rotulos": rotulos,
        "segundos": round(segundos, 1),
    }


# --- relatório --------------------------------------------------------------------------------


def _pct(valor, casas=2):
    return "sem linhas" if valor is None else f"{100 * valor:.{casas}f}%".replace(".", ",")


def _decimal(valor, casas=1):
    return f"{valor:,.{casas}f}".translate(str.maketrans(",.", ".,"))


def _tabela(cabecalho, linhas):
    return [
        "| " + " | ".join(cabecalho) + " |",
        "|" + "---|" * len(cabecalho),
        *("| " + " | ".join(str(celula) for celula in linha) + " |" for linha in linhas),
    ]


def _data(iso):
    ano, mes, dia = iso.split("-")
    return f"{dia}/{mes}/{ano}"


def _faixa(valores):
    valores = [v for v in valores if v is not None]
    return f"{_pct(min(valores))} e {_pct(max(valores))}" if valores else "sem linhas"


def _truncados(arquivos):
    if not arquivos:
        return "nenhum arquivo"
    nomes = ", ".join(f"`{a}`" for a in arquivos)
    return f"1 arquivo: {nomes}" if len(arquivos) == 1 else f"{len(arquivos)} arquivos: {nomes}"


def _maior_ks(continua):
    if not continua["maior_ks"]:
        return "0"
    return f"`{continua['coluna_do_maior_ks']}` {_decimal(continua['maior_ks'], 4)}"


def _outro(p):
    if p["fracao_no_outro_rotulo"] < 0.01:
        return "< 1%"
    return f"{p['outro_rotulo']} ({_pct(p['fracao_no_outro_rotulo'])})"


def _fora_do_filtro(p):
    """Os quadros fora do filtro por nome de tipo; os tipos do 802.3 com LLC se juntam num nome só."""
    fora = Counter()
    for tipo, quantos in p["tipos_ethernet"].items():
        if int(tipo) not in (0x0800, 0x0806):
            fora[nome_do_tipo(int(tipo))] += quantos
    if not fora:
        return "nenhum"
    return "; ".join(f"{nome}: {_milhar(quantos)}" for nome, quantos in fora.most_common())


def montar_relatorio(m):
    """Monta o relatório em Markdown a partir do manifesto."""
    pcaps, rotulos, merged = m["pcaps"], m["rotulos"], m["merged_csv"]
    v = m["versoes"]
    completos = [r for r in rotulos if r["linhas_merged_cobertas"] == r["linhas_merged"] and r["linhas_merged"]]
    nossos_completos = {r["rotulo"] for r in completos}
    com_par_completos = sum(p["com_par"] for p in pcaps if p["rotulo"] in nossos_completos)
    linhas_completos = sum(p["linhas"] for p in pcaps if p["rotulo"] in nossos_completos)
    truncados = [a["arquivo"] for a in merged["arquivos"] if a["truncado"]]
    ruins = [p["arquivo"] for p in pcaps if p["pedacos_com_menos_da_metade"]]
    ignorados = [p["arquivo"] for p in pcaps if p["quadros_mantidos"] != sum(
        n for t, n in p["tipos_ethernet"].items() if int(t) in (0x0800, 0x0806))]
    formatos = Counter(p["formato_do_instante"] for p in pcaps)
    cobertas_total = sum(r["linhas_merged_cobertas"] for r in rotulos)
    rotulos_com_pcap = [r for r in rotulos if r["pcaps"]]
    faixa_completos = [p["fracao_com_par"] for p in pcaps if p["rotulo"] in nossos_completos]
    acima = [p for p in pcaps if faixa_completos and p["fracao_com_par"] > max(faixa_completos)]
    # Partes de 2.048.000.000 de bytes: capturas maiores cortadas com tcpdump -C 2048.
    de_2048 = [p for p in pcaps if 2_048_000_000 <= p["bytes"] < 2_048_100_000]
    maior_ks = max((p["continua"]["maior_ks"] for p in pcaps), default=0.0)
    mais_lento = max((p["segundos"] for p in pcaps), default=0.0)
    linhas = [
        "# Calibração de conjunto do extrator",
        "",
        (
            f"Gerado por `python -m codigo.captura.calibrar_conjunto` em {_data(m['gerado_em'])}, com Python "
            f"{v['python']}, dpkt {v['dpkt']}, numpy {v['numpy']} e pandas {v['pandas']}."
        ),
        "",
        "O `calibracao.md` compara o extrator com o CSV oficial de cada pcap, linha a linha, e cobre os 5 pcaps",
        "que tinham esse CSV na máquina. Os CSVs por ataque não estão mais na cópia do dataset. O que existe é o",
        "`MERGED_CSV`, que junta as linhas de todas as capturas dos autores, embaralhadas e sem o nome do arquivo",
        "de origem. Esta calibração confere todos os pcaps da pasta do dataset contra ele: as linhas de cada pcap,",
        "extraídas como os autores extraíram, são procuradas entre as linhas do mesmo rótulo no `MERGED_CSV`.",
        "",
        "## Resumo",
        "",
        (
            f"- {len(pcaps)} pcaps, {len(rotulos_com_pcap)} rótulos, contra as {_milhar(merged['linhas'])} linhas dos "
            f"{len(merged['arquivos'])} arquivos do `MERGED_CSV`."
        ),
        (
            f"- Em todos os pcaps, entre {_faixa([p['fracao_com_par'] for p in pcaps])} das nossas linhas têm par "
            "exato, nas 39 colunas, entre as linhas do mesmo rótulo. "
            + ("Nenhum pedaço de 10 MB fica com menos da metade das linhas com par." if not ruins else
               f"Pcaps com pedaço de 10 MB com menos da metade das linhas com par: {', '.join(ruins)}.")
        ),
        (
            f"- Em {len(completos)} rótulos os nossos pcaps cobrem todas as linhas do `MERGED_CSV`. Nesses, o "
            f"`MERGED_CSV` traz {_pct(com_par_completos / linhas_completos if linhas_completos else None)} das nossas "
            "linhas: o que falta é a perda dos arquivos truncados na fonte oficial (ver \"Como ler os números\")."
        ),
        (
            f"- No total, os pcaps cobrem {_milhar(cobertas_total)} das {_milhar(merged['linhas'])} linhas do "
            f"`MERGED_CSV` ({_pct(cobertas_total / merged['linhas'])})."
        ),
        (
            "- Instante: " + ", ".join(f"{n} pcaps em {formato}" for formato, n in formatos.most_common())
            + ". " + ("Nenhum quadro IPv4 ou ARP ficou de fora da extração." if not ignorados else
                      f"Pcaps com quadro IPv4 ou ARP fora da extração: {', '.join(ignorados)}.")
        ),
        "",
        "## O que foi conferido",
        "",
        "1. O índice do `MERGED_CSV`: cada um dos arquivos é lido sozinho, com a linha final incompleta dos",
        f"   arquivos truncados descartada ({_truncados(truncados)}), e o rótulo de cada linha é normalizado para a",
        "   grafia canônica. Por rótulo, guardam-se os hashes das linhas.",
        f"2. A chave de cada linha arredonda os 39 valores a {m['chave']['bits_mantidos']} bits de mantissa (erro",
        "   relativo de até cerca de 4,7e-10, perto de 9 algarismos), deixa o infinito como está, põe todo NaN num",
        "   padrão só e mistura os valores num hash de 64 bits. O `MERGED_CSV` escreve os números no formato do",
        "   Java (`3.861904144287109E-5`), o infinito como texto e o NaN como campo vazio, então a chave é sobre o",
        "   valor numérico, e não sobre o texto.",
        "3. A extração de cada pcap é a dos autores: pedaços de 10.000.000 de bytes, como o `tcpdump -C 10`",
        "   (`calibrar.fatiar`), um extrator novo por pedaço e a janela da classe, 100 em DDoS, DoS e Mirai e 10",
        "   nas demais. Na mesma leitura sai a extração contínua, a da operação e da regeração dos dados de treino.",
        "4. (a) Fração das nossas linhas com par no rótulo do pcap, por multiconjunto: cada linha do `MERGED_CSV`",
        "   serve de par a uma linha nossa só. (b) Fração das linhas de cada rótulo no `MERGED_CSV` cobertas pelos",
        "   pcaps daquele rótulo. Para as linhas sem par, se casariam ignorando as colunas de tempo (`Rate`,",
        "   `IAT`) ou as de tamanho, e em que outro rótulo as linhas do pcap mais aparecem.",
        f"5. Controle do vizinho mais próximo: até {m['vizinhos_por_pcap']} linhas sem par de cada pcap, sorteadas,",
        "   comparadas coluna a coluna com a linha mais parecida do mesmo rótulo no `MERGED_CSV`.",
        "6. Leitura contínua contra fatiada, em todos os pcaps.",
        "",
        "## Resultado por pcap",
        "",
        "Colunas completas em `calibracao_conjunto_pcaps.csv`. A última coluna é o rótulo em que as linhas do pcap",
        "mais aparecem fora do próprio, pela simples presença da linha.",
        "",
        *_tabela(
            ["pcap", "rótulo", "janela", "pacotes", "quadros IPv4 e ARP", "pedaços de 10 MB", "nossas linhas",
             "com par no MERGED", "(a) fração", "(b) cobertura do rótulo", "maior fração em outro rótulo"],
            [
                [f"`{p['arquivo']}`", p["rotulo"], p["janela"], _milhar(p["pacotes"]), _milhar(p["quadros_mantidos"]),
                 p["pedacos"], _milhar(p["linhas"]), _milhar(p["com_par"]), _pct(p["fracao_com_par"]),
                 _pct(next(r["fracao_coberta"] for r in rotulos if r["rotulo"] == p["rotulo"])), _outro(p)]
                for p in pcaps
            ],
        ),
        "",
        "## Cobertura por rótulo",
        "",
        "Tabela também em `calibracao_conjunto_rotulos.csv`.",
        "",
        *_tabela(
            ["rótulo", "pcaps", "linhas no MERGED_CSV", "nossas linhas", "linhas do MERGED cobertas", "(b) cobertura"],
            [
                [r["rotulo"], r["pcaps"], _milhar(r["linhas_merged"]), _milhar(r["linhas_nossas"]),
                 _milhar(r["linhas_merged_cobertas"]), _pct(r["fracao_coberta"])]
                for r in rotulos
            ],
        ),
        "",
        "## Como ler os números",
        "",
        "- **A cobertura (b) baixa nos floods e no benigno não indica erro.** O `MERGED_CSV` vem de todas as",
        (
            "  capturas dos autores, e temos uma ou duas partes de cada rótulo. "
            f"{len(de_2048)} dos {len(pcaps)} pcaps têm entre 2.048.000.000 e"
        ),
        "  2.048.100.000 bytes, o que indica partes cortadas com `tcpdump -C 2048` de capturas maiores. Nesses",
        "  rótulos a cobertura mede quanto do rótulo temos, e não a qualidade do extrator. O que mede o extrator",
        "  é a fração (a).",
        "- **O que falta nos rótulos completos vem dos arquivos truncados.** Nos rótulos em que os nossos pcaps",
        (
            "  cobrem todas as linhas do `MERGED_CSV`, ele traz "
            f"{_pct(com_par_completos / linhas_completos if linhas_completos else None)} das nossas linhas"
        ),
        f"  (entre {_faixa(faixa_completos)} por pcap). Os arquivos truncados na fonte oficial perderam as linhas",
        "  que viriam depois do corte, e como o conjunto é embaralhado a perda cai em todas as classes em",
        "  proporção parecida: o `exploracao.md` mede 4,26% de linhas a menos contra os CSVs por ataque. As linhas",
        "  sem par são essas, e o controle do vizinho mostra que são outras janelas, e não janelas calculadas de",
        "  outro jeito.",
        (
            "- **Acima dessa faixa, o excesso vem das linhas repetidas dos floods** "
            f"({len(acima)} pcaps). Uma linha nossa que se"
        ),
        "  perdeu no `MERGED_CSV` ainda acha par numa linha idêntica vinda de outra parte da mesma captura.",
        "- **A fração em outro rótulo** mostra a sobreposição já conhecida entre DDoS e DoS (`ROADMAP.md`,",
        "  04/10/2026): as mesmas janelas aparecem com os dois rótulos.",
        "- **Se o extrator divergisse** em alguma coluna ou protocolo, ou a emulação do fatiamento estivesse",
        "  errada, a fração (a) cairia para perto do que a leitura contínua consegue (seção seguinte), e não",
        "  ficaria na faixa da perda dos arquivos truncados.",
        "",
        "## Leitura contínua contra leitura fatiada",
        "",
        "A operação e a regeração dos dados de treino leem o pcap de uma vez; o `MERGED_CSV` vem da leitura em",
        "pedaços de 10 MB. A diferença sistemática é uma janela incompleta e um IAT zerado por pedaço. Depois da",
        "primeira fronteira de pedaço as janelas ficam deslocadas, e as linhas deixam de coincidir uma a uma, mas",
        "as distribuições ficam praticamente iguais. A última coluna é a maior distância de Kolmogorov-Smirnov",
        "entre as duas leituras, entre as 39 colunas.",
        "",
        *_tabela(
            ["pcap", "janela", "linhas fatiada", "linhas contínua", "incompletas fatiada / contínua",
             "fatiada no MERGED", "contínua no MERGED", "contínua igual à fatiada", "maior KS"],
            [
                [f"`{p['arquivo']}`", p["janela"], _milhar(p["linhas"]), _milhar(p["continua"]["linhas"]),
                 f"{_milhar(p['linhas_incompletas'])} / {_milhar(p['continua']['incompletas'])}",
                 _pct(p["fracao_com_par"]), _pct(p["continua"]["fracao_com_par"]),
                 _pct(p["continua"]["fracao_igual_a_fatiada"]),
                 _maior_ks(p["continua"])]
                for p in pcaps
            ],
        ),
        "",
        f"Maior distância entre todos os pcaps e colunas: {_decimal(maior_ks, 4)}.",
        "",
        *_secao_vizinho(m),
        "## A captura de cada pcap",
        "",
        "O que o cabeçalho e os quadros de cada pcap dizem da captura. O instante em nanossegundos seria truncado",
        "para microssegundos, como o `tcpdump -r ... -w` do fatiamento dos autores grava. Quadro menor que 60",
        "bytes não passa assim no fio (falta o preenchimento) e quadro maior que 1514 bytes só existe com",
        "offload de segmentação na máquina que capturou. As opções `--preencher` e `--limitar` do extrator",
        "medem o quadro como no fio; desligadas, como aqui, ele reproduz os autores.",
        "",
        *_resumo_da_captura(pcaps),
        *_tabela(
            ["pcap", "instante", "limite de captura", "gravados menores que o original", "quadros < 60 B",
             "quadros > 1514 B", "quadros fora do filtro"],
            [
                [f"`{p['arquivo']}`", p["formato_do_instante"], _milhar(p["limite_de_captura"]),
                 _milhar(p["registros_menores_que_o_original"]), _milhar(p["quadros_menores_que_60"]),
                 _milhar(p["quadros_maiores_que_1514"]), _fora_do_filtro(p)]
                for p in pcaps
            ],
        ),
        "",
        "## Como refazer",
        "",
        "A partir da raiz do repositório, com os pcaps e o `MERGED_CSV` na pasta do dataset:",
        "",
        "    python -m codigo.captura.calibrar_conjunto --dataset CICIoT2023 --processos 3",
        "",
        "- O comando constrói o índice do `MERGED_CSV` (o processo do índice chega a cerca de 4,3 GB de memória),",
        "  extrai os pcaps em paralelo, casa as linhas, roda o controle do vizinho e grava este relatório,",
        "  `calibracao_conjunto_pcaps.csv`, `calibracao_conjunto_rotulos.csv` e `manifesto_calibracao_conjunto.json`.",
        "  O manifesto traz o SHA-256 de cada pcap e de cada arquivo do `MERGED_CSV`.",
        f"- Os dados intermediários ficam em `{TRABALHO}`, fora do git. Numa execução seguinte,",
        "  o índice e as extrações são reaproveitados enquanto os arquivos e o código do extrator não mudarem;",
        "  para refazer tudo, apague a pasta.",
        (
            f"- Tempo total desta execução: {_decimal(m['segundos'] / 60)} min; o pcap mais demorado levou "
            f"{_decimal(mais_lento / 60)} min. Os tempos das extrações reaproveitadas são os da execução em que"
            " foram feitas."
        ),
        "- Com os mesmos arquivos, os números saem iguais. Só mudam a data e os tempos.",
        "",
    ]
    return "\n".join(linhas)


def _nomes(pcaps):
    return ", ".join(f"`{p['arquivo']}`" for p in pcaps) or "nenhum"


def _resumo_da_captura(pcaps):
    """O que a tabela da captura mostra, em frases: quadros curtos, longos e limite de captura."""
    curtos = [p for p in pcaps if p["quadros_menores_que_60"]]
    longos = [p for p in pcaps if p["quadros_maiores_que_1514"]]
    limites = Counter(p["limite_de_captura"] for p in pcaps)
    cortados = [p for p in pcaps if p["registros_menores_que_o_original"]]
    return [
        (
            f"- Quadro menor que 60 bytes: {_nomes(curtos)}. Quadro maior que 1514 bytes: {len(longos)} dos "
            f"{len(pcaps)} pcaps."
        ),
        "- Limite de captura declarado: "
        + "; ".join(f"{_milhar(limite)} bytes em {n} pcaps" for limite, n in limites.most_common()) + ".",
        (
            f"- Registro gravado com menos bytes que o quadro original (limite de captura curto): {_nomes(cortados)}."
            if cortados else
            "- Nenhum pcap tem registro gravado com menos bytes que o quadro original (limite de captura curto)."
        ),
        "",
    ]


def _secao_vizinho(m):
    com = [p for p in m["pcaps"] if p.get("vizinho")]
    if not com:
        return []
    total = Counter()
    colunas = Counter()
    for p in com:
        for chave in ("examinadas", *DESFECHOS):
            total[chave] += p["vizinho"][chave]
        colunas.update(p["vizinho"]["colunas"])
    mais = ", ".join(f"`{c}` ({_milhar(n)})" for c, n in colunas.most_common(8))
    return [
        "## Linhas sem par: o vizinho mais próximo",
        "",
        (
            f"Foram examinadas {_milhar(total['examinadas'])} linhas sem par, até {m['vizinhos_por_pcap']} por pcap. "
            "Para cada uma, o `MERGED_CSV` foi percorrido em busca das linhas do mesmo rótulo com o mesmo `Number` e os"
            " mesmos tamanhos, ou o mesmo protocolo e as mesmas contagens de flags (até "
            f"{CANDIDATOS_POR_CHAVE} por chave), e a mais parecida foi comparada coluna a coluna, com a tolerância do"
            " calibrador."
        ),
        "",
        *_tabela(
            ["desfecho", "linhas"],
            [
                ["o vizinho difere só em `Rate` ou `IAT`", _milhar(total["so_tempo"])],
                ["difere em `Rate` ou `IAT` e em outras colunas", _milhar(total["tempo_e_outras"])],
                ["difere em outras colunas, com `Rate` e `IAT` iguais", _milhar(total["outras_sem_tempo"])],
                ["igual em todas as colunas", _milhar(total["igual"])],
                ["nenhum candidato com a mesma chave grossa", _milhar(total["sem_candidato"])],
            ],
        ),
        "",
        f"Colunas que mais diferem no vizinho mais próximo: {mais}.",
        "",
        (
            "Uma linha calculada de outro jeito acharia um vizinho igual em quase tudo e diferente sempre na mesma"
            " coluna. O que aparece é o contrário: o vizinho difere nos instantes e em geral em várias outras"
            " colunas, ou nem existe. As linhas sem par são janelas que faltam no `MERGED_CSV`. O vizinho igual em"
            " todas as colunas é o de uma linha repetida no pcap: a linha idêntica do `MERGED_CSV` já serviu de par"
            " a outra linha nossa igual, e na correspondência por multiconjunto cada uma serve a uma só. Por pcap,"
            " os desfechos estão no manifesto, em `vizinho`."
        ),
        "",
    ]


CAMPOS_PCAPS = (
    "arquivo", "rotulo", "janela", "bytes", "sha256", "formato_do_instante", "limite_de_captura", "pacotes",
    "quadros_mantidos", "pedacos", "linhas", "com_par", "fracao_com_par", "sem_par", "sem_par_incompletas",
    "linhas_incompletas", "sem_par_casam_sem_tempo", "sem_par_casam_sem_tamanho", "outro_rotulo",
    "fracao_no_outro_rotulo", "pedacos_com_menos_da_metade", "registros_menores_que_o_original",
    "quadros_menores_que_60", "quadros_maiores_que_1514", "segundos",
)
CAMPOS_CONTINUA = ("linhas", "incompletas", "com_par", "fracao_com_par", "fracao_igual_a_fatiada", "maior_ks",
                   "coluna_do_maior_ks")
CAMPOS_VIZINHO = ("examinadas", "so_tempo", "tempo_e_outras", "outras_sem_tempo", "sem_candidato")
CAMPOS_ROTULOS = ("rotulo", "pcaps", "linhas_merged", "linhas_nossas", "linhas_merged_cobertas", "fracao_coberta")


def _campo(valor):
    if valor is None:
        return ""
    return f"{valor:.6f}" if isinstance(valor, float) else str(valor)


def _gravar_csv(caminho, cabecalho, linhas):
    with open(caminho, "w", encoding="utf-8", newline="") as arquivo:
        escritor = csv.writer(arquivo, lineterminator="\n")
        escritor.writerow(cabecalho)
        escritor.writerows(linhas)


def gravar(manifesto, pasta):
    """Grava o manifesto e o que sai dele: o relatório e as duas tabelas."""
    pasta = Path(pasta)
    pasta.mkdir(parents=True, exist_ok=True)
    (pasta / MANIFESTO).write_text(json.dumps(manifesto, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (pasta / RELATORIO).write_text(montar_relatorio(manifesto), encoding="utf-8")
    vazio = dict.fromkeys(CAMPOS_VIZINHO)
    _gravar_csv(
        pasta / TABELA_PCAPS,
        [*CAMPOS_PCAPS, *(f"continua_{c}" for c in CAMPOS_CONTINUA), *(f"vizinho_{c}" for c in CAMPOS_VIZINHO)],
        [
            [_campo(p[c]) for c in CAMPOS_PCAPS]
            + [_campo(p["continua"][c]) for c in CAMPOS_CONTINUA]
            + [_campo((p.get("vizinho") or vazio)[c]) for c in CAMPOS_VIZINHO]
            for p in manifesto["pcaps"]
        ],
    )
    _gravar_csv(
        pasta / TABELA_ROTULOS, CAMPOS_ROTULOS, [[_campo(r[c]) for c in CAMPOS_ROTULOS] for r in manifesto["rotulos"]],
    )


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.captura.calibrar_conjunto",
        description="Confere o extrator nos pcaps do CICIoT2023 contra o MERGED_CSV inteiro.",
    )
    analisador.add_argument("--dataset", default="CICIoT2023", help="pasta com os pcaps e o MERGED_CSV")
    analisador.add_argument("--merged", help="pasta do MERGED_CSV (padrão: DATASET/MERGED_CSV)")
    analisador.add_argument("--processos", type=int, default=3, help="processos de extração (padrão: 3)")
    analisador.add_argument("--saida", default="experimentos/resultados", help="pasta do relatório e das tabelas")
    analisador.add_argument("--trabalho", default=TRABALHO, help="pasta dos dados intermediários, fora do git")
    analisador.add_argument(
        "--vizinhos", type=int, default=200, help="linhas sem par por pcap no controle do vizinho (0 desliga)",
    )
    argumentos = analisador.parse_args(argv)
    if argumentos.processos < 1 or argumentos.vizinhos < 0:
        print("erro: --processos precisa ser ao menos 1 e --vizinhos não pode ser negativo", file=sys.stderr)
        return 2
    pasta_merged = Path(argumentos.merged or Path(argumentos.dataset) / "MERGED_CSV")
    try:
        manifesto = rodar(
            argumentos.dataset, pasta_merged, argumentos.trabalho, argumentos.processos, argumentos.vizinhos,
        )
    except (OSError, ValueError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 2
    gravar(manifesto, argumentos.saida)
    print(f"relatório em {Path(argumentos.saida) / RELATORIO}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
