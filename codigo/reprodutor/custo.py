"""Custo do modelo do sistema na operação: latência, vazão e memória, num núcleo.

Mede o classificador do sistema (`modelos/rf_regerado_janela_100.joblib`, decisão de 13/10/2026)
do jeito que o reprodutor o usa, com as funções da rodada i das rodadas de teste do modelo de
10/10 (`codigo/classificador/rodadas.py`):
- uma janela por vez, num núcleo, cada vez uma janela diferente: `predict_proba` sobre a matriz,
  como na rodada i, e o caminho inteiro do reprodutor, da linha do extrator à probabilidade
  (`Classificador.probabilidades`);
- um lote de 1.000 janelas;
- a vazão do extrator no mesmo pcap da rodada i, e a do reprodutor inteiro, com a classificação e
  a política de acionamento;
- o tempo de ler o modelo e a memória do processo antes e depois, num processo novo, e o pico de
  memória do processo da medida.

As janelas da latência vêm do trecho de teste (`inicio_do_teste`) de um pcap por categoria, até
`JANELAS_POR_PCAP` de cada um, extraídas como o reprodutor extrai. Os tempos são da máquina em que
a medida rodou, que o relatório identifica, e mudam de uma execução para outra.

Uso, a partir da raiz do repositório (os pcaps em CICIoT2023/, o modelo em modelos/):
    nice -n 10 python -m codigo.reprodutor.custo
"""

import argparse
import datetime
import hashlib
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import sklearn

from codigo.captura.extrator import Extrator, ler_pcap
from codigo.classificador import rodadas
from codigo.reprodutor import reprodutor as R

PASTA_DOS_PCAPS = Path("CICIoT2023")
# Um pcap por categoria do modelo, com trecho de teste curto de alcançar.
PCAPS_DA_LATENCIA = (
    "BenignTraffic2.pcap", "DDoS-SYN_Flood1.pcap", "DoS-SYN_Flood1.pcap", "Mirai-greip_flood21.pcap",
    "Recon-PortScan.pcap", "DNS_Spoofing.pcap", "XSS.pcap", "DictionaryBruteForce.pcap",
)
JANELAS_POR_PCAP = 300
MINIMO_DE_JANELAS = 1000
LOTE = 1000
RELATORIO = Path("experimentos") / "resultados" / "custo_do_modelo_do_sistema.md"
MANIFESTO = Path("experimentos") / "resultados" / "manifesto_custo_do_modelo_do_sistema.json"


def janelas_de_teste(caminho, limite=JANELAS_POR_PCAP, manifesto=R.MANIFESTO_DA_REGERACAO):
    """Até `limite` linhas do extrator, do trecho do pcap que ficou fora do treino; nenhuma se não há trecho."""
    inicio = R.inicio_do_teste(caminho, manifesto)
    if inicio is None:
        return []
    extrator, linhas, indice = Extrator(R.JANELA), [], 0
    for ts, quadro in ler_pcap(caminho):
        linha = extrator.alimentar(ts, quadro)
        if linha is None:
            continue
        if indice >= inicio:
            linhas.append(linha)
            if len(linhas) == limite:
                break
        indice += 1
    return linhas


def _resumo(tempos):
    return {
        "mediana_ms": float(np.median(tempos)), "p95_ms": float(np.percentile(tempos, 95)),
        "p99_ms": float(np.percentile(tempos, 99)),
    }


def latencia_do_caminho(classificador, linhas):
    """Como `rodadas.latencia`, pelo caminho do reprodutor: da linha do extrator à probabilidade, uma janela por vez."""
    classificador.probabilidades(linhas[:1])  # a primeira chamada paga o aquecimento
    tempos = []
    for i in range(len(linhas)):
        linha = linhas[(i * 7919) % len(linhas)]
        inicio = time.perf_counter()
        classificador.probabilidades([linha])
        tempos.append(1000 * (time.perf_counter() - inicio))
    return _resumo(tempos)


def medir(classificador, linhas, pcap_da_vazao):
    X = np.array([[linha[coluna] for coluna in classificador.features] for linha in linhas], dtype=np.float32)
    X = np.where(np.isinf(X), np.float32(np.nan), X)
    reproducao = R.reproduzir(pcap_da_vazao, classificador)
    return {
        "janelas": len(linhas),
        "latencia_predict_proba": rodadas.latencia(classificador.modelo.predict_proba, X, repeticoes=len(X)),
        "latencia_do_caminho": latencia_do_caminho(classificador, linhas),
        "lote_ms": rodadas.em_lote(classificador.modelo.predict_proba, X, tamanho=LOTE),
        "vazao_do_extrator": rodadas.vazao_do_extrator(pcap_da_vazao),
        "vazao_do_reprodutor": {
            "arquivo": reproducao.arquivo, "quadros": reproducao.quadros, "janelas": reproducao.janelas,
            "segundos": reproducao.segundos,
        },
    }


def maquina():
    """O processador, a memória e o sistema da máquina da medida."""
    dados = {"sistema": platform.platform(), "processador": platform.processor() or platform.machine(), "memoria_bytes": None}
    if sys.platform == "darwin":
        def sysctl(chave):
            return subprocess.run(["sysctl", "-n", chave], capture_output=True, text=True, check=True).stdout.strip()
        dados["processador"], dados["memoria_bytes"] = sysctl("machdep.cpu.brand_string"), int(sysctl("hw.memsize"))
    return dados


def _milhar(numero):
    return f"{round(numero):,}".replace(",", ".")


def _decimal(valor, casas=1):
    return f"{valor:,.{casas}f}".translate(str.maketrans(",.", ".,"))


def _latencia(medida):
    return (f"mediana {_decimal(medida['mediana_ms'], 2)} ms, p95 {_decimal(medida['p95_ms'], 2)} ms, "
            f"p99 {_decimal(medida['p99_ms'], 2)} ms")


def _vazao(medida, chave_dos_quadros):
    quadros, segundos = medida[chave_dos_quadros], medida["segundos"]
    return (f"{_milhar(quadros)} quadros em {_decimal(segundos)} s: {_milhar(quadros / segundos)} quadros/s e "
            f"{_milhar(medida['janelas'] / segundos)} janelas/s")


def relatorio(m):
    """O relatório em markdown, a partir do manifesto."""
    modelo, carga, medidas, maq = m["modelo"], m["carga"], m["medidas"], m["maquina"]
    memoria = f", {_decimal(maq['memoria_bytes'] / 2**30, 0)} GB de memória" if maq["memoria_bytes"] else ""
    linhas = [
        ["Arquivo do modelo", (f"{_decimal(modelo['bytes'] / 1e6)} MB, {_milhar(modelo['nos'])} nós, profundidade média "
                               f"{_decimal(modelo['profundidade_media'])} e máxima {modelo['profundidade_maxima']}")],
        ["Importar o scikit-learn e o joblib, num processo novo", f"{_decimal(carga['importar_s'], 2)} s"],
        ["Ler o modelo", f"{_decimal(carga['carga_s'], 2)} s, com o arquivo no cache do sistema"],
        ["Memória do processo", (f"{_decimal(carga['memoria_antes'] / 1e6, 0)} MB antes de ler o modelo e "
                                 f"{_decimal(carga['memoria_depois'] / 1e6, 0)} MB depois")],
        ["Pico de memória do processo da medida", f"{_decimal(m['pico_de_memoria'] / 1e6, 0)} MB"],
        ["Uma janela, `predict_proba`, um núcleo", _latencia(medidas["latencia_predict_proba"])],
        ["Uma janela, da linha do extrator à probabilidade", _latencia(medidas["latencia_do_caminho"])],
        [f"Lote de {_milhar(LOTE)} janelas", f"{_decimal(medidas['lote_ms'], 1)} ms"],
        [f"Extrator de janela de 100 em `{medidas['vazao_do_extrator']['arquivo']}`",
         _vazao(medidas["vazao_do_extrator"], "pacotes")],
        [f"Reprodutor inteiro em `{medidas['vazao_do_reprodutor']['arquivo']}`",
         _vazao(medidas["vazao_do_reprodutor"], "quadros")],
    ]
    return "\n".join([
        "# Custo do modelo do sistema na operação",
        "",
        f"Gerado por `{m['gerado_por']}` em {m['gerado_em']}, a partir de `{MANIFESTO.name}`.",
        "",
        (f"**O que foi feito.** O modelo do sistema (`{modelo['arquivo']}`) foi medido num núcleo, como o reprodutor o "
         f"usa, com as funções da rodada i de `rodadas_de_teste.md`. A latência é de uma janela isolada, em "
         f"{_milhar(medidas['janelas'])} janelas diferentes do trecho de teste de {len(m['pcaps'])} pcaps, um por "
         "categoria, depois de uma de aquecimento; a segunda linha de latência inclui a montagem da matriz a partir "
         "da linha do extrator. O modelo foi lido num processo novo, três vezes, para medir o tempo e a memória. A "
         "vazão do extrator é a de janela de 100 com os endereços, lendo o pcap inteiro, e a do reprodutor soma a "
         "classificação em lotes e a política de acionamento. "
         f"Máquina: {maq['processador']}{memoria}, {maq['sistema']}. Os tempos mudam de uma execução para outra."),
        "",
        "| Medida | Valor |",
        "|---|---|",
        *(f"| {nome} | {valor} |" for nome, valor in linhas),
        "",
        "Janelas da latência por pcap: " + "; ".join(f"`{p['arquivo']}` {p['janelas']}" for p in m["pcaps"]) + ".",
        "",
    ])


def _sha256(caminho):
    with open(caminho, "rb") as arquivo:
        return hashlib.file_digest(arquivo, "sha256").hexdigest()


def main(argv=None):
    analisador = argparse.ArgumentParser(prog="python -m codigo.reprodutor.custo", description=__doc__)
    analisador.add_argument("--pcaps", type=Path, default=PASTA_DOS_PCAPS, help="pasta com os pcaps do CICIoT2023")
    analisador.add_argument("--modelo", type=Path, default=R.MODELO_PADRAO)
    argumentos = analisador.parse_args(argv)

    classificador = R.Classificador.carregar(argumentos.modelo)
    pcaps, linhas = [], []
    for arquivo in PCAPS_DA_LATENCIA:
        do_pcap = janelas_de_teste(argumentos.pcaps / arquivo)
        pcaps.append({"arquivo": arquivo, "janelas": len(do_pcap)})
        linhas += do_pcap
    if len(linhas) < MINIMO_DE_JANELAS:
        raise SystemExit(f"só {len(linhas)} janelas de teste; a latência pede pelo menos {MINIMO_DE_JANELAS}")
    medidas = medir(classificador, linhas, argumentos.pcaps / rodadas.PCAP_DA_VAZAO)
    manifesto = {
        "gerado_por": "python -m codigo.reprodutor.custo",
        "gerado_em": datetime.datetime.now(tz=datetime.UTC).astimezone().isoformat(timespec="seconds"),
        "versoes": {"python": platform.python_version(), "scikit-learn": sklearn.__version__, "numpy": np.__version__},
        "maquina": maquina(),
        "modelo": {
            "arquivo": argumentos.modelo.name, "sha256": _sha256(argumentos.modelo),
            "bytes": argumentos.modelo.stat().st_size, **rodadas._arvores(classificador.modelo),
        },
        "codigo": {nome: _sha256(Path("codigo") / nome) for nome in (
            "reprodutor/custo.py", "reprodutor/reprodutor.py", "captura/extrator.py", "classificador/rodadas.py",
        )},
        "pcaps": pcaps,
        "carga": rodadas.carga_num_processo_novo(argumentos.modelo),
        "medidas": medidas,
        "pico_de_memoria": rodadas.memoria_pico(),
    }
    MANIFESTO.write_text(json.dumps(manifesto, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    RELATORIO.write_text(relatorio(manifesto), encoding="utf-8")
    print(f"relatório em {RELATORIO}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
