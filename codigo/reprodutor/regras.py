"""Regras de alarme comparadas fora do CICIoT2023: o modelo do sistema, sem retreino, em capturas de outras redes.

Mede o que o sistema faz com tráfego que não é o do dataset de treino, com a regra do sistema e com
outras regras de janela e de janelas seguidas, para a decisão de 28/10/2026 (`ROADMAP.md`):

- uma casa, 90 minutos de IoT real gravados com o Mac como gateway (26/10). Só os números agregados
  saem daqui: o pcap e os endereços da casa ficam fora do repositório;
- o IoT-23 (Stratosphere Laboratory, licença CC-BY): três aparelhos reais sem ataque (Philips Hue,
  Amazon Echo e a fechadura Somfy, esta em seis dias) e malware real em Raspberry Pi;
- o CICIoMT2024 (Canadian Institute for Cybersecurity): um laboratório de IoT médico, com o tráfego
  benigno e 18 ataques do conjunto de teste, entre eles 5 de MQTT, que o CICIoT2023 não tem;
- o trecho de teste dos pcaps do CICIoT2023 (`inicio_do_teste`): o benigno e os 14 ataques que não
  são flood, para comparar com o resto.

Em cada pcap, as janelas são extraídas uma vez e passam pela política de acionamento do reprodutor
com cada regra: o extrator é trocado por um que devolve as janelas guardadas, e a política é
exatamente a do sistema. Nos floods grandes só o começo é lido (`limite`): o alarme deles abre nas
primeiras janelas com qualquer regra comparada. Uma captura sem rótulo por janela é medida por
captura: alarme sim ou não, o atraso até o primeiro e a categoria dele; numa benigna, todo
incidente é falso.

Também mede, no teste publicado do CICIoT2023 (corte por tempo), as métricas por janela de cada
regra de janela; o número de janelas seguidas não muda a classificação da janela.

Uso, a partir da raiz do repositório (pcaps em dados/raw/iot23/, dados/raw/ciciomt2024/ e CICIoT2023/;
o modelo em modelos/):
    python -m codigo.reprodutor.regras
"""

import argparse
import dataclasses
import datetime
import hashlib
import itertools
import json
import platform
import statistics
import sys
import time
from pathlib import Path

import numpy as np

from codigo.classificador.operacao import BENIGNO, SEGUIDAS, TOLERANCIA, PontoDeOperacao
from codigo.reprodutor import reprodutor as R

RELATORIO = Path("experimentos") / "resultados" / "testes_fora_do_ciciot2023.md"
MANIFESTO = Path("experimentos") / "resultados" / "manifesto_testes_fora_do_ciciot2023.json"
TRABALHO = Path("dados") / "processed" / "regras"
LIMITE_DOS_FLOODS = 300_000
LIMITE_DO_MALWARE_GRANDE = 2_000_000


@dataclasses.dataclass(frozen=True)
class PontoPorCategoria:
    """O argmax, mas a janela das categorias em `limiares` só é ataque se 1 − P(Benign) chega ao limiar dela."""

    limiares: tuple  # ((categoria, limiar), ...)
    seguidas: int = SEGUIDAS
    benigno: str = BENIGNO
    limiar: None = None

    @property
    def regra(self):
        return "por_categoria"

    def categoria(self, probabilidades, classes):
        p = np.asarray(probabilidades, dtype=float)
        classes = list(classes)
        escolhida = classes[int(p.argmax())]
        limites = dict(self.limiares)
        if escolhida == self.benigno or escolhida not in limites:
            return escolhida
        return escolhida if 1.0 - p[classes.index(self.benigno)] >= limites[escolhida] - TOLERANCIA else self.benigno

    def categorias(self, probabilidades, classes):
        return np.array([self.categoria(linha, classes) for linha in np.atleast_2d(probabilidades)], dtype=object)


def regras():
    """As regras comparadas, com a do sistema primeiro: (nome, ponto)."""
    lista = [(f"sistema: argmax e {SEGUIDAS} seguidas", PontoDeOperacao(None, SEGUIDAS))]
    for seguidas in (3, 4, 5):
        if seguidas != SEGUIDAS:
            lista.append((f"argmax e {seguidas} seguidas", PontoDeOperacao(None, seguidas)))
    lista += [(f"limiar de {_n(t, 2)} e 3 seguidas", PontoDeOperacao(t, 3)) for t in (0.60, 0.65, 0.70, 0.75, 0.80)]
    lista += [
        ("limiar de 0,65 e 4 seguidas", PontoDeOperacao(0.65, 4)),
        ("limiar de 0,70 e 4 seguidas", PontoDeOperacao(0.70, 4)),
        ("Spoofing com 0,80, demais argmax e 3 seguidas", PontoPorCategoria((("Spoofing", 0.80),), 3)),
        ("Spoofing e DDoS+DoS com 0,80, demais argmax e 3 seguidas",
         PontoPorCategoria((("Spoofing", 0.80), ("DDoS+DoS", 0.80)), 3)),
    ]
    return lista


FAMILIA_DO_CICIOT2023 = {
    "DNS_Spoofing": "Spoofing", "MITM-ArpSpoofing": "Spoofing", "Recon-PortScan": "Recon", "Recon-OSScan": "Recon",
    "Recon-HostDiscovery": "Recon", "Recon-PingSweep": "Recon", "VulnerabilityScan": "Recon",
    "DictionaryBruteForce": "BruteForce", "SqlInjection": "Web", "XSS": "Web", "CommandInjection": "Web",
    "BrowserHijacking": "Web", "Backdoor_Malware": "Web", "Uploading_Attack": "Web",
}
_CICIOMT = "dados/raw/ciciomt2024"
_IOT23 = "dados/raw/iot23"


@dataclasses.dataclass(frozen=True)
class Captura:
    grupo: str
    caminho: str
    benigna: bool
    familia: str | None = None  # a categoria do modelo que o ataque deveria ter, quando há uma
    limite: int | None = None  # quadros lidos, nos floods grandes


CAPTURAS = (
    Captura("Casa", "dados/iot_normal_90min.pcap", True),
    *(Captura("CICIoT2023 benigno (teste)", f"CICIoT2023/{n}.pcap", True)
      for n in ("BenignTraffic", "BenignTraffic1", "BenignTraffic2")),
    *(Captura("IoT-23 benigno", f"{_IOT23}/benigno/{n}.pcap", True)
      for n in ("hue_4-1", "echo_5-1", *(f"somfy_7-1_0{i}" for i in range(1, 7)))),
    Captura("CICIoMT2024 benigno", f"{_CICIOMT}/Benign_test.pcap", True),
    *(Captura("CICIoT2023 ataque (teste)", f"CICIoT2023/{n}.pcap", False, f) for n, f in FAMILIA_DO_CICIOT2023.items()),
    *(Captura("CICIoMT2024 ataque", f"{_CICIOMT}/{n}_test.pcap", False, f, lim) for n, f, lim in (
        ("ARP_Spoofing", "Spoofing", None), ("Recon-OS_Scan", "Recon", None), ("Recon-Ping_Sweep", "Recon", None),
        ("Recon-Port_Scan", "Recon", None), ("Recon-VulScan", "Recon", None), ("MQTT-Malformed_Data", None, None),
        *((n, "DDoS+DoS", LIMITE_DOS_FLOODS) for n in (
            "MQTT-DDoS-Connect_Flood", "MQTT-DDoS-Publish_Flood", "MQTT-DoS-Connect_Flood", "MQTT-DoS-Publish_Flood",
            "TCP_IP-DoS-SYN", "TCP_IP-DoS-TCP", "TCP_IP-DoS-UDP", "TCP_IP-DoS-ICMP",
            "TCP_IP-DDoS-SYN", "TCP_IP-DDoS-TCP", "TCP_IP-DDoS-UDP1", "TCP_IP-DDoS-ICMP1")))),
    *(Captura("IoT-23 malware ativo", f"{_IOT23}/malware/malware_{n}.pcap", False, None, lim) for n, lim in (
        ("34-1", None), ("42-1", None), ("3-1", None), ("9-1", None), ("1-1", LIMITE_DO_MALWARE_GRANDE),
        ("7-1", LIMITE_DO_MALWARE_GRANDE), ("36-1", LIMITE_DO_MALWARE_GRANDE), ("48-1", LIMITE_DO_MALWARE_GRANDE))),
    *(Captura("IoT-23 malware silencioso", f"{_IOT23}/malware/malware_{n}.pcap", False) for n in ("20-1", "21-1", "8-1")),
)
GRUPOS_BENIGNOS = ("Casa", "CICIoT2023 benigno (teste)", "CICIoMT2024 benigno", "IoT-23 benigno")
GRUPOS_DE_ATAQUE = ("CICIoT2023 ataque (teste)", "CICIoMT2024 ataque", "IoT-23 malware ativo")


# --- a reprodução com as janelas guardadas -------------------------------------------------------


def extrair(caminho, limite=None):
    """As saídas do extrator do reprodutor para o pcap, na ordem, até `limite` quadros."""
    extrator = R._ExtratorComContagens(R.JANELA)
    quadros = R._quadros(caminho)
    if limite:
        quadros = itertools.islice(quadros, limite)
    return [saida for saida in (extrator.alimentar(ts, quadro) for ts, quadro in quadros) if saida is not None]


class _Repetidor:
    """Faz o papel do extrator: a cada quadro de mentira, devolve a próxima janela guardada."""

    saidas = ()

    def __init__(self, _janela):
        self._fila = iter(type(self).saidas)
        self.ignorados = 0

    def alimentar(self, _ts, _quadro):
        return next(self._fila, None)

    def finalizar(self):
        return None


def reproduzir_guardado(caminho, saidas, classificador, a_partir_da_janela=0):
    """O `reproduzir` do sistema sobre janelas já extraídas: a mesma política, sem ler o pcap de novo."""
    extrator, quadros = R._ExtratorComContagens, R._quadros
    _Repetidor.saidas = saidas
    R._ExtratorComContagens = _Repetidor
    R._quadros = lambda _origem: ((0.0, b"") for _ in range(len(saidas)))
    try:
        return R.reproduzir(caminho, classificador, a_partir_da_janela=a_partir_da_janela)
    finally:
        R._ExtratorComContagens, R._quadros = extrator, quadros


def medir(captura, reproducao, regra):
    """O que uma reprodução diz sobre uma captura, numa linha."""
    incidentes = reproducao.incidentes
    primeiro = min(incidentes, key=lambda i: i.aberto_em) if incidentes else None
    horas = (reproducao.fim - reproducao.inicio) / 3600 if reproducao.inicio is not None else 0.0
    return {
        "grupo": captura.grupo, "pcap": Path(captura.caminho).name, "benigna": captura.benigna,
        "familia": captura.familia, "limite": captura.limite, "regra": regra, "horas": round(horas, 3),
        "janelas": reproducao.janelas - reproducao.puladas, "julgadas": sum(reproducao.por_categoria.values()),
        "nao_julgadas": sum(reproducao.nao_julgadas.values()),
        "como_ataque": sum(v for k, v in reproducao.por_categoria.items() if k != BENIGNO),
        "incidentes": len(incidentes) + reproducao.alem_do_teto,
        "primeiro_alarme_s": None if primeiro is None else round(primeiro.aberto_em - reproducao.inicio, 1),
        "categoria_do_primeiro": None if primeiro is None else primeiro.categoria_principal(),
    }


def avaliar_capturas(classificador, capturas=CAPTURAS, ao_medir=None):
    """Cada captura presente, com cada regra. Pula o pcap que falta e o do CICIoT2023 sem trecho de teste."""
    lista = [(nome, dataclasses.replace(classificador, ponto=ponto)) for nome, ponto in regras()]
    linhas, presentes = [], []
    for captura in capturas:
        if not Path(captura.caminho).exists():
            continue
        a_partir = 0
        if captura.caminho.startswith("CICIoT2023/"):
            a_partir = R.inicio_do_teste(captura.caminho)
            if a_partir is None:
                continue
        saidas = extrair(captura.caminho, captura.limite)
        # As janelas antes do trecho de teste só contam a posição: o reprodutor as pula sem ler.
        saidas[:a_partir] = [(None, None, 0.0, 0.0, 0)] * min(a_partir, len(saidas))
        presentes.append(captura)
        for nome, cl in lista:
            linha = medir(captura, reproduzir_guardado(captura.caminho, saidas, cl, a_partir), nome)
            linhas.append(linha)
            if ao_medir is not None:
                ao_medir(linha)
    return linhas, presentes


# --- as contas -------------------------------------------------------------------------------------


def resumir(linhas):
    """Por regra: os incidentes falsos por grupo benigno e as capturas de ataque com alarme por grupo."""
    saida = {}
    for regra in dict.fromkeys(linha["regra"] for linha in linhas):
        da_regra = [linha for linha in linhas if linha["regra"] == regra]
        grupo = {}
        for nome in dict.fromkeys(linha["grupo"] for linha in da_regra):
            do_grupo = [linha for linha in da_regra if linha["grupo"] == nome]
            atrasos = [linha["primeiro_alarme_s"] for linha in do_grupo if linha["primeiro_alarme_s"] is not None]
            com_familia = [linha for linha in do_grupo if linha["familia"] and linha["incidentes"]]
            grupo[nome] = {
                "capturas": len(do_grupo), "horas": sum(linha["horas"] for linha in do_grupo),
                "incidentes": sum(linha["incidentes"] for linha in do_grupo),
                "com_alarme": sum(1 for linha in do_grupo if linha["incidentes"]),
                "julgadas": sum(linha["julgadas"] for linha in do_grupo),
                "como_ataque": sum(linha["como_ataque"] for linha in do_grupo),
                "atraso_mediano_s": statistics.median(atrasos) if atrasos else None,
                "categoria_certa": sum(1 for linha in com_familia if linha["categoria_do_primeiro"] == linha["familia"]),
                "com_familia": sum(1 for linha in do_grupo if linha["familia"]),
            }
        saida[regra] = {
            "grupos": grupo,
            "falsos": sum(grupo[g]["incidentes"] for g in GRUPOS_BENIGNOS if g in grupo),
            "horas_benignas": sum(grupo[g]["horas"] for g in GRUPOS_BENIGNOS if g in grupo),
            "detectadas": sum(grupo[g]["com_alarme"] for g in GRUPOS_DE_ATAQUE if g in grupo),
            "de_ataque": sum(grupo[g]["capturas"] for g in GRUPOS_DE_ATAQUE if g in grupo),
        }
    return saida


def metricas_por_janela(destino="dados/processed/regerado", modelo=R.MODELO_PADRAO):
    """As métricas por janela de cada regra de janela no teste publicado do CICIoT2023."""
    from codigo.classificador import treinar_regerado as t

    regeracao = json.loads(R.MANIFESTO_DA_REGERACAO.read_text(encoding="utf-8"))
    amostra, _ = t.ler_janela(destino, R.JANELA, t.TETO, t.SEMENTE)
    totais = {p["arquivo"]: p["janelas"][str(R.JANELA)]["extraidas"] for p in regeracao["pcaps"]}
    _, teste = t.dividir_por_tempo(amostra, t.FRACAO_DE_TESTE_POR_TEMPO, totais)
    X = t.matriz(amostra, t.FEATURES_39)[teste]
    real = t.alvo(amostra["Label"].to_numpy(), t.ALVO)[teste]
    classificador = R.Classificador.carregar(modelo)
    proba = t.probabilidades(classificador.modelo, X)
    classes = list(classificador.modelo.classes_)
    vistas, saida = set(), {}
    for nome, ponto in regras():
        chave = (type(ponto).__name__, getattr(ponto, "limiar", None), getattr(ponto, "limiares", None))
        if chave in vistas:
            continue  # só muda o número de janelas seguidas: a mesma classificação por janela
        vistas.add(chave)
        previsto = ponto.categorias(proba, classes)
        f1 = []
        for k in classes:
            vp = int(((previsto == k) & (real == k)).sum())
            erros = int(((previsto == k) & (real != k)).sum() + ((previsto != k) & (real == k)).sum())
            f1.append(2 * vp / (2 * vp + erros) if vp + erros else 0.0)
        benigno = real == BENIGNO
        # A linha leva o nome da regra de janela, sem o número de janelas seguidas.
        saida[nome.removeprefix("sistema: ").rsplit(" e ", 1)[0]] = {
            "benigno_como_ataque": float((previsto[benigno] != BENIGNO).mean()),
            "ataque_como_benigno": float((previsto[~benigno] == BENIGNO).mean()),
            "macro_f1": float(np.mean(f1)),
            "recall": {k: float((previsto[real == k] == k).mean()) for k in classes},
        }
    return saida


# --- o relatório ---------------------------------------------------------------------------------


def _n(valor, casas=1):
    return "—" if valor is None else f"{valor:.{casas}f}".replace(".", ",")


def _pct(parte, todo):
    return "—" if not todo else _n(100 * parte / todo) + "%"


def _inteiro(valor):
    return f"{valor:,}".replace(",", ".")


def _data(iso):
    return datetime.datetime.fromisoformat(iso).strftime("%d/%m/%Y")


def relatorio(linhas, resumo, por_janela, manifesto):
    sistema = next(iter(resumo))
    do_sistema = [linha for linha in linhas if linha["regra"] == sistema]
    partes = [
        "# O modelo do sistema fora do CICIoT2023, e as regras de alarme comparadas",
        "",
        (f"Gerado por `python -m codigo.reprodutor.regras` em {_data(manifesto['gerado_em'])}, com Python "
        f"{manifesto['versoes']['python']} e scikit-learn {manifesto['versoes']['scikit-learn']}. O modelo é o de "
        "13/10 (`modelos/rf_regerado_janela_100.joblib`), sem retreino. A descrição das capturas e do método está "
        "no topo de `codigo/reprodutor/regras.py`; os pcaps, com tamanho e SHA-256, no manifesto ao lado."),
        "",
        ("Como ler: numa captura benigna, todo incidente é falso. Numa de ataque, sem rótulo por janela, conta "
        "se o sistema abriu incidente, em quanto tempo e em que categoria. Janela que leva mais de "
        f"{_n(R.DURACAO_MAXIMA_S, 0)} s para fechar não é julgada (`DURACAO_MAXIMA_S`). Nos floods grandes, "
        "só o começo foi lido. A casa entra só com números agregados."),
        "",
        f"## A regra do sistema ({sistema}), captura por captura",
        "",
        "| Grupo | Captura | Horas | Janelas | Não julgadas | Ataque nas julgadas | Incidentes | Categoria do 1º | 1º alarme (s) |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for linha in do_sistema:
        nome = "casa (IoT de uma residência)" if linha["grupo"] == "Casa" else linha["pcap"].removesuffix(".pcap")
        partes.append(
            f"| {linha['grupo']} | {nome} | {_n(linha['horas'])} | {_inteiro(linha['janelas'])} | "
            f"{_inteiro(linha['nao_julgadas'])} | "
            f"{_pct(linha['como_ataque'], linha['julgadas'])} | {linha['incidentes']} | "
            f"{linha['categoria_do_primeiro'] or '—'} | {_n(linha['primeiro_alarme_s'])} |"
        )
    cabeca = "| Regra | " + " | ".join(f"{g} ({_n(resumo[sistema]['grupos'][g]['horas'])} h)" for g in GRUPOS_BENIGNOS
                                         if g in resumo[sistema]["grupos"])
    partes += [
        "",
        "## As regras comparadas",
        "",
        ("Incidentes falsos por grupo benigno e no total; capturas de ataque com alarme. O malware silencioso do "
        "IoT-23 fica fora do total: nenhuma regra julga as janelas dele."),
        "",
        cabeca + " | Falsos no total | " + " | ".join(GRUPOS_DE_ATAQUE) + " | Com alarme | Categoria certa no "
        "CICIoT2023 | Atraso mediano, CICIoT2023 / IoT-23 (s) |",
        "|" + "---|" * (2 + len(GRUPOS_BENIGNOS) + len(GRUPOS_DE_ATAQUE) + 3),
    ]
    for regra, r in resumo.items():
        g = r["grupos"]
        c23 = g.get("CICIoT2023 ataque (teste)", {})
        iot = g.get("IoT-23 malware ativo", {})
        partes.append(
            f"| {regra} | " + " | ".join(str(g[n]["incidentes"]) for n in GRUPOS_BENIGNOS if n in g)
            + f" | {r['falsos']} | " + " | ".join(f"{g[n]['com_alarme']}/{g[n]['capturas']}" for n in GRUPOS_DE_ATAQUE if n in g)
            + f" | {r['detectadas']}/{r['de_ataque']} | {c23.get('categoria_certa', '—')}/{c23.get('com_familia', '—')} | "
            f"{_n(c23.get('atraso_mediano_s'))} / {_n(iot.get('atraso_mediano_s'))} |"
        )
    if por_janela:
        partes += [
            "",
            "## Por janela, no teste publicado do CICIoT2023",
            "",
            ("O número de janelas seguidas não muda a classificação de cada janela: as regras que só diferem nele "
            "têm a mesma linha."),
            "",
            ("| Regra de janela | Benigno como ataque | Ataque como benigno | Macro-F1 | Recall Spoofing | Recall Recon | "
            "Recall Web | Recall BruteForce |"),
            "|---|---|---|---|---|---|---|---|",
        ]
        for regra, m in por_janela.items():
            rec = m["recall"]
            partes.append(
                f"| {regra} | {_n(100 * m['benigno_como_ataque'], 2)}% | {_n(100 * m['ataque_como_benigno'], 2)}% | "
                f"{_n(100 * m['macro_f1'])}% | {_n(100 * rec['Spoofing'])}% | {_n(100 * rec['Recon'])}% | "
                f"{_n(100 * rec['Web'])}% | {_n(100 * rec['BruteForce'])}% |"
            )
    partes += ["", "## Reproduzir", "", "- Comando: `python -m codigo.reprodutor.regras`, a partir da raiz do repositório.",
               f"- Duração desta execução: {_n(manifesto['duracao_segundos'] / 60)} min.", ""]
    return "\n".join(partes)


def _sha256(caminho):
    with open(caminho, "rb") as arquivo:
        return hashlib.file_digest(arquivo, "sha256").hexdigest()


def main(argv=None):
    analisador = argparse.ArgumentParser(prog="python -m codigo.reprodutor.regras", description=__doc__)
    analisador.add_argument("--modelo", default=str(R.MODELO_PADRAO), help="modelo do sistema")
    analisador.add_argument("--sem-janela", action="store_true", help="não mede as métricas por janela do CICIoT2023")
    analisador.add_argument("--trabalho", default=str(TRABALHO), help="onde gravar as linhas brutas")
    argumentos = analisador.parse_args(argv)
    inicio = time.perf_counter()
    classificador = R.Classificador.carregar(argumentos.modelo)
    Path(argumentos.trabalho).mkdir(parents=True, exist_ok=True)
    with open(Path(argumentos.trabalho) / "linhas.jsonl", "w", encoding="utf-8") as bruto:
        def gravar(linha):
            bruto.write(json.dumps(linha, ensure_ascii=False) + "\n")
            bruto.flush()
        linhas, presentes = avaliar_capturas(classificador, ao_medir=gravar)
    por_janela = {} if argumentos.sem_janela else metricas_por_janela(modelo=argumentos.modelo)
    import sklearn

    manifesto = {
        "gerado_por": "python -m codigo.reprodutor.regras",
        "gerado_em": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "modelo": Path(argumentos.modelo).name, "modelo_sha256": _sha256(argumentos.modelo),
        "seguidas_do_sistema": SEGUIDAS, "duracao_maxima_s": R.DURACAO_MAXIMA_S,
        "regras": [nome for nome, _ in regras()],
        "pcaps": [{"grupo": c.grupo, "arquivo": Path(c.caminho).name, "bytes": Path(c.caminho).stat().st_size,
                   "sha256": _sha256(c.caminho), "limite_de_quadros": c.limite} for c in presentes],
        "versoes": {"python": platform.python_version(), "scikit-learn": sklearn.__version__,
                    "numpy": np.__version__},
        "duracao_segundos": time.perf_counter() - inicio,
    }
    resumo = resumir(linhas)
    MANIFESTO.write_text(json.dumps({**manifesto, "resumo": resumo, "por_janela": por_janela}, ensure_ascii=False,
                                    indent=1) + "\n", encoding="utf-8")
    RELATORIO.write_text(relatorio(linhas, resumo, por_janela, manifesto), encoding="utf-8")
    print(f"relatório em {RELATORIO}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
