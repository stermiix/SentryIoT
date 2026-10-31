"""Avalia o reprodutor nos pcaps do CICIoT2023 contra a verdade de campo: os MACs dos atacantes.

Para cada pcap, roda o reprodutor inteiro (extrator, classificador do sistema e política de
acionamento) e confere cada incidente com o que se sabe do pcap:
- quantas janelas do incidente têm algum quadro de um dos sete atacantes do dataset
  (`codigo/classificador/atacantes.py`), e quantas ficam no trecho fora do treino do modelo;
- se a primeira origem listada é um IP usado por um atacante, e se o primeiro destino não é;
- num pcap de DDoS ou de DoS, se a regra das origens deu a categoria do arquivo;
- o tempo até a detecção pela primeira janela da sequência e pelo começo real do ataque: a
  primeira janela com atacante da corrida que antecede o incidente, sem pausa no meio.

Nos pcaps benignos, todo incidente é um alarme falso, contado por hora de captura.

A verdade de campo serve só a esta avaliação: o sistema não conhece os MACs dos atacantes.

Uso, a partir da raiz do repositório (os pcaps em CICIoT2023/, o modelo em modelos/):
    python -m codigo.reprodutor.avaliar --processos 3
    python -m codigo.reprodutor.avaliar --so-relatorio     # refaz o relatório com os resultados já gravados
"""

import argparse
import datetime
import hashlib
import json
import platform
import statistics
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from codigo.classificador.atacantes import ATACANTES
from codigo.classificador.operacao import SEGUIDAS
from codigo.reprodutor import reprodutor as R

PASTA_DOS_PCAPS = Path("CICIoT2023")
MANIFESTO = R.MANIFESTO_DA_REGERACAO
PASTA_DOS_RESULTADOS = Path("dados") / "processed" / "reproducao"
RELATORIO = Path("experimentos") / "resultados" / "reproducao_dos_pcaps.md"
MANIFESTO_DO_RELATORIO = Path("experimentos") / "resultados" / "manifesto_reproducao_dos_pcaps.json"


class _ComVerdade(R._ExtratorComContagens):
    """O extrator do reprodutor, que anota em cada janela os quadros dos atacantes e os IPs deles."""

    verdade = None

    def _fechar(self):
        quadros, ips = 0, set()
        for medida in self._pendentes:
            if medida["mac_origem"] in ATACANTES or medida["mac_destino"] in ATACANTES:
                quadros += 1
            if medida["mac_origem"] in ATACANTES:
                ip = medida["ip_origem"] or medida["ip_arp"]
                if ip:
                    ips.add(R._ip(ip))
        type(self).verdade.append((quadros, ips, self._pendentes[0]["ts"]))
        return super()._fechar()


def avaliar_pcap(caminho, classificador, manifesto=MANIFESTO):
    """O resultado de um pcap, num dicionário pronto para gravar em JSON."""
    caminho = Path(caminho)
    registro = next(p for p in json.loads(Path(manifesto).read_text(encoding="utf-8"))["pcaps"] if p["arquivo"] == caminho.name)
    _ComVerdade.verdade = verdade = []
    original = R._ExtratorComContagens
    R._ExtratorComContagens = _ComVerdade
    inicio = time.perf_counter()
    try:
        reproducao = R.reproduzir(caminho, classificador)
    finally:
        R._ExtratorComContagens = original
    cenarios = R.cenarios_da_reproducao(reproducao, classificador)
    corte = R.inicio_do_teste(caminho.name, manifesto)
    ips_atacantes = set().union(*(v[1] for v in verdade)) if verdade else set()
    incidentes = []
    for cenario, incidente in zip(cenarios, reproducao.incidentes, strict=True):
        dados = cenario.incidente
        indices = [j.indice for j in incidente.ataque]
        primeira = incidente.ataque[0].indice
        while primeira > 0 and verdade[primeira - 1][0] > 0 and verdade[primeira][2] - verdade[primeira - 1][2] < R.SILENCIO_S:
            primeira -= 1
        incidentes.append({
            "id": dados.id, "categoria": dados.categoria, "categoria_do_modelo": dados.categoria_do_modelo,
            "janelas": dados.janelas, "confianca": dados.confianca, "distribuido": dados.distribuido,
            "origens_distintas": dados.origens_distintas,
            "origem_1_e_atacante": bool(dados.origens) and dados.origens[0].endereco in ips_atacantes,
            "destino_1_e_atacante": bool(dados.destinos) and dados.destinos[0].endereco in ips_atacantes,
            "janelas_com_atacante": sum(1 for i in indices if verdade[i][0] > 0),
            "janelas_no_teste": sum(1 for i in indices if corte is not None and i >= corte),
            "atraso_s": round(incidente.aberto_em - incidente.primeira_janela_de_ataque, 3),
            "atraso_desde_o_atacante_s": round(incidente.aberto_em - verdade[primeira][2], 3),
            "reaberturas": incidente.reaberturas,
        })
    return {
        "arquivo": caminho.name, "rotulo": registro["rotulo"], "categoria": registro["categoria"],
        "benigno": registro["benigno"], "corte": corte, "quadros": reproducao.quadros, "janelas": reproducao.janelas,
        "por_categoria": dict(reproducao.por_categoria), "nao_julgadas": dict(reproducao.nao_julgadas),
        "janelas_com_atacante": sum(1 for v in verdade if v[0] > 0),
        "duracao_s": round((reproducao.fim - reproducao.inicio) if reproducao.inicio is not None else 0.0, 1),
        "incidentes": incidentes, "alem_do_teto": reproducao.alem_do_teto,
        "processamento_s": round(time.perf_counter() - inicio, 1),
    }


_CLASSIFICADOR = {}


def _avaliar_e_gravar(argumentos):
    caminho, modelo, destino = argumentos
    # Um modelo carregado por processo, e não por pcap.
    if modelo not in _CLASSIFICADOR:
        _CLASSIFICADOR[modelo] = R.Classificador.carregar(modelo)
    try:
        resultado = avaliar_pcap(caminho, _CLASSIFICADOR[modelo])
    except Exception as erro:  # noqa: BLE001  (um pcap que falha não derruba os outros: vai para o relatório)
        resultado = {"arquivo": Path(caminho).name, "erro": f"{type(erro).__name__}: {erro}", "incidentes": [], "processamento_s": 0.0}
    Path(destino).write_text(json.dumps(resultado, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return resultado["arquivo"], len(resultado["incidentes"]), resultado["processamento_s"]


def _pct(parte, todo):
    return f"{100 * parte / todo:.1f}%".replace(".", ",") if todo else "—"


def _num(valor, casas=1):
    return f"{valor:,.{casas}f}".replace(",", "X").replace(".", ",").replace("X", ".")


def relatorio(resultados, artefato=None):
    """O relatório em Markdown, a partir dos resultados de cada pcap e, se houver, da medida do artefato."""
    ataque = [r for r in resultados if not r["benigno"]]
    benignos = [r for r in resultados if r["benigno"]]
    linhas = [
        "# Reprodução dos pcaps: incidentes contra a verdade de campo",
        "",
        f"Gerado por `python -m codigo.reprodutor.avaliar` em {datetime.datetime.now(tz=datetime.UTC).astimezone():%d/%m/%Y}.",
        "",
        "Cada pcap do CICIoT2023 usado na regeração passou inteiro pelo reprodutor de tráfego: extrator em",
        "janela de 100 quadros, modelo do sistema com o ponto de operação e a primeira versão da política de",
        "acionamento (`codigo/reprodutor/reprodutor.py`, parâmetros padrão). Os incidentes foram conferidos",
        "com os quadros dos sete atacantes do dataset, identificados pelo MAC. A verdade de campo é só da",
        "avaliação: o sistema não a conhece.",
        "",
        "Os pcaps de ataque tiveram o começo no treino do modelo (70% das janelas, ou o arquivo inteiro nos",
        "rótulos com vários pcaps); a coluna \"no teste\" conta as janelas dos incidentes que ficaram fora do",
        "treino. `DDoS-SYN_Flood1.pcap`, `DoS-SYN_Flood1.pcap` e `BenignTraffic2.pcap` ficaram inteiros fora.",
        "",
        "## Pcaps de ataque",
        "",
        "| Pcap | Categoria | Janelas | Incidentes | Janelas dos incidentes com atacante | No teste | Origem 1 é atacante | Destino 1 é atacante | Categoria certa | Atraso mediano (s) | Desde o atacante (s) |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in sorted(ataque, key=lambda r: (r["categoria"], r["arquivo"])):
        inc = r["incidentes"]
        janelas = sum(i["janelas"] for i in inc)
        certa = [i for i in inc if _categoria_certa(r, i)]
        linhas.append(
            f"| `{r['arquivo']}` | {r['categoria']} | {_num(r['janelas'], 0)} | {len(inc)}"
            f"{' (+' + str(r['alem_do_teto']) + ')' if r['alem_do_teto'] else ''} | "
            f"{_pct(sum(i['janelas_com_atacante'] for i in inc), janelas)} | {_num(sum(i['janelas_no_teste'] for i in inc), 0)} | "
            f"{sum(i['origem_1_e_atacante'] for i in inc)}/{len(inc)} | {sum(i['destino_1_e_atacante'] for i in inc)}/{len(inc)} | "
            f"{len(certa)}/{len(inc)} | "
            f"{_num(statistics.median([i['atraso_s'] for i in inc]), 2) if inc else '—'} | "
            f"{_num(statistics.median([i['atraso_desde_o_atacante_s'] for i in inc]), 2) if inc else '—'} |"
        )
    todos = [i for r in ataque for i in r["incidentes"]]
    flood = [(r, i) for r in ataque for i in r["incidentes"] if r["categoria"] in ("DDoS", "DoS") and i["categoria_do_modelo"] == "DDoS+DoS"]
    linhas += [
        "",
        "Entre parênteses, as sequências de ataque que abririam incidente depois do teto de 20 por pcap: uma",
        "rajada que reabriria um desses incidentes conta de novo, então o número é um teto, e não uma contagem",
        "de incidentes (sem teto, o `DNS_Spoofing.pcap` dá 51 incidentes em 28 horas). \"Categoria certa\"",
        "compara a categoria do incidente com a do pcap; nos pcaps de DDoS e DoS, é a regra das origens que",
        "separa as duas.",
        "",
        "Somando os pcaps de ataque:",
        "",
        f"- {len(todos)} incidentes; {_pct(sum(i['janelas_com_atacante'] for i in todos), sum(i['janelas'] for i in todos))} das janelas deles têm algum quadro de atacante.",
        f"- A primeira origem listada é um IP de atacante em {sum(i['origem_1_e_atacante'] for i in todos)} de {len(todos)} incidentes; o primeiro destino é um IP de atacante em {sum(i['destino_1_e_atacante'] for i in todos)}.",
        f"- Nos pcaps de DDoS e DoS, a regra das origens deu a categoria do arquivo em {sum(_categoria_certa(r, i) for r, i in flood)} de {len(flood)} incidentes da classe DDoS+DoS.",
        "",
        "## Pcaps benignos: alarmes falsos",
        "",
        "| Pcap | Janelas | Horas de captura | Incidentes | Por hora | Categorias |",
        "|---|---|---|---|---|---|",
    ]
    for r in benignos:
        horas = r["duracao_s"] / 3600
        categorias = ", ".join(f"{c} {n}" for c, n in _contar(i["categoria"] for i in r["incidentes"]))
        linhas.append(
            f"| `{r['arquivo']}` | {_num(r['janelas'], 0)} | {_num(horas)} | {len(r['incidentes'])} | "
            f"{_num(len(r['incidentes']) / horas, 2) if horas else '—'} | {categorias or '—'} |"
        )
    linhas += [
        "",
        "Só o `BenignTraffic2.pcap` ficou fora do treino; os outros dois foram treino no modelo do sistema, e",
        "o alarme deles é dentro da amostra.",
        "",
    ]
    if artefato:
        horas = next((r["duracao_s"] / 3600 for r in benignos if r["arquivo"] == PCAP_DO_ARTEFATO), None)
        linhas += [
            "## O artefato de captura numa implantação",
            "",
            f"O modelo do sistema aplicado às janelas do `{PCAP_DO_ARTEFATO}`, que ficou fora do treino, com os tamanhos",
            "de quadro como o dataset gravou e como passariam no fio, num enlace Ethernet sem agregação de",
            "segmentos (`rodadas_de_teste.md`, rodada f). Janela de ataque pela regra do ponto de operação; alarme",
            f"com {SEGUIDAS} janelas de ataque seguidas.",
            "",
            "| Tamanhos de quadro | Janelas | Como ataque | Alarmes | Por hora |",
            "|---|---|---|---|---|",
        ]
        for nome, medida in artefato.items():
            por_hora = _num(medida["alarmes"] / horas, 2) if horas else "—"
            linhas.append(
                f"| {nome} | {_num(medida['janelas'], 0)} | {_pct(medida['como_ataque'], medida['janelas'])} | {medida['alarmes']} | {por_hora} |"
            )
        linhas.append("")
    linhas += [
        "## Como os números foram obtidos",
        "",
        "- Comando: `python -m codigo.reprodutor.avaliar`, a partir da raiz do repositório.",
        "- Os resultados de cada pcap ficam em `dados/processed/reproducao/` (fora do git); o manifesto ao",
        "  lado deste relatório traz os SHA-256 do modelo, do ponto de operação e do código.",
        f"- Tempo somado de processamento: {_num(sum(r['processamento_s'] for r in resultados) / 60)} min.",
    ]
    return "\n".join(linhas) + "\n"


PASTAS_DO_ARTEFATO = {
    "como gravado": Path("dados") / "processed" / "regerado" / "janela_100",
    "como no fio (preenchido até 60 e limitado a 1.514 bytes)": Path("dados") / "processed" / "regerado_preenchido_limitado" / "janela_100",
}
PCAP_DO_ARTEFATO = "BenignTraffic2.pcap"


def alarme_do_artefato(classificador, pastas=PASTAS_DO_ARTEFATO, pcap=PCAP_DO_ARTEFATO):
    """O alarme falso do modelo do sistema no pcap benigno fora do treino, com os tamanhos de quadro
    como foram gravados e como passariam no fio. Mede o descompasso de uma implantação que capture
    os quadros como o fio, se o modelo foi treinado no dado como o dataset gravou."""
    import pandas as pd

    from codigo.classificador.preparar import matriz

    saida = {}
    for nome, pasta in pastas.items():
        arquivo = Path(pasta) / "BenignTraffic.csv.gz"
        if not arquivo.exists():
            continue
        quadro = pd.read_csv(arquivo)
        quadro = quadro[quadro["arquivo"] == pcap]
        probabilidades = classificador.modelo.predict_proba(matriz(quadro, classificador.features))
        ataque = [classificador.ponto.categoria(p, classificador.classes) != classificador.ponto.benigno for p in probabilidades]
        seguidas = alarmes = 0
        for e_ataque in ataque:
            seguidas = seguidas + 1 if e_ataque else 0
            alarmes += seguidas == classificador.ponto.seguidas
        saida[nome] = {"janelas": len(ataque), "como_ataque": sum(ataque), "alarmes": alarmes}
    return saida


def _categoria_certa(resultado, incidente):
    return incidente["categoria"] == resultado["categoria"]


def _contar(valores):
    contagem = {}
    for valor in valores:
        contagem[valor] = contagem.get(valor, 0) + 1
    return sorted(contagem.items(), key=lambda item: -item[1])


def _sha256(caminho):
    with open(caminho, "rb") as arquivo:
        return hashlib.file_digest(arquivo, "sha256").hexdigest()


def main(argv=None):
    analisador = argparse.ArgumentParser(prog="python -m codigo.reprodutor.avaliar", description=__doc__)
    analisador.add_argument("--pcaps", type=Path, default=PASTA_DOS_PCAPS, help="pasta com os pcaps do CICIoT2023")
    analisador.add_argument("--modelo", type=Path, default=R.MODELO_PADRAO)
    analisador.add_argument("--processos", type=int, default=1, help="pcaps avaliados ao mesmo tempo")
    analisador.add_argument("--so-relatorio", action="store_true", help="refaz o relatório com os resultados já gravados")
    analisador.add_argument("--retomar", action="store_true", help="pula os pcaps que já têm resultado gravado")
    argumentos = analisador.parse_args(argv)

    PASTA_DOS_RESULTADOS.mkdir(parents=True, exist_ok=True)
    pcaps = [p["arquivo"] for p in json.loads(MANIFESTO.read_text(encoding="utf-8"))["pcaps"]]
    if not argumentos.so_relatorio:
        # Os maiores primeiro: com vários processos, terminam todos perto da mesma hora.
        tarefas = sorted(
            ((argumentos.pcaps / p, argumentos.modelo, PASTA_DOS_RESULTADOS / f"{p}.json") for p in pcaps),
            key=lambda t: -t[0].stat().st_size,
        )
        if argumentos.retomar:
            tarefas = [t for t in tarefas if not t[2].exists()]
        with ProcessPoolExecutor(max_workers=argumentos.processos) as executor:
            for arquivo, incidentes, segundos in executor.map(_avaliar_e_gravar, tarefas):
                print(f"{arquivo}: {incidentes} incidentes, {segundos} s", file=sys.stderr, flush=True)
    resultados = [json.loads((PASTA_DOS_RESULTADOS / f"{p}.json").read_text(encoding="utf-8")) for p in pcaps]
    falhas = [r for r in resultados if "erro" in r]
    resultados = [r for r in resultados if "erro" not in r]
    artefato = alarme_do_artefato(R.Classificador.carregar(argumentos.modelo))
    texto = relatorio(resultados, artefato)
    if falhas:
        texto += "\n## Pcaps que falharam\n\n" + "\n".join(f"- `{r['arquivo']}`: {r['erro']}" for r in falhas) + "\n"
    RELATORIO.write_text(texto, encoding="utf-8")
    codigo = {
        nome: _sha256(Path("codigo") / nome)
        for nome in ("reprodutor/reprodutor.py", "reprodutor/avaliar.py", "captura/extrator.py", "classificador/operacao.py")
    }
    MANIFESTO_DO_RELATORIO.write_text(json.dumps({
        "gerado_por": "python -m codigo.reprodutor.avaliar",
        "gerado_em": datetime.datetime.now(tz=datetime.UTC).astimezone().isoformat(timespec="seconds"),
        "versoes": {"python": platform.python_version()},
        "modelo": {"arquivo": argumentos.modelo.name, "sha256": _sha256(argumentos.modelo)},
        "ponto_de_operacao": {"sha256": _sha256(R.operacao.ao_lado_do_modelo(argumentos.modelo))},
        "codigo": codigo,
        "politica": {
            "fecha_apos": R.FECHA_APOS, "silencio_s": R.SILENCIO_S, "reagrupa_s": R.REAGRUPA_S, "teto": R.TETO_DE_INCIDENTES,
            "parcela_da_maior_origem": R.PARCELA_DA_MAIOR_ORIGEM,
        },
        "pcaps": [{"arquivo": r["arquivo"], "quadros": r["quadros"], "janelas": r["janelas"], "incidentes": len(r["incidentes"])} for r in resultados],
        "artefato": artefato,
    }, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"relatório em {RELATORIO}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
