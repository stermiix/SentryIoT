"""Linha de comando do reprodutor de tráfego (ver `codigo/reprodutor/reprodutor.py`)."""

import argparse
import datetime
import json
import sys
from pathlib import Path

from codigo.reprodutor.reprodutor import (
    FECHA_APOS,
    MODELO_PADRAO,
    REAGRUPA_S,
    SILENCIO_S,
    TETO_DE_INCIDENTES,
    Classificador,
    cenarios_da_reproducao,
    gerar_referencia,
    gravar,
    reproduzir,
    resumo,
)

PASTA_DOS_LOGS = Path("dados") / "eventos" / "reproducoes"


def main(argv=None):
    analisador = argparse.ArgumentParser(prog="python -m codigo.reprodutor", description=__doc__)
    analisador.add_argument("pcap", nargs="?", help="o pcap a reproduzir")
    analisador.add_argument("--log", help="log de eventos a gravar (padrão: dados/eventos/reproducoes/<pcap>-<instante>.jsonl)")
    analisador.add_argument("--modelo", default=str(MODELO_PADRAO), help="modelo do sistema, com o ponto de operação ao lado")
    analisador.add_argument("--fecha-apos", type=int, default=FECHA_APOS, help="janelas benignas seguidas que encerram o incidente")
    analisador.add_argument("--silencio", type=float, default=SILENCIO_S, help="segundos sem janela que encerram o incidente")
    analisador.add_argument("--reagrupa", type=float, default=REAGRUPA_S, help="segundos em que a mesma categoria e o mesmo endereço reabrem o incidente")
    analisador.add_argument("--teto", type=int, default=TETO_DE_INCIDENTES, help="incidentes por pcap")
    analisador.add_argument("--gerar-referencia", action="store_true", help="regrava referencia_benigno.json a partir dos dados regerados")
    argumentos = analisador.parse_args(argv)

    if argumentos.gerar_referencia:
        print(f"referência gravada em {gerar_referencia()}")
        return
    if not argumentos.pcap:
        analisador.error("diga o pcap a reproduzir")
    classificador = Classificador.carregar(argumentos.modelo)
    reproducao = reproduzir(
        argumentos.pcap, classificador, fecha_apos=argumentos.fecha_apos, silencio_s=argumentos.silencio,
        reagrupa_s=argumentos.reagrupa, teto=argumentos.teto,
    )
    cenarios = cenarios_da_reproducao(reproducao, classificador)
    carimbo = datetime.datetime.now(tz=datetime.UTC).astimezone().strftime("%Y%m%d-%H%M%S")
    log = Path(argumentos.log) if argumentos.log else PASTA_DOS_LOGS / f"{Path(argumentos.pcap).stem}-{carimbo}.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    gravar(cenarios, reproducao, log)
    json.dump(resumo(reproducao, cenarios, classificador, argumentos.fecha_apos, argumentos.silencio, argumentos.reagrupa, argumentos.teto), sys.stdout, indent=1, ensure_ascii=False)
    print(f"\nlog de eventos: {log}", file=sys.stderr)


if __name__ == "__main__":
    main()
