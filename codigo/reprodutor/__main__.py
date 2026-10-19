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
    PcapInvalido,
    caminho_dos_cenarios,
    gerar_referencia,
    gravar,
    inicio_do_teste,
    reproduzir,
    resumo,
)

PASTA_DOS_LOGS = Path("dados") / "eventos" / "reproducoes"


def main(argv=None):
    analisador = argparse.ArgumentParser(prog="python -m codigo.reprodutor", description=__doc__)
    analisador.add_argument("pcap", nargs="?", help="o pcap a reproduzir")
    analisador.add_argument("--log", help="log de eventos a gravar (padrão: dados/eventos/reproducoes/<pcap>-<instante>.jsonl)")
    analisador.add_argument("--modelo", default=str(MODELO_PADRAO), help="modelo do sistema, com o ponto de operação ao lado")
    analisador.add_argument(
        "--so-teste", action="store_true",
        help="reproduz só o trecho do pcap que ficou fora do treino do modelo do sistema (pelo manifesto da regeração)",
    )
    analisador.add_argument("--fecha-apos", type=int, default=FECHA_APOS, help="janelas seguidas sem o incidente que o encerram")
    analisador.add_argument("--silencio", type=float, default=SILENCIO_S, help="segundos sem janela que encerram os incidentes")
    analisador.add_argument(
        "--reagrupa", type=float, default=REAGRUPA_S, help="segundos em que a mesma categoria e um endereço em comum reabrem o incidente",
    )
    analisador.add_argument("--teto", type=int, default=TETO_DE_INCIDENTES, help="incidentes por pcap")
    analisador.add_argument("--gerar-referencia", action="store_true", help="regrava referencia_benigno.json a partir dos dados regerados")
    argumentos = analisador.parse_args(argv)

    if argumentos.gerar_referencia:
        print(f"referência gravada em {gerar_referencia()}")
        return 0
    if not argumentos.pcap:
        analisador.error("diga o pcap a reproduzir")
    a_partir = 0
    if argumentos.so_teste:
        a_partir = inicio_do_teste(argumentos.pcap)
        if a_partir is None:
            print(f"erro: {Path(argumentos.pcap).name} não tem trecho fora do treino no manifesto da regeração", file=sys.stderr)
            return 1
    classificador = Classificador.carregar(argumentos.modelo)
    try:
        reproducao = reproduzir(
            argumentos.pcap, classificador, fecha_apos=argumentos.fecha_apos, silencio_s=argumentos.silencio,
            reagrupa_s=argumentos.reagrupa, teto=argumentos.teto, a_partir_da_janela=a_partir,
        )
    except PcapInvalido as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    carimbo = datetime.datetime.now(tz=datetime.UTC).astimezone().strftime("%Y%m%d-%H%M%S")
    log = Path(argumentos.log) if argumentos.log else PASTA_DOS_LOGS / f"{Path(argumentos.pcap).stem}-{carimbo}.jsonl"
    cenarios, deslocamento = gravar(reproducao, classificador, log)
    saida = resumo(
        reproducao, cenarios, classificador, deslocamento, argumentos.fecha_apos, argumentos.silencio, argumentos.reagrupa,
        argumentos.teto, a_partir,
    )
    json.dump(saida, sys.stdout, indent=1, ensure_ascii=False)
    print(f"\nlog de eventos: {log}", file=sys.stderr)
    print(
        f"servidor MCP com estes incidentes: python -m codigo.mcp.stub --agente triagem --log {log} "
        f"--cenarios {caminho_dos_cenarios(log)}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
