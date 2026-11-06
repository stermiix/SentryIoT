"""Tempo até a remediação na rodada final, da primeira janela do ataque à primeira ação aplicada.

Roda a partir da raiz do repositório, só com a biblioteca padrão:

    python experimentos/tempo_ate_a_remediacao.py

Lê os logs versionados da rodada oficial (`frontend/public/dados/rodada-final/oficial/`) e a coluna
`deteccao_s` de `experimentos/resultados/custo_latencia.csv`, e grava
`experimentos/resultados/tempo_ate_a_remediacao.csv`, uma linha por rodada em que uma ação foi aplicada.

A medida soma dois trechos:
- a detecção (`deteccao_s`), da primeira janela de ataque à abertura do incidente;
- dos agentes, do início da primeira chamada ao modelo (o instante do evento `llm_chamada` menos a `duracao_ms`
  dela) ao evento `acao_executada` da primeira ação aplicada.

A soma supõe que a triagem começa no instante em que o incidente abre: na rodada, os agentes rodaram em fila depois
da reprodução, e essa espera fica de fora. Não muda nenhum dado da rodada: só junta medidas já gravadas.
"""

import csv
import gzip
import json
import re
import statistics
from datetime import datetime
from pathlib import Path

LOGS = Path("frontend/public/dados/rodada-final/oficial")
CUSTO = Path("experimentos/resultados/custo_latencia.csv")
SAIDA = Path("experimentos/resultados/tempo_ate_a_remediacao.csv")
# As ações de risco alto do catálogo que aparecem na rodada; as demais aplicadas são de risco baixo.
RISCO_ALTO = {"bloquear_ip"}
NOME = re.compile(r"(?P<pcap>.+)-(?P<incidente>inc-\d+)-(?P<configuracao>\w+)-r(?P<repeticao>\d+)\.jsonl\.gz")


def _instante(texto):
    return datetime.fromisoformat(texto).timestamp()


def _deteccao():
    with CUSTO.open(newline="", encoding="utf-8") as arquivo:
        return {
            (linha["pcap"], linha["incidente"], linha["configuracao"], linha["repeticao"]): float(linha["deteccao_s"])
            for linha in csv.DictReader(arquivo)
            if linha["agente"] == "total"
        }


def medir():
    """Devolve uma linha por rodada com ação aplicada, na ordem dos arquivos de log."""
    deteccao = _deteccao()
    linhas = []
    for caminho in sorted(LOGS.glob("*.jsonl.gz")):
        nome = NOME.fullmatch(caminho.name)
        with gzip.open(caminho, "rt", encoding="utf-8") as arquivo:
            eventos = [json.loads(texto) for texto in arquivo]
        eventos = [e for e in eventos if e["incidente"] == nome["incidente"]]
        chamadas = [e for e in eventos if e["tipo"] == "llm_chamada"]
        acoes = [e for e in eventos if e["tipo"] == "acao_executada"]
        if not acoes:
            continue
        inicio = _instante(chamadas[0]["instante"]) - chamadas[0]["dados"]["duracao_ms"] / 1000
        agentes = _instante(acoes[0]["instante"]) - inicio
        chave = (f"{nome['pcap']}.pcap", nome["incidente"], nome["configuracao"], nome["repeticao"])
        acao = acoes[0]["dados"]["acao"]
        linhas.append({
            "pcap": chave[0], "incidente": chave[1], "configuracao": chave[2], "repeticao": chave[3],
            "acao": acao, "risco": "alto" if acao in RISCO_ALTO else "baixo",
            "deteccao_s": deteccao[chave], "agentes_ate_a_acao_s": round(agentes, 3),
            "ate_a_remediacao_s": round(deteccao[chave] + agentes, 3),
        })
    return linhas


def main():
    linhas = medir()
    with SAIDA.open("w", newline="", encoding="utf-8") as arquivo:
        escritor = csv.DictWriter(arquivo, fieldnames=list(linhas[0]))
        escritor.writeheader()
        escritor.writerows(linhas)
    print(f"{len(linhas)} rodadas com ação aplicada; mediana do tempo até a remediação (s):")
    for rotulo, filtro in (("todas", None), ("risco baixo", "baixo"), ("risco alto", "alto")):
        valores = [linha["ate_a_remediacao_s"] for linha in linhas if filtro in (None, linha["risco"])]
        print(f"  {rotulo}: {statistics.median(valores):.2f} ({len(valores)} rodadas)")


if __name__ == "__main__":
    main()
