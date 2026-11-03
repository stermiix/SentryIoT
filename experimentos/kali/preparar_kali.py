"""Monta o conjunto do teste com Kali no formato do executor dos experimentos.

Roda a partir da raiz do repositório, num checkout com `experimentos/kali/politica_do_laboratorio.toml` copiada
sobre `codigo/mcp/politica.toml` (o reprodutor tira das listas de candidatos os endereços protegidos, e o
servidor usa a mesma política na rodada):

    PYTHONPATH=. python experimentos/kali/preparar_kali.py

Reproduz cada captura de `dados/raw/kali/`
inteira (não há trecho de treino: nenhuma janela delas foi vista pelo modelo), grava o log e os cenários em
`dados/processed/agentes_kali/` e escreve o `conjunto.json` com todos os incidentes abertos.

A verdade de campo é a do laboratório: o atacante é o Kali (192.168.129.128) e a categoria esperada é a do
cenário. Um incidente é verdadeiro quando a categoria dele é da família da esperada (DDoS e DoS contam como
uma, como em `mesma_familia`). Não há verdade por janela, como no CICIoT2023: o número de janelas com quadro
do Kali não é usado.
"""

import sys
from pathlib import Path

from codigo.agente.experimento import ItemDoConjunto, gravar_conjunto
from codigo.classificador.mapeamento import mesma_familia
from codigo.reprodutor import reprodutor as R
from codigo.reprodutor.reprodutor import Classificador

KALI = "192.168.129.128"
ORIGEM = Path("dados/raw/kali")
SAIDA = Path("dados/processed/agentes_kali")
# Cenário (nome do arquivo) e a categoria que o sistema deveria abrir.
ESPERADA = {
    "cen1_portscan": "Recon",
    "cen2_bruteforce": "BruteForce",
    "cen2b_bruteforce": "BruteForce",
    "cen3_flood_syn": "DoS",
    "cen4_flood_udp": "DoS",
    "cen5_flood_icmp": "DoS",
    "cen6_web_nikto": "Web",
    "cen7_arpspoof": "Spoofing",
}


def main():
    classificador = Classificador.carregar(str(R.MODELO_PADRAO))
    SAIDA.mkdir(parents=True, exist_ok=True)
    itens = []
    for nome, esperada in ESPERADA.items():
        pcap = ORIGEM / f"{nome}.pcap"
        log = SAIDA / f"{nome}.jsonl"
        for velho in (log, R.caminho_dos_cenarios(log)):
            velho.unlink(missing_ok=True)
        reproducao = R.reproduzir(pcap, classificador)
        cenarios, _ = R.gravar(reproducao, classificador, log)
        novos = []
        for cenario, incidente in zip(cenarios, reproducao.incidentes, strict=True):
            dados = cenario.incidente
            novos.append(ItemDoConjunto(
                pcap=pcap.name, incidente=dados.id, categoria=dados.categoria, categoria_do_pcap=esperada,
                verdadeiro=mesma_familia(dados.categoria, esperada), confianca=dados.confianca,
                deteccao_s=round(incidente.aberto_em - incidente.primeira_janela_de_ataque, 3),
                atacantes=(KALI,), log=log.name, cenarios=R.caminho_dos_cenarios(log).name,
            ))
        print(f"{pcap.name}: {reproducao.janelas} janelas, {len(novos)} incidentes "
              f"{[(i.incidente, i.categoria, i.confianca, i.verdadeiro) for i in novos]}", flush=True)
        itens += novos
    caminho = gravar_conjunto(itens, SAIDA)
    print(f"conjunto de {len(itens)} incidentes em {caminho}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
