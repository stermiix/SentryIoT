"""Testes da medida de custo do modelo do sistema, com pcaps montados no teste e o modelo de mentira."""

import json

from codigo.reprodutor import custo
from codigo.reprodutor.test_reprodutor import (
    ataque,
    benigno,
    classificador,
    escrever_pcap,
)


def _manifesto(tmp_path, arquivo, janelas):
    caminho = tmp_path / "manifesto.json"
    caminho.write_text(json.dumps({
        "pcaps": [{"arquivo": arquivo, "janelas": {"100": {"extraidas": janelas}}}],
        "rotulos": [{"arquivos": [arquivo]}],
    }))
    return caminho


def test_janelas_de_teste_vem_so_do_trecho_fora_do_treino_e_param_no_limite(tmp_path):
    # Com 10 janelas, o corte por tempo põe as 3 últimas no teste: são as de ataque.
    pcap = escrever_pcap(tmp_path / "A.pcap", [benigno(7), ataque(3)])
    manifesto = _manifesto(tmp_path, "A.pcap", 10)

    todas = custo.janelas_de_teste(pcap, limite=10, manifesto=manifesto)
    duas = custo.janelas_de_teste(pcap, limite=2, manifesto=manifesto)

    assert len(todas) == 3 and all(linha["syn_flag_number"] > 0.5 for linha in todas)
    assert duas == todas[:2]


def test_pcap_sem_trecho_de_teste_nao_da_janela(tmp_path):
    pcap = escrever_pcap(tmp_path / "B.pcap", [benigno(4)])

    assert custo.janelas_de_teste(pcap, manifesto=_manifesto(tmp_path, "A.pcap", 10)) == []


def test_latencia_do_caminho_passa_por_cada_janela(tmp_path):
    pcap = escrever_pcap(tmp_path / "A.pcap", [ataque(5)])
    linhas = custo.janelas_de_teste(pcap, manifesto=_manifesto(tmp_path, "A.pcap", 5))
    assert linhas

    medida = custo.latencia_do_caminho(classificador(), linhas)

    assert set(medida) == {"mediana_ms", "p95_ms", "p99_ms"}
    assert 0 <= medida["mediana_ms"] <= medida["p95_ms"] <= medida["p99_ms"]


def test_relatorio_sai_do_manifesto():
    latencia = {"mediana_ms": 1.234, "p95_ms": 1.5, "p99_ms": 2.0}
    vazao = {"arquivo": "Recon-PortScan.pcap", "janelas": 8000, "segundos": 5.0}
    manifesto = {
        "gerado_por": "python -m codigo.reprodutor.custo", "gerado_em": "2026-10-25T18:00:00-03:00",
        "maquina": {"processador": "Apple M5", "memoria_bytes": 16 * 2**30, "sistema": "macOS-27.0-arm64"},
        "modelo": {"arquivo": "rf.joblib", "bytes": 365_600_000, "nos": 3_000_000, "profundidade_media": 44.9,
                   "profundidade_maxima": 53},
        "carga": {"importar_s": 0.6, "carga_s": 0.15, "memoria_antes": 160e6, "memoria_depois": 900e6},
        "pico_de_memoria": 950e6,
        "pcaps": [{"arquivo": "XSS.pcap", "janelas": 115}],
        "medidas": {
            "janelas": 1115, "latencia_predict_proba": latencia, "latencia_do_caminho": latencia, "lote_ms": 12.34,
            "vazao_do_extrator": {**vazao, "pacotes": 800_000}, "vazao_do_reprodutor": {**vazao, "quadros": 800_000},
        },
    }

    texto = custo.relatorio(manifesto)

    assert "| Uma janela, `predict_proba`, um núcleo | mediana 1,23 ms, p95 1,50 ms, p99 2,00 ms |" in texto
    assert "| Lote de 1.000 janelas | 12,3 ms |" in texto
    assert ("| Extrator de janela de 100 em `Recon-PortScan.pcap` | 800.000 quadros em 5,0 s: 160.000 quadros/s e "
            "1.600 janelas/s |") in texto
    assert "Máquina: Apple M5, 16 GB de memória, macOS-27.0-arm64." in texto
    assert "Janelas da latência por pcap: `XSS.pcap` 115." in texto
