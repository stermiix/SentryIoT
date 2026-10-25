"""Testes da medida do limiar de confiança da triagem, com resultados da avaliação montados no teste."""

import json
from pathlib import Path

import pytest

from codigo.reprodutor import limiar

SKILL_DA_TRIAGEM = Path(__file__).parents[1] / "agente" / "skills" / "triagem-do-alerta" / "SKILL.md"


def _incidente(categoria, confianca, com_atacante=1, no_teste=0, janelas=10):
    return {
        "categoria": categoria, "confianca": confianca, "janelas": janelas,
        "janelas_com_atacante": com_atacante, "janelas_no_teste": no_teste,
    }


def _resultado(pasta, arquivo, categoria, incidentes, benigno=False):
    conteudo = {"arquivo": arquivo, "categoria": categoria, "benigno": benigno, "incidentes": incidentes}
    (pasta / f"{arquivo}.json").write_text(json.dumps(conteudo), encoding="utf-8")


def test_verdadeiro_pede_pcap_de_ataque_quadro_de_atacante_e_a_categoria_do_pcap(tmp_path):
    _resultado(tmp_path, "Recon-PortScan.pcap", "Recon", [
        _incidente("Recon", 0.62),
        _incidente("Recon", 0.9, com_atacante=0),
        _incidente("Web", 0.9),
    ])
    _resultado(tmp_path, "BenignTraffic.pcap", "Benign", [_incidente("Spoofing", 0.5, com_atacante=0)], benigno=True)

    incidentes = limiar.ler(tmp_path)

    assert [i.verdadeiro for i in incidentes] == [False, True, False, False]
    assert incidentes[0].pcap == "BenignTraffic.pcap"


def test_contar_separa_falsos_pegos_de_verdadeiros_marcados(tmp_path):
    _resultado(tmp_path, "DDoS.pcap", "DDoS", [
        _incidente("DDoS", 0.95), _incidente("DDoS", 0.55), _incidente("DoS", 0.45), _incidente("DoS", 0.9),
    ])

    assert limiar.contar(limiar.ler(tmp_path), 0.6) == (1, 2, 1, 2)


def test_escolhe_so_fora_do_teste_o_menor_limiar_que_pega_mais_falsos_sem_marcar_verdadeiro(tmp_path):
    _resultado(tmp_path, "A.pcap", "Recon", [
        _incidente("Recon", 0.68),
        _incidente("Web", 0.52), _incidente("Web", 0.58),
        # No teste, um verdadeiro de 0,52 não pode mudar a escolha.
        _incidente("Recon", 0.52, no_teste=3),
    ])

    assert limiar.escolher(limiar.ler(tmp_path)) == 0.6


def test_sem_limiar_que_poupe_os_verdadeiros_nao_escolhe_nenhum(tmp_path):
    _resultado(tmp_path, "A.pcap", "Recon", [_incidente("Recon", 0.3), _incidente("Web", 0.4)])

    assert limiar.escolher(limiar.ler(tmp_path)) is None


def test_relatorio_marca_o_limiar_da_skill_e_avisa_quando_os_dados_escolhem_outro(tmp_path):
    _resultado(tmp_path, "A.pcap", "Recon", [_incidente("Recon", 0.9), _incidente("Web", 0.58)])
    texto = limiar.relatorio(limiar.ler(tmp_path))
    assert "| 0,60 (escolhido) |" in texto
    assert "a regra escolhe 0,60, o limiar da skill" in texto

    _resultado(tmp_path, "A.pcap", "Recon", [_incidente("Recon", 0.9), _incidente("Web", 0.72)])
    assert "Atenção" in limiar.relatorio(limiar.ler(tmp_path))


def test_pasta_sem_resultado_da_erro_claro(tmp_path):
    with pytest.raises(ValueError, match="nenhum resultado"):
        limiar.ler(tmp_path)
    assert limiar.main(["--resultados", str(tmp_path), "--relatorio", str(tmp_path / "r.md")]) == 1


def test_main_grava_o_relatorio(tmp_path):
    _resultado(tmp_path, "A.pcap", "Recon", [_incidente("Recon", 0.9)])

    assert limiar.main(["--resultados", str(tmp_path), "--relatorio", str(tmp_path / "r.md")]) == 0
    assert (tmp_path / "r.md").read_text(encoding="utf-8").startswith("# Limiar de confiança da triagem")


def test_skill_da_triagem_usa_o_limiar_medido():
    texto = SKILL_DA_TRIAGEM.read_text(encoding="utf-8")
    assert f"abaixo de {limiar.LIMIAR_DA_TRIAGEM:.1f}".replace(".", ",") in texto
