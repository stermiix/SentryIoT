"""Testes da montagem dos dados fixos da interface, com pastas de experimento feitas do log de exemplo do stub."""

import gzip
import json
import shutil

import pytest

from codigo.agente.vitrine import (
    INDICE,
    ErroDaVitrine,
    comprimir,
    escolher_inicial,
    main,
    montar,
    resumir,
)
from codigo.mcp.acoes import carregar_politica
from codigo.mcp.eventos import Registro, novo
from codigo.mcp.roteiro import SAIDA_PADRAO as LOG_DE_EXEMPLO

CONVERSA = {
    "agente": "triagem", "modelo": "qwen3.8-27c", "onde": "local", "motivo": "resposta_final", "tarefa": "incidente",
    "mensagens": [
        {"papel": "system", "texto": "# Triagem do alerta", "tools_pedidas": [], "resposta_a": None},
        {"papel": "user", "texto": "Abriu o incidente inc-0001.", "tools_pedidas": [], "resposta_a": None},
        {"papel": "assistant", "texto": "Rótulo da triagem: coerente", "tools_pedidas": [], "resposta_a": None},
    ],
}


def medidas(rodada, pcap, incidente, repeticao, **outras):
    """As medidas de uma rodada como `experimento.medir` as grava, com valores de um incidente verdadeiro resolvido."""
    return {
        "rodada": rodada, "pcap": pcap, "incidente": incidente, "categoria": "DDoS", "categoria_do_pcap": "DDoS",
        "verdadeiro": True, "confianca": 0.97, "deteccao_s": 0.5, "configuracao": "local", "repeticao": repeticao,
        "desfecho": "resolvido", "erro": None, "triagem_rotulo": "coerente", "triagem_correta": True,
        "n_propostas": 1, "n_aceitaveis": 1, "primeira_aceitavel": True, "acao_primeira": "bloquear_ip",
        "papel_primeiro": "origem", "n_aprovadas": 1, "n_rejeitadas": 0, "n_baixo_risco": 0, "n_novas": 0,
        "atacante_apontado": True, "atacante_certo": True, "origem_da_regra_certa": False, "agentes_s": 40.0,
        "por_agente": [
            {"agente": "triagem", "onde": "local", "chamadas": 3, "tokens_entrada": 1000, "tokens_saida": 100, "llm_s": 5.0},
            {"agente": "decisao", "onde": "local", "chamadas": 2, "tokens_entrada": 800, "tokens_saida": 50, "llm_s": 4.0},
        ],
        "avisos": [], "conclusoes": [],
        **outras,
    }


def pasta_do_experimento(raiz, rodadas, *, itens=None):
    """Uma pasta como a do `experimento`: o conjunto e, em `rodadas/`, o JSON e o log de cada rodada.

    `rodadas` é uma lista de medidas; o log de cada uma é o de exemplo do stub, com a conversa da triagem no fim.
    """
    raiz.mkdir(parents=True)
    pasta = raiz / "rodadas"
    pasta.mkdir()
    vistos = []
    for medida in rodadas:
        log = pasta / f"{medida['rodada']}.jsonl"
        shutil.copyfile(LOG_DE_EXEMPLO, log)
        Registro(log).gravar(novo("conversa_do_agente", CONVERSA, medida["incidente"]))
        (pasta / f"{medida['rodada']}.json").write_text(json.dumps(medida), encoding="utf-8")
        chave = {"pcap": medida["pcap"], "incidente": medida["incidente"]}
        if chave not in vistos:
            vistos.append(chave)
    itens = itens if itens is not None else [{**chave, "categoria": "DDoS", "log": "x.jsonl"} for chave in vistos]
    (raiz / "conjunto.json").write_text(json.dumps({"gerado_em": "2026-11-02T10:00:00-03:00", "itens": itens}), encoding="utf-8")
    return raiz


@pytest.fixture
def oficial(tmp_path):
    return pasta_do_experimento(tmp_path / "agentes", [
        medidas("DDoS-UDP_Flood-inc-0001-local-r2", "DDoS-UDP_Flood.pcap", "inc-0001", 2),
        medidas("DDoS-UDP_Flood-inc-0001-local-r1", "DDoS-UDP_Flood.pcap", "inc-0001", 1, primeira_aceitavel=False),
        medidas(
            "BenignTraffic2-inc-0002-local-r1", "BenignTraffic2.pcap", "inc-0002", 1, verdadeiro=False,
            categoria_do_pcap="Benign", confianca=0.55, desfecho="sem_proposta", triagem_rotulo="duvidoso",
            primeira_aceitavel=False, atacante_certo=False,
        ),
    ])


def test_monta_o_indice_e_os_logs_comprimidos(tmp_path, oficial):
    saida = tmp_path / "publico" / "rodada-final"

    indice = montar([("oficial", oficial)], saida)

    assert json.loads((saida / INDICE).read_text(encoding="utf-8")) == indice
    assert (indice["versao"], indice["configuracao"], indice["modelos"]) == (1, "local", ["modelo-de-exemplo"])
    assert indice["confianca_minima_para_propor"] == carregar_politica().confianca_minima_para_propor
    (grupo,) = indice["grupos"]
    assert (grupo["id"], grupo["titulo"], grupo["conjunto_gerado_em"]) == ("oficial", "Rodada oficial (CICIoT2023)", "2026-11-02T10:00:00-03:00")
    # Na ordem do conjunto e, dentro do incidente, da repetição.
    assert [e["id"] for e in grupo["execucoes"]] == [
        "oficial/DDoS-UDP_Flood-inc-0001-local-r1", "oficial/DDoS-UDP_Flood-inc-0001-local-r2", "oficial/BenignTraffic2-inc-0002-local-r1",
    ]
    primeira = grupo["execucoes"][0]
    assert primeira["log"] == "oficial/DDoS-UDP_Flood-inc-0001-local-r1.jsonl.gz"
    assert (primeira["chamadas"], primeira["tokens_entrada"], primeira["tokens_saida"], primeira["llm_s"]) == (5, 1800, 150, 9.0)
    assert (primeira["conversas"], primeira["triagem_correta"], primeira["primeira_aceitavel"]) == (1, True, False)
    # O log vai como está, byte a byte, só comprimido.
    original = (oficial / "rodadas" / "DDoS-UDP_Flood-inc-0001-local-r1.jsonl").read_bytes()
    comprimido = (saida / primeira["log"]).read_bytes()
    assert comprimido[:2] == b"\x1f\x8b" and gzip.decompress(comprimido) == original
    assert primeira["bytes"] == len(original)


def test_o_resumo_sai_das_medidas_e_deixa_o_erro_fora_das_taxas(oficial, tmp_path):
    indice = montar([("oficial", oficial)], tmp_path / "saida")
    resumo = indice["grupos"][0]["resumo"]

    assert (resumo["execucoes"], resumo["com_erro"], resumo["pcaps"], resumo["incidentes"], resumo["repeticoes"]) == (3, 0, 2, 2, 2)
    assert (resumo["verdadeiras"], resumo["falsas"]) == (2, 1)
    assert resumo["triagem_correta"] == {"acertos": 3, "de": 3}
    assert resumo["acao_aceitavel"] == {"acertos": 1, "de": 2}
    assert resumo["atacante_certo"] == {"acertos": 2, "de": 2}
    assert resumo["regra_fixa_certa"] == {"acertos": 0, "de": 2}
    assert resumo["abaixo_da_confianca_minima"] == 1
    assert resumo["desfechos"] == {"resolvido": 2, "sem_proposta": 1}
    assert (resumo["chamadas"], resumo["tokens_entrada"], resumo["tokens_saida"]) == (15, 5400, 450)
    assert resumo["mediana_tokens"] == 1950
    assert [(a["agente"], a["execucoes"], a["chamadas"], a["mediana_tokens"]) for a in resumo["por_agente"]] == [
        ("triagem", 3, 9, 1100), ("decisao", 3, 6, 850),
    ]

    com_erro = [{**e, "desfecho": "erro"} if e["repeticao"] == 2 else e for e in indice["grupos"][0]["execucoes"]]
    resumo = resumir(com_erro, 0.6)
    assert (resumo["execucoes"], resumo["com_erro"], resumo["verdadeiras"]) == (3, 1, 1)
    assert resumo["triagem_correta"] == {"acertos": 2, "de": 2}
    assert resumo["desfechos"] == {"erro": 1, "resolvido": 1, "sem_proposta": 1}


def test_a_inicial_e_a_primeira_em_que_tudo_deu_certo(oficial, tmp_path):
    indice = montar([("oficial", oficial)], tmp_path / "saida")
    # A r1 não tem a primeira ação aceitável; a r2 tem tudo, mas não é a primeira repetição: vale a primeira resolvida.
    assert indice["inicial"] == "oficial/DDoS-UDP_Flood-inc-0001-local-r1"

    execucoes = indice["grupos"][0]["execucoes"]
    execucoes[1]["repeticao"] = 1
    assert escolher_inicial(indice["grupos"]) == "oficial/DDoS-UDP_Flood-inc-0001-local-r2"
    assert montar([("oficial", oficial)], tmp_path / "saida", inicial="oficial/BenignTraffic2-inc-0002-local-r1")["inicial"] == (
        "oficial/BenignTraffic2-inc-0002-local-r1"
    )
    with pytest.raises(ErroDaVitrine, match="não está nos grupos"):
        montar([("oficial", oficial)], tmp_path / "saida", inicial="oficial/outra")


def test_e_idempotente_byte_a_byte_e_troca_o_que_havia(oficial, tmp_path):
    saida = tmp_path / "saida"
    montar([("oficial", oficial)], saida)
    antes = {p.relative_to(saida): p.read_bytes() for p in saida.rglob("*") if p.is_file()}

    montar([("oficial", oficial)], saida)
    depois = {p.relative_to(saida): p.read_bytes() for p in saida.rglob("*") if p.is_file()}

    assert antes == depois
    assert comprimir(b"abc") == comprimir(b"abc")
    # Uma rodada a menos sai também da pasta: não sobra log velho.
    (oficial / "rodadas" / "DDoS-UDP_Flood-inc-0001-local-r2.json").unlink()
    montar([("oficial", oficial)], saida)
    assert not (saida / "oficial" / "DDoS-UDP_Flood-inc-0001-local-r2.jsonl.gz").exists()


def test_tres_grupos_com_os_titulos_da_interface(tmp_path, oficial):
    kali = pasta_do_experimento(tmp_path / "kali", [medidas("nmap-inc-0001-local-r1", "nmap.pcap", "inc-0001", 1, categoria_do_pcap="Recon")])
    exemplos = pasta_do_experimento(tmp_path / "exemplos", [medidas("Mirai-inc-0001-local-r1", "Mirai.pcap", "inc-0001", 1)])

    indice = montar([("oficial", oficial), ("kali", kali), ("exemplos", exemplos)], tmp_path / "saida")

    assert [(g["id"], g["titulo"]) for g in indice["grupos"]] == [
        ("oficial", "Rodada oficial (CICIoT2023)"), ("kali", "Kali Linux, rede isolada"), ("exemplos", "Exemplos por categoria"),
    ]
    assert (tmp_path / "saida" / "kali" / "nmap-inc-0001-local-r1.jsonl.gz").is_file()


@pytest.mark.parametrize(
    ("estragar", "mensagem"),
    [
        (lambda pasta: (pasta / "conjunto.json").unlink(), "falta .*conjunto.json"),
        (lambda pasta: shutil.rmtree(pasta / "rodadas"), "falta a pasta"),
        (lambda pasta: (pasta / "rodadas" / "BenignTraffic2-inc-0002-local-r1.jsonl").unlink(), "falta o log da rodada"),
        (
            lambda pasta: [(pasta / "rodadas" / f"BenignTraffic2-inc-0002-local-r1{fim}").unlink() for fim in (".json", ".jsonl")],
            "itens do conjunto sem rodada.*BenignTraffic2.pcap inc-0002",
        ),
        (
            lambda pasta: (pasta / "rodadas" / "x.json").write_text(json.dumps({"rodada": "y"}), encoding="utf-8"),
            "não é o JSON de uma rodada",
        ),
        (
            lambda pasta: _trocar_medida(pasta, "DDoS-UDP_Flood-inc-0001-local-r1", configuracao="hibrida"),
            "configuração hibrida",
        ),
        (
            lambda pasta: _trocar_medida(pasta, "DDoS-UDP_Flood-inc-0001-local-r1", incidente="inc-0009"),
            "não está no conjunto",
        ),
        (
            lambda pasta: (pasta / "rodadas" / "DDoS-UDP_Flood-inc-0001-local-r1.jsonl").open("a", encoding="utf-8").write('{"tipo": "x"}\n'),
            "linha",
        ),
    ],
)
def test_falta_ou_defeito_falha_alto_sem_mexer_na_saida(tmp_path, oficial, estragar, mensagem):
    saida = tmp_path / "saida"
    montar([("oficial", oficial)], saida)
    antes = sorted(p.relative_to(saida) for p in saida.rglob("*"))
    estragar(oficial)

    with pytest.raises(ValueError, match=mensagem):
        montar([("oficial", oficial)], saida)

    assert sorted(p.relative_to(saida) for p in saida.rglob("*")) == antes


def _trocar_medida(pasta, rodada, **troca):
    caminho = pasta / "rodadas" / f"{rodada}.json"
    caminho.write_text(json.dumps({**json.loads(caminho.read_text(encoding="utf-8")), **troca}), encoding="utf-8")


def test_nao_apaga_pasta_de_saida_com_outra_coisa(tmp_path, oficial):
    saida = tmp_path / "saida"
    saida.mkdir()
    (saida / "importante.txt").write_text("não apagar", encoding="utf-8")

    with pytest.raises(ErroDaVitrine, match="importante.txt"):
        montar([("oficial", oficial)], saida)

    assert (saida / "importante.txt").read_text(encoding="utf-8") == "não apagar"


def test_linha_de_comando(tmp_path, oficial, capsys):
    saida = tmp_path / "saida"

    assert main(["--oficial", str(oficial), "--omitir", "kali", "exemplos", "--saida", str(saida)]) == 0
    assert "Rodada oficial (CICIoT2023): 3 execuções, 0 com erro" in capsys.readouterr().out
    assert [g["id"] for g in json.loads((saida / INDICE).read_text(encoding="utf-8"))["grupos"]] == ["oficial"]

    # Sem --omitir, a pasta padrão do Kali precisa existir; aqui ela aponta para uma que não existe.
    assert main(["--oficial", str(oficial), "--kali", str(tmp_path / "nada"), "--omitir", "exemplos", "--saida", str(saida)]) == 1
    assert "falta" in capsys.readouterr().err
