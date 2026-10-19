"""Testes da simulação: a rota `/api/simulacao` e o simulador, sem o modelo de verdade e sem provedor."""

import asyncio
import json
import os
import threading
from pathlib import Path

import pytest

from codigo.api.configuracao import Configuracao
from codigo.api.servidor import criar_app
from codigo.api.simulacao import Simulador, nome_do_pcap
from codigo.reprodutor.test_reprodutor import (
    ATACANTE,
    VITIMA,
    ataque,
    benigno,
    classificador,
    escrever_pcap,
)

CONFIG = Configuracao(url_base="https://g/v1", chave="k", modelo="modelo-local", temperatura=0.0, raciocinio=False)


def enviar(app, corpo, nome="a.pcap"):
    """Um POST com o pcap no corpo, direto no app ASGI. Devolve (status, json)."""
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http",
        "path": "/api/simulacao", "raw_path": b"/api/simulacao", "root_path": "",
        "query_string": f"nome={nome}".encode() if nome is not None else b"",
        "headers": [(b"host", b"teste"), (b"content-type", b"application/vnd.tcpdump.pcap"),
                    (b"content-length", str(len(corpo)).encode())],
        "client": ("127.0.0.1", 1), "server": ("teste", 80),
    }
    # O corpo chega em dois pedaços, como numa conexão de verdade.
    meio = len(corpo) // 2
    mensagens = iter([
        {"type": "http.request", "body": corpo[:meio], "more_body": True},
        {"type": "http.request", "body": corpo[meio:], "more_body": False},
    ])
    recebido = {"status": None, "corpo": b""}

    async def receive():
        return next(mensagens, {"type": "http.disconnect"})

    async def send(mensagem):
        if mensagem["type"] == "http.response.start":
            recebido["status"] = mensagem["status"]
        elif mensagem["type"] == "http.response.body":
            recebido["corpo"] += mensagem.get("body", b"")

    asyncio.run(app(scope, receive, send))
    return recebido["status"], json.loads(recebido["corpo"])


class SimuladorFalso:
    def __init__(self, resposta=None, erro=None):
        self.trava = threading.Lock()
        self.resposta = resposta or {"ok": True}
        self.erro = erro
        self.recebido = None

    def disponivel(self):
        return True

    def simular(self, caminho, nome):
        self.recebido = (Path(caminho).read_bytes(), nome, caminho)
        if self.erro:
            raise self.erro
        return self.resposta


def app_com(simulador, **opcoes):
    return criar_app(CONFIG, chamar_provedor=None, pasta_construida="/nao/existe", simulador=simulador, **opcoes)


def test_sem_simulador_a_rota_responde_503():
    status, corpo = enviar(app_com(None), b"pcap")

    assert status == 503
    assert "modelo do sistema" in corpo["erro"]


def test_rota_grava_o_corpo_num_arquivo_chama_o_simulador_e_apaga_o_arquivo():
    simulador = SimuladorFalso({"incidentes": []})

    status, corpo = enviar(app_com(simulador), b"0123456789", nome="../../etc/Meu pcap.pcap")

    assert status == 200
    assert corpo == {"incidentes": []}
    dados, nome, caminho = simulador.recebido
    assert dados == b"0123456789"
    assert nome == "Meu_pcap.pcap"
    assert not os.path.exists(caminho)
    assert not simulador.trava.locked()


def test_uma_simulacao_por_vez():
    simulador = SimuladorFalso()
    simulador.trava.acquire()

    status, _ = enviar(app_com(simulador), b"pcap")

    assert status == 409
    assert simulador.recebido is None


@pytest.mark.parametrize("corpo", [b"x" * 11, b""])
def test_pcap_grande_demais_ou_vazio_e_recusado(corpo):
    simulador = SimuladorFalso()

    status, _ = enviar(app_com(simulador, limite_do_pcap=10), corpo)

    assert status == (413 if corpo else 400)
    assert simulador.recebido is None
    assert not simulador.trava.locked()


def test_arquivo_que_nao_e_pcap_vira_400_com_a_mensagem_do_leitor():
    simulador = SimuladorFalso(erro=ValueError("a entrada não é um arquivo pcap"))

    status, corpo = enviar(app_com(simulador), b"nao sou pcap")

    assert status == 400
    assert corpo["erro"] == "a entrada não é um arquivo pcap"


def test_nome_do_pcap_fica_so_com_o_ultimo_trecho_e_caracteres_seguros():
    assert nome_do_pcap("C:/x/../ataque 1.pcap") == "ataque_1.pcap"
    assert nome_do_pcap("") == "captura.pcap"
    assert nome_do_pcap("...") == "captura.pcap"


def test_simulador_leva_o_incidente_ate_a_porta_da_triagem_sem_chamar_o_modelo(tmp_path):
    pcap = escrever_pcap(tmp_path / "a.pcap", [benigno(2), ataque(5), benigno(10)])
    simulador = Simulador(CONFIG, pasta=tmp_path / "simulacoes", classificador=classificador())

    saida = simulador.simular(pcap, "a.pcap")

    assert [i["id"] for i in saida["incidentes"]] == ["inc-0001"]
    assert len(saida["eventos"].splitlines()) == 3
    para_o_llm = saida["para_o_llm"]
    assert para_o_llm["enviado"] is False
    assert para_o_llm["agente"] == "triagem"
    pedido = para_o_llm["pedido"]
    assert pedido["model"] == "modelo-local"
    assert pedido["temperature"] == 0.0
    assert pedido["chat_template_kwargs"] == {"enable_thinking": False}
    assert "inc-0001" in pedido["messages"][1]["content"]
    assert para_o_llm["primeira_leitura"]["resultado"]["origens"][0]["endereco"] == ATACANTE
    # O que iria para a fronteira não traz endereço nenhum, só os rótulos neutros.
    fronteira = json.dumps(para_o_llm["visao_da_fronteira"])
    assert ATACANTE not in fronteira and VITIMA not in fronteira
    assert "origem-1" in fronteira
    pasta = next((tmp_path / "simulacoes").iterdir())
    assert (pasta / "eventos.jsonl").exists()
    assert "eventos" not in json.loads((pasta / "resumo.json").read_text())


def test_simulador_sem_incidente_nao_monta_pedido(tmp_path):
    pcap = escrever_pcap(tmp_path / "b.pcap", [benigno(4)])
    simulador = Simulador(CONFIG, pasta=tmp_path / "simulacoes", classificador=classificador())

    saida = simulador.simular(pcap, "b.pcap")

    assert saida["incidentes"] == []
    assert saida["para_o_llm"] is None
    assert saida["janelas"] == 4
