"""Testes da simulação: as rotas e o simulador, com o classificador e o provedor de mentira."""

import asyncio
import json
import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codigo.agente.test_agentes import decisao, execucao, triagem
from codigo.agente.test_laco import ProvedorFalso, resposta
from codigo.api.configuracao import Configuracao
from codigo.api.provedor import ErroDoProvedor
from codigo.api.servidor import CABECALHO_DA_INTERFACE, criar_app
from codigo.api.simulacao import (
    SemSimulacaoEmAndamento,
    SemTrechoDeTeste,
    Simulador,
    nome_do_pcap,
)
from codigo.mcp.acoes import PedidoRecusado, reconstruir
from codigo.mcp.eventos import ler
from codigo.reprodutor.reprodutor import PcapInvalido
from codigo.reprodutor.test_reprodutor import (
    ataque,
    benigno,
    classificador,
    escrever_pcap,
)

CONFIG = Configuracao(url_base="https://g/v1", chave="k", modelo="modelo-local", temperatura=0.0, raciocinio=False)
SEM_MODELO = Configuracao(url_base="", chave="", modelo="", temperatura=0.0, raciocinio=False)
CABECALHO = (CABECALHO_DA_INTERFACE[0].lower().encode(), CABECALHO_DA_INTERFACE[1].encode())


def enviar(app, corpo, nome="a.pcap", consulta="", cabecalho=True):
    """Um POST com o pcap no corpo, direto no app ASGI. Devolve (status, json)."""
    partes = [f"nome={nome}"] if nome is not None else []
    partes += [consulta] if consulta else []
    cabecalhos = [(b"host", b"teste"), (b"content-type", b"application/vnd.tcpdump.pcap"), (b"content-length", str(len(corpo)).encode())]
    if cabecalho:
        cabecalhos.append(CABECALHO)
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http",
        "path": "/api/simulacao", "raw_path": b"/api/simulacao", "root_path": "",
        "query_string": "&".join(partes).encode(), "headers": cabecalhos,
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


def pedir(app, metodo, caminho, corpo=None, cabecalho=True):
    """Um pedido com corpo JSON, direto no app ASGI. Devolve (status, json)."""
    dados = json.dumps(corpo).encode() if corpo is not None else b""
    cabecalhos = [(b"host", b"teste"), (b"content-type", b"application/json"), (b"content-length", str(len(dados)).encode())]
    if cabecalho:
        cabecalhos.append(CABECALHO)
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": metodo, "scheme": "http",
        "path": caminho, "raw_path": caminho.encode(), "root_path": "", "query_string": b"", "headers": cabecalhos,
        "client": ("127.0.0.1", 1), "server": ("teste", 80),
    }
    mensagens = iter([{"type": "http.request", "body": dados, "more_body": False}])
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
    def __init__(self, resposta=None, erro=None, agentes_rodando=False, em_andamento=None, erro_da_decisao=None):
        self.trava = threading.Lock()
        self.resposta = resposta or {"ok": True}
        self.erro = erro
        self.recebido = None
        self.agentes_rodando = agentes_rodando
        self.em_andamento = em_andamento
        self.erro_da_decisao = erro_da_decisao
        self.decisoes = []
        self.paradas = 0

    def disponivel(self):
        return True

    def ocupado(self):
        return self.trava.locked() or self.agentes_rodando

    def atual(self):
        return self.em_andamento

    def decidir(self, tipo, alvo, motivo=None):
        if self.erro_da_decisao:
            raise self.erro_da_decisao
        self.decisoes.append((tipo, alvo, motivo))

    def parar(self):
        self.paradas += 1

    def simular(self, caminho, nome, so_teste=False):
        self.recebido = (Path(caminho).read_bytes(), nome, caminho, so_teste, self.trava.locked())
        if self.erro:
            raise self.erro
        return self.resposta


def app_com(simulador, **opcoes):
    return criar_app(CONFIG, chamar_provedor=None, pasta_construida="/nao/existe", simulador=simulador, **opcoes)


def test_sem_simulador_a_rota_responde_503():
    status, corpo = enviar(app_com(None), b"pcap")

    assert status == 503
    assert "modelo do sistema" in corpo["erro"]


def test_sem_o_cabecalho_da_interface_a_rota_recusa():
    simulador = SimuladorFalso()

    status, corpo = enviar(app_com(simulador), b"pcap", cabecalho=False)

    assert status == 403
    assert CABECALHO_DA_INTERFACE[0] in corpo["erro"]
    assert simulador.recebido is None


def test_rota_grava_o_corpo_num_arquivo_chama_o_simulador_com_a_trava_e_apaga_o_arquivo():
    simulador = SimuladorFalso({"incidentes": []})

    status, corpo = enviar(app_com(simulador), b"0123456789", nome="../../etc/Meu pcap.pcap", consulta="so_teste=1")

    assert status == 200
    assert corpo == {"incidentes": []}
    dados, nome, caminho, so_teste, com_a_trava = simulador.recebido
    assert (dados, nome, so_teste, com_a_trava) == (b"0123456789", "Meu_pcap.pcap", True, True)
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


@pytest.mark.parametrize("erro", [PcapInvalido("a entrada não é um arquivo pcap"), SemTrechoDeTeste("x.pcap não tem trecho")])
def test_erro_do_arquivo_ou_do_pedido_vira_400_com_a_mensagem(erro):
    status, corpo = enviar(app_com(SimuladorFalso(erro=erro)), b"nao sou pcap")

    assert status == 400
    assert corpo["erro"] == str(erro)


def test_erro_do_servidor_vira_500_sem_detalhe():
    simulador = SimuladorFalso(erro=ValueError("o ponto de operação é de outro modelo"))

    status, corpo = enviar(app_com(simulador), b"pcap")

    assert status == 500
    assert "outro modelo" not in corpo["erro"]
    assert not simulador.trava.locked()


def test_enquanto_os_agentes_rodam_outra_simulacao_e_recusada():
    simulador = SimuladorFalso(agentes_rodando=True)

    status, corpo = enviar(app_com(simulador), b"pcap")

    assert status == 409
    assert "em andamento" in corpo["erro"]
    assert simulador.recebido is None


@pytest.mark.parametrize(("metodo", "caminho"), [
    ("GET", "/api/simulacao/atual"), ("POST", "/api/simulacao/decisao"), ("POST", "/api/simulacao/parar"),
])
def test_as_rotas_da_simulacao_em_andamento_pedem_o_cabecalho_da_interface(metodo, caminho):
    simulador = SimuladorFalso(em_andamento={"arquivo": "a.pcap"})

    status, _ = pedir(app_com(simulador), metodo, caminho, {"tipo": "aprovar", "id": "prop-0001"}, cabecalho=False)

    assert status == 403
    assert simulador.decisoes == []
    assert simulador.paradas == 0


def test_rota_atual_devolve_a_simulacao_e_nulo_quando_nao_ha_nenhuma():
    assert pedir(app_com(SimuladorFalso()), "GET", "/api/simulacao/atual") == (200, {"simulacao": None})
    assert pedir(app_com(SimuladorFalso(em_andamento={"arquivo": "a.pcap"})), "GET", "/api/simulacao/atual") == (
        200, {"simulacao": {"arquivo": "a.pcap"}},
    )


def test_rota_de_decisao_repassa_a_decisao_da_pessoa():
    simulador = SimuladorFalso()
    app = app_com(simulador)

    assert pedir(app, "POST", "/api/simulacao/decisao", {"tipo": "aprovar", "id": "prop-0001"})[0] == 200
    pedir(app, "POST", "/api/simulacao/decisao", {"tipo": "rejeitar", "id": "prop-0002", "motivo": "não pode parar"})
    pedir(app, "POST", "/api/simulacao/decisao", {"tipo": "resolvido", "id": "inc-0001", "motivo": ""})

    assert simulador.decisoes == [
        ("aprovar", "prop-0001", None), ("rejeitar", "prop-0002", "não pode parar"), ("resolvido", "inc-0001", None),
    ]


@pytest.mark.parametrize("corpo", [
    {"tipo": "promover", "id": "prop-0001"}, {"tipo": "aprovar"}, {"tipo": "aprovar", "id": 7},
    {"tipo": "rejeitar", "id": "prop-0001", "motivo": 3}, ["aprovar"],
])
def test_rota_de_decisao_recusa_pedido_fora_do_formato(corpo):
    simulador = SimuladorFalso()

    status, _ = pedir(app_com(simulador), "POST", "/api/simulacao/decisao", corpo)

    assert status == 400
    assert simulador.decisoes == []


@pytest.mark.parametrize("erro", [
    PedidoRecusado("identificador_desconhecido", "Não existe proposta com o identificador prop-0009."),
    SemSimulacaoEmAndamento("nenhuma simulação em andamento: a decisão não teria efeito"),
])
def test_decisao_que_nao_cabe_vira_409_com_a_mensagem(erro):
    status, corpo = pedir(app_com(SimuladorFalso(erro_da_decisao=erro)), "POST", "/api/simulacao/decisao", {"tipo": "aprovar", "id": "prop-0009"})

    assert status == 409
    assert corpo["erro"] == str(erro)


def test_rota_parar_chama_o_simulador():
    simulador = SimuladorFalso()

    assert pedir(app_com(simulador), "POST", "/api/simulacao/parar")[0] == 200
    assert simulador.paradas == 1


def test_nome_do_pcap_fica_so_com_o_ultimo_trecho_e_caracteres_seguros():
    assert nome_do_pcap("C:/x/../ataque 1.pcap") == "ataque_1.pcap"
    assert nome_do_pcap("") == "captura.pcap"
    assert nome_do_pcap("...") == "captura.pcap"


class OrquestradorFalso:
    """Devolve um desfecho por incidente, ou roda o que `acoes` disser, e guarda as chamadas."""

    def __init__(self, acoes=None, desfecho="resolvido"):
        self.acoes = acoes or {}
        self.desfecho = desfecho
        self.chamadas = []

    def __call__(self, incidente, **opcoes):
        self.chamadas.append((incidente, opcoes))
        if incidente in self.acoes:
            self.acoes[incidente](opcoes)
        return SimpleNamespace(desfecho=self.desfecho)


def falha(erro):
    def agir(_opcoes):
        raise erro

    return agir


def esperar_os_agentes(simulador, limite_s=30):
    """Espera os agentes terminarem e devolve a simulação como a tela a veria."""
    fim = time.monotonic() + limite_s
    while time.monotonic() < fim:
        atual = simulador.atual()
        if atual["agentes"]["estado"] not in ("rodando", "parando"):
            return atual
        time.sleep(0.01)
    raise AssertionError("os agentes não terminaram")


def esperar_evento(simulador, tipo, limite_s=30):
    fim = time.monotonic() + limite_s
    while time.monotonic() < fim:
        if any(json.loads(linha)["tipo"] == tipo for linha in simulador.atual()["eventos"].splitlines()):
            return
        time.sleep(0.01)
    raise AssertionError(f"o evento {tipo} não apareceu no log")


def pcap_com_dois_incidentes(pasta):
    """Dois ataques separados por mais que a janela de reagrupamento (`REAGRUPA_S`, 300 s)."""
    return escrever_pcap(pasta / "a.pcap", [benigno(2), ataque(5), benigno(12), ataque(5, pausa=400), benigno(12)])


def simulador_com(tmp_path, config=CONFIG, **opcoes):
    return Simulador(config, pasta=tmp_path / "simulacoes", classificador=classificador(), **opcoes)


def test_simulacao_grava_so_para_o_dono_e_devolve_o_log(tmp_path):
    pcap = escrever_pcap(tmp_path / "a.pcap", [benigno(2), ataque(5), benigno(10)])
    simulador = simulador_com(tmp_path, orquestrador=OrquestradorFalso())

    saida = simulador.simular(pcap, "a.pcap")

    assert [i["id"] for i in saida["incidentes"]] == ["inc-0001"]
    assert [json.loads(linha)["tipo"] for linha in saida["eventos"].splitlines()][:4] == [
        "janelas_classificadas", "incidente_aberto", "incidente_atualizado", "janelas_classificadas",
    ]
    esperar_os_agentes(simulador)
    pasta = next((tmp_path / "simulacoes").iterdir())
    assert pasta.stat().st_mode & 0o777 == 0o700
    for arquivo in ("eventos.jsonl", "eventos.cenarios.json", "resumo.json"):
        assert (pasta / arquivo).stat().st_mode & 0o777 == 0o600, arquivo
    assert "eventos" not in json.loads((pasta / "resumo.json").read_text())


def test_cada_incidente_vai_aos_agentes_na_ordem_com_o_modelo_local(tmp_path):
    orquestrador = OrquestradorFalso()
    simulador = simulador_com(tmp_path, orquestrador=orquestrador, provedor=object())

    saida = simulador.simular(pcap_com_dois_incidentes(tmp_path), "a.pcap")
    final = esperar_os_agentes(simulador)

    assert [i["id"] for i in saida["incidentes"]] == ["inc-0001", "inc-0002"]
    assert [incidente for incidente, _ in orquestrador.chamadas] == ["inc-0001", "inc-0002"]
    opcoes = orquestrador.chamadas[0][1]
    assert opcoes["configuracao"] == "local"
    assert opcoes["perfis"]["local"].modelo == "modelo-local"
    assert opcoes["rodada_apos_rejeicao"] is True
    assert opcoes["sumario"] is True
    assert str(opcoes["log"]).endswith("eventos.jsonl")
    assert str(opcoes["cenarios"]).endswith("eventos.cenarios.json")
    assert final["agentes"]["estado"] == "concluidos"
    assert final["agentes"]["modelo"] == "modelo-local"
    assert final["agentes"]["incidentes"] == [
        {"id": "inc-0001", "situacao": "concluido", "desfecho": "resolvido", "erro": None},
        {"id": "inc-0002", "situacao": "concluido", "desfecho": "resolvido", "erro": None},
    ]


def test_sem_incidente_os_agentes_nao_rodam(tmp_path):
    orquestrador = OrquestradorFalso()
    simulador = simulador_com(tmp_path, orquestrador=orquestrador)

    saida = simulador.simular(escrever_pcap(tmp_path / "b.pcap", [benigno(4)]), "b.pcap")

    assert saida["incidentes"] == []
    assert saida["janelas"] == 4
    assert saida["agentes"]["estado"] == "sem_incidentes"
    assert orquestrador.chamadas == []
    assert not simulador.ocupado()


def test_sem_o_modelo_configurado_a_simulacao_para_nos_incidentes_e_diz_o_que_falta(tmp_path):
    orquestrador = OrquestradorFalso()
    simulador = simulador_com(tmp_path, config=SEM_MODELO, orquestrador=orquestrador)

    saida = simulador.simular(pcap_com_dois_incidentes(tmp_path), "a.pcap")

    assert saida["agentes"]["estado"] == "sem_modelo"
    assert "LLM_BASE_URL" in saida["agentes"]["motivo"]
    assert [i["situacao"] for i in saida["agentes"]["incidentes"]] == ["na_fila", "na_fila"]
    assert orquestrador.chamadas == []
    assert not simulador.ocupado()


def test_erro_em_um_incidente_nao_impede_o_seguinte_e_nao_vaza_detalhe_inesperado(tmp_path):
    orquestrador = OrquestradorFalso({"inc-0001": falha(ErroDoProvedor("o modelo não respondeu"))})
    simulador = simulador_com(tmp_path, orquestrador=orquestrador)

    simulador.simular(pcap_com_dois_incidentes(tmp_path), "a.pcap")
    final = esperar_os_agentes(simulador)

    primeiro, segundo = final["agentes"]["incidentes"]
    assert primeiro["situacao"] == "erro"
    assert "o modelo não respondeu" in primeiro["erro"]
    assert segundo["situacao"] == "concluido"
    assert final["agentes"]["estado"] == "concluidos"


def test_falha_inesperada_fica_sem_o_detalhe_na_tela(tmp_path):
    orquestrador = OrquestradorFalso({"inc-0001": falha(RuntimeError("segredo interno"))})
    simulador = simulador_com(tmp_path, orquestrador=orquestrador)

    simulador.simular(pcap_com_dois_incidentes(tmp_path), "a.pcap")
    final = esperar_os_agentes(simulador)

    assert final["agentes"]["incidentes"][0]["situacao"] == "erro"
    assert "segredo" not in final["agentes"]["incidentes"][0]["erro"]
    assert final["agentes"]["incidentes"][1]["situacao"] == "concluido"


def test_parar_interrompe_a_espera_pela_pessoa_e_deixa_o_resto_na_fila(tmp_path):
    entrou = threading.Event()

    def espera_a_pessoa(opcoes):
        entrou.set()
        opcoes["esperar"](3600)

    orquestrador = OrquestradorFalso({"inc-0001": espera_a_pessoa})
    simulador = simulador_com(tmp_path, orquestrador=orquestrador)
    simulador.simular(pcap_com_dois_incidentes(tmp_path), "a.pcap")
    assert entrou.wait(10)

    simulador.parar()
    final = esperar_os_agentes(simulador)

    assert final["agentes"]["estado"] == "interrompidos"
    assert [i["situacao"] for i in final["agentes"]["incidentes"]] == ["interrompido", "na_fila"]
    assert [incidente for incidente, _ in orquestrador.chamadas] == ["inc-0001"]
    assert not simulador.ocupado()


def test_o_estado_final_dos_agentes_fica_no_resumo_da_pasta(tmp_path):
    simulador = simulador_com(tmp_path, orquestrador=OrquestradorFalso())

    simulador.simular(pcap_com_dois_incidentes(tmp_path), "a.pcap")
    esperar_os_agentes(simulador)

    resumo = next((tmp_path / "simulacoes").iterdir()) / "resumo.json"
    assert json.loads(resumo.read_text())["agentes"]["estado"] == "concluidos"


def test_decisao_sem_simulacao_em_andamento_e_recusada(tmp_path):
    simulador = simulador_com(tmp_path, orquestrador=OrquestradorFalso())

    with pytest.raises(SemSimulacaoEmAndamento):
        simulador.decidir("aprovar", "prop-0001")

    simulador.simular(pcap_com_dois_incidentes(tmp_path), "a.pcap")
    esperar_os_agentes(simulador)
    with pytest.raises(SemSimulacaoEmAndamento):
        simulador.decidir("aprovar", "prop-0001")


def do_pcap_ao_sumario(incidente="inc-0001"):
    """As respostas do modelo num incidente que pede a aprovação de uma pessoa."""
    return [
        *triagem(incidente),
        *decisao(incidente, "isolar_dispositivo", "destino-1", {}),
        *execucao("prop-0001", "exec-0001"),
        resposta("O incidente foi tratado e o efeito verificado."),
    ]


def test_o_pcap_vira_incidente_e_segue_ate_o_sumario_com_a_aprovacao_pela_interface(tmp_path):
    pcap = escrever_pcap(tmp_path / "a.pcap", [benigno(2), ataque(5), benigno(10)])
    simulador = simulador_com(tmp_path, provedor=ProvedorFalso(*do_pcap_ao_sumario()))

    simulador.simular(pcap, "a.pcap")
    esperar_evento(simulador, "acao_proposta")
    assert simulador.atual()["agentes"]["estado"] == "rodando"

    simulador.decidir("aprovar", "prop-0001")
    final = esperar_os_agentes(simulador)

    assert final["agentes"]["incidentes"] == [{"id": "inc-0001", "situacao": "concluido", "desfecho": "resolvido", "erro": None}]
    log = next((tmp_path / "simulacoes").iterdir()) / "eventos.jsonl"
    tipos = [evento.tipo for evento in ler(log)]
    for tipo in ("analise_emitida", "acao_proposta", "acao_aprovada", "acao_executada", "efeito_verificado", "sumario_emitido"):
        assert tipo in tipos, tipo
    aprovacao = next(evento for evento in ler(log) if evento.tipo == "acao_aprovada")
    assert aprovacao.dados.canal == "interface"
    assert reconstruir(ler(log)).incidentes["inc-0001"].estado == "encerrado"
    assert final["agentes"]["configuracao"] == "local"


def test_rejeitar_com_motivo_pela_interface_devolve_a_vez_a_decisao(tmp_path):
    pcap = escrever_pcap(tmp_path / "a.pcap", [benigno(2), ataque(5), benigno(10)])
    provedor = ProvedorFalso(
        *triagem("inc-0001"),
        *decisao("inc-0001", "isolar_dispositivo", "destino-1", {}),
        resposta("Não há outra ação que respeite o motivo."),
        resposta("A pessoa rejeitou a proposta."),
    )
    simulador = simulador_com(tmp_path, provedor=provedor)

    simulador.simular(pcap, "a.pcap")
    esperar_evento(simulador, "acao_proposta")
    simulador.decidir("rejeitar", "prop-0001", "o dispositivo não pode parar")
    final = esperar_os_agentes(simulador)

    assert final["agentes"]["incidentes"][0]["desfecho"] == "todas_rejeitadas"
    log = next((tmp_path / "simulacoes").iterdir()) / "eventos.jsonl"
    rejeicao = next(evento for evento in ler(log) if evento.tipo == "acao_rejeitada")
    assert (rejeicao.dados.canal, rejeicao.dados.motivo) == ("interface", "o dispositivo não pode parar")


def test_so_teste_pula_o_trecho_de_treino_pelo_manifesto(tmp_path, monkeypatch):
    from codigo.api import simulacao

    manifesto = tmp_path / "m.json"
    manifesto.write_text(json.dumps({
        "pcaps": [{"arquivo": "a.pcap", "janelas": {"100": {"extraidas": 20}}}], "rotulos": [{"arquivos": ["a.pcap"]}],
    }))
    monkeypatch.setattr(simulacao, "MANIFESTO", manifesto)
    pcap = escrever_pcap(tmp_path / "a.pcap", [ataque(14), benigno(6)])
    simulador = simulador_com(tmp_path, orquestrador=OrquestradorFalso())

    saida = simulador.simular(pcap, "a.pcap", so_teste=True)

    assert saida["janelas_puladas"] == 14
    assert saida["trecho"] == {"a_partir_da_janela": 14, "so_teste": True}
    assert saida["incidentes"] == []
    with pytest.raises(SemTrechoDeTeste):
        simulador.simular(pcap, "outro.pcap", so_teste=True)
