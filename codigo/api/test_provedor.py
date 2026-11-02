"""Testes do cliente do provedor de LLM, sem rede: a função que abre a conexão é trocada."""

import dataclasses
import io
import json
import socket
import urllib.error

import pytest

from codigo.agente.laco import rodar
from codigo.api.configuracao import Configuracao
from codigo.api.provedor import ErroDoProvedor, Provedor

CONFIG = Configuracao(url_base="https://gateway.exemplo/v1", chave="chave-x", modelo="m-1")


class RespostaFalsa(io.BytesIO):
    """O que `urlopen` devolve: um arquivo com o corpo, usado como gerenciador de contexto."""

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def abrir_que_lanca(erro):
    def abrir(pedido, timeout=None, context=None):
        raise erro

    return abrir


def abrir_com(corpo, capturado):
    def abrir(pedido, timeout=None, context=None):
        capturado["url"] = pedido.full_url
        capturado["cabecalhos"] = {k.lower(): v for k, v in pedido.header_items()}
        capturado["corpo"] = json.loads(pedido.data.decode("utf-8"))
        capturado["timeout"] = timeout
        return RespostaFalsa(json.dumps(corpo).encode("utf-8"))

    return abrir


def test_chat_monta_o_pedido_e_le_a_resposta_com_tokens():
    capturado = {}
    corpo = {
        "model": "m-1",
        "choices": [{"message": {"role": "assistant", "content": "Olá."}}],
        "usage": {"prompt_tokens": 12, "completion_tokens": 3},
    }
    provedor = Provedor(CONFIG, abrir=abrir_com(corpo, capturado))

    resposta = provedor.chat("m-1", "Seja breve.", [{"papel": "usuario", "conteudo": "Oi"}])

    assert resposta.conteudo == "Olá."
    assert resposta.modelo == "m-1"
    assert (resposta.tokens_entrada, resposta.tokens_saida) == (12, 3)
    assert capturado["url"] == "https://gateway.exemplo/v1/chat/completions"
    assert capturado["cabecalhos"]["authorization"] == "Bearer chave-x"
    assert capturado["timeout"] == CONFIG.prazo_s
    assert capturado["corpo"] == {
        "model": "m-1",
        "stream": False,
        "messages": [{"role": "system", "content": "Seja breve."}, {"role": "user", "content": "Oi"}],
    }


def test_parametros_de_geracao_da_configuracao_vao_no_corpo():
    capturado = {}
    config = dataclasses.replace(CONFIG, temperatura=0.0, semente=7, max_tokens=512, raciocinio=False)
    provedor = Provedor(config, abrir=abrir_com({"choices": [{"message": {"content": "ok"}}]}, capturado))

    provedor.chat("m-1", "", [{"papel": "usuario", "conteudo": "Oi"}])

    assert capturado["corpo"]["temperature"] == 0.0
    assert capturado["corpo"]["seed"] == 7
    assert capturado["corpo"]["max_tokens"] == 512
    assert capturado["corpo"]["chat_template_kwargs"] == {"enable_thinking": False}


def test_sem_prompt_de_sistema_nao_manda_mensagem_de_sistema():
    capturado = {}
    corpo = {"choices": [{"message": {"content": "ok"}}]}
    provedor = Provedor(CONFIG, abrir=abrir_com(corpo, capturado))

    provedor.chat("m-1", "", [{"papel": "usuario", "conteudo": "Oi"}, {"papel": "assistente", "conteudo": "Olá"}, {"papel": "usuario", "conteudo": "Tudo bem?"}])

    assert capturado["corpo"]["messages"] == [
        {"role": "user", "content": "Oi"},
        {"role": "assistant", "content": "Olá"},
        {"role": "user", "content": "Tudo bem?"},
    ]


def test_provedor_sem_campo_de_uso_devolve_tokens_nulos_e_modelo_pedido():
    corpo = {"choices": [{"message": {"content": "ok"}}]}
    provedor = Provedor(CONFIG, abrir=abrir_com(corpo, {}))

    resposta = provedor.chat("m-1", "", [{"papel": "usuario", "conteudo": "Oi"}])

    assert (resposta.tokens_entrada, resposta.tokens_saida) == (None, None)
    assert resposta.modelo == "m-1"


def test_resposta_sem_texto_vem_com_conteudo_vazio():
    corpo = {"choices": [{"message": {"content": None, "reasoning": "pensando"}}]}
    provedor = Provedor(CONFIG, abrir=abrir_com(corpo, {}))

    assert provedor.chat("m-1", "", [{"papel": "usuario", "conteudo": "Oi"}]).conteudo == ""


@pytest.mark.parametrize("codigo", [429, 500])
def test_erro_http_do_provedor_vira_erro_com_codigo_e_mensagem_cortada(codigo):
    detalhe = json.dumps({"error": {"message": "x" * 600}}).encode("utf-8")
    provedor = Provedor(CONFIG, abrir=abrir_que_lanca(urllib.error.HTTPError("https://g", codigo, "erro", {}, io.BytesIO(detalhe))))
    with pytest.raises(ErroDoProvedor) as erro:
        provedor.chat("m-1", "", [{"papel": "usuario", "conteudo": "Oi"}])

    assert erro.value.codigo == codigo
    assert len(erro.value.mensagem) == 500
    assert erro.value.mensagem.startswith('{"error"')


def test_prazo_estourado_vira_erro_sem_codigo():
    provedor = Provedor(CONFIG, abrir=abrir_que_lanca(TimeoutError("timed out")), esperar=lambda _: None)
    with pytest.raises(ErroDoProvedor) as erro:
        provedor.chat("m-1", "", [{"papel": "usuario", "conteudo": "Oi"}])

    assert erro.value.codigo is None
    assert "prazo" in erro.value.mensagem


def test_prazo_estourado_na_conexao_tambem_vira_erro_de_prazo():
    # Na abertura da conexão, a biblioteca padrão embrulha o estouro num URLError.
    provedor = Provedor(CONFIG, abrir=abrir_que_lanca(urllib.error.URLError(TimeoutError("timed out"))), esperar=lambda _: None)
    with pytest.raises(ErroDoProvedor) as erro:
        provedor.chat("m-1", "", [{"papel": "usuario", "conteudo": "Oi"}])

    assert erro.value.codigo is None
    assert "prazo" in erro.value.mensagem


def test_falha_de_rede_vira_erro_sem_codigo():
    provedor = Provedor(CONFIG, abrir=abrir_que_lanca(urllib.error.URLError(socket.gaierror("nome desconhecido"))))
    with pytest.raises(ErroDoProvedor) as erro:
        provedor.chat("m-1", "", [{"papel": "usuario", "conteudo": "Oi"}])

    assert erro.value.codigo is None
    assert "nome desconhecido" in erro.value.mensagem


def test_resposta_que_nao_e_json_vira_erro():
    def abrir(pedido, timeout=None, context=None):
        return RespostaFalsa(b"<html>fora do ar</html>")

    provedor = Provedor(CONFIG, abrir=abrir)
    with pytest.raises(ErroDoProvedor) as erro:
        provedor.chat("m-1", "", [{"papel": "usuario", "conteudo": "Oi"}])

    assert erro.value.codigo is None


def test_ca_do_env_entra_no_contexto_tls(tmp_path):
    # Um PEM inválido faz o `ssl` recusar na montagem do contexto: prova que o arquivo é lido.
    pem = tmp_path / "ca.pem"
    pem.write_text("isto nao e um certificado")
    config = Configuracao(url_base="https://g/v1", chave="k", modelo="m", ca=str(pem))

    with pytest.raises(Exception, match="(?i)pem|cert"):
        Provedor(config, abrir=lambda *a, **k: None)


# --- nova tentativa nas falhas passageiras (teste de 31/10) -----------------------------------------

CORPO_CERTO = {"choices": [{"message": {"content": "ok"}}], "usage": {"prompt_tokens": 5, "completion_tokens": 1}}


def abrir_em_sequencia(*falhas):
    """Lança as falhas na ordem e, depois delas, responde com o corpo certo. Conta as tentativas."""
    pendentes = list(falhas)

    def abrir(pedido, timeout=None, context=None):
        abrir.tentativas += 1
        if pendentes:
            raise pendentes.pop(0)
        return RespostaFalsa(json.dumps(CORPO_CERTO).encode("utf-8"))

    abrir.tentativas = 0
    return abrir


def erro_http(codigo):
    return urllib.error.HTTPError("https://g", codigo, "erro", {}, io.BytesIO(b"fora"))


@pytest.mark.parametrize(
    "falha",
    [
        ConnectionResetError(54, "Connection reset by peer"),
        urllib.error.URLError(ConnectionRefusedError(61, "Connection refused")),
        TimeoutError("timed out"),
        urllib.error.URLError(TimeoutError("timed out")),
        erro_http(502),
        erro_http(503),
        erro_http(504),
    ],
)
def test_falha_passageira_e_tentada_de_novo_depois_de_esperar(falha):
    abrir = abrir_em_sequencia(falha)
    esperas = []
    provedor = Provedor(CONFIG, abrir=abrir, esperar=esperas.append)

    resposta = provedor.conversar("m-1", [{"role": "user", "content": "Oi"}])

    assert resposta.conteudo == "ok"
    assert abrir.tentativas == 2
    assert esperas == [3]


def test_depois_de_duas_novas_tentativas_o_erro_sobe_como_antes():
    abrir = abrir_em_sequencia(*[ConnectionResetError(54, "Connection reset by peer")] * 3)
    esperas = []
    provedor = Provedor(CONFIG, abrir=abrir, esperar=esperas.append)

    with pytest.raises(ErroDoProvedor) as erro:
        provedor.conversar("m-1", [{"role": "user", "content": "Oi"}])

    assert erro.value.mensagem == "falha ao falar com o provedor: [Errno 54] Connection reset by peer"
    assert erro.value.codigo is None and erro.value.passageiro
    assert abrir.tentativas == 3
    assert esperas == [3, 6]


@pytest.mark.parametrize(
    "falha",
    [
        erro_http(400),
        erro_http(401),
        erro_http(429),
        erro_http(500),
        urllib.error.URLError(socket.gaierror("nome desconhecido")),
    ],
)
def test_falha_que_nao_e_passageira_nao_e_tentada_de_novo(falha):
    abrir = abrir_em_sequencia(falha)
    esperas = []
    provedor = Provedor(CONFIG, abrir=abrir, esperar=esperas.append)

    with pytest.raises(ErroDoProvedor) as erro:
        provedor.conversar("m-1", [{"role": "user", "content": "Oi"}])

    assert not erro.value.passageiro
    assert abrir.tentativas == 1
    assert esperas == []


def test_resposta_que_nao_e_json_nao_e_tentada_de_novo():
    tentativas = []

    def abrir(pedido, timeout=None, context=None):
        tentativas.append(pedido)
        return RespostaFalsa(b"<html>fora do ar</html>")

    esperas = []
    with pytest.raises(ErroDoProvedor):
        Provedor(CONFIG, abrir=abrir, esperar=esperas.append).conversar("m-1", [{"role": "user", "content": "Oi"}])

    assert len(tentativas) == 1 and esperas == []


def test_content_filter_chega_numa_resposta_normal_e_nao_e_tentado_de_novo():
    corpo = {"choices": [{"message": {"content": ""}, "finish_reason": "content_filter"}]}
    esperas = []

    resposta = Provedor(CONFIG, abrir=abrir_com(corpo, {}), esperar=esperas.append).conversar("m-1", [{"role": "user", "content": "Oi"}])

    assert resposta.motivo_termino == "content_filter"
    assert esperas == []


def test_as_esperas_e_o_numero_de_tentativas_sao_configuraveis():
    abrir = abrir_em_sequencia(*[erro_http(503)] * 2)
    esperas = []
    provedor = Provedor(CONFIG, abrir=abrir, esperar=esperas.append, esperas_s=(0.5,))

    with pytest.raises(ErroDoProvedor) as erro:
        provedor.chat("m-1", "", [{"papel": "usuario", "conteudo": "Oi"}])

    assert erro.value.codigo == 503
    assert abrir.tentativas == 2
    assert esperas == [0.5]


def test_no_laco_a_chamada_que_precisou_de_nova_tentativa_vira_uma_chamada_so():
    # O llm_chamada sai de `ao_chamar`, uma vez por resposta que chegou: a tentativa que falhou não aparece.
    recebidas = []
    provedor = Provedor(CONFIG, abrir=abrir_em_sequencia(ConnectionResetError(54, "reset")), esperar=lambda _: None)

    resultado = rodar(provedor, "m-1", [{"role": "user", "content": "Oi"}], [], lambda *_: None, ao_chamar=recebidas.append)

    assert resultado.terminou_bem
    assert len(recebidas) == 1 and (recebidas[0].tokens_entrada, recebidas[0].tokens_saida) == (5, 1)
