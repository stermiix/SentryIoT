"""Testes do cliente do provedor de LLM, sem rede: a função que abre a conexão é trocada."""

import dataclasses
import io
import json
import socket
import urllib.error

import pytest

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
    provedor = Provedor(CONFIG, abrir=abrir_que_lanca(TimeoutError("timed out")))
    with pytest.raises(ErroDoProvedor) as erro:
        provedor.chat("m-1", "", [{"papel": "usuario", "conteudo": "Oi"}])

    assert erro.value.codigo is None
    assert "prazo" in erro.value.mensagem


def test_prazo_estourado_na_conexao_tambem_vira_erro_de_prazo():
    # Na abertura da conexão, a biblioteca padrão embrulha o estouro num URLError.
    provedor = Provedor(CONFIG, abrir=abrir_que_lanca(urllib.error.URLError(TimeoutError("timed out"))))
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
