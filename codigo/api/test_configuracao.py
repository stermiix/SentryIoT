"""Testes da leitura do `.env` e da configuração do provedor."""

import os

import pytest

from codigo.api.configuracao import Configuracao, carregar_env


def test_carregar_env_le_chave_valor_e_ignora_comentarios_e_aspas(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text('# comentario\nLLM_BASE_URL = "https://g/v1" \nLLM_API_KEY=\'k\'\n\nsem_igual\nLLM_MODEL=m\n')
    for nome in ("LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL"):
        monkeypatch.delenv(nome, raising=False)

    carregar_env(str(env))

    assert os.environ["LLM_BASE_URL"] == "https://g/v1"
    assert os.environ["LLM_API_KEY"] == "k"
    assert os.environ["LLM_MODEL"] == "m"


def test_carregar_env_nao_sobrescreve_variavel_ja_definida(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("LLM_MODEL=do-arquivo\n")
    monkeypatch.setenv("LLM_MODEL", "do-ambiente")

    carregar_env(str(env))

    assert os.environ["LLM_MODEL"] == "do-ambiente"


def test_carregar_env_sem_arquivo_nao_falha(tmp_path):
    carregar_env(str(tmp_path / "nao-existe"))


def test_configuracao_do_ambiente_com_padroes():
    config = Configuracao.do_ambiente({"LLM_BASE_URL": "https://g/v1/", "LLM_API_KEY": "k", "LLM_MODEL": "m"})

    assert config.url_base == "https://g/v1"
    assert config.ca is None
    assert config.prazo_s == 300
    assert config.faltando() == []


def test_configuracao_le_ca_e_prazo():
    config = Configuracao.do_ambiente(
        {"LLM_BASE_URL": "https://g/v1", "LLM_API_KEY": "k", "LLM_MODEL": "m", "LLM_CA_BUNDLE": "/x/ca.pem", "LLM_TIMEOUT_S": "45"}
    )

    assert config.ca == "/x/ca.pem"
    assert config.prazo_s == 45


def test_modelos_permitidos_sem_a_variavel_e_so_o_padrao():
    config = Configuracao.do_ambiente({"LLM_BASE_URL": "https://g/v1", "LLM_API_KEY": "k", "LLM_MODEL": "m-1"})

    assert config.modelos_permitidos == ("m-1",)


def test_modelos_permitidos_le_a_lista_com_espacos_e_poe_o_padrao_na_frente():
    config = Configuracao.do_ambiente(
        {"LLM_BASE_URL": "https://g/v1", "LLM_API_KEY": "k", "LLM_MODEL": "m-1", "LLM_MODELOS_PERMITIDOS": " m-2 , m-3,, m-1 "}
    )

    assert config.modelos_permitidos == ("m-1", "m-2", "m-3")


def test_modelos_poe_o_padrao_na_frente_mesmo_quando_a_lista_vem_sem_ele():
    config = Configuracao(url_base="https://g/v1", chave="k", modelo="m-1", modelos_permitidos=("m-2", "m-3"))

    assert config.modelos() == ("m-1", "m-2", "m-3")


def test_faltando_lista_as_obrigatorias_em_branco():
    config = Configuracao.do_ambiente({"LLM_BASE_URL": "", "LLM_MODEL": "m"})

    assert config.faltando() == ["LLM_BASE_URL", "LLM_API_KEY"]


def test_parametros_de_geracao_ficam_de_fora_sem_as_variaveis():
    config = Configuracao.do_ambiente({"LLM_BASE_URL": "https://g/v1", "LLM_API_KEY": "k", "LLM_MODEL": "m"})

    assert config.parametros() == {}


def test_parametros_de_geracao_lidos_do_ambiente_com_os_nomes_do_corpo():
    config = Configuracao.do_ambiente({
        "LLM_TEMPERATURA": "0", "LLM_SEMENTE": "7", "LLM_MAX_TOKENS": "2048", "LLM_RACIOCINIO": "Desligado",
    })

    assert config.parametros() == {
        "temperature": 0.0, "seed": 7, "max_tokens": 2048, "chat_template_kwargs": {"enable_thinking": False},
    }
    assert Configuracao.do_ambiente({"LLM_RACIOCINIO": "ligado"}).parametros() == {"chat_template_kwargs": {"enable_thinking": True}}


@pytest.mark.parametrize(("variavel", "valor", "trecho"), [
    ("LLM_TEMPERATURA", "quente", "precisa ser um número"),
    ("LLM_TEMPERATURA", "3", "entre 0 e 2"),
    ("LLM_SEMENTE", "1.5", "número inteiro"),
    ("LLM_MAX_TOKENS", "0", "a partir de 1"),
    ("LLM_RACIOCINIO", "sim", "ligado ou desligado"),
])
def test_parametro_de_geracao_invalido_e_erro_com_o_nome_da_variavel(variavel, valor, trecho):
    with pytest.raises(ValueError, match=variavel) as erro:
        Configuracao.do_ambiente({variavel: valor})
    assert trecho in str(erro.value)
