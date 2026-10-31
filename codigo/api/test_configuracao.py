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


# --- o conjunto da nuvem (LLM_NUVEM_*) -------------------------------------------------------

NUVEM = {"LLM_NUVEM_BASE_URL": "https://n/v1/", "LLM_NUVEM_API_KEY": "k-n", "LLM_NUVEM_MODEL": "claude"}


def test_o_conjunto_da_nuvem_le_as_variaveis_com_o_prefixo_dele():
    config = Configuracao.do_ambiente({**NUVEM, "LLM_BASE_URL": "https://local/v1", "LLM_MODEL": "qwen"}, "LLM_NUVEM_")

    assert (config.url_base, config.chave, config.modelo) == ("https://n/v1", "k-n", "claude")
    assert config.faltando() == []


def test_os_dois_conjuntos_nao_se_misturam():
    ambiente = {"LLM_BASE_URL": "https://local/v1", "LLM_API_KEY": "k-l", "LLM_MODEL": "qwen", **NUVEM}

    local = Configuracao.do_ambiente(ambiente)
    nuvem = Configuracao.do_ambiente(ambiente, "LLM_NUVEM_")

    assert (local.modelo, local.chave) == ("qwen", "k-l")
    assert (nuvem.modelo, nuvem.chave) == ("claude", "k-n")


def test_faltando_diz_o_nome_do_conjunto_que_foi_lido():
    nuvem = Configuracao.do_ambiente({"LLM_NUVEM_MODEL": "claude"}, "LLM_NUVEM_")

    assert nuvem.faltando() == ["LLM_NUVEM_BASE_URL", "LLM_NUVEM_API_KEY"]


def test_parametros_e_ca_da_nuvem_vem_das_variaveis_dela_e_nao_das_do_local():
    ambiente = {
        **NUVEM, "LLM_RACIOCINIO": "desligado", "LLM_CA_BUNDLE": "/x/ca-interna.pem",
        "LLM_NUVEM_TEMPERATURA": "0.2", "LLM_NUVEM_TIMEOUT_S": "90",
    }

    nuvem = Configuracao.do_ambiente(ambiente, "LLM_NUVEM_")

    assert nuvem.parametros() == {"temperature": 0.2}
    assert (nuvem.ca, nuvem.prazo_s) == (None, 90)


def test_erro_de_parametro_da_nuvem_cita_a_variavel_da_nuvem():
    with pytest.raises(ValueError, match="LLM_NUVEM_TEMPERATURA"):
        Configuracao.do_ambiente({"LLM_NUVEM_TEMPERATURA": "9"}, "LLM_NUVEM_")


def test_provedores_do_openrouter_vao_em_provider_only():
    config = Configuracao.do_ambiente({**NUVEM, "LLM_NUVEM_PROVEDORES": " anthropic , "}, "LLM_NUVEM_")

    assert config.parametros() == {"provider": {"only": ["anthropic"]}}
    assert Configuracao.do_ambiente(NUVEM, "LLM_NUVEM_").parametros() == {}
