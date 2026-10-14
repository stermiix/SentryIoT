"""Testes da leitura do `.env` e da configuração do provedor."""

import os

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


def test_faltando_lista_as_obrigatorias_em_branco():
    config = Configuracao.do_ambiente({"LLM_BASE_URL": "", "LLM_MODEL": "m"})

    assert config.faltando() == ["LLM_BASE_URL", "LLM_API_KEY"]
