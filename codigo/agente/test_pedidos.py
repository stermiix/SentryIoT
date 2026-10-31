"""Testes dos pedidos aos modelos, sem provedor."""

import re

import pytest

from codigo.agente.pedidos import PASTA_DE_SKILLS

SKILLS_DO_REPOSITORIO = sorted(pasta.name for pasta in PASTA_DE_SKILLS.iterdir() if (pasta / "SKILL.md").is_file())


@pytest.mark.parametrize("nome", SKILLS_DO_REPOSITORIO)
def test_o_cabecalho_de_cada_skill_tem_o_nome_da_pasta_e_uma_descricao_em_yaml_valido(nome):
    texto = (PASTA_DE_SKILLS / nome / "SKILL.md").read_text(encoding="utf-8")

    cabecalho = re.match(r"---\n(.*?)\n---\n", texto, re.DOTALL)
    assert cabecalho, f"{nome}: sem cabeçalho YAML"
    campos = dict(linha.split(": ", 1) for linha in cabecalho.group(1).splitlines())
    assert campos["name"] == nome
    descricao = campos["description"]
    # Texto simples em YAML não pode ter ": " nem " #" no meio; com isso, é preciso pôr a descrição entre aspas.
    if not descricao.startswith(('"', "'")):
        assert ": " not in descricao and " #" not in descricao
