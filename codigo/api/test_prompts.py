"""Testes da leitura das skills dos agentes como prompts de sistema."""

from codigo.api.prompts import ler_prompts


def skill(pasta, nome, texto):
    (pasta / nome).mkdir()
    (pasta / nome / "SKILL.md").write_text(texto, encoding="utf-8")


def test_le_cada_pasta_com_skill_sem_o_cabecalho_e_com_o_primeiro_titulo(tmp_path):
    skill(tmp_path, "triagem-do-alerta", "---\nname: triagem-do-alerta\ndescription: x\n---\n\n# Triagem do alerta\n\nCorpo da skill.\n")

    prompts = ler_prompts(tmp_path)

    assert prompts == [{"nome": "triagem-do-alerta", "titulo": "Triagem do alerta", "texto": "# Triagem do alerta\n\nCorpo da skill."}]


def test_ordena_por_nome_e_ignora_pasta_sem_skill_e_arquivo_solto(tmp_path):
    skill(tmp_path, "recomendacao", "# Recomendação\n\ntexto")
    skill(tmp_path, "analise", "# Análise\n\ntexto")
    (tmp_path / "sem-skill").mkdir()
    (tmp_path / "README.md").write_text("# nada", encoding="utf-8")

    assert [p["nome"] for p in ler_prompts(tmp_path)] == ["analise", "recomendacao"]


def test_sem_cabecalho_e_sem_titulo_o_titulo_e_o_nome_da_pasta(tmp_path):
    skill(tmp_path, "execucao-da-acao", "Só texto, sem título.\n")

    [prompt] = ler_prompts(tmp_path)

    assert prompt["titulo"] == "execucao-da-acao"
    assert prompt["texto"] == "Só texto, sem título."


def test_cabecalho_sem_fechamento_fica_como_texto(tmp_path):
    skill(tmp_path, "x", "---\nname: x\n# Título\n")

    [prompt] = ler_prompts(tmp_path)

    assert prompt["texto"].startswith("---")
    assert prompt["titulo"] == "Título"


def test_pasta_inexistente_ou_vazia_devolve_lista_vazia(tmp_path):
    assert ler_prompts(tmp_path) == []
    assert ler_prompts(tmp_path / "nao-existe") == []
