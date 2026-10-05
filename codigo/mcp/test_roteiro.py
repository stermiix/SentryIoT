import pytest

from codigo.mcp import roteiro
from codigo.mcp.acoes import ambiente, reconstruir
from codigo.mcp.eventos import GravadorDoAgente, ler
from codigo.mcp.roteiro import SAIDA_PADRAO, executar, main
from codigo.mcp.tipos import AGENTES, TIPOS_DE_EVENTO, TOOLS

AGENTES_DA_TOOL = {tool.nome: tool.agentes for tool in TOOLS}


def test_log_de_exemplo_versionado_e_igual_ao_que_o_roteiro_gera(tmp_path):
    gerado = tmp_path / "incidente_flood.jsonl"
    executar(gerado)
    assert SAIDA_PADRAO.name == "incidente_flood.jsonl"
    assert SAIDA_PADRAO.read_bytes() == gerado.read_bytes(), (
        "o log de exemplo está desatualizado; gere de novo com: python -m codigo.mcp.roteiro --sobrescrever"
    )


def test_roteiro_gera_sempre_o_mesmo_arquivo_e_so_substitui_o_anterior_a_pedido(tmp_path):
    saida = tmp_path / "exemplo.jsonl"
    executar(saida)
    primeiro = saida.read_bytes()
    executar(saida, sobrescrever=True)
    assert saida.read_bytes() == primeiro
    with pytest.raises(FileExistsError, match="--sobrescrever"):
        executar(saida)
    assert saida.read_bytes() == primeiro


def test_main_nao_apaga_um_arquivo_que_ja_existe_sem_sobrescrever(tmp_path, capsys):
    # Antes, `--saida` apagava o arquivo indicado, fosse ele o que fosse, antes de gravar.
    de_outra_coisa = tmp_path / "anotacoes.txt"
    de_outra_coisa.write_text("conteúdo que não é um log\n", encoding="utf-8")
    assert main(["--saida", str(de_outra_coisa)]) == 1
    erro = capsys.readouterr().err
    assert erro.startswith("erro: ") and "já existe" in erro and "--sobrescrever" in erro
    assert de_outra_coisa.read_text(encoding="utf-8") == "conteúdo que não é um log\n"

    assert main(["--saida", str(de_outra_coisa), "--sobrescrever"]) == 0
    assert de_outra_coisa.read_bytes() == SAIDA_PADRAO.read_bytes()


def test_sem_sobrescrever_o_exemplo_versionado_nao_e_tocado(capsys):
    antes = SAIDA_PADRAO.read_bytes()
    assert main([]) == 1
    assert "--sobrescrever" in capsys.readouterr().err
    assert SAIDA_PADRAO.read_bytes() == antes


def test_no_exemplo_o_incidente_termina_quando_a_acao_que_o_resolveu_e_aplicada():
    eventos = ler(SAIDA_PADRAO)
    encerrado = next(evento for evento in eventos if evento.tipo == "incidente_encerrado")
    resolveu = [evento.dados for evento in eventos if evento.tipo == "acao_executada"][-1]
    assert encerrado.dados.fim == resolveu.aplicada_em
    assert encerrado.dados.inicio < encerrado.dados.fim <= encerrado.instante


def test_no_roteiro_o_papel_dos_agentes_grava_pelo_gravador_restrito(tmp_path, monkeypatch):
    # O roteiro é também o exemplo de como o código dos agentes escreve no log.
    usados = []

    class Espiao(GravadorDoAgente):
        def gravar(self, *rascunhos):
            usados.extend((self.agente, rascunho["tipo"]) for rascunho in rascunhos)
            return super().gravar(*rascunhos)

    monkeypatch.setattr(roteiro, "GravadorDoAgente", Espiao)
    saida = executar(tmp_path / "exemplo.jsonl")
    eventos = ler(saida)
    dos_agentes = [(e.dados.agente, e.tipo) for e in eventos if e.tipo in ("llm_chamada", "recomendacao_emitida")]
    # Onze chamadas ao modelo e duas recomendações.
    assert usados == dos_agentes and len(usados) == 13


def test_toda_linha_do_exemplo_e_valida_e_todos_os_tipos_de_evento_aparecem():
    # `ler` confere cada linha contra o contrato.
    eventos = ler(SAIDA_PADRAO)
    assert {evento.tipo for evento in eventos} == set(TIPOS_DE_EVENTO)
    assert [evento.id for evento in eventos] == [f"ev-{n:06d}" for n in range(1, len(eventos) + 1)]
    assert [evento.instante for evento in eventos] == sorted(evento.instante for evento in eventos)
    assert {evento.incidente for evento in eventos if evento.tipo != "janelas_classificadas"} == {"inc-0001"}


def test_exemplo_percorre_o_incidente_do_comeco_ao_fim():
    eventos = ler(SAIDA_PADRAO)
    marcos = [
        evento.tipo for evento in eventos if evento.tipo not in ("tool_chamada", "llm_chamada")
    ]
    assert marcos == [
        "janelas_classificadas", "incidente_aberto",
        # Primeira tentativa: bloqueio de uma origem, de risco baixo, que não resolve.
        "acao_proposta", "recomendacao_emitida", "acao_executada", "efeito_verificado", "incidente_atualizado",
        # Segunda rodada de decisão: uma ação do catálogo e uma ação nova, as duas de risco alto.
        "acao_proposta", "acao_proposta", "recomendacao_emitida",
        # O executor tenta antes da hora, e a pessoa rejeita uma proposta e aprova a outra.
        "recusa", "acao_rejeitada", "acao_aprovada",
        "acao_executada", "efeito_verificado", "incidente_encerrado",
        # O bloqueio que não resolveu é desfeito, e a ação nova vai para o catálogo.
        "acao_desfeita", "catalogo_ampliado",
    ]
    estado = reconstruir(eventos)
    assert estado.incidentes["inc-0001"].estado == "encerrado"
    assert {p.id: (p.acao, p.estado) for p in estado.propostas.values()} == {
        "prop-0001": ("bloquear_ip", "desfeita"),
        "prop-0002": ("isolar_dispositivo", "rejeitada"),
        "prop-0003": ("ativar_syn_cookies", "executada"),
    }
    assert {e.execucao: e.resultado for e in estado.efeitos.values()} == {"exec-0001": "persiste", "exec-0002": "cessou"}
    assert list(estado.promovidas) == ["ativar_syn_cookies"]
    ativo = ambiente(estado)
    assert [medida.acao for medida in ativo.outras_medidas] == ["ativar_syn_cookies"]
    assert ativo.bloqueios == []


def test_no_exemplo_cada_agente_so_chama_as_tools_da_sua_linha():
    eventos = ler(SAIDA_PADRAO)
    chamadas = [evento.dados for evento in eventos if evento.tipo == "tool_chamada"]
    assert {chamada.agente for chamada in chamadas} == set(AGENTES)
    assert {chamada.nome for chamada in chamadas} == set(AGENTES_DA_TOOL)
    for chamada in chamadas:
        assert chamada.agente in AGENTES_DA_TOOL[chamada.nome]
    assert {evento.dados.agente for evento in eventos if evento.tipo == "llm_chamada"} == set(AGENTES)
    assert {evento.dados.agente for evento in eventos if evento.tipo == "recomendacao_emitida"} == {"decisao"}


def test_main_grava_o_exemplo_no_caminho_pedido(tmp_path, capsys):
    saida = tmp_path / "pasta" / "exemplo.jsonl"
    assert main(["--saida", str(saida)]) == 0
    assert saida.read_bytes() == SAIDA_PADRAO.read_bytes()
    assert str(saida) in capsys.readouterr().err
