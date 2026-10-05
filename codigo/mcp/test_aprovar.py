import pytest

from codigo.mcp.acoes import PedidoRecusado
from codigo.mcp.aprovar import main
from codigo.mcp.eventos import Registro
from codigo.mcp.stub import Stub
from codigo.mcp.test_acoes import ACAO_NOVA
from codigo.mcp.tipos import TOOLS


@pytest.fixture
def stub(tmp_path):
    stub = Stub(Registro(tmp_path / "eventos.jsonl"))
    stub.abrir_incidentes()
    return stub


def aprovar(stub, *argumentos):
    return main([*argumentos, "--log", str(stub.registro.caminho)])


def propor_acao_nova(stub):
    return stub.chamar(
        "propor_acao", id="inc-0001", acao="ativar_syn_cookies", alvo="192.168.137.20", parametros=ACAO_NOVA,
        justificativa="O bloqueio de uma origem não resolveu.",
    )


def propor_isolamento(stub):
    return stub.chamar(
        "propor_acao", id="inc-0001", acao="isolar_dispositivo", alvo="192.168.137.20", parametros={},
        justificativa="Dispositivo sob ataque.",
    )


def propor_bloqueio_curto(stub):
    return stub.chamar(
        "propor_acao", id="inc-0001", acao="bloquear_ip", alvo="203.0.113.7", parametros={"duracao": 10},
        justificativa="Origem com mais quadros.",
    )


def tipos(stub):
    return [evento.tipo for evento in stub.registro.ler()]


def test_aprovacao_e_rejeicao_nao_sao_tools():
    for tool in TOOLS:
        assert "aprov" not in tool.nome and "rejeit" not in tool.nome and "promov" not in tool.nome


def test_aprovar_libera_a_proposta_para_execucao(stub, capsys):
    propor_isolamento(stub)
    with pytest.raises(PedidoRecusado):
        stub.chamar("executar_acao", id_proposta="prop-0001")

    assert aprovar(stub, "prop-0001") == 0
    saida = capsys.readouterr().out
    assert "prop-0001 aprovada" in saida
    assert "isolar_dispositivo" in saida and "192.168.137.20" in saida

    decisao = stub.registro.ler()[-1]
    assert (decisao.tipo, decisao.incidente) == ("acao_aprovada", "inc-0001")
    assert (decisao.dados.proposta, decisao.dados.canal, decisao.dados.motivo) == ("prop-0001", "terminal", None)
    assert stub.chamar("executar_acao", id_proposta="prop-0001").estado == "aplicada"


def test_rejeitar_registra_o_motivo_e_a_proposta_nao_executa(stub, capsys):
    propor_isolamento(stub)
    assert aprovar(stub, "prop-0001", "--rejeitar", "--motivo", "O dispositivo não pode sair do ar.") == 0
    assert "prop-0001 rejeitada" in capsys.readouterr().out

    decisao = stub.registro.ler()[-1]
    assert decisao.tipo == "acao_rejeitada"
    assert decisao.dados.motivo == "O dispositivo não pode sair do ar."
    with pytest.raises(PedidoRecusado, match="rejeitada"):
        stub.chamar("executar_acao", id_proposta="prop-0001")


def test_sem_identificador_lista_o_que_aguarda_aprovacao_com_tudo_o_que_sera_feito(stub, capsys):
    propor_bloqueio_curto(stub)
    propor_acao_nova(stub)
    propor_isolamento(stub)
    aprovar(stub, "prop-0003")
    capsys.readouterr()

    assert aprovar(stub) == 0
    saida = capsys.readouterr().out
    assert "1 proposta aguarda aprovação" in saida
    # A proposta de risco baixo e a que já foi aprovada não entram na lista.
    assert "prop-0002" in saida and "prop-0001" not in saida and "prop-0003" not in saida
    assert "inc-0001" in saida and "risco alto" in saida
    assert "ativar_syn_cookies" in saida and "fora do catálogo" in saida
    assert "192.168.137.20" in saida
    assert "O bloqueio de uma origem não resolveu." in saida
    for passo in ACAO_NOVA["passos"]:
        assert passo in saida
    assert ACAO_NOVA["como_desfazer"] in saida
    assert ACAO_NOVA["efeito_esperado"] in saida
    assert ACAO_NOVA["fonte"] in saida
    assert "python -m codigo.mcp.aprovar prop-0002" in saida


def test_lista_vazia(stub, capsys):
    propor_bloqueio_curto(stub)
    assert aprovar(stub) == 0
    assert "Nenhuma proposta aguarda aprovação" in capsys.readouterr().out


def test_listar_nao_grava_nada(stub):
    propor_acao_nova(stub)
    antes = stub.registro.caminho.read_bytes()
    aprovar(stub)
    assert stub.registro.caminho.read_bytes() == antes


def test_promover_leva_a_acao_nova_aplicada_para_o_catalogo(stub, capsys):
    propor_acao_nova(stub)
    assert aprovar(stub, "prop-0001", "--promover") == 1
    assert "depois de aprovada e aplicada" in capsys.readouterr().err

    aprovar(stub, "prop-0001")
    stub.chamar("executar_acao", id_proposta="prop-0001")
    assert aprovar(stub, "prop-0001", "--promover") == 0
    assert "ativar_syn_cookies promovida ao catálogo" in capsys.readouterr().out
    assert tipos(stub)[-1] == "catalogo_ampliado"
    acoes = stub.chamar("consultar_mitigacoes", categoria="DDoS").acoes
    assert (acoes[-1].nome, acoes[-1].origem) == ("ativar_syn_cookies", "promovida")


@pytest.mark.parametrize("preparar,argumentos,trecho", [
    (propor_isolamento, ["prop-0099"], "prop-0099"),
    (propor_bloqueio_curto, ["prop-0001"], "não exige aprovação"),
    (propor_bloqueio_curto, ["prop-0001", "--rejeitar"], "não exige aprovação"),
    (propor_bloqueio_curto, ["prop-0001", "--promover"], "catálogo de base"),
])
def test_pedido_que_nao_cabe_e_explicado_e_nao_muda_o_log(stub, capsys, preparar, argumentos, trecho):
    preparar(stub)
    antes = stub.registro.caminho.read_bytes()
    assert aprovar(stub, *argumentos) == 1
    erro = capsys.readouterr().err
    assert erro.startswith("erro: ") and trecho in erro
    # O comando não é tool: o que ele recusa não vira evento de recusa.
    assert stub.registro.caminho.read_bytes() == antes


def test_proposta_nao_e_decidida_duas_vezes(stub, capsys):
    propor_isolamento(stub)
    assert aprovar(stub, "prop-0001") == 0
    assert aprovar(stub, "prop-0001") == 1
    assert aprovar(stub, "prop-0001", "--rejeitar") == 1
    assert "já foi aprovada" in capsys.readouterr().err
    assert tipos(stub).count("acao_aprovada") == 1
    assert "acao_rejeitada" not in tipos(stub)


@pytest.mark.parametrize("argumentos", [
    ["prop-0001", "--rejeitar", "--promover"],
    ["--rejeitar"],
    ["--promover"],
    ["--motivo", "sem proposta"],
    ["prop-0001", "prop-0002"],
])
def test_combinacao_invalida_de_opcoes(stub, capsys, argumentos):
    propor_isolamento(stub)
    assert aprovar(stub, *argumentos) == 2
    assert capsys.readouterr().err
    assert tipos(stub).count("acao_aprovada") == 0


def test_log_que_nao_existe_da_erro_e_nao_e_criado(tmp_path, capsys):
    log = tmp_path / "nao_existe.jsonl"
    assert main(["prop-0001", "--log", str(log)]) == 1
    assert main(["--log", str(log)]) == 1
    assert "não encontrado" in capsys.readouterr().err
    assert not log.exists()


def test_log_estragado_da_erro_com_a_linha(stub, capsys):
    propor_isolamento(stub)
    with open(stub.registro.caminho, "a", encoding="utf-8") as arquivo:
        arquivo.write("linha estragada\n")
    assert aprovar(stub, "prop-0001") == 1
    assert "linha 11" in capsys.readouterr().err


@pytest.mark.parametrize("argumentos", [[], ["prop-0001"], ["prop-0001", "--rejeitar"], ["prop-0001", "--promover"]])
def test_log_com_evento_fora_de_lugar_da_erro_com_a_linha_e_sem_traceback(stub, capsys, argumentos):
    propor_isolamento(stub)
    with open(stub.registro.caminho, "a", encoding="utf-8") as arquivo:
        arquivo.write(
            '{"id":"qualquer","instante":"1999-01-01T00:00:00Z","tipo":"acao_aprovada","incidente":null,'
            '"dados":{"proposta":"prop-0007","canal":"interface","motivo":null}}\n'
        )
    antes = stub.registro.caminho.read_bytes()
    assert aprovar(stub, *argumentos) == 1
    saida = capsys.readouterr()
    assert saida.err.startswith("erro: ") and "linha 11" in saida.err and "prop-0007" in saida.err
    assert "Traceback" not in saida.err and "aprovada." not in saida.out
    assert stub.registro.caminho.read_bytes() == antes
