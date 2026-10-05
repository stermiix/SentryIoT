import json
import shutil

import pytest

from codigo.mcp import aprovar as comando
from codigo.mcp.acoes import PedidoRecusado
from codigo.mcp.aprovar import main
from codigo.mcp.eventos import Registro
from codigo.mcp.stub import Stub
from codigo.mcp.test_acoes import ACAO_NOVA
from codigo.mcp.tipos import MOTIVOS_DE_RISCO_ALTO, TOOLS


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


class Terminal:
    """Faz o papel do terminal da pessoa: diz que é interativo e responde à pergunta de confirmação."""

    def __init__(self, monkeypatch, resposta=None, interativo=True, antes_de_responder=None):
        self.perguntas = []
        self.resposta = resposta
        self.antes_de_responder = antes_de_responder
        monkeypatch.setattr(comando.sys, "stdin", self)
        monkeypatch.setattr("builtins.input", self.perguntar)
        self.interativo = interativo

    def isatty(self):
        return self.interativo

    def perguntar(self, pergunta=""):
        self.perguntas.append(pergunta)
        if self.antes_de_responder is not None:
            self.antes_de_responder()
        if self.resposta is None:
            raise AssertionError("a confirmação não deveria ter sido pedida")
        if isinstance(self.resposta, BaseException):
            raise self.resposta
        return self.resposta


def test_aprovacao_e_rejeicao_nao_sao_tools():
    for tool in TOOLS:
        assert "aprov" not in tool.nome and "rejeit" not in tool.nome and "promov" not in tool.nome


def test_aprovar_libera_a_proposta_para_execucao(stub, capsys):
    propor_isolamento(stub)
    with pytest.raises(PedidoRecusado):
        stub.chamar("executar_acao", id_proposta="prop-0001")

    assert aprovar(stub, "prop-0001", "--sim") == 0
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
    aprovar(stub, "prop-0003", "--sim")
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

    aprovar(stub, "prop-0001", "--sim")
    stub.chamar("executar_acao", id_proposta="prop-0001")
    assert aprovar(stub, "prop-0001", "--promover", "--sim") == 0
    assert "ativar_syn_cookies promovida ao catálogo" in capsys.readouterr().out
    assert tipos(stub)[-1] == "catalogo_ampliado"
    acoes = stub.chamar("consultar_mitigacoes", categoria="DDoS").acoes
    assert (acoes[-1].nome, acoes[-1].origem) == ("ativar_syn_cookies", "promovida")


@pytest.mark.parametrize("preparar,argumentos,trecho", [
    (propor_isolamento, ["prop-0099"], "prop-0099"),
    (propor_isolamento, ["prop-0099", "--sim"], "prop-0099"),
    (propor_bloqueio_curto, ["prop-0001"], "não exige aprovação"),
    (propor_bloqueio_curto, ["prop-0001", "--sim"], "não exige aprovação"),
    (propor_bloqueio_curto, ["prop-0001", "--rejeitar"], "não exige aprovação"),
    (propor_bloqueio_curto, ["prop-0001", "--promover"], "catálogo de base"),
    (propor_bloqueio_curto, ["prop-0001", "--promover", "--sim"], "catálogo de base"),
])
def test_pedido_que_nao_cabe_e_explicado_e_nao_muda_o_log(stub, capsys, monkeypatch, preparar, argumentos, trecho):
    # O pedido que não cabe é recusado antes de qualquer pergunta.
    Terminal(monkeypatch)
    preparar(stub)
    antes = stub.registro.caminho.read_bytes()
    assert aprovar(stub, *argumentos) == 1
    erro = capsys.readouterr().err
    assert erro.startswith("erro: ") and trecho in erro
    # O comando não é tool: o que ele recusa não vira evento de recusa.
    assert stub.registro.caminho.read_bytes() == antes


def test_proposta_nao_e_decidida_duas_vezes(stub, capsys):
    propor_isolamento(stub)
    assert aprovar(stub, "prop-0001", "--sim") == 0
    assert aprovar(stub, "prop-0001", "--sim") == 1
    assert aprovar(stub, "prop-0001", "--rejeitar") == 1
    assert "já foi aprovada" in capsys.readouterr().err
    assert tipos(stub).count("acao_aprovada") == 1
    assert "acao_rejeitada" not in tipos(stub)


@pytest.mark.parametrize("argumentos", [
    ["prop-0001", "--rejeitar", "--promover"],
    ["--rejeitar"],
    ["--promover"],
    ["--motivo", "sem proposta"],
    ["--sim"],
    ["prop-0001", "prop-0002"],
])
def test_combinacao_invalida_de_opcoes(stub, capsys, argumentos):
    propor_isolamento(stub)
    assert aprovar(stub, *argumentos) == 2
    assert capsys.readouterr().err
    assert tipos(stub).count("acao_aprovada") == 0


def test_log_que_nao_existe_da_erro_e_nao_e_criado(tmp_path, capsys):
    log = tmp_path / "nao_existe.jsonl"
    assert main(["prop-0001", "--sim", "--log", str(log)]) == 1
    assert main(["--log", str(log)]) == 1
    assert "não encontrado" in capsys.readouterr().err
    assert not log.exists()


def test_log_estragado_da_erro_com_a_linha(stub, capsys):
    propor_isolamento(stub)
    with open(stub.registro.caminho, "a", encoding="utf-8") as arquivo:
        arquivo.write("linha estragada\n")
    assert aprovar(stub, "prop-0001", "--sim") == 1
    assert "linha 11" in capsys.readouterr().err


@pytest.mark.parametrize("argumentos", [
    [], ["prop-0001"], ["prop-0001", "--sim"], ["prop-0001", "--rejeitar"], ["prop-0001", "--promover", "--sim"],
])
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


# --- a pessoa vê a proposta inteira e confirma antes de gravar -------------------------------


def test_aprovar_mostra_a_proposta_inteira_e_so_grava_depois_da_confirmacao(stub, capsys, monkeypatch):
    propor_acao_nova(stub)
    antes = stub.registro.caminho.read_bytes()
    vistos = {}

    def conferir_a_tela():
        # No momento da pergunta, a proposta já está toda na tela e nada foi gravado.
        vistos["tela"] = capsys.readouterr().out
        vistos["log"] = stub.registro.caminho.read_bytes()

    terminal = Terminal(monkeypatch, "sim", antes_de_responder=conferir_a_tela)
    assert aprovar(stub, "prop-0001") == 0
    assert vistos["log"] == antes
    tela = vistos["tela"]
    assert "prop-0001" in tela and "inc-0001" in tela and "risco alto" in tela
    assert "ativar_syn_cookies" in tela and "fora do catálogo" in tela and "192.168.137.20" in tela
    assert "O bloqueio de uma origem não resolveu." in tela
    for campo in ("descricao", "efeito_esperado", "como_desfazer", "fonte"):
        assert ACAO_NOVA[campo] in tela
    assert [f"{numero}. {passo}" in tela for numero, passo in enumerate(ACAO_NOVA["passos"], start=1)] == [True, True]
    assert len(terminal.perguntas) == 1 and "prop-0001" in terminal.perguntas[0] and "sim" in terminal.perguntas[0]
    assert "prop-0001 aprovada" in capsys.readouterr().out
    assert tipos(stub)[-1] == "acao_aprovada"


@pytest.mark.parametrize("resposta", ["sim", "SIM", "  Sim  ", "s", "S"])
def test_respostas_que_confirmam(stub, monkeypatch, resposta):
    propor_isolamento(stub)
    Terminal(monkeypatch, resposta)
    assert aprovar(stub, "prop-0001") == 0
    assert tipos(stub)[-1] == "acao_aprovada"


@pytest.mark.parametrize("resposta", ["", "n", "nao", "não", "talvez", "sim!", "s i m", "yes", EOFError()], ids=repr)
def test_sem_a_confirmacao_nada_e_gravado(stub, capsys, monkeypatch, resposta):
    propor_isolamento(stub)
    antes = stub.registro.caminho.read_bytes()
    Terminal(monkeypatch, resposta)
    assert aprovar(stub, "prop-0001") == 1
    saida = capsys.readouterr()
    assert "isolar_dispositivo" in saida.out and "aprovada." not in saida.out
    assert "Nada foi gravado" in saida.err
    assert stub.registro.caminho.read_bytes() == antes
    with pytest.raises(PedidoRecusado):
        stub.chamar("executar_acao", id_proposta="prop-0001")


def test_sem_terminal_interativo_so_aprova_com_sim(stub, capsys, monkeypatch):
    propor_isolamento(stub)
    antes = stub.registro.caminho.read_bytes()
    terminal = Terminal(monkeypatch, interativo=False)
    assert aprovar(stub, "prop-0001") == 1
    saida = capsys.readouterr()
    assert saida.err.startswith("erro: ") and "--sim" in saida.err
    assert "isolar_dispositivo" in saida.out
    assert stub.registro.caminho.read_bytes() == antes

    # Com --sim não há pergunta, mas a proposta inteira é mostrada do mesmo jeito.
    assert aprovar(stub, "prop-0001", "--sim") == 0
    saida = capsys.readouterr().out
    assert "isolar_dispositivo" in saida and "192.168.137.20" in saida and "Dispositivo sob ataque." in saida
    assert "prop-0001 aprovada" in saida
    assert terminal.perguntas == []


def test_promover_tambem_mostra_a_proposta_e_pede_confirmacao(stub, capsys, monkeypatch):
    propor_acao_nova(stub)
    aprovar(stub, "prop-0001", "--sim")
    stub.chamar("executar_acao", id_proposta="prop-0001")
    capsys.readouterr()

    antes = stub.registro.caminho.read_bytes()
    Terminal(monkeypatch, "n")
    assert aprovar(stub, "prop-0001", "--promover") == 1
    saida = capsys.readouterr()
    for passo in ACAO_NOVA["passos"]:
        assert passo in saida.out
    assert ACAO_NOVA["como_desfazer"] in saida.out and "Nada foi gravado" in saida.err
    assert stub.registro.caminho.read_bytes() == antes

    terminal = Terminal(monkeypatch, "sim")
    assert aprovar(stub, "prop-0001", "--promover") == 0
    assert "catálogo" in terminal.perguntas[0] and "ativar_syn_cookies" in terminal.perguntas[0]
    assert tipos(stub)[-1] == "catalogo_ampliado"

    Terminal(monkeypatch, interativo=False)
    assert aprovar(stub, "prop-0001", "--promover") == 1


def test_rejeitar_mostra_a_proposta_e_nao_pede_confirmacao(stub, capsys, monkeypatch):
    propor_isolamento(stub)
    terminal = Terminal(monkeypatch, interativo=False)
    assert aprovar(stub, "prop-0001", "--rejeitar") == 0
    saida = capsys.readouterr().out
    assert "isolar_dispositivo" in saida and "prop-0001 rejeitada" in saida
    assert terminal.perguntas == []
    assert tipos(stub)[-1] == "acao_rejeitada"


def test_tela_mostra_todos_os_parametros_inclusive_a_duracao_de_um_bloqueio_longo(stub, capsys):
    # Dez horas de bloqueio e bloqueio sem prazo são as duas propostas de bloqueio que pedem aprovação.
    bloqueio = {"id": "inc-0001", "acao": "bloquear_ip", "alvo": "203.0.113.7", "justificativa": "Origem do tráfego."}
    stub.chamar("propor_acao", **bloqueio, parametros={"duracao": 600})
    stub.chamar("propor_acao", **bloqueio, parametros={})
    stub.chamar("propor_acao", **bloqueio | {"acao": "limitar_taxa"}, parametros={"duracao": 61})
    assert aprovar(stub) == 0
    lista = capsys.readouterr().out
    assert "3 propostas aguardam aprovação" in lista
    primeira, segunda, terceira = lista.split("\n\n")[1:]
    assert "duracao: 600 minutos" in primeira and "bloquear_ip" in primeira
    assert "duracao: sem prazo" in segunda and "minutos" not in segunda
    assert "duracao: 61 minutos" in terceira and "limitar_taxa" in terceira

    assert aprovar(stub, "prop-0001", "--sim") == 0
    assert "duracao: 600 minutos" in capsys.readouterr().out
    assert aprovar(stub, "prop-0002", "--rejeitar") == 0
    assert "duracao: sem prazo" in capsys.readouterr().out


def test_tela_mostra_cada_campo_da_proposta(stub, capsys):
    # Cada linha da tela é conferida: tirar qualquer uma delas faz este teste falhar.
    propor_acao_nova(stub)
    aprovar(stub)
    linhas = capsys.readouterr().out.splitlines()
    assert linhas[2:] == [
        "prop-0001  incidente inc-0001  risco alto",
        "  motivos do risco alto:",
        f"    - acao_nova: {MOTIVOS_DE_RISCO_ALTO['acao_nova']}",
        "  ação: ativar_syn_cookies (nova, fora do catálogo)",
        "  alvo: 192.168.137.20",
        "  justificativa: O bloqueio de uma origem não resolveu.",
        f"  descrição: {ACAO_NOVA['descricao']}",
        "  passos:",
        f"    1. {ACAO_NOVA['passos'][0]}",
        f"    2. {ACAO_NOVA['passos'][1]}",
        f"  efeito esperado: {ACAO_NOVA['efeito_esperado']}",
        f"  como desfazer: {ACAO_NOVA['como_desfazer']}",
        f"  fonte: {ACAO_NOVA['fonte']}",
        "  para aprovar:  python -m codigo.mcp.aprovar prop-0001",
        "  para rejeitar: python -m codigo.mcp.aprovar prop-0001 --rejeitar",
    ]


def test_tela_mostra_todos_os_motivos_do_risco_alto_com_o_codigo_e_a_frase(stub, capsys, monkeypatch):
    # Bloqueio sem prazo do gateway, que na varredura é um dos destinos: três motivos.
    stub.chamar(
        "propor_acao", id="inc-0003", acao="bloquear_ip", alvo="192.168.137.1", parametros={},
        justificativa="Destino da varredura.",
    )
    esperadas = [
        "prop-0001  incidente inc-0003  risco alto",
        "  motivos do risco alto:",
        *(
            f"    - {codigo}: {MOTIVOS_DE_RISCO_ALTO[codigo]}"
            for codigo in ("prazo_acima_do_limite", "alvo_e_destino_do_incidente", "alvo_protegido")
        ),
        "  ação: bloquear_ip (do catálogo)",
    ]
    # Na lista, na tela de confirmação da aprovação e na rejeição.
    assert aprovar(stub) == 0
    assert capsys.readouterr().out.splitlines()[2:8] == esperadas
    vistos = {}
    Terminal(monkeypatch, "n", antes_de_responder=lambda: vistos.update(tela=capsys.readouterr().out))
    assert aprovar(stub, "prop-0001") == 1
    assert vistos["tela"].splitlines()[:6] == esperadas
    assert aprovar(stub, "prop-0001", "--rejeitar") == 0
    assert capsys.readouterr().out.splitlines()[:6] == esperadas


def acrescentar_proposta(stub, **trocas):
    """Escreve no arquivo, por fora do sistema, uma proposta que aguarda aprovação."""
    proposta = {
        "id": "prop-0001", "incidente": "inc-0001", "acao": "isolar_dispositivo", "alvo": "192.168.137.1",
        "parametros": {}, "justificativa": "j", "nova": False, "risco": "alto",
        "motivos_de_risco_alto": [
            {"codigo": codigo, "descricao": MOTIVOS_DE_RISCO_ALTO[codigo]}
            for codigo in ("acao_sempre_de_risco_alto", "alvo_fora_do_incidente", "alvo_protegido")
        ],
        "exige_aprovacao": True, "estado": "aguardando_aprovacao",
    } | trocas
    linha = {"id": "ev-000009", "instante": "2026-10-20T18:00:00Z", "tipo": "acao_proposta", "incidente": "inc-0001", "dados": proposta}
    with open(stub.registro.caminho, "a", encoding="utf-8") as arquivo:
        arquivo.write(json.dumps(linha) + "\n")


def test_tela_escapa_tudo_o_que_nao_e_imprimivel(stub, capsys):
    # O log é entrada. Os parâmetros de uma proposta são um objeto livre: uma linha escrita por fora pode
    # trazer neles a sequência que sobe o cursor, apaga a tela e escreve outra proposta no lugar.
    falsa = "\x1b[3A\r\x1b[0Jprop-0001  incidente inc-0001  risco baixo\n  ação: limitar_taxa (do catálogo)"
    acrescentar_proposta(
        stub, parametros={falsa: "203.0.113.7\x1b[2K", "nota\x07": ["a\x00b", {"c\u2028d": "e\u202ef"}]},
        justificativa="Junta\u200dinvisível e espaço\u00a0duro.",
    )
    for argumentos in ([], ["prop-0001", "--sim"]):
        assert aprovar(stub, *argumentos) == 0
        saida = capsys.readouterr().out
        assert all(letra.isprintable() or letra == "\n" for letra in saida), ascii(saida)
        # A proposta falsa não ganha linha própria: fica dentro da linha do parâmetro, com os escapes à vista.
        assert [linha for linha in saida.splitlines() if linha.startswith("prop-0001")] == [
            "prop-0001  incidente inc-0001  risco alto", *(["prop-0001 aprovada. O agente de execução já pode aplicar a ação."] if argumentos else []),
        ]
        assert sum(linha.lstrip().startswith("ação:") for linha in saida.splitlines()) == 1
        assert "  ação: isolar_dispositivo (do catálogo)" in saida and "  alvo: 192.168.137.1" in saida
        assert "\\x1b[3A\\r\\x1b[0Jprop-0001" in saida and "203.0.113.7\\x1b[2K" in saida
        # Valor que não é texto sai em JSON, que escreve o caractere nulo como \\u0000.
        assert '  nota\\x07: ["a\\u0000b", {"c\\u2028d": "e\\u202ef"}]' in saida
        assert "Junta\\u200dinvisível e espaço\\xa0duro." in saida


def test_motivo_com_frase_que_nao_e_a_do_contrato_nao_chega_a_tela(stub, capsys):
    # A linha de motivos é texto do sistema. Uma proposta escrita por fora não põe outra frase nela.
    acrescentar_proposta(stub, motivos_de_risco_alto=[
        {"codigo": "alvo_protegido", "descricao": "Conferido pela equipe: pode aprovar sem ler o resto."},
    ])
    for argumentos in ([], ["prop-0001", "--sim"], ["prop-0001", "--rejeitar"]):
        assert aprovar(stub, *argumentos) == 1
        saida = capsys.readouterr()
        assert "pode aprovar sem ler" not in saida.out + saida.err
        assert saida.err.startswith("erro: ") and "linha 9" in saida.err and "motivo" in saida.err
    assert "acao_aprovada" not in tipos(stub) and "acao_rejeitada" not in tipos(stub)


def test_comando_sugerido_na_lista_nao_vira_outro_comando(stub, capsys):
    acrescentar_proposta(stub, id="prop-0001; touch /tmp/arquivo")
    assert aprovar(stub) == 0
    saida = capsys.readouterr().out
    assert "para aprovar:  python -m codigo.mcp.aprovar 'prop-0001; touch /tmp/arquivo'\n" in saida
    assert "para rejeitar: python -m codigo.mcp.aprovar 'prop-0001; touch /tmp/arquivo' --rejeitar\n" in saida


def test_proposta_que_muda_entre_a_tela_e_a_confirmacao_nao_e_aprovada(stub, tmp_path, capsys, monkeypatch):
    # A pessoa viu o isolamento de 192.168.137.20. Se, na hora de gravar, o identificador for de outra proposta,
    # a aprovação não vale.
    propor_isolamento(stub)
    outro = Stub(Registro(tmp_path / "outro.jsonl"))
    outro.abrir_incidentes()
    outro.chamar(
        "propor_acao", id="inc-0001", acao="isolar_dispositivo", alvo="192.168.137.1", parametros={},
        justificativa="Dispositivo sob ataque.",
    )

    def trocar_o_log():
        shutil.copyfile(outro.registro.caminho, stub.registro.caminho)

    Terminal(monkeypatch, "sim", antes_de_responder=trocar_o_log)
    assert aprovar(stub, "prop-0001") == 1
    saida = capsys.readouterr()
    assert "192.168.137.20" in saida.out and "aprovada." not in saida.out
    assert "mudou" in saida.err and "Nada foi gravado" in saida.err
    assert "acao_aprovada" not in tipos(stub)
