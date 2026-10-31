"""Testes do orquestrador, com o servidor MCP de verdade (o stub, por stdio) e modelos falsos.

Os cenários são os do stub: o `inc-0002` (força bruta) cessa na primeira ação, e o `inc-0001` (flood) só
cessa na segunda, que é de risco alto e pede aprovação.
"""

import dataclasses
import json
import os

import pytest

from codigo.agente.__main__ import main, perfis_da_configuracao, resumo
from codigo.agente.agentes import (
    AGENTE_PAROU,
    RESOLVIDO,
    SEM_APROVACAO,
    SEM_PROPOSTA,
    SEM_RESOLUCAO,
    TODAS_REJEITADAS,
    Perfil,
    decidir_no_log,
    orquestrar,
    para_a_decisao,
)
from codigo.agente.test_laco import ProvedorFalso, pedido, resposta
from codigo.mcp.acoes import reconstruir
from codigo.mcp.eventos import Registro, ler
from codigo.mcp.stub import Stub

ORIGEM = "198.51.100.23"
ROTULO = "Incidente: {id}\nRótulo da triagem: coerente\nPor quê: o ataque vem de {origem}, como a categoria diz."


@pytest.fixture
def log(tmp_path):
    caminho = tmp_path / "eventos.jsonl"
    Stub(Registro(caminho), agente="todos").abrir_incidentes()
    return caminho


def chamada(nome, argumentos, identificador):
    return resposta(pedidos=[pedido(nome, json.dumps(argumentos), identificador)])


def triagem(incidente):
    return [chamada("obter_incidente", {"id": incidente}, "t1"), resposta(ROTULO.format(id=incidente, origem=ORIGEM))]


def decisao(incidente, acao, alvo, parametros, texto="Recomendo a ação proposta."):
    proposta = {"id": incidente, "acao": acao, "alvo": alvo, "parametros": parametros, "justificativa": "Pelo resumo."}
    return [
        chamada("obter_resumo", {"id": incidente}, "d1"),
        chamada("propor_acao", proposta, "d2"),
        resposta(texto),
    ]


def execucao(proposta, aplicada):
    return [
        chamada("executar_acao", {"id_proposta": proposta}, "e1"),
        chamada("verificar_efeito", {"id_execucao": aplicada}, "e2"),
        resposta("Efeito verificado."),
    ]


def aprova_tudo(log):
    def aprovador(_estado, pendentes):
        for proposta in pendentes:
            decidir_no_log(log, proposta.id, True, usuario="aprovador-de-teste", motivo="Regra do teste.")

    return aprovador


def eventos_de(log, tipo):
    return [evento for evento in ler(log) if evento.tipo == tipo]


def test_hibrida_cada_agente_roda_no_modelo_da_configuracao_e_o_log_diz_onde(log):
    local = ProvedorFalso(*triagem("inc-0002"), *execucao("prop-0001", "exec-0001"))
    nuvem = ProvedorFalso(*decisao("inc-0002", "bloquear_ip", "origem-1", {"duracao": 15}))
    perfis = {"local": Perfil(local, "qwen-local"), "nuvem": Perfil(nuvem, "claude-nuvem")}

    resultado = orquestrar("inc-0002", log=log, perfis=perfis, configuracao="hibrida")

    assert resultado.desfecho == RESOLVIDO
    assert [(e.agente, e.onde, e.motivo) for e in resultado.execucoes] == [
        ("triagem", "local", "resposta_final"),
        ("decisao", "nuvem", "resposta_final"),
        ("execucao", "local", "resposta_final"),
    ]
    assert {rodada["modelo"] for rodada in local.rodadas} == {"qwen-local"}
    assert {rodada["modelo"] for rodada in nuvem.rodadas} == {"claude-nuvem"}
    chamadas = [(e.dados.agente, e.dados.modelo, e.dados.onde, e.dados.motivo_termino) for e in eventos_de(log, "llm_chamada")]
    assert chamadas[0] == ("triagem", "m-1", "local", None)
    assert {(agente, onde) for agente, _, onde, _ in chamadas} == {("triagem", "local"), ("decisao", "nuvem"), ("execucao", "local")}
    conclusoes = [(e.dados.agente, e.dados.motivo, e.dados.veredito) for e in eventos_de(log, "agente_concluido")]
    assert conclusoes == [
        ("triagem", "resposta_final", "coerente"),
        ("decisao", "resposta_final", None),
        ("execucao", "resposta_final", None),
    ]


def test_o_veredito_chega_a_decisao_sem_endereco(log):
    local = ProvedorFalso(*triagem("inc-0002"), *execucao("prop-0001", "exec-0001"))
    nuvem = ProvedorFalso(*decisao("inc-0002", "bloquear_ip", "origem-1", {"duracao": 15}))
    perfis = {"local": Perfil(local, "qwen"), "nuvem": Perfil(nuvem, "claude")}

    orquestrar("inc-0002", log=log, perfis=perfis, configuracao="hibrida")

    # O que o orquestrador manda à nuvem não traz o endereço que a triagem escreveu.
    enviado = json.dumps(nuvem.rodadas[0]["mensagens"], ensure_ascii=False)
    abertura = nuvem.rodadas[0]["mensagens"][1]["content"]
    assert "Rótulo da triagem: coerente" in abertura
    assert "[endereço]" in abertura
    assert ORIGEM not in enviado


def test_a_recomendacao_vai_ao_log_antes_da_conclusao_e_cita_as_propostas_da_rodada(log):
    perfis = {"local": Perfil(ProvedorFalso(*triagem("inc-0002"), *execucao("prop-0001", "exec-0001")), "m")}
    nuvem = Perfil(ProvedorFalso(*decisao("inc-0002", "bloquear_ip", "origem-1", {"duracao": 15}, "Bloquear origem-1.")), "n")

    orquestrar("inc-0002", log=log, perfis={**perfis, "nuvem": nuvem}, configuracao="hibrida")

    eventos = list(ler(log))
    recomendacao = next(e for e in eventos if e.tipo == "recomendacao_emitida")
    assert (recomendacao.dados.agente, recomendacao.dados.texto, recomendacao.dados.propostas) == (
        "decisao", "Bloquear origem-1.", ["prop-0001"],
    )
    concluiu = next(e for e in eventos if e.tipo == "agente_concluido" and e.dados.agente == "decisao")
    assert recomendacao.id < concluiu.id


def test_flood_com_duas_rodadas_a_segunda_ação_de_risco_alto_espera_a_aprovacao(log):
    modelo = ProvedorFalso(
        *triagem("inc-0001"),
        *decisao("inc-0001", "bloquear_ip", "origem-1", {"duracao": 10}),
        *execucao("prop-0001", "exec-0001"),
        *decisao("inc-0001", "isolar_dispositivo", "destino-1", {}),
        *execucao("prop-0002", "exec-0002"),
    )

    resultado = orquestrar(
        "inc-0001", log=log, perfis={"local": Perfil(modelo, "qwen")}, configuracao="local", aprovador=aprova_tudo(log)
    )

    assert resultado.desfecho == RESOLVIDO
    assert [(e.agente, e.rodada) for e in resultado.execucoes] == [
        ("triagem", 1), ("decisao", 1), ("execucao", 1), ("decisao", 2), ("execucao", 2),
    ]
    efeitos = [e.dados.resultado for e in eventos_de(log, "efeito_verificado")]
    assert efeitos == ["persiste", "cessou"]
    aprovada = eventos_de(log, "acao_aprovada")
    assert [(e.dados.proposta, e.dados.usuario) for e in aprovada] == [("prop-0002", "aprovador-de-teste")]
    # A decisão da segunda rodada sabe que o efeito da primeira persistiu.
    segunda = next(r for r in modelo.rodadas if "continua aberto" in r["mensagens"][1]["content"])
    assert '"persiste"' in segunda["mensagens"][1]["content"]
    assert reconstruir(ler(log)).propostas["prop-0002"].estado == "executada"


def test_proposta_de_risco_alto_sem_aprovador_e_sem_espera_para_no_meio(log):
    modelo = ProvedorFalso(
        *triagem("inc-0001"),
        *decisao("inc-0001", "bloquear_ip", "origem-1", {"duracao": 10}),
        *execucao("prop-0001", "exec-0001"),
        *decisao("inc-0001", "isolar_dispositivo", "destino-1", {}),
    )
    esperando = []

    resultado = orquestrar(
        "inc-0001", log=log, perfis={"local": Perfil(modelo, "qwen")}, configuracao="local",
        espera_da_aprovacao_s=0, ao_esperar=esperando.append,
    )

    assert resultado.desfecho == SEM_APROVACAO
    assert [p.id for p in esperando[0]] == ["prop-0002"]
    assert reconstruir(ler(log)).propostas["prop-0002"].estado == "aguardando_aprovacao"
    assert [e.agente for e in resultado.execucoes][-1] == "decisao"


def test_espera_a_pessoa_decidir_e_segue_quando_a_aprovacao_aparece(log):
    modelo = ProvedorFalso(
        *triagem("inc-0001"),
        *decisao("inc-0001", "bloquear_ip", "origem-1", {"duracao": 10}),
        *execucao("prop-0001", "exec-0001"),
        *decisao("inc-0001", "isolar_dispositivo", "destino-1", {}),
        *execucao("prop-0002", "exec-0002"),
    )
    pausas = []

    def a_pessoa_aprova(segundos):
        pausas.append(segundos)
        decidir_no_log(log, "prop-0002", True, usuario="maria")

    resultado = orquestrar(
        "inc-0001", log=log, perfis={"local": Perfil(modelo, "qwen")}, configuracao="local",
        espera_da_aprovacao_s=60, esperar=a_pessoa_aprova,
    )

    assert resultado.desfecho == RESOLVIDO
    assert len(pausas) == 1


def test_aprovador_que_rejeita_termina_sem_executar(log):
    def rejeita(_estado, pendentes):
        for proposta in pendentes:
            decidir_no_log(log, proposta.id, False, usuario="aprovador-de-teste", motivo="Fora do gabarito.")

    modelo = ProvedorFalso(*triagem("inc-0001"), *decisao("inc-0001", "isolar_dispositivo", "destino-1", {}))

    resultado = orquestrar(
        "inc-0001", log=log, perfis={"local": Perfil(modelo, "qwen")}, configuracao="local", aprovador=rejeita
    )

    assert resultado.desfecho == TODAS_REJEITADAS
    assert "execucao" not in [e.agente for e in resultado.execucoes]
    assert eventos_de(log, "acao_executada") == []


def test_decisao_que_nao_propoe_nada_termina_em_sem_proposta(log):
    modelo = ProvedorFalso(*triagem("inc-0002"), chamada("obter_resumo", {"id": "inc-0002"}, "d1"), resposta("Nada a fazer."))

    resultado = orquestrar("inc-0002", log=log, perfis={"local": Perfil(modelo, "qwen")}, configuracao="local")

    assert resultado.desfecho == SEM_PROPOSTA
    assert eventos_de(log, "recomendacao_emitida")[0].dados.propostas == []


def test_limite_de_rodadas_sem_efeito_termina_em_sem_resolucao(log):
    modelo = ProvedorFalso(
        *triagem("inc-0001"),
        *decisao("inc-0001", "bloquear_ip", "origem-1", {"duracao": 10}),
        *execucao("prop-0001", "exec-0001"),
    )

    resultado = orquestrar(
        "inc-0001", log=log, perfis={"local": Perfil(modelo, "qwen")}, configuracao="local", maximo_de_rodadas=1
    )

    assert resultado.desfecho == SEM_RESOLUCAO


def test_agente_que_para_no_limite_encerra_o_incidente_e_deixa_a_conclusao_no_log(log):
    recusa = dataclasses.replace(resposta("Não posso."), motivo_termino="content_filter")
    local = ProvedorFalso(recusa)
    nuvem = ProvedorFalso()

    resultado = orquestrar(
        "inc-0002", log=log, perfis={"local": Perfil(local, "q"), "nuvem": Perfil(nuvem, "c")}, configuracao="hibrida"
    )

    assert resultado.desfecho == AGENTE_PAROU
    assert [e.agente for e in resultado.execucoes] == ["triagem"]
    assert nuvem.rodadas == []
    conclusao = eventos_de(log, "agente_concluido")[0].dados
    assert (conclusao.agente, conclusao.motivo, conclusao.veredito) == ("triagem", "recusa_do_provedor", None)
    assert eventos_de(log, "llm_chamada")[0].dados.motivo_termino == "content_filter"


def test_incidente_que_nao_existe_no_log_e_recusado(log):
    with pytest.raises(ValueError, match="não existe no log"):
        orquestrar("inc-0099", log=log, perfis={"local": Perfil(ProvedorFalso(), "q")}, configuracao="local")


def test_configuracao_sem_o_modelo_que_ela_usa_e_recusada(log):
    with pytest.raises(ValueError, match="modelo nuvem"):
        orquestrar("inc-0002", log=log, perfis={"local": Perfil(ProvedorFalso(), "q")}, configuracao="hibrida")
    with pytest.raises(ValueError, match="configuração desconhecida"):
        orquestrar("inc-0002", log=log, perfis={}, configuracao="tudo")


def test_decidir_no_log_grava_como_o_comando_de_aprovacao(log):
    modelo = ProvedorFalso(*triagem("inc-0001"), *decisao("inc-0001", "isolar_dispositivo", "destino-1", {}))
    orquestrar("inc-0001", log=log, perfis={"local": Perfil(modelo, "q")}, configuracao="local", espera_da_aprovacao_s=0)

    decidir_no_log(log, "prop-0001", True, usuario="aprovador-automatico", motivo="Pelo gabarito.")

    decisao_gravada = eventos_de(log, "acao_aprovada")[0]
    assert (decisao_gravada.dados.proposta, decisao_gravada.dados.usuario, decisao_gravada.dados.canal) == (
        "prop-0001", "aprovador-automatico", "terminal",
    )


# --- o veredito que vai à decisão ------------------------------------------------------------


def test_o_veredito_perde_todo_endereco_antes_de_ir_a_decisao():
    texto = "A origem 203.0.113.7 e o MAC aa:bb:cc:dd:ee:ff atacam fe80::1 e 10.0.0.5."

    assert para_a_decisao(texto) == "A origem [endereço] e o MAC [endereço] atacam [endereço] e [endereço]."


def test_veredito_longo_e_cortado_e_o_fim_cortado_nao_vaza_um_endereco():
    # O corte cai no meio de um endereço: o começo dele não pode ir à nuvem.
    texto = "x" * 3995 + " 203.0.113.7"

    mascarado = para_a_decisao(texto)

    assert len(mascarado) <= 4000 + len("[endereço]")
    assert mascarado.endswith("[endereço]")
    assert "203" not in mascarado


@pytest.mark.parametrize("resposta_da_triagem", [None, "", "   "])
def test_veredito_vazio_vai_como_texto_vazio(resposta_da_triagem):
    assert para_a_decisao(resposta_da_triagem) == ""


# --- a linha de comando ----------------------------------------------------------------------

LOCAL = {"LLM_BASE_URL": "https://g/v1", "LLM_API_KEY": "k-local", "LLM_MODEL": "qwen"}
NUVEM = {"LLM_NUVEM_BASE_URL": "https://n/v1", "LLM_NUVEM_API_KEY": "k-nuvem", "LLM_NUVEM_MODEL": "claude"}


def test_cada_configuracao_pede_so_os_modelos_que_usa():
    perfis, faltando = perfis_da_configuracao("local", LOCAL)
    assert (sorted(perfis), faltando) == (["local"], [])
    perfis, faltando = perfis_da_configuracao("nuvem", NUVEM)
    assert (sorted(perfis), faltando) == (["nuvem"], [])
    perfis, faltando = perfis_da_configuracao("hibrida", {**LOCAL, **NUVEM})
    assert sorted(perfis) == ["local", "nuvem"]
    assert (perfis["local"].modelo, perfis["nuvem"].modelo) == ("qwen", "claude")


def test_o_que_falta_no_ambiente_sai_com_o_nome_certo_de_cada_conjunto():
    _, faltando = perfis_da_configuracao("hibrida", {"LLM_BASE_URL": "https://g/v1", "LLM_MODEL": "qwen"})

    assert faltando == ["LLM_API_KEY", "LLM_NUVEM_BASE_URL", "LLM_NUVEM_API_KEY", "LLM_NUVEM_MODEL"]


def test_main_sem_o_ambiente_completo_para_antes_de_chamar_qualquer_coisa(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(os, "environ", {})

    codigo = main(["--incidente", "inc-0001", "--log", str(tmp_path / "x.jsonl"), "--env", str(tmp_path / "nao.env")])

    assert codigo == 2
    assert "LLM_BASE_URL" in capsys.readouterr().err


def test_main_com_valor_invalido_no_env_diz_qual_variavel_e_nao_levanta(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(os, "environ", {**LOCAL, "LLM_TEMPERATURA": "9"})

    codigo = main(["--incidente", "inc-0001", "--log", str(tmp_path / "x.jsonl"), "--configuracao", "local",
                   "--env", str(tmp_path / "nao.env")])

    assert codigo == 2
    erro = capsys.readouterr().err
    assert "LLM_TEMPERATURA" in erro and "k-local" not in erro


def test_o_resumo_nao_traz_texto_de_modelo_nem_a_chave(log):
    modelo = ProvedorFalso(*triagem("inc-0002"), *decisao("inc-0002", "bloquear_ip", "origem-1", {"duracao": 15}),
                           *execucao("prop-0001", "exec-0001"))
    resultado = orquestrar("inc-0002", log=log, perfis={"local": Perfil(modelo, "qwen")}, configuracao="local")

    texto = resumo(resultado)

    assert texto.splitlines()[0] == "incidente inc-0002, configuração local: resolvido"
    assert "triagem" in texto and "decisao" in texto and "execucao" in texto
    assert ORIGEM not in texto and "Recomendo" not in texto
