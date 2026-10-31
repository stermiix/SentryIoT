"""Testes do aprovador automático e da conferência das propostas contra o gabarito.

Os cenários são os do stub: o `inc-0001` é um DDoS (origens 203.0.113.x, destino 192.168.137.20) e o
`inc-0002` é uma força bruta (origem 198.51.100.23, destino 192.168.137.31).
"""

from types import SimpleNamespace

import pytest

from codigo.agente.agentes import RESOLVIDO, TODAS_REJEITADAS, Perfil, orquestrar
from codigo.agente.aprovador import (
    DESTINO,
    ORIGEM,
    USUARIO,
    AprovadorPorGabarito,
    carregar_gabarito,
    conferir_proposta,
    papel_do_alvo,
)
from codigo.agente.test_agentes import decisao, eventos_de, execucao, triagem
from codigo.agente.test_laco import ProvedorFalso
from codigo.mcp.acoes import BASE, reconstruir
from codigo.mcp.eventos import Registro, ler
from codigo.mcp.stub import Stub

ATACANTE = "198.51.100.23"
VITIMA = "192.168.137.31"
OUTRO = "192.168.137.99"
GABARITO = carregar_gabarito()


@pytest.fixture
def log(tmp_path):
    caminho = tmp_path / "eventos.jsonl"
    Stub(Registro(caminho), agente="todos").abrir_incidentes()
    return caminho


def proposta(acao, alvo, nova=False):
    return SimpleNamespace(acao=acao, alvo=alvo, nova=nova)


def incidente(categoria, *destinos):
    return SimpleNamespace(categoria=categoria, destinos=[SimpleNamespace(endereco=d) for d in destinos])


def conferir(acao, alvo, categoria="BruteForce", nova=False, destinos=(VITIMA,), atacantes=(ATACANTE,)):
    return conferir_proposta(proposta(acao, alvo, nova), incidente(categoria, *destinos), frozenset(atacantes), GABARITO)


# --- o gabarito ------------------------------------------------------------------------------


def test_o_gabarito_vira_categoria_acao_e_papeis():
    assert GABARITO["BruteForce"]["revogar_credencial"] == frozenset({DESTINO})
    assert GABARITO["DDoS"]["limitar_taxa"] == frozenset({ORIGEM, DESTINO})
    assert "Benign" not in GABARITO


# --- o papel do alvo -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("alvo", "papel"),
    [
        (ATACANTE, ORIGEM),
        (VITIMA, DESTINO),
        (f"23/tcp@{VITIMA}", DESTINO),
        (f"admin@{VITIMA}", DESTINO),
        (f"23/tcp@{ATACANTE}", ORIGEM),
        (OUTRO, None),
        ("origem-1", None),
        ("", None),
        (None, None),
    ],
)
def test_papel_do_alvo_vem_do_endereco_no_fim_do_alvo(alvo, papel):
    assert papel_do_alvo(alvo, {VITIMA}, {ATACANTE}) == papel


def test_endereco_que_e_atacante_e_destino_conta_como_origem():
    assert papel_do_alvo(ATACANTE, {ATACANTE, VITIMA}, {ATACANTE}) == ORIGEM


def test_o_endereco_ipv6_que_embute_um_ipv4_e_o_mesmo_dispositivo():
    assert papel_do_alvo(f"::ffff:{VITIMA}", {VITIMA}, set()) == DESTINO


# --- a conferência ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("categoria", "acao", "alvo"),
    [
        ("BruteForce", "revogar_credencial", f"admin@{VITIMA}"),
        ("BruteForce", "bloquear_ip", ATACANTE),
        ("BruteForce", "limitar_taxa", ATACANTE),
        ("DDoS", "limitar_taxa", VITIMA),
        ("DDoS", "bloquear_ip", ATACANTE),
        ("Recon", "fechar_porta", f"23/tcp@{VITIMA}"),
        ("Mirai", "fechar_porta", f"23/tcp@{ATACANTE}"),
        ("Web", "isolar_dispositivo", VITIMA),
    ],
)
def test_acao_aceitavel_sobre_o_alvo_no_papel_certo_e_aceita(categoria, acao, alvo):
    conferencia = conferir(acao, alvo, categoria)

    assert conferencia.aceitavel
    assert conferencia.papel in (ORIGEM, DESTINO)
    assert conferencia.motivo.startswith("Aprovada pelo gabarito")


@pytest.mark.parametrize(
    ("categoria", "acao", "alvo", "papel", "trecho"),
    [
        # A ação é aceitável na categoria, mas o alvo está no papel errado.
        ("BruteForce", "revogar_credencial", f"admin@{ATACANTE}", ORIGEM, "só vale sobre destino"),
        ("DDoS", "bloquear_ip", VITIMA, DESTINO, "só vale sobre origem"),
        ("Recon", "fechar_porta", f"23/tcp@{ATACANTE}", ORIGEM, "só vale sobre destino"),
        # A ação não é aceitável na categoria.
        ("DDoS", "isolar_dispositivo", VITIMA, None, "não aceita isolar_dispositivo na categoria DDoS"),
        ("Spoofing", "bloquear_ip", ATACANTE, None, "não aceita bloquear_ip na categoria Spoofing"),
        # O alvo não é atacante nem destino do incidente.
        ("BruteForce", "revogar_credencial", f"admin@{OUTRO}", None, "nem um destino listado"),
        # Sem ação aceitável na categoria: o alarme falso.
        ("Benign", "bloquear_ip", ATACANTE, None, "categoria Benign"),
    ],
)
def test_acao_ou_alvo_fora_do_gabarito_e_rejeitado_com_o_motivo(categoria, acao, alvo, papel, trecho):
    conferencia = conferir(acao, alvo, categoria)

    assert not conferencia.aceitavel
    assert conferencia.papel == papel
    assert trecho in conferencia.motivo
    assert conferencia.motivo.startswith("Rejeitada")


def test_a_conferencia_aceita_exatamente_o_que_o_gabarito_lista_em_todas_as_categorias_acoes_e_papeis():
    # Todas as combinações de categoria, ação do catálogo e papel do alvo: só as do arquivo passam.
    alvos = {ORIGEM: ATACANTE, DESTINO: VITIMA}
    combinacoes = 0
    for categoria in GABARITO:
        for acao in BASE:
            for papel, endereco in alvos.items():
                alvo = {"credencial": f"admin@{endereco}", "porta": f"23/tcp@{endereco}"}.get(BASE[acao].tipo_de_alvo, endereco)
                esperado = papel in GABARITO[categoria].get(acao, ())

                conferencia = conferir(acao, alvo, categoria)

                assert conferencia.aceitavel is esperado, (categoria, acao, papel)
                combinacoes += 1
    assert combinacoes == len(GABARITO) * len(BASE) * 2


def test_acao_nova_nao_entra_na_conta_automatica():
    conferencia = conferir("ativar_syn_cookies", VITIMA, "BruteForce", nova=True)

    assert not conferencia.aceitavel
    assert "ação nova" in conferencia.motivo


def test_o_motivo_nao_traz_endereco():
    conferencias = [
        conferir("bloquear_ip", VITIMA, "DDoS"),
        conferir("revogar_credencial", f"admin@{OUTRO}"),
        conferir("revogar_credencial", f"admin@{VITIMA}"),
    ]

    assert all(VITIMA not in c.motivo and OUTRO not in c.motivo and ATACANTE not in c.motivo for c in conferencias)


# --- o aprovador, no orquestrador ------------------------------------------------------------


def roda(log, incidente_id, *respostas_da_decisao, atacantes=(ATACANTE,)):
    local = ProvedorFalso(*triagem(incidente_id), *execucao("prop-0001", "exec-0001"))
    nuvem = ProvedorFalso(*respostas_da_decisao)
    aprovador = AprovadorPorGabarito(log, atacantes)
    resultado = orquestrar(
        incidente_id, log=log, perfis={"local": Perfil(local, "qwen"), "nuvem": Perfil(nuvem, "claude")},
        configuracao="hibrida", aprovador=aprovador,
    )
    return resultado, aprovador


def test_aprova_a_proposta_de_risco_alto_que_o_gabarito_aceita_e_a_execucao_segue(log):
    resultado, aprovador = roda(log, "inc-0002", *decisao("inc-0002", "revogar_credencial", "admin@destino-1", {}))

    assert resultado.desfecho == RESOLVIDO
    [aprovada] = eventos_de(log, "acao_aprovada")
    assert (aprovada.dados.proposta, aprovada.dados.usuario, aprovada.dados.canal) == ("prop-0001", USUARIO, "terminal")
    assert aprovada.dados.motivo.startswith("Aprovada pelo gabarito")
    assert [(d.proposta, d.acao, d.conferencia.aceitavel, d.conferencia.papel) for d in aprovador.decisoes] == [
        ("prop-0001", "revogar_credencial", True, DESTINO),
    ]
    assert reconstruir(ler(log)).propostas["prop-0001"].estado == "executada"


def test_rejeita_a_proposta_de_risco_alto_fora_do_gabarito_e_nada_e_executado(log):
    resultado, aprovador = roda(log, "inc-0002", *decisao("inc-0002", "fechar_porta", "22/tcp@destino-1", {}))

    assert resultado.desfecho == TODAS_REJEITADAS
    [rejeitada] = eventos_de(log, "acao_rejeitada")
    assert (rejeitada.dados.proposta, rejeitada.dados.usuario) == ("prop-0001", USUARIO)
    assert "não aceita fechar_porta na categoria BruteForce" in rejeitada.dados.motivo
    assert eventos_de(log, "acao_executada") == []
    assert [d.conferencia.aceitavel for d in aprovador.decisoes] == [False]


def test_rejeita_a_acao_nova_e_a_conta_como_nova(log):
    nova = {
        "descricao": "Ativa SYN cookies no dispositivo.", "passos": ["Ligar a opção."],
        "efeito_esperado": "O dispositivo resiste ao flood.", "como_desfazer": "Desligar a opção.",
    }

    resultado, aprovador = roda(log, "inc-0002", *decisao("inc-0002", "ativar_syn_cookies", "destino-1", nova))

    assert resultado.desfecho == TODAS_REJEITADAS
    assert [(d.acao, d.nova, d.conferencia.aceitavel) for d in aprovador.decisoes] == [("ativar_syn_cookies", True, False)]
    assert "ação nova" in eventos_de(log, "acao_rejeitada")[0].dados.motivo


def test_a_proposta_de_risco_baixo_nao_passa_pelo_aprovador(log):
    # O bloqueio da origem do inc-0002 é de risco baixo: libera sozinho, e o aprovador não é chamado.
    resultado, aprovador = roda(log, "inc-0002", *decisao("inc-0002", "bloquear_ip", "origem-1", {"duracao": 15}))

    assert resultado.desfecho == RESOLVIDO
    assert aprovador.decisoes == []
    assert eventos_de(log, "acao_aprovada") == []


def test_no_flood_a_primeira_acao_de_risco_baixo_executa_e_a_de_risco_alto_fora_do_gabarito_e_rejeitada(log):
    local = ProvedorFalso(*triagem("inc-0001"), *execucao("prop-0001", "exec-0001"))
    nuvem = ProvedorFalso(
        *decisao("inc-0001", "bloquear_ip", "origem-1", {"duracao": 10}),
        *decisao("inc-0001", "isolar_dispositivo", "destino-1", {}),
    )
    aprovador = AprovadorPorGabarito(log, ["203.0.113.7", "203.0.113.18"])

    resultado = orquestrar(
        "inc-0001", log=log, perfis={"local": Perfil(local, "qwen"), "nuvem": Perfil(nuvem, "claude")},
        configuracao="hibrida", aprovador=aprovador,
    )

    assert resultado.desfecho == TODAS_REJEITADAS
    assert [(d.proposta, d.acao) for d in aprovador.decisoes] == [("prop-0002", "isolar_dispositivo")]
    assert "não aceita isolar_dispositivo na categoria DDoS" in eventos_de(log, "acao_rejeitada")[0].dados.motivo


def test_atacante_com_endereco_invalido_e_erro(log):
    with pytest.raises(ValueError, match="endereço inválido"):
        AprovadorPorGabarito(log, ["não é um endereço"])
