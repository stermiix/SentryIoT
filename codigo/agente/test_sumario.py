"""Os fatos que o sumário do incidente recebe: o que aconteceu, o que não aconteceu e o desfecho."""

from codigo.agente.sumario import fatos_do_incidente
from codigo.mcp.acoes import decidir, reconstruir
from codigo.mcp.eventos import Registro
from codigo.mcp.stub import Stub


def test_os_fatos_dizem_o_que_nao_aconteceu_e_terminam_pelo_desfecho(tmp_path):
    registro = Registro(tmp_path / "eventos.jsonl")
    stub = Stub(registro, agente="todos")
    stub.abrir_incidentes()
    stub.chamar(
        "propor_acao", id="inc-0001", acao="isolar_dispositivo", alvo="destino-1", parametros={},
        justificativa="Dispositivo sob ataque.",
    )

    fatos = fatos_do_incidente(registro.ler(), "inc-0001", "sem_aprovacao").splitlines()

    assert fatos[0].startswith("Classificador: DDoS (o modelo disse DDoS+DoS)")
    assert "Proposta prop-0001: isolar_dispositivo" in "\n".join(fatos)
    assert fatos[-4:] == [
        "Nenhuma pessoa aprovou nem rejeitou proposta.",
        "A triagem não apontou atacante.",
        "Nenhuma ação foi aplicada.",
        "Desfecho: a proposta de risco alto ficou esperando uma pessoa, e a espera acabou sem decisão.",
    ]


def test_a_rejeicao_entra_com_o_motivo_e_sem_a_frase_de_que_ninguem_decidiu(tmp_path):
    registro = Registro(tmp_path / "eventos.jsonl")
    stub = Stub(registro, agente="todos")
    stub.abrir_incidentes()
    proposta = stub.chamar(
        "propor_acao", id="inc-0001", acao="isolar_dispositivo", alvo="destino-1", parametros={},
        justificativa="Dispositivo sob ataque.",
    )
    registro.atualizar(
        lambda eventos: decidir(reconstruir(eventos), proposta.id, False, usuario="operador", motivo="Não pode parar.")
    )

    fatos = fatos_do_incidente(registro.ler(), "inc-0001", "todas_rejeitadas")

    assert "A pessoa (operador) rejeitou a proposta prop-0001: Não pode parar." in fatos
    assert "Nenhuma pessoa aprovou nem rejeitou proposta." not in fatos
    assert fatos.endswith("Desfecho: a pessoa rejeitou as propostas, e nenhuma ação foi aplicada.")
