"""O atacante apontado pela triagem (decisão de 2026-10-31): a tool, o evento, os rótulos e o resumo da decisão.

O cenário é o da força bruta do stub com dois candidatos a mais, como no `DictionaryBruteForce.pcap`: um
aparelho comum que abre muitas conexões com a nuvem e o atacante, que a regra fixa deixou fora das origens.
"""

import dataclasses

import pytest

from codigo.mcp.acoes import com_rotulos, reconstruir
from codigo.mcp.cenarios import CENARIOS
from codigo.mcp.eventos import LogInvalido, Registro, novo
from codigo.mcp.stub import Stub
from codigo.mcp.test_stub import Relogio, chamar, recusado
from codigo.mcp.tipos import (
    CandidatoAAtacante,
    EnderecoContado,
    PortaDoCandidato,
    tem_endereco,
)

FORCA_BRUTA = next(cenario for cenario in CENARIOS if cenario.nome == "forca_bruta")
INCIDENTE = FORCA_BRUTA.incidente.id
ORIGEM_DA_REGRA = FORCA_BRUTA.incidente.origens[0].endereco
ATACADO = FORCA_BRUTA.incidente.destinos[0].endereco
COMUM = "192.168.137.147"
ATACANTE = "192.168.137.65"


def candidato(endereco, abertas, destino, porta):
    return CandidatoAAtacante(
        endereco=endereco, janelas=18, no_trafego_normal=0.4, quadros_enviados=900, quadros_recebidos=600,
        conexoes_abertas=abertas, conexoes_recebidas=0, destinos=[EnderecoContado(endereco=destino, quadros=900)],
        portas=[PortaDoCandidato(porta=porta, protocolo="tcp", quadros=900)],
    )


@pytest.fixture
def linhas(tmp_path):
    """Os stubs da triagem e da decisão sobre o mesmo log, com o incidente aberto."""
    incidente = FORCA_BRUTA.incidente.model_copy(
        update={"candidatos": [candidato(COMUM, 95, "54.202.68.76", 9999), candidato(ATACANTE, 66, ATACADO, 22)]}
    )
    cenarios = [dataclasses.replace(FORCA_BRUTA, incidente=incidente)]
    registro = Registro(tmp_path / "eventos.jsonl", relogio=Relogio())
    triagem = Stub(registro, agente="triagem", cenarios=cenarios)
    triagem.abrir_incidentes()
    return triagem, Stub(registro, agente="decisao", cenarios=cenarios)


def apontar(triagem, endereco, justificativa="Abre as conexões à porta 22 do atacado."):
    return chamar(triagem, "apontar_atacante", id=INCIDENTE, endereco=endereco, justificativa=justificativa)


def test_a_triagem_aponta_um_candidato_fora_das_origens_e_a_decisao_recebe_o_rotulo_sem_endereco(linhas):
    triagem, decisao = linhas
    apontado = apontar(
        triagem, ATACANTE, f"{ATACANTE} abre as conexões à porta 22 de {ATACADO}; {COMUM} só fala com 54.202.68.76."
    )

    assert apontado.endereco == ATACANTE
    assert [evento.tipo for evento in triagem.registro.ler()[-2:]] == ["tool_chamada", "atacante_apontado"]
    resumo = chamar(decisao, "obter_resumo", id=INCIDENTE)
    # As origens da regra vêm primeiro; os candidatos, na ordem, depois.
    assert resumo.atacante_apontado.rotulo == "origem-3"
    assert resumo.atacante_apontado.justificativa == (
        "origem-3 abre as conexões à porta 22 de destino-1; origem-2 só fala com [endereço]."
    )
    assert not tem_endereco(resumo.model_dump_json())


def test_sem_apontamento_o_resumo_vem_sem_atacante(linhas):
    _, decisao = linhas
    assert chamar(decisao, "obter_resumo", id=INCIDENTE).atacante_apontado is None


def test_vale_o_ultimo_apontado(linhas):
    triagem, decisao = linhas
    apontar(triagem, COMUM)
    apontar(triagem, ATACANTE)

    assert chamar(decisao, "obter_resumo", id=INCIDENTE).atacante_apontado.rotulo == "origem-3"
    assert reconstruir(triagem.registro.ler()).atacantes[INCIDENTE].endereco == ATACANTE


def test_o_candidato_apontado_conta_como_origem_do_incidente_no_risco(linhas):
    triagem, decisao = linhas
    apontar(triagem, ATACANTE)

    proposta = chamar(
        decisao, "propor_acao", id=INCIDENTE, acao="bloquear_ip", alvo="origem-3", parametros={"duracao": 10},
        justificativa="Atacante apontado pela triagem.",
    )

    # A linha da decisão recebe a proposta com o rótulo; o log guarda o endereço.
    assert reconstruir(decisao.registro.ler()).propostas[proposta.id].alvo == ATACANTE
    assert "alvo_fora_do_incidente" not in [motivo.codigo for motivo in proposta.motivos_de_risco_alto]


@pytest.mark.parametrize("endereco", ["10.9.9.9", "não é endereço", ATACADO])
def test_endereco_fora_dos_candidatos_e_das_origens_e_recusado(linhas, endereco):
    triagem, _ = linhas
    recusado(triagem, "alvo_nao_permitido", "apontar_atacante", id=INCIDENTE, endereco=endereco, justificativa="x")


def test_a_origem_da_regra_tambem_pode_ser_apontada(linhas):
    triagem, _ = linhas
    assert apontar(triagem, ORIGEM_DA_REGRA).endereco == ORIGEM_DA_REGRA


def test_justificativa_vazia_e_recusada(linhas):
    triagem, _ = linhas
    recusado(triagem, "argumentos_invalidos", "apontar_atacante", id=INCIDENTE, endereco=ATACANTE, justificativa=" ")


def test_so_a_triagem_aponta(linhas):
    _, decisao = linhas
    recusado(decisao, "tool_fora_da_linha", "apontar_atacante", id=INCIDENTE, endereco=ATACANTE, justificativa="x")


def test_log_com_atacante_que_nao_e_do_incidente_e_invalido(linhas):
    triagem, _ = linhas
    triagem.registro.gravar(
        novo("atacante_apontado", {"endereco": "10.9.9.9", "justificativa": "Escrito por fora."}, INCIDENTE)
    )
    with pytest.raises(LogInvalido, match="não está entre os candidatos nem as origens"):
        reconstruir(triagem.registro.ler())


def test_com_rotulos_troca_o_endereco_mais_longo_primeiro_e_prefere_o_rotulo_de_origem():
    rotulos = {"origem-1": "10.0.0.1", "origem-2": "10.0.0.12", "destino-1": "10.0.0.1", "destino-2": "10.0.0.3"}

    assert com_rotulos("10.0.0.12 ataca 10.0.0.1, 10.0.0.3 e 8.8.8.8.", rotulos) == (
        "origem-2 ataca origem-1, destino-2 e [endereço]."
    )
    # O ponto final colado ao endereço não o esconde; o ponto seguido de dígito faz parte de outro endereço.
    assert com_rotulos("Vem de 10.0.0.3.", rotulos) == "Vem de destino-2."
    assert "destino-2" not in com_rotulos("Vem de 10.0.0.3.7.", rotulos)
