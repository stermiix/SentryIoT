import ipaddress
import math
from datetime import timedelta

import pytest

from codigo.captura.extrator import COLUNAS, CONTAGENS
from codigo.mcp import cenarios
from codigo.mcp.cenarios import (
    CENARIOS,
    REDES_DE_EXEMPLO,
    cenario_do_incidente,
    efeito,
    evoluir,
    janelas,
)
from codigo.mcp.tipos import LIMITE_DE_JANELAS, Incidente, Janela, LoteDeJanelas

POR_NOME = {cenario.nome: cenario for cenario in CENARIOS}
FLOOD = POR_NOME["flood"]


def de_exemplo(endereco):
    return any(ipaddress.ip_address(endereco) in rede for rede in REDES_DE_EXEMPLO)


def test_sao_os_quatro_cenarios_da_especificacao():
    assert list(POR_NOME) == ["flood", "forca_bruta", "varredura", "falso_positivo"]
    assert [cenario.incidente.id for cenario in CENARIOS] == ["inc-0001", "inc-0002", "inc-0003", "inc-0004"]
    assert [cenario.incidente.categoria for cenario in CENARIOS] == ["DDoS", "BruteForce", "Recon", "DoS"]
    assert all(cenario.descricao.strip() for cenario in CENARIOS)


def test_os_numeros_sao_declarados_como_ilustrativos():
    assert "ilustrativos" in cenarios.__doc__


def test_cenario_do_incidente():
    assert cenario_do_incidente("inc-0003") is POR_NOME["varredura"]
    assert cenario_do_incidente("inc-0099") is None


def test_enderecos_de_exemplo_sao_as_faixas_de_documentacao_e_a_rede_local():
    assert [str(rede) for rede in REDES_DE_EXEMPLO] == [
        "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "192.168.137.0/24",
    ]


@pytest.mark.parametrize("cenario", CENARIOS, ids=lambda cenario: cenario.nome)
class TestCadaCenario:
    def test_incidente_e_valido_e_comeca_aberto(self, cenario):
        incidente = cenario.incidente
        assert isinstance(incidente, Incidente)
        assert Incidente.model_validate(incidente.model_dump(mode="json")) == incidente
        assert incidente.estado == "aberto"
        assert incidente.inicio < incidente.fim
        assert incidente.features_principais

    def test_so_usa_enderecos_de_exemplo(self, cenario):
        incidente = cenario.incidente
        enderecos = [item.endereco for item in (*incidente.origens, *incidente.destinos)]
        for janela in janelas(cenario, incidente, LIMITE_DE_JANELAS):
            enderecos += [janela.origem, janela.destino]
        assert enderecos
        assert all(de_exemplo(endereco) for endereco in enderecos)

    def test_numeros_do_incidente_sao_coerentes_entre_si(self, cenario):
        incidente = cenario.incidente
        quadros = incidente.janelas * cenario.quadros_por_janela
        for lista in (incidente.origens, incidente.destinos):
            contagens = [item.quadros for item in lista]
            assert contagens == sorted(contagens, reverse=True)
            assert 0 < sum(contagens) <= quadros
        assert 1 <= len(incidente.origens) <= incidente.origens_distintas
        assert incidente.distribuido == (incidente.origens_distintas > 1)

    def test_categoria_segue_a_regra_das_origens(self, cenario):
        incidente = cenario.incidente
        if incidente.categoria_do_modelo in ("DDoS", "DoS"):
            assert incidente.categoria == ("DDoS" if incidente.distribuido else "DoS")
        else:
            assert incidente.categoria == incidente.categoria_do_modelo

    def test_lote_de_janelas_contem_as_janelas_do_incidente(self, cenario):
        lote = cenario.lote
        assert isinstance(lote, LoteDeJanelas)
        assert lote.janelas == sum(lote.por_categoria.values())
        assert lote.por_categoria[cenario.incidente.categoria_do_modelo] == cenario.incidente.janelas
        assert lote.por_categoria["Benign"] > 0

    def test_roteiro_de_efeitos_termina_com_o_incidente_cessando(self, cenario):
        assert cenario.efeitos
        assert set(cenario.efeitos) <= {"cessou", "diminuiu", "persiste"}
        assert cenario.efeitos[-1] == "cessou"

    def test_janelas_sao_validas_e_trazem_as_39_features(self, cenario):
        fatia = janelas(cenario, cenario.incidente, LIMITE_DE_JANELAS)
        assert len(fatia) == min(LIMITE_DE_JANELAS, cenario.incidente.janelas)
        for janela in fatia:
            assert isinstance(janela, Janela)
            assert Janela.model_validate(janela.model_dump(mode="json")) == janela
            assert tuple(janela.features) == COLUNAS
            assert all(isinstance(valor, int | float) and math.isfinite(valor) for valor in janela.features.values())
            assert janela.categoria_do_modelo == cenario.incidente.categoria_do_modelo
            assert cenario.incidente.inicio <= janela.instante <= cenario.incidente.fim
            assert janela.origem in [item.endereco for item in cenario.incidente.origens]
            assert janela.destino in [item.endereco for item in cenario.incidente.destinos]

    def test_features_de_cada_janela_respeitam_as_relacoes_do_extrator(self, cenario):
        for janela in janelas(cenario, cenario.incidente, 5):
            f = janela.features
            assert f["Number"] == cenario.quadros_por_janela
            assert f["Tot sum"] == pytest.approx(f["AVG"] * f["Number"], rel=1e-3)
            assert f["Tot size"] == f["AVG"]
            assert f["Variance"] == pytest.approx(f["Std"] ** 2, rel=1e-3)
            assert f["Min"] <= f["AVG"] <= f["Max"]
            assert f["Rate"] > 0 and f["IAT"] > 0
            for contagem, flag in CONTAGENS:
                assert f[contagem] == pytest.approx(f[flag] * f["Number"])
            for indicador in ("TCP", "UDP", "IPv", "LLC", "syn_flag_number", "ack_flag_number"):
                assert 0 <= f[indicador] <= 1


def test_flood_e_distribuido_e_o_modelo_nao_distingue_dos_de_ddos():
    incidente = FLOOD.incidente
    assert (incidente.categoria_do_modelo, incidente.categoria) == ("DoS", "DDoS")
    assert incidente.origens_distintas == 37
    assert incidente.janelas > 10_000
    for janela in janelas(FLOOD, incidente, 5):
        assert janela.features["syn_flag_number"] == 1.0
        assert janela.features["Rate"] == pytest.approx(35778.4, rel=0.1)


def test_no_flood_a_primeira_acao_nao_resolve_e_a_segunda_resolve():
    assert FLOOD.efeitos == ("persiste", "cessou")
    assert efeito(FLOOD, 1) == "persiste"
    assert efeito(FLOOD, 2) == "cessou"
    # Depois do fim do roteiro vale o último resultado.
    assert efeito(FLOOD, 3) == "cessou"


def test_os_cenarios_exercitam_os_tres_resultados_de_efeito():
    assert {resultado for cenario in CENARIOS for resultado in cenario.efeitos} == {"cessou", "diminuiu", "persiste"}
    assert POR_NOME["forca_bruta"].efeitos == ("cessou",)
    assert POR_NOME["varredura"].efeitos == ("diminuiu", "cessou")


def test_falso_positivo_tem_confianca_baixa_e_origem_da_rede_local():
    incidente = POR_NOME["falso_positivo"].incidente
    assert incidente.confianca < 0.7
    assert incidente.origens_distintas == 1
    assert ipaddress.ip_address(incidente.origens[0].endereco) in REDES_DE_EXEMPLO[-1]


@pytest.mark.parametrize("limite,indices", [
    (1, [0]),
    (2, [0, 10733]),
    (3, [0, 5366, 10733]),
    (5, [0, 2683, 5366, 8049, 10733]),
])
def test_janelas_vem_espacadas_ao_longo_do_incidente(limite, indices):
    assert [janela.indice for janela in janelas(FLOOD, FLOOD.incidente, limite)] == indices


def test_janelas_de_incidente_pequeno_vem_todas():
    falso_positivo = POR_NOME["falso_positivo"]
    assert falso_positivo.incidente.janelas == 9
    assert [j.indice for j in janelas(falso_positivo, falso_positivo.incidente, 20)] == list(range(9))


def test_a_mesma_janela_sai_sempre_igual():
    assert janelas(FLOOD, FLOOD.incidente, 20) == janelas(FLOOD, FLOOD.incidente, 20)
    por_indice = {janela.indice: janela for janela in janelas(FLOOD, FLOOD.incidente, 3)}
    assert janelas(FLOOD, FLOOD.incidente, 5)[2] == por_indice[5366]
    # As janelas não são cópias uma da outra.
    assert por_indice[0].features["Rate"] != por_indice[5366].features["Rate"]


def test_incidente_que_cessa_e_encerrado():
    encerrado = evoluir(FLOOD, FLOOD.incidente, "cessou")
    assert encerrado == FLOOD.incidente.model_copy(update={"estado": "encerrado"})


def test_incidente_que_persiste_continua_aberto_e_cresce():
    inicial = FLOOD.incidente
    depois = evoluir(FLOOD, inicial, "persiste")
    assert depois.estado == "aberto"
    assert depois.janelas == 2 * inicial.janelas
    assert depois.fim - inicial.fim == inicial.fim - inicial.inicio == timedelta(seconds=30)
    assert depois.inicio == inicial.inicio
    assert depois.destinos[0].quadros == 2 * inicial.destinos[0].quadros
    assert [item.endereco for item in depois.origens] == [item.endereco for item in inicial.origens]
    # Outra verificação com o mesmo resultado soma mais um período igual ao inicial.
    assert evoluir(FLOOD, depois, "persiste").janelas == 3 * inicial.janelas
    assert Incidente.model_validate(depois.model_dump(mode="json")) == depois


def test_incidente_que_diminui_cresce_menos_do_que_o_que_persiste():
    varredura = POR_NOME["varredura"]
    inicial = varredura.incidente
    diminuiu = evoluir(varredura, inicial, "diminuiu")
    persiste = evoluir(varredura, inicial, "persiste")
    assert inicial.janelas < diminuiu.janelas < persiste.janelas
    assert diminuiu.estado == "aberto"
    assert diminuiu.fim == persiste.fim
