import math

import pytest

from codigo.captura.calibrar import (
    colunas_divergentes,
    encaixar,
    fatiar,
    ler_oficial,
    valores_iguais,
)
from codigo.captura.extrator import COLUNAS


def linha(valor):
    return {coluna: float(valor) for coluna in COLUNAS}


def test_fatiar_abre_pedaco_novo_depois_de_passar_do_limite():
    quadros = [(float(i), b"\x00" * 1000) for i in range(7)]
    assert [len(p) for p in fatiar(quadros, limite=3000)] == [3, 3, 1]
    assert list(fatiar([])) == []


@pytest.mark.parametrize("a,b,esperado", [
    (1.0, 1.0, True),
    (1.0, 1.0 + 1e-12, True),
    (1.0, 1.001, False),
    (0.0, 0.0, True),
    (math.nan, math.nan, True),
    (math.nan, 1.0, False),
    (math.inf, math.inf, True),
    (math.inf, 1e300, False),
])
def test_valores_iguais(a, b, esperado):
    assert valores_iguais(a, b) is esperado


def test_ler_oficial_converte_vazio_e_infinito(tmp_path):
    caminho = tmp_path / "oficial.csv"
    valores = ["inf" if c == "Rate" else "" if c in ("Std", "Variance") else "2" for c in COLUNAS]
    caminho.write_text(",".join(COLUNAS) + "\n" + ",".join(valores) + "\n")
    (lida,) = ler_oficial(caminho)
    assert lida["Rate"] == math.inf and math.isnan(lida["Std"]) and lida["Number"] == 2.0


def test_ler_oficial_exige_as_39_colunas(tmp_path):
    caminho = tmp_path / "oficial.csv"
    caminho.write_text("Rate,Number\n1,2\n")
    with pytest.raises(ValueError, match="colunas"):
        ler_oficial(caminho)


def test_colunas_divergentes():
    assert colunas_divergentes(linha(1), linha(1)) == []
    outra = linha(1) | {"Rate": 9.0, "IAT": 7.0}
    assert colunas_divergentes(linha(1), outra) == ["Rate", "IAT"]


def test_encaixar_segue_a_ordem_do_oficial():
    a, b = [linha(0), linha(1), linha(2)], [linha(3), linha(4)]
    assert encaixar([a, b], b + a) == b + a


def test_encaixar_mesmo_com_a_primeira_linha_do_bloco_divergente():
    a, b, c = [linha(0), linha(1), linha(2)], [linha(3), linha(4)], [linha(5), linha(6)]
    oficial = c + [linha(3) | {"Rate": 99.0}, linha(4)] + a
    assert encaixar([a, b, c], oficial) == c + b + a
