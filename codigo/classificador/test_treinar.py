import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from codigo.classificador.preparar import (
    FEATURES_33,
    FEATURES_39,
    alvo,
    dividir,
    matriz,
)
from codigo.classificador.test_preparar import gravar_amostra, quadro_sintetico
from codigo.classificador.treinar import (
    ARVORES,
    carregar_modelo,
    main,
    prever,
    salvar,
    treinar,
)


def caso(por_classe=40):
    quadro = quadro_sintetico(por_classe=por_classe)
    return matriz(quadro, FEATURES_39), alvo(quadro["Label"].to_numpy(), "8")


def mesmas_arvores(a, b):
    return len(a.estimators_) == len(b.estimators_) and all(
        np.array_equal(p.tree_.feature, q.tree_.feature)
        and np.array_equal(p.tree_.threshold, q.tree_.threshold, equal_nan=True)
        and np.array_equal(p.tree_.value, q.tree_.value)
        for p, q in zip(a.estimators_, b.estimators_)
    )


def test_treinar_usa_o_random_forest_com_os_parametros_padrao():
    X, y = caso()
    modelo, segundos = treinar(X, y, semente=3)
    # O modelo é o classificador puro: sem StandardScaler nem outro passo antes dele.
    assert type(modelo) is RandomForestClassifier
    assert modelo.get_params() == RandomForestClassifier().get_params() | {"random_state": 3, "n_jobs": -1}
    assert ARVORES == 100 == len(modelo.estimators_)
    assert modelo.n_features_in_ == 39
    assert segundos > 0


def test_treinar_aprende_o_caso_sintetico():
    X, y = caso()
    modelo, _ = treinar(X, y, arvores=20)
    faceis = ~np.isin(y, ["DDoS", "DoS"])
    assert (modelo.predict(X[faceis]) == y[faceis]).all()


def test_treinar_com_a_mesma_semente_da_o_mesmo_modelo():
    X, y = caso()
    primeiro, _ = treinar(X, y, semente=5, arvores=15)
    segundo, _ = treinar(X, y, semente=5, arvores=15)
    assert mesmas_arvores(primeiro, segundo)
    assert np.array_equal(primeiro.feature_importances_, segundo.feature_importances_)
    assert np.array_equal(prever(primeiro, X), prever(segundo, X))
    outro, _ = treinar(X, y, semente=6, arvores=15)
    assert not mesmas_arvores(primeiro, outro)


def test_prever_soma_os_votos_das_arvores_em_ordem_fixa():
    X, y = caso()
    modelo, _ = treinar(X, y, arvores=15)
    previsto = prever(modelo, X)
    # A soma em ordem fixa: árvore por árvore, na ordem em que estão no modelo.
    votos = np.zeros((len(X), len(modelo.classes_)))
    for arvore in modelo.estimators_:
        votos += arvore.predict_proba(X)
    votos /= len(modelo.estimators_)
    assert np.array_equal(previsto, modelo.classes_[votos.argmax(axis=1)])
    assert all(np.array_equal(prever(modelo, X), previsto) for _ in range(5))
    # O modelo volta com a configuração de núcleos com que foi treinado.
    assert modelo.n_jobs == -1


def test_prever_usa_um_nucleo_e_devolve_o_modelo_como_estava():
    class Espia:
        n_jobs = -1

        def predict(self, X):
            self.nucleos_na_predicao = self.n_jobs
            if X is None:
                raise ValueError("sem entrada")
            return X

    espia = Espia()
    assert prever(espia, "entrada") == "entrada"
    assert espia.nucleos_na_predicao == 1 and espia.n_jobs == -1
    with pytest.raises(ValueError, match="sem entrada"):
        prever(espia, None)
    assert espia.n_jobs == -1


def test_treinar_aceita_menos_arvores_e_valor_vazio():
    X, y = caso()
    X[::7, 3] = np.nan
    modelo, _ = treinar(X, y, arvores=7)
    assert len(modelo.estimators_) == 7
    assert len(modelo.predict(X)) == len(y)


def test_salvar_e_carregar_devolvem_o_modelo_com_o_registro(tmp_path):
    X, y = caso()
    modelo, _ = treinar(X, y, arvores=5)
    caminho = tmp_path / "modelos" / "rf.joblib"
    tamanho = salvar(caminho, modelo, FEATURES_39, "8", semente=42, divisao="grupos")
    assert tamanho == caminho.stat().st_size > 0
    assert [p.name for p in caminho.parent.iterdir()] == ["rf.joblib"]
    pacote = carregar_modelo(caminho)
    assert pacote["features"] == FEATURES_39 and pacote["alvo"] == "8"
    assert pacote["semente"] == 42 and pacote["divisao"] == "grupos"
    assert mesmas_arvores(pacote["modelo"], modelo)
    assert np.array_equal(prever(pacote["modelo"], X), prever(modelo, X))


def test_carregar_modelo_recusa_arquivo_que_nao_e_um_modelo_salvo_aqui(tmp_path):
    import joblib

    caminho = tmp_path / "outro.joblib"
    joblib.dump({"qualquer": "coisa"}, caminho)
    with pytest.raises(ValueError, match="outro.joblib"):
        carregar_modelo(caminho)


def executar(tmp_path, *extras, amostra=None):
    saida = tmp_path / "modelos" / "rf.joblib"
    codigo = main(["--amostra", str(amostra or tmp_path / "amostra.csv.gz"), "--saida", str(saida), *extras])
    return codigo, saida


def test_main_treina_na_parte_de_treino_e_salva_o_modelo(tmp_path, capsys):
    quadro = quadro_sintetico(por_classe=40)
    sha256 = gravar_amostra(tmp_path / "amostra.csv.gz", quadro)
    codigo, saida = executar(
        tmp_path, "--features", "33", "--alvo", "7", "--divisao", "grupos", "--arvores", "10", "--semente", "9"
    )
    assert codigo == 0
    pacote = carregar_modelo(saida)
    assert pacote["features"] == FEATURES_33 and pacote["alvo"] == "7"
    assert (pacote["divisao"], pacote["semente"], pacote["arvores"]) == ("grupos", 9, 10)
    assert pacote["amostra_sha256"] == sha256
    # O modelo saiu da parte de treino da divisão registrada.
    treino, _ = dividir(quadro, "grupos", semente=9)
    esperado, _ = treinar(
        matriz(quadro, FEATURES_33)[treino], alvo(quadro["Label"].to_numpy(), "7")[treino], semente=9, arvores=10
    )
    assert mesmas_arvores(pacote["modelo"], esperado)
    assert "rf.joblib" in capsys.readouterr().err


def test_main_usa_os_padroes_do_projeto(tmp_path, capsys):
    gravar_amostra(tmp_path / "amostra.csv.gz", quadro_sintetico(por_classe=20))
    codigo, saida = executar(tmp_path)
    assert codigo == 0
    pacote = carregar_modelo(saida)
    assert pacote["features"] == FEATURES_39 and pacote["alvo"] == "8"
    assert (pacote["divisao"], pacote["semente"], pacote["arvores"]) == ("estratificada", 42, 100)


def test_main_sem_a_amostra_ou_com_saida_fora_do_padrao(tmp_path, capsys):
    codigo, saida = executar(tmp_path)
    assert codigo == 1 and not saida.exists()
    assert "erro:" in capsys.readouterr().err
    gravar_amostra(tmp_path / "amostra.csv.gz", quadro_sintetico(por_classe=20))
    codigo = main(["--amostra", str(tmp_path / "amostra.csv.gz"), "--saida", str(tmp_path / "rf.bin")])
    assert codigo == 1 and not (tmp_path / "rf.bin").exists()
    assert ".joblib" in capsys.readouterr().err


@pytest.mark.parametrize("extras", [("--features", "46"), ("--alvo", "5"), ("--divisao", "temporal"), ("--arvores", "0")])
def test_main_recusa_opcao_invalida(tmp_path, capsys, extras):
    gravar_amostra(tmp_path / "amostra.csv.gz", quadro_sintetico(por_classe=20))
    codigo, saida = executar(tmp_path, *extras)
    assert codigo == 2 and not saida.exists()
