"""Treino do classificador: Random Forest do scikit-learn sobre a amostra do CICIoT2023.

Os parâmetros são os padrão do scikit-learn, com semente fixa e todos os núcleos da máquina, a
não ser que se peça um limite de núcleos. O limite muda o tempo de treino, e não o modelo. Não há `StandardScaler` nem outro passo antes do modelo: árvores não dependem de escala, e o
número que sai do extrator entra direto no classificador.

O modelo é salvo junto com o que é preciso para usá-lo e para refazê-lo: as features, na ordem
em que foi treinado, o alvo, a divisão, a semente e o hash da amostra. O arquivo fica fora do git.

Uso, a partir da raiz do repositório:
    python -m codigo.classificador.treinar
    python -m codigo.classificador.treinar --features 33 --alvo 7 --divisao grupos
    python -m codigo.classificador.treinar --nucleos 4
"""
import argparse
import os
import sys
import time
from pathlib import Path

import joblib
import sklearn
from sklearn.ensemble import RandomForestClassifier

from codigo.classificador.preparar import (
    ALVOS,
    CONJUNTOS_DE_FEATURES,
    DIVISOES,
    SEMENTE,
    alvo,
    carregar,
    dividir,
    matriz,
)

ARVORES = 100  # o padrão do scikit-learn, escrito aqui para constar do registro
TODOS_OS_NUCLEOS = -1  # o valor com que o scikit-learn usa todos os núcleos da máquina


def treinar(X, y, semente=SEMENTE, arvores=ARVORES, pesos=None, nucleos=TODOS_OS_NUCLEOS):
    """Treina o Random Forest e devolve o modelo e os segundos gastos no treino.

    `nucleos` limita os núcleos usados no treino, para a máquina continuar utilizável enquanto
    ele roda. As árvores dependem só da semente: com qualquer limite, o modelo é o mesmo.

    `pesos` é o peso de cada linha no treino, o `sample_weight` do scikit-learn. Sem ele, todas as
    linhas pesam o mesmo, e a priori que o modelo aprende é a proporção das classes em `y`. Na
    versão do scikit-learn que o projeto fixa, o peso é a chance de a linha entrar no sorteio com
    reposição que monta o conjunto de cada árvore: o que conta é a proporção entre os pesos, e não
    a escala deles.
    """
    modelo = RandomForestClassifier(n_estimators=arvores, random_state=semente, n_jobs=nucleos)
    inicio = time.perf_counter()
    modelo.fit(X, y, sample_weight=pesos)
    return modelo, time.perf_counter() - inicio


def prever(modelo, X):
    """Classe prevista para cada linha, igual a cada chamada.

    Com vários núcleos, o scikit-learn soma os votos das árvores na ordem em que elas terminam.
    A soma em ponto flutuante muda no último dígito conforme a ordem, e uma linha com duas
    classes empatadas pode trocar de lado de uma chamada para outra. Com um núcleo a ordem é
    fixa, e a mesma entrada dá sempre a mesma resposta.
    """
    nucleos = modelo.n_jobs
    modelo.n_jobs = 1
    try:
        return modelo.predict(X)
    finally:
        modelo.n_jobs = nucleos


def salvar(caminho, modelo, features, alvo, **registro):
    """Grava o modelo com o seu registro e devolve o tamanho do arquivo, em bytes.

    A gravação é feita num arquivo provisório, trocado de nome no fim: uma execução
    interrompida não deixa um modelo pela metade no lugar do anterior.
    """
    caminho = Path(caminho)
    caminho.parent.mkdir(parents=True, exist_ok=True)
    provisorio = caminho.with_name(caminho.name + ".parcial")
    pacote = {
        "modelo": modelo,
        "features": tuple(features),
        "alvo": alvo,
        "versoes": {"scikit-learn": sklearn.__version__},
        **registro,
    }
    try:
        joblib.dump(pacote, provisorio)
        os.replace(provisorio, caminho)
    finally:
        provisorio.unlink(missing_ok=True)
    return caminho.stat().st_size


def carregar_modelo(caminho):
    """Lê um modelo gravado por `salvar`: um dicionário com o modelo, as features, o alvo e o registro.

    O arquivo é lido com `joblib`, que executa o que estiver dentro dele. Só abra modelos
    gerados por este projeto.
    """
    recusa = ValueError(f"{Path(caminho).name}: não é um modelo gravado por codigo.classificador.treinar")
    try:
        pacote = joblib.load(caminho)
    except OSError:
        raise  # arquivo ausente ou sem permissão de leitura: o erro do sistema já diz o que houve
    except Exception:  # noqa: BLE001
        # Um arquivo que não é do joblib falha de muitas formas ao ser lido, conforme os bytes que traz.
        raise recusa from None
    if not isinstance(pacote, dict) or not {"modelo", "features", "alvo"} <= set(pacote):
        raise recusa
    return pacote


def _decimal(valor):
    return f"{valor:.1f}".replace(".", ",")


def _positivo(texto):
    try:
        valor = int(texto)
    except ValueError:
        raise argparse.ArgumentTypeError("a quantidade de árvores precisa ser um número inteiro") from None
    if valor < 1:
        raise argparse.ArgumentTypeError("a quantidade de árvores precisa ser de ao menos 1")
    return valor


def _nucleos(texto):
    try:
        valor = int(texto)
    except ValueError:
        raise argparse.ArgumentTypeError("a quantidade de núcleos precisa ser um número inteiro") from None
    if valor < 1 and valor != TODOS_OS_NUCLEOS:
        raise argparse.ArgumentTypeError(
            f"a quantidade de núcleos precisa ser de ao menos 1, ou {TODOS_OS_NUCLEOS} para usar todos"
        )
    return valor


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.classificador.treinar",
        description="Treina o Random Forest na parte de treino da amostra e salva o modelo.",
    )
    analisador.add_argument("--amostra", default="dados/processed/amostra.csv.gz")
    analisador.add_argument("--features", choices=list(CONJUNTOS_DE_FEATURES), default="39")
    analisador.add_argument("--alvo", choices=list(ALVOS), default="8", help="quantidade de classes (padrão: 8)")
    analisador.add_argument("--divisao", choices=list(DIVISOES), default="estratificada")
    analisador.add_argument("--semente", type=int, default=SEMENTE, help=f"padrão: {SEMENTE}")
    analisador.add_argument("--arvores", type=_positivo, default=ARVORES, help=f"padrão: {ARVORES}")
    analisador.add_argument(
        "--nucleos", type=_nucleos, default=TODOS_OS_NUCLEOS,
        help=f"núcleos usados no treino (padrão: {TODOS_OS_NUCLEOS}, todos). O modelo é o mesmo com qualquer valor",
    )
    analisador.add_argument(
        "--saida", default=None, help="arquivo do modelo, terminado em .joblib (padrão: modelos/rf_<opções>.joblib)"
    )
    try:
        argumentos = analisador.parse_args(argv)
    except SystemExit as encerramento:
        return encerramento.code
    saida = argumentos.saida or f"modelos/rf_f{argumentos.features}_{argumentos.divisao}_c{argumentos.alvo}.joblib"
    try:
        # Só .joblib é ignorado pelo git em qualquer pasta: outro nome poderia acabar versionado.
        if not saida.endswith(".joblib"):
            raise ValueError("o nome do arquivo de saída precisa terminar em .joblib")
        quadro, sha256 = carregar(argumentos.amostra)
        features = CONJUNTOS_DE_FEATURES[argumentos.features]
        treino, _ = dividir(quadro, argumentos.divisao, argumentos.semente)
        X = matriz(quadro, features)[treino]
        y = alvo(quadro["Label"].to_numpy(), argumentos.alvo)[treino]
        modelo, segundos = treinar(X, y, argumentos.semente, argumentos.arvores, nucleos=argumentos.nucleos)
        tamanho = salvar(
            saida, modelo, features, argumentos.alvo,
            divisao=argumentos.divisao, semente=argumentos.semente, arvores=argumentos.arvores,
            nucleos=argumentos.nucleos, amostra_sha256=sha256,
        )
    except (OSError, ValueError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrompido: nenhum modelo foi gravado", file=sys.stderr)
        return 130
    print(
        f"{len(treino)} linhas de treino, {len(features)} features, {len(modelo.classes_)} classes, "
        f"{argumentos.arvores} árvores em {_decimal(segundos)} s",
        file=sys.stderr,
    )
    print(f"modelo em {saida} ({_decimal(tamanho / 1e6)} MB)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
