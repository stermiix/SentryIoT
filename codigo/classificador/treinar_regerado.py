"""Treino e avaliação do Random Forest sobre os dados regerados dos pcaps.

Os dados vêm de `codigo.classificador.regerar`: as janelas de cada pcap do CICIoT2023 extraídas
pelo nosso extrator, com um tamanho de janela só para todas as classes e o rótulo de ataque
apenas nas janelas em que aparece um Raspberry Pi atacante. Este módulo treina um modelo por
tamanho de janela, 10 e 100, e mede os dois, para que a escolha da janela seja feita pelas
métricas.

O que ele faz, para cada janela:

1. Lê os CSVs regerados de todos os rótulos e limita cada rótulo a um teto de linhas, sorteadas
   com semente fixa, como na amostra do treino exploratório.
2. Divide treino e teste por tempo: dentro de cada pcap, as primeiras 70% das janelas vão para o
   treino e as últimas 30% para o teste, para não deixar janelas vizinhas dos dois lados. Um
   rótulo com mais de um pcap tem o último arquivo, em ordem de nome, inteiro no teste.
3. Treina o Random Forest de 7 categorias, com DDoS e DoS juntos, nas 39 features, com os
   parâmetros padrão do scikit-learn, e salva o modelo em `modelos/`, fora do git.
4. Mede na parte de teste: precisão, recall e F1 por categoria, macro-F1, taxa de falso positivo
   do benigno, matriz de confusão e, por pcap, a fração das janelas de teste na categoria
   esperada. Resume também os IPs de origem distintos por janela nas classes de DDoS e DoS, que é
   a base da separação entre os dois fora do modelo.
5. Grava `regeracao.md`, as tabelas em CSV, as matrizes de confusão e o manifesto de que tudo sai.

Os números são parciais enquanto faltarem pcaps: o relatório diz quais categorias e quantos
rótulos ainda não têm pcap. Quando chegarem, basta regerar e rodar este comando de novo.

Uso, a partir da raiz do repositório:
    python -m codigo.classificador.treinar_regerado --nucleos 4
    python -m codigo.classificador.treinar_regerado --refazer-relatorio
"""
import argparse
import datetime
import json
import platform
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn

from codigo.classificador.avaliar import (
    avaliar,
    contar,
    importancias,
    matriz_de_confusao,
)
from codigo.classificador.experimento import (
    MATRIZES,
    _campo,
    _decimal,
    _enumerar,
    _gravar_csv,
    _milhar,
    _pct,
    _pp,
    _tabela,
)
from codigo.classificador.mapeamento import CATEGORIA_DO_ROTULO, CATEGORIAS, ROTULOS
from codigo.classificador.preparar import (
    ALVOS,
    FEATURES_39,
    FRACAO_DE_TESTE_POR_TEMPO,
    SEMENTE,
    agrupar,
    alvo,
    carregar,
    dividir_por_tempo,
    impressao_digital,
    matriz,
)
from codigo.classificador.regerar import MANIFESTO as MANIFESTO_DA_REGERACAO
from codigo.classificador.regerar import nome_da_pasta
from codigo.classificador.treinar import (
    ARVORES,
    TODOS_OS_NUCLEOS,
    _nucleos,
    _positivo,
    prever,
    salvar,
    treinar,
)

MANIFESTO = "manifesto_treino_regerado.json"
RELATORIO = "regeracao.md"
METRICAS = "regeracao_metricas.csv"
POR_ARQUIVO = "regeracao_por_arquivo.csv"
MODELOS = "modelos"
# O modelo: 7 categorias, com DDoS e DoS juntos (decisão de 04/10/2026 no ROADMAP.md), nas 39 features.
ALVO = "7"
DIVISAO = "tempo"
# Teto de linhas por rótulo, como na amostra do treino exploratório.
TETO = 50_000
CLASSES = tuple(ALVOS[ALVO].classes)
EXTRAS = ("indice", "ips_origem", "ips_destino", "atacante")
# Quantas features o relatório lista, das mais importantes.
FEATURES_LISTADAS = 10


def ler_janela(destino, janela, teto=None, semente=SEMENTE):
    """Os CSVs regerados de uma janela, de todos os rótulos, em ordem de arquivo e de índice.

    Com `teto`, cada rótulo é limitado ao ser lido, arquivo a arquivo, para que os rótulos de
    milhões de janelas não fiquem inteiros na memória. Devolve o quadro e um resumo do que foi
    lido antes do teto: as linhas regeradas de cada rótulo e os IPs de origem por janela nas
    classes de DDoS e DoS.
    """
    pasta = Path(destino) / nome_da_pasta(janela)
    arquivos = sorted(pasta.glob("*.csv.gz"))
    if not arquivos:
        raise ValueError(f"nenhum CSV regerado em {pasta}: rode python -m codigo.classificador.regerar")
    gerador = np.random.default_rng(semente)
    partes, resumo = [], {"regeradas": {}, "ips_de_origem": []}
    for arquivo in arquivos:
        parte, _ = carregar(arquivo)
        faltam = [coluna for coluna in ("arquivo", *EXTRAS) if coluna not in parte.columns]
        if faltam:
            raise ValueError(f"{arquivo.name}: faltam as colunas {', '.join(faltam)}")
        for coluna in EXTRAS:
            parte[coluna] = parte[coluna].astype(np.int64)
        for rotulo, quantas in parte["Label"].value_counts().items():
            resumo["regeradas"][rotulo] = resumo["regeradas"].get(rotulo, 0) + int(quantas)
        resumo["ips_de_origem"] += ips_de_origem(parte)
        partes.append(parte if teto is None else limitar(parte, teto, gerador))
    quadro = pd.concat(partes, ignore_index=True)
    resumo["regeradas"] = {rotulo: resumo["regeradas"][rotulo] for rotulo in ROTULOS if rotulo in resumo["regeradas"]}
    resumo["ips_de_origem"].sort(key=lambda r: ROTULOS.index(r["rotulo"]))
    return quadro.sort_values(["arquivo", "indice"], kind="stable").reset_index(drop=True), resumo


def limitar(quadro, teto=TETO, semente=SEMENTE):
    """No máximo `teto` linhas por rótulo, sorteadas. As linhas ficam na ordem original.

    `semente` é um número ou um gerador já criado, para que a leitura arquivo a arquivo sorteie
    como se fosse de uma vez só.
    """
    gerador = semente if isinstance(semente, np.random.Generator) else np.random.default_rng(semente)
    rotulos = quadro["Label"].to_numpy()
    manter = np.zeros(len(quadro), dtype=bool)
    for rotulo in sorted(np.unique(rotulos).tolist()):
        posicoes = np.flatnonzero(rotulos == rotulo)
        if len(posicoes) > teto:
            posicoes = gerador.choice(posicoes, teto, replace=False)
        manter[posicoes] = True
    return quadro[manter]


def ips_de_origem(quadro):
    """Resumo dos IPs de origem distintos por janela nas classes de DDoS e DoS presentes."""
    resumo = []
    for rotulo in ROTULOS:
        if CATEGORIA_DO_ROTULO[rotulo] not in ("DDoS", "DoS"):
            continue
        ips = quadro.loc[quadro["Label"] == rotulo, "ips_origem"].to_numpy()
        if len(ips) == 0:
            continue
        resumo.append({
            "rotulo": rotulo,
            "categoria": CATEGORIA_DO_ROTULO[rotulo],
            "janelas": len(ips),
            "minimo": int(ips.min()),
            "p25": float(np.percentile(ips, 25)),
            "mediana": float(np.median(ips)),
            "p75": float(np.percentile(ips, 75)),
            "maximo": int(ips.max()),
            "media": float(ips.mean()),
            "ate_1": float((ips <= 1).mean()),
        })
    return resumo


def _por_arquivo(amostra, teste, previsto):
    """Por pcap: as janelas de teste, a fração na categoria esperada e as categorias previstas."""
    arquivos = amostra[["arquivo", "Label"]].drop_duplicates().sort_values("arquivo")
    de_teste = amostra.iloc[teste]
    por_arquivo = []
    for arquivo, rotulo in arquivos.itertuples(index=False):
        esperada = ALVOS[ALVO].classe_do_rotulo[rotulo]
        no_teste = (de_teste["arquivo"] == arquivo).to_numpy()
        previstas = {classe: 0 for classe in CLASSES}
        if no_teste.any():
            contagem = contar(de_teste["Label"].to_numpy()[no_teste], previsto[no_teste], CLASSES).sum(axis=0)
            previstas = {classe: int(contagem[classe]) for classe in CLASSES}
        quantas = int(no_teste.sum())
        por_arquivo.append({
            "arquivo": arquivo,
            "rotulo": rotulo,
            "esperada": esperada,
            "janelas_de_teste": quantas,
            "na_esperada": previstas[esperada] / quantas if quantas else None,
            "previstas": previstas,
        })
    return por_arquivo


def _por_rotulo(regeracao, resumo, amostra, treino, teste, arquivos_de_teste):
    de_treino, de_teste = amostra.iloc[treino], amostra.iloc[teste]
    arquivos_do_rotulo = {r["rotulo"]: r["arquivos"] for r in regeracao["rotulos"]}
    por_rotulo = []
    for rotulo, regeradas in resumo["regeradas"].items():
        no_teste = de_teste[de_teste["Label"] == rotulo]
        por_rotulo.append({
            "rotulo": rotulo,
            "categoria": CATEGORIA_DO_ROTULO[rotulo],
            "arquivos": sorted(arquivos_do_rotulo.get(rotulo, [])),
            "regeradas": regeradas,
            "amostra": int((amostra["Label"] == rotulo).sum()),
            "treino": int((de_treino["Label"] == rotulo).sum()),
            "teste": len(no_teste),
            "linhas_no_arquivo_de_teste": int(no_teste["arquivo"].isin(arquivos_de_teste).sum()),
        })
    return por_rotulo


def treinar_janela(regeracao, destino, janela, semente=SEMENTE, arvores=ARVORES, nucleos=TODOS_OS_NUCLEOS,
                   teto=TETO, modelos=MODELOS):
    """Lê, limita, divide, treina, avalia e salva o modelo de uma janela. Devolve o registro dela."""
    amostra, resumo = ler_janela(destino, janela, teto, semente)
    totais = {p["arquivo"]: p["janelas"][str(janela)]["extraidas"] for p in regeracao["pcaps"]}
    treino, teste = dividir_por_tempo(amostra, FRACAO_DE_TESTE_POR_TEMPO, totais)
    if len(teste) == 0 or len(treino) == 0:
        raise ValueError(f"janela de {janela}: a divisão por tempo deixou o treino ou o teste vazio")
    arquivos_de_teste = []
    for arquivos in amostra.groupby("Label")["arquivo"].unique().values:
        if len(arquivos) > 1:
            arquivos_de_teste.append(max(arquivos.tolist()))
    X = matriz(amostra, FEATURES_39)
    y = alvo(amostra["Label"].to_numpy(), ALVO)
    modelo, segundos = treinar(X[treino], y[treino], semente, arvores, nucleos=nucleos)
    X_teste = X[teste]
    previsto = prever(modelo, X_teste)
    rotulos_de_teste = amostra["Label"].to_numpy()[teste]
    avaliacao = avaliar(previsto, rotulos_de_teste, ALVO, grupos=agrupar(X_teste))
    # A medida nos arquivos inteiros de teste: pcaps que o modelo não viu em nenhuma janela.
    inteiros = amostra["arquivo"].to_numpy()[teste]
    nos_inteiros = np.isin(inteiros, arquivos_de_teste)
    avaliacao_inteiros = (
        avaliar(previsto[nos_inteiros], rotulos_de_teste[nos_inteiros], ALVO) if nos_inteiros.any() else None
    )
    caminho = Path(modelos) / f"rf_regerado_janela_{janela}.joblib"
    tamanho = salvar(
        caminho, modelo, FEATURES_39, ALVO, divisao=DIVISAO, semente=semente, arvores=arvores, nucleos=nucleos,
        janela=janela, teto=teto, fracao_de_teste=FRACAO_DE_TESTE_POR_TEMPO, treino_sha256=impressao_digital(treino),
    )
    return {
        "janela": janela,
        "linhas": {"regeradas": sum(resumo["regeradas"].values()), "amostra": len(amostra), "treino": len(treino),
                   "teste": len(teste)},
        "por_rotulo": _por_rotulo(regeracao, resumo, amostra, treino, teste, arquivos_de_teste),
        "arquivos_de_teste": sorted(arquivos_de_teste),
        "divisao": {"treino_sha256": impressao_digital(treino), "teste_sha256": impressao_digital(teste)},
        "treino_segundos": segundos,
        "avaliacao": avaliacao,
        "avaliacao_arquivos_inteiros": avaliacao_inteiros,
        "importancias": importancias(modelo, FEATURES_39),
        "por_arquivo": _por_arquivo(amostra, teste, previsto),
        "ips_de_origem": resumo["ips_de_origem"],
        "modelo": {"arquivo": caminho.name, "bytes": tamanho},
    }


def rodar(regeracao, destino, semente=SEMENTE, arvores=ARVORES, nucleos=TODOS_OS_NUCLEOS, teto=TETO,
          modelos=MODELOS, ao_terminar=None):
    inicio = time.perf_counter()
    janelas = []
    for janela in regeracao["janelas"]:
        registro = treinar_janela(regeracao, destino, janela, semente, arvores, nucleos, teto, modelos)
        janelas.append(registro)
        if ao_terminar is not None:
            ao_terminar(registro)
    return {"janelas": janelas, "duracao_segundos": time.perf_counter() - inicio}


def resumir_rodada(m):
    """O que fica de uma rodada quando outra a substitui: os pcaps, os rótulos e as medidas principais."""
    return {
        "gerado_em": m["gerado_em"],
        "pcaps": len(m["regeracao"]["pcaps"]),
        "rotulos": sorted(r["rotulo"] for r in m["regeracao"]["rotulos"]),
        "rotulos_sem_pcap": m["rotulos_sem_pcap"],
        "janelas": [
            {
                "janela": j["janela"],
                "teste": j["linhas"]["teste"],
                "acuracia": j["avaliacao"]["amostra"]["acuracia"],
                "macro_f1": j["avaliacao"]["amostra"]["macro_f1"],
                "falso_positivo_benigno": j["avaliacao"]["amostra"]["falso_positivo_benigno"],
                "por_classe": {
                    classe: {"recall": me["recall"], "f1": me["f1"], "suporte": me["suporte"]}
                    for classe, me in j["avaliacao"]["amostra"]["por_classe"].items()
                },
            }
            for j in m["janelas"]
        ],
    }


def rodadas_anteriores(caminho):
    """As rodadas registradas no manifesto que está em `caminho`, mais ele próprio resumido."""
    try:
        anterior = json.loads(Path(caminho).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    try:
        return [*anterior.get("rodadas_anteriores", []), resumir_rodada(anterior)]
    except KeyError:
        return anterior.get("rodadas_anteriores", [])


def montar_manifesto(registro, regeracao, caminho_da_regeracao, destino, semente, arvores, nucleos, teto,
                     anteriores=()):
    presentes = {r["rotulo"] for r in regeracao["rotulos"]}
    categorias = {CATEGORIA_DO_ROTULO[rotulo] for rotulo in presentes}
    return {
        "descricao": (
            "Random Forest de 7 categorias treinado nos dados regerados dos pcaps do CICIoT2023, com janela de "
            + _enumerar(regeracao["janelas"]) + " quadros, divisão por tempo e teto de linhas por rótulo"
        ),
        "gerado_por": "python -m codigo.classificador.treinar_regerado",
        "gerado_em": datetime.datetime.now(tz=datetime.UTC).astimezone().strftime("%Y-%m-%d"),
        "semente": semente,
        "arvores": arvores,
        "nucleos": nucleos,
        "teto": teto,
        "alvo": ALVO,
        "features": len(FEATURES_39),
        "divisao": DIVISAO,
        "fracao_de_teste": FRACAO_DE_TESTE_POR_TEMPO,
        "parametros": {
            "modelo": "sklearn.ensemble.RandomForestClassifier",
            "demais_parametros": "padrão do scikit-learn",
            "escalonamento": "nenhum",
            "predicao": "votos somados em ordem fixa, com um núcleo",
        },
        "versoes": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit-learn": sklearn.__version__,
        },
        "regeracao": {
            "manifesto": Path(caminho_da_regeracao).as_posix(),
            "gerado_em": regeracao["gerado_em"],
            "dataset": regeracao["dataset"],
            "destino": str(destino),
            "regra": regeracao["regra"],
            "pcaps": regeracao["pcaps"],
            "rotulos": regeracao["rotulos"],
        },
        "classes": list(CLASSES),
        "categorias_sem_pcap": [c for c in CATEGORIAS if c not in categorias],
        "rotulos_sem_pcap": len(ROTULOS) - len(presentes),
        "janelas": registro["janelas"],
        "duracao_segundos": registro["duracao_segundos"],
        "rodadas_anteriores": list(anteriores),
    }


def _por_rotulo_do_alvo(avaliacao):
    matriz_por_rotulo = avaliacao["matriz_por_rotulo"]
    return pd.DataFrame(
        matriz_por_rotulo["contagem"], index=matriz_por_rotulo["rotulos"], columns=matriz_por_rotulo["classes"],
    )


def gravar(manifesto, pasta):
    """Grava o manifesto e o que sai dele: relatório, tabelas e matrizes de confusão."""
    pasta = Path(pasta)
    (pasta / MATRIZES).mkdir(parents=True, exist_ok=True)
    (pasta / MANIFESTO).write_text(json.dumps(manifesto, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (pasta / RELATORIO).write_text(montar_relatorio(manifesto), encoding="utf-8")
    _gravar_csv(
        pasta / METRICAS,
        ["janela", "classe", "precisao", "recall", "f1", "suporte", "taxa_falso_positivo"],
        [
            [
                j["janela"], classe, _campo(m["precisao"]), _campo(m["recall"]), _campo(m["f1"]), round(m["suporte"]),
                _campo(m["taxa_falso_positivo"]),
            ]
            for j in manifesto["janelas"] for classe, m in j["avaliacao"]["amostra"]["por_classe"].items()
        ],
    )
    _gravar_csv(
        pasta / POR_ARQUIVO,
        ["janela", "arquivo", "rotulo", "categoria_esperada", "janelas_de_teste", "na_esperada", *CLASSES],
        [
            [
                j["janela"], p["arquivo"], p["rotulo"], p["esperada"], p["janelas_de_teste"], _campo(p["na_esperada"]),
                *(p["previstas"][classe] for classe in CLASSES),
            ]
            for j in manifesto["janelas"] for p in j["por_arquivo"]
        ],
    )
    for j in manifesto["janelas"]:
        nome = f"regerado_janela_{j['janela']}"
        por_rotulo = _por_rotulo_do_alvo(j["avaliacao"])
        por_rotulo.to_csv(pasta / MATRIZES / f"{nome}_por_rotulo.csv", index_label="rotulo", lineterminator="\n")
        matriz_de_confusao(por_rotulo, ALVO).to_csv(
            pasta / MATRIZES / f"{nome}.csv", index_label="classe_real", lineterminator="\n",
        )


# --- relatório -------------------------------------------------------------------------------


def _data(m):
    return datetime.date.fromisoformat(m["gerado_em"]).strftime("%d/%m/%Y")


def _janelas(m):
    return [str(j["janela"]) for j in m["janelas"]]


def _cabecalho(m):
    v = m["versoes"]
    return [
        "# Treino sobre os dados regerados",
        "",
        (
            f"Gerado por `{m['gerado_por']}` em {_data(m)}, com Python {v['python']}, scikit-learn "
            f"{v['scikit-learn']}, pandas {v['pandas']} e numpy {v['numpy']}."
        ),
        "",
        "O modelo treinado no `MERGED_CSV` oficial aprende o tamanho da janela, de 100 quadros nas classes de",
        "DDoS, DoS e Mirai e de 10 nas demais, em vez do comportamento do tráfego (`teste_da_janela.md`), e o",
        "rótulo oficial é dado ao arquivo inteiro, mesmo nas janelas sem nenhum quadro do atacante",
        "(`janelas_sem_atacante.md`). Por isso os dados de treino foram gerados de novo a partir dos pcaps, com o",
        "nosso extrator, em janela única e com o rótulo decidido janela a janela (decisão de 10/10/2026 no",
        "`ROADMAP.md`). Este relatório traz o Random Forest de 7 categorias treinado nesses dados, um modelo por",
        "janela, de " + _enumerar(_janelas(m)) + " quadros, e as medidas de cada um na parte de teste.",
    ]


def _dados(m):
    r = m["regeracao"]
    janelas = _janelas(m)
    cabecalho = ["Arquivo", "Rótulo", "Categoria", "Pacotes"]
    for janela in janelas:
        cabecalho += [f"Janelas de {janela}", f"Mantidas ({janela})"]
    cabecalho.append("Extração (s)")
    linhas = []
    for p in r["pcaps"]:
        linha = [f"`{p['arquivo']}`", p["rotulo"], p["categoria"], _milhar(p["pacotes"])]
        for janela in janelas:
            c = p["janelas"][janela]
            fracao = c["mantidas"] / c["extraidas"] if c["extraidas"] else None
            linha += [_milhar(c["extraidas"]), f"{_milhar(c['mantidas'])} ({_pct(fracao, 1)})"]
        linha.append(_decimal(p["segundos"]))
        linhas.append(linha)
    por_rotulo = [
        [rot["rotulo"], rot["categoria"], _enumerar(f"`{a}`" for a in rot["arquivos"])]
        + [_milhar(rot["linhas"][janela]) for janela in janelas]
        for rot in r["rotulos"]
    ]
    secao = [
        "## Os dados regerados",
        "",
        f"Os pcaps da pasta do dataset em {datetime.date.fromisoformat(r['gerado_em']).strftime('%d/%m/%Y')}, lidos",
        "inteiros pelo extrator em leitura contínua, com os dois tamanhos de janela. Regra de rótulo: num pcap",
        "benigno toda janela é `BenignTraffic`; num pcap de ataque a janela recebe o rótulo do arquivo se tem",
        "quadro com MAC de um Raspberry Pi atacante na origem ou no destino, e é descartada se não tem. A janela",
        "descartada não vira benigna, porque o tráfego de fundo de uma captura de ataque pode estar contaminado.",
        "",
        *_tabela(cabecalho, linhas),
        "",
        "Linhas regeradas por rótulo, somando os arquivos dele:",
        "",
        *_tabela(["Rótulo", "Categoria", "Arquivos", *(f"Linhas ({janela})" for janela in janelas)], por_rotulo),
        "",
    ]
    if m["categorias_sem_pcap"]:
        secao.append(
            f"Categorias que ainda não têm pcap: {_enumerar(m['categorias_sem_pcap'])}. "
            f"{m['rotulos_sem_pcap']} dos 34 rótulos ainda não têm pcap."
        )
    else:
        secao.append(
            f"Todas as {len(CLASSES)} categorias do modelo têm ao menos um pcap. {m['rotulos_sem_pcap']} dos 34 "
            "rótulos ainda não têm pcap."
        )
    secao += [
        "Os números deste relatório são parciais até os outros pcaps chegarem: o modelo só conhece as variantes",
        "de cada categoria que estão na tabela. Com pcaps novos na pasta, `regerar` extrai só eles e este comando",
        "refaz o treino e o relatório.",
    ]
    return secao


def _treino_e_teste(m):
    linhas = [
        [
            j["janela"], _milhar(j["linhas"]["regeradas"]), _milhar(j["linhas"]["amostra"]),
            _milhar(j["linhas"]["treino"]), _milhar(j["linhas"]["teste"]),
            _enumerar(f"`{a}`" for a in j["arquivos_de_teste"]) if j["arquivos_de_teste"] else "nenhum",
            _decimal(j["treino_segundos"]),
        ]
        for j in m["janelas"]
    ]
    secao = [
        "## Treino e teste",
        "",
        f"Cada rótulo entra com no máximo {_milhar(m['teto'])} linhas, sorteadas com a semente {m['semente']}, como na",
        "amostra do treino exploratório. A divisão é por tempo: dentro de cada pcap, as primeiras",
        f"{_pct(1 - m['fracao_de_teste'], 0)} das janelas vão para o treino e as últimas {_pct(m['fracao_de_teste'], 0)}",
        "para o teste, com o corte no total de janelas do arquivo, para não deixar janelas vizinhas dos dois lados.",
        "Um rótulo com mais de um pcap tem o último arquivo, em ordem de nome, inteiro no teste. O modelo é o",
        f"`RandomForestClassifier` do scikit-learn com {m['arvores']} árvores e os demais parâmetros padrão, sem",
        f"`StandardScaler`, com as {m['features']} features e {len(CLASSES)} categorias (DDoS e DoS juntos).",
        "",
        *_tabela(
            ["Janela", "Linhas regeradas", "Após o teto", "Treino", "Teste", "Arquivos inteiros no teste", "Treino (s)"],
            linhas,
        ),
    ]
    primeira = m["janelas"][0]
    inteiros = set(primeira["arquivos_de_teste"])
    secao += [
        "",
        "Como cada rótulo foi dividido. O rótulo com mais de um pcap tem um arquivo inteiro no teste, e o modelo",
        "não vê nenhuma janela dele; nos demais, o teste é o fim do próprio pcap.",
        "",
        *_tabela(
            ["Rótulo", "Arquivos", "Divisão"],
            [
                [
                    r["rotulo"], _enumerar(f"`{a}`" for a in r["arquivos"]),
                    "por arquivo: " + _enumerar(f"`{a}`" for a in r["arquivos"] if a in inteiros) + " inteiro no teste"
                    if len(r["arquivos"]) > 1 else "por tempo",
                ]
                for r in primeira["por_rotulo"]
            ],
        ),
    ]
    for j in m["janelas"]:
        secao += [
            "",
            f"Linhas por rótulo com janela de {j['janela']}:",
            "",
            *_tabela(
                ["Rótulo", "Categoria", "Regeradas", "Após o teto", "Treino", "Teste"],
                [
                    [r["rotulo"], r["categoria"], _milhar(r["regeradas"]), _milhar(r["amostra"]), _milhar(r["treino"]),
                     _milhar(r["teste"])]
                    for r in j["por_rotulo"]
                ],
            ),
        ]
    return secao


def _mais_prevista(previstas):
    classe, quantas = max(previstas.items(), key=lambda par: par[1])
    return classe if quantas else "nenhuma"


def _resultados(m, j):
    a = j["avaliacao"]["amostra"]
    por_rotulo = _por_rotulo_do_alvo(j["avaliacao"])
    confusao = matriz_de_confusao(por_rotulo, ALVO)
    por_classe = [
        [classe, _milhar(me["suporte"]), _pct(me["precisao"]), _pct(me["recall"]), _pct(me["f1"]),
         _pct(me["taxa_falso_positivo"])]
        for classe, me in a["por_classe"].items()
    ]
    matriz_linhas = [
        [classe, *(_milhar(confusao.loc[classe, prevista]) for prevista in CLASSES)] for classe in CLASSES
    ]
    por_arquivo = [
        [f"`{p['arquivo']}`", p["rotulo"], p["esperada"], _milhar(p["janelas_de_teste"]),
         _pct(p["na_esperada"]) if p["na_esperada"] is not None else "sem teste", _mais_prevista(p["previstas"])]
        for p in j["por_arquivo"]
    ]
    importantes = list(j["importancias"].items())[:FEATURES_LISTADAS]
    inteiros = []
    if j["avaliacao_arquivos_inteiros"] is not None:
        ai = j["avaliacao_arquivos_inteiros"]["amostra"]
        inteiros = [
            "",
            f"### Nos arquivos inteiros de teste, com janela de {j['janela']}",
            "",
            "É a medida honesta: " + _enumerar(f"`{a}`" for a in j["arquivos_de_teste"]) + ", pcaps de que o modelo "
            f"não viu nenhuma janela. {_milhar(j['avaliacao_arquivos_inteiros']['linhas'])} linhas, acurácia "
            f"{_pct(ai['acuracia'])}, macro-F1 {_pct(ai['macro_f1'])} entre as categorias presentes, tráfego benigno "
            f"classificado como ataque {_pct(ai['falso_positivo_benigno'])}. A precisão e o falso positivo de cada "
            "categoria valem só dentro desses arquivos.",
            "",
            *_tabela(
                ["Categoria", "Linhas de teste", "Precisão", "Recall", "F1"],
                [
                    [classe, _milhar(me["suporte"]), _pct(me["precisao"]), _pct(me["recall"]), _pct(me["f1"])]
                    for classe, me in ai["por_classe"].items() if me["suporte"]
                ],
            ),
        ]
    return [
        f"## Resultados com janela de {j['janela']}",
        "",
        (
            f"Na parte de teste, de {_milhar(j['linhas']['teste'])} linhas: acurácia {_pct(a['acuracia'])}, macro-F1 "
            f"{_pct(a['macro_f1'])}, F1 ponderado {_pct(a['f1_ponderado'])}, teto destas linhas {_pct(a['teto'])}. "
            f"Tráfego benigno classificado como ataque: {_pct(a['falso_positivo_benigno'])}."
        ),
        "",
        *_tabela(["Categoria", "Linhas de teste", "Precisão", "Recall", "F1", "Falso positivo"], por_classe),
        "",
        "Matriz de confusão, com a categoria real nas linhas e a prevista nas colunas:",
        "",
        *_tabela(["Real \\ prevista", *CLASSES], matriz_linhas),
        "",
        "Por pcap, a fração das janelas de teste na categoria esperada e a categoria mais prevista:",
        "",
        *_tabela(["Arquivo", "Rótulo", "Categoria esperada", "Janelas de teste", "Na esperada", "Mais prevista"],
                 por_arquivo),
        "",
        f"As {FEATURES_LISTADAS} features mais importantes (redução média de impureza): "
        + _enumerar(f"`{feature}` ({_pct(valor, 1)})" for feature, valor in importantes) + ".",
        *inteiros,
    ]


def _lado_a_lado(m):
    janelas = m["janelas"]
    rotulos = [str(j["janela"]) for j in janelas]
    linhas = []
    for classe in CLASSES:
        linha = [classe]
        for medida in ("recall", "f1"):
            linha += [_pct(j["avaliacao"]["amostra"]["por_classe"][classe][medida]) for j in janelas]
        linhas.append(linha)
    globais = [
        ["Macro-F1", *(_pct(j["avaliacao"]["amostra"]["macro_f1"]) for j in janelas)],
        ["Acurácia", *(_pct(j["avaliacao"]["amostra"]["acuracia"]) for j in janelas)],
        ["Benigno classificado como ataque", *(_pct(j["avaliacao"]["amostra"]["falso_positivo_benigno"]) for j in janelas)],
        ["Linhas de teste", *(_milhar(j["linhas"]["teste"]) for j in janelas)],
    ]
    melhor_f1 = max(janelas, key=lambda j: j["avaliacao"]["amostra"]["macro_f1"])
    menor_fp = min(janelas, key=lambda j: j["avaliacao"]["amostra"]["falso_positivo_benigno"] or 0)
    return [
        "## As duas janelas lado a lado",
        "",
        *_tabela(["Medida", *(f"Janela de {r}" for r in rotulos)], globais),
        "",
        *_tabela(
            ["Categoria", *(f"Recall ({r})" for r in rotulos), *(f"F1 ({r})" for r in rotulos)], linhas,
        ),
        "",
        f"O maior macro-F1 é o da janela de {melhor_f1['janela']}, e a menor taxa de tráfego benigno classificado",
        f"como ataque é a da janela de {menor_fp['janela']}. Com janela de 100, cada pcap gera cerca de um décimo das",
        "janelas que gera com 10, e as classes raras ficam com poucas linhas de teste; na operação, a janela de 10",
        "decide com menos quadros e responde mais vezes por segundo.",
    ]


def _ips(m):
    secao = [
        "## IPs de origem por janela em DDoS e DoS",
        "",
        "O modelo não separa DDoS de DoS: as features descrevem os pacotes, não quantas máquinas atacam. A separação",
        "sai da quantidade de IPs de origem distintos das janelas do incidente, fora do modelo. A tabela resume essa",
        "quantidade nas janelas regeradas de cada classe de DDoS e DoS presente, antes do teto.",
    ]
    for j in m["janelas"]:
        if not j["ips_de_origem"]:
            continue
        secao += [
            "",
            f"Janela de {j['janela']}:",
            "",
            *_tabela(
                ["Rótulo", "Categoria", "Janelas", "Mínimo", "P25", "Mediana", "P75", "Máximo", "Média",
                 "Janelas com até 1 IP de origem"],
                [
                    [r["rotulo"], r["categoria"], _milhar(r["janelas"]), r["minimo"], _decimal(r["p25"]),
                     _decimal(r["mediana"]), _decimal(r["p75"]), r["maximo"], _decimal(r["media"], 2), _pct(r["ate_1"])]
                    for r in j["ips_de_origem"]
                ],
            ),
        ]
    if all(not j["ips_de_origem"] for j in m["janelas"]):
        secao += ["", "Nenhuma classe de DDoS ou DoS tem pcap ainda."]
        return secao
    secao += [""]
    for j in m["janelas"]:
        ddos = [r["mediana"] for r in j["ips_de_origem"] if r["categoria"] == "DDoS"]
        dos = [r["mediana"] for r in j["ips_de_origem"] if r["categoria"] == "DoS"]
        if not ddos or not dos:
            continue
        separa = min(ddos) > max(dos)
        secao.append(
            f"Com janela de {j['janela']}, a mediana de IPs de origem por janela vai de {_decimal(min(ddos))} a "
            f"{_decimal(max(ddos))} nas classes de DDoS e de {_decimal(min(dos))} a {_decimal(max(dos))} nas de DoS: "
            + ("as faixas não se cruzam." if separa else "as faixas se cruzam, e a contagem de uma janela isolada não "
               "separa as duas categorias. A separação precisa olhar as janelas do incidente em conjunto.")
        )
    return secao


def _diferenca(novo, antigo):
    if novo is None or antigo is None:
        return "sem valor"
    return f"{_pct(antigo)} para {_pct(novo)} ({_pp(novo - antigo)} p.p.)"


def _rodadas_anteriores(m):
    anteriores = m.get("rodadas_anteriores", [])
    if not anteriores:
        return []
    secao = [
        "## Rodadas anteriores, como referência",
        "",
        "As medidas das rodadas parciais, antes de os outros pcaps chegarem. Cada rodada é o mesmo comando sobre",
        "os pcaps que havia na pasta na data.",
    ]
    for rodada in anteriores:
        rotulos = [str(j["janela"]) for j in rodada["janelas"]]
        secao += [
            "",
            (
                f"Rodada de {datetime.date.fromisoformat(rodada['gerado_em']).strftime('%d/%m/%Y')}: "
                f"{rodada['pcaps']} pcaps, {len(rodada['rotulos'])} rótulos ({rodada['rotulos_sem_pcap']} sem pcap)."
            ),
            "",
            *_tabela(
                ["Medida", *(f"Janela de {r}" for r in rotulos)],
                [
                    ["Macro-F1", *(_pct(j["macro_f1"]) for j in rodada["janelas"])],
                    ["Acurácia", *(_pct(j["acuracia"]) for j in rodada["janelas"])],
                    ["Benigno classificado como ataque", *(_pct(j["falso_positivo_benigno"]) for j in rodada["janelas"])],
                    ["Linhas de teste", *(_milhar(j["teste"]) for j in rodada["janelas"])],
                ],
            ),
            "",
            *_tabela(
                ["Categoria", *(f"Recall ({r})" for r in rotulos), *(f"F1 ({r})" for r in rotulos)],
                [
                    [classe, *(_pct(j["por_classe"][classe]["recall"]) for j in rodada["janelas"]),
                     *(_pct(j["por_classe"][classe]["f1"]) for j in rodada["janelas"])]
                    for classe in CLASSES
                ],
            ),
        ]
    ultima = anteriores[-1]
    presentes = sorted(r["rotulo"] for r in m["regeracao"]["rotulos"])
    entraram = [r for r in presentes if r not in ultima["rotulos"]]
    sairam = [r for r in ultima["rotulos"] if r not in presentes]
    secao += ["", "O que mudou da última rodada para esta:", ""]
    secao.append(
        f"- Pcaps: de {ultima['pcaps']} para {len(m['regeracao']['pcaps'])}. "
        + (f"Rótulos que entraram: {_enumerar(entraram)}. " if entraram else "Nenhum rótulo entrou. ")
        + (f"Rótulos que saíram: {_enumerar(sairam)}." if sairam else "")
    )
    for j in m["janelas"]:
        anterior = next((a for a in ultima["janelas"] if a["janela"] == j["janela"]), None)
        if anterior is None:
            continue
        a = j["avaliacao"]["amostra"]
        secao.append(
            f"- Janela de {j['janela']}: macro-F1 de {_diferenca(a['macro_f1'], anterior['macro_f1'])}; benigno "
            f"classificado como ataque de {_diferenca(a['falso_positivo_benigno'], anterior['falso_positivo_benigno'])}; "
            "recall por categoria: "
            + "; ".join(
                f"{classe} de {_diferenca(a['por_classe'][classe]['recall'], anterior['por_classe'][classe]['recall'])}"
                for classe in CLASSES
            ) + "."
        )
    return secao


def _ressalvas(m):
    return [
        "## Ressalvas",
        "",
        "- **Os números são parciais.** Faltam pcaps de " + (
            _enumerar(m["categorias_sem_pcap"]) + " e de " if m["categorias_sem_pcap"] else ""
        ) + f"{m['rotulos_sem_pcap']} rótulos. Uma categoria representada por uma ou duas variantes pode ficar mais",
        "  fácil do que será com todas.",
        (
            "- **Uma semente.** Divisão por tempo não sorteia, mas o teto por rótulo e o modelo usam a semente "
            f"{m['semente']}, e nada foi repetido com outra."
        ),
        "- **O teste vem das mesmas capturas.** As janelas de teste são o fim de cada pcap, da mesma rede e do",
        "  mesmo dia das de treino. A medida vale para a captura, não para outra rede. O rótulo com dois pcaps",
        "  tem um arquivo inteiro no teste, que é mais exigente; nos demais, as janelas na fronteira do corte",
        "  são vizinhas das de treino.",
        "- **As janelas descartadas não são avaliadas.** O tráfego de fundo dos pcaps de ataque fica fora do",
        "  treino e do teste. O que o modelo faz com ele não está medido aqui.",
        "- **O atacante também gera tráfego benigno.** O MAC `dc:a6:32:dc:27:d5` aparece em cerca de 1% dos",
        "  quadros dos pcaps benignos (`janelas_sem_atacante.md`). A regra de rótulo não o usa nos pcaps benignos,",
        "  então parte do tráfego comum desse dispositivo está no treino como benigno.",
        "- **As seis colunas da janela deixaram de ser atalho.** Com uma janela só, `Number` vale o mesmo em todas",
        "  as classes, a não ser na última janela de cada pcap, que pode ficar incompleta.",
    ]


def _como_foram_obtidos(m):
    r = m["regeracao"]
    return [
        "## Como os números foram obtidos",
        "",
        (
            f"- Comando: `{m['gerado_por']}`, a partir da raiz do repositório, depois de `python -m "
            "codigo.classificador.regerar`. Ele refaz a leitura, o teto, a divisão, o treino, a avaliação e este "
            "relatório."
        ),
        (
            f"- Dados: `{r['destino']}/janela_<W>/<rotulo>.csv.gz`, registrados em `{Path(r['manifesto']).name}` "
            f"(gerado em {datetime.date.fromisoformat(r['gerado_em']).strftime('%d/%m/%Y')}, pcaps em "
            f"`{r['dataset']}`), com o SHA-256 de cada pcap."
        ),
        "- Modelos: um por janela, em `modelos/`, fora do git: "
        + _enumerar(f"`{j['modelo']['arquivo']}` ({_decimal(j['modelo']['bytes'] / 1e6)} MB)" for j in m["janelas"])
        + f". Treinados com {m['nucleos'] if m['nucleos'] > 0 else 'todos os'} núcleos; a quantidade de núcleos muda "
        "o tempo, e não o modelo. Predição com um núcleo, em ordem fixa.",
        f"- Divisões: o SHA-256 das posições de treino e de teste de cada janela está em `{MANIFESTO}`.",
        (
            f"- `{METRICAS}` tem uma linha por janela e categoria; `{POR_ARQUIVO}`, uma por janela e pcap; "
            f"`{MATRIZES}/regerado_janela_<W>.csv` é a matriz de confusão e `_por_rotulo.csv` abre a classe real nos "
            "34 rótulos."
        ),
        f"- Tempo total, na máquina em que rodou: {_decimal(m['duracao_segundos'])} s.",
        "- Com os mesmos CSVs regerados e a mesma semente, os números saem iguais. Só mudam a data e os tempos.",
    ]


def montar_relatorio(m):
    secoes = [_cabecalho(m), _dados(m), _treino_e_teste(m)]
    secoes += [_resultados(m, j) for j in m["janelas"]]
    secoes += [_lado_a_lado(m), _ips(m), _rodadas_anteriores(m), _ressalvas(m), _como_foram_obtidos(m)]
    return "\n".join("\n".join(secao) + "\n" for secao in secoes if secao).rstrip("\n") + "\n"


# --- comando ---------------------------------------------------------------------------------


def _relatar(j):
    a = j["avaliacao"]["amostra"]
    print(
        f"janela de {j['janela']}: {_milhar(j['linhas']['treino'])} linhas de treino, {_milhar(j['linhas']['teste'])} de "
        f"teste, treino em {_decimal(j['treino_segundos'])} s; macro-F1 {_pct(a['macro_f1'])}, benigno como ataque "
        f"{_pct(a['falso_positivo_benigno'])}",
        file=sys.stderr,
    )


def main(argv=None):
    analisador = argparse.ArgumentParser(
        prog="python -m codigo.classificador.treinar_regerado",
        description="Treina e avalia o Random Forest de 7 categorias nos dados regerados, com janela de 10 e de 100.",
        allow_abbrev=False,
    )
    analisador.add_argument("--saida", default="experimentos/resultados", help="pasta dos resultados")
    analisador.add_argument(
        "--manifesto-da-regeracao", default=None,
        help=f"manifesto gravado por regerar (padrão: {MANIFESTO_DA_REGERACAO} na pasta dos resultados)",
    )
    analisador.add_argument("--destino", default=None, help="pasta dos CSVs regerados (padrão: a do manifesto)")
    analisador.add_argument("--modelos", default=MODELOS, help=f"pasta dos modelos salvos (padrão: {MODELOS})")
    analisador.add_argument("--semente", type=int, default=SEMENTE, help=f"padrão: {SEMENTE}")
    analisador.add_argument("--arvores", type=_positivo, default=ARVORES, help=f"padrão: {ARVORES}")
    analisador.add_argument("--teto", type=_positivo, default=TETO, help=f"linhas por rótulo (padrão: {TETO})")
    analisador.add_argument(
        "--nucleos", type=_nucleos, default=TODOS_OS_NUCLEOS,
        help=f"núcleos usados no treino (padrão: {TODOS_OS_NUCLEOS}, todos). Os números são os mesmos com qualquer valor",
    )
    analisador.add_argument(
        "--refazer-relatorio", action="store_true",
        help="não treina: refaz o relatório e as tabelas a partir do manifesto do treino",
    )
    try:
        argumentos = analisador.parse_args(argv)
    except SystemExit as encerramento:
        return encerramento.code
    saida = Path(argumentos.saida)
    try:
        if argumentos.refazer_relatorio:
            manifesto = json.loads((saida / MANIFESTO).read_text(encoding="utf-8"))
        else:
            caminho = Path(argumentos.manifesto_da_regeracao or saida / MANIFESTO_DA_REGERACAO)
            if not caminho.exists():
                raise ValueError(f"{caminho} não existe: rode python -m codigo.classificador.regerar antes")
            regeracao = json.loads(caminho.read_text(encoding="utf-8"))
            destino = argumentos.destino or regeracao["destino"]
            anteriores = rodadas_anteriores(saida / MANIFESTO)
            registro = rodar(
                regeracao, destino, argumentos.semente, argumentos.arvores, argumentos.nucleos, argumentos.teto,
                argumentos.modelos, ao_terminar=_relatar,
            )
            manifesto = montar_manifesto(
                registro, regeracao, caminho, destino, argumentos.semente, argumentos.arvores, argumentos.nucleos,
                argumentos.teto, anteriores,
            )
        gravar(manifesto, saida)
    except (OSError, ValueError, KeyError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrompido: nenhum resultado foi gravado", file=sys.stderr)
        return 130
    print(f"resultados em {saida}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
