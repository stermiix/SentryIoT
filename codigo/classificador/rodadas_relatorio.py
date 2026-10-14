"""Relatórios e tabelas das rodadas de teste, a partir do manifesto que `rodadas` grava.

Este módulo só formata: nenhum número é calculado aqui a partir dos dados, e por isso ele fica fora
da chave dos resultados guardados das rodadas. `rodadas_de_teste.md` sai do manifesto das rodadas
do modelo de 10/10 e `rodadas_normalizadas.md`, do manifesto da comparação de capturas; quando os
dois existem, o primeiro cita o segundo no Spoofing com o pcap fora do treino.
"""
import datetime
import json
from pathlib import Path

import numpy as np

from codigo.classificador.experimento import (
    _campo,
    _decimal,
    _enumerar,
    _gravar_csv,
    _milhar,
    _pct,
    _pp,
    _tabela,
)
from codigo.classificador.regerar import DESCARTADAS
from codigo.classificador.rodadas import (
    ALVOS_DO_LIMIAR,
    BENIGNO,
    BLOCO,
    CATEGORIAS_DO_RESUMO,
    CLASSES,
    FAIXAS_DE_QUADROS,
    JANELA,
    JANELAS_DA_LATENCIA,
    JANELAS_SEGUIDAS,
    MANIFESTO,
    MANIFESTO_DAS_CAPTURAS,
    REAMOSTRAGENS,
    RELATORIO,
    RELATORIO_DAS_CAPTURAS,
    REPETICOES_DA_PERMUTACAO,
    SUBAMOSTRA_DA_PERMUTACAO,
    TRABALHO,
    wilson,
)

# --- números para o relatório ------------------------------------------------------------------


def _fracao(parte, total):
    return parte / total if total else None


def _ataques(previstas):
    """Janelas previstas em alguma categoria de ataque."""
    return sum(quantas for classe, quantas in previstas.items() if classe != BENIGNO)


def _media(valores):
    valores = [v for v in valores if v is not None]
    return float(np.mean(valores)) if valores else None


def _desvio(valores):
    valores = [v for v in valores if v is not None]
    return float(np.std(valores, ddof=1)) if len(valores) > 1 else None


def _com_faixa(valores, casas=2):
    """A média e, com mais de um valor, o menor e o maior entre parênteses."""
    valores = [v for v in valores if v is not None]
    if not valores:
        return "sem valor"
    if len(valores) == 1:
        return _pct(valores[0], casas)
    return f"{_pct(float(np.mean(valores)), casas)} ({_pct(min(valores), casas)} a {_pct(max(valores), casas)})"


# Uma explicação só para o tamanho dos quadros, a mesma nos dois relatórios.
EXPLICACAO_DOS_QUADROS = (
    "Quadro menor que 60 bytes não sai assim no fio: a placa de rede o completa antes de transmitir, e ele aparece "
    "no pcap quando a captura é feita na própria máquina que envia. Quadro maior que 1.514 bytes também não passa "
    "num enlace Ethernet de MTU 1.500: ele aparece quando a placa da máquina que captura junta segmentos TCP antes "
    "de entregá-los (offload de segmentação), ou numa rede com jumbo frames. Os pcaps não dizem qual foi o caso, e "
    "as duas medidas são compatíveis com capturas gravadas de jeitos diferentes. Elas também não separam a forma de "
    "gravar do ataque: um quadro ARP, que o spoofing usa, tem 42 bytes antes do preenchimento."
)


def criterio_da_diferenca():
    """O parágrafo que diz quando uma diferença entre duas condições conta, o mesmo nos dois relatórios."""
    return (
        "As diferenças entre duas condições (uma configuração e a de referência, o modelo com e sem um pcap no "
        "treino, com e sem o TTL) são pareadas: as duas usam a mesma semente e são medidas nas mesmas janelas. Em "
        f"cada semente, a diferença ganha uma variância por reamostragem de blocos de {BLOCO} janelas vizinhas do "
        "mesmo pcap, sorteados juntos para as duas condições; a diferença publicada é a média das sementes, e a "
        "variância dela soma a média das variâncias por blocos (a do conjunto de teste) e a variância da diferença "
        "entre as sementes dividida pela quantidade delas (a do treino). A diferença só conta quando o intervalo de "
        "95% não contém o zero; senão, é \"sem diferença\"."
    )


def _leitura(comparacao):
    """A diferença pareada média, em pontos, com o intervalo de 95%, e se ele deixa o zero de fora."""
    if comparacao is None or comparacao.get("diferenca") is None:
        return "sem valor"
    texto = (f"{_pp(comparacao['diferenca'])} p.p. (de {_pp(comparacao['inferior'])} a "
             f"{_pp(comparacao['superior'])})")
    return texto + (", diferente de zero" if comparacao["acima"] else ", sem diferença")


def _no_caminho(registro, *chaves):
    """O valor no caminho de chaves, ou None se alguma falta."""
    for chave in chaves:
        if not isinstance(registro, dict) or chave not in registro:
            return None
        registro = registro[chave]
    return registro


def _controle(m):
    return [str(s) for s in m["parametros"]["sementes"][:m["parametros"]["sementes_de_controle"]]]


def _nas_sementes(registros, sementes):
    return [registros[s] for s in sementes if s in registros]


def _benigno_de_fora(unidade):
    return next((p for p in unidade["de_fora"] if p["categoria"] == BENIGNO), None)


def rotacoes_do_benigno(resultado, sementes):
    """Para cada rotação, o pcap benigno de fora e, por semente, as janelas e as previstas nele."""
    saida = []
    rotacoes_ = [("0", resultado["corte"]), *sorted(resultado.get("rotacao", {}).items())]
    for rotacao, por_semente in rotacoes_:
        unidades = _nas_sementes(por_semente, sementes)
        if not unidades:
            continue
        benignos = [_benigno_de_fora(u) for u in unidades]
        saida.append({
            "rotacao": rotacao, "arquivo": benignos[0]["arquivo"], "janelas": benignos[0]["janelas"],
            "como_ataque": [_fracao(_ataques(b["previstas"]), b["janelas"]) for b in benignos],
            "previstas": [b["previstas"] for b in benignos],
            "outros": [[p for p in u["de_fora"] if p["categoria"] != BENIGNO] for u in unidades],
            "macro_f1": [u["medidas"]["macro_f1"] for u in unidades],
            "sementes": [str(u["semente"]) for u in unidades],
            "alarmes": [u.get("alarmes_no_benigno") for u in unidades],
        })
    return saida


def pior_benigno(resultado, sementes):
    """Por semente, a maior fração de benigno classificado como ataque entre os pcaps benignos de fora."""
    rotacoes_ = rotacoes_do_benigno(resultado, sementes)
    por_semente = {}
    for r in rotacoes_:
        for semente, fracao in zip(r["sementes"], r["como_ataque"]):
            por_semente.setdefault(semente, []).append(fracao)
    completas = [max(v) for v in por_semente.values() if len(v) == len(rotacoes_)]
    return completas


def benigno_no_total(resultado, sementes):
    """Por semente, as janelas benignas de todos os pcaps de fora somadas: a fração classificada como ataque."""
    rotacoes_ = rotacoes_do_benigno(resultado, sementes)
    somas = {}
    for r in rotacoes_:
        for semente, previstas in zip(r["sementes"], r["previstas"]):
            ataque, janelas = somas.get(semente, (0, 0))
            somas[semente] = (ataque + _ataques(previstas), janelas + r["janelas"])
    return [_fracao(a, n) for a, n in somas.values()]


def fundo_por_semente(resultado, sementes, parte="teste"):
    """Por semente, a fração das janelas de fundo de todos os pcaps de ataque, numa parte, classificada como ataque."""
    saida = []
    for unidade in _nas_sementes(resultado["corte"], sementes):
        janelas = sum(p[parte]["janelas"] for p in unidade["fundo"])
        saida.append(_fracao(sum(_ataques(p[parte]["previstas"]) for p in unidade["fundo"]), janelas))
    return saida


def recall_fora(resultado, sementes, categoria, medida="na_categoria", trecho="teste"):
    """Por semente, o acerto somado nos pcaps de uma categoria quando cada um sai do treino."""
    saida = []
    for semente in sementes:
        acertos = janelas = 0
        for por_semente in resultado.get("fora", {}).values():
            unidade = por_semente.get(semente)
            if unidade is None or unidade["categoria"] != categoria:
                continue
            previstas = unidade[trecho]["previstas"]
            acertos += previstas[categoria] if medida == "na_categoria" else _ataques(previstas)
            janelas += unidade[trecho]["janelas"]
        if janelas:
            saida.append(acertos / janelas)
    return saida


def recall_dentro(resultado, sementes, categoria, arquivos, medida="na_categoria"):
    """Por semente, o acerto do treino com o pcap dentro, nas mesmas janelas de teste dos pcaps dados."""
    saida = []
    for unidade in _nas_sementes(resultado["corte"], sementes):
        acertos = janelas = 0
        for arquivo in arquivos:
            p = unidade["por_pcap"].get(arquivo)
            if p is None:
                continue
            acertos += p["previstas"][categoria] if medida == "na_categoria" else _ataques(p["previstas"])
            janelas += p["janelas"]
        if janelas:
            saida.append(acertos / janelas)
    return saida


def _do_corte(resultado, sementes, funcao):
    return [funcao(u["medidas"]) for u in _nas_sementes(resultado["corte"], sementes)]


def _data(m):
    return datetime.date.fromisoformat(m["gerado_em"]).strftime("%d/%m/%Y")


def _versoes(m):
    v = m["versoes"]
    return f"Python {v['python']}, scikit-learn {v['scikit-learn']}, pandas {v['pandas']} e numpy {v['numpy']}"


# --- o relatório das rodadas do modelo de 10/10 -------------------------------------------------


def _cabecalho(m):
    r = m["resultados"]
    p = m["parametros"]
    return [
        "# Rodadas de teste do modelo de janela de 100",
        "",
        f"Gerado por `{m['gerado_por']}` em {_data(m)}, com {_versoes(m)}.",
        "",
        "As rodadas medem o modelo de 10/10: o Random Forest de 7 categorias treinado nos dados regerados com",
        "janela de 100 quadros, sem o tráfego de fundo dos pcaps de ataque. Ele foi o modelo do sistema até",
        "13/10/2026 e é a configuração 0 de `rodadas_normalizadas.md`; desde então, o modelo do sistema é o da",
        "configuração 5, com o fundo da parte de treino como benigno e o ponto de operação escolhido na validação",
        "(`regeracao.md`, `ponto_de_operacao.md`), e o de 10/10 fica como referência (`regeracao_sem_fundo.md`).",
        "Os números abaixo valem para o modelo de 10/10. O relatório do treino mede uma divisão por tempo, com uma",
        "semente e só nas janelas que têm um quadro do atacante. As rodadas abaixo refazem o treino com as mesmas",
        "funções (leitura com teto, divisão por tempo, treino e avaliação) e medem o que aquela divisão não mostra.",
        "Cada rodada diz o que foi feito, traz os números e diz o que eles mostram, sem recomendar uma saída.",
        "",
        (
            f"Rodadas feitas: {_enumerar(r['rodadas'])}. Em cada treino, a semente define ao mesmo tempo o sorteio do "
            f"teto de {_milhar(p['teto'])} linhas por rótulo e o Random Forest. A rodada b usa as sementes "
            f"{_enumerar(p['sementes'])}; as que treinam um modelo por rotação ou por pcap usam as "
            f"{p['sementes_de_controle']} primeiras. Nas tabelas, um valor com parênteses é a média das sementes, "
            "com o menor e o maior entre parênteses."
        ),
        "",
        criterio_da_diferenca(),
    ]


def _secao_a(m):
    unidade = m["resultados"]["corte"].get(str(m["parametros"]["sementes"][0]), {})
    reproducao = unidade.get("detalhe", {}).get("reproducao")
    if reproducao is None:
        return []
    publicadas = reproducao["linhas_publicadas"]
    iguais = reproducao["divisao_igual"]
    linhas = [
        ["Linhas de treino e de teste", f"{_milhar(reproducao['linhas']['treino'])} e {_milhar(reproducao['linhas']['teste'])}"
         + (" (iguais às publicadas)" if (reproducao["linhas"]["treino"], reproducao["linhas"]["teste"])
            == (publicadas["treino"], publicadas["teste"]) else " (diferentes das publicadas)")],
        ["SHA-256 das posições de treino e de teste", "iguais aos de `manifesto_treino_regerado.json`"
         if iguais["treino"] and iguais["teste"] else "diferentes dos de `manifesto_treino_regerado.json`"],
        ["`treino_sha256` gravado no modelo", "igual" if iguais["treino_do_modelo"] else "diferente"],
        ["Medidas do modelo salvo no teste refeito", (f"{reproducao['medidas_conferidas']} conferidas, "
                                                      f"{len(reproducao['medidas_diferentes'])} diferentes das publicadas")],
        ["Matriz de confusão por rótulo", "idêntica à publicada" if reproducao["matriz_por_rotulo_igual"] else "diferente"],
        ["Predições do retreino com a semente 42 contra as do modelo salvo",
         (f"{_milhar(reproducao['predicoes_diferentes_do_retreino'])} diferentes em "
          f"{_milhar(reproducao['janelas_de_teste'])} janelas")],
    ]
    modelo = reproducao["modelo"]
    publicado = Path((m["entradas"].get("treino_publicado") or {}).get("manifesto", "manifesto_treino_regerado.json")).name
    linhas[1][1] = linhas[1][1].replace("manifesto_treino_regerado.json", publicado)
    return [
        "## a. Reprodução do modelo publicado",
        "",
        (
            f"**O que foi feito.** O modelo salvo `{modelo['arquivo']}` (SHA-256 `{modelo['sha256'][:16]}…`, semente "
            f"{modelo['semente']}, {modelo['arvores']} árvores) classificou a parte de teste refeita com a leitura, o "
            f"teto e a divisão do repositório, e as medidas foram comparadas com as de `{publicado}`. "
            "O modelo foi treinado de novo com a semente 42 e as predições dos dois foram comparadas janela a janela."
        ),
        "",
        *_tabela(["Conferência", "Resultado"], linhas),
    ]


def _medidas_globais(medidas):
    return [
        ("Macro-F1", lambda a: a["macro_f1"]),
        ("Acurácia", lambda a: a["acuracia"]),
        ("Benigno classificado como ataque", lambda a: a["benigno_como_ataque"]),
        ("Ataque classificado como benigno", lambda a: a["ataque_como_benigno"]),
        *((f"Recall {classe}", lambda a, c=classe: a["por_classe"][c]["recall"]) for classe in CLASSES),
        *((f"F1 {classe}", lambda a, c=classe: a["por_classe"][c]["f1"]) for classe in CLASSES),
    ]


def _secao_b(m):
    corte = m["resultados"]["corte"]
    if len(corte) < 2:
        return []
    sementes = list(corte)
    linhas = []
    for nome, funcao in _medidas_globais(None):
        valores = [funcao(corte[s]["medidas"]) for s in sementes]
        desvio = _desvio(valores)
        linhas.append([
            nome, _pct(valores[0]), _pct(_media(valores)), "sem valor" if desvio is None else f"{_pp(desvio).lstrip('+')} p.p.",
            f"{_pct(min(valores))} a {_pct(max(valores))}",
        ])
    macro = [corte[s]["medidas"]["macro_f1"] for s in sementes]
    benigno = [corte[s]["medidas"]["benigno_como_ataque"] for s in sementes]
    return [
        "## b. Sementes",
        "",
        (
            f"**O que foi feito.** O treino da divisão por tempo com as sementes {_enumerar(sementes)}. A divisão por "
            "tempo não sorteia; a semente muda quais linhas dos rótulos acima do teto entram e o Random Forest. "
            "Desvio amostral (n − 1)."
        ),
        "",
        *_tabela(["Medida", f"Semente {sementes[0]}", "Média", "Desvio", "Menor a maior"], linhas),
        "",
        (
            f"**O que os números mostram.** O macro-F1 varia {_pp(max(macro) - min(macro)).lstrip('+')} p.p. entre as "
            f"sementes e o benigno classificado como ataque, {_pp(max(benigno) - min(benigno)).lstrip('+')} p.p. "
            "As categorias com poucas janelas de teste variam mais. Essa faixa mede só o treino; as comparações das "
            "outras rodadas somam a ela a variação do conjunto de teste, pelo critério do começo do relatório."
        ),
    ]


def _distribuicao(previstas_por_semente, janelas, classes):
    return [_com_faixa([_fracao(p[c], janelas) for p in previstas_por_semente]) for c in classes]


def _secao_c(m):
    r = m["resultados"]
    controle = _controle(m)
    rotacoes_ = rotacoes_do_benigno(r, controle)
    if len(rotacoes_) < 2:
        return []
    ataques = [c for c in CLASSES if c != BENIGNO and c in ("Recon", "DDoS+DoS", "Spoofing", "Web")]
    linhas = []
    for rot in rotacoes_:
        outros = {}
        for lista in rot["outros"]:
            for p in lista:
                outros.setdefault(p["arquivo"], []).append(_fracao(p["previstas"][p["categoria"]], p["janelas"]))
        linhas.append([
            rot["rotacao"] + (" (publicada)" if rot["rotacao"] == "0" else ""), f"`{rot['arquivo']}`",
            _milhar(rot["janelas"]), _com_faixa(rot["como_ataque"]),
            *_distribuicao(rot["previstas"], rot["janelas"], ataques),
            "; ".join(f"`{arquivo}` {_com_faixa(v)}" for arquivo, v in outros.items()) or "nenhum",
            _com_faixa(rot["macro_f1"]),
        ])
    total = benigno_no_total(r, controle)
    pior = pior_benigno(r, controle)
    medias = [(rot["arquivo"], _media(rot["como_ataque"])) for rot in rotacoes_]
    melhor, pior_pcap = min(medias, key=lambda par: par[1]), max(medias, key=lambda par: par[1])
    return [
        "## c. Rotação do pcap de fora do treino",
        "",
        (
            "**O que foi feito.** Nos rótulos com mais de um pcap (o benigno e os dois SYN), um pcap fica inteiro "
            "fora do treino. A divisão publicada deixa de fora o último pelo sufixo numérico do nome; aqui o pcap de fora anda "
            "uma posição a cada rotação, até cada pcap benigno ficar de fora uma vez. Os rótulos de um pcap só "
            "mantêm o corte por tempo. A medida é no pcap de fora inteiro, com todas as janelas dele, e não só nas "
            "que o teto sorteou."
        ),
        "",
        *_tabela(
            ["Rotação", "Pcap benigno de fora", "Janelas", "Benigno como ataque",
             *(f"Como {c}" for c in ataques), "Outros pcaps de fora: na categoria", "Macro-F1 no teste com teto"],
            linhas,
        ),
        "",
        (
            f"Somando as janelas dos {len(rotacoes_)} pcaps benignos, cada um com o modelo que não o viu, "
            f"{_com_faixa(total)} viram ataque. O pior pcap benigno de fora, por semente, fica em {_com_faixa(pior)}."
        ),
        "",
        (
            f"**O que os números mostram.** O alarme falso do pcap benigno de fora vai de {_pct(melhor[1])} "
            f"(`{melhor[0]}`) a {_pct(pior_pcap[1])} (`{pior_pcap[0]}`), conforme o pcap que fica fora do treino. O "
            "número publicado é o de uma das rotações."
        ),
    ]


def _secao_d(m):
    r = m["resultados"]
    controle = _controle(m)
    unidades = _nas_sementes(r["corte"], controle)
    if not unidades or not unidades[0]["fundo"]:
        return []
    extraidas = m["entradas"]["regeracao"]["extraidas"]
    linhas = []
    por_pcap = {}
    for u in unidades:
        for p in u["fundo"]:
            por_pcap.setdefault(p["arquivo"], []).append(p)
    for arquivo, registros in sorted(por_pcap.items(), key=lambda par: -(par[1][0]["treino"]["janelas"]
                                                                       + par[1][0]["teste"]["janelas"])):
        primeiro = registros[0]
        total = primeiro["treino"]["janelas"] + primeiro["teste"]["janelas"]
        if total == 0:
            continue
        celulas = [f"`{arquivo}`", primeiro["categoria"], f"{_milhar(total)} / {_milhar(extraidas[arquivo])}"]
        for parte in ("treino", "teste"):
            janelas = primeiro[parte]["janelas"]
            celulas += [
                _milhar(janelas),
                _com_faixa([_fracao(_ataques(p[parte]["previstas"]), janelas) for p in registros], 1) if janelas else "-",
                _com_faixa([_fracao(p[parte]["previstas"][p["categoria"]], janelas) for p in registros], 1)
                if janelas else "-",
            ]
        soma = {c: sum(p["teste"]["previstas"][c] for p in registros) for c in CLASSES if c != BENIGNO}
        celulas.append(max(soma, key=soma.get) if sum(soma.values()) else "nenhum")
        linhas.append(celulas)
    teste, treino = fundo_por_semente(r, controle, "teste"), fundo_por_semente(r, controle, "treino")
    benigno = [_fracao(_ataques(_benigno_de_fora(u)["previstas"]), _benigno_de_fora(u)["janelas"]) for u in unidades]
    secao = [
        "## d. Tráfego de fundo dos pcaps de ataque",
        "",
        (
            "**O que foi feito.** As janelas que a regra de rótulo descarta, sem nenhum quadro de um MAC atacante, "
            "estão gravadas à parte desde a versão 2 da regeração (`descartadas/`). O modelo da divisão por tempo "
            "classificou todas elas. Cada janela fica na parte de treino ou na de teste do seu pcap pelo mesmo corte "
            "da divisão: o modelo nunca viu nenhuma delas, mas as da parte de treino são do mesmo trecho de captura "
            "das janelas com que ele treinou. Nos SYN, o pcap de fora é todo teste e o outro, todo treino."
        ),
        "",
        *_tabela(
            ["Pcap", "Categoria", "Fundo / janelas", "Treino: janelas", "Treino: como ataque",
             "Treino: na categoria do pcap", "Teste: janelas", "Teste: como ataque", "Teste: na categoria do pcap",
             "Ataque mais previsto no teste"],
            linhas,
        ),
        "",
        (
            f"Juntando os pcaps, na parte de teste {_com_faixa(teste)} das janelas de fundo viram ataque, e na "
            f"de treino, {_com_faixa(treino)}. No pcap benigno de fora da divisão publicada, {_com_faixa(benigno)}."
        ),
    ]
    detalhe = r["corte"].get(controle[0], {}).get("detalhe", {})
    limiar = detalhe.get("limiar_no_fundo", {})
    if limiar.get("janelas") and detalhe.get("limiar"):
        candidatos = [str(linha["limiar"]) for _, linha in candidatos_do_limiar(detalhe["limiar"])]
        secao += [
            "",
            "Com os limiares candidatos da rodada g, na parte de teste e na semente principal: "
            + "; ".join(
                f"t = {t.replace('.', ',')}: {_pct(_fracao(limiar['como_ataque'][t], limiar['janelas']))}"
                for t in ["argmax", *candidatos]
            ).replace("t = argmax", "argmax") + ".",
        ]
    quadros = unidades[0].get("por_quadros_do_atacante")
    if quadros:
        faixas = [f"{de}-{ate}" for de, ate in FAIXAS_DE_QUADROS]
        por_categoria = []
        for classe, por_faixa in quadros.items():
            fundo = [p for p in unidades[0]["fundo"] if p["categoria"] == classe]
            janelas_fundo = sum(p["teste"]["janelas"] for p in fundo)
            celulas = [classe, (f"{_pct(_fracao(sum(p['teste']['previstas'][classe] for p in fundo), janelas_fundo), 0)} "
                                f"({_milhar(janelas_fundo)})") if janelas_fundo else "-"]
            celulas += [
                f"{_pct(_fracao(por_faixa[f]['na_categoria'], por_faixa[f]['janelas']), 0)} ({_milhar(por_faixa[f]['janelas'])})"
                if por_faixa[f]["janelas"] else "-"
                for f in faixas
            ]
            por_categoria.append(celulas)
        secao += [
            "",
            (
                "Quantos quadros do atacante há na janela, na parte de teste e na semente principal: a fração na "
                "categoria do pcap, com as janelas entre parênteses. A coluna 0 é o fundo."
            ),
            "",
            *_tabela(["Categoria", "0 (fundo)", *(str(de) if de == ate else f"{de} a {ate}" for de, ate in FAIXAS_DE_QUADROS)],
                     por_categoria),
        ]
    grandes = []
    for arquivo, registros in por_pcap.items():
        janelas = registros[0]["teste"]["janelas"]
        if janelas >= 100:
            grandes.append((_media([_fracao(p["teste"]["previstas"][p["categoria"]], janelas) for p in registros]),
                            arquivo, janelas))
    grandes.sort(reverse=True)
    secao += [
        "",
        (
            "Entre os pcaps com ao menos 100 janelas de fundo na parte de teste, as maiores frações na categoria do "
            "próprio pcap são as de " + _enumerar(f"`{arquivo}` ({_pct(fracao, 1)} de {_milhar(janelas)})"
                                               for fracao, arquivo, janelas in grandes[:4]) + "."
        ) if grandes else "",
    ]
    secao += [
        "",
        (
            "**O que os números mostram.** A coluna \"na categoria do pcap\" é a fração do fundo que o modelo põe na "
            "categoria do ataque daquela captura, sem nenhum quadro do atacante na janela. Onde ela fica perto do "
            "recall das janelas com atacante, a categoria acompanha a captura, e não o ataque. Parte do fundo pode "
            "conter efeito do ataque, então a fração de fundo classificada como ataque é uma estimativa pessimista do "
            "alarme falso durante um ataque."
        ),
    ]
    return secao


def _secao_e(m, capturas=None):
    r = m["resultados"]
    controle = _controle(m)
    if not r.get("fora"):
        return []
    linhas = []
    for arquivo, por_semente in r["fora"].items():
        unidades = _nas_sementes(por_semente, controle)
        if not unidades:
            continue
        categoria = unidades[0]["categoria"]
        janelas = unidades[0]["teste"]["janelas"]
        linhas.append([
            f"`{arquivo}`", categoria, _milhar(janelas),
            _com_faixa(recall_dentro(r, controle, categoria, [arquivo])),
            _com_faixa([_fracao(u["teste"]["previstas"][categoria], u["teste"]["janelas"]) for u in unidades]),
            _com_faixa(recall_dentro(r, controle, categoria, [arquivo], "como_ataque")),
            _com_faixa([_fracao(_ataques(u["teste"]["previstas"]), u["teste"]["janelas"]) for u in unidades]),
            _com_faixa([_fracao(u["inteiro"]["previstas"][categoria], u["inteiro"]["janelas"]) for u in unidades]),
        ])
    categorias = []
    for categoria in CLASSES:
        arquivos = [a for a, s in r["fora"].items() if next(iter(s.values()))["categoria"] == categoria]
        if not arquivos:
            continue
        dentro, fora = recall_dentro(r, controle, categoria, arquivos), recall_fora(r, controle, categoria)
        comparacao = _no_caminho(r, "comparacoes", "dentro_e_fora", "por_categoria", categoria, "na_categoria")
        categorias.append([categoria, len(arquivos), _com_faixa(dentro), _com_faixa(fora), _leitura(comparacao)])
    quedas = []
    for arquivo, por_semente in r["fora"].items():
        comparacao = _no_caminho(r, "comparacoes", "dentro_e_fora", "por_pcap", arquivo)
        categoria = next(iter(por_semente.values()))["categoria"]
        if categoria != "BruteForce" and comparacao and comparacao["acima"] and comparacao["diferenca"] < 0:
            quedas.append((-comparacao["diferenca"], arquivo))
    maiores = sorted(quedas, reverse=True)[:4]
    return [
        "## e. Pcap inteiro fora do treino",
        "",
        (
            "**O que foi feito.** Para cada pcap da lista, o modelo foi treinado sem nenhuma janela dele, com o resto "
            "igual à divisão publicada, e classificou as janelas dele. \"Dentro da captura\" é o modelo da divisão "
            "publicada, que treinou com o começo do mesmo pcap, nas mesmas janelas de teste. Cada pcap de Recon e de "
            "Web é uma técnica diferente, então tirar o pcap tira também a técnica do treino; o pcap de BruteForce é "
            "o único da categoria, e sem ele a categoria some do treino."
        ),
        "",
        *_tabela(
            ["Pcap", "Categoria", "Janelas de teste", "Na categoria, dentro da captura", "Na categoria, pcap fora",
             "Como ataque, dentro", "Como ataque, pcap fora", "Pcap inteiro fora: na categoria"],
            linhas,
        ),
        "",
        "Somando os pcaps de cada categoria, nas janelas de teste:",
        "",
        *_tabela(["Categoria", "Pcaps", "Recall dentro da captura", "Recall com o pcap fora", "Diferença"], categorias),
        "",
        (
            "**O que os números mostram.** O recall dentro da captura mede o reconhecimento de um trecho seguinte "
            "da mesma captura; o recall com o pcap fora mede o reconhecimento de uma captura que o modelo não viu. A "
            "distância entre os dois, por categoria, está na última coluna."
            + (" Fora BruteForce, as maiores quedas por pcap que contam são em "
               + _enumerar(f"`{arquivo}` ({_pp(-queda)} p.p.)" for queda, arquivo in maiores) + "." if maiores else "")
        ),
        "",
        _frase_do_spoofing(capturas, controle),
    ]


def _spoofing_normalizado(capturas, sementes):
    """O recall de Spoofing com o pcap fora nas configurações da comparação de capturas, se ela existe."""
    if not capturas:
        return None
    return {nome: _media(recall_fora(res, sementes, "Spoofing")) for nome, res in capturas["resultados"].items()}


def _frase_do_spoofing(capturas, sementes):
    """A ressalva do Spoofing com o pcap fora: os dois pcaps de spoofing têm o mesmo artefato de quadro curto."""
    valores = _spoofing_normalizado(capturas, sementes)
    base = (
        "O recall de Spoofing com o pcap fora não mostra que o Spoofing é reconhecido numa captura nova: os dois pcaps "
        "de spoofing têm quadros menores que 60 bytes na maior parte das janelas (rodada f)"
    )
    if valores is None or "1" not in valores:
        return base + f", e o efeito disso está em `{RELATORIO_DAS_CAPTURAS}`."
    return (
        base + f". Com o quadro menor que 60 bytes contado como 60, ele vai de {_pct(valores['0'])} para "
        f"{_pct(valores['1'])} (configuração 1 de `{RELATORIO_DAS_CAPTURAS}`)."
    )


def _secao_f(m):
    r = m["resultados"]
    controle = _controle(m)
    if "tamanhos" not in r:
        return []
    t = r["tamanhos"]
    linhas = [
        [classe, _milhar(v["janelas"]), _pct(_fracao(v["abaixo_de_60"], v["janelas"])),
         _pct(_fracao(v["acima_de_1514"], v["janelas"]))]
        for classe, v in t["por_categoria"].items()
    ]
    pcaps = [
        [f"`{arquivo}`", v["categoria"], _milhar(v["janelas"]), _pct(_fracao(v["abaixo_de_60"], v["janelas"])),
         _pct(_fracao(v["acima_de_1514"], v["janelas"]))]
        for arquivo, v in t["por_pcap"].items() if v["abaixo_de_60"] or v["categoria"] == BENIGNO
    ]
    secao = [
        "## f. Atalhos da captura",
        "",
        "### Tamanho dos quadros",
        "",
        (
            "**O que foi feito.** Em todas as janelas mantidas, a fração com algum quadro menor que 60 bytes (`Min`) e "
            "com algum quadro maior que 1.514 bytes (`Max`). " + EXPLICACAO_DOS_QUADROS
        ),
        "",
        *_tabela(["Categoria", "Janelas", "Com quadro menor que 60 bytes", "Com quadro maior que 1.514 bytes"], linhas),
        "",
        "Os pcaps com algum quadro menor que 60 bytes, e os benignos:",
        "",
        *_tabela(["Pcap", "Categoria", "Janelas", "Com quadro menor que 60 bytes", "Com quadro maior que 1.514 bytes"],
                 pcaps),
    ]
    sem_ttl = r.get("sem_ttl", {})
    if sem_ttl:
        com, sem = _nas_sementes(r["corte"], controle), _nas_sementes(sem_ttl, controle)
        comparacoes = _no_caminho(r, "comparacoes", "sem_ttl") or {}
        medidas = [
            ("Macro-F1", "macro_f1", lambda a: a["macro_f1"]),
            ("Benigno classificado como ataque", "benigno_como_ataque", lambda a: a["benigno_como_ataque"]),
            *((f"Recall {c}", f"recall_{c}", lambda a, c=c: a["por_classe"][c]["recall"]) for c in CLASSES if c != BENIGNO),
        ]
        linhas = [[nome, _com_faixa([f(u["medidas"]) for u in com]), _com_faixa([f(u["medidas"]) for u in sem]),
                   _leitura(comparacoes.get(chave))] for nome, chave, f in medidas]
        fora_com = [_fracao(_ataques(_benigno_de_fora(u)["previstas"]), _benigno_de_fora(u)["janelas"]) for u in com]
        fora_sem = [_fracao(_ataques(_benigno_de_fora(u)["previstas"]), _benigno_de_fora(u)["janelas"]) for u in sem]
        linhas.append([f"Pcap benigno de fora (`{_benigno_de_fora(com[0])['arquivo']}`) como ataque", _com_faixa(fora_com),
                       _com_faixa(fora_sem), _leitura(comparacoes.get("benigno_de_fora"))])
        secao += [
            "",
            "### TTL",
            "",
            "**Ablação.** O mesmo treino, nas mesmas sementes, sem a coluna `Time_To_Live`.",
            "",
            *_tabela(["Medida", "39 features", "Sem `Time_To_Live`", "Diferença"], linhas),
        ]
    ttls = [u["ttl"] for u in _nas_sementes(r["corte"], controle) if u.get("ttl")]
    if ttls:
        faixas = []
        for i, faixa in enumerate(ttls[0]["faixas"]):
            rotulo = ("até " + str(faixa["ate"])) if faixa["acima_de"] is None else (
                f"acima de {faixa['acima_de']}" if faixa["ate"] is None else f"{faixa['acima_de']} a {faixa['ate']}")
            janelas = faixa["janelas"]
            faixas.append([rotulo, _milhar(janelas),
                           _com_faixa([_fracao(t["faixas"][i]["como_ataque"], janelas) for t in ttls], 1)])
        fixado = [[valor, _com_faixa([_fracao(t["fixado"][valor], t["janelas"]) for t in ttls], 1)]
                  for valor in ttls[0]["fixado"]]
        secao += [
            "",
            (
                f"**Janelas benignas de TTL baixo.** As janelas de `{ttls[0]['arquivo']}`, que o modelo da divisão "
                "publicada não viu, pelo TTL médio da janela, e as mesmas janelas com o TTL trocado por um valor fixo:"
            ),
            "",
            *_tabela(["TTL médio da janela", "Janelas", "Como ataque"], faixas),
            "",
            *_tabela(["TTL de todas as janelas trocado por", "Como ataque"], fixado),
        ]
    detalhe = r["corte"].get(controle[0], {}).get("detalhe", {})
    permut = detalhe.get("permutacao")
    if permut:
        linhas = []
        for classe, registro in permut["por_categoria"].items():
            if registro["base"] is None:
                continue
            maiores = sorted(registro["quedas"].items(), key=lambda par: -par[1][0])[:5]
            linhas.append([classe, f"{_pct(registro['base'])} ({_milhar(registro['janelas'])})",
                           "; ".join(f"`{f}` {_pp(q[0]).lstrip('+')}" for f, q in maiores)])
        globais = sorted(permut["macro_f1"]["quedas"].items(), key=lambda par: -par[1][0])[:6]
        impureza = sorted(permut["impureza"].items(), key=lambda par: -par[1])[:6]
        secao += [
            "",
            "### Importância por permutação",
            "",
            (
                "**O que foi feito.** No modelo da semente principal, cada feature das janelas de teste de uma "
                f"categoria foi trocada pelo valor de uma janela de teste qualquer, {REPETICOES_DA_PERMUTACAO} vezes, "
                f"com até {_milhar(SUBAMOSTRA_DA_PERMUTACAO)} janelas da categoria. A queda é a do recall, em pontos."
            ),
            "",
            *_tabela(["Categoria", "Recall de base (janelas)", "Features que mais derrubam o recall (p.p.)"], linhas),
            "",
            (
                "No macro-F1, numa subamostra com até a mesma quantidade de janelas de cada categoria: "
                + "; ".join(f"`{f}` {_pp(q[0]).lstrip('+')}" for f, q in globais)
                + " p.p. Pela redução de impureza, a medida que o relatório da regeração lista: "
                + "; ".join(f"`{f}` {_pct(v, 1)}" for f, v in impureza) + "."
            ),
        ]
    return secao


def candidatos_do_limiar(curva, alvos=ALVOS_DO_LIMIAR):
    """Para cada alvo de benigno classificado como ataque, o menor limiar que fica dentro dele."""
    saida, escolhidos = [], set()
    for alvo_ in alvos:
        dentro = [linha for linha in curva if linha["limiar"] != "argmax" and linha["benigno_como_ataque"] <= alvo_]
        if dentro:
            linha = min(dentro, key=lambda linha: linha["limiar"])
            if linha["limiar"] not in escolhidos:
                escolhidos.add(linha["limiar"])
                saida.append((alvo_, linha))
    return saida


def _horas(alarmes_, segundos):
    return _fracao(alarmes_, segundos / 3600) if segundos else None


def _secao_g(m):
    r = m["resultados"]
    controle = _controle(m)
    detalhe = r["corte"].get(controle[0], {}).get("detalhe", {})
    curva = detalhe.get("limiar")
    if not curva:
        return []
    fundo = detalhe.get("limiar_no_fundo", {})
    pior = None
    for por_semente in r.get("rotacao", {}).values():
        unidade = por_semente.get(controle[0])
        if unidade and unidade.get("limiar_no_benigno"):
            limiar = unidade["limiar_no_benigno"]
            janelas = _benigno_de_fora(unidade)["janelas"]
            taxa = _fracao(_ataques(_benigno_de_fora(unidade)["previstas"]), janelas)
            if pior is None or taxa > pior[2]:
                pior = (limiar, janelas, taxa, limiar["arquivo"])
    linhas = []
    for linha in curva:
        chave = "argmax" if linha["limiar"] == "argmax" else str(linha["limiar"])
        celulas = [
            "argmax (hoje)" if chave == "argmax" else _decimal(linha["limiar"], 2), _pct(linha["benigno_como_ataque"]),
            _pct(linha["recall_de_ataque"]), _pct(linha["ataque_como_benigno"]), _pct(linha["macro_f1"]),
            _pct(linha["recall"]["Recon"]), _pct(linha["recall"]["Web"]), _pct(linha["recall"]["BruteForce"]),
            _pct(_fracao(fundo.get("como_ataque", {}).get(chave), fundo.get("janelas"))) if fundo.get("janelas") else "-",
        ]
        if pior is not None:
            celulas.append(_pct(pior[2]) if chave == "argmax" else _pct(_fracao(pior[0]["como_ataque"][chave], pior[1])))
        linhas.append(celulas)
    cabecalho = ["Limiar", "Benigno como ataque", "Recall de ataque", "Ataque como benigno", "Macro-F1",
                 "Recall Recon", "Recall Web", "Recall BruteForce", "Fundo de teste como ataque"]
    if pior is not None:
        cabecalho.append(f"`{pior[3]}` de fora como ataque")
    candidatos = candidatos_do_limiar(curva)
    secao = [
        "## g. Ponto de operação",
        "",
        "### Limiar sobre a probabilidade de benigno",
        "",
        (
            "**O que foi feito.** Com as probabilidades do modelo da semente principal no teste, a regra: se "
            "1 − P(Benign) ≥ t, a janela é ataque, na categoria de ataque mais provável; senão, é Benign. \"Recall de "
            "ataque\" é a fração das janelas de ataque postas em qualquer categoria de ataque. As duas últimas colunas "
            "aplicam a mesma regra ao fundo da parte de teste (rodada d) e ao pior pcap benigno de fora (rodada c)."
        ),
        "",
        *_tabela(cabecalho, linhas),
        "",
        "Pontos candidatos, o menor limiar que deixa o benigno classificado como ataque dentro de cada alvo:",
        "",
    ]
    secao += [
        f"- até {_pct(alvo_, 1)}: t = {_decimal(linha['limiar'], 2)}, benigno como ataque "
        f"{_pct(linha['benigno_como_ataque'])}, recall de ataque {_pct(linha['recall_de_ataque'])}, macro-F1 "
        f"{_pct(linha['macro_f1'])}, recall de Recon {_pct(linha['recall']['Recon'])} e de Web {_pct(linha['recall']['Web'])}."
        for alvo_, linha in candidatos
    ] or ["- nenhum limiar da curva chega aos alvos."]
    secao += [
        "",
        (
            "O argmax de hoje não é t = 0,5: ele dá Benign sempre que Benign é a classe mais provável, mesmo abaixo "
            "de 0,5. Os candidatos foram escolhidos no próprio teste, cujo benigno é um pcap só; a escolha final do "
            "limiar precisa sair de uma parte de validação, e não do teste."
        ),
    ]
    seguidas = detalhe.get("seguidas")
    if seguidas and seguidas["ataques"]:
        benignos = seguidas["benignos"]
        rotacoes_ = rotacoes_do_benigno(r, [controle[0]])
        linhas = []
        for n in map(str, JANELAS_SEGUIDAS):
            detectados = [a for a in seguidas["ataques"] if a["seguidas"][n]["primeira_janela"] is not None]
            janelas = [a["seguidas"][n]["primeira_janela"] for a in detectados]
            segundos = [a["seguidas"][n]["primeiro_segundos"] for a in detectados]
            celulas = [n]
            for b in benignos:
                celulas.append(f"{b['alarmes'][n]} ({_decimal(_horas(b['alarmes'][n], b['segundos']), 1)} por hora)")
            for rot in rotacoes_:
                alarme = rot["alarmes"][0]
                if alarme is not None and alarme["arquivo"] not in {b["arquivo"] for b in benignos}:
                    celulas.append(f"{alarme['alarmes'][n]} ({_decimal(_horas(alarme['alarmes'][n], alarme['segundos']), 1)}"
                                   " por hora)")
            celulas += [
                f"{len(detectados)} de {len(seguidas['ataques'])}",
                _decimal(float(np.median(janelas)), 0) if janelas else "-",
                _decimal(float(np.median(segundos)), 2) if segundos else "-",
                _decimal(float(np.max(segundos)), 1) if segundos else "-",
            ]
            linhas.append(celulas)
        cabecalho = ["N", *(f"Alarmes em `{b['arquivo']}`" for b in benignos)]
        cabecalho += [f"Alarmes em `{rot['alarmes'][0]['arquivo']}` (rotação {rot['rotacao']})" for rot in rotacoes_
                      if rot["alarmes"][0] is not None and rot["alarmes"][0]["arquivo"] not in {b["arquivo"] for b in benignos}]
        cabecalho += ["Pcaps de ataque com alarme no trecho de teste", "Janelas até o alarme (mediana)",
                      "Segundos até o alarme (mediana)", "Segundos até o alarme (maior)"]
        secao += [
            "",
            "### N janelas seguidas",
            "",
            (
                "**O que foi feito.** Um alarme dispara quando N janelas seguidas são classificadas como ataque; a "
                "sequência que continua não dispara outro. No pcap benigno de fora, a conta é sobre o pcap inteiro, e o "
                "tempo é a soma da duração das janelas. Em cada pcap de ataque, a sequência é o trecho de teste inteiro, "
                "com as janelas com e sem o atacante na ordem do arquivo, como o extrator as entregaria; o tempo até o "
                "alarme conta do começo do trecho. A semente é a principal, e a coluna da rotação usa o modelo daquela "
                "rotação."
            ),
            "",
            *_tabela(cabecalho, linhas),
        ]
    return secao


def _secao_h(m):
    r = m["resultados"]
    controle = _controle(m)
    detalhe = r["corte"].get(controle[0], {}).get("detalhe", {})
    intervalos = detalhe.get("intervalos")
    if not intervalos:
        return []
    def intervalo(par):
        return "sem valor" if par[0] is None else f"{_pct(par[0], 1)} a {_pct(par[1], 1)}"

    linhas = []
    for classe, v in intervalos.items():
        sementes = [u["medidas"]["por_classe"][classe]["recall"] for u in r["corte"].values()]
        linhas.append([
            classe, _milhar(v["janelas"]), _pct(_fracao(v["acertos"], v["janelas"]), 1), intervalo(v["recall_wilson"]),
            intervalo(v["recall_blocos"]), "sem valor" if v["autocorrelacao"] is None else _decimal(v["autocorrelacao"], 2),
            "sem valor" if v["n_efetivo"] is None else _milhar(v["n_efetivo"]),
            f"{_pct(_fracao(v['certas'], v['previstas']), 1)} ({_milhar(v['previstas'])})", intervalo(v["precisao_wilson"]),
            f"{_pct(min(sementes), 1)} a {_pct(max(sementes), 1)}",
        ])
    web = intervalos.get("Web", {}).get("por_pcap", {})
    return [
        "## h. Intervalos de confiança das classes raras",
        "",
        (
            "**O que foi feito.** No teste da semente principal: o intervalo de Wilson de 95%, que trata as janelas "
            f"como independentes; o intervalo por blocos de {BLOCO} janelas vizinhas do mesmo pcap, com "
            f"{_milhar(REAMOSTRAGENS)} reamostragens, porque janelas vizinhas erram juntas; a correlação do acerto "
            "entre uma janela e a seguinte; e o tamanho efetivo n(1 − r)/(1 + r)."
        ),
        "",
        *_tabela(
            ["Categoria", "Janelas de teste", "Recall", "Wilson", "Por blocos", "Autocorrelação", "n efetivo",
             "Precisão (previstas)", "Wilson da precisão", "Recall entre as sementes"],
            linhas,
        ),
        "",
        "Recall de Web por pcap, com o intervalo de Wilson: " + "; ".join(
            f"`{arquivo}` {_pct(_fracao(v['acertos'], v['janelas']), 1)} de {_milhar(v['janelas'])} "
            f"({intervalo(wilson(v['acertos'], v['janelas']))})" for arquivo, v in web.items()
        ) + ".",
        "",
        (
            "**O que os números mostram.** Quando a autocorrelação é alta, o tamanho efetivo é uma fração das janelas "
            "de teste e o intervalo por blocos é bem mais largo que o de Wilson; é ele que vale para comparar duas "
            "configurações. A precisão de uma categoria com poucas previsões vem de poucas janelas."
        ),
    ]


def _latencia(medida):
    return (f"mediana {_decimal(medida['mediana_ms'], 2)} ms, p95 {_decimal(medida['p95_ms'], 2)} ms, "
            f"p99 {_decimal(medida['p99_ms'], 2)} ms")


def _secao_i(m):
    r = m["resultados"]
    custo_ = r.get("custo")
    if not custo_:
        return []
    controle = _controle(m)
    linhas = []
    modelo = custo_.get("modelo")
    if modelo:
        carga = modelo["carga"]
        linhas += [
            ["Arquivo do modelo", (f"{_decimal(modelo['bytes'] / 1e6)} MB, {_milhar(modelo['nos'])} nós, profundidade "
                                   f"média {_decimal(modelo['profundidade_media'])} e máxima {modelo['profundidade_maxima']}")],
            ["Importar o scikit-learn e o joblib, num processo novo", f"{_decimal(carga['importar_s'], 2)} s"],
            ["Ler o modelo", f"{_decimal(carga['carga_s'], 2)} s, com o arquivo no cache do sistema"],
            ["Memória do processo", (f"{_decimal(carga['memoria_antes'] / 1e6, 0)} MB antes de ler o modelo e "
                                     f"{_decimal(carga['memoria_depois'] / 1e6, 0)} MB depois")],
            ["Uma janela, `predict`, um núcleo", _latencia(modelo["latencia_predict"])],
            ["Uma janela, `predict_proba`", _latencia(modelo["latencia_predict_proba"])],
            ["Lote de 1.000 janelas", f"{_decimal(modelo['lote_de_1000_ms'], 1)} ms"],
        ]
    vazao = custo_.get("vazao")
    if vazao:
        linhas.append([f"Extrator de janela de 100 em `{vazao['arquivo']}`",
                       (f"{_milhar(vazao['pacotes'])} pacotes em {_decimal(vazao['segundos'])} s: "
                        f"{_milhar(vazao['pacotes'] / vazao['segundos'])} pacotes/s e "
                        f"{_milhar(vazao['janelas'] / vazao['segundos'])} janelas/s")])
    duracao = [[classe, _decimal(v["mediana"], 3), _decimal(v["p90"], 3), _decimal(v["p99"], 3)]
               for classe, v in custo_["duracao_da_janela"].items()]
    menor = custo_["menor"]
    principal = r["corte"][controle[0]]["medidas"]
    def pior_da_rotacao(de_fora):
        benigno = next(p for p in de_fora if p["categoria"] == BENIGNO)
        return _fracao(_ataques(benigno["previstas"]), benigno["janelas"])

    rotacao_100 = {rot: por_semente[controle[0]] for rot, por_semente in r.get("rotacao", {}).items()
                   if controle[0] in por_semente}
    variantes = []
    if modelo:
        variantes.append([
            f"{m['parametros']['arvores']} árvores (o do sistema)", f"{_decimal(modelo['bytes'] / 1e6)} MB",
            _milhar(modelo["nos"]), f"{_decimal(modelo['latencia_predict']['mediana_ms'], 2)} ms",
            f"{_decimal(modelo['lote_de_1000_ms'], 1)} ms", _pct(principal["macro_f1"]), _pct(principal["benigno_como_ataque"]),
            _pct(principal["por_classe"]["Recon"]["recall"]), _pct(principal["por_classe"]["Web"]["recall"]),
            _pct(principal["por_classe"]["BruteForce"]["recall"]),
            "; ".join(_pct(pior_da_rotacao(u["de_fora"])) for u in rotacao_100.values()) or "-",
        ])
    variantes.append([
        f"{menor['arvores']} árvores", f"{_decimal(menor['bytes'] / 1e6)} MB", _milhar(menor["nos"]),
        f"{_decimal(menor['latencia_predict']['mediana_ms'], 2)} ms", f"{_decimal(menor['lote_de_1000_ms'], 1)} ms",
        _pct(menor["medidas"]["macro_f1"]), _pct(menor["medidas"]["benigno_como_ataque"]),
        _pct(menor["medidas"]["por_classe"]["Recon"]["recall"]), _pct(menor["medidas"]["por_classe"]["Web"]["recall"]),
        _pct(menor["medidas"]["por_classe"]["BruteForce"]["recall"]),
        "; ".join(_pct(pior_da_rotacao(de_fora)) for de_fora in menor["rotacao"].values()) or "-",
    ])
    return [
        "## i. Custo",
        "",
        (
            "**O que foi feito.** O modelo salvo foi lido num processo novo, três vezes, para medir o tempo e a "
            f"memória; a latência é de uma janela isolada, com um núcleo, em {JANELAS_DA_LATENCIA} janelas diferentes "
            "do teste, depois de uma de aquecimento. A vazão é a do extrator de janela de 100 com os endereços, lendo o "
            "pcap inteiro. Os tempos são desta máquina, dividida com outros processos, e mudam de uma execução para "
            "outra."
        ),
        "",
        *_tabela(["Medida", "Valor"], linhas),
        "",
        (
            "Quanto tempo uma janela de 100 quadros leva para fechar (`Number` / `Rate`), em segundos, na amostra da "
            "semente principal:"
        ),
        "",
        *_tabela(["Categoria", "Mediana", "P90", "P99"], duracao),
        "",
        f"O Random Forest de {menor['arvores']} árvores, na mesma divisão e na mesma semente:",
        "",
        *_tabela(
            ["Variante", "Arquivo", "Nós", "Latência (mediana)", "Lote de 1.000", "Macro-F1", "Benigno como ataque",
             "Recall Recon", "Recall Web", "Recall BruteForce", "Pcap benigno de fora nas rotações: como ataque"],
            variantes,
        ),
    ]


def _tempo_de_treino(valor):
    """A soma dos segundos de treino de todos os resultados, onde quer que estejam."""
    if isinstance(valor, dict):
        return sum(v if k == "treino_segundos" else _tempo_de_treino(v) for k, v in valor.items())
    if isinstance(valor, list):
        return sum(_tempo_de_treino(v) for v in valor)
    return 0.0


def _nucleos_em_texto(nucleos):
    if nucleos <= 0:
        return "todos os núcleos"
    return "1 núcleo" if nucleos == 1 else f"{nucleos} núcleos"


def _como_foram_obtidos(m):
    e = m["entradas"]
    linhas = [
        "## Como os números foram obtidos",
        "",
        f"- Comando: `{m['comando']}`, a partir da raiz do repositório, depois de `python -m codigo.classificador.regerar`.",
        (
            f"- Dados: `{e['regeracao']['destino']}/janela_{JANELA}/`, {len(e['arquivos'])} arquivos (os CSVs de rótulo "
            f"e as partes de `{DESCARTADAS}/`), com o SHA-256 de cada um em `{m['arquivo_do_manifesto']}`. Manifesto da "
            f"regeração `{e['regeracao']['manifesto']}`, SHA-256 `{e['regeracao']['sha256']}`; extrator com SHA-256 "
            f"`{e['regeracao']['extrator']['sha256']}` e opções {e['regeracao']['extrator']['opcoes'] or 'nenhuma'}."
        ),
    ]
    if e.get("modelo"):
        linhas.append(
            f"- Modelo salvo: `{e['modelo']['arquivo']}`, SHA-256 `{e['modelo']['sha256']}`."
            + ("" if "_sem_fundo" in e["modelo"]["arquivo"] else
               " O nome é o da data da medida, quando este era o modelo do sistema; hoje o modelo de 10/10 é refeito por "
               "`treinar_regerado --sem-fundo` em `rf_regerado_janela_100_sem_fundo.joblib`.")
        )
    p = m["parametros"]
    linhas += [
        (
            f"- Treinos: `RandomForestClassifier` do scikit-learn com {p['arvores']} árvores e os demais parâmetros "
            f"padrão, {_nucleos_em_texto(p['nucleos'])} (o modelo não depende disso), teto de "
            f"{_milhar(p['teto'])} linhas por rótulo e corte de {_pct(1 - p['fracao_de_teste'], 0)} das janelas de cada "
            "pcap, as mesmas funções de `treinar_regerado`. Predição com um núcleo, em ordem fixa."
        ),
        "- Os números das tabelas são arredondados; os valores completos, com as contagens, estão no manifesto, e as",
        f"  tabelas em CSV começam com `{m['prefixo']}_`.",
        (
            f"- Tempo desta execução, na máquina em que rodou: {_decimal(m['duracao_segundos'])} s. Os treinos já "
            f"guardados em `{TRABALHO}/` são reaproveitados e não entram nessa conta; somados, os treinos de que os "
            f"números saem levaram {_decimal(_tempo_de_treino(m['resultados']))} s."
        ),
        *_codigo_e_memoria(m),
        "- Com as mesmas entradas, o mesmo código e as mesmas sementes, os números saem iguais. Só mudam a data e os",
        "  tempos.",
    ]
    return linhas


def _maior_memoria(valor):
    """O maior pico de memória registrado no manifesto: o da execução e o do fim de cada treino."""
    if isinstance(valor, dict):
        return max([v if k == "memoria_pico_bytes" else _maior_memoria(v) for k, v in valor.items()] or [0])
    if isinstance(valor, list):
        return max([_maior_memoria(v) for v in valor] or [0])
    return 0


def _codigo_e_memoria(m):
    """As linhas do código de que os números saíram e da memória necessária para reproduzi-los."""
    codigo = m.get("codigo")
    linhas = []
    if codigo:
        linhas.append(
            "- Código: o SHA-256 de cada módulo de que os números saem ("
            + _enumerar(f"`{Path(nome).name}`" for nome in codigo["arquivos"])
            + f") está no manifesto e entra na chave dos treinos guardados; commit `{(codigo['commit'] or '?')[:12]}`"
            + (", com alterações ainda fora dele." if codigo["com_alteracoes_fora_do_commit"] else ".")
        )
    memoria = _maior_memoria(m)
    if memoria:
        linhas.append(
            f"- Memória: pico de {_decimal(memoria / 1e9)} GB no processo, o necessário para reproduzir com a mesma "
            "quantidade de núcleos."
        )
    return linhas


def _resumo(m, capturas=None):
    """Os números principais de cada rodada, numa lista curta no começo do relatório."""
    r = m["resultados"]
    controle = _controle(m)
    itens = []
    reproducao = r["corte"].get(controle[0], {}).get("detalhe", {}).get("reproducao")
    if reproducao:
        itens.append(
            f"a. O modelo salvo reproduz as medidas publicadas ({len(reproducao['medidas_diferentes'])} diferenças em "
            f"{reproducao['medidas_conferidas']}), e o retreino com a semente 42 dá "
            f"{_milhar(reproducao['predicoes_diferentes_do_retreino'])} predições diferentes das dele."
        )
    if len(r["corte"]) > 1:
        itens.append(
            f"b. Entre {len(r['corte'])} sementes, macro-F1 {_com_faixa(_do_corte(r, list(r['corte']), lambda a: a['macro_f1']))} "
            f"e benigno classificado como ataque {_com_faixa(_do_corte(r, list(r['corte']), lambda a: a['benigno_como_ataque']))}."
        )
    rotacoes_ = rotacoes_do_benigno(r, controle)
    if len(rotacoes_) > 1:
        itens.append(
            "c. Benigno classificado como ataque com cada pcap benigno fora do treino: "
            + "; ".join(f"`{rot['arquivo']}` {_com_faixa(rot['como_ataque'])}" for rot in rotacoes_)
            + f". No total dos três, {_com_faixa(benigno_no_total(r, controle))}."
        )
    if r["corte"] and next(iter(r["corte"].values()))["fundo"]:
        itens.append(
            f"d. Janelas de fundo dos pcaps de ataque, sem nenhum quadro do atacante, classificadas como ataque: "
            f"{_com_faixa(fundo_por_semente(r, controle))} na parte de teste."
        )
    if r.get("fora"):
        partes = []
        for categoria in CATEGORIAS_DO_RESUMO:
            arquivos = [a for a, s in r["fora"].items() if next(iter(s.values()))["categoria"] == categoria]
            if arquivos:
                partes.append(f"{categoria} {_com_faixa(recall_fora(r, controle, categoria))} contra "
                              f"{_com_faixa(recall_dentro(r, controle, categoria, arquivos))}")
        valores = _spoofing_normalizado(capturas, controle)
        itens.append(
            "e. Recall com o pcap inteiro fora do treino, contra dentro da captura: " + "; ".join(partes) + "."
            + (f" No Spoofing, com o quadro menor que 60 bytes contado como 60, o recall com o pcap fora cai para "
               f"{_pct(valores['1'])} (`{RELATORIO_DAS_CAPTURAS}`)." if valores and "1" in valores else "")
        )
    if "tamanhos" in r:
        t = r["tamanhos"]["por_categoria"]
        itens.append(
            "f. Janelas com quadro menor que 60 bytes: "
            + ", ".join(f"{c} {_pct(_fracao(v['abaixo_de_60'], v['janelas']), 1)}" for c, v in t.items())
            + "; com quadro maior que 1.514 bytes: "
            + ", ".join(f"{c} {_pct(_fracao(v['acima_de_1514'], v['janelas']), 1)}" for c, v in t.items()) + "."
        )
    curva = r["corte"].get(controle[0], {}).get("detalhe", {}).get("limiar")
    if curva:
        itens.append(
            "g. Pontos candidatos do limiar, escolhidos no próprio teste (a escolha final precisa de uma parte de "
            "validação): "
            + "; ".join(f"t = {_decimal(linha['limiar'], 2)} com {_pct(linha['benigno_como_ataque'])} de benigno como "
                        f"ataque e {_pct(linha['recall_de_ataque'])} de recall de ataque"
                        for _, linha in candidatos_do_limiar(curva)) + "."
        )
    intervalos = r["corte"].get(controle[0], {}).get("detalhe", {}).get("intervalos")
    if intervalos:
        itens.append(
            "h. Recall com o intervalo por blocos: "
            + "; ".join(f"{c} {_pct(_fracao(v['acertos'], v['janelas']), 1)} ({_pct(v['recall_blocos'][0], 1)} a "
                        f"{_pct(v['recall_blocos'][1], 1)})" for c, v in intervalos.items() if v["recall_blocos"][0] is not None)
            + "."
        )
    custo_ = r.get("custo", {})
    if custo_.get("modelo"):
        itens.append(
            f"i. Uma janela leva {_decimal(custo_['modelo']['latencia_predict']['mediana_ms'], 2)} ms para ser classificada "
            f"sozinha e {_decimal(custo_['modelo']['lote_de_1000_ms'] / 1000, 3)} ms num lote de 1.000; o modelo tem "
            f"{_decimal(custo_['modelo']['bytes'] / 1e6)} MB."
        )
    return ["## Resumo", "", *(f"- {item}" for item in itens)] if itens else []


def montar_relatorio(m, capturas=None):
    """O relatório das rodadas do modelo de 10/10, a partir do manifesto e, se houver, do da comparação de capturas."""
    secoes = [_cabecalho(m), _resumo(m, capturas), _secao_a(m), _secao_b(m), _secao_c(m), _secao_d(m),
              _secao_e(m, capturas), _secao_f(m), _secao_g(m), _secao_h(m), _secao_i(m), _como_foram_obtidos(m)]
    return "\n".join("\n".join(secao) + "\n" for secao in secoes if secao).rstrip("\n") + "\n"


# --- o relatório da comparação de capturas -----------------------------------------------------


def pcap_do_pior_benigno(resultado, sementes):
    """O pcap benigno de maior alarme, na média das sementes, quando fica fora do treino."""
    rotacoes_ = rotacoes_do_benigno(resultado, sementes)
    return max(rotacoes_, key=lambda rot: _media(rot["como_ataque"]))["arquivo"]


def medidas_do_resumo(resultado, sementes, pior=None):
    """As medidas da tabela-resumo de uma configuração, cada uma com o valor de cada semente.

    O pior pcap benigno é o mesmo em todas as configurações, `pior`: o de maior alarme na de
    referência, para que a comparação seja nas mesmas janelas.
    """
    pior = pior or pcap_do_pior_benigno(resultado, sementes)
    rotacao = next(rot for rot in rotacoes_do_benigno(resultado, sementes) if rot["arquivo"] == pior)
    medidas = {
        "macro_f1": _do_corte(resultado, sementes, lambda a: a["macro_f1"]),
        "pior_benigno": rotacao["como_ataque"],
        "fundo": fundo_por_semente(resultado, sementes),
    }
    for categoria in CATEGORIAS_DO_RESUMO:
        medidas[f"fora_{categoria}"] = recall_fora(resultado, sementes, categoria)
        medidas[f"fora_{categoria}_como_ataque"] = recall_fora(resultado, sementes, categoria, "como_ataque")
    return medidas


def comparacoes_do_resumo(resultado, pior):
    """A comparação pareada de cada medida da tabela-resumo com a configuração de referência."""
    comparacao = resultado.get("comparacao")
    if comparacao is None:
        return {}
    saida = {
        "macro_f1": comparacao["corte"]["macro_f1"],
        "pior_benigno": comparacao["rotacao"].get(pior),
        "fundo": comparacao["fundo"]["teste"],
    }
    for categoria in CATEGORIAS_DO_RESUMO:
        por_categoria = comparacao["fora"]["por_categoria"].get(categoria, {})
        saida[f"fora_{categoria}"] = por_categoria.get("na_categoria")
        saida[f"fora_{categoria}_como_ataque"] = por_categoria.get("como_ataque")
    return saida


def rotulos_do_resumo(pior):
    return {
        "macro_f1": "Macro-F1 no corte por tempo",
        "pior_benigno": f"Benigno como ataque no pior pcap benigno de fora (`{pior}`)",
        "fundo": "Fundo virando ataque (parte de teste)",
        **{f"fora_{c}": f"Recall {c} com o pcap fora" for c in CATEGORIAS_DO_RESUMO},
    }


def _celula(valores, comparacao=None):
    """A média e a faixa das sementes, com um asterisco se a diferença pareada para a referência conta."""
    texto = _com_faixa(valores, 1)
    if comparacao is not None and comparacao.get("acima"):
        texto += " *"
    return texto


def _pior(m):
    return pcap_do_pior_benigno(m["resultados"]["0"], _controle(m))


_POR_EXTENSO = {1: "uma", 2: "duas", 3: "três", 4: "quatro", 5: "cinco", 6: "seis", 7: "sete", 8: "oito"}


def _por_extenso(numero):
    return _POR_EXTENSO.get(numero, str(numero))


def _com_fundo(configuracoes):
    """As configurações que põem o fundo da parte de treino no treino como benigno."""
    return [c for c in configuracoes if c.get("fundo_como_benigno")]


def _frase_do_fundo_no_treino(configuracoes):
    """O que as configurações com o fundo no treino fazem, e o que a comparação entre elas separa."""
    com_fundo = _com_fundo(configuracoes)
    if not com_fundo:
        return ""
    nomes = _enumerar(c["nome"] for c in com_fundo)
    frase = (
        f" {'Nas configurações' if len(com_fundo) > 1 else 'Na configuração'} {nomes}, as janelas de fundo da parte de "
        "treino de cada pcap de ataque, sem nenhum quadro do atacante, entram no treino como Benign"
    )
    destinos = {c["destino"] for c in com_fundo}
    if len(com_fundo) > 1 and len(destinos) == len(com_fundo):
        frase += (
            ": " + _enumerar(f"a {c['nome']} sobre os dados de `{c['destino']}`" for c in com_fundo)
            + ". A comparação entre elas separa o efeito do fundo do efeito do tamanho do quadro."
        )
    else:
        frase += "."
    return frase


def _cabecalho_das_capturas(m):
    p = m["parametros"]
    configuracoes = m["entradas"]["configuracoes"]
    return [
        "# Captura normalizada: comparação de configurações",
        "",
        f"Gerado por `{m['gerado_por']}` em {_data(m)}, com {_versoes(m)}.",
        "",
        (
            "Os pcaps do CICIoT2023 não têm os tamanhos de quadro distribuídos do mesmo jeito: os de spoofing têm "
            "quadros menores que 60 bytes, e os benignos, quadros maiores que 1.514 bytes (`rodadas_de_teste.md`, "
            "rodada f). " + EXPLICACAO_DOS_QUADROS + " O extrator tem duas opções, desligadas por padrão, que mudam só "
            "o tamanho medido: o preenchimento conta como 60 bytes o quadro menor que isso, e o teto conta como 1.514 "
            "o quadro maior. As duas aproximam o tamanho do quadro no fio, sem reproduzi-lo: no fio, um quadro "
            "agregado de 64 KB seria várias dezenas de quadros, e não um de 1.514 bytes, e a contagem de quadros, o "
            "`IAT` e o `Rate` da janela continuam os da captura."
        ),
        "",
        (
            "Este relatório lê as pastas regeradas antes por `regerar --preencher` e por `regerar --preencher "
            f"--limitar` e compara o modelo de 10/10 (configuração 0) com {_por_extenso(len(configuracoes) - 1)} "
            "alternativas, no corte por tempo e nas rodadas c (rotação do pcap benigno de fora), d (tráfego de fundo) "
            "e e (pcap fora do treino)." + _frase_do_fundo_no_treino(configuracoes)
        ),
        "",
        *_tabela(
            ["Configuração", "O que muda", "Dados", "Opções do extrator"],
            [[c["nome"], c["descricao"], f"`{c['destino']}`", _enumerar(f"`{o}`" for o, _ in c["opcoes"]) if c["opcoes"]
              else "nenhuma"] for c in configuracoes],
        ),
        "",
        (
            f"Cada configuração foi treinada com as sementes {_enumerar(p['sementes'][:p['sementes_de_controle']])}, que "
            "definem ao mesmo tempo o sorteio do teto e o Random Forest. Os valores são a média das sementes, com o "
            "menor e o maior entre parênteses, e o asterisco marca a diferença para a configuração 0 que conta pelo "
            "critério abaixo. A tabela-resumo fecha o relatório."
        ),
        "",
        criterio_da_diferenca(),
    ]


def _tabela_resumo(m):
    r = m["resultados"]
    sementes = _controle(m)
    pior = _pior(m)
    linhas = []
    for nome, resultado in r.items():
        medidas = medidas_do_resumo(resultado, sementes, pior)
        comparacoes = comparacoes_do_resumo(resultado, pior)
        celulas = [nome]
        for chave in rotulos_do_resumo(pior):
            celula = _celula(medidas[chave], comparacoes.get(chave))
            if chave == "fora_BruteForce":
                celula += f" (como ataque {_celula(medidas['fora_BruteForce_como_ataque'], comparacoes.get('fora_BruteForce_como_ataque'))})"
            celulas.append(celula)
        linhas.append(celulas)
    return [
        "## Tabela-resumo",
        "",
        *_tabela(["Configuração", *rotulos_do_resumo(pior).values()], linhas),
        "",
        (
            "O asterisco marca a diferença para a configuração 0 cujo intervalo de 95% deixa o zero de fora. O pior pcap "
            f"benigno de fora é `{pior}`, o de maior alarme na configuração 0, e é o mesmo em todas as linhas. O fundo é "
            "o das janelas sem nenhum quadro do atacante, na parte de teste dos pcaps de ataque. O recall com o pcap "
            "fora soma os pcaps da categoria, cada um medido nas suas janelas de teste com o modelo que não o viu. "
            "BruteForce tem um pcap só: com ele fora a categoria some do treino, o recall é zero por construção, e entre "
            "parênteses fica a fração vista como algum ataque."
        ),
    ]


# --- a regra de adoção da configuração 5 --------------------------------------------------------
#
# A regra que a equipe definiu para a configuração 5 (o fundo como benigno sem a normalização do
# quadro): ela passa a ser o modelo do sistema se, na média das sementes, (a) o benigno classificado
# como ataque no pior pcap benigno de fora do treino fica abaixo de 10%, (b) o recall de DDoS+DoS no
# corte por tempo fica em pelo menos 98% e (c) o recall do `Recon-PortScan.pcap` com o pcap fora do
# treino não cai mais de 5 pontos em relação à configuração 0. Se uma condição falha, o modelo
# continua o da configuração 0.

CANDIDATA, REFERENCIA = "5", "0"
PIOR_BENIGNO_ABAIXO_DE = 0.10
RECALL_DE_DDOS_MINIMO = 0.98
PCAP_DA_REGRA = "Recon-PortScan.pcap"
QUEDA_MAXIMA_DO_PCAP = 0.05


def atende_a_regra(pior_benigno, recall_de_ddos, diferenca_do_pcap):
    """Se cada condição da regra é atendida: (a), (b) e (c), com os valores médios das sementes."""
    return (
        pior_benigno < PIOR_BENIGNO_ABAIXO_DE,
        recall_de_ddos >= RECALL_DE_DDOS_MINIMO,
        diferenca_do_pcap >= -QUEDA_MAXIMA_DO_PCAP,
    )


def _recall_do_pcap_fora(resultado, sementes, arquivo, trecho="teste"):
    """O recall de um pcap fora do treino, por semente: no trecho de teste dele ou no pcap inteiro."""
    unidades = _nas_sementes(resultado.get("fora", {}).get(arquivo, {}), sementes)
    return [_fracao(u[trecho]["previstas"][u["categoria"]], u[trecho]["janelas"]) for u in unidades]


def _janelas_do_pcap_fora(resultado, sementes, arquivo, trecho="teste"):
    unidades = _nas_sementes(resultado.get("fora", {}).get(arquivo, {}), sementes)
    return unidades[0][trecho]["janelas"] if unidades else None


def regra_de_adocao(m):
    """As medidas da regra na configuração candidata e na de referência, e o veredito, ou None sem as duas."""
    r = m["resultados"]
    if CANDIDATA not in r or REFERENCIA not in r:
        return None
    sementes = _controle(m)
    medidas = {}
    for nome in (REFERENCIA, CANDIDATA):
        rotacoes_ = rotacoes_do_benigno(r[nome], sementes)
        pior = max(rotacoes_, key=lambda rot: _media(rot["como_ataque"]))
        medidas[nome] = {
            "pior_benigno": _media(pior["como_ataque"]), "pcap_do_pior_benigno": pior["arquivo"],
            "recall_de_ddos": _media(_do_corte(r[nome], sementes, lambda a: a["por_classe"]["DDoS+DoS"]["recall"])),
            "recall_do_pcap": _media(_recall_do_pcap_fora(r[nome], sementes, PCAP_DA_REGRA)),
            # O pcap inteiro, e não só o trecho de teste: a regra mede o trecho, e o inteiro fica por transparência.
            "recall_do_pcap_inteiro": _media(_recall_do_pcap_fora(r[nome], sementes, PCAP_DA_REGRA, "inteiro")),
            "janelas_do_trecho": _janelas_do_pcap_fora(r[nome], sementes, PCAP_DA_REGRA),
            "janelas_do_pcap_inteiro": _janelas_do_pcap_fora(r[nome], sementes, PCAP_DA_REGRA, "inteiro"),
        }
    diferenca = medidas[CANDIDATA]["recall_do_pcap"] - medidas[REFERENCIA]["recall_do_pcap"]
    diferenca_inteiro = medidas[CANDIDATA]["recall_do_pcap_inteiro"] - medidas[REFERENCIA]["recall_do_pcap_inteiro"]
    condicoes = atende_a_regra(medidas[CANDIDATA]["pior_benigno"], medidas[CANDIDATA]["recall_de_ddos"], diferenca)
    return {
        "medidas": medidas, "diferenca_do_pcap": diferenca, "diferenca_do_pcap_inteiro": diferenca_inteiro,
        "c_pelo_pcap_inteiro": diferenca_inteiro >= -QUEDA_MAXIMA_DO_PCAP,
        "comparacao_do_pcap": _no_caminho(r[CANDIDATA], "comparacao", "fora", "por_pcap", PCAP_DA_REGRA),
        "condicoes": dict(zip("abc", condicoes)), "adotada": all(condicoes),
    }


def _regra_das_capturas(m):
    regra = regra_de_adocao(m)
    if regra is None:
        return []
    ref, nova = regra["medidas"][REFERENCIA], regra["medidas"][CANDIDATA]
    sim = lambda condicao: "sim" if regra["condicoes"][condicao] else "não"
    comparacao = regra["comparacao_do_pcap"]
    linhas = [
        ["(a) Benigno como ataque no pior pcap benigno de fora", f"abaixo de {_pct(PIOR_BENIGNO_ABAIXO_DE, 0)}",
         f"{_pct(ref['pior_benigno'], 1)} (`{ref['pcap_do_pior_benigno']}`)",
         f"{_pct(nova['pior_benigno'], 1)} (`{nova['pcap_do_pior_benigno']}`)", sim("a")],
        ["(b) Recall DDoS+DoS no corte por tempo", f"pelo menos {_pct(RECALL_DE_DDOS_MINIMO, 0)}",
         _pct(ref["recall_de_ddos"], 2), _pct(nova["recall_de_ddos"], 2), sim("b")],
        [f"(c) Recall do `{PCAP_DA_REGRA}` com o pcap fora", f"queda de até {_decimal(100 * QUEDA_MAXIMA_DO_PCAP, 0)} p.p.",
         _pct(ref["recall_do_pcap"], 1),
         f"{_pct(nova['recall_do_pcap'], 1)} ({_pp(regra['diferenca_do_pcap'])} p.p.)", sim("c")],
    ]
    falham = [c for c, atende in regra["condicoes"].items() if not atende]
    veredito = (
        f"Pela regra, a configuração {CANDIDATA} passa a ser o modelo do sistema." if regra["adotada"] else
        f"Pela regra, a configuração {CANDIDATA} não é adotada e o modelo continua o da configuração {REFERENCIA}: "
        + ("falha a condição " if len(falham) == 1 else "falham as condições ") + _enumerar(f"({c})" for c in falham) + "."
    )
    return [
        f"## Regra de adoção da configuração {CANDIDATA}",
        "",
        (
            f"A regra definida pela equipe: a configuração {CANDIDATA} passa a ser o modelo do sistema se, na média das "
            f"sementes, (a) o benigno classificado como ataque no pior pcap benigno de fora do treino fica abaixo de "
            f"{_pct(PIOR_BENIGNO_ABAIXO_DE, 0)}, (b) o recall de DDoS+DoS no corte por tempo fica em pelo menos "
            f"{_pct(RECALL_DE_DDOS_MINIMO, 0)} e (c) o recall do `{PCAP_DA_REGRA}` com o pcap fora do treino não cai mais "
            f"de {_decimal(100 * QUEDA_MAXIMA_DO_PCAP, 0)} pontos em relação à configuração {REFERENCIA}. Se uma condição "
            f"falha, o modelo continua o da configuração {REFERENCIA}. O pior pcap benigno é o de cada configuração."
        ),
        "",
        *_tabela(["Condição", "Limite", f"Configuração {REFERENCIA}", f"Configuração {CANDIDATA}", "Atende"], linhas),
        "",
        veredito + (
            f" A diferença da condição (c), com o intervalo de 95% das diferenças pareadas, é {_leitura(comparacao)}."
            if comparacao else ""
        ),
        "",
        _trecho_da_condicao_c(regra),
    ]


def _trecho_da_condicao_c(regra):
    """Qual trecho do pcap a condição (c) mediu, e o que daria o pcap inteiro."""
    ref, nova = regra["medidas"][REFERENCIA], regra["medidas"][CANDIDATA]
    if ref.get("recall_do_pcap_inteiro") is None:
        return ""
    queda = -regra["diferenca_do_pcap_inteiro"]
    texto = (
        f"A condição (c) foi medida no trecho de teste do `{PCAP_DA_REGRA}` ({_milhar(nova['janelas_do_trecho'])} "
        "janelas), com o pcap fora do treino: é a convenção de todas as medidas com o pcap fora deste relatório, e a que "
        "estava na tabela quando a regra foi fixada. No pcap inteiro "
        f"({_milhar(nova['janelas_do_pcap_inteiro'])} janelas), o recall vai de {_pct(ref['recall_do_pcap_inteiro'], 1)} "
        f"para {_pct(nova['recall_do_pcap_inteiro'], 1)}, uma " + ("queda" if queda > 0 else "alta") + " de "
        f"{_decimal(100 * abs(queda), 2)} pontos"
    )
    if regra["condicoes"]["c"] and not regra["c_pelo_pcap_inteiro"]:
        texto += (
            ", e pelo pcap inteiro a condição (c) falharia. A adoção foi mantida porque a regra foi aplicada como foi "
            "fixada e porque o ganho no alarme falso é grande: no pior pcap benigno de fora, de "
            f"{_pct(ref['pior_benigno'], 1)} para {_pct(nova['pior_benigno'], 1)}."
        )
    else:
        texto += "."
    return texto


def _diferencas_das_capturas(m):
    r = m["resultados"]
    if "0" not in r:
        return []
    pior = _pior(m)
    rotulos = {
        "macro_f1": "macro-F1 no corte por tempo", "pior_benigno": "benigno como ataque no pior pcap benigno de fora",
        "fundo": "fundo virando ataque",
        **{f"fora_{c}": f"recall de {c} com o pcap fora" for c in CATEGORIAS_DO_RESUMO},
        **{f"fora_{c}_como_ataque": f"{c} visto como algum ataque com o pcap fora" for c in CATEGORIAS_DO_RESUMO},
    }
    secao = [
        "## Quais diferenças contam",
        "",
        "Nas medidas da tabela-resumo, a diferença para a configuração 0, com o intervalo de 95% entre parênteses:",
        "",
    ]
    if not any("comparacao" in resultado for resultado in r.values()):
        return [
            "## Quais diferenças contam",
            "",
            (
                "Este manifesto não traz as diferenças pareadas: ele foi gravado antes de o critério existir, e as "
                "tabelas não marcam nenhuma diferença. As médias e as faixas das sementes valem; para saber quais "
                "diferenças contam, é preciso rodar a comparação de novo."
            ),
        ]
    for nome, resultado in r.items():
        if nome == "0":
            continue
        comparacoes = comparacoes_do_resumo(resultado, pior)
        contam = [
            f"{rotulos[chave]} ({_pp(c['diferenca'])} p.p., de {_pp(c['inferior'])} a {_pp(c['superior'])})"
            for chave in rotulos if (c := comparacoes.get(chave)) and c["acima"]
        ]
        nao_contam = [rotulos[chave] for chave in rotulos if (c := comparacoes.get(chave)) and not c["acima"]]
        secao.append(
            f"- Configuração {nome}: " + (_enumerar(contam) + "." if contam else "nenhuma diferença conta.")
            + (f" Sem diferença: {_enumerar(nao_contam)}." if nao_contam else "")
        )
    return secao


def _corte_das_capturas(m):
    r = m["resultados"]
    sementes = _controle(m)
    medidas = [
        ("Macro-F1", "macro_f1", lambda a: a["macro_f1"]), ("Acurácia", "acuracia", lambda a: a["acuracia"]),
        ("Benigno classificado como ataque", "benigno_como_ataque", lambda a: a["benigno_como_ataque"]),
        ("Ataque classificado como benigno", "ataque_como_benigno", lambda a: a["ataque_como_benigno"]),
        *((f"Recall {c}", f"recall_{c}", lambda a, c=c: a["por_classe"][c]["recall"]) for c in CLASSES),
        *((f"Precisão {c}", f"precisao_{c}", lambda a, c=c: a["por_classe"][c]["precisao"])
          for c in ("Spoofing", "Web", "BruteForce")),
    ]
    linhas = [
        [rotulo, *(_celula(_do_corte(res, sementes, funcao), _no_caminho(res, "comparacao", "corte", chave))
                   for res in r.values())]
        for rotulo, chave, funcao in medidas
    ]
    return [
        "## Corte por tempo",
        "",
        "A divisão publicada: o começo de cada pcap no treino e o fim no teste, e um pcap inteiro de fora nos rótulos de",
        "vários pcaps. O asterisco marca a diferença para a configuração 0 que conta.",
        "",
        *_tabela(["Medida", *(f"Configuração {nome}" for nome in r)], linhas),
    ]


def _rotacao_das_capturas(m):
    r = m["resultados"]
    sementes = _controle(m)
    arquivos = [rot["arquivo"] for rot in rotacoes_do_benigno(next(iter(r.values())), sementes)]
    pior = _pior(m)
    linhas = []
    for nome, resultado in r.items():
        rotacoes_ = {rot["arquivo"]: rot for rot in rotacoes_do_benigno(resultado, sementes)}
        celulas = [nome]
        for arquivo in arquivos:
            celulas.append(_celula(rotacoes_[arquivo]["como_ataque"], _no_caminho(resultado, "comparacao", "rotacao",
                                                                                   arquivo)))
        celulas.append(_celula(benigno_no_total(resultado, sementes),
                               _no_caminho(resultado, "comparacao", "rotacao", "total")))
        linhas.append(celulas)
    return [
        "## c. Rotação do pcap benigno de fora",
        "",
        "Tráfego benigno classificado como ataque em cada pcap benigno, com o modelo que deixou esse pcap inteiro fora",
        f"do treino, e no total dos três. O pior é `{pior}`.",
        "",
        *_tabela(["Configuração", *(f"`{a}`" for a in arquivos), "Total"], linhas),
    ]


def _aviso_do_fundo_de_treino(m):
    """Nas configurações com o fundo no treino, a parte de treino do fundo deixa de ser medida fora da amostra."""
    com_fundo = _com_fundo(m["entradas"]["configuracoes"])
    if not com_fundo:
        return []
    varias = len(com_fundo) > 1
    return [
        (f"{'Nas configurações' if varias else 'Na configuração'} {_enumerar(c['nome'] for c in com_fundo)} o fundo da "
         "parte de treino entra no treino como benigno, e a coluna da parte de treino"),
        "deixa de ser uma medida fora da amostra.",
    ]


def _fundo_das_capturas(m):
    r = m["resultados"]
    sementes = _controle(m)
    referencia = r.get("0")
    if referencia is None:
        return []
    primeiro = _nas_sementes(referencia["corte"], sementes)[0]
    arquivos = [p["arquivo"] for p in sorted(primeiro["fundo"], key=lambda p: -p["teste"]["janelas"])
                if p["teste"]["janelas"] >= 50]
    totais = [[nome, _celula(fundo_por_semente(res, sementes, "teste"), _no_caminho(res, "comparacao", "fundo", "teste")),
               _celula(fundo_por_semente(res, sementes, "treino"), _no_caminho(res, "comparacao", "fundo", "treino"))]
              for nome, res in r.items()]

    def na_categoria(resultado, arquivo):
        valores = []
        for u in _nas_sementes(resultado["corte"], sementes):
            p = next(f for f in u["fundo"] if f["arquivo"] == arquivo)
            valores.append(_fracao(p["teste"]["previstas"][p["categoria"]], p["teste"]["janelas"]))
        return valores

    por_pcap = []
    for arquivo in arquivos:
        categoria = next(p["categoria"] for p in primeiro["fundo"] if p["arquivo"] == arquivo)
        janelas = next(p["teste"]["janelas"] for p in primeiro["fundo"] if p["arquivo"] == arquivo)
        por_pcap.append([f"`{arquivo}`", categoria, _milhar(janelas),
                         *(_celula(na_categoria(res, arquivo), _no_caminho(res, "comparacao", "fundo", "por_pcap", arquivo))
                           for res in r.values())])
    return [
        "## d. Tráfego de fundo",
        "",
        "Fração das janelas sem nenhum quadro do atacante classificada como algum ataque, somando os pcaps de ataque.",
        *_aviso_do_fundo_de_treino(m),
        "",
        *_tabela(["Configuração", "Parte de teste", "Parte de treino"], totais),
        "",
        "Por pcap, na parte de teste, a fração do fundo posta na categoria do próprio pcap (pcaps com ao menos 50 janelas",
        "de fundo na parte de teste):",
        "",
        *_tabela(["Pcap", "Categoria", "Janelas de fundo no teste", *(f"Configuração {nome}" for nome in r)], por_pcap),
    ]


def _fora_das_capturas(m):
    r = m["resultados"]
    sementes = _controle(m)
    referencia = r.get("0")
    if referencia is None or not referencia.get("fora"):
        return []

    def do_pcap(resultado, arquivo):
        unidades = _nas_sementes(resultado["fora"][arquivo], sementes)
        return [_fracao(u["teste"]["previstas"][u["categoria"]], u["teste"]["janelas"]) for u in unidades]

    linhas = []
    for arquivo, por_semente in referencia["fora"].items():
        unidade = next(iter(por_semente.values()))
        linhas.append([f"`{arquivo}`", unidade["categoria"], _milhar(unidade["teste"]["janelas"]),
                       *(_celula(do_pcap(res, arquivo), _no_caminho(res, "comparacao", "fora", "por_pcap", arquivo))
                         for res in r.values())])
    categorias = []
    for categoria in CLASSES:
        if not any(next(iter(s.values()))["categoria"] == categoria for s in referencia["fora"].values()):
            continue
        categorias.append([categoria, *(_celula(recall_fora(res, sementes, categoria),
                                                _no_caminho(res, "comparacao", "fora", "por_categoria", categoria,
                                                            "na_categoria"))
                                        for res in r.values())])
    return [
        "## e. Pcap fora do treino",
        "",
        "Recall de cada pcap, nas janelas de teste dele, quando nenhuma janela dele entra no treino:",
        "",
        *_tabela(["Pcap", "Categoria", "Janelas de teste", *(f"Configuração {nome}" for nome in r)], linhas),
        "",
        "Somando os pcaps de cada categoria:",
        "",
        *_tabela(["Categoria", *(f"Configuração {nome}" for nome in r)], categorias),
    ]


def _tamanhos_das_capturas(m):
    r = m["resultados"]
    com_tamanhos = [(nome, res["tamanhos"]) for nome, res in r.items() if "tamanhos" in res]
    if not com_tamanhos:
        return []
    linhas = []
    for classe in CLASSES:
        celulas = [classe]
        for _, t in com_tamanhos:
            v = t["por_categoria"][classe]
            celulas += [_pct(_fracao(v["abaixo_de_60"], v["janelas"]), 1), _pct(_fracao(v["acima_de_1514"], v["janelas"]), 1)]
        linhas.append(celulas)
    cabecalho = ["Categoria"]
    for nome, _ in com_tamanhos:
        cabecalho += [f"Menor que 60 ({nome})", f"Maior que 1.514 ({nome})"]
    return [
        "## O tamanho dos quadros em cada pasta",
        "",
        "Fração das janelas mantidas com algum quadro menor que 60 bytes e maior que 1.514 bytes, por pasta de dados,",
        "para conferir o que as opções do extrator fizeram:",
        "",
        *_tabela(cabecalho, linhas),
    ]


def _como_foram_obtidos_das_capturas(m):
    p = m["parametros"]
    linhas = [
        "## Como os números foram obtidos",
        "",
        f"- Comando: `{m['comando']}`, a partir da raiz do repositório.",
        "- Dados de cada pasta, regerados por `python -m codigo.classificador.regerar --janelas 100` com as opções do",
        "  extrator de cada configuração:",
    ]
    for destino, entrada in m["entradas"]["pastas"].items():
        extrator = entrada["regeracao"]["extrator"] or {}
        linhas.append(
            f"  - `{destino}`: manifesto `{entrada['regeracao']['manifesto']}` (SHA-256 "
            f"`{entrada['regeracao']['sha256']}`), extrator com SHA-256 `{extrator.get('sha256')}` e opções "
            f"{extrator.get('opcoes') or 'nenhuma'}; {len(entrada['arquivos'])} arquivos lidos, com o SHA-256 de cada um "
            f"em `{m['arquivo_do_manifesto']}`."
        )
    linhas += [
        (
            f"- Treinos: `RandomForestClassifier` com {p['arvores']} árvores e os demais parâmetros padrão, teto de "
            f"{_milhar(p['teto'])} linhas por rótulo, corte de {_pct(1 - p['fracao_de_teste'], 0)} das janelas de cada "
            "pcap, as mesmas funções de `treinar_regerado`; a configuração 0 é o mesmo treino de `rodadas_de_teste.md`."
        ),
        f"- As tabelas em CSV começam com `{m['prefixo']}_`; os valores completos, com as contagens, estão no manifesto.",
        (
            f"- Tempo desta execução, na máquina em que rodou: {_decimal(m['duracao_segundos'])} s. Os treinos já "
            f"guardados em `{TRABALHO}/` são reaproveitados e não entram nessa conta; somados, os treinos de que os "
            f"números saem levaram {_decimal(_tempo_de_treino(m['resultados']))} s."
        ),
        *_codigo_e_memoria(m),
        "- Com as mesmas entradas, o mesmo código e as mesmas sementes, os números saem iguais. Só mudam a data e os",
        "  tempos.",
    ]
    return linhas


def montar_relatorio_das_capturas(m):
    """O relatório da comparação de capturas, a partir do manifesto."""
    secoes = [_cabecalho_das_capturas(m), _corte_das_capturas(m), _rotacao_das_capturas(m), _fundo_das_capturas(m),
              _fora_das_capturas(m), _tamanhos_das_capturas(m), _diferencas_das_capturas(m), _tabela_resumo(m),
              _regra_das_capturas(m), _como_foram_obtidos_das_capturas(m)]
    return "\n".join("\n".join(secao) + "\n" for secao in secoes if secao).rstrip("\n") + "\n"


# --- tabelas e gravação ----------------------------------------------------------------------


def _linhas_do_corte(nome, resultado):
    linhas = []
    for semente, u in resultado["corte"].items():
        a = u["medidas"]
        for chave in ("macro_f1", "acuracia", "f1_ponderado", "benigno_como_ataque", "ataque_como_benigno"):
            linhas.append([nome, semente, chave, "", _campo(a[chave])])
        for classe, medida in a["por_classe"].items():
            for chave in ("precisao", "recall", "f1", "suporte"):
                linhas.append([nome, semente, chave, classe, _campo(medida[chave])])
    return linhas


def _linhas_da_rotacao(nome, resultado):
    rotacoes_ = [("0", resultado["corte"]), *sorted(resultado.get("rotacao", {}).items())]
    return [
        [nome, rotacao, semente, p["arquivo"], p["rotulo"], p["categoria"], p["janelas"],
         *(p["previstas"][c] for c in CLASSES)]
        for rotacao, por_semente in rotacoes_ for semente, u in por_semente.items() for p in u["de_fora"]
    ]


def _linhas_do_fundo(nome, resultado):
    return [
        [nome, semente, p["arquivo"], p["rotulo"], p["categoria"], parte, p[parte]["janelas"],
         *(p[parte]["previstas"][c] for c in CLASSES)]
        for semente, u in resultado["corte"].items() for p in u["fundo"] for parte in ("treino", "teste")
    ]


def _linhas_do_pcap_fora(nome, resultado):
    linhas = []
    for arquivo, por_semente in resultado.get("fora", {}).items():
        for semente, u in por_semente.items():
            for trecho in ("teste", "inteiro"):
                linhas.append([nome, semente, arquivo, u["categoria"], "pcap fora", trecho, u[trecho]["janelas"],
                               *(u[trecho]["previstas"][c] for c in CLASSES)])
            dentro = resultado["corte"].get(semente, {}).get("por_pcap", {}).get(arquivo)
            if dentro is not None:
                linhas.append([nome, semente, arquivo, u["categoria"], "divisão publicada", "teste", dentro["janelas"],
                               *(dentro["previstas"][c] for c in CLASSES)])
    return linhas


CABECALHOS = {
    "corte": ["configuracao", "semente", "medida", "classe", "valor"],
    "rotacao": ["configuracao", "rotacao", "semente", "arquivo", "rotulo", "categoria", "janelas", *CLASSES],
    "fundo": ["configuracao", "semente", "arquivo", "rotulo", "categoria", "parte", "janelas", *CLASSES],
    "pcap_fora": ["configuracao", "semente", "arquivo", "categoria", "treino", "trecho", "janelas", *CLASSES],
}


def _achatar(comparacoes, caminho=()):
    """Cada comparação de um dicionário aninhado, com o caminho de chaves até ela."""
    if isinstance(comparacoes, dict) and "acima" in comparacoes:
        yield caminho, comparacoes
    elif isinstance(comparacoes, dict):
        for chave, valor in comparacoes.items():
            yield from _achatar(valor, (*caminho, str(chave)))


def _linhas_das_diferencas(manifesto, capturas):
    """Uma linha por diferença pareada: o que se comparou, a medida, a diferença, o intervalo e se conta."""
    if capturas:
        fontes = [(nome, res.get("comparacao", {})) for nome, res in manifesto["resultados"].items()]
    else:
        fontes = [("0", manifesto["resultados"].get("comparacoes", {}))]
    return [
        [nome, caminho[0], "/".join(caminho[1:]), _campo(c["diferenca"]), _campo(c["inferior"]), _campo(c["superior"]),
         int(c["acima"])]
        for nome, comparacoes in fontes for caminho, c in _achatar(comparacoes)
    ]


def gravar(manifesto, pasta):
    """Grava o manifesto e o que sai dele: o relatório e as tabelas."""
    pasta = Path(pasta)
    pasta.mkdir(parents=True, exist_ok=True)
    capturas = manifesto["arquivo_do_manifesto"] == MANIFESTO_DAS_CAPTURAS
    (pasta / manifesto["arquivo_do_manifesto"]).write_text(
        json.dumps(manifesto, indent=1, ensure_ascii=False) + "\n", encoding="utf-8",
    )
    if capturas:
        (pasta / RELATORIO_DAS_CAPTURAS).write_text(montar_relatorio_das_capturas(manifesto), encoding="utf-8")
        # O relatório das rodadas cita a comparação de capturas: ele é refeito com ela, se já existe.
        if (pasta / MANIFESTO).exists():
            sistema = json.loads((pasta / MANIFESTO).read_text(encoding="utf-8"))
            (pasta / RELATORIO).write_text(montar_relatorio(sistema, manifesto), encoding="utf-8")
    else:
        outra = pasta / MANIFESTO_DAS_CAPTURAS
        capturas_ = json.loads(outra.read_text(encoding="utf-8")) if outra.exists() else None
        (pasta / RELATORIO).write_text(montar_relatorio(manifesto, capturas_), encoding="utf-8")
    por_configuracao = manifesto["resultados"] if capturas else {"0": manifesto["resultados"]}
    prefixo = manifesto["prefixo"]
    for nome, montar in (("corte", _linhas_do_corte), ("rotacao", _linhas_da_rotacao), ("fundo", _linhas_do_fundo),
                         ("pcap_fora", _linhas_do_pcap_fora)):
        linhas = [linha for configuracao, res in por_configuracao.items() for linha in montar(configuracao, res)]
        _gravar_csv(pasta / f"{prefixo}_{nome}.csv", CABECALHOS[nome], linhas)
    _gravar_csv(
        pasta / f"{prefixo}_diferencas.csv",
        ["configuracao", "comparacao", "medida", "diferenca", "inferior", "superior", "conta"],
        _linhas_das_diferencas(manifesto, capturas),
    )
    if capturas:
        sementes = _controle(manifesto)
        pior = _pior(manifesto)
        _gravar_csv(
            pasta / f"{prefixo}_resumo.csv", ["configuracao", "medida", "semente", "valor"],
            [[nome, chave, semente, _campo(valor)]
             for nome, res in por_configuracao.items()
             for chave, valores in medidas_do_resumo(res, sementes, pior).items()
             for semente, valor in zip(sementes, valores)],
        )
        return
    detalhe = manifesto["resultados"]["corte"].get(_controle(manifesto)[0], {}).get("detalhe", {})
    if detalhe.get("limiar"):
        fundo = detalhe["limiar_no_fundo"]
        _gravar_csv(
            pasta / f"{prefixo}_limiar.csv",
            ["limiar", "benigno_como_ataque", "recall_de_ataque", "ataque_como_benigno", "macro_f1",
             *(f"recall_{c}" for c in CLASSES), "fundo_de_teste_como_ataque"],
            [[linha["limiar"], _campo(linha["benigno_como_ataque"]), _campo(linha["recall_de_ataque"]),
              _campo(linha["ataque_como_benigno"]), _campo(linha["macro_f1"]),
              *(_campo(linha["recall"][c]) for c in CLASSES),
              _campo(_fracao(fundo["como_ataque"].get(str(linha["limiar"])), fundo["janelas"]))]
             for linha in detalhe["limiar"]],
        )
    if detalhe.get("permutacao"):
        p = detalhe["permutacao"]
        _gravar_csv(
            pasta / f"{prefixo}_permutacao.csv", ["alvo", "feature", "queda_media", "desvio"],
            [[f"recall {classe}", feature, _campo(q[0]), _campo(q[1])]
             for classe, registro in p["por_categoria"].items() for feature, q in registro["quedas"].items()]
            + [["macro-F1", feature, _campo(q[0]), _campo(q[1])] for feature, q in p["macro_f1"]["quedas"].items()],
        )
    if detalhe.get("intervalos"):
        _gravar_csv(
            pasta / f"{prefixo}_intervalos.csv",
            ["classe", "janelas", "acertos", "wilson_inferior", "wilson_superior", "blocos_inferior", "blocos_superior",
             "autocorrelacao", "n_efetivo", "previstas", "certas", "precisao_wilson_inferior", "precisao_wilson_superior"],
            [[classe, v["janelas"], v["acertos"], _campo(v["recall_wilson"][0]), _campo(v["recall_wilson"][1]),
              _campo(v["recall_blocos"][0]), _campo(v["recall_blocos"][1]), _campo(v["autocorrelacao"]),
              _campo(v["n_efetivo"]), v["previstas"], v["certas"], _campo(v["precisao_wilson"][0]),
              _campo(v["precisao_wilson"][1])]
             for classe, v in detalhe["intervalos"].items()],
        )

