"""Relatório e tabelas do ponto de operação, a partir do manifesto que `ponto_de_operacao` grava.

Este módulo só formata: nenhum número é calculado aqui a partir dos dados, e por isso ele fica fora
da chave dos resultados guardados do ponto de operação.
"""
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
from codigo.classificador.operacao import SEGUIDAS
from codigo.classificador.ponto_de_operacao import (
    MANIFESTO,
    PREFIXO,
    RELATORIO,
    TRABALHO,
)
from codigo.classificador.rodadas import BENIGNO, BLOCO, CLASSES, RELATORIO_DAS_CAPTURAS
from codigo.classificador.rodadas_relatorio import (
    CANDIDATA,
    REFERENCIA,
    _codigo_e_memoria,
    _data,
    _fracao,
    _media,
    _versoes,
)

REGRAS = ("argmax", "limiar", "ponto")
NOME_DA_REGRA = {"argmax": "argmax", "limiar": "melhor limiar", "ponto": "ponto de operação"}


def _sementes(m):
    return [str(s) for s in m["parametros"]["sementes"]]


def _configuracoes(m):
    """Os nomes das configurações, a vencedora pela regra de adoção primeiro."""
    nomes = list(m["resultados"]["configuracoes"])
    vencedora = _vencedora(m)
    return [vencedora, *(n for n in nomes if n != vencedora)] if vencedora in nomes else nomes


def _referencia(m):
    return m["parametros"]["configuracoes"][0]


def _vencedora(m):
    """A configuração adotada pela regra da comparação de capturas, ou a de referência sem ela."""
    regra = m["resultados"].get("regra")
    nomes = list(m["resultados"]["configuracoes"])
    if regra is None:
        return nomes[0]
    return CANDIDATA if regra["adotada"] else REFERENCIA


def _unidades(m, nome, rotacao="0"):
    por_semente = m["resultados"]["configuracoes"][nome]["resultados"][rotacao]
    return [por_semente[s] for s in _sementes(m) if s in por_semente]


def _rotacoes(m, nome):
    return sorted(m["resultados"]["configuracoes"][nome]["resultados"], key=int)


def _faixa(valores, casas=1, por_cento=True):
    """A média e, com mais de um valor, o menor e o maior entre parênteses."""
    valores = [v for v in valores if v is not None]
    if not valores:
        return "sem valor"
    formatar = (lambda v: _pct(v, casas)) if por_cento else (lambda v: _decimal(v, casas))
    inteiros = not por_cento and all(float(v).is_integer() for v in valores)
    extremo = _milhar if inteiros else formatar
    if len(valores) == 1 or min(valores) == max(valores):
        return extremo(valores[0])
    return f"{formatar(float(np.mean(valores)))} ({extremo(min(valores))} a {extremo(max(valores))})"


def _limiares(unidades):
    """O melhor limiar de cada semente, o que concorreu com o argmax."""
    return "; ".join(_decimal(u["melhor_limiar"], 2) for u in unidades)


def _escolhas(unidades):
    """A regra escolhida na validação de cada semente: o argmax ou o limiar, com o t."""
    nomes = ["argmax" if u["regra"] == "argmax" else f"limiar {_decimal(u['limiar'], 2)}" for u in unidades]
    return f"{nomes[0]} nas {len(nomes)} sementes" if len(set(nomes)) == 1 and len(nomes) > 1 else "; ".join(nomes)


def _marca(texto, *comparacoes):
    """O texto com † se o limiar muda a medida em relação ao argmax e * se a configuração difere da de referência."""
    marcas = "".join(sinal for sinal, c in comparacoes if c is not None and c.get("acima"))
    return f"{texto} {marcas}" if marcas else texto


def _comparacao(m, chave, *caminho):
    valor = m["resultados"]["comparacoes"].get(chave)
    for parte in caminho:
        if not isinstance(valor, dict) or parte not in valor:
            return None
        valor = valor[parte]
    return valor


def _chave_limiar_argmax(nome):
    return f"{nome}:limiar-argmax"


def _chave_contra_referencia(m, nome):
    return f"{nome}-{_referencia(m)}:ponto"


def _por_hora(alarmes, segundos):
    return alarmes / (segundos / 3600) if segundos else None


# --- seções --------------------------------------------------------------------------------------


def _cabecalho(m):
    p = m["parametros"]
    regra = m["resultados"].get("regra")
    vencedora = _vencedora(m)
    outras = [n for n in _configuracoes(m) if n != vencedora]
    if regra is None:
        origem = f"Sem o manifesto da comparação de capturas, a configuração de referência ({vencedora}) vem primeiro."
    else:
        falham = [c for c, atende in regra["condicoes"].items() if not atende]
        origem = (
            f"Pela regra de adoção aplicada em `{RELATORIO_DAS_CAPTURAS}`, a vencedora é a configuração {vencedora}"
            + (" (as três condições são atendidas)" if regra["adotada"] else
               f" (a configuração 5 falha {'a condição' if len(falham) == 1 else 'as condições'} "
               f"{_enumerar(f'({c})' for c in falham)})")
            + f"; a configuração {_enumerar(outras)} entra para comparação."
        )
    return [
        "# Ponto de operação: regra e alarme escolhidos na validação",
        "",
        f"Gerado por `{m['gerado_por']}` em {_data(m)}, com {_versoes(m)}.",
        "",
        (
            "A decisão da equipe: a regra de decisão da janela é escolhida numa parte de validação, nunca no teste. "
            "Concorrem a categoria mais provável (argmax) e o limiar, em que a janela é ataque se 1 − P(Benign) ≥ t, "
            "na categoria de ataque mais provável, e senão é Benign. Um incidente só abre com "
            f"{p['seguidas']} janelas de ataque seguidas, na ordem do pcap. Os pontos candidatos de "
            "`rodadas_de_teste.md` (rodada g) saíram do próprio teste e não são usados aqui."
        ),
        "",
        (
            f"**Validação.** Dentro da parte de treino de cada pcap (os primeiros {_pct(1 - p['fracao_de_teste'], 0)} das "
            f"janelas), as últimas {_pct(p['fracao_de_validacao'], 0)} dessas janelas, por tempo, são a validação, e o "
            "resto é o treino reduzido. Nos rótulos com um pcap inteiro no teste, a validação são as últimas "
            f"{_pct(p['fracao_de_validacao'], 0)} de cada pcap de treino. O teste é o mesmo das rodadas. Na configuração "
            "com o fundo no treino, o fundo da validação também fica fora do treino reduzido."
        ),
        "",
        (
            "**Regra.** O modelo treinado no treino reduzido, com a mesma amostra e a mesma semente, classifica todas "
            "as janelas da validação: as dos pcaps benignos e as com o atacante dos pcaps de ataque. Os candidatos são "
            f"o argmax e os limiares de {_decimal(p['limiares'][0], 2)} a {_decimal(p['limiares'][-1], 2)}, de 0,01 em "
            f"0,01. Entre os que deixam no máximo {_pct(p['alarme_falso_maximo'], 0)} das janelas benignas da validação "
            "como ataque, vence o de maior recall de ataque na validação; no empate, o de menos benigno como ataque. "
            "O melhor limiar é o que venceria entre os limiares, e fica nas tabelas para comparação com o argmax. "
            "Nas rotações do pcap benigno de fora, cada rotação escolhe a sua regra na sua validação: a validação "
            "da rotação 0 tem janelas do pcap que a rotação 1 deixa de fora."
        ),
        "",
        (
            "**Teste.** O modelo treinado no treino inteiro, o mesmo treino do corte por tempo das rodadas, com as três "
            "regras: o argmax, o melhor limiar e o ponto de operação, que é a regra que venceu na validação da sua "
            f"semente e rotação. {origem}"
        ),
        "",
        (
            f"Cada configuração foi medida com as sementes {_enumerar(p['sementes'])}, que definem o teto e o Random "
            "Forest. Os valores são a média das sementes, com o menor e o maior entre parênteses. As diferenças são "
            "pareadas como em `rodadas_normalizadas.md`: mesma semente e mesmas janelas, com a variância por "
            f"reamostragem de blocos de {BLOCO} janelas vizinhas somada à variância entre as sementes. A diferença só "
            "conta quando o intervalo de 95% não contém o zero; senão, é \"sem diferença\". Nas tabelas, † marca a "
            "diferença entre o melhor limiar e o argmax que conta, e * a diferença para a configuração "
            f"{_referencia(m)}, as duas no ponto de operação, que conta."
        ),
    ]


def _resumo(m):
    itens = []
    for nome in _configuracoes(m):
        unidades = _unidades(m, nome)
        principal = unidades[0]
        benigno = [u["benigno_de_fora"] for u in unidades]
        piores = _pior_benigno(m, nome, "ponto")
        trechos = [u["trechos_de_ataque"] for u in unidades]
        com_alarme = [sum(1 for t in ts if t["ponto"]["alarmes"]) for ts in trechos]
        regra = "o argmax" if principal["regra"] == "argmax" else f"o limiar t = {_decimal(principal['limiar'], 2)}"
        itens.append(
            f"Configuração {nome}: na validação da semente {principal['semente']} venceu {regra} (rotação 0: "
            f"{_escolhas(unidades)}; melhor limiar {_limiares(unidades)}), com N = {principal['seguidas']}. No ponto de "
            f"operação, no corte por tempo, macro-F1 {_faixa([u['medidas']['ponto']['macro_f1'] for u in unidades])} e "
            f"benigno como ataque {_faixa([u['medidas']['ponto']['benigno_como_ataque'] for u in unidades], 2)} por "
            f"janela; no `{benigno[0]['arquivo']}` inteiro, "
            f"{_faixa([_fracao(b['ponto']['como_ataque'], b['ponto']['janelas']) for b in benigno], 2)} das janelas "
            f"como ataque, e alarmes com {SEGUIDAS} janelas seguidas, {_faixa([b['ponto']['alarmes'] for b in benigno], 1, False)} "
            f"({_faixa([_por_hora(b['ponto']['alarmes'], b['ponto']['segundos']) for b in benigno], 1, False)} por "
            "hora); pior pcap benigno de "
            f"fora (`{piores['arquivo']}`), {_faixa(piores['valores'])}; fundo virando ataque, "
            f"{_faixa([_fracao(u['fundo']['ponto']['como_ataque'], u['fundo']['ponto']['janelas']) for u in unidades])}"
            f"; pcaps de ataque com alarme no trecho de teste, {_faixa(com_alarme, 0, False)} de {len(trechos[0])}."
        )
    return ["## Resumo", "", *(f"- {item}" for item in itens)]


def _pior_benigno(m, nome, regra):
    """O pcap benigno de fora de maior fração como ataque, na média das sementes, e os valores dele."""
    candidatos = []
    for rotacao in _rotacoes(m, nome):
        unidades = _unidades(m, nome, rotacao)
        valores = [_fracao(u["benigno_de_fora"][regra]["como_ataque"], u["benigno_de_fora"][regra]["janelas"])
                   for u in unidades]
        candidatos.append({"arquivo": unidades[0]["benigno_de_fora"]["arquivo"], "rotacao": rotacao, "valores": valores})
    return max(candidatos, key=lambda c: _media(c["valores"]))


def _validacao(m):
    linhas = []
    for nome in _configuracoes(m):
        for rotacao in _rotacoes(m, nome):
            unidades = _unidades(m, nome, rotacao)
            v = [u["validacao"] for u in unidades]
            melhor = [x["curva"][str(u["melhor_limiar"])] for u, x in zip(unidades, v)]
            linhas.append([
                nome, f"{rotacao} (`{unidades[0]['benigno_de_fora']['arquivo']}` de fora)",
                _faixa([x["janelas_benignas"] for x in v], 0, False), _faixa([x["janelas_de_ataque"] for x in v], 0, False),
                _faixa([_fracao(x["argmax"]["benigno_como_ataque"], x["janelas_benignas"]) for x in v], 2),
                _faixa([_fracao(x["argmax"]["ataque_reconhecido"], x["janelas_de_ataque"]) for x in v], 2),
                _limiares(unidades),
                _faixa([_fracao(c["benigno_como_ataque"], x["janelas_benignas"]) for c, x in zip(melhor, v)], 2),
                _faixa([_fracao(c["ataque_reconhecido"], x["janelas_de_ataque"]) for c, x in zip(melhor, v)], 2),
                _escolhas(unidades),
            ])
    detalhe = []
    for nome in _configuracoes(m):
        v = [u["validacao"] for u in _unidades(m, nome)]
        recall = "; ".join(
            f"{classe} {_faixa([_fracao(x['por_categoria'][classe]['na_categoria'], x['por_categoria'][classe]['janelas']) for x in v])}"
            for classe in CLASSES if classe != BENIGNO
        )
        benignos = [sum(p["alarmes"] for p in x["por_pcap"] if p["categoria"] == BENIGNO) for x in v]
        horas = [sum(p["segundos"] for p in x["por_pcap"] if p["categoria"] == BENIGNO) / 3600 for x in v]
        ataques = [[p for p in x["por_pcap"] if p["categoria"] != BENIGNO and p["com_atacante"]] for x in v]
        com_alarme = [sum(1 for p in a if p["alarmes"]) for a in ataques]
        sem = sorted({p["arquivo"] for a in ataques for p in a if not p["alarmes"]})
        detalhe.append(
            f"- Configuração {nome}, rotação 0, na regra escolhida em cada semente: recall na validação {recall}; fundo "
            f"da validação como ataque {_faixa([_fracao(x['fundo']['como_ataque'], x['fundo']['janelas']) for x in v])}; "
            f"alarmes com {m['parametros']['seguidas']} janelas seguidas nos trechos benignos da validação "
            f"({_decimal(_media(horas), 1)} h), {_faixa(benignos, 1, False)}; pcaps de ataque com alarme no trecho de validação, "
            f"{_faixa(com_alarme, 0, False)} de {len(ataques[0])}"
            + (f" (sem alarme em alguma semente: {_enumerar(f'`{a}`' for a in sem)})." if sem else ".")
        )
    return [
        "## A regra escolhida na validação",
        "",
        (
            "Em cada configuração, rotação e semente: as janelas da validação, o que o argmax e o melhor limiar fazem "
            "com elas (benigno classificado como ataque e recall de ataque, a fração das janelas com o atacante "
            "postas em alguma categoria de ataque) e a regra que venceu. Só concorre o candidato com no máximo "
            f"{_pct(m['parametros']['alarme_falso_maximo'], 0)} das benignas como ataque."
        ),
        "",
        *_tabela(["Configuração", "Rotação", "Janelas benignas", "Janelas de ataque", "Argmax: benigno como ataque",
                  "Argmax: recall de ataque", "Melhor limiar (por semente)", "Limiar: benigno como ataque",
                  "Limiar: recall de ataque", "Regra escolhida"], linhas),
        "",
        f"Na validação da rotação 0, a regra escolhida e as {SEGUIDAS} janelas seguidas no resto da validação:",
        "",
        *detalhe,
    ]


def _medidas_do_corte():
    return [
        ("Macro-F1", "macro_f1", lambda a: a["macro_f1"]),
        ("Acurácia", "acuracia", lambda a: a["acuracia"]),
        ("Benigno classificado como ataque", "benigno_como_ataque", lambda a: a["benigno_como_ataque"]),
        ("Ataque classificado como benigno", "ataque_como_benigno", lambda a: a["ataque_como_benigno"]),
        *((f"{nome} {c}", f"{chave}_{c}", lambda a, c=c, chave=chave: a["por_classe"][c][chave])
          for nome, chave in (("Recall", "recall"), ("Precisão", "precisao"), ("F1", "f1")) for c in CLASSES),
    ]


def _corte(m):
    nomes = _configuracoes(m)
    linhas = []
    for rotulo, chave, funcao in _medidas_do_corte():
        celulas = [rotulo]
        for nome in nomes:
            unidades = _unidades(m, nome)
            for regra in REGRAS:
                texto = _faixa([funcao(u["medidas"][regra]) for u in unidades])
                if regra == "limiar":
                    texto = _marca(texto, ("†", _comparacao(m, _chave_limiar_argmax(nome), "corte", chave)))
                if regra == "ponto":
                    texto = _marca(texto, ("*", _comparacao(m, _chave_contra_referencia(m, nome), "corte", chave)))
                celulas.append(texto)
        linhas.append(celulas)
    suporte = _unidades(m, nomes[0])[0]["medidas"]["ponto"]["por_classe"]
    return [
        "## No teste: corte por tempo",
        "",
        (
            "As janelas de teste da divisão publicada (o fim de cada pcap e o pcap inteiro de fora nos rótulos de vários "
            "pcaps), com o mesmo modelo nas três regras; a coluna do ponto de operação repete a da regra que venceu na "
            "validação de cada semente. Janelas de teste por categoria, na semente principal: "
            + ", ".join(f"{c} {_milhar(suporte[c]['suporte'])}" for c in CLASSES) + "."
        ),
        "",
        *_tabela(["Medida", *(f"Configuração {n}, {NOME_DA_REGRA[r]}" for n in nomes for r in REGRAS)], linhas),
    ]


def _benigno_de_fora(m):
    linhas = []
    for nome in _configuracoes(m):
        for rotacao in _rotacoes(m, nome):
            unidades = _unidades(m, nome, rotacao)
            b = [u["benigno_de_fora"] for u in unidades]
            como_ataque = {r: [_fracao(x[r]["como_ataque"], x[r]["janelas"]) for x in b] for r in REGRAS}
            alarmes = {r: [x[r]["alarmes"] for x in b] for r in REGRAS}
            por_hora = [_por_hora(x["ponto"]["alarmes"], x["ponto"]["segundos"]) for x in b]
            linhas.append([
                nome, f"`{b[0]['arquivo']}`", _milhar(b[0]["ponto"]["janelas"]), _escolhas(unidades),
                _faixa(como_ataque["argmax"]),
                _marca(_faixa(como_ataque["limiar"]), ("†", _comparacao(m, _chave_limiar_argmax(nome), "rotacao", rotacao))),
                _marca(_faixa(como_ataque["ponto"]),
                       ("*", _comparacao(m, _chave_contra_referencia(m, nome), "rotacao", rotacao))),
                *(_faixa(alarmes[r], 1, False) for r in REGRAS), _faixa(por_hora, 1, False),
            ])
    piores = [f"configuração {nome}, `{p['arquivo']}` com {_faixa(p['valores'])}"
              for nome in _configuracoes(m) for p in [_pior_benigno(m, nome, "ponto")]]
    seguidas = m["parametros"]["seguidas"]
    return [
        "## Benigno de fora: por janela e por alarme",
        "",
        (
            "Cada pcap benigno inteiro, com o modelo da rotação que o deixa fora do treino e a regra escolhida na "
            f"validação dessa rotação: a fração das janelas classificada como ataque e os alarmes com {seguidas} janelas "
            "de ataque seguidas, na ordem do pcap, com o argmax, com o melhor limiar e no ponto de operação. A hora é a "
            "soma da duração das janelas do pcap."
        ),
        "",
        *_tabela(["Configuração", "Pcap de fora", "Janelas", "Regra escolhida", "Como ataque, argmax",
                  "Como ataque, melhor limiar", "Como ataque, ponto de operação", "Alarmes, argmax",
                  "Alarmes, melhor limiar", "Alarmes, ponto de operação", "Alarmes por hora, ponto de operação"], linhas),
        "",
        "Pior pcap benigno de fora, no ponto de operação: " + "; ".join(piores) + ".",
    ]


def _fundo(m):
    linhas = []
    for nome in _configuracoes(m):
        unidades = _unidades(m, nome)
        valores = {r: [_fracao(u["fundo"][r]["como_ataque"], u["fundo"][r]["janelas"]) for u in unidades] for r in REGRAS}
        linhas.append([
            nome, _milhar(unidades[0]["fundo"]["ponto"]["janelas"]), _faixa(valores["argmax"]),
            _marca(_faixa(valores["limiar"]), ("†", _comparacao(m, _chave_limiar_argmax(nome), "fundo"))),
            _marca(_faixa(valores["ponto"]), ("*", _comparacao(m, _chave_contra_referencia(m, nome), "fundo"))),
        ])
    return [
        "## Fundo virando ataque",
        "",
        "As janelas sem nenhum quadro do atacante na parte de teste dos pcaps de ataque, classificadas como algum ataque:",
        "",
        *_tabela(["Configuração", "Janelas de fundo no teste", "Argmax", "Melhor limiar", "Ponto de operação"], linhas),
    ]


def _trechos(m):
    seguidas = m["parametros"]["seguidas"]
    linhas, sem_alarme = [], []
    for nome in _configuracoes(m):
        unidades = _unidades(m, nome)
        for regra in REGRAS:
            trechos = [u["trechos_de_ataque"] for u in unidades]
            com = [sum(1 for t in ts if t[regra]["alarmes"]) for ts in trechos]
            janelas = [float(np.median([t[regra]["primeira_janela"] for t in ts if t[regra]["primeira_janela"]]))
                       for ts in trechos if any(t[regra]["primeira_janela"] for t in ts)]
            segundos = [[t[regra]["primeiro_segundos"] for t in ts if t[regra]["primeiro_segundos"] is not None]
                        for ts in trechos]
            linhas.append([
                nome, NOME_DA_REGRA[regra], f"{_faixa(com, 0, False)} de {len(trechos[0])}", _faixa(janelas, 0, False),
                _faixa([float(np.median(s)) for s in segundos if s], 2, False),
                _faixa([max(s) for s in segundos if s], 1, False),
            ])
            if regra == "ponto":
                faltam = sorted({t["arquivo"] for ts in trechos for t in ts if not t[regra]["alarmes"]})
                if faltam:
                    sem_alarme.append(f"configuração {nome}: {_enumerar(f'`{a}`' for a in faltam)}")
    return [
        "## Pcaps de ataque no trecho de teste",
        "",
        (
            "Em cada pcap de ataque com parte de teste, a sequência de todas as janelas do trecho de teste, com e sem o "
            "atacante, na ordem do arquivo, como o extrator as entregaria. O tempo até o alarme conta do começo do "
            f"trecho, pela soma da duração das janelas. O alarme é o de {seguidas} janelas de ataque seguidas."
        ),
        "",
        *_tabela(["Configuração", "Regra", "Pcaps com alarme", "Janelas até o primeiro alarme (mediana)",
                  "Segundos até o primeiro alarme (mediana)", "Segundos até o primeiro alarme (maior)"], linhas),
        "",
        ("Pcaps sem alarme no ponto de operação em alguma semente: " + "; ".join(sem_alarme) + "." if sem_alarme else
         "No ponto de operação, todos os pcaps de ataque com parte de teste alarmam, em todas as sementes."),
    ]


ROTULOS_DAS_DIFERENCAS = {
    "macro_f1": "macro-F1", "acuracia": "acurácia", "benigno_como_ataque": "benigno como ataque no corte por tempo",
    "ataque_como_benigno": "ataque como benigno", **{f"recall_{c}": f"recall de {c}" for c in CLASSES},
}


def _lista_de_diferencas(m, chave):
    comparacao = m["resultados"]["comparacoes"][chave]
    nome = chave.split(":")[0].split("-")[0]
    rotulos = dict(ROTULOS_DAS_DIFERENCAS)
    itens = [(rotulos[k], comparacao["corte"][k]) for k in rotulos if k in comparacao["corte"]]
    for rotacao, c in comparacao["rotacao"].items():
        arquivo = _unidades(m, nome, rotacao)[0]["benigno_de_fora"]["arquivo"]
        itens.append((f"`{arquivo}` de fora como ataque", c))
    itens.append(("fundo virando ataque", comparacao["fundo"]))
    contam = [f"{rotulo} ({_pp(c['diferenca'])} p.p., de {_pp(c['inferior'])} a {_pp(c['superior'])})"
              for rotulo, c in itens if c and c.get("acima")]
    nao = [rotulo for rotulo, c in itens if c and not c.get("acima")]
    return (_enumerar(contam) + "." if contam else "nenhuma diferença conta.") + (
        f" Sem diferença: {_enumerar(nao)}." if nao else "")


def _diferencas(m):
    linhas = []
    for nome in _configuracoes(m):
        linhas.append(f"- Configuração {nome}, melhor limiar contra argmax: "
                      f"{_lista_de_diferencas(m, _chave_limiar_argmax(nome))}")
    for nome in _configuracoes(m):
        if nome != _referencia(m):
            linhas.append(f"- Configuração {nome} contra a {_referencia(m)}, as duas no ponto de operação: "
                          f"{_lista_de_diferencas(m, _chave_contra_referencia(m, nome))}")
    return ["## Quais diferenças contam", "", "A diferença com o intervalo de 95% entre parênteses:", "", *linhas]


def _conferencia(m):
    linhas = []
    for nome in _configuracoes(m):
        conferidas = [u["conferencia"] for r in _rotacoes(m, nome) for u in _unidades(m, nome, r) if u.get("conferencia")]
        total = sum(sum(c.values()) for c in conferidas)
        unidades = sum(len(_unidades(m, nome, r)) for r in _rotacoes(m, nome))
        if conferidas:
            linhas.append(
                f"- Configuração {nome}: em {len(conferidas)} de {unidades} treinos inteiros, as predições do argmax "
                f"conferidas com as do mesmo treino guardado das rodadas (o corte por tempo, o fundo e o pcap benigno de "
                f"fora) diferem em {_milhar(total)} janelas."
            )
    if not linhas:
        return []
    return ["## Conferência", "", *linhas]


def _modelos_salvos(m):
    salvos = m["resultados"].get("modelos_salvos", {})
    if not salvos:
        return []
    regra = lambda regra_, limiar: "argmax" if regra_ == "argmax" else f"limiar {_decimal(limiar, 2)}"
    linhas = []
    for nome in _configuracoes(m):
        s = salvos.get(nome)
        if s is None:
            continue
        gravado = s["ponto_gravado"]
        linhas.append([
            nome, f"`{s['arquivo']}`", f"`{s['sha256'][:16]}…`",
            " e ".join(_milhar(s[f"diferentes_{r}"]) for r in REGRAS),
            f"{regra(s['regra_escolhida'], s['limiar_escolhido'])}, N = {s['seguidas']}",
            f"{regra(gravado['regra'], gravado['limiar'])}, N = {gravado['seguidas']}" if gravado else "sem JSON",
            "sim" if s["confere"] else "não",
        ])
    return [
        "## Os modelos salvos",
        "",
        (
            "Os modelos que `codigo.classificador.treinar_regerado` salva, com o ponto de operação num JSON ao lado, "
            "conferidos contra o treino inteiro da semente principal, no corte por tempo: o do sistema (configuração 5) "
            "e o de referência, de 10/10 (configuração 0, `--sem-fundo`). `codigo.classificador.operacao` lê o JSON, "
            "recusa o de outro modelo e aplica a regra, o argmax ou o limiar, a uma janela "
            "(`PontoDeOperacao.categoria`, `Vigia`) e a uma sequência (`PontoDeOperacao.aplicar`). A pasta `modelos/` "
            "fica fora do git."
        ),
        "",
        *_tabela(["Configuração", "Modelo", "SHA-256", "Predições diferentes do retreino (argmax, melhor limiar e ponto)",
                  "Regra escolhida aqui", "Regra no JSON", "Confere"], linhas),
    ]


def _tempo_de_treino(valor):
    if isinstance(valor, dict):
        return sum(v if k == "treino_segundos" else _tempo_de_treino(v) for k, v in valor.items())
    if isinstance(valor, list):
        return sum(_tempo_de_treino(v) for v in valor)
    return 0.0


def _como_foram_obtidos(m):
    e, p = m["entradas"], m["parametros"]
    linhas = [
        "## Como os números foram obtidos",
        "",
        f"- Comando: `{m['comando']}`, a partir da raiz do repositório.",
        (
            f"- Dados: `{e['regeracao']['destino']}/janela_{p['janela']}/`, {len(e['arquivos'])} arquivos, com o SHA-256 "
            f"de cada um em `{MANIFESTO}`; manifesto da regeração `{e['regeracao']['manifesto']}`, SHA-256 "
            f"`{e['regeracao']['sha256']}`."
        ),
    ]
    if e.get("capturas"):
        linhas.append(f"- Regra de adoção lida de `{e['capturas']['manifesto']}`, SHA-256 `{e['capturas']['sha256']}`.")
    linhas += [
        (
            f"- Treinos: `RandomForestClassifier` com {p['arvores']} árvores e os demais parâmetros padrão, teto de "
            f"{_milhar(p['teto'])} linhas por rótulo, as funções de `rodadas` e `treinar_regerado`; dois treinos por "
            "semente e rotação, o reduzido e o inteiro. Predição com um núcleo, em ordem fixa."
        ),
        f"- As tabelas em CSV começam com `{PREFIXO}_`; os valores completos, com as contagens, estão no manifesto.",
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


def montar_relatorio(m):
    """O relatório do ponto de operação, a partir do manifesto."""
    secoes = [_cabecalho(m), _resumo(m), _validacao(m), _corte(m), _benigno_de_fora(m), _fundo(m), _trechos(m),
              _diferencas(m), _conferencia(m), _modelos_salvos(m), _como_foram_obtidos(m)]
    return "\n".join("\n".join(secao) + "\n" for secao in secoes if secao).rstrip("\n") + "\n"


# --- tabelas e gravação ----------------------------------------------------------------------


def _achatar(comparacoes, caminho=()):
    if isinstance(comparacoes, dict) and "acima" in comparacoes:
        yield caminho, comparacoes
    elif isinstance(comparacoes, dict):
        for chave, valor in comparacoes.items():
            yield from _achatar(valor, (*caminho, str(chave)))


def gravar(manifesto, pasta):
    """Grava o manifesto e o que sai dele: o relatório e as tabelas."""
    pasta = Path(pasta)
    pasta.mkdir(parents=True, exist_ok=True)
    (pasta / MANIFESTO).write_text(json.dumps(manifesto, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    (pasta / RELATORIO).write_text(montar_relatorio(manifesto), encoding="utf-8")
    configuracoes = manifesto["resultados"]["configuracoes"]
    limiar, curva, teste, benigno, trechos = [], [], [], [], []
    for nome, c in configuracoes.items():
        for rotacao, por_semente in c["resultados"].items():
            for semente, u in por_semente.items():
                v = u["validacao"]
                melhor = v["curva"][str(u["melhor_limiar"])]
                limiar.append([nome, rotacao, semente, u["regra"], _campo(u["limiar"]), _campo(u["melhor_limiar"]),
                               v["janelas_benignas"], v["janelas_de_ataque"], v["argmax"]["benigno_como_ataque"],
                               v["argmax"]["ataque_reconhecido"], melhor["benigno_como_ataque"], melhor["ataque_reconhecido"]])
                curva += [[nome, rotacao, semente, t_, c["benigno_como_ataque"], c["ataque_reconhecido"],
                           v["janelas_benignas"], v["janelas_de_ataque"]] for t_, c in v["curva"].items()]
                b = u["benigno_de_fora"]
                benigno += [[nome, rotacao, semente, b["arquivo"], regra, b[regra]["janelas"], b[regra]["como_ataque"],
                             b[regra]["alarmes"], _campo(b[regra]["segundos"])] for regra in REGRAS]
                if "medidas" not in u:
                    continue
                for regra in REGRAS:
                    a = u["medidas"][regra]
                    teste += [[nome, semente, regra, chave, "", _campo(a[chave])]
                              for chave in ("macro_f1", "acuracia", "f1_ponderado", "benigno_como_ataque",
                                            "ataque_como_benigno")]
                    teste += [[nome, semente, regra, chave, classe, _campo(medida[chave])]
                              for classe, medida in a["por_classe"].items() for chave in ("precisao", "recall", "f1", "suporte")]
                    trechos += [[nome, semente, regra, t["arquivo"], t["categoria"], t[regra]["janelas"], t["com_atacante"],
                                 t[regra]["como_ataque"], t[regra]["alarmes"], t[regra]["primeira_janela"] or "",
                                 _campo(t[regra]["primeiro_segundos"])] for t in u["trechos_de_ataque"]]
                    teste.append([nome, semente, regra, "fundo_como_ataque", "",
                                  _campo(_fracao(u["fundo"][regra]["como_ataque"], u["fundo"][regra]["janelas"]))])
    _gravar_csv(pasta / f"{PREFIXO}_limiar.csv",
                ["configuracao", "rotacao", "semente", "regra", "limiar", "melhor_limiar", "janelas_benignas_validacao",
                 "janelas_de_ataque_validacao", "argmax_benigno_como_ataque", "argmax_ataque_reconhecido",
                 "limiar_benigno_como_ataque", "limiar_ataque_reconhecido"], limiar)
    _gravar_csv(pasta / f"{PREFIXO}_curva.csv", ["configuracao", "rotacao", "semente", "limiar", "benigno_como_ataque",
                                                 "ataque_reconhecido", "janelas_benignas_validacao",
                                                 "janelas_de_ataque_validacao"], curva)
    _gravar_csv(pasta / f"{PREFIXO}_teste.csv", ["configuracao", "semente", "regra", "medida", "classe", "valor"], teste)
    _gravar_csv(pasta / f"{PREFIXO}_benigno.csv", ["configuracao", "rotacao", "semente", "arquivo", "regra", "janelas",
                                                   "como_ataque", "alarmes", "segundos"], benigno)
    _gravar_csv(pasta / f"{PREFIXO}_trechos.csv", ["configuracao", "semente", "regra", "arquivo", "categoria", "janelas",
                                                   "com_atacante", "como_ataque", "alarmes", "primeira_janela",
                                                   "primeiro_segundos"], trechos)
    _gravar_csv(
        pasta / f"{PREFIXO}_diferencas.csv", ["comparacao", "medida", "diferenca", "inferior", "superior", "conta"],
        [[chave, "/".join(caminho), _campo(c["diferenca"]), _campo(c["inferior"]), _campo(c["superior"]), int(c["acima"])]
         for chave, comparacoes in manifesto["resultados"]["comparacoes"].items() for caminho, c in _achatar(comparacoes)],
    )
