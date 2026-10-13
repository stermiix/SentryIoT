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

REGRAS = ("argmax", "limiar")
NOME_DA_REGRA = {"argmax": "argmax (hoje)", "limiar": "limiar"}


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
    return "; ".join(_decimal(u["limiar"], 2) for u in unidades)


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
    return f"{nome}-{_referencia(m)}:limiar"


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
        "# Ponto de operação: limiar e alarme escolhidos na validação",
        "",
        f"Gerado por `{m['gerado_por']}` em {_data(m)}, com {_versoes(m)}.",
        "",
        (
            "A decisão da equipe: o limiar e a regra de janelas seguidas são escolhidos numa parte de validação, nunca "
            "no teste. A regra: a janela é ataque se 1 − P(Benign) ≥ t, na categoria de ataque mais provável; senão, é "
            f"Benign. Um incidente só abre com {p['seguidas']} janelas de ataque seguidas, na ordem do pcap. Os pontos "
            "candidatos de `rodadas_de_teste.md` (rodada g) saíram do próprio teste e não são usados aqui."
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
            "**Limiar.** O modelo treinado no treino reduzido, com a mesma amostra e a mesma semente, classifica todas "
            f"as janelas da validação. O limiar t é o menor da grade de {_decimal(p['limiares'][0], 2)} a "
            f"{_decimal(p['limiares'][-1], 2)}, de 0,01 em 0,01, que deixa no máximo "
            f"{_pct(p['alarme_falso_maximo'], 0)} das janelas dos pcaps benignos da validação como ataque. Nas rotações do "
            "pcap benigno de fora, cada rotação escolhe o seu t na sua validação: a validação da rotação 0 tem janelas "
            "do pcap que a rotação 1 deixa de fora."
        ),
        "",
        (
            "**Teste.** O modelo treinado no treino inteiro, o mesmo treino do corte por tempo das rodadas, com o t da "
            "sua semente e rotação. As colunas \"argmax\" são o mesmo modelo com a categoria mais provável, a regra de "
            f"hoje. {origem}"
        ),
        "",
        (
            f"Cada configuração foi medida com as sementes {_enumerar(p['sementes'])}, que definem o teto e o Random "
            "Forest. Os valores são a média das sementes, com o menor e o maior entre parênteses. As diferenças são "
            "pareadas como em `rodadas_normalizadas.md`: mesma semente e mesmas janelas, com a variância por "
            f"reamostragem de blocos de {BLOCO} janelas vizinhas somada à variância entre as sementes. A diferença só "
            "conta quando o intervalo de 95% não contém o zero; senão, é \"sem diferença\". Nas tabelas, † marca a "
            "diferença entre o limiar e o argmax que conta, e * a diferença para a configuração "
            f"{_referencia(m)} no limiar que conta."
        ),
    ]


def _resumo(m):
    itens = []
    for nome in _configuracoes(m):
        unidades = _unidades(m, nome)
        principal = unidades[0]
        benigno = [u["benigno_de_fora"] for u in unidades]
        piores = _pior_benigno(m, nome, "limiar")
        trechos = [u["trechos_de_ataque"] for u in unidades]
        com_alarme = [sum(1 for t in ts if t["limiar"]["alarmes"]) for ts in trechos]
        itens.append(
            f"Configuração {nome}: t = {_decimal(principal['limiar'], 2)} na semente {principal['semente']} "
            f"({_limiares(unidades)} nas sementes {_enumerar(_sementes(m))}), N = {principal['seguidas']}. No corte por "
            f"tempo, macro-F1 {_faixa([u['medidas']['limiar']['macro_f1'] for u in unidades])} e benigno como ataque "
            f"{_faixa([u['medidas']['limiar']['benigno_como_ataque'] for u in unidades], 2)} por janela; no "
            f"`{benigno[0]['arquivo']}` inteiro, "
            f"{_faixa([_fracao(b['limiar']['como_ataque'], b['limiar']['janelas']) for b in benigno], 2)} das janelas "
            f"como ataque e {_faixa([b['limiar']['alarmes'] for b in benigno], 1, False)} alarmes "
            f"({_faixa([_por_hora(b['limiar']['alarmes'], b['limiar']['segundos']) for b in benigno], 1, False)} por "
            "hora); pior pcap benigno de "
            f"fora (`{piores['arquivo']}`), {_faixa(piores['valores'])}; fundo virando ataque, "
            f"{_faixa([_fracao(u['fundo']['limiar']['como_ataque'], u['fundo']['limiar']['janelas']) for u in unidades])}"
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
            linhas.append([
                nome, f"{rotacao} (`{unidades[0]['benigno_de_fora']['arquivo']}` de fora)",
                _faixa([x["janelas_benignas"] for x in v], 0, False),
                _limiares(unidades),
                _faixa([_fracao(x["benigno_como_ataque"][str(x["limiar"])], x["janelas_benignas"]) for x in v], 2),
                _faixa([_fracao(x["benigno_argmax"], x["janelas_benignas"]) for x in v], 2),
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
            f"- Configuração {nome}, rotação 0, no t de cada semente: recall na validação {recall}; fundo da validação "
            f"como ataque {_faixa([_fracao(x['fundo']['como_ataque'], x['fundo']['janelas']) for x in v])}; nos trechos "
            f"benignos da validação ({_decimal(_media(horas), 1)} h), {_faixa(benignos, 1, False)} alarmes com "
            f"{m['parametros']['seguidas']} janelas seguidas; pcaps de ataque com alarme no trecho de validação, "
            f"{_faixa(com_alarme, 0, False)} de {len(ataques[0])}"
            + (f" (sem alarme em alguma semente: {_enumerar(f'`{a}`' for a in sem)})." if sem else ".")
        )
    return [
        "## O limiar escolhido na validação",
        "",
        (
            "Em cada configuração, rotação e semente: as janelas dos pcaps benignos na validação, o t escolhido em cada "
            "semente, a fração dessas janelas que o t deixa como ataque e a que o argmax deixaria."
        ),
        "",
        *_tabela(["Configuração", "Rotação", "Janelas benignas na validação", "t (por semente)",
                  "Benigno da validação como ataque, no t", "Com o argmax"], linhas),
        "",
        "Na validação da rotação 0, a regra inteira (o t e as 3 janelas seguidas) no resto da validação:",
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
            for regra in ("argmax", "limiar"):
                texto = _faixa([funcao(u["medidas"][regra]) for u in unidades])
                if regra == "limiar":
                    texto = _marca(texto, ("†", _comparacao(m, _chave_limiar_argmax(nome), "corte", chave)),
                                   ("*", _comparacao(m, _chave_contra_referencia(m, nome), "corte", chave)))
                celulas.append(texto)
        linhas.append(celulas)
    suporte = _unidades(m, nomes[0])[0]["medidas"]["limiar"]["por_classe"]
    return [
        "## No teste: corte por tempo",
        "",
        (
            "As janelas de teste da divisão publicada (o fim de cada pcap e o pcap inteiro de fora nos rótulos de vários "
            "pcaps), com o mesmo modelo nas duas regras. Janelas de teste por categoria, na semente principal: "
            + ", ".join(f"{c} {_milhar(suporte[c]['suporte'])}" for c in CLASSES) + "."
        ),
        "",
        *_tabela(["Medida", *(f"Configuração {n}, {NOME_DA_REGRA[r]}" for n in nomes for r in ("argmax", "limiar"))],
                 linhas),
    ]


def _benigno_de_fora(m):
    linhas = []
    for nome in _configuracoes(m):
        for rotacao in _rotacoes(m, nome):
            unidades = _unidades(m, nome, rotacao)
            b = [u["benigno_de_fora"] for u in unidades]
            como_ataque = {r: [_fracao(x[r]["como_ataque"], x[r]["janelas"]) for x in b] for r in ("argmax", "limiar")}
            alarmes = {r: [x[r]["alarmes"] for x in b] for r in ("argmax", "limiar")}
            por_hora = [_por_hora(x["limiar"]["alarmes"], x["limiar"]["segundos"]) for x in b]
            linhas.append([
                nome, f"`{b[0]['arquivo']}`", _milhar(b[0]["limiar"]["janelas"]), _limiares(unidades),
                _faixa(como_ataque["argmax"]),
                _marca(_faixa(como_ataque["limiar"]),
                       ("†", _comparacao(m, _chave_limiar_argmax(nome), "rotacao", rotacao)),
                       ("*", _comparacao(m, _chave_contra_referencia(m, nome), "rotacao", rotacao))),
                _faixa(alarmes["argmax"], 1, False), _faixa(alarmes["limiar"], 1, False), _faixa(por_hora, 1, False),
            ])
    piores = [f"configuração {nome}, `{p['arquivo']}` com {_faixa(p['valores'])}"
              for nome in _configuracoes(m) for p in [_pior_benigno(m, nome, "limiar")]]
    seguidas = m["parametros"]["seguidas"]
    return [
        "## Benigno de fora: por janela e por alarme",
        "",
        (
            "Cada pcap benigno inteiro, com o modelo da rotação que o deixa fora do treino e o t escolhido na validação "
            f"dessa rotação: a fração das janelas classificada como ataque e os alarmes com {seguidas} janelas de ataque "
            "seguidas, na ordem do pcap. A hora é a soma da duração das janelas do pcap."
        ),
        "",
        *_tabela(["Configuração", "Pcap de fora", "Janelas", "t (por semente)", "Como ataque, argmax", "Como ataque, limiar",
                  f"Alarmes com {seguidas} seguidas, argmax", f"Alarmes com {seguidas} seguidas, limiar",
                  "Alarmes por hora, limiar"], linhas),
        "",
        "Pior pcap benigno de fora, no limiar: " + "; ".join(piores) + ".",
    ]


def _fundo(m):
    linhas = []
    for nome in _configuracoes(m):
        unidades = _unidades(m, nome)
        valores = {r: [_fracao(u["fundo"][r]["como_ataque"], u["fundo"][r]["janelas"]) for u in unidades]
                   for r in ("argmax", "limiar")}
        linhas.append([
            nome, _milhar(unidades[0]["fundo"]["limiar"]["janelas"]), _faixa(valores["argmax"]),
            _marca(_faixa(valores["limiar"]), ("†", _comparacao(m, _chave_limiar_argmax(nome), "fundo")),
                   ("*", _comparacao(m, _chave_contra_referencia(m, nome), "fundo"))),
        ])
    return [
        "## Fundo virando ataque",
        "",
        "As janelas sem nenhum quadro do atacante na parte de teste dos pcaps de ataque, classificadas como algum ataque:",
        "",
        *_tabela(["Configuração", "Janelas de fundo no teste", "Argmax", "Limiar"], linhas),
    ]


def _trechos(m):
    seguidas = m["parametros"]["seguidas"]
    linhas, sem_alarme = [], []
    for nome in _configuracoes(m):
        unidades = _unidades(m, nome)
        for regra in ("argmax", "limiar"):
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
            if regra == "limiar":
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
        ("Pcaps sem alarme no limiar em alguma semente: " + "; ".join(sem_alarme) + "." if sem_alarme else
         "No limiar, todos os pcaps de ataque com parte de teste alarmam, em todas as sementes."),
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
        linhas.append(f"- Configuração {nome}, limiar contra argmax: {_lista_de_diferencas(m, _chave_limiar_argmax(nome))}")
    for nome in _configuracoes(m):
        if nome != _referencia(m):
            linhas.append(f"- Configuração {nome} contra a {_referencia(m)}, as duas no limiar: "
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
    linhas = []
    for nome in _configuracoes(m):
        s = salvos.get(nome)
        if s is None:
            continue
        gravado = s["ponto_gravado"]
        linhas.append([
            nome, f"`{s['arquivo']}`", f"`{s['sha256'][:16]}…`",
            f"{_milhar(s['diferentes_argmax'])} e {_milhar(s['diferentes_limiar'])}",
            f"{_decimal(s['limiar_escolhido'], 2)} e {s['seguidas']}",
            f"{_decimal(gravado['limiar'], 2)} e {gravado['seguidas']}" if gravado else "sem JSON",
            "sim" if s["confere"] else "não",
        ])
    return [
        "## Os modelos salvos",
        "",
        (
            "Os modelos que `codigo.classificador.treinar_regerado` salva, com o ponto de operação num JSON ao lado, "
            "conferidos contra o treino inteiro da semente principal, no corte por tempo: o do sistema (configuração 5) "
            "e o de referência, de 10/10 (configuração 0, `--sem-fundo`). `codigo.classificador.operacao` lê o JSON, "
            "recusa o de outro modelo e aplica a regra a uma janela (`PontoDeOperacao.categoria`, `Vigia`) e a uma "
            "sequência (`PontoDeOperacao.aplicar`). A pasta `modelos/` fica fora do git."
        ),
        "",
        *_tabela(["Configuração", "Modelo", "SHA-256", "Predições diferentes do retreino (argmax e limiar)",
                  "t e N escolhidos aqui", "t e N no JSON", "Confere"], linhas),
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
                limiar.append([nome, rotacao, semente, _campo(u["limiar"]), v["janelas_benignas"],
                               v["benigno_como_ataque"][str(u["limiar"])], v["benigno_argmax"]])
                curva += [[nome, rotacao, semente, t, n, v["janelas_benignas"]] for t, n in v["benigno_como_ataque"].items()]
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
    _gravar_csv(pasta / f"{PREFIXO}_limiar.csv", ["configuracao", "rotacao", "semente", "limiar", "janelas_benignas_validacao",
                                                  "como_ataque_no_limiar", "como_ataque_no_argmax"], limiar)
    _gravar_csv(pasta / f"{PREFIXO}_curva.csv", ["configuracao", "rotacao", "semente", "limiar", "como_ataque",
                                                 "janelas_benignas_validacao"], curva)
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
