"""O executor dos experimentos ponta a ponta dos agentes.

Para cada incidente do conjunto, em cada configuração (tudo local, tudo na nuvem, híbrida) e em cada
repetição, roda o orquestrador (`codigo/agente/agentes.py`) com o aprovador automático
(`codigo/agente/aprovador.py`) e mede o que a decisão de 25/10/2026 pede:

- a qualidade da recomendação: se a ação proposta é aceitável no alvo certo pelo gabarito. Cada proposta é
  conferida com `conferir_proposta`, inclusive as de risco baixo, que não passam pelo aprovador;
- o acerto da triagem, ao lado: `coerente` num incidente verdadeiro, `duvidoso` ou `ruido` num falso. Um
  incidente é verdadeiro pela mesma regra de `codigo/reprodutor/limiar.py`: o pcap não é benigno, alguma
  janela do incidente tem quadro de um atacante do dataset e a categoria do incidente é a do pcap;
- tokens, custo e tempo por agente, e o tempo até a remediação em duas partes: a detecção (da primeira
  janela de ataque à abertura do incidente, vinda do reprodutor) e os agentes (da abertura ao fim da
  execução, sem o tempo de uma pessoa aprovar: o aprovador automático decide na hora);
- as propostas aprovadas, rejeitadas e novas.

O trabalho é em três comandos, a partir da raiz do repositório (o `preparar` abaixo é o conjunto fixado, ver
"O conjunto dos experimentos"):

    python -m codigo.agente.experimento preparar \\
        CICIoT2023/DDoS-SYN_Flood1.pcap CICIoT2023/DDoS-UDP_Flood.pcap CICIoT2023/DDoS-HTTP_Flood-.pcap \\
        CICIoT2023/Recon-PortScan.pcap CICIoT2023/Recon-OSScan.pcap CICIoT2023/Recon-HostDiscovery.pcap \\
        CICIoT2023/DictionaryBruteForce.pcap CICIoT2023/BenignTraffic2.pcap \\
        --por-pcap 4 --saida dados/processed/agentes
    python -m codigo.agente.experimento rodar --conjunto dados/processed/agentes/conjunto.json \\
        --configuracoes local hibrida nuvem --repeticoes 3 --saida dados/processed/agentes
    python -m codigo.agente.experimento consolidar --rodadas dados/processed/agentes/rodadas \\
        --saida experimentos/resultados

O conjunto dos experimentos, fixado antes da primeira rodada, como o gabarito, para não ser ajustado depois de
ver os resultados. Os cenários são os do artigo (seção 3.6), DDoS, varredura de portas (Recon) e força bruta
(BruteForce), e as regras são estas:

- só entra pcap com um trecho fora do treino do modelo do sistema, porque o `preparar` reproduz só esse trecho:
  nenhuma janela dele foi vista no treino. `DDoS-SYN_Flood.pcap`, que ficou inteiro no treino, e
  `Recon-PingSweep.pcap`, com 68 janelas de teste, ficam de fora;
- DDoS: três técnicas diferentes, com três pcaps, o SYN flood (`DDoS-SYN_Flood1.pcap`, inteiro fora do treino), o
  UDP flood e o HTTP flood, que é de aplicação. Recon: a varredura de portas (`Recon-PortScan.pcap`) e mais dois
  pcaps da categoria, `Recon-OSScan.pcap` e `Recon-HostDiscovery.pcap`. BruteForce: o único pcap da categoria,
  `DictionaryBruteForce.pcap`;
- `BenignTraffic2.pcap`, o pcap benigno inteiro fora do treino, entra para haver alarme falso de verdade, em que a
  triagem deve dizer `duvidoso` ou `ruido`. Os incidentes de categoria errada dos pcaps de ataque também são falsos
  (`reprodutor/limiar.py`) e já vêm no conjunto, sem escolha;
- de cada pcap entram os primeiros 4 incidentes, na ordem em que abriram (`--por-pcap 4`): sem escolher incidente
  a incidente, para ninguém poder escolher os que dão certo. São no máximo 29 incidentes (4 em cada um dos sete
  pcaps de ataque e o do benigno, que só tem 1), perto dos cerca de 30 previstos e, com 3 configurações e 3
  repetições, perto das 270 rodadas. O que o `preparar` imprime diz quantos entraram de fato;
- se entrarem menos de 27, sobe-se `--por-pcap` para 5, com a mesma lista de pcaps e sem olhar nenhum resultado dos
  agentes. A lista de pcaps não muda depois disso.

`preparar` reproduz cada pcap (só o trecho fora do treino, como `python -m codigo.reprodutor --so-teste`),
grava o log e os cenários de cada um e anota os IPs dos atacantes do dataset, que o aprovador e a conferência
usam. `rodar` guarda um JSON por rodada e retoma de onde parou: a rodada que já terminou, sem erro, não
repete, o que importa numa conta paga. `consolidar` junta os JSON em `avaliacao_agentes.csv` e
`custo_latencia.csv`. Os experimentos rodam em Linux ou em macOS, ou em sequência: sem `fcntl` (Windows), duas
rodadas ao mesmo tempo sobre um log não são seguras. Aqui cada rodada tem o log só dela, e elas rodam em fila.

Fica de fora desta versão a rodada com a marca de "já resolvido" (a explicação, sem ação), que o artigo também
compara no tempo.
"""

import argparse
import csv
import datetime
import json
import os
import shutil
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from codigo.agente.__main__ import perfis_da_configuracao
from codigo.agente.agentes import CONFIGURACOES, MAXIMO_DE_RODADAS, orquestrar
from codigo.agente.aprovador import (
    AprovadorPorGabarito,
    carregar_gabarito,
    conferir_proposta,
)
from codigo.agente.cliente_mcp import ErroDoServidor
from codigo.api.configuracao import carregar_env
from codigo.api.provedor import ErroDoProvedor
from codigo.classificador.atacantes import rotulo_do_pcap
from codigo.classificador.mapeamento import CATEGORIA_DO_ROTULO
from codigo.mcp.acoes import PedidoRecusado, reconstruir
from codigo.mcp.eventos import ler
from codigo.mcp.tipos import endereco_canonico
from codigo.reprodutor import avaliar
from codigo.reprodutor import reprodutor as R

RAIZ = Path(__file__).resolve().parents[2]
CONJUNTO = "conjunto.json"
PASTA_DAS_RODADAS = "rodadas"
AVALIACAO = "avaliacao_agentes.csv"
CUSTO = "custo_latencia.csv"
COERENTE = "coerente"
# O rótulo que a triagem dá ao incidente falso.
DE_FALSO = ("duvidoso", "ruido")
ERRO = "erro"

COLUNAS_DA_AVALIACAO = (
    "pcap", "incidente", "categoria", "categoria_do_pcap", "verdadeiro", "configuracao", "repeticao", "desfecho",
    "triagem_rotulo", "triagem_correta", "n_propostas", "n_aceitaveis", "primeira_aceitavel", "acao_primeira",
    "papel_primeiro", "n_aprovadas", "n_rejeitadas", "n_baixo_risco", "n_novas",
)
COLUNAS_DO_CUSTO = (
    "pcap", "incidente", "configuracao", "repeticao", "agente", "onde", "chamadas", "tokens_entrada",
    "tokens_saida", "llm_s", "agentes_s", "deteccao_s", "custo_usd",
)
# Os erros que uma rodada pode dar sem que o resto do experimento deva parar.
_ERROS_DA_RODADA = (ErroDoProvedor, ErroDoServidor, PedidoRecusado, OSError, ValueError)


@dataclass(frozen=True)
class ItemDoConjunto:
    """Um incidente do experimento: o que ele é, a verdade de campo e onde estão o log e os cenários dele."""

    pcap: str
    incidente: str
    categoria: str
    categoria_do_pcap: str
    verdadeiro: bool
    confianca: float
    deteccao_s: float
    atacantes: tuple[str, ...]
    log: str
    cenarios: str | None = None


# --- preparar --------------------------------------------------------------------------------


def preparar_pcap(pcap, pasta, classificador, *, a_partir_da_janela=0, por_pcap=None, categoria_do_pcap=None):
    """Reproduz um pcap, grava o log e os cenários dele em `pasta` e devolve os itens do conjunto.

    `categoria_do_pcap` é lida do nome do arquivo (`DDoS-UDP_Flood1.pcap`); passe-a para uma captura que o
    nome do dataset não descreve. Num pcap benigno, todo incidente é falso. `por_pcap` limita os incidentes
    aos primeiros, na ordem em que abriram.
    """
    pcap, pasta = Path(pcap), Path(pasta)
    if categoria_do_pcap is None:
        categoria_do_pcap = CATEGORIA_DO_ROTULO[rotulo_do_pcap(pcap.name)]
    pasta.mkdir(parents=True, exist_ok=True)
    log = pasta / f"{pcap.stem}.jsonl"
    # O log é nosso e recomeça do zero: a numeração dos incidentes continuaria a de um anterior.
    for velho in (log, R.caminho_dos_cenarios(log)):
        velho.unlink(missing_ok=True)
    reproducao, verdade, ips = avaliar.reproduzir_com_verdade(pcap, classificador, a_partir_da_janela=a_partir_da_janela)
    cenarios, _ = R.gravar(reproducao, classificador, log)
    atacantes = tuple(sorted(ips))
    itens = []
    for cenario, incidente in zip(cenarios, reproducao.incidentes, strict=True):
        dados = cenario.incidente
        com_atacante = sum(1 for janela in incidente.ataque if verdade[janela.indice][0] > 0)
        itens.append(ItemDoConjunto(
            pcap=pcap.name, incidente=dados.id, categoria=dados.categoria, categoria_do_pcap=categoria_do_pcap,
            verdadeiro=categoria_do_pcap != "Benign" and com_atacante > 0 and dados.categoria == categoria_do_pcap,
            confianca=dados.confianca, deteccao_s=round(incidente.aberto_em - incidente.primeira_janela_de_ataque, 3),
            atacantes=atacantes, log=log.name, cenarios=R.caminho_dos_cenarios(log).name,
        ))
    return itens[:por_pcap]


def gravar_conjunto(itens, pasta):
    """Grava `conjunto.json` em `pasta`, com os caminhos do log e dos cenários relativos a ele."""
    caminho = Path(pasta) / CONJUNTO
    corpo = {
        "gerado_em": datetime.datetime.now(tz=datetime.UTC).astimezone().isoformat(timespec="seconds"),
        "itens": [asdict(item) for item in itens],
    }
    caminho.write_text(json.dumps(corpo, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return caminho


def ler_conjunto(caminho):
    """Os itens de um `conjunto.json`, com o log e os cenários já resolvidos a partir da pasta dele."""
    caminho = Path(caminho)
    itens = []
    for bruto in json.loads(caminho.read_text(encoding="utf-8"))["itens"]:
        bruto = {**bruto, "atacantes": tuple(bruto["atacantes"])}
        bruto["log"] = str(caminho.parent / bruto["log"])
        if bruto.get("cenarios"):
            bruto["cenarios"] = str(caminho.parent / bruto["cenarios"])
        itens.append(ItemDoConjunto(**bruto))
    return itens


# --- rodar -----------------------------------------------------------------------------------


def id_da_rodada(item, configuracao, repeticao):
    return f"{Path(item.pcap).stem}-{item.incidente}-{configuracao}-r{repeticao}"


def rodar_item(
    item, configuracao, repeticao, *, perfis, pasta_das_rodadas, gabarito=None, executar=orquestrar,
    maximo_de_rodadas=MAXIMO_DE_RODADAS, **limites_do_laco,
):
    """Roda um incidente numa configuração e devolve o resultado medido, que também fica em JSON.

    A rodada tem um log só dela, copiado do log do incidente. Se o JSON dela já existe e não é de erro, é
    devolvido sem rodar de novo. Um erro do provedor, do servidor ou do log não derruba o experimento: a
    rodada fica com desfecho `erro` e roda de novo na próxima vez.
    """
    pasta = Path(pasta_das_rodadas)
    pasta.mkdir(parents=True, exist_ok=True)
    identificador = id_da_rodada(item, configuracao, repeticao)
    resultado = pasta / f"{identificador}.json"
    if resultado.exists():
        anterior = json.loads(resultado.read_text(encoding="utf-8"))
        if anterior["desfecho"] != ERRO:
            return anterior
    gabarito = gabarito if gabarito is not None else carregar_gabarito()
    log = pasta / f"{identificador}.jsonl"
    shutil.copyfile(item.log, log)
    aprovador = AprovadorPorGabarito(log, item.atacantes, gabarito)
    no_aprovador = [0.0]

    def aprovar(estado, pendentes):
        comeco = time.perf_counter()
        try:
            aprovador(estado, pendentes)
        finally:
            no_aprovador[0] += time.perf_counter() - comeco

    erro = None
    desfecho = ERRO
    inicio = time.perf_counter()
    try:
        orquestrado = executar(
            item.incidente, log=log, cenarios=item.cenarios, perfis=perfis, configuracao=configuracao,
            aprovador=aprovar, maximo_de_rodadas=maximo_de_rodadas, espera_da_aprovacao_s=0, **limites_do_laco,
        )
        desfecho = orquestrado.desfecho
    except _ERROS_DA_RODADA as excecao:
        erro = f"{type(excecao).__name__}: {excecao}"[:300]
    agentes_s = time.perf_counter() - inicio - no_aprovador[0]
    medida = medir(item, configuracao, repeticao, identificador, log, aprovador, gabarito, desfecho, erro, agentes_s)
    resultado.write_text(json.dumps(medida, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return medida


def medir(item, configuracao, repeticao, identificador, log, aprovador, gabarito, desfecho, erro, agentes_s):
    """O que a rodada deixou no log, em números: triagem, propostas conferidas, tokens e tempo."""
    eventos = list(ler(log))
    estado = reconstruir(eventos)
    atacantes = frozenset(endereco_canonico(a) for a in item.atacantes)
    por_agente = {}
    rotulo = None
    for evento in eventos:
        if evento.incidente != item.incidente:
            continue
        if evento.tipo == "llm_chamada":
            dados = evento.dados
            linha = por_agente.setdefault(dados.agente, _linha_do_agente(dados.agente, dados.onde))
            linha["chamadas"] += 1
            linha["tokens_entrada"] += dados.tokens_entrada
            linha["tokens_saida"] += dados.tokens_saida
            linha["llm_s"] += dados.duracao_ms / 1000
        elif evento.tipo == "agente_concluido" and evento.dados.agente == "triagem":
            rotulo = evento.dados.veredito
    propostas = [p for p in estado.propostas.values() if p.incidente == item.incidente]
    conferencias = [conferir_proposta(p, estado.incidentes[item.incidente], atacantes, gabarito) for p in propostas]
    decisoes = [d for d in aprovador.decisoes if d.incidente == item.incidente]
    primeira = conferencias[0] if conferencias else None
    return {
        "rodada": identificador, **{k: v for k, v in asdict(item).items() if k in _DO_ITEM},
        "configuracao": configuracao, "repeticao": repeticao, "desfecho": desfecho, "erro": erro,
        "triagem_rotulo": rotulo, "triagem_correta": _triagem_correta(item.verdadeiro, rotulo),
        "n_propostas": len(propostas), "n_aceitaveis": sum(c.aceitavel for c in conferencias),
        # Num incidente falso, nenhuma ação é aceitável, qualquer que seja o gabarito.
        "primeira_aceitavel": bool(primeira and primeira.aceitavel and item.verdadeiro),
        "acao_primeira": propostas[0].acao if propostas else None, "papel_primeiro": primeira.papel if primeira else None,
        "n_aprovadas": sum(d.conferencia.aceitavel for d in decisoes),
        "n_rejeitadas": sum(not d.conferencia.aceitavel for d in decisoes),
        "n_baixo_risco": len(propostas) - len(decisoes), "n_novas": sum(p.nova for p in propostas),
        "agentes_s": round(agentes_s, 3),
        "por_agente": [{**linha, "llm_s": round(linha["llm_s"], 3)} for linha in por_agente.values()],
    }


_DO_ITEM = ("pcap", "incidente", "categoria", "categoria_do_pcap", "verdadeiro", "confianca", "deteccao_s")


def _linha_do_agente(agente, onde):
    return {"agente": agente, "onde": onde, "chamadas": 0, "tokens_entrada": 0, "tokens_saida": 0, "llm_s": 0.0}


def _triagem_correta(verdadeiro, rotulo):
    """Se o rótulo da triagem acerta o incidente. Sem rótulo, a triagem não acertou."""
    return rotulo == COERENTE if verdadeiro else rotulo in DE_FALSO


# --- consolidar ------------------------------------------------------------------------------


def ler_rodadas(pasta):
    return [json.loads(caminho.read_text(encoding="utf-8")) for caminho in sorted(Path(pasta).glob("*.json"))]


def custo_em_dolar(linha, preco_entrada, preco_saida):
    """O custo de um agente que rodou na nuvem, com os preços em dólares por milhão de tokens. Local não custa."""
    if linha["onde"] != "nuvem" or preco_entrada is None or preco_saida is None:
        return None
    return round((linha["tokens_entrada"] * preco_entrada + linha["tokens_saida"] * preco_saida) / 1_000_000, 6)


def consolidar(pasta_das_rodadas, saida, *, preco_entrada=None, preco_saida=None):
    """Junta os JSON das rodadas em `avaliacao_agentes.csv` e `custo_latencia.csv`. Devolve as rodadas lidas."""
    rodadas = ler_rodadas(pasta_das_rodadas)
    saida = Path(saida)
    saida.mkdir(parents=True, exist_ok=True)
    with open(saida / AVALIACAO, "w", encoding="utf-8", newline="") as arquivo:
        escritor = csv.DictWriter(arquivo, fieldnames=COLUNAS_DA_AVALIACAO, extrasaction="ignore")
        escritor.writeheader()
        escritor.writerows(rodadas)
    with open(saida / CUSTO, "w", encoding="utf-8", newline="") as arquivo:
        escritor = csv.DictWriter(arquivo, fieldnames=COLUNAS_DO_CUSTO)
        escritor.writeheader()
        for r in rodadas:
            base = {k: r[k] for k in ("pcap", "incidente", "configuracao", "repeticao")}
            for linha in r["por_agente"]:
                escritor.writerow({
                    **base, **{k: linha[k] for k in ("agente", "onde", "chamadas", "tokens_entrada", "tokens_saida", "llm_s")},
                    "custo_usd": custo_em_dolar(linha, preco_entrada, preco_saida),
                })
            total = {k: sum(linha[k] for linha in r["por_agente"]) for k in ("chamadas", "tokens_entrada", "tokens_saida", "llm_s")}
            custos = [custo_em_dolar(linha, preco_entrada, preco_saida) for linha in r["por_agente"]]
            escritor.writerow({
                **base, "agente": "total", "onde": None, **total, "llm_s": round(total["llm_s"], 3),
                "agentes_s": r["agentes_s"], "deteccao_s": r["deteccao_s"],
                "custo_usd": round(sum(c for c in custos if c is not None), 6) if any(c is not None for c in custos) else None,
            })
    return rodadas


def resumo(rodadas):
    """Um resumo por configuração, para ler no terminal: rodadas, erros, qualidade e acerto da triagem."""
    linhas = []
    for configuracao in sorted({r["configuracao"] for r in rodadas}):
        delas = [r for r in rodadas if r["configuracao"] == configuracao]
        erros = sum(r["desfecho"] == ERRO for r in delas)
        verdadeiras = [r for r in delas if r["verdadeiro"] and r["desfecho"] != ERRO]
        validas = [r for r in delas if r["desfecho"] != ERRO]
        qualidade = f"{100 * sum(r['primeira_aceitavel'] for r in verdadeiras) / len(verdadeiras):.1f}%" if verdadeiras else "-"
        triagem = f"{100 * sum(r['triagem_correta'] for r in validas) / len(validas):.1f}%" if validas else "-"
        linhas.append(
            f"{configuracao}: {len(delas)} rodadas, {erros} com erro, qualidade {qualidade} "
            f"({len(verdadeiras)} verdadeiras), triagem certa em {triagem}"
        )
    return linhas


# --- linha de comando ------------------------------------------------------------------------


def perfis_das_configuracoes(configuracoes, ambiente):
    """Os modelos que as configurações usam, lidos do ambiente. Devolve `(perfis, faltando)`."""
    perfis, faltando = {}, []
    for configuracao in configuracoes:
        encontrados, ausentes = perfis_da_configuracao(configuracao, ambiente)
        perfis.update(encontrados)
        faltando += [nome for nome in ausentes if nome not in faltando]
    return perfis, faltando


def _preparar(argumentos):
    from codigo.reprodutor.reprodutor import Classificador, inicio_do_teste

    classificador = Classificador.carregar(argumentos.modelo)
    itens = []
    for pcap in argumentos.pcaps:
        a_partir = 0
        if not argumentos.pcap_inteiro:
            a_partir = inicio_do_teste(pcap)
            if a_partir is None:
                print(f"erro: {Path(pcap).name} não tem trecho fora do treino no manifesto da regeração", file=sys.stderr)
                return 1
        novos = preparar_pcap(pcap, argumentos.saida, classificador, a_partir_da_janela=a_partir, por_pcap=argumentos.por_pcap)
        print(f"{Path(pcap).name}: {len(novos)} incidentes, {sum(i.verdadeiro for i in novos)} verdadeiros")
        itens += novos
    caminho = gravar_conjunto(itens, argumentos.saida)
    print(f"conjunto de {len(itens)} incidentes em {caminho}")
    return 0


def _rodar(argumentos):
    carregar_env(argumentos.env)
    perfis, faltando = perfis_das_configuracoes(argumentos.configuracoes, os.environ)
    if faltando:
        print(f"faltam no .env: {', '.join(faltando)}", file=sys.stderr)
        return 2
    itens = ler_conjunto(argumentos.conjunto)[: argumentos.limite]
    pasta = Path(argumentos.saida) / PASTA_DAS_RODADAS
    gabarito = carregar_gabarito()
    total = len(itens) * len(argumentos.configuracoes) * argumentos.repeticoes
    feitas = 0
    for repeticao in range(1, argumentos.repeticoes + 1):
        for configuracao in argumentos.configuracoes:
            for item in itens:
                feitas += 1
                medida = rodar_item(item, configuracao, repeticao, perfis=perfis, pasta_das_rodadas=pasta, gabarito=gabarito)
                print(f"[{feitas}/{total}] {medida['rodada']}: {medida['desfecho']}", flush=True)
    print("\n".join(resumo(ler_rodadas(pasta))))
    return 0


def _consolidar(argumentos):
    rodadas = consolidar(
        argumentos.rodadas, argumentos.saida, preco_entrada=argumentos.preco_entrada, preco_saida=argumentos.preco_saida
    )
    print(f"{len(rodadas)} rodadas em {Path(argumentos.saida) / AVALIACAO} e {Path(argumentos.saida) / CUSTO}")
    print("\n".join(resumo(rodadas)))
    return 0


def main(argv=None):
    analisador = argparse.ArgumentParser(prog="python -m codigo.agente.experimento", description=__doc__.split("\n\n")[0])
    comandos = analisador.add_subparsers(dest="comando", required=True)

    preparar = comandos.add_parser("preparar", help="reproduz os pcaps e monta o conjunto de incidentes")
    preparar.add_argument("pcaps", nargs="+", help="os pcaps do dataset, como CICIoT2023/Recon-PortScan.pcap")
    preparar.add_argument("--saida", default="dados/processed/agentes", help="pasta do conjunto, dos logs e dos cenários")
    preparar.add_argument("--por-pcap", type=int, help="no máximo, os primeiros N incidentes de cada pcap")
    preparar.add_argument("--pcap-inteiro", action="store_true", help="reproduz o pcap inteiro, e não só o trecho fora do treino")
    preparar.add_argument("--modelo", default=str(R.MODELO_PADRAO), help="o modelo do sistema, com o ponto de operação ao lado")

    rodar = comandos.add_parser("rodar", help="roda os agentes nos incidentes do conjunto, e retoma de onde parou")
    rodar.add_argument("--conjunto", default=f"dados/processed/agentes/{CONJUNTO}")
    rodar.add_argument("--configuracoes", nargs="+", choices=list(CONFIGURACOES), default=list(CONFIGURACOES))
    rodar.add_argument("--repeticoes", type=int, default=3)
    rodar.add_argument("--limite", type=int, help="só os primeiros N incidentes do conjunto, para um teste curto")
    rodar.add_argument("--saida", default="dados/processed/agentes", help="pasta de onde saem as rodadas")
    rodar.add_argument("--env", default=str(RAIZ / ".env"), help="arquivo .env (padrão: o da raiz)")

    juntar = comandos.add_parser("consolidar", help="junta as rodadas nos dois CSV")
    juntar.add_argument("--rodadas", default=f"dados/processed/agentes/{PASTA_DAS_RODADAS}")
    juntar.add_argument("--saida", default="experimentos/resultados")
    juntar.add_argument("--preco-entrada", type=float, help="dólares por milhão de tokens de entrada, na nuvem")
    juntar.add_argument("--preco-saida", type=float, help="dólares por milhão de tokens de saída, na nuvem")

    argumentos = analisador.parse_args(argv)
    if argumentos.comando in ("rodar",) and argumentos.repeticoes < 1:
        analisador.error("--repeticoes precisa ser 1 ou mais")
    try:
        return {"preparar": _preparar, "rodar": _rodar, "consolidar": _consolidar}[argumentos.comando](argumentos)
    except (OSError, ValueError, KeyError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
