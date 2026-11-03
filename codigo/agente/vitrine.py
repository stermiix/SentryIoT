"""Os dados fixos da interface: a rodada final dos experimentos dos agentes, pronta para ir no build.

Lê as pastas que `python -m codigo.agente.experimento` grava (o `conjunto.json` e as rodadas em `rodadas/`, cada uma
com as medidas em JSON e o log real em JSONL) e monta em `frontend/public/dados/rodada-final/` o que a interface
abre sem configuração nenhuma:

- `indice.json`: os grupos (a rodada oficial no CICIoT2023, o teste com o Kali Linux numa rede isolada e os
  exemplos por categoria), cada um com as execuções, as medidas de cada execução e um resumo calculado delas;
- `<grupo>/<rodada>.jsonl.gz`: o log de cada execução, comprimido com gzip, byte a byte o que a rodada gravou.

Uso, da raiz do repositório, depois que as três rodadas terminarem:

    python -m codigo.agente.vitrine

As pastas lidas por padrão são `dados/processed/agentes` (oficial), `dados/processed/agentes_kali` e
`dados/processed/agentes_exemplos`; `--oficial`, `--kali` e `--exemplos` trocam cada uma, e `--omitir kali` deixa um
grupo de fora. Depois, `cd frontend && npm run build` põe os dados no `dist/`, e os arquivos de
`frontend/public/dados/rodada-final/` vão para o git com a interface.

O comando é idempotente: com as mesmas rodadas, os arquivos saem iguais, byte a byte. Ele falha, sem gravar nada,
quando falta um arquivo (o conjunto, a pasta das rodadas, o log de uma rodada), quando um item do conjunto não tem
rodada, quando uma rodada não é da configuração local (a única dos experimentos desde 31/10) ou quando um log não
segue o contrato. A rodada que terminou em erro entra, com o desfecho `erro`, e fica fora das taxas do resumo.
"""

import argparse
import gzip
import io
import json
import shutil
import statistics
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from codigo.agente.experimento import CONJUNTO, ERRO, PASTA_DAS_RODADAS
from codigo.mcp.acoes import carregar_politica
from codigo.mcp.eventos import ler

RAIZ = Path(__file__).resolve().parents[2]
SAIDA_PADRAO = RAIZ / "frontend" / "public" / "dados" / "rodada-final"
INDICE = "indice.json"
# Versão do formato do `indice.json`, que a interface confere antes de ler.
VERSAO_DO_INDICE = 1
# A única configuração dos experimentos (decisão de 31/10/2026): a interface diz "modelo local" em toda execução.
CONFIGURACAO = "local"


@dataclass(frozen=True)
class Grupo:
    id: str
    titulo: str
    descricao: str
    pasta_padrao: Path


GRUPOS = (
    Grupo(
        "oficial",
        "Rodada oficial (CICIoT2023)",
        "O conjunto fixado antes da primeira rodada: os primeiros incidentes de cada pcap, na ordem em que abriram, "
        "só no trecho que ficou fora do treino do modelo. É a rodada que o artigo mede.",
        RAIZ / "dados" / "processed" / "agentes",
    ),
    Grupo(
        "kali",
        "Kali Linux, rede isolada",
        "Ataques disparados de uma máquina com Kali Linux numa rede isolada da equipe, capturados em pcap e "
        "reproduzidos pelo sistema.",
        RAIZ / "dados" / "processed" / "agentes_kali",
    ),
    Grupo(
        "exemplos",
        "Exemplos por categoria",
        "Incidentes de outras categorias do CICIoT2023, fora dos cenários medidos, para mostrar o sistema em cada "
        "tipo de ataque.",
        RAIZ / "dados" / "processed" / "agentes_exemplos",
    ),
)
POR_ID = {grupo.id: grupo for grupo in GRUPOS}

# O que passa das medidas da rodada (`experimento.medir`) para a execução no índice, sem mudar.
_DAS_MEDIDAS = (
    "rodada", "pcap", "incidente", "repeticao", "categoria_do_pcap", "categoria", "verdadeiro", "confianca",
    "deteccao_s", "desfecho", "erro", "triagem_rotulo", "triagem_correta", "n_propostas", "n_aceitaveis",
    "primeira_aceitavel", "acao_primeira", "n_aprovadas", "n_rejeitadas", "n_baixo_risco", "n_novas",
    "atacante_apontado", "atacante_certo", "origem_da_regra_certa", "agentes_s",
)
_DO_AGENTE = ("chamadas", "tokens_entrada", "tokens_saida", "llm_s")
# O que pode estar na pasta de saída: o índice e, numa pasta por grupo, os logs comprimidos.
_SUFIXO_DO_LOG = ".jsonl.gz"


class ErroDaVitrine(ValueError):
    """Falta um arquivo, ou uma rodada não serve para a interface. A mensagem diz qual e onde."""


# --- leitura de um grupo ---------------------------------------------------------------------


def ler_grupo(pasta):
    """As execuções de uma pasta do experimento, na ordem do conjunto e da repetição.

    Devolve `(conjunto_gerado_em, execucoes)`; cada execução traz as medidas, os números dos agentes e o caminho do
    log da rodada (`caminho_do_log`), já conferido contra o contrato.
    """
    pasta = Path(pasta)
    conjunto = pasta / CONJUNTO
    if not conjunto.is_file():
        raise ErroDaVitrine(f"falta {conjunto}: rode o `preparar` do experimento nesta pasta")
    corpo = json.loads(conjunto.read_text(encoding="utf-8"))
    itens = corpo.get("itens")
    if not isinstance(itens, list) or not itens:
        raise ErroDaVitrine(f"{conjunto} não tem itens")
    ordem = {(item["pcap"], item["incidente"]): posicao for posicao, item in enumerate(itens)}

    rodadas = pasta / PASTA_DAS_RODADAS
    if not rodadas.is_dir():
        raise ErroDaVitrine(f"falta a pasta {rodadas}: rode o `rodar` do experimento")
    execucoes = []
    for caminho in sorted(rodadas.glob("*.json")):
        execucoes.append(_execucao(caminho, ordem))
    if not execucoes:
        raise ErroDaVitrine(f"{rodadas} não tem rodada nenhuma")

    sem_rodada = sorted(set(ordem) - {(e["pcap"], e["incidente"]) for e in execucoes}, key=ordem.get)
    if sem_rodada:
        faltam = ", ".join(f"{pcap} {incidente}" for pcap, incidente in sem_rodada)
        raise ErroDaVitrine(f"itens do conjunto sem rodada em {rodadas}: {faltam}")
    execucoes.sort(key=lambda e: (ordem[(e["pcap"], e["incidente"])], e["repeticao"]))
    return corpo.get("gerado_em"), execucoes


def _execucao(caminho, ordem):
    medidas = json.loads(caminho.read_text(encoding="utf-8"))
    if not isinstance(medidas, dict) or medidas.get("rodada") != caminho.stem:
        raise ErroDaVitrine(f"{caminho} não é o JSON de uma rodada do experimento (o campo rodada não bate com o nome)")
    faltando = [campo for campo in (*_DAS_MEDIDAS, "configuracao", "por_agente") if campo not in medidas]
    if faltando:
        raise ErroDaVitrine(f"{caminho} não traz {', '.join(faltando)}")
    if medidas["configuracao"] != CONFIGURACAO:
        raise ErroDaVitrine(
            f"{caminho} é da configuração {medidas['configuracao']}; os experimentos rodam só na configuração local, "
            "e a interface diz isso em toda execução"
        )
    if (medidas["pcap"], medidas["incidente"]) not in ordem:
        raise ErroDaVitrine(f"{caminho} é de {medidas['pcap']} {medidas['incidente']}, que não está no conjunto")
    log = caminho.with_suffix(".jsonl")
    if not log.is_file():
        raise ErroDaVitrine(f"falta o log da rodada, {log}")

    eventos = ler(log)  # Linha fora do contrato levanta LogInvalido, com o arquivo e a linha.
    incidente = medidas["incidente"]
    if not any(e.tipo == "incidente_aberto" and e.dados.id == incidente for e in eventos):
        raise ErroDaVitrine(f"o log {log} não abre o incidente {incidente}")
    do_incidente = [e for e in eventos if e.incidente == incidente]
    modelos = sorted({e.dados.modelo for e in do_incidente if e.tipo == "llm_chamada"})
    lugares = sorted({e.dados.onde for e in do_incidente if e.tipo == "llm_chamada" and e.dados.onde})
    if any(lugar != CONFIGURACAO for lugar in lugares):
        raise ErroDaVitrine(f"o log {log} tem chamada ao modelo fora da máquina local ({', '.join(lugares)})")

    por_agente = medidas["por_agente"]
    totais = {campo: sum(linha[campo] for linha in por_agente) for campo in _DO_AGENTE}
    return {
        **{campo: medidas[campo] for campo in _DAS_MEDIDAS},
        **totais,
        "llm_s": round(totais["llm_s"], 3),
        "por_agente": [{"agente": linha["agente"], **{campo: linha[campo] for campo in _DO_AGENTE}} for linha in por_agente],
        "modelos": modelos,
        "conversas": sum(1 for e in do_incidente if e.tipo == "conversa_do_agente"),
        "avisos": list(medidas.get("avisos") or []),
        "caminho_do_log": log,
    }


# --- resumo ----------------------------------------------------------------------------------


def _taxa(execucoes, campo):
    return {"acertos": sum(bool(e[campo]) for e in execucoes), "de": len(execucoes)}


def _mediana(valores):
    valores = list(valores)
    return round(statistics.median(valores), 3) if valores else None


def resumir(execucoes, confianca_minima):
    """O resumo de um grupo, calculado das medidas: as mesmas contas do `resumo` do experimento, e um pouco mais.

    As rodadas com erro contam no total e nos erros, e ficam fora das taxas e das medianas. A ação aceitável, o
    atacante certo e a regra fixa contam só nos incidentes verdadeiros, como no experimento.
    """
    validas = [e for e in execucoes if e["desfecho"] != ERRO]
    verdadeiras = [e for e in validas if e["verdadeiro"]]
    desfechos = {}
    for execucao in execucoes:
        desfechos[execucao["desfecho"]] = desfechos.get(execucao["desfecho"], 0) + 1
    agentes = []
    for agente in ("triagem", "decisao", "execucao"):
        linhas = [linha for e in validas for linha in e["por_agente"] if linha["agente"] == agente]
        if not linhas:
            continue
        agentes.append({
            "agente": agente,
            "execucoes": len(linhas),
            **{campo: sum(linha[campo] for linha in linhas) for campo in ("chamadas", "tokens_entrada", "tokens_saida")},
            "llm_s": round(sum(linha["llm_s"] for linha in linhas), 3),
            "mediana_tokens": _mediana(linha["tokens_entrada"] + linha["tokens_saida"] for linha in linhas),
            "mediana_llm_s": _mediana(linha["llm_s"] for linha in linhas),
        })
    return {
        "execucoes": len(execucoes),
        "com_erro": len(execucoes) - len(validas),
        "pcaps": len({e["pcap"] for e in execucoes}),
        "incidentes": len({(e["pcap"], e["incidente"]) for e in execucoes}),
        "repeticoes": max(e["repeticao"] for e in execucoes),
        "verdadeiras": len(verdadeiras),
        "falsas": len(validas) - len(verdadeiras),
        "triagem_correta": _taxa(validas, "triagem_correta"),
        "acao_aceitavel": _taxa(verdadeiras, "primeira_aceitavel"),
        "atacante_certo": _taxa(verdadeiras, "atacante_certo"),
        "regra_fixa_certa": _taxa(verdadeiras, "origem_da_regra_certa"),
        "abaixo_da_confianca_minima": sum(e["confianca"] < confianca_minima for e in validas),
        "desfechos": dict(sorted(desfechos.items())),
        "chamadas": sum(e["chamadas"] for e in execucoes),
        "tokens_entrada": sum(e["tokens_entrada"] for e in execucoes),
        "tokens_saida": sum(e["tokens_saida"] for e in execucoes),
        "mediana_tokens": _mediana(e["tokens_entrada"] + e["tokens_saida"] for e in validas),
        "mediana_agentes_s": _mediana(e["agentes_s"] for e in validas),
        "mediana_deteccao_s": _mediana(e["deteccao_s"] for e in validas),
        "por_agente": agentes,
    }


def escolher_inicial(grupos):
    """A execução em que a interface abre: a primeira, na ordem do conjunto oficial, em que tudo deu certo.

    Tudo certo é um incidente verdadeiro, na primeira repetição, com a triagem certa, a primeira ação aceitável
    pelo gabarito, o atacante certo e o efeito verificado. Sem nenhuma assim, vale a primeira resolvida num
    incidente verdadeiro, depois a primeira sem erro e, por fim, a primeira de todas. A regra é fixa, para ninguém
    escolher a dedo.
    """
    execucoes = [e for grupo in grupos for e in grupo["execucoes"]]
    criterios = (
        lambda e: e["verdadeiro"] and e["repeticao"] == 1 and e["triagem_correta"] and e["primeira_aceitavel"]
        and e["atacante_certo"] and e["desfecho"] == "resolvido",
        lambda e: e["verdadeiro"] and e["desfecho"] == "resolvido",
        lambda e: e["desfecho"] != ERRO,
        lambda e: True,
    )
    for criterio in criterios:
        for execucao in execucoes:
            if criterio(execucao):
                return execucao["id"]
    raise ErroDaVitrine("nenhuma execução para abrir")


# --- montagem --------------------------------------------------------------------------------


def montar(pastas, saida=SAIDA_PADRAO, *, inicial=None, politica=None):
    """Monta o índice e os logs comprimidos em `saida`. `pastas` é uma lista de pares (id do grupo, pasta).

    Lê e confere tudo antes de gravar: se algo falta, nada muda em `saida`. Devolve o índice.
    """
    if not pastas:
        raise ErroDaVitrine("nenhum grupo para montar")
    confianca_minima = (politica or carregar_politica()).confianca_minima_para_propor
    grupos, logs = [], {}
    for id_do_grupo, pasta in pastas:
        grupo = POR_ID.get(id_do_grupo)
        if grupo is None:
            raise ErroDaVitrine(f"grupo desconhecido: {id_do_grupo}; os grupos são {', '.join(POR_ID)}")
        gerado_em, execucoes = ler_grupo(pasta)
        saidas = []
        for execucao in execucoes:
            caminho = execucao.pop("caminho_do_log")
            relativo = f"{grupo.id}/{execucao['rodada']}{_SUFIXO_DO_LOG}"
            logs[relativo] = caminho
            saidas.append({"id": f"{grupo.id}/{execucao['rodada']}", **execucao, "log": relativo, "bytes": caminho.stat().st_size})
        grupos.append({
            "id": grupo.id,
            "titulo": grupo.titulo,
            "descricao": grupo.descricao,
            "conjunto_gerado_em": gerado_em,
            "resumo": resumir(saidas, confianca_minima),
            "execucoes": saidas,
        })

    ids = {e["id"] for grupo in grupos for e in grupo["execucoes"]}
    if inicial is not None and inicial not in ids:
        raise ErroDaVitrine(f"a execução inicial {inicial} não está nos grupos")
    indice = {
        "versao": VERSAO_DO_INDICE,
        "configuracao": CONFIGURACAO,
        "modelos": sorted({modelo for grupo in grupos for e in grupo["execucoes"] for modelo in e["modelos"]}),
        "confianca_minima_para_propor": confianca_minima,
        "inicial": inicial or escolher_inicial(grupos),
        "grupos": grupos,
    }
    _gravar(Path(saida), indice, logs)
    return indice


def _gravar(saida, indice, logs):
    """Grava numa pasta ao lado e troca a pasta de saída por ela: quem lê nunca vê metade de uma montagem."""
    _conferir_saida(saida)
    saida.parent.mkdir(parents=True, exist_ok=True)
    nova = Path(tempfile.mkdtemp(prefix=".rodada-final-", dir=saida.parent))
    nova.chmod(0o755)  # O mkdtemp cria a pasta só para o dono; ela vai ser servida e versionada.
    try:
        for relativo, origem in logs.items():
            destino = nova / relativo
            destino.parent.mkdir(parents=True, exist_ok=True)
            destino.write_bytes(comprimir(origem.read_bytes()))
        (nova / INDICE).write_text(json.dumps(indice, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        if saida.exists():
            shutil.rmtree(saida)
        nova.rename(saida)
    finally:
        if nova.exists():
            shutil.rmtree(nova)


def comprimir(dados):
    """gzip sem data nem nome de arquivo no cabeçalho: os mesmos dados dão os mesmos bytes."""
    memoria = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=memoria, mtime=0, compresslevel=9) as arquivo:
        arquivo.write(dados)
    return memoria.getvalue()


def _do_sistema(caminho):
    """Os arquivos que o macOS deixa nas pastas (`.DS_Store` e os `._*` de atributos): não são de ninguém."""
    return caminho.is_file() and (caminho.name == ".DS_Store" or caminho.name.startswith("._"))


def _conferir_saida(saida):
    """Só apaga uma pasta de saída que tenha o que este comando grava: um caminho errado não leva nada junto.

    Os arquivos ocultos do sistema (`_do_sistema`) não contam: eles saem junto com a pasta.
    """
    if not saida.exists():
        return
    if not saida.is_dir():
        raise ErroDaVitrine(f"{saida} existe e não é uma pasta")
    for caminho in saida.rglob("*"):
        if _do_sistema(caminho):
            continue
        relativo = caminho.relative_to(saida)
        if caminho.is_dir() and len(relativo.parts) == 1 and relativo.name in POR_ID:
            continue
        if caminho.is_file() and (
            relativo == Path(INDICE)
            or (len(relativo.parts) == 2 and relativo.parts[0] in POR_ID and caminho.name.endswith(_SUFIXO_DO_LOG))
        ):
            continue
        raise ErroDaVitrine(f"{saida} tem {relativo}, que este comando não grava: confira o --saida")


# --- linha de comando ------------------------------------------------------------------------


def main(argv=None):
    analisador = argparse.ArgumentParser(prog="python -m codigo.agente.vitrine", description=__doc__.split("\n\n")[0])
    for grupo in GRUPOS:
        analisador.add_argument(f"--{grupo.id}", type=Path, default=grupo.pasta_padrao, help=f"pasta do grupo {grupo.titulo}")
    analisador.add_argument("--omitir", nargs="+", choices=list(POR_ID), default=[], help="grupos que ficam de fora")
    analisador.add_argument("--saida", type=Path, default=SAIDA_PADRAO, help="pasta dos dados da interface")
    analisador.add_argument("--inicial", help="id da execução em que a interface abre (padrão: a regra de escolher_inicial)")
    argumentos = analisador.parse_args(argv)
    pastas = [(grupo.id, getattr(argumentos, grupo.id)) for grupo in GRUPOS if grupo.id not in argumentos.omitir]
    try:
        indice = montar(pastas, argumentos.saida, inicial=argumentos.inicial)
    except (OSError, ValueError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    for grupo in indice["grupos"]:
        resumo = grupo["resumo"]
        print(f"{grupo['titulo']}: {resumo['execucoes']} {'execução' if resumo['execucoes'] == 1 else 'execuções'}, {resumo['com_erro']} com erro")
        if resumo["com_erro"]:
            print(f"  aviso: {resumo['com_erro']} rodadas terminaram em erro e entram com o desfecho erro", file=sys.stderr)
    tamanho = sum(caminho.stat().st_size for caminho in Path(argumentos.saida).rglob("*") if caminho.is_file())
    print(f"índice e logs em {argumentos.saida} ({tamanho / 1_000_000:.1f} MB); a interface abre em {indice['inicial']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
