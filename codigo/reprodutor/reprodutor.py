"""Reprodutor de tráfego: um pcap passa pelo extrator, pelo classificador e pela política de
acionamento, e os incidentes vão para o log de eventos no formato do contrato do servidor MCP.

É o que liga o classificador ao servidor. A leitura é acelerada: o pcap é lido o mais rápido
possível, e os instantes das janelas e dos incidentes são os do próprio pcap. O tempo até a
detecção sai desses instantes: da primeira janela de ataque da sequência até o fim da janela que
abriu o incidente.

Classificação. Cada janela de 100 quadros (decisão de 10/10/2026) passa pelo modelo do sistema
e recebe a categoria pela regra do ponto de operação gravado ao lado dele (`operacao.ler`).

Política de acionamento, primeira versão (19/10/2026). Ela agrupa as janelas do mesmo ataque num
incidente só, para que um flood de centenas de janelas por segundo não vire centenas de chamadas
aos modelos:
- o incidente abre na janela que completa as `seguidas` janelas de ataque seguidas do ponto de
  operação (hoje 3), e as janelas dessa sequência entram nele;
- enquanto ele está aberto, as janelas de ataque seguintes entram nele, e `fecha_apos` janelas
  benignas seguidas o encerram;
- a categoria do incidente é a mais frequente entre as suas janelas de ataque, e a confiança é a
  média da probabilidade dessa categoria nessas janelas;
- uma pausa de mais de `silencio_s` segundos zera a sequência e encerra o incidente aberto, seja
  entre duas janelas, seja dentro de uma janela que dura mais que isso: os pcaps do dataset juntam
  sessões de captura separadas por horas, e sem a regra um incidente atravessaria a pausa e o tempo
  até a detecção a incluiria. A janela que contém a pausa junta duas sessões: é classificada e
  contada, mas não entra em sequência nem em incidente;
- uma sequência nova com a mesma categoria de um incidente encerrado há no máximo `reagrupa_s`
  segundos, e com algum endereço em comum entre os `ENDERECOS_DA_CHAVE` mais frequentes de cada um
  (como origem ou como destino), reabre esse incidente em vez de abrir outro: uma varredura em
  rajadas contra alvos diferentes é um ataque só, e o atacante aparece em todas;
- passado o `teto` de incidentes por pcap, os seguintes só entram na contagem.
Os números são parâmetros, porque o experimento ponta a ponta vai comparar valores.

Regra das origens. O modelo não separa DDoS de DoS. O incidente é distribuído quando a origem que
mais manda quadros ao destino principal do incidente responde por menos de `PARCELA_DA_MAIOR_ORIGEM`
deles: num DoS, uma origem só domina o tráfego para a vítima; num DDoS, ou com origem forjada a
cada quadro, nenhuma domina.

As features principais do incidente são as de maior importância no Random Forest, com o valor
mediano nas janelas da categoria e a mediana do tráfego benigno do treino ao lado
(`referencia_benigno.json`, gerado por `python -m codigo.reprodutor --gerar-referencia`).

Uso, a partir da raiz do repositório:
    python -m codigo.reprodutor CICIoT2023/Recon-PingSweep.pcap
    python -m codigo.reprodutor captura.pcap --log dados/eventos/minha.jsonl --fecha-apos 20
"""

import datetime
import hashlib
import json
import math
import socket
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from codigo.captura.extrator import COLUNAS, Extrator, ler_pcap
from codigo.classificador import operacao
from codigo.classificador.treinar import carregar_modelo
from codigo.mcp.cenarios import Cenario, gravar_cenarios
from codigo.mcp.eventos import Registro, ler, novo
from codigo.mcp.tipos import (
    DDOS_E_DOS,
    EnderecoContado,
    FeaturePrincipal,
    Incidente,
    Janela,
    LoteDeJanelas,
)

JANELA = 100
MODELO_PADRAO = Path("modelos") / "rf_regerado_janela_100.joblib"
REFERENCIA = Path(__file__).with_name("referencia_benigno.json")
# Janelas classificadas de uma vez: o Random Forest é bem mais rápido em lote.
LOTE = 512
FECHA_APOS = 10
SILENCIO_S = 60.0
REAGRUPA_S = 300.0
ENDERECOS_DA_CHAVE = 3
TETO_DE_INCIDENTES = 20
PARCELA_DA_MAIOR_ORIGEM = 0.8
# Quantos endereços o incidente lista, quantas features principais e quantas janelas reais guarda
# para `obter_janelas`.
ENDERECOS_LISTADOS = 10
FEATURES_PRINCIPAIS = 5
JANELAS_GUARDADAS = 1000
# Em um replay a ação não age sobre o tráfego gravado: a verificação do efeito é simulada e dá
# "cessou" na primeira ação aplicada. Entra nas limitações do experimento.
EFEITOS_DO_REPLAY = ("cessou",)


def _ip(valor):
    return socket.inet_ntoa(valor)


class _ExtratorComContagens(Extrator):
    """O extrator do sistema, que devolve com cada janela os quadros por endereço e o período dela.

    Lê a lista de medidas da janela antes de o extrator fechá-la. A origem de um quadro ARP é o
    IP que ele anuncia, a única origem que um spoofing de ARP tem.
    """

    def _fechar(self):
        origens, destinos, pares = Counter(), Counter(), Counter()
        for medida in self._pendentes:
            origem = medida["ip_origem"] or medida["ip_arp"]
            destino = medida["ip_destino"]
            if origem:
                origens[origem] += 1
            if destino:
                destinos[destino] += 1
            if origem and destino:
                pares[origem, destino] += 1
        inicio, fim = self._pendentes[0]["ts"], self._pendentes[-1]["ts"]
        return super()._fechar(), origens, destinos, pares, inicio, fim


@dataclass(frozen=True)
class Classificador:
    """O modelo do sistema com a regra de decisão gravada ao lado dele."""

    modelo: object
    features: tuple
    ponto: operacao.PontoDeOperacao
    arquivo: str

    @classmethod
    def carregar(cls, caminho=MODELO_PADRAO):
        pacote = carregar_modelo(caminho)
        modelo = pacote["modelo"]
        modelo.n_jobs = 1
        return cls(modelo, tuple(pacote["features"]), operacao.ler(caminho), Path(caminho).name)

    @property
    def classes(self):
        return list(self.modelo.classes_)

    def importancias(self):
        """As features da maior para a menor importância no modelo."""
        pesos = getattr(self.modelo, "feature_importances_", None)
        if pesos is None:
            return list(self.features)
        return [self.features[i] for i in np.argsort(-np.asarray(pesos), kind="stable")]

    def probabilidades(self, linhas):
        X = np.array([[linha[coluna] for coluna in self.features] for linha in linhas], dtype=np.float32)
        return self.modelo.predict_proba(np.where(np.isinf(X), np.float32(np.nan), X))


@dataclass
class _JanelaDeAtaque:
    indice: int
    inicio: float
    fim: float
    categoria: str
    confianca: float
    origem: str | None
    destino: str | None
    valores: tuple


@dataclass
class IncidenteReproduzido:
    """As janelas de um incidente, como a política de acionamento as reuniu."""

    primeira_janela_de_ataque: float
    aberto_em: float
    ataque: list = field(default_factory=list)
    por_categoria: Counter = field(default_factory=Counter)
    origens: Counter = field(default_factory=Counter)
    destinos: Counter = field(default_factory=Counter)
    pares: Counter = field(default_factory=Counter)
    # Janelas benignas depois da última de ataque: só contam no lote se outra de ataque vier.
    benignas_pendentes: int = 0
    reaberturas: int = 0

    def categoria_principal(self):
        return Counter(j.categoria for j in self.ataque).most_common(1)[0][0]

    def enderecos_principais(self):
        return _enderecos_principais(self.origens, self.destinos)

    def acrescentar(self, janela, origens, destinos, pares):
        if self.benignas_pendentes:
            self.por_categoria["Benign"] += self.benignas_pendentes
            self.benignas_pendentes = 0
        self.ataque.append(janela)
        self.por_categoria[janela.categoria] += 1
        self.origens.update(origens)
        self.destinos.update(destinos)
        self.pares.update(pares)


@dataclass
class Reproducao:
    arquivo: str
    quadros: int = 0
    ignorados: int = 0
    janelas: int = 0
    por_categoria: Counter = field(default_factory=Counter)
    inicio: float | None = None
    fim: float | None = None
    incidentes: list = field(default_factory=list)
    alem_do_teto: int = 0
    segundos: float = 0.0


def _enderecos_principais(origens, destinos):
    return {endereco for endereco, _ in (origens + destinos).most_common(ENDERECOS_DA_CHAVE)}


def reproduzir(
    origem, classificador, *, fecha_apos=FECHA_APOS, silencio_s=SILENCIO_S, reagrupa_s=REAGRUPA_S,
    teto=TETO_DE_INCIDENTES, nome=None,
):
    """Lê o pcap, classifica as janelas e reúne as de ataque em incidentes pela política de acionamento."""
    inicio_do_processamento = time.perf_counter()
    reproducao = Reproducao(arquivo=nome or Path(origem).name)
    extrator = _ExtratorComContagens(JANELA)
    vigia = operacao.Vigia(classificador.ponto, classificador.classes)
    benigno = classificador.ponto.benigno
    estado = {"sequencia": [], "aberto": None, "benignas": 0, "ultimo_fim": None}

    def fechar_incidente():
        estado["aberto"].benignas_pendentes = 0
        estado["aberto"] = None
        estado["benignas"] = 0

    def para_reabrir(sequencia):
        """O incidente encerrado há pouco com a mesma categoria e algum endereço principal em comum, se houver."""
        categoria = Counter(j.categoria for j, _ in sequencia).most_common(1)[0][0]
        origens, destinos = Counter(), Counter()
        for _, (suas_origens, seus_destinos, _pares) in sequencia:
            origens.update(suas_origens)
            destinos.update(seus_destinos)
        enderecos = _enderecos_principais(origens, destinos)
        for anterior in reversed(reproducao.incidentes):
            if sequencia[0][0].inicio - anterior.ataque[-1].fim > reagrupa_s:
                return None
            if anterior.categoria_principal() == categoria and anterior.enderecos_principais() & enderecos:
                return anterior
        return None

    def processar(janela, categoria, abre, contagens):
        reproducao.por_categoria[categoria] += 1
        aberto = estado["aberto"]
        if aberto is not None:
            if categoria == benigno:
                aberto.benignas_pendentes += 1
                estado["benignas"] += 1
                if estado["benignas"] >= fecha_apos:
                    fechar_incidente()
            else:
                estado["benignas"] = 0
                aberto.acrescentar(janela, *contagens)
            return
        if categoria == benigno:
            estado["sequencia"] = []
            return
        estado["sequencia"].append((janela, contagens))
        if not abre:
            return
        sequencia, estado["sequencia"] = estado["sequencia"], []
        anterior = para_reabrir(sequencia)
        if anterior is not None:
            anterior.reaberturas += 1
            for janela_da_sequencia, suas_contagens in sequencia:
                anterior.acrescentar(janela_da_sequencia, *suas_contagens)
            estado["aberto"] = anterior
            return
        if len(reproducao.incidentes) >= teto:
            reproducao.alem_do_teto += 1
            return
        novo_incidente = IncidenteReproduzido(primeira_janela_de_ataque=sequencia[0][0].inicio, aberto_em=janela.fim)
        for anterior, suas_contagens in sequencia:
            novo_incidente.acrescentar(anterior, *suas_contagens)
        reproducao.incidentes.append(novo_incidente)
        estado["aberto"] = novo_incidente

    pendentes = []

    def classificar_pendentes():
        if not pendentes:
            return
        classes = classificador.classes
        probabilidades = classificador.probabilidades([p[1] for p in pendentes])
        for (indice, linha, origens, destinos, pares, inicio, fim), linha_de_p in zip(pendentes, probabilidades, strict=True):
            entre_janelas = inicio - estado["ultimo_fim"] if estado["ultimo_fim"] is not None else 0.0
            com_pausa = fim - inicio > silencio_s
            if entre_janelas > silencio_s or com_pausa:
                vigia.seguidas = 0
                estado["sequencia"] = []
                if estado["aberto"] is not None:
                    fechar_incidente()
            estado["ultimo_fim"] = fim
            categoria, abre = vigia.alimentar(linha_de_p)
            if com_pausa:
                vigia.seguidas = 0
                reproducao.por_categoria[categoria] += 1
                continue
            janela = None
            if categoria != benigno:
                valores = tuple(float(linha[coluna]) for coluna in COLUNAS)
                janela = _JanelaDeAtaque(
                    indice=indice, inicio=inicio, fim=fim, categoria=categoria,
                    confianca=float(linha_de_p[classes.index(categoria)]),
                    origem=_ip(origens.most_common(1)[0][0]) if origens else None,
                    destino=_ip(destinos.most_common(1)[0][0]) if destinos else None,
                    valores=valores,
                )
            processar(janela, categoria, abre, (origens, destinos, pares))
        pendentes.clear()

    def receber(saida, indice):
        linha, origens, destinos, pares, inicio, fim = saida
        if reproducao.inicio is None:
            reproducao.inicio = inicio
        reproducao.fim = fim
        pendentes.append((indice, linha, origens, destinos, pares, inicio, fim))
        if len(pendentes) >= LOTE:
            classificar_pendentes()

    for ts, quadro in ler_pcap(origem):
        reproducao.quadros += 1
        saida = extrator.alimentar(ts, quadro)
        if saida is not None:
            receber(saida, reproducao.janelas)
            reproducao.janelas += 1
    saida = extrator.finalizar()
    if saida is not None:
        receber(saida, reproducao.janelas)
        reproducao.janelas += 1
    classificar_pendentes()
    reproducao.ignorados = extrator.ignorados
    reproducao.segundos = time.perf_counter() - inicio_do_processamento
    return reproducao


def _instante(ts):
    return datetime.datetime.fromtimestamp(ts, tz=datetime.UTC)


def _finito(valor):
    return valor if valor is not None and math.isfinite(valor) else None


def _contados(contagem):
    return [EnderecoContado(endereco=_ip(ip), quadros=n) for ip, n in contagem.most_common(ENDERECOS_LISTADOS)]


def ler_referencia(caminho=REFERENCIA):
    return json.loads(Path(caminho).read_text(encoding="utf-8"))["mediana"]


def _regra_das_origens(incidente):
    """Origens distintas que mandam quadros ao destino principal, e se nenhuma delas domina."""
    if not incidente.destinos:
        return 0, False
    alvo = incidente.destinos.most_common(1)[0][0]
    para_o_alvo = Counter({origem: n for (origem, destino), n in incidente.pares.items() if destino == alvo})
    total = sum(para_o_alvo.values())
    if not total:
        return 0, False
    return len(para_o_alvo), max(para_o_alvo.values()) / total < PARCELA_DA_MAIOR_ORIGEM


def montar_cenario(incidente, numero, classificador, referencia, arquivo):
    """O incidente no formato do contrato, dentro de um cenário que o servidor MCP atende."""
    categoria_do_modelo = Counter(j.categoria for j in incidente.ataque).most_common(1)[0][0]
    da_categoria = [j for j in incidente.ataque if j.categoria == categoria_do_modelo]
    origens_distintas, distribuido = _regra_das_origens(incidente)
    categoria = ("DDoS" if distribuido else "DoS") if categoria_do_modelo == DDOS_E_DOS else categoria_do_modelo
    valores = np.array([j.valores for j in da_categoria], dtype=np.float64)
    valores[~np.isfinite(valores)] = np.nan
    with np.errstate(all="ignore"):
        medianas = dict(zip(COLUNAS, np.nanmedian(valores, axis=0) if len(valores) else [], strict=False))
    principais = []
    for nome in classificador.importancias():
        valor, base = _finito(float(medianas.get(nome, math.nan))), _finito(referencia.get(nome))
        if valor is not None and base is not None:
            principais.append(FeaturePrincipal(nome=nome, valor=round(valor, 4), referencia_benigno=round(base, 4)))
        if len(principais) == FEATURES_PRINCIPAIS:
            break
    identificador = f"inc-{numero:04d}"
    dados = Incidente(
        id=identificador,
        estado="aberto",
        categoria=categoria,
        categoria_do_modelo=categoria_do_modelo,
        confianca=round(sum(j.confianca for j in da_categoria) / len(da_categoria), 2),
        inicio=_instante(incidente.ataque[0].inicio),
        fim=_instante(incidente.ataque[-1].fim),
        janelas=len(incidente.ataque),
        origens_distintas=origens_distintas,
        distribuido=distribuido,
        origens=_contados(incidente.origens),
        destinos=_contados(incidente.destinos),
        features_principais=principais,
    )
    # O incidente reúne todas as janelas de ataque da sequência, de qualquer categoria; a categoria,
    # a confiança e as features principais vêm das janelas da categoria mais frequente. O índice da
    # janela guardada é a posição dela entre as que `janelas` conta, mesmo quando só uma parte é guardada.
    passo = max(1, math.ceil(len(incidente.ataque) / JANELAS_GUARDADAS))
    guardadas = [(posicao, j) for posicao, j in enumerate(incidente.ataque) if posicao % passo == 0 and j.origem and j.destino]
    reais = tuple(
        Janela(
            indice=posicao, instante=_instante(j.inicio), categoria_do_modelo=j.categoria,
            confianca=round(j.confianca, 2), origem=j.origem, destino=j.destino,
            features={coluna: _finito(valor) for coluna, valor in zip(COLUNAS, j.valores, strict=True)},
        )
        for posicao, j in guardadas
    )
    lote = LoteDeJanelas(janelas=sum(incidente.por_categoria.values()), por_categoria=dict(incidente.por_categoria))
    perfil = {nome: round(float(v), 4) for nome, v in medianas.items() if _finito(float(v)) is not None}
    descricao = (
        f"Incidente de {categoria} reconstruído do pcap {arquivo}: {len(incidente.ataque)} janelas de ataque, "
        f"da {incidente.ataque[0].indice} à {incidente.ataque[-1].indice}."
    )
    return Cenario(
        nome=f"{arquivo}:{identificador}", descricao=descricao, incidente=dados, lote=lote,
        efeitos=EFEITOS_DO_REPLAY, quadros_por_janela=JANELA, perfil=perfil, janelas_reais=reais,
    )


def cenarios_da_reproducao(reproducao, classificador, referencia=None, primeiro=1):
    """Os cenários dos incidentes, numerados a partir de `primeiro` (ver `proximo_numero`)."""
    referencia = referencia if referencia is not None else ler_referencia()
    return [
        montar_cenario(incidente, numero, classificador, referencia, reproducao.arquivo)
        for numero, incidente in enumerate(reproducao.incidentes, start=primeiro)
    ]


def proximo_numero(caminho_do_log):
    """O número do próximo incidente num log que pode já ter incidentes de outra reprodução."""
    caminho = Path(caminho_do_log)
    if not caminho.exists() or caminho.stat().st_size == 0:
        return 1
    numeros = [
        int(evento.incidente.removeprefix("inc-"))
        for evento in ler(caminho)
        if evento.tipo == "incidente_aberto" and evento.incidente and evento.incidente.removeprefix("inc-").isdigit()
    ]
    return max(numeros, default=0) + 1


def caminho_dos_cenarios(caminho_do_log):
    """Onde ficam os cenários de um log: ao lado dele, com `.cenarios.json` no lugar de `.jsonl`."""
    caminho = Path(caminho_do_log)
    return caminho.with_name(caminho.stem + ".cenarios.json")


def gravar(cenarios, reproducao, caminho_do_log, relogio=None):
    """Grava no log, para cada incidente, o lote de janelas e a abertura; no fim, o lote do resto do pcap."""
    registro = Registro(caminho_do_log) if relogio is None else Registro(caminho_do_log, relogio=relogio)
    rascunhos = []
    for cenario in cenarios:
        rascunhos.append(novo("janelas_classificadas", cenario.lote))
        rascunhos.append(novo("incidente_aberto", cenario.incidente, cenario.incidente.id))
    resto = reproducao.por_categoria.copy()
    for cenario in cenarios:
        resto.subtract(cenario.lote.por_categoria)
    resto = Counter({categoria: n for categoria, n in resto.items() if n > 0})
    if resto:
        rascunhos.append(novo("janelas_classificadas", LoteDeJanelas(janelas=sum(resto.values()), por_categoria=dict(resto))))
    if rascunhos:
        registro.gravar(*rascunhos)
    # Os cenários vão ao lado do log, somados aos de reproduções anteriores no mesmo log, para o
    # servidor (`python -m codigo.mcp.stub --cenarios`) atender todos os incidentes dele.
    destino = caminho_dos_cenarios(caminho_do_log)
    anteriores = []
    if destino.exists():
        from codigo.mcp.cenarios import ler_cenarios

        anteriores = [c for c in ler_cenarios(destino) if c.incidente.id not in {n.incidente.id for n in cenarios}]
    gravar_cenarios([*anteriores, *cenarios], destino)
    return registro


def resumo(
    reproducao, cenarios, classificador, fecha_apos=FECHA_APOS, silencio_s=SILENCIO_S, reagrupa_s=REAGRUPA_S,
    teto=TETO_DE_INCIDENTES,
):
    """O que a reprodução produziu, para a linha de comando e para a interface."""
    duracao = (reproducao.fim - reproducao.inicio) if reproducao.inicio is not None else 0.0
    incidentes = []
    for cenario, reproduzido in zip(cenarios, reproducao.incidentes, strict=True):
        dados = cenario.incidente
        incidentes.append({
            "id": dados.id, "categoria": dados.categoria, "categoria_do_modelo": dados.categoria_do_modelo,
            "janelas": dados.janelas, "confianca": dados.confianca, "distribuido": dados.distribuido,
            "origens_distintas": dados.origens_distintas,
            "inicio": dados.inicio.isoformat(), "fim": dados.fim.isoformat(),
            "primeira_janela_de_ataque": _instante(reproduzido.primeira_janela_de_ataque).isoformat(),
            "aberto_em": _instante(reproduzido.aberto_em).isoformat(),
            "atraso_de_deteccao_s": round(reproduzido.aberto_em - reproduzido.primeira_janela_de_ataque, 3),
            "reaberturas": reproduzido.reaberturas,
        })
    return {
        "arquivo": reproducao.arquivo,
        "quadros": reproducao.quadros,
        "ignorados": reproducao.ignorados,
        "janelas": reproducao.janelas,
        "por_categoria": dict(reproducao.por_categoria.most_common()),
        "duracao_do_pcap_s": round(duracao, 3),
        "processamento_s": round(reproducao.segundos, 3),
        "modelo": classificador.arquivo,
        "ponto_de_operacao": {
            "regra": classificador.ponto.regra, "limiar": classificador.ponto.limiar, "seguidas": classificador.ponto.seguidas,
        },
        "acionamento": {
            "fecha_apos": fecha_apos, "silencio_s": silencio_s, "reagrupa_s": reagrupa_s, "teto": teto,
            "parcela_da_maior_origem": PARCELA_DA_MAIOR_ORIGEM,
        },
        "incidentes": incidentes,
        "incidentes_alem_do_teto": reproducao.alem_do_teto,
    }


def gerar_referencia(pasta=Path("dados/processed/regerado/janela_100"), destino=REFERENCIA):
    """Grava a mediana de cada feature nas janelas dos pcaps benignos regerados."""
    import pandas as pd

    from codigo.classificador.preparar import matriz

    arquivo = Path(pasta) / "BenignTraffic.csv.gz"
    quadro = pd.read_csv(arquivo, usecols=list(COLUNAS))
    X = matriz(quadro, COLUNAS).astype(np.float64)
    medianas = np.nanmedian(X, axis=0)
    with open(arquivo, "rb") as aberto:
        sha256 = hashlib.file_digest(aberto, "sha256").hexdigest()
    conteudo = {
        "descricao": "Mediana de cada feature nas janelas de 100 quadros dos três pcaps benignos regerados: "
        "o valor de referência do tráfego benigno nas features principais do incidente.",
        "gerado_por": "python -m codigo.reprodutor --gerar-referencia",
        "fonte": {"arquivo": Path(*arquivo.parts[-5:]).as_posix(), "sha256": sha256, "janelas": len(quadro)},
        "gerado_em": datetime.datetime.now(tz=datetime.UTC).astimezone().date().isoformat(),
        "mediana": {coluna: round(float(v), 4) for coluna, v in zip(COLUNAS, medianas, strict=True)},
    }
    Path(destino).write_text(json.dumps(conteudo, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return Path(destino)
