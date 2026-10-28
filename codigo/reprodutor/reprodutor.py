"""Reprodutor de tráfego: um pcap passa pelo extrator, pelo classificador e pela política de
acionamento, e os incidentes vão para o log de eventos no formato do contrato do servidor MCP.

É o que liga o classificador ao servidor. A leitura é acelerada: o pcap é lido o mais rápido
possível. O tempo até a detecção sai dos instantes do próprio pcap: da primeira janela de ataque da
sequência até o fim da janela que abriu o incidente.

Relógio. Os instantes do pcap são deslocados para um relógio de reprodução que termina na hora da
gravação: a última janela do pcap acontece "agora", e o resto, antes. Assim o log não mistura o
relógio do pcap com o da máquina, e uma ação aplicada depois não estica a duração do incidente em
anos. O deslocamento fica no resumo, para voltar aos instantes originais.

Classificação. Cada janela de 100 quadros (decisão de 10/10/2026) passa pelo modelo do sistema e
recebe a categoria pela regra do ponto de operação gravado ao lado dele (`operacao.ler`). A última
janela do pcap, quando não chega a 100 quadros, é descartada: ela teria Number, Rate e Std fora
do que o modelo viu no treino. Com `a_partir_da_janela`, as janelas anteriores são extraídas, para
manter o alinhamento, mas não são classificadas: é como se reproduz só o trecho de teste de um pcap
cujo começo entrou no treino (`inicio_do_teste`).

Política de acionamento, primeira versão (19/10/2026). Ela agrupa as janelas do mesmo ataque num
incidente só, para que um flood de centenas de janelas por segundo não vire centenas de chamadas
aos modelos:
- uma janela de ataque entra no incidente aberto com a mesma categoria ou com algum endereço
  principal em comum; se nenhum aberto combina, ela conta para uma sequência nova. Ataques
  diferentes ao mesmo tempo ficam em incidentes diferentes;
- o incidente abre quando a sequência chega às `seguidas` janelas de ataque do ponto de operação
  (hoje 3); entram nele as janelas da categoria mais frequente da sequência e as que têm endereço
  em comum com elas, e as outras ficam na sequência;
- um incidente aberto se encerra depois de `fecha_apos` janelas seguidas que não são dele;
- a categoria do incidente é a mais frequente entre as suas janelas de ataque, e a confiança é a
  média da probabilidade dessa categoria nessas janelas;
- uma pausa de mais de `silencio_s` segundos entre duas janelas zera a sequência e encerra os
  incidentes abertos: os pcaps do dataset juntam sessões de captura separadas por horas;
- uma janela que leva mais de `duracao_maxima_s` segundos para fechar não é julgada: zera a
  sequência, encerra os incidentes abertos e vai para `nao_julgadas`, e não para `por_categoria`.
  É a janela que junta duas sessões de captura, ou a de um tráfego mais lento que qualquer um do
  treino: no CICIoT2023, 99% das janelas de 100 quadros de cada categoria fecham em menos de 5 s,
  menos as de Web, com 99% abaixo de 65 s (`rodadas_de_teste.md`, rodada i). Um aparelho sozinho
  e de pouco tráfego, como a lâmpada Philips Hue do IoT-23 (cerca de 6 minutos por janela), fica
  fora do que o modelo conhece, e a classificação dele não vale nem como alarme nem como medida;
- uma sequência nova com a mesma categoria de um incidente encerrado há no máximo `reagrupa_s`
  segundos, e com algum endereço em comum entre os `ENDERECOS_DA_CHAVE` mais frequentes de cada um,
  reabre esse incidente em vez de abrir outro: uma varredura em rajadas contra alvos diferentes é
  um ataque só, e o atacante aparece em todas;
- passado o `teto` de incidentes por pcap, a sequência seguinte só entra na contagem, e as janelas
  dela deixam de ser guardadas até uma benigna.
Os números são parâmetros, porque o experimento ponta a ponta vai comparar valores.

Papéis. O atacante vem primeiro, pela presença dos endereços contra o fundo. O fundo são as
janelas benignas do mesmo pcap que não caem num incidente aberto, e o destaque de um endereço é a
fração das janelas do incidente em que ele aparece como origem menos a fração das janelas do fundo
em que aparece. Num ataque de pouco volume, o tráfego normal da rede domina as contagens, e o
atacante é o que aparece em quase todas as janelas do incidente e quase nunca nas benignas; o
gateway e os dispositivos comuns aparecem nas duas. São candidatos os endereços que mandam quadros
e têm destaque positivo, fora os protegidos e críticos da política (o gateway fala com todos), e
os fortes são os que chegam a `DESTAQUE_RELATIVO` do maior destaque. Entre os fortes, o atacante é
o que mais abre conexões (SYN sem ACK, descontadas as que recebe), quando abre pelo menos
`MINIMO_DE_ABERTURAS`; senão, é o que mais manda quadros além dos que recebe. O alvo vem depois: é,
entre os destinos do atacante, o que mais se destaca como destino contra o fundo. Numa varredura
(Recon, na categoria do modelo), o atacante é a única origem, e os destinos são todos os endereços
a que ele mandou quadros. Nos outros casos, as origens são os fortes que mandam quadros ao alvo, e
os destinos, para onde essas origens mandam: as respostas da vítima não põem o atacante entre os
destinos. Sem candidato, ou sem destino do atacante, os papéis saem do volume: o alvo é o endereço
que mais recebe quadros, e as origens são todas as que mandam a ele. Multicast e broadcast nunca
são candidatos nem alvo: um anúncio de SSDP recebe de todos os dispositivos da rede. O incidente é
distribuído quando a maior origem responde por menos de `PARCELA_DA_MAIOR_ORIGEM` dos quadros
enviados ao alvo; é a regra que separa DDoS de DoS, que o modelo não separa. Com origem forjada a
cada quadro, nenhuma domina, e o incidente sai distribuído. No ARP spoofing não há destino IP: as
origens são os endereços anunciados, e a lista de destinos fica vazia.

Contagens. As contagens de endereço de um incidente são podadas para os `CONTADOS_DEPOIS_DA_PODA`
mais frequentes quando passam de `LIMITE_DE_CONTADOS`: com origem forjada, a memória fica limitada,
e os mais frequentes, que são os que o incidente lista, continuam certos.

Portas. O incidente lista as `PORTAS_LISTADAS` portas de destino do TCP e do UDP que mais receberam
quadros, só entre os destinos que ele lista: é por elas que o agente escolhe a porta a fechar. A
porta vem do cabeçalho de transporte de cada quadro e não entra nas 39 features.

As features principais do incidente são as de maior importância no Random Forest, com o valor
mediano nas janelas da categoria e a mediana do tráfego benigno do treino ao lado
(`referencia_benigno.json`, gerado por `python -m codigo.reprodutor --gerar-referencia`).

Uso, a partir da raiz do repositório:
    python -m codigo.reprodutor CICIoT2023/Recon-PingSweep.pcap
    python -m codigo.reprodutor CICIoT2023/XSS.pcap --so-teste
    python -m codigo.reprodutor captura.pcap --log dados/eventos/minha.jsonl --fecha-apos 20
"""

import datetime
import hashlib
import json
import math
import socket
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from codigo.captura.extrator import COLUNAS, Extrator, ler_pcap
from codigo.classificador import operacao
from codigo.classificador.treinar import carregar_modelo
from codigo.mcp.cenarios import Cenario, gravar_cenarios, ler_cenarios
from codigo.mcp.eventos import Registro, agora, novo
from codigo.mcp.tipos import (
    DDOS_E_DOS,
    EnderecoContado,
    FeaturePrincipal,
    Incidente,
    Janela,
    LoteDeJanelas,
    PortaContada,
)

JANELA = 100
MODELO_PADRAO = Path("modelos") / "rf_regerado_janela_100.joblib"
MANIFESTO_DA_REGERACAO = Path("experimentos") / "resultados" / "manifesto_regeracao.json"
REFERENCIA = Path(__file__).with_name("referencia_benigno.json")
# Janelas classificadas de uma vez: o Random Forest é bem mais rápido em lote.
LOTE = 512
FECHA_APOS = 10
SILENCIO_S = 60.0
# A janela mais lenta que o reprodutor julga (ver a política de acionamento acima).
DURACAO_MAXIMA_S = 60.0
REAGRUPA_S = 300.0
ENDERECOS_DA_CHAVE = 3
TETO_DE_INCIDENTES = 20
PARCELA_DA_MAIOR_ORIGEM = 0.8
# Aberturas de conexão (SYN sem ACK) que bastam para apontar o atacante entre os que mais se
# destacam: quem inicia conexões é o sentido do ataque, mesmo quando a vítima responde com mais
# quadros.
MINIMO_DE_ABERTURAS = 3
# Uma origem conta como candidata a atacante se o destaque dela chega a esta fração do maior.
DESTAQUE_RELATIVO = 0.5
LIMITE_DE_CONTADOS = 20_000
CONTADOS_DEPOIS_DA_PODA = 5_000
# Quantos endereços o incidente lista, quantas features principais e quantas janelas reais guarda
# para `obter_janelas`.
ENDERECOS_LISTADOS = 10
PORTAS_LISTADAS = 5
FEATURES_PRINCIPAIS = 5
JANELAS_GUARDADAS = 1000
# Em um replay a ação não age sobre o tráfego gravado: a verificação do efeito é simulada e dá
# "cessou" na primeira ação aplicada. Entra nas limitações do experimento.
EFEITOS_DO_REPLAY = ("cessou",)
# Número do protocolo no cabeçalho IPv4 e o nome dele no contrato.
_TRANSPORTE = {6: "tcp", 17: "udp"}


class PcapInvalido(ValueError):
    """O arquivo enviado não é um pcap que o extrator lê: pcapng, outro formato ou outro enlace."""


def _ip(valor):
    return socket.inet_ntoa(valor)


class _ExtratorComContagens(Extrator):
    """O extrator do sistema, que devolve com cada janela os quadros por par de endereços e o período dela.

    Lê a lista de medidas da janela antes de o extrator fechá-la. A origem de um quadro ARP é o
    IP que ele anuncia, a única origem que um spoofing de ARP tem. As portas são contadas por
    destino, protocolo e porta.
    """

    def _fechar(self):
        origens, destinos, pares, aberturas, portas = Counter(), Counter(), Counter(), Counter(), Counter()
        for medida in self._pendentes:
            origem = medida["ip_origem"] or medida["ip_arp"]
            destino = medida["ip_destino"]
            if origem:
                origens[origem] += 1
            if destino:
                destinos[destino] += 1
                if medida["porta_destino"]:
                    portas[destino, medida["Protocol Type"], medida["porta_destino"]] += 1
            if origem and destino:
                pares[origem, destino] += 1
                if medida["syn_flag_number"] and not medida["ack_flag_number"]:
                    aberturas[origem, destino] += 1
        inicio, fim, quadros = self._pendentes[0]["ts"], self._pendentes[-1]["ts"], len(self._pendentes)
        return super()._fechar(), _Contagens(origens, destinos, pares, aberturas, portas), inicio, fim, quadros


@dataclass
class _Contagens:
    origens: Counter
    destinos: Counter
    pares: Counter
    aberturas: Counter
    # Quadros por (destino, protocolo, porta de destino).
    portas: Counter = field(default_factory=Counter)


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
    valores: np.ndarray


def _podar(contagem):
    if len(contagem) > LIMITE_DE_CONTADOS:
        mantidos = contagem.most_common(CONTADOS_DEPOIS_DA_PODA)
        contagem.clear()
        contagem.update(dict(mantidos))


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
    aberturas: Counter = field(default_factory=Counter)
    # Em quantas janelas do incidente cada endereço aparece como origem e como destino.
    presenca_origem: Counter = field(default_factory=Counter)
    presenca_destino: Counter = field(default_factory=Counter)
    portas: Counter = field(default_factory=Counter)
    # Janelas benignas depois da última de ataque: só contam no lote se outra de ataque vier.
    benignas_pendentes: int = 0
    # Janelas seguidas que não são dele; com `fecha_apos` delas, ele se encerra.
    sem_ele: int = 0
    reaberturas: int = 0
    # O incidente como estava quando abriu, e a contagem de janelas do pcap até ali.
    abertura: "IncidenteReproduzido | None" = None
    janelas_ate_abrir: Counter = field(default_factory=Counter)
    _principais: frozenset = frozenset()
    _principais_em: int = -1

    def categoria_principal(self):
        return self.por_categoria_de_ataque().most_common(1)[0][0]

    def por_categoria_de_ataque(self):
        return Counter({categoria: n for categoria, n in self.por_categoria.items() if categoria != "Benign"})

    def enderecos_principais(self):
        """Os endereços mais frequentes, como origem ou destino, recalculados a cada 64 janelas."""
        if self._principais_em < 0 or len(self.ataque) - self._principais_em >= 64:
            self._principais = frozenset(_ip(e) for e in _enderecos_principais(self.origens, self.destinos))
            self._principais_em = len(self.ataque)
        return self._principais

    def acrescentar(self, janela, contagens):
        if self.benignas_pendentes:
            self.por_categoria["Benign"] += self.benignas_pendentes
            self.benignas_pendentes = 0
        self.sem_ele = 0
        self.ataque.append(janela)
        self.por_categoria[janela.categoria] += 1
        for nome in ("origens", "destinos", "pares", "aberturas", "portas"):
            contagem = getattr(self, nome)
            contagem.update(getattr(contagens, nome))
            _podar(contagem)
        self.presenca_origem.update(contagens.origens.keys())
        self.presenca_destino.update(contagens.destinos.keys())
        _podar(self.presenca_origem)
        _podar(self.presenca_destino)

    def copia(self):
        return IncidenteReproduzido(
            self.primeira_janela_de_ataque, self.aberto_em, list(self.ataque), Counter(self.por_categoria),
            Counter(self.origens), Counter(self.destinos), Counter(self.pares), Counter(self.aberturas),
            Counter(self.presenca_origem), Counter(self.presenca_destino), Counter(self.portas),
        )


@dataclass
class Reproducao:
    arquivo: str
    quadros: int = 0
    ignorados: int = 0
    janelas: int = 0
    puladas: int = 0
    incompletas: int = 0
    por_categoria: Counter = field(default_factory=Counter)
    # As janelas lentas demais para julgar, pela categoria que o modelo daria a elas.
    nao_julgadas: Counter = field(default_factory=Counter)
    inicio: float | None = None
    fim: float | None = None
    incidentes: list = field(default_factory=list)
    alem_do_teto: int = 0
    segundos: float = 0.0
    # O fundo contra o qual os papéis são escolhidos: em quantas janelas benignas cada endereço
    # aparece como origem e como destino, e quantas janelas benignas houve.
    fundo: "Fundo" = field(default_factory=lambda: Fundo())


@dataclass
class Fundo:
    origens: Counter = field(default_factory=Counter)
    destinos: Counter = field(default_factory=Counter)
    janelas: int = 0

    def acrescentar(self, contagens):
        self.janelas += 1
        self.origens.update(contagens.origens.keys())
        self.destinos.update(contagens.destinos.keys())
        _podar(self.origens)
        _podar(self.destinos)


def _enderecos_principais(origens, destinos):
    return {endereco for endereco, _ in (origens + destinos).most_common(ENDERECOS_DA_CHAVE)}


def _quadros(origem):
    """Os quadros do pcap; o que o leitor recusa no arquivo vira `PcapInvalido`."""
    try:
        yield from ler_pcap(origem)
    except ValueError as erro:
        raise PcapInvalido(str(erro)) from None


def reproduzir(
    origem, classificador, *, fecha_apos=FECHA_APOS, silencio_s=SILENCIO_S, reagrupa_s=REAGRUPA_S,
    teto=TETO_DE_INCIDENTES, a_partir_da_janela=0, nome=None, duracao_maxima_s=DURACAO_MAXIMA_S,
):
    """Lê o pcap, classifica as janelas e reúne as de ataque em incidentes pela política de acionamento."""
    inicio_do_processamento = time.perf_counter()
    reproducao = Reproducao(arquivo=nome or Path(origem).name)
    extrator = _ExtratorComContagens(JANELA)
    ponto, classes = classificador.ponto, classificador.classes
    benigno, seguidas = ponto.benigno, ponto.seguidas
    abertos = []
    sequencia = deque(maxlen=seguidas)
    estado = {"ultimo_fim": None, "descartando": False}

    def encerrar(incidente):
        incidente.benignas_pendentes = 0
        abertos.remove(incidente)

    def encerrar_todos():
        while abertos:
            encerrar(abertos[0])

    def encerrar_os_sem_atividade():
        for incidente in [i for i in abertos if i.sem_ele >= fecha_apos]:
            encerrar(incidente)

    def compativel(incidente, janela):
        if janela.categoria == incidente.categoria_principal():
            return True
        return bool({janela.origem, janela.destino} & incidente.enderecos_principais())

    def para_reabrir(janelas):
        """O incidente encerrado há pouco com a mesma categoria e algum endereço principal em comum, se houver."""
        categoria = Counter(j.categoria for j, _ in janelas).most_common(1)[0][0]
        origens, destinos = Counter(), Counter()
        for _, contagens in janelas:
            origens.update(contagens.origens)
            destinos.update(contagens.destinos)
        enderecos = {_ip(e) for e in _enderecos_principais(origens, destinos)}
        candidatos = [
            anterior for anterior in reproducao.incidentes
            if anterior not in abertos
            and janelas[0][0].inicio - anterior.ataque[-1].fim <= reagrupa_s
            and anterior.categoria_principal() == categoria
            and anterior.enderecos_principais() & enderecos
        ]
        return max(candidatos, key=lambda anterior: anterior.ataque[-1].fim, default=None)

    def processar(janela, categoria, contagens):
        reproducao.por_categoria[categoria] += 1
        if categoria == benigno:
            # O fundo é o tráfego benigno fora de incidente: a janela benigna no meio de um flood é,
            # quase sempre, ataque que o modelo deixou passar, e traria os atacantes para o fundo.
            if not abertos:
                reproducao.fundo.acrescentar(contagens)
            sequencia.clear()
            estado["descartando"] = False
            for incidente in abertos:
                incidente.benignas_pendentes += 1
                incidente.sem_ele += 1
            encerrar_os_sem_atividade()
            return
        # A janela vai para o aberto da mesma categoria, ou, sem ele, para um com endereço em comum.
        dono = next((i for i in abertos if i.categoria_principal() == janela.categoria), None)
        dono = dono or next((i for i in abertos if compativel(i, janela)), None)
        for incidente in abertos:
            if incidente is not dono:
                incidente.sem_ele += 1
        encerrar_os_sem_atividade()
        if dono is not None:
            dono.acrescentar(janela, contagens)
            return
        if estado["descartando"]:
            return
        sequencia.append((janela, contagens))
        if len(sequencia) < seguidas:
            return
        # As janelas da categoria mais frequente da sequência, e as que têm endereço em comum com
        # elas, são o ataque que abre; as outras ficam esperando para formar o próprio incidente.
        categoria = Counter(j.categoria for j, _ in sequencia).most_common(1)[0][0]
        enderecos = {e for j, _ in sequencia if j.categoria == categoria for e in (j.origem, j.destino)} - {None}
        janelas = [(j, c) for j, c in sequencia if j.categoria == categoria or {j.origem, j.destino} & enderecos]
        escolhidas = {id(j) for j, _ in janelas}
        restantes = [(j, c) for j, c in sequencia if id(j) not in escolhidas]
        sequencia.clear()
        sequencia.extend(restantes)
        anterior = para_reabrir(janelas)
        if anterior is not None:
            anterior.reaberturas += 1
            for janela_da_sequencia, suas_contagens in janelas:
                anterior.acrescentar(janela_da_sequencia, suas_contagens)
            abertos.append(anterior)
            return
        if len(reproducao.incidentes) >= teto:
            reproducao.alem_do_teto += 1
            estado["descartando"] = True
            return
        novo_incidente = IncidenteReproduzido(primeira_janela_de_ataque=janelas[0][0].inicio, aberto_em=janela.fim)
        for janela_da_sequencia, suas_contagens in janelas:
            novo_incidente.acrescentar(janela_da_sequencia, suas_contagens)
        novo_incidente.abertura = novo_incidente.copia()
        novo_incidente.janelas_ate_abrir = Counter(reproducao.por_categoria)
        reproducao.incidentes.append(novo_incidente)
        abertos.append(novo_incidente)

    pendentes = []

    def classificar_pendentes():
        if not pendentes:
            return
        probabilidades = classificador.probabilidades([p[1] for p in pendentes])
        for (indice, linha, contagens, inicio, fim), linha_de_p in zip(pendentes, probabilidades, strict=True):
            entre_janelas = inicio - estado["ultimo_fim"] if estado["ultimo_fim"] is not None else 0.0
            lenta = fim - inicio > duracao_maxima_s
            if entre_janelas > silencio_s or lenta:
                sequencia.clear()
                estado["descartando"] = False
                encerrar_todos()
            estado["ultimo_fim"] = fim
            categoria = ponto.categoria(linha_de_p, classes)
            if lenta:
                reproducao.nao_julgadas[categoria] += 1
                continue
            janela = None
            if categoria != benigno:
                janela = _JanelaDeAtaque(
                    indice=indice, inicio=inicio, fim=fim, categoria=categoria,
                    confianca=float(linha_de_p[classes.index(categoria)]),
                    origem=_ip(contagens.origens.most_common(1)[0][0]) if contagens.origens else None,
                    destino=_ip(contagens.destinos.most_common(1)[0][0]) if contagens.destinos else None,
                    valores=np.array([linha[coluna] for coluna in COLUNAS], dtype=np.float32),
                )
            processar(janela, categoria, contagens)
        pendentes.clear()

    def receber(saida, indice):
        linha, contagens, inicio, fim, _ = saida
        if indice < a_partir_da_janela:
            reproducao.puladas += 1
            return
        if reproducao.inicio is None:
            reproducao.inicio = inicio
        reproducao.fim = fim
        pendentes.append((indice, linha, contagens, inicio, fim))
        if len(pendentes) >= LOTE:
            classificar_pendentes()

    for ts, quadro in _quadros(origem):
        reproducao.quadros += 1
        saida = extrator.alimentar(ts, quadro)
        if saida is not None:
            receber(saida, reproducao.janelas)
            reproducao.janelas += 1
    sobra = extrator.finalizar()
    if sobra is not None:
        reproducao.incompletas += 1
    classificar_pendentes()
    reproducao.ignorados = extrator.ignorados
    reproducao.segundos = time.perf_counter() - inicio_do_processamento
    return reproducao


def inicio_do_teste(arquivo, manifesto=MANIFESTO_DA_REGERACAO):
    """A primeira janela do pcap que ficou fora do treino do modelo do sistema (rotação 0).

    0 quando o pcap ficou inteiro no teste; None quando ele não aparece na regeração ou ficou
    inteiro no treino, e não há trecho que o modelo não viu.
    """
    from codigo.classificador.rodadas import lados

    lado = lados(json.loads(Path(manifesto).read_text(encoding="utf-8")), 0).get(Path(arquivo).name)
    if lado == "teste":
        return 0
    return lado if isinstance(lado, int) else None


def _finito(valor):
    return valor if valor is not None and math.isfinite(valor) else None


def _arredondado(valor):
    """O valor guardado em 32 bits, de volta com 6 casas: sem o ruído de 0.019999999552965164."""
    valor = _finito(float(valor))
    return None if valor is None else round(valor, 6)


def ler_referencia(caminho=REFERENCIA):
    return json.loads(Path(caminho).read_text(encoding="utf-8"))["mediana"]


_NAO_ATACANTES = None


def _nao_atacantes():
    """Os endereços protegidos e críticos da política (gateway, DNS, captura): nunca o atacante de uma varredura."""
    global _NAO_ATACANTES
    if _NAO_ATACANTES is None:
        from codigo.mcp.acoes import carregar_politica

        politica = carregar_politica()
        _NAO_ATACANTES = frozenset(str(e) for e in (*politica.enderecos_protegidos, *politica.enderecos_criticos))
    return _NAO_ATACANTES


def _unicast(endereco):
    """Se o endereço (em bytes) pode ser o alvo de um ataque: nem multicast nem broadcast."""
    return not (endereco[0] >= 224 or endereco[-1] in (0, 255))


def _destaque(presenca, janelas, no_fundo, janelas_do_fundo):
    """Quanto a presença de cada endereço nas janelas do incidente passa da presença nas benignas."""
    return Counter({
        endereco: n / janelas - (no_fundo.get(endereco, 0) / janelas_do_fundo if janelas_do_fundo else 0.0)
        for endereco, n in presenca.items()
    })


def _papeis(incidente, categoria_do_modelo, fundo=None):
    """Origens, destinos, origens distintas e se é distribuído (ver "Papéis" no docstring).

    O atacante aparece em quase todas as janelas do incidente e quase nunca nas benignas; o gateway e
    os dispositivos comuns aparecem nas duas. Entre os endereços que mais se destacam como origem, o
    atacante é o que abre conexões (SYN sem ACK) ou, sem elas, o que manda mais do que recebe. O alvo
    é o destino do atacante que mais se destaca. As contagens devolvidas são quadros de verdade.
    """
    pares, aberturas = incidente.pares, incidente.aberturas
    if not pares:
        return incidente.origens, Counter(), len(incidente.origens), False
    fundo = fundo or Fundo()
    janelas = len(incidente.ataque)
    como_origem = _destaque(incidente.presenca_origem, janelas, fundo.origens, fundo.janelas)
    como_destino = _destaque(incidente.presenca_destino, janelas, fundo.destinos, fundo.janelas)
    enviados, recebidos, abre, recebe_abertura = Counter(), Counter(), Counter(), Counter()
    for (origem, destino), n in pares.items():
        enviados[origem] += n
        recebidos[destino] += n
    for (origem, destino), n in aberturas.items():
        abre[origem] += n
        recebe_abertura[destino] += n
    candidatos = {
        e: d for e, d in como_origem.items()
        if d > 0 and e in enviados and _unicast(e) and _ip(e) not in _nao_atacantes()
    }
    if not candidatos:
        return _papeis_pelo_volume(pares)
    maior = max(candidatos.values())
    fortes = [e for e, d in candidatos.items() if d >= DESTAQUE_RELATIVO * maior]
    iniciadores = [e for e in fortes if abre[e] - recebe_abertura[e] >= MINIMO_DE_ABERTURAS]
    if iniciadores:
        atacante = max(iniciadores, key=lambda e: abre[e] - recebe_abertura[e])
    else:
        atacante = max(fortes, key=lambda e: (enviados[e] - recebidos[e], candidatos[e]))
    alvos = {destino for (origem, destino) in pares if origem == atacante and destino != atacante and _unicast(destino)}
    if not alvos:
        return _papeis_pelo_volume(pares)
    if categoria_do_modelo == "Recon":
        destinos = Counter({destino: pares[atacante, destino] for destino in alvos})
        return Counter({atacante: enviados[atacante]}), destinos, 1, False
    alvo = max(alvos, key=lambda d: (como_destino.get(d, 0.0), pares[atacante, d]))
    # As origens são as que se destacam e mandam ao alvo: no DDoS, várias; no DoS, uma.
    origens = Counter({
        origem: pares[origem, alvo] for origem in fortes if (origem, alvo) in pares and origem != alvo
    })
    if not origens:
        return _papeis_pelo_volume(pares)
    destinos = Counter()
    for (origem, destino), n in pares.items():
        if origem in origens and destino not in origens:
            destinos[destino] += n
    total = sum(origens.values())
    return origens, destinos, len(origens), max(origens.values()) / total < PARCELA_DA_MAIOR_ORIGEM


def _papeis_pelo_volume(pares):
    """Sem origem que se destaque (origem forjada a cada quadro): o alvo é quem mais recebe."""
    recebidos, leque = Counter(), Counter()
    for (_, destino), n in pares.items():
        if _unicast(destino):
            recebidos[destino] += n
            leque[destino] += 1
    if not recebidos:
        return Counter(), Counter(), 0, False
    alvo = max(recebidos, key=lambda destino: (recebidos[destino], leque[destino]))
    origens = Counter({origem: n for (origem, destino), n in pares.items() if destino == alvo})
    destinos = Counter({alvo: recebidos[alvo]})
    total = sum(origens.values())
    return origens, destinos, len(origens), max(origens.values()) / total < PARCELA_DA_MAIOR_ORIGEM


def _contados(contagem):
    return [EnderecoContado(endereco=_ip(ip), quadros=n) for ip, n in contagem.most_common(ENDERECOS_LISTADOS)]


def _portas(portas, destinos):
    """As portas mais atacadas entre os destinos que o incidente lista, da que recebe mais quadros para a que recebe menos."""
    listados = {ip for ip, _ in destinos.most_common(ENDERECOS_LISTADOS)}
    escolhidas = [
        (chave, n) for chave, n in portas.most_common() if chave[0] in listados and chave[1] in _TRANSPORTE
    ][:PORTAS_LISTADAS]
    return [
        PortaContada(destino=_ip(destino), porta=porta, protocolo=_TRANSPORTE[protocolo], quadros=n)
        for (destino, protocolo, porta), n in escolhidas
    ]


def montar_incidente(incidente, identificador, classificador, referencia, deslocamento, fundo=None):
    """O incidente no formato do contrato, no relógio de reprodução."""
    categoria_do_modelo = incidente.categoria_principal()
    da_categoria = [j for j in incidente.ataque if j.categoria == categoria_do_modelo]
    origens, destinos, origens_distintas, distribuido = _papeis(incidente, categoria_do_modelo, fundo)
    categoria = ("DDoS" if distribuido else "DoS") if categoria_do_modelo == DDOS_E_DOS else categoria_do_modelo
    valores = np.array([j.valores for j in da_categoria], dtype=np.float64)
    valores[~np.isfinite(valores)] = np.nan
    with np.errstate(all="ignore"):
        medianas = dict(zip(COLUNAS, np.nanmedian(valores, axis=0), strict=True))
    principais = []
    for nome in classificador.importancias():
        valor, base = _finito(float(medianas.get(nome, math.nan))), _finito(referencia.get(nome))
        if valor is not None and base is not None:
            principais.append(FeaturePrincipal(nome=nome, valor=round(valor, 4), referencia_benigno=round(base, 4)))
        if len(principais) == FEATURES_PRINCIPAIS:
            break
    dados = Incidente(
        id=identificador,
        estado="aberto",
        categoria=categoria,
        categoria_do_modelo=categoria_do_modelo,
        confianca=round(sum(j.confianca for j in da_categoria) / len(da_categoria), 2),
        inicio=_instante(incidente.ataque[0].inicio, deslocamento),
        fim=_instante(incidente.ataque[-1].fim, deslocamento),
        janelas=len(incidente.ataque),
        origens_distintas=origens_distintas,
        distribuido=distribuido,
        origens=_contados(origens),
        destinos=_contados(destinos),
        features_principais=principais,
        portas=_portas(incidente.portas, destinos),
    )
    return dados, medianas


def _instante(ts, deslocamento):
    return datetime.datetime.fromtimestamp(ts + deslocamento, tz=datetime.UTC)


def montar_cenario(incidente, identificador, classificador, referencia, arquivo, deslocamento, fundo=None):
    """O incidente final dentro de um cenário que o servidor MCP atende, com as janelas reais."""
    dados, medianas = montar_incidente(incidente, identificador, classificador, referencia, deslocamento, fundo)
    # O índice da janela guardada é a posição dela entre as que `janelas` conta, mesmo quando só
    # uma parte é guardada. Janela sem destino IP (ARP) não cabe no contrato e fica de fora.
    passo = max(1, math.ceil(len(incidente.ataque) / JANELAS_GUARDADAS))
    guardadas = [(posicao, j) for posicao, j in enumerate(incidente.ataque) if posicao % passo == 0 and j.origem and j.destino]
    reais = tuple(
        Janela(
            indice=posicao, instante=_instante(j.inicio, deslocamento), categoria_do_modelo=j.categoria,
            confianca=round(j.confianca, 2), origem=j.origem, destino=j.destino,
            features={coluna: _arredondado(valor) for coluna, valor in zip(COLUNAS, j.valores, strict=True)},
        )
        for posicao, j in guardadas
    )
    lote = LoteDeJanelas(janelas=sum(incidente.por_categoria.values()), por_categoria=dict(incidente.por_categoria))
    perfil = {nome: round(float(v), 4) for nome, v in medianas.items() if _finito(float(v)) is not None}
    descricao = (
        f"Incidente de {dados.categoria} reconstruído do pcap {arquivo}: {len(incidente.ataque)} janelas de ataque, "
        f"da {incidente.ataque[0].indice} à {incidente.ataque[-1].indice}."
    )
    return Cenario(
        nome=f"{arquivo}:{identificador}", descricao=descricao, incidente=dados, lote=lote,
        efeitos=EFEITOS_DO_REPLAY, quadros_por_janela=JANELA, perfil=perfil, janelas_reais=reais,
    )


def cenarios_da_reproducao(reproducao, classificador, referencia=None, primeiro=1, deslocamento=0.0):
    """Os cenários dos incidentes, numerados a partir de `primeiro`, no relógio dado por `deslocamento`."""
    referencia = referencia if referencia is not None else ler_referencia()
    return [
        montar_cenario(incidente, f"inc-{numero:04d}", classificador, referencia, reproducao.arquivo, deslocamento, reproducao.fundo)
        for numero, incidente in enumerate(reproducao.incidentes, start=primeiro)
    ]


def caminho_dos_cenarios(caminho_do_log):
    """Onde ficam os cenários de um log: ao lado dele, com `.cenarios.json` no lugar de `.jsonl`."""
    caminho = Path(caminho_do_log)
    return caminho.with_name(caminho.stem + ".cenarios.json")


def _lote(contagem):
    contagem = Counter({categoria: n for categoria, n in contagem.items() if n > 0})
    return LoteDeJanelas(janelas=sum(contagem.values()), por_categoria=dict(contagem)) if contagem else None


def gravar(reproducao, classificador, caminho_do_log, *, referencia=None, relogio=agora):
    """Grava a reprodução no log, na ordem em que aconteceu, e os cenários ao lado dele.

    Tudo é decidido com o log travado (`Registro.atualizar`): a numeração continua do maior
    `inc-` que o log já tem, e o relógio de reprodução começa depois do último evento dele. Para
    cada incidente vão o lote das janelas classificadas até ele abrir, a abertura com o estado
    daquele momento e, se ele cresceu depois, uma atualização com o estado final, no instante da
    última janela dele. No fim, o lote das janelas restantes. Devolve os cenários e o deslocamento
    do relógio.
    """
    referencia = referencia if referencia is not None else ler_referencia()
    registro = Registro(caminho_do_log, relogio=relogio)
    feitos = {}

    def decidir(eventos):
        abertos_no_log = [e.incidente for e in eventos if e.tipo == "incidente_aberto" and e.incidente]
        numeros = [int(i.removeprefix("inc-")) for i in abertos_no_log if i.removeprefix("inc-").isdigit()]
        primeiro = max(numeros, default=0) + 1
        fim_do_pcap = reproducao.fim if reproducao.fim is not None else 0.0
        inicio_do_pcap = reproducao.inicio if reproducao.inicio is not None else 0.0
        agora_ = relogio().timestamp()
        deslocamento = agora_ - fim_do_pcap
        if eventos:
            # O log não volta no tempo: a reprodução começa, no mínimo, no último evento dele.
            deslocamento = max(deslocamento, eventos[-1].instante.timestamp() - inicio_do_pcap)
        cenarios = cenarios_da_reproducao(reproducao, classificador, referencia, primeiro, deslocamento)
        marcados = []
        anterior = Counter()
        for ordem, (cenario, incidente) in enumerate(zip(cenarios, reproducao.incidentes, strict=True)):
            identificador = cenario.incidente.id
            abertura, _ = montar_incidente(incidente.abertura, identificador, classificador, referencia, deslocamento, reproducao.fundo)
            quando = _instante(incidente.aberto_em, deslocamento)
            lote = _lote(incidente.janelas_ate_abrir - anterior)
            anterior = incidente.janelas_ate_abrir
            if lote is not None:
                marcados.append((quando, 2 * ordem, novo("janelas_classificadas", lote)))
            marcados.append((quando, 2 * ordem + 1, novo("incidente_aberto", abertura, identificador)))
            if cenario.incidente != abertura:
                final = _instante(incidente.ataque[-1].fim, deslocamento)
                marcados.append((final, 2 * ordem + 1, novo("incidente_atualizado", cenario.incidente, identificador)))
        resto = _lote(reproducao.por_categoria - anterior)
        if resto is not None:
            marcados.append((_instante(fim_do_pcap, deslocamento), 2 * len(cenarios) + 2, novo("janelas_classificadas", resto)))
        marcados.sort(key=lambda item: (item[0], item[1]))
        feitos.update(cenarios=cenarios, deslocamento=deslocamento)
        return None, [{**rascunho, "instante": quando} for quando, _, rascunho in marcados]

    registro.atualizar(decidir)
    # Os cenários vão ao lado do log, somados aos de reproduções anteriores no mesmo log, para o
    # servidor (`python -m codigo.mcp.stub --cenarios`) atender todos os incidentes dele.
    cenarios = feitos["cenarios"]
    destino = caminho_dos_cenarios(caminho_do_log)
    novos = {c.incidente.id for c in cenarios}
    anteriores = [c for c in ler_cenarios(destino) if c.incidente.id not in novos] if destino.exists() else []
    gravar_cenarios([*anteriores, *cenarios], destino)
    return cenarios, feitos["deslocamento"]


def resumo(
    reproducao, cenarios, classificador, deslocamento=0.0, fecha_apos=FECHA_APOS, silencio_s=SILENCIO_S,
    reagrupa_s=REAGRUPA_S, teto=TETO_DE_INCIDENTES, a_partir_da_janela=0, duracao_maxima_s=DURACAO_MAXIMA_S,
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
            "primeira_janela_de_ataque": _instante(reproduzido.primeira_janela_de_ataque, deslocamento).isoformat(),
            "aberto_em": _instante(reproduzido.aberto_em, deslocamento).isoformat(),
            "atraso_de_deteccao_s": round(reproduzido.aberto_em - reproduzido.primeira_janela_de_ataque, 3),
            "reaberturas": reproduzido.reaberturas,
        })
    return {
        "arquivo": reproducao.arquivo,
        "quadros": reproducao.quadros,
        "ignorados": reproducao.ignorados,
        "janelas": reproducao.janelas,
        "janelas_puladas": reproducao.puladas,
        "janelas_incompletas": reproducao.incompletas,
        "por_categoria": dict(reproducao.por_categoria.most_common()),
        "janelas_nao_julgadas": sum(reproducao.nao_julgadas.values()),
        "nao_julgadas_por_categoria": dict(reproducao.nao_julgadas.most_common()),
        "duracao_do_pcap_s": round(duracao, 3),
        "processamento_s": round(reproducao.segundos, 3),
        "relogio": {
            "deslocamento_s": round(deslocamento, 6),
            "inicio_no_pcap": _instante(reproducao.inicio, 0).isoformat() if reproducao.inicio is not None else None,
            "fim_no_pcap": _instante(reproducao.fim, 0).isoformat() if reproducao.fim is not None else None,
        },
        "trecho": {"a_partir_da_janela": a_partir_da_janela, "so_teste": a_partir_da_janela > 0},
        "modelo": classificador.arquivo,
        "ponto_de_operacao": {
            "regra": classificador.ponto.regra, "limiar": classificador.ponto.limiar, "seguidas": classificador.ponto.seguidas,
        },
        "acionamento": {
            "fecha_apos": fecha_apos, "silencio_s": silencio_s, "duracao_maxima_s": duracao_maxima_s,
            "reagrupa_s": reagrupa_s, "teto": teto, "parcela_da_maior_origem": PARCELA_DA_MAIOR_ORIGEM,
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
