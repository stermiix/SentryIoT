"""Incidentes de exemplo do stub.

Quatro cenários, um por situação que os agentes precisam saber tratar: um flood em que a
primeira ação não resolve, um ataque de força bruta, uma varredura de portas e um falso
positivo.

Todos os números deste módulo são ilustrativos. Foram escolhidos para parecer com o tráfego de
cada situação e para fechar entre si (janelas, quadros, taxa e duração), mas não saíram do
classificador nem de uma captura, e não podem ser citados como resultado. Os endereços são das
faixas reservadas para documentação e da rede local de exemplo.

Cada cenário traz o roteiro do que acontece depois de cada ação aplicada: `efeitos` diz o que
`verificar_efeito` responde depois da primeira ação, da segunda, e assim por diante. O efeito
depende só da ordem das ações, não de qual ação foi escolhida.
"""
import ipaddress
import random
from dataclasses import dataclass
from datetime import UTC, datetime

from codigo.captura.extrator import COLUNAS, CONTAGENS
from codigo.mcp.tipos import Incidente, Janela, LoteDeJanelas

# Faixas reservadas para documentação e a rede local usada nos exemplos do projeto.
REDES_DE_EXEMPLO = tuple(
    ipaddress.ip_network(rede) for rede in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "192.168.137.0/24")
)
# Quanto o incidente cresce, em relação ao tamanho inicial, a cada verificação em que não cessou.
_CRESCIMENTO = {"persiste": 1.0, "diminuiu": 0.3}


@dataclass(frozen=True)
class Cenario:
    nome: str
    descricao: str
    incidente: Incidente
    # O lote de janelas que saiu do classificador e deu origem ao incidente.
    lote: LoteDeJanelas
    # Resultado de `verificar_efeito` depois da primeira ação aplicada, da segunda etc.
    efeitos: tuple
    # Tamanho da janela do extrator: 100 quadros nos floods e 10 nas demais classes.
    quadros_por_janela: int
    # Valor típico, na janela, das features que não são zero nem calculadas a partir de outras.
    perfil: dict


def _instante(hora, minuto, segundo):
    return datetime(2026, 10, 20, hora, minuto, segundo, tzinfo=UTC)


def _contados(*pares):
    return [{"endereco": endereco, "quadros": quadros} for endereco, quadros in pares]


def _principais(*trios):
    return [{"nome": nome, "valor": valor, "referencia_benigno": referencia} for nome, valor, referencia in trios]


CENARIOS = (
    Cenario(
        nome="flood",
        descricao=(
            "Flood de pacotes SYN contra um dispositivo, vindo de 37 origens. O modelo diz DoS, e a regra "
            "das origens corrige para DDoS. Bloquear uma origem não resolve: a primeira ação aplicada "
            "deixa o incidente como está, e só a segunda faz o tráfego cessar."
        ),
        incidente=Incidente(
            id="inc-0001",
            estado="aberto",
            categoria="DDoS",
            categoria_do_modelo="DoS",
            confianca=0.97,
            inicio=_instante(14, 3, 11),
            fim=_instante(14, 3, 41),
            janelas=10_734,
            origens_distintas=37,
            distribuido=True,
            origens=_contados(
                ("203.0.113.7", 61_240), ("203.0.113.18", 58_910), ("198.51.100.4", 55_376),
                ("198.51.100.77", 49_822), ("192.0.2.61", 44_105),
            ),
            destinos=_contados(("192.168.137.20", 1_073_352)),
            features_principais=_principais(
                ("Rate", 35778.4, 96.2), ("syn_flag_number", 1.0, 0.06), ("IAT", 0.000028, 0.0104),
                ("Tot size", 54.0, 310.5),
            ),
        ),
        lote=LoteDeJanelas(janelas=10_946, por_categoria={"DoS": 10_734, "Benign": 212}),
        efeitos=("persiste", "cessou"),
        quadros_por_janela=100,
        perfil={
            "Header_Length": 20.0, "Protocol Type": 6, "Time_To_Live": 58.4, "Rate": 35778.4,
            "syn_flag_number": 1.0, "HTTP": 1.0, "TCP": 1.0, "IPv": 1.0, "LLC": 1.0,
            "Min": 54, "Max": 54, "AVG": 54.0, "Std": 0.0,
        },
    ),
    Cenario(
        nome="forca_bruta",
        descricao=(
            "Ataque de dicionário contra o SSH de um dispositivo, vindo de uma origem só. A primeira ação "
            "aplicada faz o tráfego cessar."
        ),
        incidente=Incidente(
            id="inc-0002",
            estado="aberto",
            categoria="BruteForce",
            categoria_do_modelo="BruteForce",
            confianca=0.91,
            inicio=_instante(15, 12, 4),
            fim=_instante(15, 14, 36),
            janelas=180,
            origens_distintas=1,
            distribuido=False,
            origens=_contados(("198.51.100.23", 912)),
            destinos=_contados(("192.168.137.31", 912)),
            features_principais=_principais(
                ("SSH", 1.0, 0.02), ("Rate", 11.8, 96.2), ("psh_flag_number", 0.4, 0.21), ("Tot size", 98.4, 310.5),
            ),
        ),
        lote=LoteDeJanelas(janelas=244, por_categoria={"BruteForce": 180, "Benign": 64}),
        efeitos=("cessou",),
        quadros_por_janela=10,
        perfil={
            "Header_Length": 32.0, "Protocol Type": 6, "Time_To_Live": 64.0, "Rate": 11.8,
            "fin_flag_number": 0.1, "syn_flag_number": 0.1, "psh_flag_number": 0.4, "ack_flag_number": 0.9,
            "SSH": 1.0, "TCP": 1.0, "IPv": 1.0, "LLC": 1.0,
            "Min": 66, "Max": 162, "AVG": 98.4, "Std": 31.2,
        },
    ),
    Cenario(
        nome="varredura",
        descricao=(
            "Varredura de portas em quatro dispositivos da rede, vinda de uma origem só. A primeira ação "
            "aplicada faz o tráfego diminuir, e a segunda faz cessar."
        ),
        incidente=Incidente(
            id="inc-0003",
            estado="aberto",
            categoria="Recon",
            categoria_do_modelo="Recon",
            confianca=0.88,
            inicio=_instante(16, 40, 10),
            fim=_instante(16, 41, 9),
            janelas=96,
            origens_distintas=1,
            distribuido=False,
            origens=_contados(("192.0.2.45", 480)),
            destinos=_contados(
                ("192.168.137.20", 122), ("192.168.137.31", 120), ("192.168.137.42", 119), ("192.168.137.1", 119),
            ),
            features_principais=_principais(
                ("syn_flag_number", 0.5, 0.06), ("rst_flag_number", 0.5, 0.01), ("Tot size", 57.0, 310.5),
                ("Rate", 16.2, 96.2),
            ),
        ),
        lote=LoteDeJanelas(janelas=147, por_categoria={"Recon": 96, "Benign": 51}),
        efeitos=("diminuiu", "cessou"),
        quadros_por_janela=10,
        perfil={
            "Header_Length": 22.0, "Protocol Type": 6, "Time_To_Live": 58.0, "Rate": 16.2,
            "syn_flag_number": 0.5, "rst_flag_number": 0.5, "ack_flag_number": 0.5,
            "HTTP": 0.1, "HTTPS": 0.1, "Telnet": 0.1, "SSH": 0.1, "TCP": 1.0, "IPv": 1.0, "LLC": 1.0,
            "Min": 54, "Max": 60, "AVG": 57.0, "Std": 3.2,
        },
    ),
    Cenario(
        nome="falso_positivo",
        descricao=(
            "Falso positivo: uma câmera da rede envia vídeo para o servidor de costume, e o modelo aponta "
            "DoS com confiança baixa. Não há ataque. O esperado é a triagem apontar a dúvida e nenhuma "
            "ação de risco alto ser proposta."
        ),
        incidente=Incidente(
            id="inc-0004",
            estado="aberto",
            categoria="DoS",
            categoria_do_modelo="DoS",
            confianca=0.58,
            inicio=_instante(17, 25, 30),
            fim=_instante(17, 25, 33),
            janelas=9,
            origens_distintas=1,
            distribuido=False,
            origens=_contados(("192.168.137.42", 900)),
            destinos=_contados(("198.51.100.90", 900)),
            features_principais=_principais(
                ("Rate", 310.4, 96.2), ("Tot size", 1242.0, 310.5), ("ack_flag_number", 1.0, 0.62),
                ("syn_flag_number", 0.0, 0.06),
            ),
        ),
        lote=LoteDeJanelas(janelas=152, por_categoria={"DoS": 9, "Benign": 143}),
        efeitos=("cessou",),
        quadros_por_janela=100,
        perfil={
            "Header_Length": 32.0, "Protocol Type": 6, "Time_To_Live": 64.0, "Rate": 310.4,
            "psh_flag_number": 0.3, "ack_flag_number": 1.0, "HTTPS": 1.0, "TCP": 1.0, "IPv": 1.0, "LLC": 1.0,
            "Min": 66, "Max": 1514, "AVG": 1242.0, "Std": 520.0,
        },
    ),
)
_POR_INCIDENTE = {cenario.incidente.id: cenario for cenario in CENARIOS}


def cenario_do_incidente(identificador):
    """O cenário a que o incidente pertence, ou None se o identificador não é de nenhum."""
    return _POR_INCIDENTE.get(identificador)


def efeito(cenario, ordem):
    """Resultado da verificação depois da ação de número `ordem` aplicada no incidente (a partir de 1).

    Depois que o roteiro acaba, vale o último resultado.
    """
    return cenario.efeitos[min(ordem, len(cenario.efeitos)) - 1]


def evoluir(cenario, incidente, resultado, aplicada_em=None):
    """O incidente depois de uma verificação de efeito.

    Se o tráfego cessou, o incidente é encerrado. Se persiste ou diminuiu, ele continua aberto
    por mais um período igual ao inicial, com mais janelas e mais quadros.

    `aplicada_em` é o instante em que a ação verificada foi aplicada. O incidente nunca termina
    antes dele: se cessou, foi quando a ação entrou; se continua, ainda havia tráfego depois dela.
    """
    def fim(calculado):
        return calculado if aplicada_em is None else max(calculado, aplicada_em)

    if resultado == "cessou":
        return incidente.model_copy(update={"estado": "encerrado", "fim": fim(incidente.fim)})
    inicial = cenario.incidente
    fator = _CRESCIMENTO[resultado]

    def crescer(atuais, de_partida):
        return [
            atual.model_copy(update={"quadros": atual.quadros + round(partida.quadros * fator)})
            for atual, partida in zip(atuais, de_partida, strict=True)
        ]

    return incidente.model_copy(update={
        "fim": fim(incidente.fim + (inicial.fim - inicial.inicio)),
        "janelas": incidente.janelas + round(inicial.janelas * fator),
        "origens": crescer(incidente.origens, inicial.origens),
        "destinos": crescer(incidente.destinos, inicial.destinos),
    })


def janelas(cenario, incidente, limite):
    """Até `limite` janelas do incidente, espaçadas do começo ao fim dele.

    A janela de um índice sai sempre igual: os valores variam em torno do perfil do cenário,
    com um sorteio que tem o identificador do incidente e o índice como semente.
    """
    total = incidente.janelas
    if limite >= total:
        indices = range(total)
    elif limite == 1:
        indices = [0]
    else:
        indices = [posicao * (total - 1) // (limite - 1) for posicao in range(limite)]
    return [_janela(cenario, incidente, indice) for indice in indices]


def _janela(cenario, incidente, indice):
    sorteio = random.Random(f"{incidente.id}:{indice}")
    features = _features(cenario, sorteio)
    confianca = min(1.0, max(0.0, incidente.confianca + sorteio.uniform(-0.04, 0.03)))
    return Janela(
        indice=indice,
        instante=incidente.inicio + (incidente.fim - incidente.inicio) * indice / incidente.janelas,
        categoria_do_modelo=incidente.categoria_do_modelo,
        confianca=round(confianca, 2),
        origem=_sortear_endereco(sorteio, incidente.origens),
        destino=_sortear_endereco(sorteio, incidente.destinos),
        features=features,
    )


def _sortear_endereco(sorteio, contados):
    return sorteio.choices([item.endereco for item in contados], weights=[item.quadros for item in contados])[0]


def _features(cenario, sorteio):
    """As 39 features de uma janela, com as relações que o extrator garante entre as colunas."""
    numero = cenario.quadros_por_janela
    features = dict.fromkeys(COLUNAS, 0.0) | cenario.perfil
    features["Rate"] = round(features["Rate"] * sorteio.uniform(0.92, 1.08), 1)
    features["IAT"] = round(1 / features["Rate"], 6)
    features["Time_To_Live"] = round(features["Time_To_Live"] + sorteio.uniform(-1, 1), 1)
    if features["Std"]:
        # O tamanho médio dos quadros varia de uma janela para outra, sem sair dos extremos.
        media = features["AVG"] * sorteio.uniform(0.97, 1.03)
        features["AVG"] = round(min(features["Max"], max(features["Min"], media)), 1)
        features["Std"] = round(features["Std"] * sorteio.uniform(0.9, 1.1), 1)
    features["Tot size"] = features["AVG"]
    features["Tot sum"] = round(features["AVG"] * numero, 1)
    features["Variance"] = round(features["Std"] ** 2, 2)
    features["Number"] = numero
    for contagem, flag in CONTAGENS:
        features[contagem] = round(features[flag] * numero)
    return features
