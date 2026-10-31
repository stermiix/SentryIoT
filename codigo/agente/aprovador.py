"""O aprovador automático dos experimentos e a conferência de cada proposta contra o gabarito.

Nos experimentos ninguém aprova à mão as cerca de 270 rodadas (decisão de 25/10/2026). O aprovador faz o
papel da pessoa, com uma regra fixa: aprova a proposta de risco alto que o gabarito da recomendação
(`experimentos/gabarito_da_recomendacao.toml`) aceita, uma ação aceitável na categoria do incidente sobre
um alvo no papel certo, e rejeita as demais, inclusive a ação nova, que é contada à parte. A decisão vai
para o log como a de uma pessoa (`decidir_no_log`), com o usuário `aprovador-automatico`.

O papel do alvo vem da verdade de campo, e não do que o agente escreveu:

- `origem` é um dos atacantes do dataset, identificados pelo MAC (`codigo/classificador/atacantes.py`).
  Quem chama diz os IPs deles no pcap (`atacantes`): o sistema não conhece os MACs, e só a avaliação,
  como `codigo/reprodutor/avaliar.py`, os usa;
- `destino` é um endereço que o incidente lista entre os destinos e que não é atacante.

Um alvo que não é uma coisa nem outra não tem papel, e a proposta não é aceitável.

`conferir_proposta` é a mesma conferência sem gravar nada. Ela serve à métrica da qualidade da recomendação,
que olha toda proposta, e não só as de risco alto, as únicas que passam pelo aprovador.
"""

import tomllib
from dataclasses import dataclass
from pathlib import Path

from codigo.agente.agentes import decidir_no_log
from codigo.mcp.tipos import endereco_canonico

GABARITO = Path(__file__).resolve().parents[2] / "experimentos" / "gabarito_da_recomendacao.toml"
USUARIO = "aprovador-automatico"
ORIGEM = "origem"
DESTINO = "destino"


def carregar_gabarito(caminho=GABARITO):
    """O gabarito como `{categoria: {acao: frozenset(papeis)}}`."""
    bruto = tomllib.loads(Path(caminho).read_text(encoding="utf-8"))
    return {
        categoria: {acao: frozenset(papeis) for acao, papeis in acoes.items()} for categoria, acoes in bruto.items()
    }


@dataclass(frozen=True)
class Conferencia:
    """O resultado de conferir uma proposta: se é aceitável, o papel do alvo e o porquê, em uma linha."""

    aceitavel: bool
    papel: str | None
    motivo: str


@dataclass(frozen=True)
class DecisaoAutomatica:
    """Uma decisão do aprovador, para o executor dos experimentos contar."""

    proposta: str
    incidente: str
    acao: str
    nova: bool
    conferencia: Conferencia


def _canonico(endereco):
    try:
        return endereco_canonico(str(endereco).strip())
    except ValueError:
        return None


def papel_do_alvo(alvo, destinos, atacantes):
    """O papel do endereço de um alvo (`origem`, `destino` ou None).

    O alvo vem como o servidor o guarda, com o endereço no fim: `198.51.100.23`, `23/tcp@192.168.137.31` ou
    `admin@192.168.137.31`. `destinos` são os endereços que o incidente lista como destino.
    """
    endereco = _canonico(alvo.rpartition("@")[2]) if isinstance(alvo, str) else None
    if endereco is None:
        return None
    if endereco in atacantes:
        return ORIGEM
    if endereco in destinos:
        return DESTINO
    return None


def conferir_proposta(proposta, incidente, atacantes, gabarito):
    """Confere uma proposta contra o gabarito, sem gravar nada. `atacantes` são os IPs canônicos dos atacantes."""
    categoria = incidente.categoria
    if proposta.nova:
        return Conferencia(False, None, "Rejeitada: ação nova, fora do catálogo. Entra na conta à parte, e não na automática.")
    aceitas = gabarito.get(categoria, {})
    if proposta.acao not in aceitas:
        return Conferencia(False, None, f"Rejeitada: o gabarito não aceita {proposta.acao} na categoria {categoria}.")
    destinos = {_canonico(item.endereco) for item in incidente.destinos}
    papel = papel_do_alvo(proposta.alvo, destinos, atacantes)
    if papel is None:
        return Conferencia(
            False, None, "Rejeitada: o alvo não é um atacante do dataset nem um destino listado no incidente."
        )
    if papel not in aceitas[proposta.acao]:
        aceitos = " ou ".join(sorted(aceitas[proposta.acao]))
        return Conferencia(
            False, papel, f"Rejeitada: {proposta.acao} em {categoria} só vale sobre {aceitos}, e o alvo é {papel}."
        )
    return Conferencia(True, papel, f"Aprovada pelo gabarito: {proposta.acao} em {categoria}, com o alvo no papel de {papel}.")


class AprovadorPorGabarito:
    """O aprovador que `orquestrar(aprovador=...)` chama com as propostas que aguardam aprovação.

    `atacantes` são os IPs dos atacantes do dataset no pcap do incidente. Cada decisão fica em `decisoes`.
    """

    def __init__(self, log, atacantes, gabarito=None):
        self.log = log
        self.atacantes = frozenset(_canonico_ou_erro(endereco) for endereco in atacantes)
        self.gabarito = gabarito if gabarito is not None else carregar_gabarito()
        self.decisoes = []

    def __call__(self, estado, pendentes):
        for proposta in pendentes:
            conferencia = conferir_proposta(proposta, estado.incidentes[proposta.incidente], self.atacantes, self.gabarito)
            decidir_no_log(self.log, proposta.id, conferencia.aceitavel, usuario=USUARIO, motivo=conferencia.motivo)
            self.decisoes.append(
                DecisaoAutomatica(proposta.id, proposta.incidente, proposta.acao, proposta.nova, conferencia)
            )


def _canonico_ou_erro(endereco):
    canonico = _canonico(endereco)
    if canonico is None:
        raise ValueError(f"atacante com endereço inválido: {endereco!r}")
    return canonico
