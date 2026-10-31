"""Gravação e leitura do log de eventos do SentryIoT.

O log é um arquivo de texto com um objeto JSON por linha, só de acréscimo. Cada linha segue o
tipo `Evento` de `tipos.py`: `id`, `instante`, `tipo`, `incidente` e `dados`. É dele que a
interface web tira a fila de incidentes, o rastro das tools e os números de custo, ao vivo ou
em replay.

O estado das propostas, das aprovações e das ações ativas não fica na memória de nenhum
processo: é reconstruído a partir do log (ver `acoes.py`). Por isso o servidor, o comando de
aprovação e, mais adiante, a interface web podem trabalhar sobre o mesmo arquivo.

Quem grava o quê: o servidor e o comando de aprovação usam `Registro`, que aceita qualquer evento
do contrato. O código dos agentes recebe `GravadorDoAgente`, que só aceita `llm_chamada`,
`agente_concluido` e `recomendacao_emitida`.
"""
import errno
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from codigo.mcp.tipos import (
    AGENTES,
    AnaliseDaTriagem,
    ChamadaDeLLM,
    ConclusaoDoAgente,
    Recomendacao,
    Sumario,
    validar_evento,
    visivel,
)

try:
    import fcntl
except ImportError:  # No Windows não existe fcntl: a gravação segue sem a trava do arquivo.
    fcntl = None

RAIZ = Path(__file__).resolve().parents[2]
# Fica em dados/, fora do git: o log de uma execução é dado de trabalho, não resultado.
CAMINHO_PADRAO = RAIZ / "dados" / "eventos" / "eventos.jsonl"
# O que o código de um agente pode gravar, e o formato dos dados de cada tipo.
_DADOS_DO_AGENTE = {
    "llm_chamada": ChamadaDeLLM, "agente_concluido": ConclusaoDoAgente, "analise_emitida": AnaliseDaTriagem,
    "recomendacao_emitida": Recomendacao, "sumario_emitido": Sumario,
}
TIPOS_DO_AGENTE = tuple(_DADOS_DO_AGENTE)
# Caracteres que o JSON deixa passar crus dentro de um texto e que alguns leitores tratam como fim
# de linha (`str.splitlines`, por exemplo). No arquivo eles vão escapados: um evento, uma linha.
_FIM_DE_LINHA_PARA_ALGUNS = {0x85: "\\u0085", 0x2028: "\\u2028", 0x2029: "\\u2029"}
# O arquivo do log nunca é aberto através de um link simbólico. Onde a opção não existe (Windows), o
# caminho é aberto como vem.
_SEM_SEGUIR_LINK = getattr(os, "O_NOFOLLOW", 0)
# Onde está o incidente dentro de `dados`, nos tipos de evento que o trazem sem depender do estado.
# Nos demais (aprovação, promoção, recomendação), quem confere é a reconstrução (`acoes.reconstruir`).
_INCIDENTE_DOS_DADOS = {
    "incidente_aberto": "id", "incidente_atualizado": "id", "incidente_encerrado": "id",
    "acao_proposta": "incidente", "acao_executada": "incidente", "acao_desfeita": "incidente",
    "efeito_verificado": "incidente", "incidente_marcado_resolvido": "incidente",
}


class LogInvalido(ValueError):
    """O log de eventos não pode ser usado como está.

    Vale para linha fora do contrato e para evento que não cabe no ponto em que aparece, como
    a aprovação de uma proposta que não existe. A mensagem traz o arquivo e o número da linha.
    """


def agora():
    """Instante atual, em UTC."""
    return datetime.now(UTC)


def novo(tipo, dados, incidente=None):
    """Rascunho de um evento. O identificador e o instante são postos na hora de gravar."""
    return {"tipo": tipo, "incidente": incidente, "dados": dados}


class EventosLidos(list):
    """Os eventos de um arquivo de log, na ordem das linhas, com a linha de onde cada um saiu.

    É uma lista como outra qualquer. O que ela guarda a mais serve para que um erro encontrado
    depois da leitura, na sequência dos eventos, aponte o arquivo e a linha.
    """

    def __init__(self, caminho):
        super().__init__()
        self.caminho = caminho
        self.linhas = []
        # Falso quando a última linha do arquivo não termina em quebra de linha.
        self.termina_em_quebra = True

    def onde(self, indice):
        """Arquivo e linha do evento de posição `indice`, para mensagens de erro."""
        return f"{self.caminho}, linha {self.linhas[indice]}"


def _ler_linhas(arquivo, caminho):
    eventos = EventosLidos(caminho)
    for numero, linha in enumerate(arquivo, start=1):
        eventos.termina_em_quebra = linha.endswith("\n")
        if not linha.strip():
            continue
        try:
            evento = validar_evento(json.loads(linha))
        except ValueError as erro:
            detalhe = _resumo_do_erro(erro)
            raise LogInvalido(f"{caminho}, linha {numero}: evento fora do contrato ({detalhe})") from None
        problema = _fora_de_sequencia(evento, eventos[-1] if eventos else None, len(eventos) + 1)
        if problema is not None:
            raise LogInvalido(f"{caminho}, linha {numero}: {problema}")
        eventos.append(evento)
        eventos.linhas.append(numero)
    return eventos


def identificador(numero):
    """O identificador do evento de posição `numero` no arquivo, a partir de 1."""
    return f"ev-{numero:06d}"


def _fora_de_sequencia(evento, anterior, posicao):
    """O que impede o evento de estar nesta posição do arquivo, ou None se ele cabe.

    O identificador é a posição do evento, o instante não volta no tempo e o campo `incidente` é o
    mesmo que vem dentro de `dados`. Assim, uma linha apagada no meio, linhas trocadas de lugar ou
    repetidas e um evento posto no rastro de outro incidente aparecem na leitura. Apagar as últimas
    linhas do arquivo não aparece: o README registra esse limite.
    """
    if evento.id != identificador(posicao):
        return (
            f"o evento traz o identificador {visivel(evento.id)[:40]}, e o desta posição é {identificador(posicao)}: "
            "há linha apagada, repetida ou fora de ordem"
        )
    if anterior is not None and evento.instante < anterior.instante:
        return f"o instante do evento {evento.id} é anterior ao do evento {anterior.id}"
    campo = _INCIDENTE_DOS_DADOS.get(evento.tipo)
    if campo is not None and evento.incidente != getattr(evento.dados, campo):
        return (
            f"o evento {evento.id} diz que é do incidente {evento.incidente}, e os dados são do incidente "
            f"{getattr(evento.dados, campo)}"
        )
    return None


def _resumo_do_erro(erro, maximo=3):
    """O que está errado na linha, em uma linha: os campos e o defeito de cada um, sem o valor lido.

    A mensagem vai para o terminal de quem opera o sistema. O que estava no log, que é entrada,
    não é repetido nela, e o que sobrar de fora sai escapado.
    """
    if not isinstance(erro, ValidationError):
        return visivel(erro)[:300]
    defeitos = erro.errors(include_url=False, include_input=False, include_context=False)
    partes = [f"{'.'.join(str(parte) for parte in defeito['loc'])}: {defeito['type']}" for defeito in defeitos[:maximo]]
    if len(defeitos) > maximo:
        partes.append(f"e mais {len(defeitos) - maximo}")
    return visivel("; ".join(partes))[:300]


def _abrir(caminho, gravar=False):
    """Abre o arquivo do log sem seguir link simbólico.

    Para gravar, o arquivo que ainda não existe é criado só com leitura e escrita para o dono
    (0600): o log traz endereços, alvos e contas da rede. Um link simbólico no lugar do log, mesmo
    pendente, é recusado, para que o log não seja escrito em outro arquivo.
    """
    modo = os.O_RDWR | os.O_CREAT | os.O_APPEND if gravar else os.O_RDONLY
    try:
        descritor = os.open(caminho, modo | _SEM_SEGUIR_LINK, 0o600)
    except OSError as erro:
        if erro.errno == errno.ELOOP:
            raise OSError(f"o log de eventos não pode ser um link simbólico: {caminho}") from None
        raise
    return open(descritor, "a+" if gravar else "r", encoding="utf-8")


def ler(caminho):
    """Lê o log e devolve os eventos na ordem em que foram gravados.

    Arquivo que ainda não existe é um log vazio. Linha que não segue o contrato levanta
    `LogInvalido`, que é um ValueError, com o número da linha.
    """
    try:
        with _abrir(caminho) as arquivo:
            return _ler_linhas(arquivo, caminho)
    except FileNotFoundError:
        return EventosLidos(caminho)


class Registro:
    """O log de eventos em um arquivo.

    `relogio` é a função que dá o instante de cada gravação. Trocá-la permite gravar um log
    com instantes fixos, como o do exemplo versionado.
    """

    def __init__(self, caminho=CAMINHO_PADRAO, relogio=agora):
        self.caminho = Path(caminho)
        self.relogio = relogio

    def ler(self):
        return ler(self.caminho)

    def gravar(self, *rascunhos):
        """Acrescenta os eventos ao log e os devolve com identificador e instante."""
        return self.atualizar(lambda _eventos: (None, rascunhos))[1]

    def atualizar(self, decidir):
        """Lê o log, chama `decidir(eventos)` e grava o que ela pedir, sem intervalo no meio.

        `decidir` devolve um par: o resultado, que é repassado a quem chamou, e os rascunhos
        dos eventos a gravar. O arquivo fica travado da leitura até a gravação, para que dois
        processos não decidam sobre o mesmo estado nem repitam um identificador. Se `decidir`
        falhar, se algum rascunho estiver fora do contrato, fora da sequência do log ou se alguma
        linha não puder ser lida de volta, nada é gravado.

        A trava é a do `fcntl`. Onde ele não existe (Windows), não há trava: só um processo por
        vez deve usar o arquivo, e isso não é conferido.
        """
        # A pasta que o log cria é só do dono, como o arquivo.
        self.caminho.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with _abrir(self.caminho, gravar=True) as arquivo:
            if fcntl is not None:
                fcntl.flock(arquivo, fcntl.LOCK_EX)
            arquivo.seek(0)
            eventos = _ler_linhas(arquivo, self.caminho)
            resultado, rascunhos = decidir(eventos)
            # O relógio da máquina pode ser acertado para trás. O log não volta: o evento novo fica, no
            # mínimo, com o instante do último.
            instante = max(self.relogio(), eventos[-1].instante) if eventos else self.relogio()
            # A numeração continua do último identificador do arquivo, que a leitura já conferiu.
            primeiro = int(eventos[-1].id.removeprefix("ev-")) + 1 if eventos else 1
            gravados = [
                validar_evento({"id": identificador(numero), "instante": instante, **rascunho})
                for numero, rascunho in enumerate(rascunhos, start=primeiro)
            ]
            anterior = eventos[-1] if eventos else None
            for numero, evento in enumerate(gravados, start=primeiro):
                problema = _fora_de_sequencia(evento, anterior, numero)
                if problema is not None:
                    raise ValueError(f"o evento {evento.id}, do tipo {evento.tipo}, não pode ser gravado: {problema}")
                anterior = evento
            linhas = [_linha(evento) for evento in gravados]
            if linhas:
                # Arquivo que não termina em quebra de linha (cortado, ou editado à mão) ganha a
                # quebra antes: sem ela, o evento novo ficaria colado ao último.
                inicio = "" if eventos.termina_em_quebra else "\n"
                # Uma escrita só para o lote inteiro: ou entram todas as linhas, ou nenhuma.
                arquivo.write(inicio + "".join(linhas))
        return resultado, gravados


def _linha(evento):
    """A linha do evento no arquivo, já conferida: lida de volta, ela dá o mesmo evento.

    Sem a conferência, um valor que o leitor não aceita (um inteiro de milhares de dígitos em um
    campo livre, por exemplo) seria gravado, e a partir daí o log inteiro deixaria de ser lido.
    """
    try:
        linha = evento.model_dump_json().translate(_FIM_DE_LINHA_PARA_ALGUNS)
        relido = validar_evento(json.loads(linha))
    except (ValueError, RecursionError) as erro:
        detalhe = visivel(str(erro))[:200]
        raise ValueError(
            f"o evento {evento.id}, do tipo {evento.tipo}, não pode ser gravado: o log não o leria de volta "
            f"({type(erro).__name__}: {detalhe})"
        ) from None
    if relido != evento:
        raise ValueError(
            f"o evento {evento.id}, do tipo {evento.tipo}, não pode ser gravado: lido de volta, sairia diferente"
        )
    return linha + "\n"


class GravadorDoAgente:
    """O que o código de um agente recebe para gravar no log: só o que é dele.

    Aceita `llm_chamada`, `agente_concluido`, `analise_emitida`, `recomendacao_emitida` e `sumario_emitido`,
    sempre em nome do próprio agente (a análise e o sumário são da triagem),
    num incidente que existe no log (ou sem incidente), e a recomendação só cita proposta que existe e
    é do mesmo incidente. Proposta, aprovação, execução e os demais eventos são gravados pelo servidor
    e pelo comando de aprovação, nunca pelo agente.

    É uma restrição de interface, e não do sistema operacional: um processo que consegue escrever
    no arquivo consegue escrever qualquer linha. Esse limite do stub está declarado no README.
    """

    def __init__(self, agente, caminho=CAMINHO_PADRAO, relogio=agora):
        if agente not in AGENTES:
            raise ValueError(f"agente desconhecido: {agente!r}")
        self._agente = agente
        self._registro = Registro(caminho, relogio)

    @property
    def agente(self):
        return self._agente

    @property
    def caminho(self):
        return self._registro.caminho

    def gravar(self, *rascunhos):
        """Acrescenta os eventos ao log e os devolve com identificador e instante.

        Se algum rascunho não for do agente, nenhum é gravado.
        """
        def decidir(eventos):
            incidentes = {evento.dados.id for evento in eventos if evento.tipo == "incidente_aberto"}
            propostas = {evento.dados.id: evento.dados.incidente for evento in eventos if evento.tipo == "acao_proposta"}
            for rascunho in rascunhos:
                self._conferir(rascunho, incidentes, propostas)
            return None, rascunhos

        return self._registro.atualizar(decidir)[1]

    def _conferir(self, rascunho, incidentes, propostas):
        tipo = rascunho.get("tipo") if isinstance(rascunho, dict) else None
        if tipo not in _DADOS_DO_AGENTE:
            aceitos = f"{', '.join(TIPOS_DO_AGENTE[:-1])} e {TIPOS_DO_AGENTE[-1]}"
            raise ValueError(
                f"o gravador do agente só aceita {aceitos}, e veio {visivel(repr(tipo))[:80]}"
            )
        try:
            dados = _DADOS_DO_AGENTE[tipo].model_validate(rascunho.get("dados"))
        except ValidationError as erro:
            campos = sorted({str(defeito["loc"][0]) if defeito["loc"] else "dados" for defeito in erro.errors()})
            raise ValueError(
                f"{tipo} fora do contrato. Confira: {visivel(', '.join(campos))[:200]}"
            ) from None
        if dados.agente != self._agente:
            raise ValueError(
                f"este gravador é do agente de {self._agente} e não grava {tipo} em nome do agente de {dados.agente}"
            )
        incidente = rascunho.get("incidente")
        if incidente is not None and incidente not in incidentes:
            raise ValueError(f"o incidente {visivel(repr(incidente))[:80]} não existe no log")
        citadas = getattr(dados, "propostas", ())
        desconhecidas = [proposta for proposta in citadas if proposta not in propostas]
        if desconhecidas:
            raise ValueError(
                f"a recomendação cita proposta que não existe no log: {visivel(', '.join(desconhecidas))[:200]}"
            )
        de_outro = [f"{proposta}, do incidente {propostas[proposta]}" for proposta in citadas if propostas[proposta] != incidente]
        if de_outro:
            raise ValueError(
                f"a recomendação, no incidente {visivel(incidente)}, cita proposta de outro incidente: "
                f"{visivel('; '.join(de_outro))[:200]}"
            )

