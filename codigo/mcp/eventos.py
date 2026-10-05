"""Gravação e leitura do log de eventos do SentryIoT.

O log é um arquivo de texto com um objeto JSON por linha, só de acréscimo. Cada linha segue o
tipo `Evento` de `tipos.py`: `id`, `instante`, `tipo`, `incidente` e `dados`. É dele que a
interface web tira a fila de incidentes, o rastro das tools e os números de custo, ao vivo ou
em replay.

O estado das propostas, das aprovações e das ações ativas não fica na memória de nenhum
processo: é reconstruído a partir do log (ver `acoes.py`). Por isso o servidor, o comando de
aprovação e, mais adiante, a interface web podem trabalhar sobre o mesmo arquivo.

Quem grava o quê: o servidor e o comando de aprovação usam `Registro`, que aceita qualquer evento
do contrato. O código dos agentes recebe `GravadorDoAgente`, que só aceita `llm_chamada` e
`recomendacao_emitida`.
"""
import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from codigo.mcp.tipos import (
    AGENTES,
    ChamadaDeLLM,
    Recomendacao,
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
_DADOS_DO_AGENTE = {"llm_chamada": ChamadaDeLLM, "recomendacao_emitida": Recomendacao}
TIPOS_DO_AGENTE = tuple(_DADOS_DO_AGENTE)
# Caracteres que o JSON deixa passar crus dentro de um texto e que alguns leitores tratam como fim
# de linha (`str.splitlines`, por exemplo). No arquivo eles vão escapados: um evento, uma linha.
_FIM_DE_LINHA_PARA_ALGUNS = {0x85: "\\u0085", 0x2028: "\\u2028", 0x2029: "\\u2029"}


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
            eventos.append(validar_evento(json.loads(linha)))
        except ValueError as erro:
            # O detalhe do erro pode repetir um pedaço da linha: vai escapado, como tudo o que sai do log.
            raise LogInvalido(visivel(f"{caminho}, linha {numero}: evento fora do contrato ({erro})")) from None
        eventos.linhas.append(numero)
    return eventos


def ler(caminho):
    """Lê o log e devolve os eventos na ordem em que foram gravados.

    Arquivo que ainda não existe é um log vazio. Linha que não segue o contrato levanta
    `LogInvalido`, que é um ValueError, com o número da linha.
    """
    try:
        with open(caminho, encoding="utf-8") as arquivo:
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
        falhar, se algum rascunho estiver fora do contrato ou se alguma linha não puder ser
        lida de volta, nada é gravado.

        A trava é a do `fcntl`. Onde ele não existe (Windows), não há trava, e só um processo
        por vez pode usar o arquivo.
        """
        self.caminho.parent.mkdir(parents=True, exist_ok=True)
        with open(self.caminho, "a+", encoding="utf-8") as arquivo:
            if fcntl is not None:
                fcntl.flock(arquivo, fcntl.LOCK_EX)
            arquivo.seek(0)
            eventos = _ler_linhas(arquivo, self.caminho)
            resultado, rascunhos = decidir(eventos)
            instante = self.relogio()
            gravados = [
                validar_evento({"id": f"ev-{numero:06d}", "instante": instante, **rascunho})
                for numero, rascunho in enumerate(rascunhos, start=len(eventos) + 1)
            ]
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

    Aceita `llm_chamada` e `recomendacao_emitida`, sempre em nome do próprio agente, e a
    recomendação só cita proposta que existe no log. Proposta, aprovação, execução e os demais
    eventos são gravados pelo servidor e pelo comando de aprovação, nunca pelo agente.

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
            propostas = {evento.dados.id for evento in eventos if evento.tipo == "acao_proposta"}
            for rascunho in rascunhos:
                self._conferir(rascunho, propostas)
            return None, rascunhos

        return self._registro.atualizar(decidir)[1]

    def _conferir(self, rascunho, propostas):
        tipo = rascunho.get("tipo") if isinstance(rascunho, dict) else None
        if tipo not in _DADOS_DO_AGENTE:
            raise ValueError(
                f"o gravador do agente só aceita {' e '.join(TIPOS_DO_AGENTE)}, e veio {visivel(repr(tipo))[:80]}"
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
        desconhecidas = [proposta for proposta in getattr(dados, "propostas", ()) if proposta not in propostas]
        if desconhecidas:
            raise ValueError(
                f"a recomendação cita proposta que não existe no log: {visivel(', '.join(desconhecidas))[:200]}"
            )

