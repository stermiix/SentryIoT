"""Gravação e leitura do log de eventos do SentryIoT.

O log é um arquivo de texto com um objeto JSON por linha, só de acréscimo. Cada linha segue o
tipo `Evento` de `tipos.py`: `id`, `instante`, `tipo`, `incidente` e `dados`. É dele que a
interface web tira a fila de incidentes, o rastro das tools e os números de custo, ao vivo ou
em replay.

O estado das propostas, das aprovações e das ações ativas não fica na memória de nenhum
processo: é reconstruído a partir do log (ver `acoes.py`). Por isso o servidor, o comando de
aprovação e, mais adiante, a interface web podem trabalhar sobre o mesmo arquivo.
"""
import json
from datetime import UTC, datetime
from pathlib import Path

from codigo.mcp.tipos import validar_evento

try:
    import fcntl
except ImportError:  # No Windows não existe fcntl: a gravação segue sem a trava do arquivo.
    fcntl = None

RAIZ = Path(__file__).resolve().parents[2]
# Fica em dados/, fora do git: o log de uma execução é dado de trabalho, não resultado.
CAMINHO_PADRAO = RAIZ / "dados" / "eventos" / "eventos.jsonl"


def agora():
    """Instante atual, em UTC."""
    return datetime.now(UTC)


def novo(tipo, dados, incidente=None):
    """Rascunho de um evento. O identificador e o instante são postos na hora de gravar."""
    return {"tipo": tipo, "incidente": incidente, "dados": dados}


def _ler_linhas(arquivo, caminho):
    eventos = []
    for numero, linha in enumerate(arquivo, start=1):
        if not linha.strip():
            continue
        try:
            eventos.append(validar_evento(json.loads(linha)))
        except ValueError as erro:
            raise ValueError(f"{caminho}, linha {numero}: evento fora do contrato ({erro})") from None
    return eventos


def ler(caminho):
    """Lê o log e devolve os eventos na ordem em que foram gravados.

    Arquivo que ainda não existe é um log vazio. Linha que não segue o contrato levanta
    ValueError com o número da linha.
    """
    try:
        with open(caminho, encoding="utf-8") as arquivo:
            return _ler_linhas(arquivo, caminho)
    except FileNotFoundError:
        return []


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
        falhar ou algum rascunho estiver fora do contrato, nada é gravado.
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
            # Uma escrita só para o lote inteiro: ou entram todas as linhas, ou nenhuma.
            arquivo.write("".join(_linha(evento) for evento in gravados))
        return resultado, gravados


def _linha(evento):
    return evento.model_dump_json() + "\n"

