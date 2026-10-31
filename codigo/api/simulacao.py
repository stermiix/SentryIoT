"""A simulação da interface: um pcap enviado pela tela vira incidente e passa pelos agentes.

O pcap passa pelo reprodutor (extrator, classificador e política de acionamento) e os incidentes vão
para um log de eventos novo. Cada incidente segue então para o orquestrador
(`codigo/agente/agentes.py`), um por vez e na ordem em que abriu: triagem, decisão, aprovação de uma
pessoa quando o risco é alto, execução, verificação do efeito e sumário. Os agentes rodam em segundo
plano, na configuração local (decisão de 31/10/2026), e a tela acompanha o log com `atual`.

A aprovação continua sendo da pessoa. `decidir` grava pelo mesmo caminho do comando
`python -m codigo.mcp.aprovar`, com o canal `interface`, e nenhum agente chega a ela. Só vale enquanto
os agentes rodam: depois disso, uma aprovação ficaria no log sem ninguém para executar a ação.

Em replay, a ação não age sobre o tráfego gravado: a verificação do efeito é simulada e dá sempre
"cessou" (`EFEITOS_DO_REPLAY`, em `codigo/reprodutor/reprodutor.py`). A interface diz isso.

Cada simulação grava em `dados/eventos/simulacoes/<instante>-<pcap>/`, fora do git: o log de
eventos, os cenários e o resumo, só com leitura e escrita para o dono (os três trazem endereços da
rede). O pcap enviado é apagado no fim. Com `so_teste`, só o trecho do pcap que ficou fora do
treino do modelo do sistema é classificado (`inicio_do_teste`).
"""

import datetime
import json
import logging
import os
import re
import threading
from pathlib import Path

from codigo.agente.agentes import LOCAL, Perfil, orquestrar
from codigo.agente.cliente_mcp import ErroDoServidor
from codigo.api.provedor import ErroDoProvedor, Provedor
from codigo.mcp import acoes
from codigo.mcp.acoes import PedidoRecusado
from codigo.mcp.eventos import Registro
from codigo.reprodutor.reprodutor import (
    MANIFESTO_DA_REGERACAO,
    Classificador,
    PcapInvalido,  # noqa: F401  (reexportado para a rota)
    caminho_dos_cenarios,
    gravar,
    inicio_do_teste,
    reproduzir,
    resumo,
)

log = logging.getLogger(__name__)
RAIZ = Path(__file__).resolve().parents[2]
MODELO_PADRAO = RAIZ / "modelos" / "rf_regerado_janela_100.joblib"
MANIFESTO = RAIZ / MANIFESTO_DA_REGERACAO
PASTA_PADRAO = RAIZ / "dados" / "eventos" / "simulacoes"
NOME_PADRAO = "captura.pcap"
_FORA_DO_NOME = re.compile(r"[^A-Za-z0-9._-]+")
# Os experimentos e a simulação rodam só no modelo local (decisão de 31/10/2026).
CONFIGURACAO = LOCAL
# A pessoa tem tempo de sobra para ler a proposta: quem encerra a espera é o botão de parar.
ESPERA_DA_PESSOA_S = 3600
# O estado dos agentes numa simulação.
RODANDO = "rodando"
PARANDO = "parando"
CONCLUIDOS = "concluidos"
INTERROMPIDOS = "interrompidos"
SEM_MODELO = "sem_modelo"
SEM_INCIDENTES = "sem_incidentes"
# A situação de cada incidente nos agentes.
NA_FILA = "na_fila"
EM_ANDAMENTO = "em_andamento"
CONCLUIDO = "concluido"
ERRO = "erro"
INTERROMPIDO = "interrompido"
# As decisões que a pessoa toma pela tela, e o que `decidir` recebe em `tipo`.
APROVAR = "aprovar"
REJEITAR = "rejeitar"
RESOLVIDO = "resolvido"
TIPOS_DE_DECISAO = (APROVAR, REJEITAR, RESOLVIDO)
CANAL = "interface"
TAMANHO_DO_ERRO = 300
# Erros que um incidente pode dar sem que os seguintes deixem de rodar.
_ERROS_DO_INCIDENTE = (ErroDoProvedor, ErroDoServidor, PedidoRecusado, OSError, ValueError)


def nome_do_pcap(nome):
    """O nome do arquivo enviado, só com o último trecho do caminho e caracteres seguros."""
    nome = _FORA_DO_NOME.sub("_", Path(nome or "").name).strip("._")[:100]
    return nome or NOME_PADRAO


class SemTrechoDeTeste(ValueError):
    """O pcap pedido com `so_teste` ficou inteiro no treino, ou não está na regeração."""


class SemSimulacaoEmAndamento(Exception):
    """A decisão chegou sem agente que possa agir sobre ela."""


class _Interrompida(Exception):
    """A pessoa pediu para parar enquanto o orquestrador esperava uma decisão."""


class Acompanhamento:
    """O que os agentes fizeram numa simulação: escrito pela linha deles, lido pelas rotas."""

    def __init__(self, pasta, caminho_do_log, cenarios, saida, incidentes, estado, modelo, motivo=None):
        self.pasta = pasta
        self.log = caminho_do_log
        self.cenarios = cenarios
        self.saida = saida
        self.modelo = modelo
        self.motivo = motivo
        self.estado = estado
        self.incidentes = [{"id": id_, "situacao": NA_FILA, "desfecho": None, "erro": None} for id_ in incidentes]
        self._trava = threading.Lock()
        self._parar = threading.Event()

    def foto(self, estado=None):
        with self._trava:
            atual = estado or self.estado
            return {
                "estado": PARANDO if atual == RODANDO and self._parar.is_set() else atual,
                "configuracao": CONFIGURACAO,
                "modelo": self.modelo,
                "motivo": self.motivo,
                "incidentes": [dict(item) for item in self.incidentes],
            }

    def rodando(self):
        with self._trava:
            return self.estado == RODANDO

    def marcar(self, item, **campos):
        with self._trava:
            item.update(campos)

    def encerrar(self, estado):
        with self._trava:
            self.estado = estado

    def pedir_parada(self):
        self._parar.set()

    def parada_pedida(self):
        return self._parar.is_set()

    def esperar(self, segundos):
        """O lugar do `time.sleep` na espera pela pessoa: o pedido de parar a encerra na hora."""
        if self._parar.wait(segundos):
            raise _Interrompida


class Simulador:
    """Guarda o modelo carregado entre as simulações e deixa uma só rodar por vez."""

    def __init__(self, config, caminho_do_modelo=MODELO_PADRAO, pasta=PASTA_PADRAO, classificador=None, provedor=None,
                 orquestrador=orquestrar):
        self.config = config
        self.caminho_do_modelo = Path(caminho_do_modelo)
        self.pasta = Path(pasta)
        self.provedor = provedor or Provedor(config)
        self.orquestrador = orquestrador
        self._classificador = classificador
        self._carga = threading.Lock()
        # Tomada pela rota durante o processamento do pcap.
        self.trava = threading.Lock()
        self._atual = None

    def disponivel(self):
        return self._classificador is not None or self.caminho_do_modelo.is_file()

    def ocupado(self):
        """Se há um pcap em processamento ou agentes rodando: uma simulação por vez."""
        return self.trava.locked() or (self._atual is not None and self._atual.rodando())

    def classificador(self):
        with self._carga:
            if self._classificador is None:
                self._classificador = Classificador.carregar(self.caminho_do_modelo)
            return self._classificador

    def simular(self, caminho_do_pcap, nome, so_teste=False):
        """Roda a simulação e devolve o que já se sabe, com os agentes começando em segundo plano.

        Levanta `PcapInvalido` para o arquivo que não dá para ler e `SemTrechoDeTeste` quando
        `so_teste` é pedido para um pcap sem trecho fora do treino.
        """
        classificador = self.classificador()
        a_partir = 0
        if so_teste:
            a_partir = inicio_do_teste(nome, MANIFESTO)
            if a_partir is None:
                raise SemTrechoDeTeste(f"{nome} não tem trecho fora do treino no manifesto da regeração")
        reproducao = reproduzir(caminho_do_pcap, classificador, nome=nome, a_partir_da_janela=a_partir)
        instante = datetime.datetime.now(tz=datetime.UTC).astimezone().strftime("%Y%m%d-%H%M%S-%f")
        pasta = self.pasta / f"{instante}-{Path(nome).stem}"
        self.pasta.mkdir(parents=True, exist_ok=True, mode=0o700)
        pasta.mkdir(mode=0o700)
        caminho_do_log = pasta / "eventos.jsonl"
        cenarios, deslocamento = gravar(reproducao, classificador, caminho_do_log)
        saida = resumo(reproducao, cenarios, classificador, deslocamento, a_partir_da_janela=a_partir)
        saida["log"] = _relativo(caminho_do_log)
        saida["cenarios"] = _relativo(caminho_dos_cenarios(caminho_do_log))
        acompanhamento = self._acompanhar(pasta, caminho_do_log, [c.incidente.id for c in cenarios], saida)
        self._gravar_resumo(acompanhamento)
        self._atual = acompanhamento
        if acompanhamento.rodando():
            threading.Thread(target=self._tratar, args=(acompanhamento,), name="agentes-da-simulacao", daemon=True).start()
        return self.atual()

    def atual(self):
        """A simulação mais recente como a tela a vê, com o log como está agora. Nula se não houve nenhuma."""
        acompanhamento = self._atual
        if acompanhamento is None:
            return None
        eventos = acompanhamento.log.read_text(encoding="utf-8") if acompanhamento.log.exists() else ""
        return {**acompanhamento.saida, "eventos": eventos, "agentes": acompanhamento.foto()}

    def decidir(self, tipo, alvo, motivo=None):
        """Grava a decisão da pessoa no log. Levanta `PedidoRecusado` se o pedido não couber."""
        acompanhamento = self._atual
        if acompanhamento is None or not acompanhamento.rodando() or acompanhamento.parada_pedida():
            raise SemSimulacaoEmAndamento("não há agentes rodando: a decisão não teria efeito. Use o terminal para registrá-la")

        def gravar_decisao(eventos):
            estado = acoes.reconstruir(eventos)
            if tipo == RESOLVIDO:
                return acoes.marcar_resolvido(estado, alvo, canal=CANAL, motivo=motivo)
            return acoes.decidir(estado, alvo, tipo == APROVAR, canal=CANAL, motivo=motivo)

        Registro(acompanhamento.log).atualizar(gravar_decisao)

    def parar(self):
        """Pede para os agentes pararem: a espera por uma pessoa acaba na hora, e a fila não anda mais."""
        if self._atual is not None:
            self._atual.pedir_parada()

    def _acompanhar(self, pasta, caminho_do_log, incidentes, saida):
        estado, motivo = RODANDO, None
        faltando = self.config.faltando()
        if not incidentes:
            estado = SEM_INCIDENTES
        elif faltando:
            estado = SEM_MODELO
            motivo = "o backend está sem configuração do provedor: faltam " + ", ".join(faltando)
        return Acompanhamento(
            pasta, caminho_do_log, caminho_dos_cenarios(caminho_do_log), saida, incidentes, estado, self.config.modelo, motivo,
        )

    def _tratar(self, acompanhamento):
        """Leva cada incidente aos agentes, em ordem. Um erro num deles não impede os seguintes."""
        perfis = {LOCAL: Perfil(self.provedor, self.config.modelo)}
        estado = CONCLUIDOS
        for item in acompanhamento.incidentes:
            if acompanhamento.parada_pedida():
                estado = INTERROMPIDOS
                break
            acompanhamento.marcar(item, situacao=EM_ANDAMENTO)
            try:
                resultado = self.orquestrador(
                    item["id"], log=acompanhamento.log, cenarios=acompanhamento.cenarios, perfis=perfis,
                    configuracao=CONFIGURACAO, espera_da_aprovacao_s=ESPERA_DA_PESSOA_S, esperar=acompanhamento.esperar,
                    rodada_apos_rejeicao=True, sumario=True,
                )
            except _Interrompida:
                acompanhamento.marcar(item, situacao=INTERROMPIDO)
                estado = INTERROMPIDOS
                break
            except _ERROS_DO_INCIDENTE as erro:
                acompanhamento.marcar(item, situacao=ERRO, erro=str(erro)[:TAMANHO_DO_ERRO])
            except Exception:  # o detalhe vai para o log do servidor, não para a tela
                log.exception("falha inesperada nos agentes da simulação")
                acompanhamento.marcar(item, situacao=ERRO, erro="falha inesperada ao rodar os agentes")
            else:
                acompanhamento.marcar(item, situacao=CONCLUIDO, desfecho=resultado.desfecho)
        # O resumo vem antes da mudança de estado: quem vê os agentes parados encontra o arquivo pronto.
        try:
            self._gravar_resumo(acompanhamento, estado)
        except OSError:
            log.exception("o resumo final da simulação não foi gravado")
        finally:
            acompanhamento.encerrar(estado)

    def _gravar_resumo(self, acompanhamento, estado=None):
        corpo = {**acompanhamento.saida, "agentes": acompanhamento.foto(estado)}
        _gravar_so_do_dono(acompanhamento.pasta / "resumo.json", json.dumps(corpo, indent=1, ensure_ascii=False) + "\n")


def _gravar_so_do_dono(caminho, texto):
    descritor = os.open(caminho, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with open(descritor, "w", encoding="utf-8") as arquivo:
        arquivo.write(texto)


def _relativo(caminho):
    try:
        return Path(caminho).resolve().relative_to(RAIZ).as_posix()
    except ValueError:
        return Path(caminho).as_posix()
