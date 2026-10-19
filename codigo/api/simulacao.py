"""A simulação da interface: um pcap enviado pela tela vai até a porta do primeiro modelo.

O pcap passa pelo reprodutor (extrator, classificador e política de acionamento), os incidentes
vão para um log de eventos novo, e o primeiro deles ganha o pedido que o orquestrador mandaria ao
modelo da triagem. A chamada ao modelo fica de fora: `para_o_llm.enviado` é sempre falso.

Cada simulação grava em `dados/eventos/simulacoes/<instante>-<pcap>/`, fora do git: o log de
eventos e o resumo. O pcap enviado é apagado no fim.
"""

import datetime
import json
import re
import threading
from pathlib import Path

from codigo.agente.pedidos import PASTA_DE_SKILLS, pedido_da_triagem
from codigo.mcp import acoes
from codigo.mcp.eventos import ler
from codigo.reprodutor.reprodutor import (
    Classificador,
    cenarios_da_reproducao,
    gravar,
    reproduzir,
    resumo,
)

RAIZ = Path(__file__).resolve().parents[2]
MODELO_PADRAO = RAIZ / "modelos" / "rf_regerado_janela_100.joblib"
PASTA_PADRAO = RAIZ / "dados" / "eventos" / "simulacoes"
NOME_PADRAO = "captura.pcap"
_FORA_DO_NOME = re.compile(r"[^A-Za-z0-9._-]+")


def nome_do_pcap(nome):
    """O nome do arquivo enviado, só com o último trecho do caminho e caracteres seguros."""
    nome = _FORA_DO_NOME.sub("_", Path(nome or "").name).strip("._")[:100]
    return nome or NOME_PADRAO


class Simulador:
    """Guarda o modelo carregado entre as simulações e deixa uma só rodar por vez."""

    def __init__(self, config, caminho_do_modelo=MODELO_PADRAO, pasta=PASTA_PADRAO, pasta_de_skills=PASTA_DE_SKILLS,
                 classificador=None):
        self.config = config
        self.caminho_do_modelo = Path(caminho_do_modelo)
        self.pasta = Path(pasta)
        self.pasta_de_skills = pasta_de_skills
        self._classificador = classificador
        self._carga = threading.Lock()
        # Tomada pela rota durante o envio e o processamento: uma simulação por vez.
        self.trava = threading.Lock()

    def disponivel(self):
        return self._classificador is not None or self.caminho_do_modelo.is_file()

    def classificador(self):
        with self._carga:
            if self._classificador is None:
                self._classificador = Classificador.carregar(self.caminho_do_modelo)
            return self._classificador

    def simular(self, caminho_do_pcap, nome):
        classificador = self.classificador()
        reproducao = reproduzir(caminho_do_pcap, classificador, nome=nome)
        cenarios = cenarios_da_reproducao(reproducao, classificador)
        instante = datetime.datetime.now(tz=datetime.UTC).astimezone().strftime("%Y%m%d-%H%M%S-%f")
        pasta = self.pasta / f"{instante}-{Path(nome).stem}"
        pasta.mkdir(parents=True, exist_ok=True)
        log = pasta / "eventos.jsonl"
        gravar(cenarios, reproducao, log)
        saida = resumo(reproducao, cenarios, classificador)
        saida["log"] = _relativo(log)
        saida["eventos"] = log.read_text(encoding="utf-8") if log.exists() else ""
        saida["para_o_llm"] = self._para_o_llm(cenarios, log) if cenarios else None
        (pasta / "resumo.json").write_text(
            json.dumps({k: v for k, v in saida.items() if k != "eventos"}, indent=1, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return saida

    def _para_o_llm(self, cenarios, log):
        """O que o primeiro incidente leva até a porta dos modelos, sem chamada nenhuma."""
        incidente = cenarios[0].incidente
        estado = acoes.reconstruir(ler(log))
        visao_da_fronteira = acoes.resumo_do_incidente(estado, acoes.carregar_politica(), incidente.id)
        return {
            "enviado": False,
            "motivo": "A simulação para na porta do modelo: o orquestrador que faz a chamada ainda não existe.",
            "agente": "triagem",
            "onde_roda": "modelo local",
            "incidente": incidente.id,
            "pedido": pedido_da_triagem(incidente.id, self.config.modelo, self.config.parametros(), self.pasta_de_skills),
            "primeira_leitura": {"tool": "obter_incidente", "resultado": estado.incidentes[incidente.id].model_dump(mode="json")},
            "visao_da_fronteira": {"tool": "obter_resumo", "resultado": visao_da_fronteira.model_dump(mode="json")},
        }


def _relativo(caminho):
    try:
        return Path(caminho).resolve().relative_to(RAIZ).as_posix()
    except ValueError:
        return Path(caminho).as_posix()
