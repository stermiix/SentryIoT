import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from codigo.mcp.eventos import CAMINHO_PADRAO, LogInvalido, Registro, agora, ler, novo
from codigo.mcp.tipos import ChamadaDeLLM

RAIZ = Path(__file__).resolve().parents[2]
INICIO = datetime(2026, 10, 20, 14, 3, 41, tzinfo=UTC)
LOTE = {"janelas": 450, "por_categoria": {"DoS": 412, "Benign": 38}}
CHAMADA = {
    "agente": "triagem", "modelo": "modelo-de-exemplo", "tokens_entrada": 812, "tokens_saida": 164,
    "duracao_ms": 2300.0,
}


class RelogioDeTeste:
    """Devolve instantes fixos, um segundo depois do outro a cada leitura."""

    def __init__(self):
        self.leituras = 0

    def __call__(self):
        self.leituras += 1
        return INICIO + timedelta(seconds=self.leituras - 1)


@pytest.fixture
def registro(tmp_path):
    return Registro(tmp_path / "eventos.jsonl", relogio=RelogioDeTeste())


def test_gravar_acrescenta_uma_linha_json_por_evento(registro):
    registro.gravar(novo("janelas_classificadas", LOTE))
    registro.gravar(novo("llm_chamada", CHAMADA, incidente="inc-0001"))
    linhas = registro.caminho.read_text(encoding="utf-8").splitlines()
    assert [json.loads(linha) for linha in linhas] == [
        {
            "id": "ev-000001", "instante": "2026-10-20T14:03:41Z", "tipo": "janelas_classificadas",
            "incidente": None, "dados": LOTE,
        },
        {
            "id": "ev-000002", "instante": "2026-10-20T14:03:42Z", "tipo": "llm_chamada",
            "incidente": "inc-0001", "dados": CHAMADA,
        },
    ]
    assert list(json.loads(linhas[0])) == ["id", "instante", "tipo", "incidente", "dados"]
    assert registro.caminho.read_bytes().endswith(b"\n")


def test_gravar_devolve_os_eventos_ja_com_identificador_e_instante(registro):
    gravados = registro.gravar(novo("janelas_classificadas", LOTE), novo("llm_chamada", CHAMADA, "inc-0001"))
    assert [evento.id for evento in gravados] == ["ev-000001", "ev-000002"]
    # Os eventos gravados de uma vez só têm o mesmo instante.
    assert [evento.instante for evento in gravados] == [INICIO, INICIO]
    assert gravados[1].dados == ChamadaDeLLM.model_validate(CHAMADA)
    assert gravados == registro.ler()


def test_dados_podem_vir_como_modelo_do_contrato(registro):
    registro.gravar(novo("llm_chamada", ChamadaDeLLM.model_validate(CHAMADA), "inc-0001"))
    assert json.loads(registro.caminho.read_text(encoding="utf-8"))["dados"] == CHAMADA


def test_o_log_e_so_de_acrescimo(registro):
    registro.gravar(novo("janelas_classificadas", LOTE))
    antes = registro.caminho.read_bytes()
    registro.gravar(novo("llm_chamada", CHAMADA, "inc-0001"))
    assert registro.caminho.read_bytes().startswith(antes)


def test_texto_com_acento_vai_legivel_no_arquivo(registro):
    registro.gravar(novo("recomendacao_emitida", {"agente": "decisao", "texto": "Limitar a taxa já.", "propostas": []}))
    assert "Limitar a taxa já." in registro.caminho.read_text(encoding="utf-8")


def test_a_numeracao_continua_do_arquivo_e_nao_da_memoria(tmp_path):
    caminho = tmp_path / "eventos.jsonl"
    Registro(caminho).gravar(novo("janelas_classificadas", LOTE))
    outro = Registro(caminho)
    assert [evento.id for evento in outro.gravar(novo("janelas_classificadas", LOTE))] == ["ev-000002"]
    assert [evento.id for evento in ler(caminho)] == ["ev-000001", "ev-000002"]


def test_cria_a_pasta_do_log(tmp_path):
    caminho = tmp_path / "pasta" / "nova" / "eventos.jsonl"
    Registro(caminho).gravar(novo("janelas_classificadas", LOTE))
    assert len(ler(caminho)) == 1


def test_ler_arquivo_que_nao_existe_devolve_lista_vazia(tmp_path):
    assert ler(tmp_path / "nao_existe.jsonl") == []
    assert Registro(tmp_path / "nao_existe.jsonl").ler() == []


@pytest.mark.parametrize("rascunho", [
    novo("incidente_reaberto", LOTE),
    novo("llm_chamada", LOTE),
    novo("llm_chamada", CHAMADA | {"tokens_entrada": -1}),
    novo("janelas_classificadas", {"janelas": 1, "por_categoria": {"Exfiltracao": 1}}),
])
def test_evento_fora_do_contrato_nao_e_gravado(registro, rascunho):
    with pytest.raises(ValidationError):
        registro.gravar(novo("janelas_classificadas", LOTE), rascunho)
    # Nem o evento válido do mesmo lote fica no arquivo.
    assert registro.ler() == []


def test_atualizar_le_decide_e_grava_de_uma_vez(registro):
    registro.gravar(novo("janelas_classificadas", LOTE))

    def decidir(eventos):
        assert [evento.id for evento in eventos] == ["ev-000001"]
        return "resposta", [novo("llm_chamada", CHAMADA, "inc-0001")]

    resultado, gravados = registro.atualizar(decidir)
    assert resultado == "resposta"
    assert [evento.id for evento in gravados] == ["ev-000002"]
    assert [evento.tipo for evento in registro.ler()] == ["janelas_classificadas", "llm_chamada"]


def test_atualizar_sem_eventos_novos_nao_mexe_no_arquivo(registro):
    registro.gravar(novo("janelas_classificadas", LOTE))
    antes = registro.caminho.read_bytes()
    assert registro.atualizar(lambda eventos: (len(eventos), [])) == (1, [])
    assert registro.caminho.read_bytes() == antes


def test_erro_em_decidir_nao_grava_nada(registro):
    def decidir(_eventos):
        raise RuntimeError("falhou no meio")

    with pytest.raises(RuntimeError, match="falhou no meio"):
        registro.atualizar(decidir)
    assert registro.ler() == []


@pytest.mark.parametrize("linha", [
    "isto não é JSON",
    '{"id": "ev-000002", "tipo": "janelas_classificadas"}',
    '{"id": "ev-000002", "instante": "2026-10-20T14:03:41Z", "tipo": "llm_chamada", "incidente": null, "dados": {}}',
])
def test_linha_invalida_no_arquivo_da_erro_com_o_numero_da_linha(registro, linha):
    registro.gravar(novo("janelas_classificadas", LOTE))
    with open(registro.caminho, "a", encoding="utf-8") as arquivo:
        arquivo.write(linha + "\n")
    with pytest.raises(LogInvalido, match=r"eventos\.jsonl, linha 2"):
        registro.ler()
    # Com o arquivo estragado, nada novo é gravado por cima.
    with pytest.raises(ValueError, match="linha 2"):
        registro.gravar(novo("janelas_classificadas", LOTE))


def test_leitura_guarda_o_arquivo_e_a_linha_de_cada_evento(registro):
    registro.gravar(novo("janelas_classificadas", LOTE), novo("llm_chamada", CHAMADA, "inc-0001"))
    with open(registro.caminho, "a", encoding="utf-8") as arquivo:
        arquivo.write("\n\n")
    registro.gravar(novo("janelas_classificadas", LOTE))
    eventos = registro.ler()
    assert isinstance(eventos, list) and len(eventos) == 3
    # As linhas em branco não são eventos, mas contam na numeração das linhas do arquivo.
    assert [eventos.onde(indice) for indice in range(3)] == [
        f"{registro.caminho}, linha 1", f"{registro.caminho}, linha 2", f"{registro.caminho}, linha 5",
    ]

    def decidir(lidos):
        return lidos.onde(2), []

    assert registro.atualizar(decidir) == (f"{registro.caminho}, linha 5", [])


def test_linhas_em_branco_sao_ignoradas(registro):
    registro.gravar(novo("janelas_classificadas", LOTE))
    with open(registro.caminho, "a", encoding="utf-8") as arquivo:
        arquivo.write("\n")
    assert [evento.id for evento in registro.gravar(novo("janelas_classificadas", LOTE))] == ["ev-000002"]


def test_gravacoes_simultaneas_nao_repetem_identificador(tmp_path):
    caminho = tmp_path / "eventos.jsonl"

    def gravar_varios():
        registro = Registro(caminho)
        for _ in range(25):
            registro.gravar(novo("janelas_classificadas", LOTE))

    tarefas = [threading.Thread(target=gravar_varios) for _ in range(8)]
    for tarefa in tarefas:
        tarefa.start()
    for tarefa in tarefas:
        tarefa.join()
    assert [evento.id for evento in ler(caminho)] == [f"ev-{n:06d}" for n in range(1, 201)]


def test_relogio_padrao_devolve_o_instante_atual_em_utc():
    instante = agora()
    assert instante.utcoffset() == timedelta(0)
    assert abs(datetime.now(UTC) - instante) < timedelta(seconds=5)


def test_caminho_padrao_fica_na_pasta_de_dados_e_fora_do_git():
    assert CAMINHO_PADRAO == RAIZ / "dados" / "eventos" / "eventos.jsonl"
    ignorados = (RAIZ / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "dados/eventos/" in ignorados
