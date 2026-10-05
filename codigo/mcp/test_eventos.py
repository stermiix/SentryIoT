import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from codigo.mcp.eventos import (
    CAMINHO_PADRAO,
    TIPOS_DO_AGENTE,
    GravadorDoAgente,
    LogInvalido,
    Registro,
    agora,
    ler,
    novo,
)
from codigo.mcp.test_tipos import DADOS_POR_TIPO
from codigo.mcp.tipos import TIPOS_DE_EVENTO, ChamadaDeLLM, Recomendacao

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


def test_erro_de_linha_fora_do_contrato_diz_o_campo_e_nao_repete_o_conteudo_da_linha(registro):
    registro.gravar(novo("janelas_classificadas", LOTE))
    invalida = {
        "id": "ev-000002", "instante": "2026-10-20T14:03:41Z", "tipo": "llm_chamada", "incidente": None,
        "dados": CHAMADA | {"modelo": "segredo-do-log", "tokens_entrada": -5, "tokens_saida": "muitos", "duracao_ms": -1},
    }
    with open(registro.caminho, "a", encoding="utf-8") as arquivo:
        arquivo.write(json.dumps(invalida) + "\n")
    with pytest.raises(LogInvalido) as captura:
        registro.ler()
    mensagem = str(captura.value)
    assert f"{registro.caminho}, linha 2: evento fora do contrato" in mensagem
    assert "dados.tokens_entrada" in mensagem and "dados.tokens_saida" in mensagem and "dados.duracao_ms" in mensagem
    # Uma linha só, curta, sem o valor que estava no log e sem o endereço da documentação do pydantic.
    assert mensagem.isprintable() and len(mensagem) < 600
    assert "segredo-do-log" not in mensagem and "muitos" not in mensagem and "pydantic" not in mensagem


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


def test_arquivo_sem_quebra_de_linha_no_fim_nao_cola_o_evento_seguinte(registro):
    registro.gravar(novo("janelas_classificadas", LOTE))
    registro.caminho.write_bytes(registro.caminho.read_bytes().removesuffix(b"\n"))
    assert not registro.caminho.read_bytes().endswith(b"\n")

    # Sem a quebra, o evento novo era escrito na mesma linha do anterior, e o log deixava de ser lido.
    registro.gravar(novo("llm_chamada", CHAMADA, "inc-0001"))
    registro.gravar(novo("janelas_classificadas", LOTE))
    assert [evento.id for evento in registro.ler()] == ["ev-000001", "ev-000002", "ev-000003"]
    linhas = registro.caminho.read_text(encoding="utf-8").split("\n")
    assert [linha.count('"id":"ev-') for linha in linhas] == [1, 1, 1, 0]


def chamada_de_tool(**argumentos):
    return {"agente": None, "nome": "obter_janelas", "argumentos": argumentos, "resultado": {}, "duracao_ms": 1.0}


def aninhado(niveis):
    valor = atual = {}
    for _ in range(niveis):
        atual["a"] = {}
        atual = atual["a"]
    return valor


@pytest.mark.parametrize("rascunho", [
    novo("tool_chamada", chamada_de_tool(limite=10**5000), "inc-0001"),
    novo("llm_chamada", CHAMADA | {"tokens_entrada": 10**5000}, "inc-0001"),
    novo("tool_chamada", chamada_de_tool(x="\ud800"), "inc-0001"),
    novo("tool_chamada", chamada_de_tool(x=aninhado(3000)), "inc-0001"),
    novo("tool_chamada", chamada_de_tool(x=float("nan")), "inc-0001"),
], ids=["inteiro de 5000 dígitos em argumentos", "inteiro de 5000 dígitos em contagem", "surrogate solto", "3000 níveis", "nan"])
def test_evento_que_nao_seria_lido_de_volta_nao_e_gravado(registro, rascunho):
    # Antes, a linha era gravada e o log inteiro deixava de ser lido: toda chamada seguinte falhava.
    registro.gravar(novo("janelas_classificadas", LOTE))
    antes = registro.caminho.read_bytes()
    with pytest.raises(ValueError, match="não pode ser gravado") as captura:
        registro.gravar(novo("janelas_classificadas", LOTE), rascunho)
    assert len(str(captura.value)) < 600
    assert registro.caminho.read_bytes() == antes
    assert [evento.id for evento in registro.gravar(novo("janelas_classificadas", LOTE))] == ["ev-000002"]
    assert len(registro.ler()) == 2


def test_cada_evento_ocupa_uma_linha_para_qualquer_leitor(registro):
    # NEL, separador de linha e separador de parágrafo dividem a linha para quem lê com splitlines().
    texto = "a\x85b\u2028c\u2029d\x1ce\nf"
    registro.gravar(novo("tool_chamada", chamada_de_tool(x=texto), "inc-0001"))
    registro.gravar(novo("janelas_classificadas", LOTE))
    bruto = registro.caminho.read_text(encoding="utf-8")
    assert len(bruto.splitlines()) == 2
    assert all(json.loads(linha)["id"] for linha in bruto.splitlines())
    assert registro.ler()[0].dados.argumentos == {"x": texto}


# --- o que o código dos agentes grava --------------------------------------------------------


@pytest.fixture
def gravador(registro):
    return GravadorDoAgente("decisao", registro.caminho, relogio=RelogioDeTeste())


def test_gravador_do_agente_grava_chamada_ao_modelo_e_recomendacao(gravador, registro):
    assert TIPOS_DO_AGENTE == ("llm_chamada", "recomendacao_emitida")
    assert (gravador.agente, gravador.caminho) == ("decisao", registro.caminho)
    chamada = CHAMADA | {"agente": "decisao"}
    recomendacao = {"agente": "decisao", "texto": "Bloquear a origem.\n\nSe não resolver, limitar a taxa.", "propostas": []}
    gravados = gravador.gravar(novo("llm_chamada", chamada, "inc-0001"))
    gravados += gravador.gravar(
        novo("recomendacao_emitida", Recomendacao.model_validate(recomendacao), "inc-0001"),
        novo("llm_chamada", ChamadaDeLLM.model_validate(chamada), "inc-0001"),
    )
    assert [(evento.id, evento.tipo) for evento in gravados] == [
        ("ev-000001", "llm_chamada"), ("ev-000002", "recomendacao_emitida"), ("ev-000003", "llm_chamada"),
    ]
    assert gravados == registro.ler()


@pytest.mark.parametrize("tipo", [tipo for tipo in TIPOS_DE_EVENTO if tipo not in ("llm_chamada", "recomendacao_emitida")])
def test_gravador_do_agente_recusa_todos_os_outros_eventos(gravador, registro, tipo):
    # Aprovação, proposta, execução, incidente: nada disso é o agente quem grava.
    with pytest.raises(ValueError, match=f"llm_chamada e recomendacao_emitida.*{tipo}"):
        gravador.gravar(novo(tipo, DADOS_POR_TIPO[tipo], "inc-0001"))
    # Um evento permitido no mesmo lote também não entra.
    with pytest.raises(ValueError, match=tipo):
        gravador.gravar(novo("llm_chamada", CHAMADA | {"agente": "decisao"}, "inc-0001"), novo(tipo, DADOS_POR_TIPO[tipo]))
    assert registro.ler() == []


def test_gravador_so_grava_em_nome_do_proprio_agente(gravador, registro):
    with pytest.raises(ValueError, match="decisao.*triagem"):
        gravador.gravar(novo("llm_chamada", CHAMADA, "inc-0001"))
    with pytest.raises(ValueError, match="decisao.*execucao"):
        gravador.gravar(novo("recomendacao_emitida", {"agente": "execucao", "texto": "Bloquear.", "propostas": []}))
    with pytest.raises(ValueError, match="agente desconhecido"):
        GravadorDoAgente("detector", registro.caminho)
    assert registro.ler() == []


def test_recomendacao_so_cita_proposta_que_existe_no_log(gravador, registro):
    registro.gravar(
        novo("incidente_aberto", DADOS_POR_TIPO["incidente_aberto"], "inc-0001"),
        novo("acao_proposta", DADOS_POR_TIPO["acao_proposta"], "inc-0001"),
    )
    recomendacao = {"agente": "decisao", "texto": "Bloquear a origem.", "propostas": ["prop-0001"]}
    gravador.gravar(novo("recomendacao_emitida", recomendacao, "inc-0001"))
    with pytest.raises(ValueError, match="prop-0099"):
        gravador.gravar(novo("recomendacao_emitida", recomendacao | {"propostas": ["prop-0001", "prop-0099"]}, "inc-0001"))
    assert [evento.tipo for evento in registro.ler()] == ["incidente_aberto", "acao_proposta", "recomendacao_emitida"]


@pytest.mark.parametrize("rascunho", [
    {"tipo": "llm_chamada"}, {"dados": CHAMADA}, {}, "llm_chamada", None,
    novo("llm_chamada", CHAMADA | {"agente": "decisao", "tokens_entrada": -1}),
    novo("recomendacao_emitida", {"agente": "decisao", "texto": "ok\x1b[2J", "propostas": []}),
])
def test_gravador_recusa_rascunho_malformado_sem_gravar(gravador, registro, rascunho):
    with pytest.raises(ValueError):
        gravador.gravar(rascunho)
    assert registro.ler() == []


def test_gravador_do_agente_so_oferece_a_gravacao(gravador):
    assert [nome for nome in dir(gravador) if not nome.startswith("_")] == ["agente", "caminho", "gravar"]


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
